//! xtask — host-side build/run/test driver for the SentinelOS kernel.
//!
//! This crate is a STANDALONE workspace living in `kernel/xtask/`.  It is
//! intentionally NOT a member of the `kernel/` workspace so it builds for the
//! host triple instead of inheriting `build.target = "x86_64-unknown-none"`.
//!
//! # Usage (run from kernel/)
//!
//! Drive it through the host-detecting Makefile — portable across Linux (CI /
//! Claude Code on the web) and macOS. The `cargo xtask` alias in
//! `.cargo/config.toml` is a macOS-only shortcut; both invoke this same binary.
//!
//! ```sh
//! make build       # cross-compile the boot binary for x86_64-unknown-none
//! make run         # build ISO, launch QEMU with serial output on stdout
//! make test        # build ISO, boot headless in QEMU (TCG), assert banner in serial.log
//! make test-kvm    # build ISO, boot under KVM (-cpu host), assert the x2APIC enable path
//! make screenshot  # build ISO, boot in headless QEMU, capture PNG via QMP
//! ```
//!
//! # Dependencies
//!
//! * `qemu-system-x86_64` — `brew install qemu`
//! * `xorriso`            — `brew install xorriso`
//! * `kernel/limine/`     — clone v11.x-binary and `make -C kernel/limine`

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::{Duration, Instant},
};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("build") => do_build(),
        Some("run") => do_run(),
        Some("test") => do_test(),
        Some("test-kvm") => do_test_kvm(),
        Some("screenshot") => do_screenshot(),
        other => {
            eprintln!(
                "Usage: cargo xtask <build|run|test|test-kvm|screenshot>\nUnknown subcommand: {:?}",
                other
            );
            ExitCode::FAILURE
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// QEMU arguments attaching an Intel **e1000** NIC (the Intel 82540EM the HAL
/// driver targets) to a user-mode (SLIRP) network backend, plus a packet capture
/// of everything that crosses that link.
///
/// - `-device e1000,netdev=n0` — the emulated 82540EM (vendor 0x8086 device
///   0x100E) the `hal::e1000` driver binds to, on the `n0` backend.
/// - `-netdev user,id=n0` — SLIRP user-mode networking (no host privileges
///   needed); the guest gets `10.0.2.15`, the gateway is `10.0.2.2`.
/// - `-object filter-dump,...,file=target/net.pcap` — dumps every TX/RX frame on
///   `n0` to a pcap so the test can prove frames actually left/arrived
///   (`tcpdump -r target/net.pcap`).
///
/// The pcap path is filled in per-call (it needs the kernel root); this returns
/// the static flags and the caller appends the `filter-dump` object.
fn e1000_args(pcap_path: &str) -> Vec<String> {
    vec![
        "-device".into(),
        "e1000,netdev=n0".into(),
        "-netdev".into(),
        "user,id=n0".into(),
        "-object".into(),
        format!("filter-dump,id=d0,netdev=n0,file={}", pcap_path),
    ]
}

/// Size of the persistent filesystem disk image (16 MiB) created on first run.
const DISK_IMG_BYTES: u64 = 16 * 1024 * 1024;

/// Default path of the persistent disk image (under `target/`, gitignored).
fn disk_img_path() -> PathBuf {
    kr("target/sentinelos-disk.img")
}

/// Ensure a raw disk image exists, then return the QEMU args that attach it as a
/// **persistent legacy ATA (ISA IDE) disk** the `hal::ata` driver can read/write.
///
/// On the **q35** machine the onboard `if=ide` storage is an AHCI/SATA controller
/// that does **not** answer the legacy command-block ports (`0x1F0..=0x1F7`) the
/// PIO driver pokes. So we explicitly create the legacy ISA IDE controller and
/// hang the disk on its primary channel:
///
/// - `-drive if=none,id=sosdisk,file=<img>,format=raw` — the raw backing image,
///   not auto-attached to any bus (`format=raw` ⇒ guest writes persist verbatim).
/// - `-device isa-ide,id=soside` — the legacy ISA IDE controller at iobase
///   `0x1F0` / control `0x3F6` (exactly the ports `hal::ata` drives).
/// - `-device ide-hd,drive=sosdisk,bus=soside.0` — attach the disk as the
///   **primary master** (`bus=…​.0`, unit 0), which `hal::ata::identify` probes.
///
/// The image is created (sparse, zero-filled to [`DISK_IMG_BYTES`]) only if it
/// does not already exist, so data written by a previous boot survives.
fn disk_args() -> Vec<String> {
    let img = disk_img_path();
    if !img.exists() {
        // Create the parent (target/) if needed, then a zero-filled sparse image.
        if let Some(parent) = img.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match fs::File::create(&img).and_then(|f| f.set_len(DISK_IMG_BYTES)) {
            Ok(()) => println!(
                "Created persistent disk image: {} ({} MiB)",
                img.display(),
                DISK_IMG_BYTES / (1024 * 1024)
            ),
            Err(e) => eprintln!(
                "WARNING: could not create disk image {}: {e}",
                img.display()
            ),
        }
    } else {
        println!("Using existing disk image: {}", img.display());
    }
    vec![
        "-drive".into(),
        format!("if=none,id=sosdisk,file={},format=raw", img.display()),
        "-device".into(),
        "isa-ide,id=soside".into(),
        "-device".into(),
        "ide-hd,drive=sosdisk,bus=soside.0".into(),
    ]
}

/// Path to the `kernel/` workspace root (one level up from `xtask/`).
fn kernel_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // strip xtask/
    p
}

/// Resolve a path relative to the kernel root.
fn kr(rel: &str) -> PathBuf {
    kernel_root().join(rel)
}

/// Run a command, inherit stdio, and return whether it succeeded.
fn run_cmd(cmd: &mut Command) -> bool {
    match cmd.status() {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("command failed with exit code: {}", s);
            false
        }
        Err(e) => {
            eprintln!("failed to spawn command: {}", e);
            false
        }
    }
}

/// Build the boot ELF for x86_64-unknown-none. Returns path to the ELF.
fn build_kernel() -> Option<PathBuf> {
    let root = kernel_root();
    println!("Building kernel for x86_64-unknown-none ...");
    let ok = run_cmd(
        Command::new("cargo")
            .args([
                "build",
                "--package",
                "boot",
                "--target",
                "x86_64-unknown-none",
            ])
            .current_dir(&root),
    );
    if !ok {
        return None;
    }
    let elf = root.join("target/x86_64-unknown-none/debug/sentinelos");
    if elf.exists() {
        println!("Kernel ELF: {}", elf.display());
        Some(elf)
    } else {
        eprintln!("ELF not found at expected path: {}", elf.display());
        None
    }
}

/// Assemble a bootable ISO image using Limine v11 + xorriso.
///
/// Layout of iso_root/:
///   sentinelos.elf
///   limine.conf
///   limine-bios.sys
///   limine-bios-cd.bin
///   limine-uefi-cd.bin
///   EFI/BOOT/BOOTX64.EFI
fn build_iso(kernel_elf: &Path) -> Option<PathBuf> {
    let limine_dir = kr("limine");
    let limine_bin = limine_dir.join("limine");
    let limine_conf = kr("limine.conf");
    let iso_root = kr("target/iso_root");
    let iso_path = kr("target/sentinelos.iso");

    // Verify limine host tool exists.
    if !limine_bin.exists() {
        eprintln!(
            "Limine host tool not found at {}. Run:\n  make -C kernel/limine",
            limine_bin.display()
        );
        return None;
    }

    // Create iso_root directory tree.
    let efi_boot = iso_root.join("EFI/BOOT");
    fs::create_dir_all(&efi_boot).expect("create iso_root/EFI/BOOT");

    // Copy kernel ELF.
    fs::copy(kernel_elf, iso_root.join("sentinelos.elf")).expect("copy kernel ELF into iso_root");

    // Copy limine config.
    fs::copy(&limine_conf, iso_root.join("limine.conf")).expect("copy limine.conf into iso_root");

    // Copy Limine BIOS artifacts.
    for name in &[
        "limine-bios.sys",
        "limine-bios-cd.bin",
        "limine-uefi-cd.bin",
    ] {
        let src = limine_dir.join(name);
        if !src.exists() {
            eprintln!("Missing Limine artifact: {}", src.display());
            return None;
        }
        fs::copy(&src, iso_root.join(name)).expect("copy Limine artifact");
    }

    // Copy UEFI bootloader.
    let bootx64_src = limine_dir.join("BOOTX64.EFI");
    if !bootx64_src.exists() {
        eprintln!("Missing BOOTX64.EFI in {}", limine_dir.display());
        return None;
    }
    fs::copy(&bootx64_src, efi_boot.join("BOOTX64.EFI")).expect("copy BOOTX64.EFI");

    // Build the ISO with xorriso (standard Limine El-Torito BIOS+UEFI incantation).
    // Flags match the official Limine USAGE.md recipe exactly.
    println!("Building ISO with xorriso ...");
    let ok = run_cmd(Command::new("xorriso").args([
        "-as",
        "mkisofs",
        "-R",
        "-r",
        "-J",
        "-b",
        "limine-bios-cd.bin",
        "-no-emul-boot",
        "-boot-load-size",
        "4",
        "-boot-info-table",
        "-hfsplus",
        "-apm-block-size",
        "2048",
        "--efi-boot",
        "limine-uefi-cd.bin",
        "-efi-boot-part",
        "--efi-boot-image",
        "--protective-msdos-label",
        iso_root.to_str().unwrap(),
        "-o",
        iso_path.to_str().unwrap(),
    ]));
    if !ok {
        return None;
    }

    // Install Limine BIOS boot sectors into the ISO.
    println!("Installing Limine BIOS sectors ...");
    let ok = run_cmd(Command::new(&limine_bin).args(["bios-install", iso_path.to_str().unwrap()]));
    if !ok {
        return None;
    }

    println!("ISO ready: {}", iso_path.display());
    Some(iso_path)
}

// ── subcommands ───────────────────────────────────────────────────────────────

fn do_build() -> ExitCode {
    match build_kernel() {
        Some(_) => {
            println!("Build succeeded.");
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("Build failed.");
            ExitCode::FAILURE
        }
    }
}

fn do_run() -> ExitCode {
    let Some(elf) = build_kernel() else {
        return ExitCode::FAILURE;
    };
    let Some(iso) = build_iso(&elf) else {
        return ExitCode::FAILURE;
    };

    let pcap = kr("target/net.pcap");
    println!("Launching QEMU (serial → stdout, Ctrl-C to quit) ...");
    println!("NIC: e1000 on SLIRP; frames captured to {}", pcap.display());
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args([
        "-M",
        "q35",
        // SMEP/SMAP/UMIP (Haswell base + explicit flags) so cpu_security enables
        // them; `-smp 4` gives the guest four logical CPUs for the SMP path.
        // x2APIC is intentionally NOT requested: QEMU's TCG (software) APIC cannot
        // emulate it, so the kernel takes its documented no-op fallback here; the
        // x2APIC enable path activates under KVM / on real hardware. See
        // docs/specs/2026-07-14-smp-x2apic-design.md.
        "-cpu",
        "Haswell,+smep,+smap,+umip",
        "-smp",
        "4",
        "-m",
        "256M",
        "-cdrom",
        iso.to_str().unwrap(),
        "-serial",
        "stdio",
        "-display",
        "none",
        "-no-reboot",
    ])
    .args(e1000_args(pcap.to_str().unwrap()))
    .args(disk_args());
    println!("Disk: persistent IDE image attached (filesystem survives reboot).");
    let ok = run_cmd(&mut cmd);

    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// End-marker written by `kmain` after the full banner has been flushed.
const END_MARKER: &str = "boot-bringup-ok";
/// Full banner line we require to be present as well.
const BANNER_LINE: &str = "SentinelOS \u{2014} boot bring-up OK";
/// Marker proving the SMP (x2APIC) bring-up branch actually executed. Both the
/// enable line (`[smp] x2APIC enabled …`) and the graceful "not advertised"
/// fallback share this prefix, so it positively confirms the path ran regardless
/// of whether the host (KVM/hardware vs. TCG) advertises x2APIC.
const SMP_MARKER: &str = "[smp]";
/// The x2APIC **enable** line (the `Some` branch of `enable_bsp`). Only printed
/// where x2APIC is actually present — i.e. under KVM (`-cpu host`) or on real
/// hardware, never under TCG. Asserting it in the KVM boot test is the concrete
/// evidence that the AP1 MSR write sequence ran and the virtual wire held
/// (verification condition C1 for the SMP TCB; see the SMP design doc + issue #10).
const SMP_ENABLED_MARKER: &str = "[smp] x2APIC enabled";
/// The timer-liveness substring the enable line carries — its presence with a
/// non-empty tick count proves the PIT kept ticking through LINT0=ExtINT.
const SMP_TIMER_LIVE_MARKER: &str = "timer live";
/// The ML bring-up line proving the **AVX2** vector tier is active — printed when
/// the CPU advertises `avx2` and the boot-time AVX2 int8-GEMM self-test passes. The
/// kernel's AVX2 kernel is hand-written `asm!` (the `x86_64-unknown-none` soft-float
/// target won't codegen `core::arch` SIMD intrinsics to VEX), so it runs correctly
/// under both TCG (`-cpu Haswell` has avx2) and KVM — asserting this proves the
/// vector inference path executes and computes correctly, not just the scalar tier.
const ML_AVX2_ACTIVE: &str = "[ml] inference: detected=avx2, active=avx2";
/// Seconds to wait for the boot end-marker before giving up. Generous because
/// under software-emulated QEMU (TCG, no KVM) on CI and Claude Code on the web
/// the full bring-up — networking, then seeding + writing the 16 MiB disk image
/// through the PIO ATA driver — can take well over 20 s before the marker prints.
/// The poll below exits the instant the marker appears, so a larger cap only
/// affects the timeout path and never slows a healthy boot.
const BOOT_TIMEOUT_SECS: u64 = 60;

fn do_test() -> ExitCode {
    boot_test(false)
}

/// KVM boot test: boot under real hardware acceleration (`-enable-kvm -cpu host`)
/// so the guest sees x2APIC, then assert the x2APIC **enable** path ran. This is
/// the verification-condition-C1 evidence the TCG boot test cannot produce (TCG
/// does not emulate x2APIC). Requires a host with `/dev/kvm` (real hardware or a
/// KVM-capable CI runner) — it fails fast if KVM cannot initialise.
fn do_test_kvm() -> ExitCode {
    boot_test(true)
}

/// Boot the kernel headless in QEMU, poll the serial log, and assert the boot
/// markers. `kvm = false` is the portable TCG test (CI default); `kvm = true`
/// adds real acceleration + `-cpu host` and additionally requires the x2APIC
/// **enable** line (proving the SMP AP1 write sequence executed on real silicon).
fn boot_test(kvm: bool) -> ExitCode {
    let Some(elf) = build_kernel() else {
        return ExitCode::FAILURE;
    };
    let Some(iso) = build_iso(&elf) else {
        return ExitCode::FAILURE;
    };

    let serial_log = kr("target/serial.log");
    let pcap = kr("target/net.pcap");

    // Remove stale log + pcap from a previous run.
    let _ = fs::remove_file(&serial_log);
    let _ = fs::remove_file(&pcap);

    // Base machine args, then the acceleration/CPU model differs by mode.
    let serial_arg = format!("file:{}", serial_log.display());
    let mut qargs: Vec<String> = vec!["-M".into(), "q35".into()];
    if kvm {
        // Real KVM acceleration with host-CPU passthrough: the host advertises
        // x2APIC (every modern CPU has it), so `enable_bsp` takes the enable path
        // instead of the TCG fallback. `-cpu host` requires the KVM accelerator.
        qargs.push("-enable-kvm".into());
        qargs.push("-cpu".into());
        qargs.push("host".into());
    } else {
        // SMEP/SMAP/UMIP (Haswell base + explicit flags) so cpu_security enables
        // them. x2APIC is intentionally NOT requested: TCG cannot emulate it, so
        // the kernel takes its no-op fallback (the enable path is what the KVM
        // variant proves). See docs/specs/2026-07-14-smp-x2apic-design.md.
        qargs.push("-cpu".into());
        qargs.push("Haswell,+smep,+smap,+umip".into());
    }
    // `-smp 4` gives the guest four logical CPUs for the SMP path.
    for a in [
        "-smp",
        "4",
        "-m",
        "256M",
        "-cdrom",
        iso.to_str().unwrap(),
        "-serial",
        &serial_arg,
        "-display",
        "none",
        "-no-reboot",
    ] {
        qargs.push(a.into());
    }

    println!(
        "Launching QEMU ({}) ...",
        if kvm { "KVM + -cpu host" } else { "TCG" }
    );
    println!("NIC: e1000 on SLIRP; frames captured to {}", pcap.display());

    // Spawn QEMU in the background; direct COM1 to a file so we can poll it. The
    // e1000 NIC + SLIRP backend + filter-dump pcap let the test confirm the NIC
    // brings up and frames cross the wire (inspect target/net.pcap).
    let mut child = Command::new("qemu-system-x86_64")
        .args(&qargs)
        .args(e1000_args(pcap.to_str().unwrap()))
        .args(disk_args())
        .spawn()
        .expect("failed to spawn qemu-system-x86_64");

    // Poll every 200 ms up to BOOT_TIMEOUT_SECS (safety cap) until the marker appears.
    let deadline = Instant::now() + Duration::from_secs(BOOT_TIMEOUT_SECS);
    let poll_interval = Duration::from_millis(200);
    let mut found = false;

    while Instant::now() < deadline {
        std::thread::sleep(poll_interval);
        let log = fs::read_to_string(&serial_log).unwrap_or_default();
        if log.contains(END_MARKER) {
            found = true;
            break;
        }
    }

    // Always kill QEMU after we're done polling (it halts forever in `halt_loop`).
    let _ = child.kill();
    let _ = child.wait();

    // Read final log (may have grown slightly after the last poll).
    let log = fs::read_to_string(&serial_log).unwrap_or_default();
    println!("--- serial.log ---");
    println!("{}", log);
    println!("--- end serial.log ---");

    if !found {
        eprintln!(
            "TEST FAILED: end-marker '{}' not found within {} s.",
            END_MARKER, BOOT_TIMEOUT_SECS
        );
        return ExitCode::FAILURE;
    }

    if !log.contains(BANNER_LINE) {
        eprintln!(
            "TEST FAILED: end-marker present but banner line '{}' missing.",
            BANNER_LINE
        );
        return ExitCode::FAILURE;
    }

    if !log.contains(SMP_MARKER) {
        eprintln!(
            "TEST FAILED: end-marker present but SMP bring-up line '{}' missing.",
            SMP_MARKER
        );
        return ExitCode::FAILURE;
    }

    // Under KVM the guest sees x2APIC, so the *enable* path (not the fallback)
    // must have run — this is the C1 evidence the TCG test cannot produce.
    if kvm && !(log.contains(SMP_ENABLED_MARKER) && log.contains(SMP_TIMER_LIVE_MARKER)) {
        eprintln!(
            "KVM TEST FAILED: expected the x2APIC enable line '{} … {}' \
             (the enable path did not run — is x2APIC exposed under `-cpu host`?).",
            SMP_ENABLED_MARKER, SMP_TIMER_LIVE_MARKER
        );
        return ExitCode::FAILURE;
    }

    // The AVX2 int8-GEMM self-test must pass (both TCG and KVM), so the ML tier is
    // the AVX2 vector kernel — proving the hand-written `asm!` kernel executes and
    // computes correctly. `-cpu Haswell` (TCG) and `-cpu host` (KVM) both expose
    // avx2, so this holds in either mode; a scalar fallback here means the vector
    // kernel is wrong or avx2 is unexpectedly absent.
    if !log.contains(ML_AVX2_ACTIVE) {
        eprintln!(
            "TEST FAILED: expected the ML line '{}' (the AVX2 self-test should pass \
             where avx2 is exposed — did the vector kernel regress?).",
            ML_AVX2_ACTIVE
        );
        return ExitCode::FAILURE;
    }

    if kvm {
        println!(
            "KVM TEST PASSED: x2APIC ENABLE path proven — '{}' with '{}' — and the \
             AVX2 int8-GEMM tier verified active ('{}'), plus banner + end-marker '{}'.",
            SMP_ENABLED_MARKER, SMP_TIMER_LIVE_MARKER, ML_AVX2_ACTIVE, END_MARKER
        );
    } else {
        println!(
            "TEST PASSED: full banner, SMP bring-up line, AVX2 tier active, and \
             end-marker '{}' confirmed in serial output.",
            END_MARKER
        );
    }
    ExitCode::SUCCESS
}

// ── screenshot ─────────────────────────────────────────────────────────────────

/// Python script template used to drive QMP and capture a PNG screendump.
///
/// The script:
///   1. Connects to the QMP unix socket (retries up to 15 s — QEMU may not be ready yet).
///   2. Reads the QMP greeting.
///   3. Sends `qmp_capabilities` to enter command mode.
///   4. Sends `screendump` with PNG format.
///   5. Prints "SCREENDUMP_OK" on success, exits non-zero on any error.
const QMP_SCRIPT: &str = r#"
import socket, json, sys, time, pathlib

sock_path = sys.argv[1]
png_path  = sys.argv[2]

# Retry connecting — QEMU may not have created the socket yet.
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
deadline = time.monotonic() + 15.0
while True:
    try:
        s.connect(sock_path)
        break
    except (FileNotFoundError, ConnectionRefusedError):
        if time.monotonic() > deadline:
            print("QMP_ERROR: socket not available after 15 s", file=sys.stderr)
            sys.exit(1)
        time.sleep(0.25)

def recv_json(sock):
    """Read one complete JSON object from a line-oriented socket."""
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        try:
            return json.loads(buf.decode())
        except json.JSONDecodeError:
            pass  # need more bytes
    return json.loads(buf.decode())

def send_cmd(sock, cmd):
    sock.sendall((json.dumps(cmd) + "\n").encode())

# 1. Read greeting.
greeting = recv_json(s)
print(f"QMP greeting: {greeting.get('QMP', {}).get('version', {}).get('qemu', 'unknown')}", flush=True)

# 2. Enter command mode.
send_cmd(s, {"execute": "qmp_capabilities"})
cap_resp = recv_json(s)
if "error" in cap_resp:
    print(f"QMP_ERROR: qmp_capabilities failed: {cap_resp}", file=sys.stderr)
    sys.exit(1)

# 3. Take screendump.
send_cmd(s, {"execute": "screendump", "arguments": {"filename": png_path, "format": "png"}})
dump_resp = recv_json(s)
if "error" in dump_resp:
    print(f"QMP_ERROR: screendump failed: {dump_resp}", file=sys.stderr)
    sys.exit(1)

print("SCREENDUMP_OK", flush=True)
s.close()
"#;

fn do_screenshot() -> ExitCode {
    let Some(elf) = build_kernel() else {
        return ExitCode::FAILURE;
    };
    let Some(iso) = build_iso(&elf) else {
        return ExitCode::FAILURE;
    };

    let serial_log = kr("target/serial.log");
    // The QMP control socket lives in the system temp dir, NOT under target/:
    // a UNIX socket path must fit in `sockaddr_un.sun_path` (104 bytes on macOS),
    // and a deep checkout/worktree path under target/ blows that limit (QEMU then
    // refuses to start). A short, process-unique temp path keeps screenshots
    // working regardless of how deeply the repo is nested.
    let qmp_sock = std::env::temp_dir().join(format!("sos-qmp-{}.sock", std::process::id()));
    let png_path = kr("target/sentinelos-boot.png");

    // Remove stale artefacts from a previous run.
    let _ = fs::remove_file(&serial_log);
    let _ = fs::remove_file(&qmp_sock);
    let _ = fs::remove_file(&png_path);

    println!("Launching QEMU (headless + QMP socket) ...");

    // Spawn QEMU in background:
    //   - no interactive window (-display none)
    //   - GOP/VGA framebuffer rendered internally (screendump still works)
    //   - QMP control socket for programmatic screendump
    let pcap = kr("target/net.pcap");
    let _ = fs::remove_file(&pcap);
    let mut child = Command::new("qemu-system-x86_64")
        .args([
            "-M",
            "q35",
            // SMEP/SMAP/UMIP so cpu_security enables them; `-smp 4` gives the guest
            // four logical CPUs for the SMP path. x2APIC is intentionally NOT
            // requested: TCG cannot emulate it, so the kernel takes its no-op
            // fallback (the enable path activates under KVM / real hardware). See
            // docs/specs/2026-07-14-smp-x2apic-design.md.
            "-cpu",
            "Haswell,+smep,+smap,+umip",
            "-smp",
            "4",
            "-m",
            "256M",
            "-cdrom",
            iso.to_str().unwrap(),
            "-display",
            "none",
            "-no-reboot",
            "-serial",
            &format!("file:{}", serial_log.display()),
            "-qmp",
            &format!("unix:{},server,nowait", qmp_sock.display()),
        ])
        .args(e1000_args(pcap.to_str().unwrap()))
        .args(disk_args())
        .spawn()
        .expect("failed to spawn qemu-system-x86_64");

    // ── Step 1: wait for boot-bringup-ok in serial log (up to 20 s) ──────────
    println!("Waiting for '{}' in serial log ...", END_MARKER);
    let boot_deadline = Instant::now() + Duration::from_secs(BOOT_TIMEOUT_SECS);
    let mut boot_found = false;
    while Instant::now() < boot_deadline {
        std::thread::sleep(Duration::from_millis(200));
        let log = fs::read_to_string(&serial_log).unwrap_or_default();
        if log.contains(END_MARKER) {
            boot_found = true;
            println!("Boot marker found. Waiting 10 s for full framebuffer draw ...");
            break;
        }
    }

    if !boot_found {
        eprintln!(
            "Timed out waiting for boot marker '{}' ({} s).",
            END_MARKER, BOOT_TIMEOUT_SECS
        );
        let log = fs::read_to_string(&serial_log).unwrap_or_default();
        eprintln!("--- serial.log so far ---\n{}\n---", log);
        let _ = child.kill();
        let _ = child.wait();
        return ExitCode::FAILURE;
    }

    // ── Step 2: wait extra time for the per-pixel framebuffer draw ───────────
    // Under TCG (software emulation) the VGA/GOP pixel-by-pixel draw is slow.
    std::thread::sleep(Duration::from_secs(10));

    // ── Step 3: drive QMP via Python to capture screendump ───────────────────
    println!("Taking screendump via QMP ...");

    // Write the embedded Python script to a temp file.
    let script_path = kr("target/qmp_screenshot.py");
    fs::write(&script_path, QMP_SCRIPT).expect("write qmp_screenshot.py");

    let qmp_out = Command::new("python3")
        .args([
            script_path.to_str().unwrap(),
            qmp_sock.to_str().unwrap(),
            png_path.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run python3");

    let stdout = String::from_utf8_lossy(&qmp_out.stdout);
    let stderr = String::from_utf8_lossy(&qmp_out.stderr);
    println!("QMP stdout:\n{}", stdout);
    if !stderr.is_empty() {
        eprintln!("QMP stderr:\n{}", stderr);
    }

    // ── Step 4: kill QEMU ─────────────────────────────────────────────────────
    let _ = child.kill();
    let _ = child.wait();

    // ── Step 5: verify the PNG ────────────────────────────────────────────────
    if !qmp_out.status.success() || !stdout.contains("SCREENDUMP_OK") {
        eprintln!("SCREENSHOT FAILED: QMP script reported an error.");
        return ExitCode::FAILURE;
    }

    match fs::metadata(&png_path) {
        Ok(meta) if meta.len() > 5_000 => {
            println!(
                "SCREENSHOT SUCCESS: {} ({} bytes)",
                png_path.display(),
                meta.len()
            );
            ExitCode::SUCCESS
        }
        Ok(meta) => {
            eprintln!(
                "SCREENSHOT FAILED: PNG exists but is suspiciously small ({} bytes). \
                 The framebuffer may not have been drawn yet.",
                meta.len()
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("SCREENSHOT FAILED: PNG not found after screendump: {}", e);
            ExitCode::FAILURE
        }
    }
}
