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
    process::{Command, ExitCode, Stdio},
    time::{Duration, Instant},
};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("build") => do_build(),
        Some("run") => do_run(),
        Some("test") => do_test(),
        Some("test-kvm") => do_test_kvm(),
        Some("check-no-vector") => do_check_no_vector(),
        Some("screenshot") => do_screenshot(),
        Some("boot-timing") => {
            // Default 5 runs: enough for a median plus a visible spread without
            // making the CI job slow.
            let runs = args.next().and_then(|a| a.parse::<usize>().ok()).unwrap_or(5);
            do_boot_timing(runs)
        }
        other => {
            eprintln!(
                "Usage: cargo xtask <build|run|test|test-kvm|check-no-vector|screenshot|boot-timing [runs]>\n\
                 Unknown subcommand: {:?}",
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
/// Logical CPUs every QEMU invocation here is given (`-smp 4`), and therefore the
/// exact CPU count the SMP phase-2 bring-up summary must report as online.
const QEMU_SMP_CPUS: u64 = 4;
/// Prefix of the SMP phase-2 bring-up **summary** line written by
/// `kernel::smp::bring_up_aps` once every application processor has been started
/// (or given up on): `[smp] online=A/B bsp-apic-id=N aps-ok=K aps-failed=F
/// skipped=S`. `A` = CPUs running kernel code, `B` = CPUs tracked (BSP included),
/// `K` = APs that came online **on the expected core** and passed the int8 GEMM
/// proof there. The boot test requires `B == QEMU_SMP_CPUS`, `A == B`, and
/// `K == B - 1`: every AP the bootloader parked is now in the kernel and its own
/// vector state is live and bit-exact. This is the phase-2 proof and it runs
/// under **TCG** (the bootloader's xAPIC INIT-SIPI-SIPI works there), so `make
/// test` — not just the KVM job — gates it.
const SMP_ONLINE_PREFIX: &str = "[smp] online=";
/// Substring of a per-AP failure line (`[smp] cpuN FAILED to start (timeout …)`
/// or `[smp] cpuN NOT started (…)`) — any occurrence fails the boot test.
const SMP_AP_FAILED_MARKERS: [&str; 2] = ["FAILED to start", "NOT started"];
/// Prefix of the SMP PR-2 **per-CPU scheduler** boot-proof line written by
/// `kernel::sched::prove_pinned`: `[sched] pinned: target=cpuN ran-on=cpuN
/// bsp=cpu0 distinct=yes ok`. The BSP placed a task on an application processor
/// (`spawn_on`), sent it a reschedule IPI, and the task recorded — from its own
/// `cpuid` APIC ID — which core it actually ran on. The boot test requires the
/// line to carry [`SCHED_PINNED_DISTINCT_OK`] and end in `ok`: the task ran on
/// the targeted core, and that core is not the BSP. Runs under TCG (xAPIC MMIO
/// IPIs) and KVM (x2APIC IPIs) alike.
const SCHED_PINNED_PREFIX: &str = "[sched] pinned: ";
/// The field of the pinned-proof line asserting the task ran on a core other
/// than the BSP.
const SCHED_PINNED_DISTINCT_OK: &str = "distinct=yes";
/// Prefix of the SMP phase-3 **LAPIC timer** line written by
/// `kernel::interrupts::init_lapic_timer`: `[timer] lapic: N counts/tick (div16)
/// -> 100 Hz scheduler tick on every core; PIT stays wall clock`. Its presence
/// (with [`TIMER_LAPIC_EVERY_CORE`]) proves the BSP calibrated its LAPIC timer
/// against the PIT and moved the scheduler tick onto it — the count every AP then
/// copies. The unavailable/failed variants say `stays on the PIT` instead.
const TIMER_LAPIC_PREFIX: &str = "[timer] lapic: ";
/// The substring of the LAPIC timer line confirming the tick is per-core.
const TIMER_LAPIC_EVERY_CORE: &str = "scheduler tick on every core";
/// Prefix of the SMP phase-3 **AP preemption** proof line written by
/// `kernel::sched::prove_ap_preemptive`: `[sched] ap-preemptive: cpuN
/// gemm-iters=<N> gemm-exact=yes spin-iters=<N> tick-preempted=<N> ok` — the
/// PR-B payoff proof on an application processor. `tick-preempted` counts only
/// switches made by that core's own LAPIC-timer tick (the IPIs that deliver the
/// two tasks are excluded), so `>= 1` is evidence of the AP's tick. Field-checked
/// like the BSP line: `gemm-exact=yes`, both iteration counts `> 0`,
/// `tick-preempted >= 1`, trailing `ok`.
const SCHED_AP_PREEMPTIVE_PREFIX: &str = "[sched] ap-preemptive: ";

/// Component model PR-1 (`docs/specs/2026-09-18-component-model-design.md`
/// §14): the host verified the embedded `hello` component's framed SHA-256 id,
/// refused a one-bit-wrong id before anything ran, instantiated on the native
/// runtime, and got `hello, sentinelos` back through the inbox ring and the
/// envelope codec with the kernel stamping `from` both ways.
const COMP_HELLO_PREFIX: &str = "[comp] hello: ";
/// SMP phase 3b-i: the core-independent monotonic clock. With the BSP's
/// interrupts disabled the PIT must stand still while `kernel::clock::mono_ticks`
/// advances (carried by the APs' LAPIC ticks), and with them enabled it must run
/// at the PIT's rate.
const CLOCK_MONO_PREFIX: &str = "[clock] mono: ";
/// Every field the `[clock] mono:` line must carry, plus a trailing `ok`.
const CLOCK_MONO_REQUIRED: &[&str] = &["pit-frozen=yes", "bsp-stalled-advance=yes", "rate-ok=yes"];
/// Every field the `[comp] hello:` line must carry, plus a trailing `ok`.
const COMP_HELLO_REQUIRED: &[&str] = &[
    "verified=yes",
    "wrong-id=refused",
    "runtime=native",
    "reply=ok",
];
/// The `[ml]` `active=` values that mean a *vector* tier is live — a real SIMD
/// int8-GEMM kernel runs (its boot self-test passed), not the scalar fallback. We
/// accept **any** implemented vector tier because the runner fleet is heterogeneous:
/// TCG (`-cpu Haswell`) and older KVM hosts run the 256-bit `avx2` kernel, KVM hosts
/// that expose AVX-512 run the 512-bit `avx512f` kernel, and those that also expose
/// VNNI run the fused `avx512-vnni` (`VPDPBUSD`) kernel. We do NOT assert the
/// `detected=…` field: it is the best tier the CPU *advertises* and legitimately
/// varies further (up to `amx-int8` on newer silicon), whereas `active` is the best
/// *implemented* tier. All three vector tiers are proven bit-identical to scalar
/// (boot self-test + host differential tests).
const ML_VECTOR_ACTIVE: [&str; 3] = [
    ", active=avx2;",
    ", active=avx512f;",
    ", active=avx512-vnni;",
];
/// The boot-proof result substring: the live-dispatch `identity·B == B` int8 GEMM
/// computed the right answer end-to-end (see `kernel::ml::prove`). Asserting it
/// alongside a vector `active=` tier proves the vector kernel not only was selected
/// but produced the correct result in the booted kernel.
const ML_GEMM_OK: &str = "int8 GEMM ok";
/// The MLP inference boot-proof result (see `kernel::ml::infer_prove`): a real
/// batched quantized 2-layer MLP forward pass (quantize → GEMM → dequant → ReLU →
/// requant → GEMM) whose final int32 accumulator checksum is a fixed, tier-
/// independent constant. Asserting the exact checksum proves end-to-end *inference*
/// — not just a bare GEMM — computed the expected result on the active tier.
///
/// This spans `infer_prove`'s pass/fail branch point (`" ok"` vs `" FAIL"`) THROUGH
/// the checksum digits in one contiguous string, deliberately: `infer_prove` prints
/// `"; acc2 checksum=<n>"` unconditionally (pass or fail), so matching the checksum
/// digits alone would be a vacuous gate that never actually distinguishes a failing
/// run. Requiring the literal text `"ok; acc2 checksum=240475"` as one substring
/// means the log can only contain it if the pass branch was taken (printing `" ok"`)
/// AND the checksum was exactly 240475 immediately after — either alone would not
/// satisfy the match.
const ML_MLP_OK: &str = "ok; acc2 checksum=240475";
/// The interrupts-on GEMM proof result (see `kernel::ml::prove_interrupts_on`):
/// vector GEMMs run bit-exact in a loop with interrupts ENABLED and the PIT firing,
/// so timer IRQs land mid-GEMM (each running the `isr_common` per-IRQ `XSAVE`).
/// `-> ok` requires every result held AND the timer actually advanced, so asserting
/// it proves the interrupts-off precondition is genuinely lifted.
const ML_IRQ_OK: &str = "timer ticks -> ok";
/// The transformer-block inference boot-proof result (see
/// `kernel::ml::infer_block_prove`, inference workload 2 — see
/// `docs/specs/2026-07-16-inference-workload2-design.md`): a real quantized
/// pre-norm transformer block (layernorm → multi-head self-attention with
/// per-head int8 `QKᵀ`/`P·V` GEMMs → residual → layernorm → the existing FFN →
/// residual) whose requantized output checksum is a fixed, tier-independent
/// constant. Asserting the exact checksum proves the attention GEMM shapes
/// (not just the MLP's plain dense shapes) and the two new libm-free
/// primitives (softmax, layernorm) all computed the expected result on the
/// active tier.
///
/// Spans `infer_block_prove`'s pass/fail branch point (`" ok"` vs `" FAIL"`)
/// THROUGH the checksum digits in one contiguous string, exactly like
/// [`ML_MLP_OK`]: `infer_block_prove` prints `"; tfb checksum=<n>"`
/// unconditionally (pass or fail), so matching the checksum digits alone would
/// be a vacuous gate. Requiring the literal text `"ok; tfb checksum=4332"` as
/// one substring means the log can only contain it if the pass branch was
/// taken (printing `" ok"`) AND the checksum was exactly 4332 immediately
/// after — either alone would not satisfy the match.
const ML_TFB_OK: &str = "ok; tfb checksum=4332";
/// The PR-A/PR-B cooperative-scheduler boot-proof's **verdict-line prefix**
/// (see `kernel::sched::prove_cooperative` /
/// `kernel::sched::validate_cooperative_sequence`): two kernel threads ("A",
/// "B") each print-and-record then voluntarily yield, a fixed 3 times each,
/// interleaved with the adopted idle task (`kmain`) yielding until both exit
/// and the ready queue drains. `prove_cooperative` prints THREE lines sharing
/// the `"[sched] cooperative: "` text — a diagnostic raw sequence line, this
/// verdict line, and a diagnostic deferred-tick-preemptions line — so this
/// longer prefix (through `"interleave="`) is what actually locates the one
/// that matters here.
///
/// # Why phase is not asserted (issue #21 defect 3)
///
/// The original marker asserted one fixed, exact string —
/// `"[sched] cooperative: A0 B0 A1 B1 A2 B2 ok"` — reasoning that
/// cooperative round-robin has no dependence on wall-clock timing. That
/// reasoning stopped being true the moment PR-B wired the timer live: this
/// is a genuinely **preemptive** kernel, and a freshly-spawned task's
/// `task_prologue` unconditionally resets its preempt-disable depth to `0`
/// and opens the interrupt window the instant it starts running — before
/// its own first `print_marker_atomic` call ever reaches its own
/// `preempt_disable`. On real KVM CI (this defect's origin — issue #21,
/// defect 3) a burst of PIT ticks that piled up while the guest was
/// descheduled was observed to land and drain in exactly that window,
/// preempting task "A" before its very first print and handing task "B" the
/// CPU first — producing the still-valid, still-strictly-alternating,
/// still-correctly-per-task-ordered sequence `B0 A0 B1 A1 B2 A2` instead of
/// `A0 B0 A1 B1 A2 B2`. A preemptive kernel simply does not guarantee which
/// task's first print wins that race, so asserting one fixed phase was
/// wrong.
///
/// What a round-robin scheduler DOES still guarantee regardless of phase —
/// strict alternation (Invariant #4) and each task's own internal iteration
/// order — is exactly what this verdict line's individual fields assert
/// instead, mirroring [`SCHED_PREEMPTIVE_PREFIX`]'s field-based style
/// ([`SCHED_COOPERATIVE_INTERLEAVE_OK`]/[`SCHED_COOPERATIVE_ORDER_OK`]/
/// [`SCHED_COOPERATIVE_ITERS_OK`] below) rather than one exact-string phase
/// assertion. A mismatch on any field still means either the round-robin
/// queue policy regressed (Invariant #4) or the register/stack switch
/// (`hal::context::switch`/`sentinel_gpr_switch`) corrupted a task's
/// execution — the same failure modes the old marker caught, just without
/// the spurious phase requirement.
const SCHED_COOPERATIVE_PREFIX: &str = "[sched] cooperative: interleave=";
/// Required substring of a **passing** cooperative verdict line: strict
/// alternation — no task appeared twice in a row, checked from EITHER
/// starting phase. See [`SCHED_COOPERATIVE_PREFIX`]'s docs.
const SCHED_COOPERATIVE_INTERLEAVE_OK: &str = "interleave=strict";
/// Required substring of a **passing** cooperative verdict line: each task's
/// own recorded iterations ran `0, 1, 2` in exactly that order (no gap,
/// repeat, or reorder), and no unrecognised task letter was recorded.
const SCHED_COOPERATIVE_ORDER_OK: &str = "per-task-order=ok";
/// Required substring of a **passing** cooperative verdict line: both proof
/// tasks completed exactly 3 iterations each. Unlike
/// [`SCHED_PREEMPTIVE_PREFIX`]'s counters, this one IS asserted as a fixed
/// value: PR-A's proof tasks always run exactly `PROOF_ITERATIONS` (3)
/// iterations by construction, so — phase aside — this count is not
/// timing-dependent.
const SCHED_COOPERATIVE_ITERS_OK: &str = "iters=3/3";
/// The PR-B **preemptive**-scheduler boot-proof marker prefix (see
/// `kernel::sched::prove_preemptive`): a "gemm" task (loops a fixed int8
/// GEMM) and a "spin" task (loops a counter) are spawned and **never call
/// `yield_now`** — only the timer (`on_tick`) can switch either of them away.
/// Unlike [`SCHED_COOPERATIVE_ITERS_OK`]'s fixed count, this is **not**
/// asserted as an exact string: the iteration/preemption counts here are
/// inherently timing-dependent
/// (host/TCG speed, scheduling luck), so [`boot_test`] instead checks this
/// prefix is present, that `gemm-exact=yes` appears (bit-exact GEMM results —
/// a mismatch would mean a preemption clobbered a live vector accumulator),
/// and parses out the `preempted=`/`gemm-iters=`/`spin-iters=` counts to
/// assert `preempted >= 1` and both iteration counts `> 0` — proving BOTH
/// tasks progressed AND at least one genuine timer-driven preemption occurred
/// AND the GEMM stayed exact, without depending on exact counts.
const SCHED_PREEMPTIVE_PREFIX: &str = "[sched] preemptive: ";
/// Substring present only on `prove_preemptive`'s passing branch (mirrors
/// `ML_TFB_OK`'s "span the pass/fail branch point" technique): `gemm-exact=`
/// is printed unconditionally (`yes` or `no`), so requiring the literal
/// `yes` — not just the field's presence — means this can only match a run
/// where every GEMM iteration was bit-exact.
const SCHED_PREEMPTIVE_GEMM_EXACT: &str = "gemm-exact=yes";
/// The passing form of `spawn`'s guard-page proof line (see
/// `kernel::sched::spawn`): a read-only page-table walk confirming the guard
/// page just below a freshly-allocated kernel stack is genuinely unmapped
/// (`hal::mm::stack_guard_is_unmapped`). Printed once per `spawn` call (`'A'`
/// and `'B'` in the PR-A boot proof), so requiring it as a substring is enough
/// — it must appear at least once and never be contradicted by
/// [`GUARD_PAGE_MAPPED_MARKER`].
const GUARD_PAGE_UNMAPPED_MARKER: &str = "guard-page unmapped=true";
/// The failing form of the same line. This must **never** appear: if the
/// guard page were mapped, a stack overflow would silently corrupt whatever
/// lies below it instead of faulting, defeating the whole point of the guard
/// page. Asserted in both directions alongside
/// [`GUARD_PAGE_UNMAPPED_MARKER`] so neither a missing walk nor a failed one
/// can slip through.
const GUARD_PAGE_MAPPED_MARKER: &str = "guard-page unmapped=false";
/// Seconds to wait for the boot end-marker before giving up. Generous because
/// under software-emulated QEMU (TCG, no KVM) on CI and Claude Code on the web
/// the full bring-up — networking, then seeding + writing the 16 MiB disk image
/// through the PIO ATA driver — can take well over 20 s before the marker prints.
/// The poll below exits the instant the marker appears, so a larger cap only
/// affects the timeout path and never slows a healthy boot.
const BOOT_TIMEOUT_SECS: u64 = 60;

/// Parse the decimal number immediately following `field` (e.g.
/// `"preempted="`) in `line`, if present. Used to check the PR-B preemptive
/// boot proof's (inherently timing-dependent) counters — `preempted >= 1`,
/// `gemm-iters > 0`, `spin-iters > 0` — rather than an exact string, since
/// those counts vary run to run (host/TCG speed, scheduling luck). Returns
/// `None` if `field` is absent or is not followed by at least one ASCII
/// digit.
fn parse_u64_after(line: &str, field: &str) -> Option<u64> {
    let after = line.split_once(field)?.1;
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

/// Parse the SMP bring-up summary (`[smp] online=A/B … aps-ok=K …`, see
/// [`SMP_ONLINE_PREFIX`]) into `(A, B, K)`; `None` if any field is malformed.
fn parse_smp_summary(line: &str) -> Option<(u64, u64, u64)> {
    let online = parse_u64_after(line, "online=")?;
    let after_online = line.split_once("online=")?.1;
    let tracked = parse_u64_after(after_online, "/")?;
    let aps_ok = parse_u64_after(line, "aps-ok=")?;
    Some((online, tracked, aps_ok))
}

/// Check whether a cooperative-scheduler boot-proof **verdict** line (see
/// [`SCHED_COOPERATIVE_PREFIX`]'s docs) reports every required field
/// passing: strict interleave, in-order per-task iterations, and the
/// expected iteration count for both tasks — deliberately NOT checking which
/// task's entries came first (issue #21 defect 3: phase is a genuine race
/// on a preemptive kernel, not something this test can or should pin down).
///
/// Pure string logic, so this is directly unit-testable without booting a
/// kernel (mirrors [`parse_u64_after`]'s host-testability rationale). The
/// three required substrings and the trailing `"ok"` cannot simultaneously
/// hold on a line the kernel-side verdict logic considers failing (see
/// `kernel::sched::validate_cooperative_sequence`'s `ok()` gate) — so this
/// check is two-sided in effect even though it is written as one positive
/// substring/suffix test, exactly like the individual-field checks already
/// used for [`SCHED_PREEMPTIVE_PREFIX`].
fn coop_verdict_passed(line: &str) -> bool {
    line.contains(SCHED_COOPERATIVE_INTERLEAVE_OK)
        && line.contains(SCHED_COOPERATIVE_ORDER_OK)
        && line.contains(SCHED_COOPERATIVE_ITERS_OK)
        && line.trim_end().ends_with("ok")
}

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

/// Symbol-name substrings that may legitimately contain vector instructions: the
/// **`hal::simd` module**, the **`isr_common`** ISR entry stub, the
/// **`hal::cpu::xrstor`** primitive, and **`hal::context::switch`** (the
/// scheduler's per-task vector-save bracket), and nothing else. Vector code is
/// confined to `hal::simd` (the GEMM `asm!` kernels + the `xsave`/`xrstor`
/// self-test); it must never appear in interrupt-handler code (in
/// `hal::pit`/`keyboard`/`mouse`/`idt` or any `kernel` module) — **except** three
/// audited, deliberate cases:
///   - `isr_common` itself, whose gated per-IRQ `xsave`/`xrstor` (hal-tcb I1) is the
///     mechanism that makes the "handlers are vector-free" invariant hold in the
///     first place, so it must be allowlisted rather than flagged.
///   - `hal::cpu::xrstor`, the shared `pub(crate)` primitive (hal-tcb C14): in an
///     unoptimized (`cargo build`, no `-O`) kernel build, `#[inline]` is only a
///     hint, so a caller's call site stays under the caller's own symbol but the
///     `xrstor` instruction itself is outlined into its own `hal::cpu::xrstor`
///     symbol — whose *body* legitimately contains the literal instruction.
///   - `hal::context::switch` (hal-tcb CX4, the scheduler design doc's
///     eager per-task vector-save bracket around `hal::context::switch`'s register
///     swap): this function does **not** itself contain a vector instruction — it
///     *calls* the already-audited `cpu::xsave`/`cpu::xrstor` (a real, un-inlined
///     `call`, not inlined vector asm). The one line this guard would otherwise
///     flag here is `call ... <hal::cpu::xrstor>` — the disassembler prints the
///     call *target's* symbol name as part of the instruction text, and that name
///     happens to contain the substring `"xrstor"` (a `VECTOR_CLOBBER_MNEMONICS`
///     entry), even though no `xrstor` instruction executes in `switch` itself.
///     The exemption in [`find_vector_violations`] is **whole-symbol**, not
///     per-instruction: once `current` (the enclosing function name) matches an
///     allowlist entry, *every* line until the next function header is skipped,
///     so an actual vector instruction placed inside `switch` would **not** be
///     flagged either. This entry is needed only to suppress the `xrstor`-text
///     false positive above; it is safe to grant precisely because `switch` is
///     itself audited TCB asm (hal-tcb §9, CX4) reviewed line-by-line, not
///     because the guard independently re-checks its body for real vector
///     instructions.
///     `hal::cpu::xsave`'s call site does **not** need this treatment: `"xsave"`
///     is deliberately absent from `VECTOR_CLOBBER_MNEMONICS` (it only reads
///     registers to memory, never clobbers), so a `call ... <hal::cpu::xsave>`
///     line never matches in the first place.
///
/// Matching the **module path** (rather than the four specific GEMM symbols) is
/// robust to the compiler inlining the `#[inline]` `madd` helpers into their
/// `_impl` callers — the vector instructions stay under a `hal::simd` symbol either
/// way. Both the mangled (`3hal4simd`, `3hal3cpu6xrstor`, `3hal7context6switch`) and
/// demangled (`hal::simd`, `hal::cpu::xrstor`, `hal::context::switch`) forms are
/// listed so the guard works whether or not objdump demangles.
const VECTOR_CODE_ALLOWLIST: &[&str] = &[
    "3hal4simd",
    "hal::simd",
    "isr_common",
    "3hal3cpu6xrstor",
    "hal::cpu::xrstor",
    "3hal7context6switch",
    "hal::context::switch",
];

/// Operand-less mnemonics that clobber vector **data**/control state but carry no
/// `%xmm/%ymm/%zmm` operand text, so the operand scan alone would miss them.
/// `xrstor`/`fxrstor`/`ldmxcsr` **load** (overwrite) vector or MXCSR state from
/// memory and are therefore included — a stray one outside `hal::simd`/`isr_common`
/// would silently clobber live vector state. Save ops (`xsave`/`fxsave`/`stmxcsr`)
/// are deliberately excluded: they only *read* registers to memory, they never
/// clobber register state, so they cannot violate the "handlers are vector-free"
/// invariant this guard enforces. The soft-float target cannot emit any of these,
/// but the guard covers them so it stays honest.
const VECTOR_CLOBBER_MNEMONICS: &[&str] =
    &["vzeroupper", "vzeroall", "xrstor", "fxrstor", "ldmxcsr"];

/// Pure core of [`do_check_no_vector`]: given `objdump -d` text and an allowlist of
/// symbol-name substrings, return `(symbol, instruction)` for every vector
/// instruction found in a **non**-allowlisted function. Detects a vector register
/// operand (`%xmm`/`%ymm`/`%zmm`/`%k0`–`%k7`) or a [`VECTOR_CLOBBER_MNEMONICS`] op.
/// Split out (no I/O) so it can be unit-tested against synthetic disassembly — see
/// the `tests` module, which checks it both flags a planted instruction and does not
/// flag one inside `hal::simd`.
fn find_vector_violations(disasm: &str, allowlist: &[&str]) -> Vec<(String, String)> {
    let mut current = String::new();
    let mut violations: Vec<(String, String)> = Vec::new();
    for line in disasm.lines() {
        // Function header lines look like `<hexaddr> <symbol>:`.
        if line.trim_end().ends_with(">:") {
            if let (Some(lt), Some(gt)) = (line.find('<'), line.rfind('>')) {
                current = line[lt + 1..gt].to_string();
            }
            continue;
        }
        let lower = line.to_ascii_lowercase();
        // objdump (AT&T) prints vector registers `%`-prefixed (`%xmm0`/`%ymm1`/
        // `%zmm2`/`%k3`), so match that form to avoid matching symbol names/immediates.
        let touches_vector = lower.contains("%xmm")
            || lower.contains("%ymm")
            || lower.contains("%zmm")
            || (0..8).any(|d| lower.contains(&format!("%k{d}")))
            || VECTOR_CLOBBER_MNEMONICS.iter().any(|m| lower.contains(m));
        if touches_vector && !allowlist.iter().any(|a| current.contains(a)) {
            violations.push((current.clone(), line.trim().to_string()));
        }
    }
    violations
}

/// Guard the "compiled handlers are vector-free" invariant that lets vector GEMM run
/// with interrupts enabled: disassemble the kernel and assert **every** vector
/// instruction lives inside the audited `hal::simd` module ([`VECTOR_CODE_ALLOWLIST`]).
/// If any other function (a future interrupt handler, `memcpy`, …) ever emits a
/// vector instruction, this fails — turning "an IRQ can't clobber vector state" into
/// a machine-checked property. The soft-float `x86_64-unknown-none` target makes this
/// hold today (only the audited kernels use vectors); the guard keeps it true.
fn do_check_no_vector() -> ExitCode {
    let Some(elf) = build_kernel() else {
        return ExitCode::FAILURE;
    };
    println!(
        "Disassembling {} to check for stray vector instructions ...",
        elf.display()
    );
    let out = match Command::new("objdump").arg("-d").arg(&elf).output() {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            eprintln!(
                "objdump failed ({}): {}",
                o.status,
                String::from_utf8_lossy(&o.stderr)
            );
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("could not run objdump: {e}");
            return ExitCode::FAILURE;
        }
    };
    let text = String::from_utf8_lossy(&out);
    let violations = find_vector_violations(&text, VECTOR_CODE_ALLOWLIST);

    if violations.is_empty() {
        println!(
            "check-no-vector PASSED: every vector instruction is inside the \
             audited hal::simd module ({:?}); no interrupt-reachable code uses \
             vectors, so an IRQ cannot clobber an in-flight GEMM.",
            VECTOR_CODE_ALLOWLIST
        );
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "check-no-vector FAILED: {} vector instruction(s) found OUTSIDE the \
             hal::simd module. Non-allowlisted code with vector instructions could \
             run in an interrupt handler and clobber an interrupted GEMM's YMM/ZMM \
             state. Either remove the vector code, or (if it is audited and never \
             runs in a handler) move it into hal::simd.",
            violations.len()
        );
        for (func, insn) in violations.iter().take(40) {
            eprintln!("  in {func}:\n      {insn}");
        }
        ExitCode::FAILURE
    }
}

/// Boot the kernel headless in QEMU, poll the serial log, and assert the boot
/// markers. `kvm = false` is the portable TCG test (CI default); `kvm = true`
/// adds real acceleration + `-cpu host` and additionally requires the x2APIC
/// **enable** line (proving the SMP AP1 write sequence executed on real silicon).
/// The QEMU machine arguments shared by every way this repo boots the kernel
/// ([`boot_test`] and [`do_boot_timing`]).
///
/// Factored out deliberately: a timing harness that constructed its own argument
/// list would silently drift from the one the boot test actually asserts on, and
/// then report numbers for a machine nobody ships. One definition, two callers.
fn qemu_base_args(kvm: bool, iso: &Path, serial_arg: &str) -> Vec<String> {
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
        serial_arg,
        "-display",
        "none",
        "-no-reboot",
    ] {
        qargs.push(a.into());
    }
    qargs
}

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

    let serial_arg = format!("file:{}", serial_log.display());
    let qargs = qemu_base_args(kvm, &iso, &serial_arg);

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

    // SMP phase 2: every application processor the bootloader parked must have
    // come online in the kernel, on the core we expected, and passed the int8 GEMM
    // proof on that core. `-smp 4` fixes the expected counts exactly.
    let Some(smp_line) = log.lines().find(|l| l.contains(SMP_ONLINE_PREFIX)) else {
        eprintln!(
            "TEST FAILED: SMP bring-up summary line '{}…' missing (did \
             `kernel::smp::bring_up_aps` run?).",
            SMP_ONLINE_PREFIX
        );
        return ExitCode::FAILURE;
    };
    let Some((online, tracked, aps_ok)) = parse_smp_summary(smp_line) else {
        eprintln!(
            "TEST FAILED: could not parse the SMP bring-up summary: '{}'",
            smp_line
        );
        return ExitCode::FAILURE;
    };
    if tracked != QEMU_SMP_CPUS || online != tracked || aps_ok != tracked - 1 {
        eprintln!(
            "TEST FAILED: expected every CPU online and every AP verified \
             (online={0}/{0}, aps-ok={1}) under `-smp {0}`, got: '{2}'",
            QEMU_SMP_CPUS,
            QEMU_SMP_CPUS - 1,
            smp_line
        );
        return ExitCode::FAILURE;
    }
    if let Some(bad) = log
        .lines()
        .find(|l| l.contains("[smp] cpu") && SMP_AP_FAILED_MARKERS.iter().any(|m| l.contains(m)))
    {
        eprintln!("TEST FAILED: an application processor failed to start: '{}'", bad);
        return ExitCode::FAILURE;
    }

    // SMP PR-2: the per-CPU scheduler must have run a task on an application
    // processor via a reschedule IPI, and that task must report the targeted
    // core — not the BSP — as the one it ran on.
    let Some(pinned_line) = log.lines().find(|l| l.contains(SCHED_PINNED_PREFIX)) else {
        eprintln!(
            "TEST FAILED: per-CPU scheduler proof line '{}…' missing (did \
             `kernel::sched::prove_pinned` run?).",
            SCHED_PINNED_PREFIX
        );
        return ExitCode::FAILURE;
    };
    if !pinned_line.contains(SCHED_PINNED_DISTINCT_OK) || !pinned_line.trim_end().ends_with("ok") {
        eprintln!(
            "TEST FAILED: the pinned task did not run on the targeted application \
             processor (expected '{}' and a trailing 'ok'): '{}'",
            SCHED_PINNED_DISTINCT_OK, pinned_line
        );
        return ExitCode::FAILURE;
    }

    // SMP phase 3: the LAPIC timer must carry the scheduler tick on every core …
    let Some(timer_line) = log.lines().find(|l| l.contains(TIMER_LAPIC_PREFIX)) else {
        eprintln!(
            "TEST FAILED: LAPIC timer line '{}…' missing (calibration did not run, or \
             the scheduler tick stayed on the PIT).",
            TIMER_LAPIC_PREFIX
        );
        return ExitCode::FAILURE;
    };
    if !timer_line.contains(TIMER_LAPIC_EVERY_CORE) {
        eprintln!(
            "TEST FAILED: the scheduler tick did not move to the LAPIC timer \
             (expected '{}'): '{}'",
            TIMER_LAPIC_EVERY_CORE, timer_line
        );
        return ExitCode::FAILURE;
    }
    // … and an application processor's tick must preempt two non-yielding tasks
    // with the GEMM task's vector state surviving bit-exact.
    let Some(ap_line) = log.lines().find(|l| l.contains(SCHED_AP_PREEMPTIVE_PREFIX)) else {
        eprintln!(
            "TEST FAILED: AP preemption proof line '{}…' missing (did \
             `kernel::sched::prove_ap_preemptive` run?).",
            SCHED_AP_PREEMPTIVE_PREFIX
        );
        return ExitCode::FAILURE;
    };
    let ap_tick_preempted = parse_u64_after(ap_line, "tick-preempted=").unwrap_or(0);
    let ap_gemm_iters = parse_u64_after(ap_line, "gemm-iters=").unwrap_or(0);
    let ap_spin_iters = parse_u64_after(ap_line, "spin-iters=").unwrap_or(0);
    if !ap_line.contains(SCHED_PREEMPTIVE_GEMM_EXACT)
        || ap_tick_preempted < 1
        || ap_gemm_iters == 0
        || ap_spin_iters == 0
        || !ap_line.trim_end().ends_with("ok")
    {
        eprintln!(
            "TEST FAILED: the AP preemption proof did not pass (expected '{}', \
             tick-preempted>=1, both iteration counts > 0, trailing 'ok'): '{}'",
            SCHED_PREEMPTIVE_GEMM_EXACT, ap_line
        );
        return ExitCode::FAILURE;
    }

    // SMP phase 3b-i: the monotonic clock must keep running while the BSP is
    // stalled with interrupts off (only another core can have advanced it), at
    // least two cores must be feeding it, and it must track the PIT's rate.
    let Some(clock_line) = log.lines().find(|l| l.contains(CLOCK_MONO_PREFIX)) else {
        eprintln!(
            "TEST FAILED: monotonic clock proof line '{}…' missing (did \
             `kernel::clock::prove_mono` run?).",
            CLOCK_MONO_PREFIX
        );
        return ExitCode::FAILURE;
    };
    let clock_ticking = parse_u64_after(clock_line, "ticking=").unwrap_or(0);
    if CLOCK_MONO_REQUIRED.iter().any(|f| !clock_line.contains(f))
        || clock_ticking < 2
        || !clock_line.trim_end().ends_with(" ok")
    {
        eprintln!(
            "TEST FAILED: the monotonic clock proof did not pass (expected {:?}, \
             ticking>=2 and a trailing 'ok'): '{}'",
            CLOCK_MONO_REQUIRED, clock_line
        );
        return ExitCode::FAILURE;
    }

    // Component model PR-1: the hello component must verify, the wrong id must
    // be refused, and the reply must come back through the codec.
    let Some(comp_line) = log.lines().find(|l| l.contains(COMP_HELLO_PREFIX)) else {
        eprintln!(
            "TEST FAILED: component host proof line '{}…' missing (did \
             `kernel::host::prove_hello` run?).",
            COMP_HELLO_PREFIX
        );
        return ExitCode::FAILURE;
    };
    if COMP_HELLO_REQUIRED.iter().any(|f| !comp_line.contains(f))
        || !comp_line.trim_end().ends_with(" ok")
    {
        eprintln!(
            "TEST FAILED: the component host proof did not pass (expected {:?} and a \
             trailing 'ok'): '{}'",
            COMP_HELLO_REQUIRED, comp_line
        );
        return ExitCode::FAILURE;
    }

    // A vector int8-GEMM self-test must pass (both TCG and KVM), so the ML tier is a
    // real SIMD kernel — proving the hand-written `asm!` kernels execute and compute
    // correctly. `-cpu Haswell` (TCG) exposes avx2; `-cpu host` (KVM) exposes avx2
    // and, on AVX-512 silicon, avx512f (+ avx512-vnni where present) — so `active=`
    // is one of avx2/avx512f/avx512-vnni, never scalar. A scalar fallback here means
    // a vector kernel is wrong or avx2 is unexpectedly absent.
    let Some(active_tier) = ML_VECTOR_ACTIVE.iter().find(|m| log.contains(**m)) else {
        eprintln!(
            "TEST FAILED: expected one of {:?} in the [ml] line (a vector self-test \
             should pass where avx2/avx512f is exposed — did a vector kernel regress?).",
            ML_VECTOR_ACTIVE
        );
        return ExitCode::FAILURE;
    };
    // ...and it must have computed the boot proof correctly end-to-end.
    if !log.contains(ML_GEMM_OK) {
        eprintln!(
            "TEST FAILED: a vector tier is active but the boot-proof GEMM did not \
             report '{}' (the live vector dispatch produced a wrong result).",
            ML_GEMM_OK
        );
        return ExitCode::FAILURE;
    }

    // The MLP inference proof must have run AND produced the exact expected checksum
    // — proving end-to-end quantized inference (not just a bare GEMM) on the active
    // tier. The checksum is tier-independent, so this holds under both TCG and KVM.
    if !log.contains(ML_MLP_OK) {
        eprintln!(
            "TEST FAILED: the MLP inference proof did not report '{}' \
             (end-to-end quantized inference produced a wrong or missing result).",
            ML_MLP_OK
        );
        return ExitCode::FAILURE;
    }

    // Vector GEMM must stay bit-exact with interrupts ENABLED (the per-IRQ XSAVE +
    // vector-free handlers, proven under real timer pressure) — the lifted
    // interrupts-off precondition.
    if !log.contains(ML_IRQ_OK) {
        eprintln!(
            "TEST FAILED: the interrupts-on GEMM proof did not report '{}' \
             (a timer IRQ corrupted an in-flight GEMM, or the timer never fired).",
            ML_IRQ_OK
        );
        return ExitCode::FAILURE;
    }

    // The quantized transformer-block proof (inference workload 2) must have run
    // AND produced the exact expected checksum — proving one full pre-norm block
    // (attention + FFN), not just the MLP's plain dense shapes, on the active tier.
    if !log.contains(ML_TFB_OK) {
        eprintln!(
            "TEST FAILED: the transformer-block inference proof did not report '{}' \
             (end-to-end quantized attention+FFN produced a wrong or missing result).",
            ML_TFB_OK
        );
        return ExitCode::FAILURE;
    }

    // Guard-paged kernel stacks (design doc item "guard-paged kernel stacks"):
    // `spawn`'s read-only page-table walk must have reported the guard page
    // unmapped, and must never have reported it mapped — checked in both
    // directions so a missing walk and a failed one are equally fatal.
    if !log.contains(GUARD_PAGE_UNMAPPED_MARKER) {
        eprintln!(
            "TEST FAILED: expected '{}' in the [sched] spawn lines (the guard-page \
             unmapped check did not run, or ran and failed silently).",
            GUARD_PAGE_UNMAPPED_MARKER
        );
        return ExitCode::FAILURE;
    }
    if log.contains(GUARD_PAGE_MAPPED_MARKER) {
        eprintln!(
            "TEST FAILED: found '{}' in the [sched] spawn lines (the guard page below \
             a kernel stack is mapped — a stack overflow would silently corrupt memory \
             instead of faulting).",
            GUARD_PAGE_MAPPED_MARKER
        );
        return ExitCode::FAILURE;
    }

    // PR-A/PR-B cooperative-scheduler proof: a property-based verdict, NOT a
    // fixed-phase exact string (see `SCHED_COOPERATIVE_PREFIX`'s docs — issue
    // #21 defect 3: on a preemptive kernel, which task's first print wins the
    // race is not a guarantee this test can make).
    let Some(coop_line) = log.lines().find(|l| l.contains(SCHED_COOPERATIVE_PREFIX)) else {
        eprintln!(
            "TEST FAILED: no line containing '{}' found (the cooperative-scheduler \
             boot proof's verdict line did not print).",
            SCHED_COOPERATIVE_PREFIX
        );
        return ExitCode::FAILURE;
    };
    if !coop_verdict_passed(coop_line) {
        eprintln!(
            "TEST FAILED: the cooperative-scheduler boot proof's verdict line did not \
             report every field passing (expected '{}', '{}', and '{}', ending in \
             'ok' — the round-robin queue policy (Invariant #4) or the register/stack \
             context switch regressed): '{}'",
            SCHED_COOPERATIVE_INTERLEAVE_OK,
            SCHED_COOPERATIVE_ORDER_OK,
            SCHED_COOPERATIVE_ITERS_OK,
            coop_line
        );
        return ExitCode::FAILURE;
    }

    // PR-B preemptive-scheduler proof (the payoff): a compute ("gemm") task
    // and a "spin" task, neither of which ever voluntarily yields, must both
    // have progressed, the GEMM must have stayed bit-exact across every
    // preemption, and at least one genuine timer-driven preemption must have
    // occurred. Counts are timing-dependent, so we parse fields rather than
    // match one exact line (see `SCHED_PREEMPTIVE_PREFIX`'s docs).
    let Some(preempt_line) = log.lines().find(|l| l.contains(SCHED_PREEMPTIVE_PREFIX)) else {
        eprintln!(
            "TEST FAILED: no line containing '{}' found (the PR-B timer-preemption \
             boot proof did not run).",
            SCHED_PREEMPTIVE_PREFIX
        );
        return ExitCode::FAILURE;
    };
    if !preempt_line.contains(SCHED_PREEMPTIVE_GEMM_EXACT) {
        eprintln!(
            "TEST FAILED: the preemptive boot proof did not report '{}' \
             (a timer preemption clobbered a live vector accumulator, or the \
             proof failed outright): '{}'",
            SCHED_PREEMPTIVE_GEMM_EXACT, preempt_line
        );
        return ExitCode::FAILURE;
    }
    let preempted = parse_u64_after(preempt_line, "preempted=").unwrap_or(0);
    let gemm_iters = parse_u64_after(preempt_line, "gemm-iters=").unwrap_or(0);
    let spin_iters = parse_u64_after(preempt_line, "spin-iters=").unwrap_or(0);
    if preempted < 1 {
        eprintln!(
            "TEST FAILED: expected at least 1 timer-driven preemption \
             ('preempted>=1'), got {}: '{}'",
            preempted, preempt_line
        );
        return ExitCode::FAILURE;
    }
    if gemm_iters == 0 || spin_iters == 0 {
        eprintln!(
            "TEST FAILED: expected BOTH the gemm and spin tasks to have made \
             progress (gemm-iters={}, spin-iters={}): '{}'",
            gemm_iters, spin_iters, preempt_line
        );
        return ExitCode::FAILURE;
    }
    if !preempt_line.trim_end().ends_with("ok") {
        eprintln!(
            "TEST FAILED: the preemptive boot proof line did not end in 'ok' \
             (individual fields passed but the overall proof still reported \
             FAIL): '{}'",
            preempt_line
        );
        return ExitCode::FAILURE;
    }

    if kvm {
        println!(
            "KVM TEST PASSED: x2APIC ENABLE path proven — '{}' with '{}' — SMP \
             phase 2 proven ('{}': all {} CPUs online, {} APs GEMM-verified on \
             their own cores), the per-CPU scheduler proven ('{}'), the per-core \
             LAPIC tick proven ('{}'), a vector int8-GEMM tier verified active ('{}' with \
             '{}' and '{}' in the [ml] lines), the cooperative scheduler verdict \
             ('{}'), the preemptive scheduler proof ('{}', preempted={}, \
             gemm-iters={}, spin-iters={}), plus banner + end-marker '{}'.",
            SMP_ENABLED_MARKER,
            SMP_TIMER_LIVE_MARKER,
            smp_line,
            tracked,
            aps_ok,
            pinned_line,
            ap_line,
            active_tier,
            ML_GEMM_OK,
            ML_TFB_OK,
            coop_line,
            SCHED_PREEMPTIVE_GEMM_EXACT,
            preempted,
            gemm_iters,
            spin_iters,
            END_MARKER
        );
    } else {
        println!(
            "TEST PASSED: full banner, SMP bring-up line, SMP phase 2 proven \
             ('{}': all {} CPUs online, {} APs GEMM-verified on their own cores), \
             the per-CPU scheduler proven ('{}'), the per-core LAPIC tick proven \
             ('{}'), vector tier active ('{}' with '{}' and '{}'), the cooperative \
             scheduler verdict ('{}'), the preemptive scheduler proof ('{}', \
             preempted={}, gemm-iters={}, spin-iters={}), the monotonic clock proven \
             ('{}'), the component host proven ('{}'), and end-marker '{}' confirmed \
             in serial output.",
            smp_line,
            tracked,
            aps_ok,
            pinned_line,
            ap_line,
            active_tier,
            ML_GEMM_OK,
            ML_TFB_OK,
            coop_line,
            SCHED_PREEMPTIVE_GEMM_EXACT,
            preempted,
            gemm_iters,
            spin_iters,
            clock_line,
            comp_line,
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

#[cfg(test)]
mod tests {
    use super::{find_vector_violations, VECTOR_CODE_ALLOWLIST};

    // Synthetic `objdump -d` snippets: a function header line followed by AT&T
    // instruction lines. These are the exact shapes `find_vector_violations` parses.

    #[test]
    fn flags_vector_operand_in_a_handler() {
        // A vector instruction inside an interrupt handler (hal::pit::on_tick) — the
        // exact thing the guard exists to catch — must be reported.
        let disasm = "\
ffffffff80100000 <_ZN3hal3pit7on_tick17habcdef0123456789E>:\n\
    100000:\t48 89 e5             \tmov    %rsp,%rbp\n\
    100003:\tc5 f8 57 c0          \tvxorps %xmm0,%xmm0,%xmm0\n";
        let v = find_vector_violations(disasm, VECTOR_CODE_ALLOWLIST);
        assert_eq!(v.len(), 1, "planted vector insn must be flagged");
        assert!(v[0].0.contains("on_tick"), "reports the offending symbol");
    }

    #[test]
    fn allows_vector_operand_inside_hal_simd() {
        // The same instruction inside the audited hal::simd module is allowed.
        let disasm = "\
ffffffff80142360 <_ZN3hal4simd10avx2_madd817h196b7f4f546f12d3E>:\n\
    142360:\tc5 fd fe c9          \tvpaddd %ymm1,%ymm0,%ymm1\n";
        assert!(
            find_vector_violations(disasm, VECTOR_CODE_ALLOWLIST).is_empty(),
            "vector code in hal::simd is permitted"
        );
    }

    #[test]
    fn flags_operandless_vzeroupper_in_handler() {
        // Operand-less vector-clobbering ops (no %xmm/%ymm/%zmm text) must still be
        // caught outside hal::simd.
        let disasm = "\
ffffffff80101000 <_ZN3hal8keyboard9on_key_ev17hcafebabeE>:\n\
    101000:\tc5 f8 77             \tvzeroupper\n";
        let v = find_vector_violations(disasm, VECTOR_CODE_ALLOWLIST);
        assert_eq!(v.len(), 1, "vzeroupper in a handler must be flagged");
    }

    #[test]
    fn flags_opmask_register_in_handler() {
        let disasm = "\
ffffffff80102000 <_ZN6kernel3net4poll17hdeadbeefE>:\n\
    102000:\t62 f1 7c 48 90 c1    \tkmovw  %k1,%k0\n";
        assert_eq!(
            find_vector_violations(disasm, VECTOR_CODE_ALLOWLIST).len(),
            1
        );
    }

    #[test]
    fn ignores_pure_gp_code() {
        // Plain integer code (what every handler compiles to on the soft-float
        // target) is never flagged.
        let disasm = "\
ffffffff80103000 <_ZN3hal3pic3eoi17hfeedfaceE>:\n\
    103000:\t48 89 e5             \tmov    %rsp,%rbp\n\
    103003:\tb0 20                \tmov    $0x20,%al\n\
    103005:\tc3                   \tret\n";
        assert!(find_vector_violations(disasm, VECTOR_CODE_ALLOWLIST).is_empty());
    }

    #[test]
    fn flags_xrstor_in_a_non_allowlisted_handler() {
        // `xrstor` has no %xmm/%ymm/%zmm operand text (it takes a memory operand),
        // but it LOADS vector state, so a stray one outside hal::simd/isr_common
        // must be flagged just like an operand-form vector instruction.
        let disasm = "\
ffffffff80104000 <_ZN3hal5mouse9on_packet17h0011223344556677E>:\n\
    104000:\t48 89 e5             \tmov    %rsp,%rbp\n\
    104003:\t0f ae 0d 00 00 00 00 \txrstor 0x0(%rip)\n";
        let v = find_vector_violations(disasm, VECTOR_CODE_ALLOWLIST);
        assert_eq!(v.len(), 1, "xrstor in a handler must be flagged");
        assert!(v[0].0.contains("on_packet"), "reports the offending symbol");
    }

    #[test]
    fn allows_xrstor_inside_isr_common() {
        // isr_common's gated per-IRQ xrstor (hal-tcb I1) is the one audited
        // exception: it must NOT be flagged even though its symbol is not under
        // hal::simd, because VECTOR_CODE_ALLOWLIST explicitly names it.
        let disasm = "\
ffffffff80105000 <isr_common>:\n\
    105000:\t48 89 e5             \tmov    %rsp,%rbp\n\
    105003:\t0f ae 0f             \txrstor (%rdi)\n";
        assert!(
            find_vector_violations(disasm, VECTOR_CODE_ALLOWLIST).is_empty(),
            "isr_common's audited xrstor is allowlisted, not flagged"
        );
    }

    // ── `parse_u64_after` (PR-B preemptive-proof marker parsing) ────────────

    #[test]
    fn parse_smp_summary_reads_online_tracked_and_aps_ok() {
        use super::parse_smp_summary;

        let line = "[smp] online=4/4 bsp-apic-id=0 aps-ok=3 aps-failed=0 skipped=0";
        assert_eq!(parse_smp_summary(line), Some((4, 4, 3)));
        let partial = "[smp] online=3/4 bsp-apic-id=0 aps-ok=2 aps-failed=1 skipped=0";
        assert_eq!(parse_smp_summary(partial), Some((3, 4, 2)));
        let single = "[smp] online=1/1 bsp-apic-id=0 aps-ok=0 aps-failed=0 skipped=0";
        assert_eq!(parse_smp_summary(single), Some((1, 1, 0)));
        assert_eq!(parse_smp_summary("[smp] online=4/4"), None);
        assert_eq!(parse_smp_summary("[smp] x2APIC not advertised"), None);
    }

    #[test]
    fn parse_u64_after_extracts_the_first_run_of_digits() {
        use super::parse_u64_after;

        let line = "[sched] preemptive: gemm-iters=123 gemm-exact=yes spin-iters=456 \
                     preempted=7 ok";
        assert_eq!(parse_u64_after(line, "gemm-iters="), Some(123));
        assert_eq!(parse_u64_after(line, "spin-iters="), Some(456));
        assert_eq!(parse_u64_after(line, "preempted="), Some(7));
    }

    #[test]
    fn parse_u64_after_returns_none_when_field_absent() {
        use super::parse_u64_after;

        let line = "[sched] preemptive: gemm-iters=1 gemm-exact=no spin-iters=2 \
                     preempted=0 FAIL";
        assert_eq!(parse_u64_after(line, "preempted="), Some(0));
        assert_eq!(parse_u64_after(line, "nope="), None);
    }

    #[test]
    fn parse_u64_after_returns_none_when_no_digits_follow() {
        use super::parse_u64_after;

        assert_eq!(parse_u64_after("preempted=ok", "preempted="), None);
    }

    // ── `coop_verdict_passed` (issue #21 defect 3: property-based
    // cooperative-proof verdict, not a fixed-phase exact string) ───────────

    #[test]
    fn coop_verdict_passed_accepts_the_expected_passing_line() {
        use super::coop_verdict_passed;

        let line = "[sched] cooperative: interleave=strict per-task-order=ok iters=3/3 ok";
        assert!(coop_verdict_passed(line));
    }

    #[test]
    fn coop_verdict_line_is_found_and_passes_regardless_of_the_raw_lines_phase() {
        use super::{coop_verdict_passed, SCHED_COOPERATIVE_PREFIX};

        // Mirrors two real serial logs: the deterministic-queue-policy phase
        // (task A prints first) and the KVM-observed phase (issue #21
        // defect 3: a burst of caught-up PIT ticks preempts task A before
        // its first print, so B goes first). The verdict line is identical
        // either way — that is the whole point of this fix, so both logs
        // must be found and pass.
        let a_first_log = "\
[sched] cooperative: A0 B0 A1 B1 A2 B2 (raw sequence above; not the pass/fail gate)
[sched] cooperative: interleave=strict per-task-order=ok iters=3/3 ok
[sched] cooperative: deferred-tick-preemptions observed=0
";
        let b_first_log = "\
[sched] cooperative: B0 A0 B1 A1 B2 A2 (raw sequence above; not the pass/fail gate)
[sched] cooperative: interleave=strict per-task-order=ok iters=3/3 ok
[sched] cooperative: deferred-tick-preemptions observed=1
";
        for log in [a_first_log, b_first_log] {
            let line = log
                .lines()
                .find(|l| l.contains(SCHED_COOPERATIVE_PREFIX))
                .expect("verdict line present");
            assert!(coop_verdict_passed(line));
        }
    }

    #[test]
    fn coop_verdict_passed_rejects_broken_interleave() {
        use super::coop_verdict_passed;

        let line = "[sched] cooperative: interleave=broken per-task-order=ok iters=3/3 FAIL";
        assert!(!coop_verdict_passed(line));
    }

    #[test]
    fn coop_verdict_passed_rejects_broken_per_task_order() {
        use super::coop_verdict_passed;

        let line = "[sched] cooperative: interleave=strict per-task-order=fail iters=2/3 FAIL";
        assert!(!coop_verdict_passed(line));
    }

    #[test]
    fn coop_verdict_passed_rejects_a_short_iteration_count() {
        use super::coop_verdict_passed;

        let line = "[sched] cooperative: interleave=strict per-task-order=ok iters=2/3 FAIL";
        assert!(!coop_verdict_passed(line));
    }

    #[test]
    fn coop_verdict_passed_rejects_a_line_that_ends_in_fail() {
        use super::coop_verdict_passed;

        // Defensive: even if every field substring matched, the line must
        // still end in "ok", not "FAIL".
        let line = "[sched] cooperative: interleave=strict per-task-order=ok iters=3/3 FAIL";
        assert!(!coop_verdict_passed(line));
    }

    #[test]
    fn sched_cooperative_prefix_does_not_match_the_raw_diagnostic_line() {
        use super::SCHED_COOPERATIVE_PREFIX;

        // The raw sequence line and the deferred-tick-preemptions line share
        // the short `"[sched] cooperative: "` text but not the longer
        // verdict-line prefix (through `"interleave="`) — `boot_test` must
        // only ever match the verdict line, never these diagnostic ones.
        let raw = "[sched] cooperative: (raw sequence above; not the pass/fail gate)";
        let deferred = "[sched] cooperative: deferred-tick-preemptions observed=0";
        assert!(!raw.contains(SCHED_COOPERATIVE_PREFIX));
        assert!(!deferred.contains(SCHED_COOPERATIVE_PREFIX));
    }
}

/// `cargo xtask boot-timing [runs]` — boot the SAME ISO `runs` times and report
/// the wall-clock spread from QEMU launch to [`END_MARKER`].
///
/// Why this exists: a single boot sample says very little on shared CI hardware,
/// and the boot cost that matters is not what any one run reports. This builds
/// once, then re-launches the identical image so only the guest boot varies, and
/// prints min/median/max so a regression shows up as a moved distribution rather
/// than a suspicious one-off.
///
/// Uses [`qemu_base_args`] — the same arguments [`boot_test`] asserts on — plus
/// the same NIC and disk, so the number describes the machine the boot test
/// actually validates. Auto-detects KVM via `/dev/kvm`; the mode is printed,
/// because TCG and KVM numbers are not comparable.
///
/// Polls at 10 ms rather than [`boot_test`]'s 200 ms: at a ~2 s boot, 200 ms
/// granularity is 10% error, which would swamp exactly the differences this is
/// meant to detect.
fn do_boot_timing(runs: usize) -> ExitCode {
    if runs == 0 {
        eprintln!("boot-timing: runs must be >= 1");
        return ExitCode::FAILURE;
    }
    let Some(elf) = build_kernel() else {
        return ExitCode::FAILURE;
    };
    let Some(iso) = build_iso(&elf) else {
        return ExitCode::FAILURE;
    };

    let kvm = Path::new("/dev/kvm").exists();
    let mode = if kvm { "KVM + -cpu host" } else { "TCG" };
    let serial_log = kr("target/serial-timing.log");
    let pcap = kr("target/net-timing.pcap");

    println!("Timing {runs} boot(s) under {mode} ...");

    let mut samples: Vec<u128> = Vec::with_capacity(runs);
    let mut last_log = String::new();

    for run in 1..=runs {
        let _ = fs::remove_file(&serial_log);
        let _ = fs::remove_file(&pcap);
        let serial_arg = format!("file:{}", serial_log.display());

        let start = Instant::now();
        let mut child = Command::new("qemu-system-x86_64")
            .args(qemu_base_args(kvm, &iso, &serial_arg))
            .args(e1000_args(pcap.to_str().unwrap()))
            .args(disk_args())
            // QEMU's own startup chatter would interleave with the per-run
            // lines; the serial log is the signal here.
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn qemu-system-x86_64");

        let deadline = start + Duration::from_secs(BOOT_TIMEOUT_SECS);
        let mut elapsed = None;
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
            let log = fs::read_to_string(&serial_log).unwrap_or_default();
            if log.contains(END_MARKER) {
                elapsed = Some(start.elapsed());
                last_log = log;
                break;
            }
        }
        let _ = child.kill();
        let _ = child.wait();

        match elapsed {
            Some(d) => {
                // Report the preemption evidence per run, not just at the end:
                // the question this tool exists to answer is "did a change make
                // boot faster at the cost of a weaker proof?", and that is only
                // visible if every run's `preempted=` count is on screen next to
                // its time.
                let evidence = last_log
                    .lines()
                    .find(|l| l.contains("[sched] preemptive"))
                    .map(|l| {
                        l.split_whitespace()
                            .find(|w| w.starts_with("preempted="))
                            .unwrap_or("preempted=?")
                            .to_string()
                    })
                    .unwrap_or_else(|| "preempted=<no line>".to_string());
                println!("  run {run}: {} ms  ({evidence})", d.as_millis());
                samples.push(d.as_millis());
            }
            None => {
                eprintln!(
                    "boot-timing: run {run} never reached '{END_MARKER}' within {BOOT_TIMEOUT_SECS} s"
                );
                return ExitCode::FAILURE;
            }
        }
    }

    samples.sort_unstable();
    let n = samples.len();
    println!(
        "\nboot -> '{}' over {} run(s), {}: min {} ms | median {} ms | max {} ms",
        END_MARKER,
        n,
        if kvm { "KVM" } else { "TCG" },
        samples[0],
        samples[n / 2],
        samples[n - 1]
    );

    // The tick-bound proofs are the largest remaining cost in a fast boot, so
    // surface their evidence alongside the timing: a reader can see at a glance
    // whether a faster number came at the price of a weaker proof.
    for line in last_log.lines().filter(|l| {
        l.contains("[sched] preemptive")
            || l.contains("timer-preemptions suppressed")
            || l.contains("[sched] cooperative: interleave")
    }) {
        println!("last run: {}", line.trim());
    }

    ExitCode::SUCCESS
}
