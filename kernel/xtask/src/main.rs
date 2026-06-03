//! xtask — host-side build/run/test driver for the SentinelOS kernel.
//!
//! This crate is a STANDALONE workspace living in `kernel/xtask/`.  It is
//! intentionally NOT a member of the `kernel/` workspace so it builds for the
//! host triple instead of inheriting `build.target = "x86_64-unknown-none"`.
//!
//! # Usage (run from kernel/)
//!
//! ```sh
//! cargo xtask build   # cross-compile the boot binary for x86_64-unknown-none
//! cargo xtask run     # build ISO, launch QEMU with serial output on stdout
//! cargo xtask test    # build ISO, run QEMU ~8s, assert banner in serial.log
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
    time::Duration,
};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("build") => do_build(),
        Some("run") => do_run(),
        Some("test") => do_test(),
        other => {
            eprintln!(
                "Usage: cargo xtask <build|run|test>\nUnknown subcommand: {:?}",
                other
            );
            ExitCode::FAILURE
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

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
            .args(["build", "--package", "boot", "--target", "x86_64-unknown-none"])
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
    fs::copy(kernel_elf, iso_root.join("sentinelos.elf"))
        .expect("copy kernel ELF into iso_root");

    // Copy limine config.
    fs::copy(&limine_conf, iso_root.join("limine.conf"))
        .expect("copy limine.conf into iso_root");

    // Copy Limine BIOS artifacts.
    for name in &["limine-bios.sys", "limine-bios-cd.bin", "limine-uefi-cd.bin"] {
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
    fs::copy(&bootx64_src, efi_boot.join("BOOTX64.EFI"))
        .expect("copy BOOTX64.EFI");

    // Build the ISO with xorriso (standard Limine El-Torito BIOS+UEFI incantation).
    // Flags match the official Limine USAGE.md recipe exactly.
    println!("Building ISO with xorriso ...");
    let ok = run_cmd(Command::new("xorriso").args([
        "-as", "mkisofs",
        "-R", "-r", "-J",
        "-b", "limine-bios-cd.bin",
        "-no-emul-boot",
        "-boot-load-size", "4",
        "-boot-info-table",
        "-hfsplus",
        "-apm-block-size", "2048",
        "--efi-boot", "limine-uefi-cd.bin",
        "-efi-boot-part",
        "--efi-boot-image",
        "--protective-msdos-label",
        iso_root.to_str().unwrap(),
        "-o", iso_path.to_str().unwrap(),
    ]));
    if !ok {
        return None;
    }

    // Install Limine BIOS boot sectors into the ISO.
    println!("Installing Limine BIOS sectors ...");
    let ok = run_cmd(Command::new(&limine_bin).args([
        "bios-install",
        iso_path.to_str().unwrap(),
    ]));
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

    println!("Launching QEMU (serial → stdout, Ctrl-C to quit) ...");
    let ok = run_cmd(
        Command::new("qemu-system-x86_64")
            .args([
                "-M", "q35",
                "-m", "256M",
                "-cdrom", iso.to_str().unwrap(),
                "-serial", "stdio",
                "-display", "none",
                "-no-reboot",
            ]),
    );

    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

fn do_test() -> ExitCode {
    let Some(elf) = build_kernel() else {
        return ExitCode::FAILURE;
    };
    let Some(iso) = build_iso(&elf) else {
        return ExitCode::FAILURE;
    };

    let serial_log = kr("target/serial.log");

    // Remove stale log if present.
    let _ = fs::remove_file(&serial_log);

    println!("Running QEMU for serial capture (8 s) ...");

    // Launch QEMU in the background; write serial to file.
    // macOS has no `timeout`, so we background QEMU manually, sleep, kill it.
    let mut child = Command::new("qemu-system-x86_64")
        .args([
            "-M", "q35",
            "-m", "256M",
            "-cdrom", iso.to_str().unwrap(),
            "-serial", &format!("file:{}", serial_log.display()),
            "-display", "none",
            "-no-reboot",
        ])
        .spawn()
        .expect("failed to spawn qemu-system-x86_64");

    std::thread::sleep(Duration::from_secs(8));

    // Kill QEMU (it halts forever — no self-exit yet; isa-debug-exit is later).
    let _ = child.kill();
    let _ = child.wait();

    // Read serial log.
    let log = fs::read_to_string(&serial_log).unwrap_or_default();
    println!("--- serial.log ---");
    println!("{}", log);
    println!("--- end serial.log ---");

    if log.contains("SentinelOS") {
        println!("TEST PASSED: banner found in serial output.");
        ExitCode::SUCCESS
    } else {
        eprintln!("TEST FAILED: 'SentinelOS' not found in serial output.");
        ExitCode::FAILURE
    }
}
