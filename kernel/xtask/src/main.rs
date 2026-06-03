//! xtask — host-side build/run/test driver for the SentinelOS kernel.
//!
//! This crate is a STANDALONE workspace living in `kernel/xtask/`.  It is
//! intentionally NOT a member of the `kernel/` workspace so it builds for the
//! host triple instead of inheriting `build.target = "x86_64-unknown-none"`.
//!
//! # Usage (run from kernel/)
//!
//! ```sh
//! cargo xtask build   # cross-compile kernel for x86_64-unknown-none
//! cargo xtask run     # TODO: needs qemu-system-x86_64 + limine (see below)
//! cargo xtask test    # TODO: needs qemu-system-x86_64 + limine (see below)
//! ```
//!
//! # QEMU / Limine — pending deps
//!
//! `cargo xtask run` and `cargo xtask test` are stubbed until the following
//! tools are available on the build host.  Install them with:
//!
//! ```sh
//! brew install qemu xorriso
//! ```
//!
//! Then fetch a pinned Limine release (e.g. 8.x binary-only):
//!
//! ```sh
//! LIMINE_VER=8.0.4
//! curl -Lo /usr/local/bin/limine \
//!   "https://github.com/limine-bootloader/limine/releases/download/v${LIMINE_VER}/limine-$(uname -m)-unknown-linux"
//! chmod +x /usr/local/bin/limine
//! ```
//!
//! Once both `qemu-system-x86_64` and `limine` are on `$PATH`, replace the
//! TODO stubs in `run()` and `test_kernel()` below.
//!
//! # QEMU invocation (template for when deps land)
//!
//! ```sh
//! qemu-system-x86_64 \
//!   -serial stdio \
//!   -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
//!   -display none \
//!   -no-reboot \
//!   -cdrom target/sentinelos.iso
//! ```

use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("build") => build(),
        Some("run") => run(),
        Some("test") => test_kernel(),
        other => {
            eprintln!(
                "Usage: cargo xtask <build|run|test>\nUnknown subcommand: {:?}",
                other
            );
            ExitCode::FAILURE
        }
    }
}

/// Cross-compile the kernel crate for `x86_64-unknown-none`.
fn build() -> ExitCode {
    // kernel/ workspace root is one directory up from xtask/.
    let kernel_root = {
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop(); // strip xtask/
        p
    };

    println!("Building kernel for x86_64-unknown-none …");

    let status = Command::new("cargo")
        .args([
            "build",
            "--package",
            "kernel",
            "--target",
            "x86_64-unknown-none",
        ])
        .current_dir(&kernel_root)
        .status()
        .expect("failed to spawn cargo");

    if status.success() {
        println!("Build succeeded.");
        ExitCode::SUCCESS
    } else {
        eprintln!("Build failed (exit {})", status);
        ExitCode::FAILURE
    }
}

/// TODO: assemble a Limine bootable ISO and launch QEMU.
///
/// Requires:
///   - `qemu-system-x86_64` on $PATH  (`brew install qemu`)
///   - `xorriso` on $PATH             (`brew install xorriso`)
///   - `limine` on $PATH              (see module-level doc for pinned release URL)
///
/// Until those deps are present this subcommand exits with a clear message.
fn run() -> ExitCode {
    // TODO: once qemu-system-x86_64 + limine are confirmed installed:
    //   1. Call build() to produce the kernel ELF.
    //   2. Use xorriso + limine to assemble target/sentinelos.iso.
    //   3. Exec:
    //        qemu-system-x86_64 \
    //          -serial stdio \
    //          -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    //          -display none \
    //          -no-reboot \
    //          -cdrom target/sentinelos.iso
    eprintln!(
        "cargo xtask run: pending deps — install qemu + xorriso (brew install qemu xorriso) \
         and fetch a pinned limine binary.  See xtask/src/main.rs for exact instructions."
    );
    ExitCode::FAILURE
}

/// TODO: run kernel under QEMU with the isa-debug-exit device for test reporting.
///
/// Same deps as `run()`.  See module-level doc.
fn test_kernel() -> ExitCode {
    // TODO: once qemu-system-x86_64 + limine are confirmed installed:
    //   1. Call build() with a test feature flag.
    //   2. Assemble ISO.
    //   3. Exec QEMU; interpret exit-code from isa-debug-exit:
    //        exit 33 (0x21) → tests passed  (value 0x10 << 1 | 1)
    //        anything else  → tests failed
    eprintln!(
        "cargo xtask test: pending deps — install qemu + xorriso (brew install qemu xorriso) \
         and fetch a pinned limine binary.  See xtask/src/main.rs for exact instructions."
    );
    ExitCode::FAILURE
}
