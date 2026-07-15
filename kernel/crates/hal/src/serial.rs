//! 16550 UART serial driver on COM1 — the kernel's primary console.
//!
//! This module is part of the TCB. It performs raw x86 port I/O (`in`/`out`),
//! which is the only way to talk to the legacy 16550-compatible UART that QEMU
//! exposes at COM1 (I/O port base `0x3F8`). Every `in`/`out` lives inside a
//! single-purpose `unsafe` block with a `// SAFETY:` justification; see
//! `kernel/docs/hal-tcb.md` for the registry.
//!
//! # Concurrency model
//!
//! At bring-up the kernel is single-core and runs with interrupts effectively
//! disabled on the boot path, so contention is minimal. To keep the global
//! writer sound without pulling in an external `spin`/atomics crate, every write
//! through the global console is performed with maskable interrupts disabled for
//! the duration of the write and the prior interrupt state restored afterwards
//! (see `with_console`). This prevents an interrupt handler from re-entering
//! the UART mid-byte and interleaving output. It is **not** a multi-core lock;
//! SMP synchronisation is a sub-project #2 concern.

// Only the bare-metal `inb`/`outb`/`interrupts_enabled` bodies use inline asm; the
// host stubs (`not(target_os = "none")`) do not, so this import is bare-metal-only
// to avoid an unused-import warning on the host test target.
#[cfg(target_os = "none")]
use core::arch::asm;
use core::fmt::{self, Write};

/// I/O port base address of COM1 on a PC-compatible platform.
const COM1_BASE: u16 = 0x3F8;

// ── 16550 register offsets from the port base ──────────────────────────────
//
// When the Divisor Latch Access Bit (DLAB) in the Line Control Register is
// clear, offsets 0 and 1 are the data and interrupt-enable registers; when DLAB
// is set they become the low/high bytes of the baud-rate divisor.
const REG_DATA: u16 = 0; // RBR/THR (DLAB=0) · divisor low (DLAB=1)
const REG_INT_ENABLE: u16 = 1; // IER     (DLAB=0) · divisor high (DLAB=1)
const REG_FIFO_CTRL: u16 = 2; // FCR (write) / IIR (read)
const REG_LINE_CTRL: u16 = 3; // LCR  — holds the DLAB bit
const REG_MODEM_CTRL: u16 = 4; // MCR
const REG_LINE_STATUS: u16 = 5; // LSR  — bit 5 = THR empty

/// Line Status Register bit: Transmit-Holding-Register Empty.
const LSR_THR_EMPTY: u8 = 1 << 5;

/// Read a byte from the given x86 I/O port.
///
/// # Safety
///
/// Port I/O is inherently device-dependent. The caller must ensure `port` names
/// a register that is safe to read and that doing so has no
/// memory-safety-relevant side effects. All call sites in this module read only
/// 16550 UART registers at the fixed COM1 base, which is a pure device read.
#[cfg(target_os = "none")]
#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: `in al, dx` reads one byte from the I/O port in `dx` into `al`.
    // The contract that `port` is a valid, read-safe UART register is delegated
    // to this function's own `# Safety` section and upheld by every caller,
    // which only ever passes a COM1 register offset. The instruction touches no
    // memory (`nomem`) and uses no stack (`nostack`); it does not affect RFLAGS
    // in a way we depend on, but to be conservative we do not claim
    // `preserves_flags`.
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack));
    }
    value
}

/// Host stub for [`inb`]: `in` is a privileged instruction, so on any target
/// other than bare-metal (`target_os = "none"`) — kernel-crate **host unit
/// tests** and Miri, where `hal` is compiled for Linux — executing it would
/// `#GP` (delivered as SIGSEGV) and kill the whole test process. Returns `0xFF`
/// (all status bits set) so any "wait for status bit" poll — e.g.
/// [`Serial::is_transmit_ready`]'s `LSR_THR_EMPTY` check — succeeds immediately
/// instead of spinning forever.
///
/// # Safety
///
/// Trivially safe (no side effects); `unsafe` only to keep one signature with
/// the bare-metal twin.
#[cfg(not(target_os = "none"))]
#[inline]
unsafe fn inb(_port: u16) -> u8 {
    0xFF
}

/// Write a byte to the given x86 I/O port.
///
/// # Safety
///
/// Writing to an arbitrary I/O port can reconfigure or damage hardware and is
/// therefore `unsafe`. The caller must ensure `port` names a register that is
/// safe to write with `value`. All call sites in this module write only
/// 16550 UART configuration/data registers at the fixed COM1 base.
#[cfg(target_os = "none")]
#[inline]
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: `out dx, al` writes the byte in `al` to the I/O port in `dx`. The
    // contract that `port`/`value` are a valid, write-safe UART register pair is
    // delegated to this function's `# Safety` section and upheld by every
    // caller, which only programs COM1 registers. The instruction touches no
    // memory (`nomem`) and no stack (`nostack`).
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack));
    }
}

/// Host stub for [`outb`]: `out` is privileged and would `#GP`→SIGSEGV in a
/// host test process (see [`inb`]'s host stub). Console output is silently
/// dropped on non-bare-metal targets — host tests assert on return values, not
/// serial text, and the QEMU boot test asserts the real serial log.
///
/// # Safety
///
/// Trivially safe (no side effects); `unsafe` only to match the bare-metal twin.
#[cfg(not(target_os = "none"))]
#[inline]
unsafe fn outb(_port: u16, _value: u8) {}

/// A handle to a 16550-compatible UART at a fixed I/O port base.
///
/// `Serial` is a zero-sized-ish value type (it stores only the port base) and
/// implements [`core::fmt::Write`], so it can be used with `write!`/`writeln!`.
/// Construct one with [`Serial::com1`] or drive the global console via the
/// [`crate::print!`] / [`crate::println!`] macros.
#[derive(Clone, Copy, Debug)]
pub struct Serial {
    base: u16,
}

impl Serial {
    /// Create a handle to COM1 (I/O base `0x3F8`).
    ///
    /// This does not touch hardware; call [`Serial::init`] (or the module-level
    /// [`init`]) once before writing to configure the UART.
    #[must_use]
    pub const fn com1() -> Self {
        Self { base: COM1_BASE }
    }

    /// Initialise the UART: 38400 baud, 8 data bits, no parity, 1 stop bit
    /// (8N1), with the FIFO enabled and cleared.
    ///
    /// This is idempotent and infallible on QEMU's emulated COM1; re-running it
    /// simply re-applies the same configuration. The loopback self-test is
    /// intentionally omitted at bring-up to keep the boot path free of failure
    /// branches (the spec treats COM1 init as infallible — see §8).
    pub fn init(self) {
        let base = self.base;
        // SAFETY: every `outb` below targets a documented 16550 register at the
        // fixed COM1 base (`base` + a constant offset in `0..=5`). The values
        // written are the standard, well-defined 8N1 + FIFO programming
        // sequence for a 16550 UART. Writing these configuration registers only
        // affects the UART device; it cannot alias or corrupt Rust-managed
        // memory. `outb`'s safety contract (valid, write-safe port) is therefore
        // satisfied for each call. The ordering matters: we disable interrupts,
        // set DLAB to program the divisor, then clear DLAB to set the data
        // format, configure the FIFO, and assert the modem-control lines.
        unsafe {
            // Disable all UART interrupts (we poll the LSR instead of using IRQs).
            outb(base + REG_INT_ENABLE, 0x00);
            // Enable DLAB so offsets 0/1 address the baud-rate divisor.
            outb(base + REG_LINE_CTRL, 0x80);
            // Divisor = 3 → 115200 / 3 = 38400 baud (low byte then high byte).
            outb(base + REG_DATA, 0x03);
            outb(base + REG_INT_ENABLE, 0x00);
            // Clear DLAB and select 8 data bits, no parity, 1 stop bit (8N1).
            outb(base + REG_LINE_CTRL, 0x03);
            // Enable FIFO, clear receive+transmit FIFOs, 14-byte trigger level.
            outb(base + REG_FIFO_CTRL, 0xC7);
            // Assert DTR + RTS, and OUT2 (required to gate the UART IRQ line on
            // real PCs; harmless on QEMU). No loopback.
            outb(base + REG_MODEM_CTRL, 0x0B);
        }
    }

    /// Return `true` when the transmit holding register is empty and the next
    /// byte may be written without overrunning the UART.
    fn is_transmit_ready(self) -> bool {
        // SAFETY: reads the Line Status Register, a read-only 16550 status
        // register at the fixed COM1 base. Reading it has no side effects beyond
        // clearing latched error bits we do not consult, so it cannot affect
        // memory safety. `inb`'s safety contract (valid, read-safe port) holds.
        let status = unsafe { inb(self.base + REG_LINE_STATUS) };
        (status & LSR_THR_EMPTY) != 0
    }

    /// Write a single byte to the UART, busy-waiting until the transmit holding
    /// register is empty.
    pub fn write_byte(self, byte: u8) {
        while !self.is_transmit_ready() {
            core::hint::spin_loop();
        }
        // SAFETY: writes one byte to the Transmit Holding Register (DLAB=0) at
        // the fixed COM1 base. We only reach this point once the LSR reports the
        // THR is empty, so the write cannot overrun the UART. Writing the data
        // register transmits a byte and has no memory-safety-relevant side
        // effect; `outb`'s safety contract holds.
        unsafe {
            outb(self.base + REG_DATA, byte);
        }
    }

    /// Write a byte slice to the UART, translating `\n` to `\r\n` so output is
    /// well-formed on terminals expecting carriage returns.
    pub fn write_bytes(self, bytes: &[u8]) {
        for &byte in bytes {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }
}

impl Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s.as_bytes());
        Ok(())
    }
}

/// The global COM1 console handle used by [`crate::print!`] / [`crate::println!`].
///
/// `Serial` carries no interior mutability and all UART state lives in the
/// device itself, so sharing one handle across the kernel is sound; the only
/// coordination needed is preventing interleaved writes, which [`with_console`]
/// provides by masking interrupts for the duration of each write.
static CONSOLE: Serial = Serial::com1();

/// Initialise the global COM1 console.
///
/// Call this **once**, early on the boot path, before the first
/// [`crate::print!`]. It is idempotent and infallible on QEMU's COM1.
pub fn init() {
    CONSOLE.init();
}

/// Read the current interrupt-enable flag (RFLAGS.IF) so it can be restored.
///
/// Returns `true` if maskable interrupts were enabled.
#[cfg(target_os = "none")]
#[inline]
fn interrupts_enabled() -> bool {
    let flags: u64;
    // SAFETY: `pushfq` pushes the 64-bit RFLAGS onto the stack and `pop` loads
    // it into `flags`. This reads processor flags and uses the stack in a
    // balanced push/pop pair (so we do NOT set `nostack`); it does not modify
    // RFLAGS itself (`preserves_flags`) and accesses no program memory we model
    // in Rust (`nomem`). Reading the flags cannot violate memory safety.
    unsafe {
        asm!("pushfq; pop {}", out(reg) flags, options(nomem, preserves_flags));
    }
    // Bit 9 of RFLAGS is the interrupt-enable flag (IF).
    (flags & (1 << 9)) != 0
}

/// Host stub for [`interrupts_enabled`]: `pushfq` is unprivileged but Miri
/// cannot interpret inline asm, and on the host the kernel's IF-state model is
/// meaningless anyway. Returns `false` so [`with_console`] never calls the
/// (no-op) enable path — matching the interrupts-off convention of the paths
/// host tests exercise.
#[cfg(not(target_os = "none"))]
#[inline]
fn interrupts_enabled() -> bool {
    false
}

/// Run `f` with maskable interrupts disabled, restoring the previous interrupt
/// state afterwards.
///
/// This is the global console's "no interleaving" guard: it ensures a print
/// cannot be re-entered by an interrupt handler that also prints. The previous
/// `IF` state is saved before masking and re-enabled only if it had been set,
/// so callers that already ran with interrupts disabled stay disabled.
fn with_console<R>(f: impl FnOnce(Serial) -> R) -> R {
    let were_enabled = interrupts_enabled();
    crate::cpu::disable_interrupts();
    let result = f(CONSOLE);
    if were_enabled {
        crate::cpu::enable_interrupts();
    }
    result
}

/// Back-end for the [`crate::print!`] / [`crate::println!`] macros.
///
/// Formats `args` directly onto the global COM1 console with interrupts masked
/// for the duration of the write. Not intended to be called directly — use the
/// macros. A formatting error from the UART writer is intentionally ignored
/// (the writer is infallible in practice and the boot path must not panic).
#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    with_console(|mut serial| {
        // `Serial::write_str` is infallible (always returns `Ok`), so this
        // `write_fmt` cannot fail; we drop the `Result` to keep the print path
        // panic-free per spec §8.
        let _ = serial.write_fmt(args);
    });
}

/// Print a `&str` label followed by `value` as zero-padded 64-bit hex
/// (`0x` + 16 digits) and a newline — **without** `core::fmt`'s argument
/// machinery.
///
/// The exception/fault path runs in contexts where pulling in the full
/// `core::fmt` integer-formatting machinery is undesirable: it routes integer
/// arguments through function-pointer indirection that has proven fragile on the
/// bare-metal target (an early fault while *reporting* a fault is the worst time
/// to discover it). This routine builds the digits into a fixed stack buffer
/// using only arithmetic and a static lookup table, then writes raw bytes to the
/// console, so it is allocation-free, panic-free, and independent of the fmt
/// arg path. Used by the kernel's exception handlers and the IDT self-test.
pub fn print_labeled_hex(label: &str, value: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // "0x" + 16 hex digits.
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    let mut shift = 60i32;
    let mut i = 2;
    while shift >= 0 {
        let nibble = ((value >> shift) & 0xF) as usize;
        buf[i] = HEX[nibble];
        i += 1;
        shift -= 4;
    }
    with_console(|serial| {
        serial.write_bytes(label.as_bytes());
        serial.write_bytes(&buf);
        serial.write_byte(b'\n');
    });
}

/// Print a `&str` label followed by `value` as a decimal `u64` and a newline,
/// **without** `core::fmt`'s argument machinery (see [`print_labeled_hex`] for
/// why the fault path avoids it). Allocation-free and panic-free.
pub fn print_labeled_dec(label: &str, value: u64) {
    // u64 max is 20 digits.
    let mut buf = [0u8; 20];
    let mut n = value;
    let mut i = buf.len();
    // Emit at least one digit (handles value == 0).
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    with_console(|serial| {
        serial.write_bytes(label.as_bytes());
        serial.write_bytes(&buf[i..]);
        serial.write_byte(b'\n');
    });
}

/// Print a `&str` line (no formatting args) followed by a newline.
///
/// A thin, fmt-arg-free convenience for the fault path: it writes the literal
/// bytes and a newline directly. Equivalent to `println!("{}", s)` but without
/// routing through `core::fmt`.
pub fn print_line(s: &str) {
    with_console(|serial| {
        serial.write_bytes(s.as_bytes());
        serial.write_byte(b'\n');
    });
}

/// Write a string slice to the COM1 console (no trailing newline, no `fmt`).
///
/// A `fmt`-free console write: the `core::fmt` machinery that `println!("{}", …)`
/// uses needs GOT/`.rela` relocations that this higher-half, statically-relocated
/// kernel deliberately discards in its linker script, so any `{}` argument
/// formatting **faults** at runtime. This helper (and [`write_dec`]) let early
/// boot code emit dynamic values — numbers, slices — without touching `fmt`.
/// Interrupts are masked for the write, exactly like the macros.
pub fn write_str(s: &str) {
    with_console(|serial| serial.write_bytes(s.as_bytes()));
}

/// Write a `u64` in decimal to the COM1 console (no newline, no `fmt`).
///
/// See [`write_str`] for why a `fmt`-free integer printer is needed on this
/// target. Digits are generated into a fixed stack buffer (max 20 for `u64`)
/// without any heap or `fmt` involvement, then emitted with interrupts masked.
pub fn write_dec(mut value: u64) {
    // A `u64` has at most 20 decimal digits; fill from the end.
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    if value == 0 {
        write_str("0");
        return;
    }
    while value != 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    with_console(|serial| serial.write_bytes(&buf[i..]));
}

/// Print formatted text to the COM1 serial console (no trailing newline).
///
/// Mirrors the standard library `print!`. Available as `hal::print!`.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::serial::_print(::core::format_args!($($arg)*))
    };
}

/// Print formatted text to the COM1 serial console, followed by a newline.
///
/// Mirrors the standard library `println!`. Available as `hal::println!`.
#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n")
    };
    ($($arg:tt)*) => {
        $crate::serial::_print(::core::format_args!("{}\n", ::core::format_args!($($arg)*)))
    };
}
