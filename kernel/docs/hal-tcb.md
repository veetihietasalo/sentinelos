# HAL TCB Registry — SentinelOS

This document is the authoritative registry of **every `unsafe` operation** in
the SentinelOS Trusted Computing Base. The `hal` crate is the *only* crate
permitted to use `unsafe`; the `kernel` crate carries `#![forbid(unsafe_code)]`.
Each entry below names the unsafe primitive, why it is necessary, why it is
sound, and its formal-verification status.

- **Owner:** hal-specialist
- **Scope:** sub-project #1 (boot bring-up) — serial console + CPU primitives;
  sub-project #2 (hardware interrupts) — 8259 PIC remap + EOI (`hal::pic`),
  8254 PIT timer (`hal::pit`), and the `sti`/`int3`/`CR2` CPU primitives;
  sub-project #2a (interrupts) — GDT/TSS/IST, IDT, and the raw ISR stubs;
  sub-project #2 part 1 (memory) — frame allocator, paging, kernel heap +
  `#[global_allocator]` (`hal::mm`, §5); plus the device-MMIO mapping +
  DMA-frame helpers `mm::map_mmio` / `mm::DmaFrame` (§5f) added for the NIC;
  sub-project #3 (input) — the PS/2 (i8042) keyboard on IRQ1 (`hal::keyboard`)
  and the PS/2 mouse on IRQ12 (`hal::mouse`, §2h);
  sub-project #5 (UI, first slice) — the Limine framebuffer surface (`hal::framebuffer`);
  sub-project #6 (networking) — PCI config-space enumeration (`hal::pci`, §6a) and
  the Intel e1000 NIC driver (`hal::e1000`, §6b);
  sub-project #7 (storage) — the legacy ATA (IDE) PIO disk driver (`hal::ata`,
  §7) backing `kernel::fs` on-disk persistence;
  hardware report — the `cpuid` CPU-identification wrapper (`hal::cpuid`, §8)
  behind the shell's `cpuinfo`/`devices` commands;
  SMP (phase 1) — the Local APIC in x2APIC / virtual-wire mode (`hal::apic`, §2i),
  the first step toward multi-core;
  SMP (phase 2) — application-processor bring-up over the Limine MP protocol
  (`hal::smp`, §2k): the sealed per-AP entry sequence (per-AP GDT/TSS/IST via
  `gdt::init_ap`, G6; the shared IDT via `idt::load`, I6; own vector state; own
  LAPIC via `apic::enable_ap`, AP3), plus the **live per-core `CR4.OSXSAVE`
  gate** that replaced the global `VECTOR_SAVE_ARMED` flag in `isr_common` (I1)
  and `context::switch` (CX4);
  AI/ML compute — AVX vector-state enablement + the AVX2/AVX-512F/AVX-512VNNI
  int8 GEMM kernels (`hal::simd`, §2j), gated behind a boot-time SIMD self-test,
  the shared `xsave`/`xrstor` primitives (`hal::cpu`, C13/C14) backing that
  self-test and the per-task context-switch save path, and the per-IRQ
  vector-state save/restore in the shared ISR entry stub (`hal::idt::isr_common`,
  I1) that lets vector GEMM run with interrupts enabled;
  scheduler PR-A — the cooperative kernel-thread context switch (`hal::context`,
  §9): one `global_asm!` register switch, a fabricated first-run frame, and the
  eager per-task `xsave`/`xrstor` bracket around it, plus the guard-paged
  kernel-thread stacks it runs on (`mm::alloc_kernel_stack`, §5g), backing
  `kernel::sched`'s cooperative round-robin scheduler;
  SMP phase 3b-ii — IOAPIC device-IRQ routing: the Limine RSDP and a bounded
  copy-out reader of firmware tables (`hal::acpi`, §2l; parsing is in the safe
  kernel), IOAPIC register access + redirection entries and the
  delivery-path-exact device EOI (`hal::ioapic`, §2m), the LAPIC ISR read and
  LINT0 mask (AP8/AP9), the 8259 mask-all (P6) and the i8042 re-arm drain (K6)
- **Crate lints:** `#![deny(unsafe_op_in_unsafe_fn)]`,
  `#![warn(clippy::undocumented_unsafe_blocks)]` — every `unsafe` block is
  forced to carry a `// SAFETY:` comment.
- **Verification legend:** current status (see §3 for the authoritative detail) —
  Miri is **live** (`.github/workflows/verify.yml` runs it on every kernel change);
  Kani harnesses are **written in-tree** (`#[cfg(kani)]`) but only **discharged by
  the experimental, `continue-on-error` CI `kani` job** — they have never been
  proven live in CI, so until that job is promoted to gating, the always-on host
  tests (and Miri, where applicable) remain the enforced guard, not the Kani
  harnesses; fuzz is still **pending**. "Reasoned" = argued sound by construction
  in the `// SAFETY:` comment and reviewed.

> Note: inline `in`/`out` and most privileged instructions are **not**
> Miri-executable (Miri has no model for x86 port I/O or `hlt`/`cli`/`sti`).
> For those, verification is by manual review + QEMU boot evidence, not Miri.

---

## 1. `hal::serial` — 16550 UART on COM1 (`0x3F8`)

The serial driver is the only source of device I/O in the bring-up TCB. All
hardware access is funnelled through two private primitives, `inb`/`outb`, each
documented with a `# Safety` rustdoc section.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| S1 | `serial.rs` · `inb()` | `in al, dx` (port read) | Only way to read 16550 status/data registers | `unsafe fn` whose `# Safety` requires a read-safe UART port; all callers pass a COM1 register offset (`base + 0..=5`). Pure device read, `nomem`/`nostack`. | Reasoned + QEMU (Miri/Kani/fuzz **pending**) |
| S2 | `serial.rs` · `outb()` | `out dx, al` (port write) | Only way to program/transmit on the 16550 | `unsafe fn` whose `# Safety` requires a write-safe UART port; all callers pass a COM1 register offset with a defined value. Device-only effect, `nomem`/`nostack`. | Reasoned + QEMU (Miri/Kani/fuzz **pending**) |
| S3 | `serial.rs` · `Serial::init()` | block of `outb` calls | 8N1 + FIFO programming sequence | Each `outb` targets a constant COM1 register offset with a standard, well-defined value; affects only the UART device, cannot alias Rust memory. Satisfies `outb`'s contract per call. | Reasoned + QEMU (**pending**) |
| S4 | `serial.rs` · `Serial::is_transmit_ready()` | `inb(base + LSR)` | Poll Transmit-Holding-Register-Empty before writing | Reads the read-only Line Status Register; no side effect relevant to memory safety. Satisfies `inb`'s contract. | Reasoned + QEMU (**pending**) |
| S5 | `serial.rs` · `Serial::write_byte()` | `outb(base + DATA, byte)` | Transmit one byte | Reached only after the LSR reports THR empty, so no overrun; writes the data register, device-only effect. Satisfies `outb`'s contract. | Reasoned + QEMU (**pending**) |
| S6 | `serial.rs` · `interrupts_enabled()` (`pub(crate)`) | `pushfq; pop {}` (read RFLAGS) | Read IF so the console guard can restore prior interrupt state — and, PR-B of the scheduler design doc, so **`kernel::sched`** can save/restore the prior interrupt state around its own short `SCHED`-locking critical sections (re-exposed publicly as [`crate::cpu::interrupts_enabled`], §9). No new `unsafe` op — a second, `pub` call site over the same instruction. | Balanced push/pop reads RFLAGS into a register; `nomem`, `preserves_flags`, stack-balanced (no `nostack`). Reading flags cannot violate memory safety. | Reasoned + QEMU (`kernel::sched`'s `with_interrupts_disabled` guard exercises this read on every `SCHED` accessor call during the PR-B preemptive boot proof, with interrupts genuinely live) |

> **Fault-path printing (no new `unsafe`).** `serial::print_labeled_hex` /
> `print_labeled_dec` / `print_line` build digits into a fixed stack buffer with
> plain arithmetic and write raw bytes through the existing (already-documented)
> `Serial::write_bytes` path — they add **no** new unsafe op. They exist because
> `core::fmt`'s *integer-argument* machinery (the `format_args!("{:#x}", n)`
> path) routes through function-pointer indirection that **page-faults on the
> `x86_64-unknown-none` target** — so an exception reporter using `{:#018x}`
> would fault *while reporting a fault*. The exception/IDT-default handlers and
> the `int3` self-test therefore report via these fmt-arg-free helpers. (String
> literals with no formatted args — the banner, status lines — are unaffected and
> still use `println!`.)

### Concurrency note

The global console (`static CONSOLE: Serial`) is shared, but `Serial` has no
interior mutability — all UART state lives in the device. Writes go through
`with_console`, which (1) masks maskable interrupts (`cli`) on the calling core
for the duration of the write and restores the prior `IF` state (`sti` only if
it had been set), so an interrupt handler on the same core can never re-enter
the UART mid-byte, and (2) — since SMP phase 2 put every core in the kernel —
holds the cross-core `CONSOLE_LOCK` (`hal::sync::SpinMutex<()>`) around the
write so two cores cannot interleave bytes. The lock is taken **after**
interrupts are masked (a holder can never be interrupted by a handler wanting
the same lock on its own core). The wait is **bounded** (`try_lock` in a loop,
`CONSOLE_LOCK_SPIN_LIMIT` iterations, then write anyway): the console is the
fault-report channel of last resort, and a `#DF`/`#GP` handler must still get
its report out past a core that halted mid-print. No new `unsafe` — the lock is
the safe `SpinMutex` API (§5e).

## 2. `hal::cpu` — CPU primitives

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| C1 | `cpu.rs` · `disable_interrupts()` | `cli` | Mask maskable interrupts for critical sections | Clears RFLAGS.IF only; affects interrupt-delivery timing, never memory validity/aliasing. `nomem`/`nostack`; not `preserves_flags` (modifies IF). | Reasoned (**pending**) |
| C2 | `cpu.rs` · `enable_interrupts()` | `sti` | Re-open the interrupt window after a critical section | Sets RFLAGS.IF only; not itself UB. At bring-up no IDT/handlers exist, so this is for symmetry; handler safety is the IDT owner's responsibility (sub-project #2). | Reasoned (**pending**) |
| C3 | `cpu.rs` · `halt()` | `hlt` (single) | Idle the core until the next interrupt | Idles the CPU; accesses no memory/registers; `preserves_flags`. Cannot violate memory safety. | Reasoned (**pending**) |
| C4 | `cpu.rs` · `halt_loop()` | `hlt` (in a `loop`) | Terminal park for boot path + panic handler (`-> !`) | Same as C3; re-halts on every wake so the core never spins hot and never falls through. Diverging, safe wrapper. | Reasoned (**pending**) |
| C5 | `cpu.rs` · `breakpoint()` | `int3` (vector 3) | One-shot runtime self-test of the live IDT (the `[selftest]` boot line) | Software interrupt that vectors through the IDT's gate 3; touches no memory (`nomem`); the CPU's interrupt-frame push is balanced by the ISR stub. With a resumable #BP handler it returns; with none, `hal`'s default reporter halts. Cannot create UB. | Reasoned + QEMU (`int3` → #BP, resumes) |
| C6 | `cpu.rs` · `read_cr2()` | `mov {}, cr2` (read CR2) | Report the faulting linear address in the #PF handler | Pure read of the CR2 control register at CPL 0; accesses no program memory (`nomem`), no stack (`nostack`), `preserves_flags`. Observing the last faulting address cannot affect memory validity/aliasing. | Reasoned + QEMU |
| C7 | `cpu.rs` · `read_cr4()` | `mov {}, cr4` (read CR4) | Inspect which hardware protections (SMEP/SMAP/UMIP/PAE/PGE) are active | Pure read of CR4 at CPL 0; `nomem`/`nostack`/`preserves_flags`. Observing a control register cannot affect memory validity/aliasing. Exposed **safe**. | Reasoned + QEMU |
| C8 | `cpu.rs` · `write_cr4()` (`pub(crate) unsafe`) | `mov cr4, {}` (write CR4) | Enable SMEP/SMAP/UMIP (`cpu_security::enable`) and `OSXSAVE` (`simd::enable`, for AVX state) | Driven by two callers, each read-modify-writing CR4 to OR in only CPU-advertised feature bits and preserve all others (incl. PAE/PGE): `cpu_security::enable` (SMEP/SMAP/UMIP) and `simd::enable` (`OSXSAVE`, cpuid-gated on `xsave`+`avx`, §2j). `nostack`/`preserves_flags`; `nomem` deliberately omitted so the write is a conservative barrier around paging-relevant state. SMEP/SMAP/UMIP add faults only for ring-0 use of user-accessible pages / ring-3 instructions, of which the kernel has none (audited: no `USER` mapping, no ring-3); `OSXSAVE` only enables `xgetbv`/`xsetbv` + XSAVE management — none can create UB. | Reasoned + QEMU (SMEP+SMAP+UMIP + OSXSAVE on at boot, no #GP/#PF) |
| C9 | `cpu.rs` · `read_msr()` (`pub(crate) unsafe`) | `rdmsr` (edx:eax ← MSR[ecx]) | Read `IA32_EFER` before setting NXE | Caller passes only known-present MSRs (`IA32_EFER`, implemented on every long-mode CPU) so `rdmsr` cannot #GP; pure read into `edx:eax`; `nomem`/`nostack`/`preserves_flags`. Cannot create UB. | Reasoned + QEMU |
| C10 | `cpu.rs` · `write_msr()` (`pub(crate) unsafe`) | `wrmsr` (MSR[ecx] ← edx:eax) | Set `IA32_EFER.NXE` (enable NX) via `cpu_security::enable` | Driven only by `cpu_security::enable` writing `IA32_EFER` with NXE OR-ed into its current value (preserving LME/LMA/SCE). NXE makes PTE bit 63 effective — which the kernel's page flags already set and Limine already enables — so it is idempotent and can only make an errant instruction fetch fault, never corrupt memory. `nostack`/`preserves_flags`; `nomem` omitted as a barrier. | Reasoned + QEMU (`[cpu-sec] enabled: nx …`) |
| C11 | `cpu.rs` · `xgetbv()` (`pub(crate) unsafe`) | `xgetbv` (edx:eax ← XCR[ecx]) | Read `XCR0` when bringing up AVX vector state | Pure read of the extended control register selected by `ecx`; the sole caller (`simd`) passes `0` (XCR0) and only after `CR4.OSXSAVE` is set, so it cannot `#UD`/`#GP`. `nomem`/`nostack`/`preserves_flags`. Reading a control register cannot create UB. | Reasoned + QEMU (`[simd] AVX enabled …`) |
| C12 | `cpu.rs` · `xsetbv()` (`pub(crate) unsafe`) | `xsetbv` (XCR[ecx] ← edx:eax) | Enable AVX (`YMM`) — and, where present, AVX-512 (`ZMM`) — state in `XCR0` so `avx`/`avx2`/`avx512f` don't `#UD` | Driven only by `simd::enable`, which sets `CR4.OSXSAVE` first (so no `#UD`) and writes `XCR0` with the x87\|SSE\|AVX component bits, plus — **only** when `cpuid` advertises `avx512f` — the `opmask`\|`ZMM_Hi256`\|`Hi16_ZMM` bits. Each bit is `cpuid`-confirmed supported before being set (so no `#GP`; AVX requires SSE, and the three AVX-512 bits are all supported iff `avx512f` and enabled together). Enabling vector state only makes `YMM`/`ZMM` usable/saveable — it changes no Rust-visible memory. `nostack`/`preserves_flags`; `nomem` omitted as a barrier. | **AVX path:** Reasoned + QEMU (`[simd] AVX enabled …` on every boot). **AVX-512 path OBSERVED:** the `opmask\|ZMM_Hi256\|Hi16_ZMM` bits are set only when `avx512f` is advertised (never under TCG). The `kvm-smp` CI job landed a VNNI-capable KVM `-cpu host` runner and booted with `[ml] … active=avx512-vnni; int8 GEMM ok` (serial log archived as artifact) — which requires the AVX-512 `XCR0` write to have executed at CPL-0 and the ZMM state to be live, so this path is now dynamically confirmed on real silicon (the archived `[simd]` line also shows `avx512f=ok`). Runner assignment is non-deterministic, so it is not guaranteed every run, but it has been observed. |
| C13 | `cpu.rs` · `xsave()` (`pub(crate) unsafe`) | `xsave [mem]` (save the `XCR0`-enabled vector/FPU state components to memory) | Save vector state: the boot `xsave`/`xrstor` round-trip self-test (`simd::xsave_roundtrip_ok`), and — **live, second caller** — `hal::context::switch`'s eager per-task vector save (§9, CX4), gated on `crate::idt::vector_state_armed`. (The per-IRQ save in `isr_common`, I1, uses the same instruction **inline** in `global_asm!`, not this fn.) | Requires `CR4.OSXSAVE` (set by `simd::enable` before any caller) so no `#UD`; the caller's `# Safety` requires a 64-byte-aligned area of ≥ `cpuid`-leaf-`0xD` bytes whose 64-byte header is zeroed (`XCOMP_BV = 0` ⇒ standard format), so no `#GP`. Writes only the save area (no `nomem`), `nostack`, `preserves_flags`. Saving register state to a valid buffer cannot create UB. **The round-trip self-test (`simd::xsave_roundtrip_ok`) also contains three VEX `asm!` blocks** — `vmovdqu`/`vpxor` on `xmm0` to stage and read back a known pattern — which are additional vector asm in the TCB; they are legal (VEX needs only `OSXSAVE`+`XCR0`, both set; legacy SSE would need `OSFXSR`), touch only `xmm0` + bounded `[known]`/`[got]` buffers, and are Miri/Kani-opaque like SM1–SM3. `context::switch`'s call passes `hal::context::XsaveArea`'s runtime-aligned window (§9, CX6) — 64-byte aligned, `XSAVE_AREA_SIZE` bytes, header-zeroed by `new_init`/`zeroize` — satisfying this fn's precondition identically to the self-test's on-stack buffer. | Reasoned + QEMU (the boot round-trip self-test passes on every boot, gating the per-IRQ save; the scheduler's live call is exercised on every `hal::context::switch`, asserted by the PR-A cooperative boot-proof interleave) |
| C15 | `cpu.rs` · `enable_interrupts_and_halt()` | `sti; hlt` (one asm block) | The race-free idle step for an application processor waiting for a reschedule IPI | `sti`'s interrupt shadow defers recognition to after the next instruction, so with both in one block a pending wake-up is taken **after** `hlt` is entered and wakes the core; as two separate blocks (C2 then C3) an IPI could land in between and the core would sleep through it. Neither instruction touches memory or GP registers (`nomem`, `nostack`); IF is modified (no `preserves_flags`). Cannot create UB. | Reasoned + QEMU (`-smp 4`: each AP idles on it in `kernel::sched::ap_idle_loop` and is woken by the pinned-task proof's IPI) |
| C16 | `cpu.rs` · `rdtsc()` | `rdtsc` (EDX:EAX ← time-stamp counter; inline `asm!`) | A coarse, uncalibrated bound on waits that stay on one core. **Two callers:** (1) `kernel::ioapic`'s boot-time PIT-liveness check — the PIT is the thing being tested, so it cannot time itself; 2^35 cycles so a starved TCG host cannot falsely fail it; (2) since SentinelFS FS-1b, `hal::ata`'s status-wait deadlines (A1–A4 callers: durations instead of a count of status reads, turned into TSC cycles at the rate `kernel::interrupts::calibrate_tsc` measures against the PIT once at boot, plus 25 %, or at a 5 GHz fallback until a rate is accepted) | Always legal at CPL 0 (`CR4.TSD` restricts only CPL > 0; the host build runs it in user mode, which TSD-clear Linux allows); reads EDX:EAX only — `nomem`/`nostack`/`preserves_flags`, no side effect, no input to get wrong. `rdtsc` itself is never a calibrated clock: the measured rate lives in `hal::ata` (`set_tsc_hz`, set once, 100 MHz–10 GHz accepted, plain `AtomicU64`, no `unsafe`) and only sizes the ATA budgets. A wrong rate is the same case as a slow or jumping TSC below: a wait ends early (`Timeout`, reset, error) or late, never a wrong success. Extra premise for the measured rate: the TSC ticks at one constant rate on every core (constant TSC); offsets between cores do not matter, only the rate. **Premises of its use as a bound:** the TSC is monotonic **per core only** — no cross-core use: the IOAPIC wait runs with IF = 1 for the wait only (it counts PIT ticks); it runs inline on the BSP and never migrates, and an ATA wait never changes core mid-wait (the scheduler does not migrate tasks; `sfs-commit` is `spawn_on(0)`, the toy FS's caller is `kmain` on the BSP). A stopped or slow TSC only *lengthens* a wait (the ATA read-count backstop bounds it; the IOAPIC wait ends on PIT ticks first); a forward jump only ends a wait early — for ATA an early `Timeout`, which resets the channel and returns an error, for the IOAPIC a failed liveness check, which keeps the 8259 — safe either way, never a wrong success. The budgets are wall time, so preemption of a waiting task counts against them (ATA budgets are seconds; a slice is 10 ms). | Reasoned + QEMU (the IOAPIC liveness wait completes on PIT ticks — the TSC bound is the failure path; every boot's ATA waits run on it) + host tests of the ATA wait logic it clocks (`ata::wait_tests`, also under Miri) and Kani `poll_until_is_a_deadline` |
| C14 | `cpu.rs` · `xrstor()` (`pub(crate) unsafe`) | `xrstor [mem]` (restore vector/FPU state from a saved image) | Restore vector state; pairs with C13 (self-test + — **live, second caller** — `hal::context::switch`'s eager per-task vector restore, §9 CX4; `isr_common` uses the instruction inline) | Requires `CR4.OSXSAVE` (no `#UD`); the caller's `# Safety` requires a 64-byte-aligned standard-format `XSAVE` image (e.g. one `xsave` just wrote, or an all-zero [`hal::context::XsaveArea`] — the architectural init image, §9 CX4 req. #2), so no `#GP`. Reads the image (`readonly`), loads the vector registers, writes no other memory, `nostack`, `preserves_flags`. Loading register state from a valid image cannot create UB in Rust-managed memory. | Reasoned + QEMU (round-trip self-test: state survives save → zero → restore; the scheduler's live call is exercised on every `hal::context::switch`) |

`cpu_security::enable` (safe) drives the SMEP/SMAP/UMIP path of C8 (the `OSXSAVE`
path is `simd::enable`, §2j) and the `IA32_EFER` path of C9/C10: it
gates every bit on `cpuid` detection (never sets an unsupported bit → no #GP) and
only *adds* protection on the audited supervisor-only address space, so those
`unsafe` blocks cannot create UB. See
`docs/specs/2026-07-14-cpu-security-features-design.md`. The **x2APIC** path of
C9/C10 (`IA32_APIC_BASE` + the `0x800`-range registers) is driven by `hal::apic`
(§2i), likewise `cpuid`-gated so no unimplemented MSR is ever touched.

---

## 2a. `hal::gdt` — GDT + TSS + IST (sub-project #2a)

Builds a 64-bit GDT (null, kernel code `0x08`, kernel data `0x10`, plus a 16-byte
TSS system descriptor `0x18`) and a TSS whose `IST[0]` points at a dedicated
16 KiB double-fault stack, then loads them. All privileged steps run inside one
private `install(gdt, tss, ist_top)` sequence with two callers: the safe
`gdt::init()` (the BSP's statics; runs **exactly once** on the boot core with
interrupts disabled) and the crate-private `gdt::init_ap(slot)` (SMP phase 2: an
application processor's **own** slot of `AP_GDT`/`AP_TSS`/`AP_DOUBLE_FAULT_STACKS`,
run once on that AP with interrupts masked — a TSS descriptor goes *busy* on
`ltr`, so cores cannot share one, and each core needs its own IST stack). In both
cases the tables are exclusively owned by the calling core, so they are neither
aliased nor concurrently accessed. Code/data descriptors are identical on every
core, which is what lets the shared IDT's `KERNEL_CODE_SELECTOR` gates load
unchanged on each AP.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| G1 | `gdt.rs` · `install()` (via `init()` / `init_ap()`) | write `static mut TSS.ist[0]` / `static mut GDT[..]` via `addr_of_mut!` raw pointers | The TSS-stack top and TSS-descriptor base are runtime addresses that must be baked into the tables | Once per core, interrupts off, on tables exclusively owned by the calling core (`install`'s contract; upheld by `init` — the BSP statics — and `init_ap` — a per-AP slot, see G6); writes go through raw pointers (no aliasing `&mut`); each descriptor field is computed from the table's own address/size, so the tables are self-consistent. | Reasoned + QEMU fault tests; per-AP tables exercised on every `-smp 4` boot (each AP runs on its own TSS) |
| G2 | `gdt.rs` · `install()` (via `init()` / `init_ap()`) | `lgdt [mem]` | Only way to point the CPU at the new GDT | Operand is a 10-byte pointer to our well-formed `GDT` with exact `limit`; read-only memory; loads descriptor-table base/limit without changing execution or other registers. | Reasoned + QEMU |
| G3 | `gdt.rs` · `install()` (via `init()` / `init_ap()`) | far return (`push sel; push rip; retfq`) to reload `CS` | `mov cs, reg` is illegal in long mode; a far transfer is the canonical CS reload | Pushes the kernel-code selector and the address of the next instruction, then `retfq` pops them into `CS:RIP`; selector indexes the just-loaded present 64-bit code descriptor → valid same-privilege far return. Stack-balanced. | Reasoned + QEMU |
| G4 | `gdt.rs` · `install()` (via `init()` / `init_ap()`) | `mov ss/ds/es/fs/gs, sel` | Make the data segment registers consistent with the new GDT | Loads the present, writable kernel-data selector (`0x10`); long-mode treats these bases as 0, so it only refreshes the selectors. Cannot corrupt memory. | Reasoned + QEMU |
| G5 | `gdt.rs` · `install()` (via `init()` / `init_ap()`) | `ltr sel` | Arm the TSS so `IST[0]` (double-fault stack) is live | Loads the task register from the available-64-bit-TSS selector (`0x18`) pointing at the calling core's TSS (never `ltr`-ed on another core, so *available*, not *busy*); after this a fault routed to `IST[0]` switches to that core's known-good double-fault stack. Loading a valid TSS selector cannot corrupt memory. | Reasoned + QEMU (double-fault test) |
| G6 | `gdt.rs` · `init_ap(slot)` | `addr_of_mut!(AP_GDT/AP_TSS/AP_DOUBLE_FAULT_STACKS) as *mut _` + `.add(slot)` to pick the AP's slot, then `install` | Each AP needs its own TSS (busy bit) and IST stack; a fixed static array indexed by AP slot needs no allocator | `slot < MAX_APS` is checked first, so every `.add(slot)` stays inside its array; the kernel hands out dense cpu indices uniquely and starts APs serially, so exactly one AP ever touches a slot — exclusively owned, unaliased, never concurrent. IST top = one past the end of the slot's 16-byte-aligned 8 KiB stack. Discharges `install`'s contract (G1–G5). | Reasoned + QEMU (`-smp 4`: three APs install slots 0–2 and run on them) |

## 2b. `hal::idt` — IDT + raw ISR stubs (sub-project #2a)

Builds a 256-entry IDT and the per-vector assembly entry stubs (stable
`global_asm!`, `.altmacro` + `.rept`). Each stub normalises the stack (synthetic
`0` error code for vectors that push none), pushes the vector number, and jumps
to one shared `isr_common` tail that saves the 15 GP registers, points `rdi` at
the assembled frame, and `call`s the `extern "C"` trampoline. Error-code vectors
(8, 10–14, 17, 21, 29, 30) push only the vector (the CPU already pushed the error
code) — verified against the emitted assembly. All privileged steps run inside
the single safe entry `idt::init()` (once, single-core, interrupts off).

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| I1 | `idt.rs` · `isr_stub_*` / `isr_common` (`global_asm!`) | raw ISR entry stubs: push error-code/vector, save/restore GP regs, **gated per-IRQ `xsave`/`xrstor` of vector state**, align stack, `call` trampoline, `iretq` | Stable Rust has no `x86-interrupt` ABI; hand-rolled stubs are the stable way to give every handler a uniform frame; the per-IRQ vector save lets vector GEMM run interrupts-on (defense-in-depth atop the CI-checked vector-free-handlers invariant) | Push order matches `InterruptFrame` field-for-field (r15 lowest); synthetic `0` only for no-error-code vectors (confirmed in emitted asm); 16-byte stack alignment restored before `call`; symmetric pops + `add rsp,16` + `iretq` leave the CPU frame intact. **Vector save:** gated on the **live `CR4.OSXSAVE` bit of the executing core** (`mov rbx, cr4; test ebx, OSXSAVE`) — the exact architectural precondition of `xsave`, read from the hardware about to execute it, so it cannot desynchronise and needs no cross-core ordering; `simd::enable` leaves that bit set only after `XCR0` is programmed **and** the `cpuid`-`0xD` save size fits `VECTOR_SAVE_AREA_MAX` **and** an `xsave`/`xrstor` round-trip passes (on failure it clears `OSXSAVE` again), so `OSXSAVE = 1` ⇒ the on-stack 64-byte-aligned `VECTOR_SAVE_AREA_MAX`-byte area (header zeroed for standard format) is sufficient; the save-area pointer (or 0) is held in the callee-saved `r15` and **drives the restore**, so save and restore cannot mismatch; on-stack (not per-CPU) so an exception nested in a handler is correct. **SMP (phase 2):** this replaced the earlier global `VECTOR_SAVE_ARMED` flag, whose documented hazard (an AP interrupted before its own `simd::enable` would `#UD`) is thereby closed structurally; additionally every AP's only entry (`smp::ap_entry`, SMP3) runs `simd::enable` before the kernel can `sti` on it. Stubs are jumped to by the CPU, never called from Rust. | Reasoned + QEMU fault tests (int3 / #PF / #DF); the per-IRQ save is exercised every timer tick on the BSP, and `kernel::ml::prove_interrupts_on` runs 100s of GEMMs interrupts-on across live timer ticks bit-exact (`[ml] gemm-under-irq: … -> ok`) |
| I2 | `idt.rs` · `isr_trampoline()` | `&*frame` — form `&InterruptFrame` from the stub's `rdi` pointer | The boundary that hands the fault to safe handler code | `frame` is set by `isr_common` to the base of the stack image it just built, laid out exactly as `#[repr(C)] InterruptFrame`; the region is valid, aligned, unaliased, and stable for the whole call (the stub does not touch it until after return). | Reasoned + QEMU |
| I3 | `idt.rs` · `stub_addr()` | read `ISR_STUB_TABLE[n]` via `addr_of!` + `*const u64::read()` | Resolve each stub's link-time address as data (avoids 256 `extern fn` decls) | `ISR_STUB_TABLE` is an assembler-emitted `.rodata` array of 256 stub addresses; `n` is always `< IDT_ENTRIES` (== table length) so the read is in bounds; values are code addresses stored into gates, never dereferenced here. | Reasoned + QEMU |
| I4 | `idt.rs` · `init()` | write `static mut IDT[..]` via `addr_of_mut!` raw pointer | Each gate's handler offset is a runtime stub address | Single-call, single-core, interrupts-off init; writes via `addr_of_mut!` (no aliasing `&mut`); each gate built from a valid stub address + the present kernel-code selector; vector 8 gets `ist = DOUBLE_FAULT_IST_INDEX + 1`. | Reasoned + QEMU |
| I5 | `idt.rs` · `lidt_idt()` (via `init()`) | `lidt [mem]` | Only way to arm fault delivery through the new IDT | Operand is a 10-byte pointer to our fully-initialised `IDT` with exact `limit`; read-only memory; arms vectoring without changing registers/memory. | Reasoned + QEMU |
| I6 | `idt.rs` · `load()` → `lidt_idt()` | `lidt` of the **shared**, already-built `IDT` on an application processor | Limine leaves an AP's IDT undefined; the AP must route exceptions through the same stubs/handlers as the BSP | `IDT` is filled exactly once by the BSP's `init()` and never written again — immutable shared data — and `hal::smp` releases no AP before `kmain` has run `interrupts::init`, so the table is complete when any AP loads it; a second core pointing its IDTR at read-only memory is exactly as sound as the first. Gates name `KERNEL_CODE_SELECTOR`, which the AP's own GDT (G6) defines identically. | Reasoned + QEMU (`-smp 4`: each AP's GEMM proof and `hlt` idle run under the shared IDT) |

## 2c. `hal::interrupts` — safe registration bridge (sub-project #2a)

This module is **safe** API; it exists to let the `kernel` crate
(`#![forbid(unsafe_code)]`) register handlers without a `hal → kernel` dependency
cycle. It contains exactly **one** `unsafe` op:

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| X1 | `interrupts.rs` · `handler_for()` | `transmute::<*mut (), Handler>` | Stable Rust cannot cast a data pointer back to a `fn` pointer except via `transmute` | The `*mut ()` read from `HANDLERS` is non-null and was produced *only* by `set_handler` casting a valid `Handler` (`fn(&InterruptFrame)`) to `*mut ()`; the transmute is the exact inverse, recovering the same fn pointer; no data is dereferenced. Stored/loaded via `AtomicPtr` (no tearing). | Reasoned + QEMU (dispatch test) |

> `set_handler` itself uses only a `fn → *mut ()` cast (safe) and an atomic
> store; `init()` just calls `gdt::init()` then `idt::init()`. No other `unsafe`.

## 2d. `hal::framebuffer` — Limine linear framebuffer surface (sub-project #5)

Owns the `#[used] static FRAMEBUFFER_REQUEST: limine::request::FramebufferRequest`
so the bootloader provides a linear RGB framebuffer, and wraps the first
framebuffer's geometry + channel masks in a safe `Framebuffer` handle. The public
surface — `get`, `width`/`height`/`pitch`/`bpp`/`bytes_per_pixel`, the
`red_mask`/`green_mask`/`blue_mask` accessors, `pack_rgb`, `put_pixel`, and
`fill_rect` — is **entirely safe** and **bounds-checked** (out-of-range
coordinates are no-ops; `fill_rect` clips to the visible surface). The packed
pixel format is derived from the firmware-reported per-channel shift+size, so
`pack_rgb` is correct for any layout (not just `0x00RRGGBB`). All `unsafe` is
confined to the two ops below.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| F1 | `framebuffer.rs` · `Framebuffer::get()` | deref the Limine framebuffer **response** (`get_response()` → `framebuffers().next()` → read `addr`/`width`/`height`/`pitch`/`bpp`/masks) | Only way to learn the bootloader-mapped framebuffer base + geometry | `get_response()` yields `Some(&FramebufferResponse)` only after Limine atomically populated our `#[used]` request before `_start`; the response/framebuffer pointers it walks were filled by the bootloader and are valid + initialised. We never mutate the request, the shared borrow is dropped before returning (only plain scalars are copied out), and a null base is rejected → `None`. | Reasoned + QEMU (Miri/Kani **pending**) |
| F2 | `framebuffer.rs` · `Framebuffer::write_pixel_at()` (called by `put_pixel`/`fill_rect`) | `ptr::write_volatile` byte stores to the framebuffer MMIO at `base + offset` | Plot a pixel; volatile so MMIO stores are never elided/coalesced | `unsafe fn` whose `# Safety` requires `offset + bytes_per_pixel <= height*pitch`; both callers reach it only via bounds-checked `byte_offset`/clipped `fill_rect`, so every byte write lands inside the mapped `height*pitch` region (`pitch >= width*bytes_per_pixel`). `base` is non-null (checked in `get`); `u8` writes are alignment-1; single-core boot path ⇒ unaliased. Byte-by-byte handles 16/24/32-bpp without an over-wide store. | Reasoned + QEMU (Miri/Kani **pending**) |

> `Framebuffer` carries `unsafe impl Send + Sync`: the base is an MMIO pointer
> valid for the program's life and the handle exposes no interior mutability; the
> geometry/mask fields are immutable. Concurrent **writes** are the caller's
> responsibility (documented on the drawing methods) — single-core at bring-up.
> `pack_rgb`, the dimension/mask getters, and the bounds/clip arithmetic are pure
> safe logic (Kani candidates).

## 2e. `hal::pic` — 8259A PIC pair remap + EOI (sub-project #2)

Remaps the cascaded master/slave 8259A PIC pair (ports `0x20/0x21` and
`0xA0/0xA1`) from their power-on vectors (which **collide** with CPU exceptions
0–31) to vectors `0x20`–`0x2F` (32–47), masks every line, and provides
per-line mask/unmask plus an End-Of-Interrupt routine. All hardware access is
funnelled through two private primitives, `inb`/`outb`, each documented with a
`# Safety` rustdoc section. The public surface (`init`, `mask_irq`,
`unmask_irq`, `end_of_interrupt`) is **safe**. `init` runs once on the boot core
with interrupts disabled; `end_of_interrupt` runs inside an interrupt handler
(interrupts already masked by the interrupt gate) — single-core, no SMP lock.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| P1 | `pic.rs` · `inb()` | `in al, dx` (port read) | Only way to read a PIC Interrupt Mask Register before a read-modify-write | `unsafe fn` whose `# Safety` requires a read-safe PIC port; all callers pass a master/slave data port. Pure device read, `nomem`/`nostack`. | Reasoned + QEMU |
| P2 | `pic.rs` · `outb()` / `outb_wait()` | `out dx, al` (port write) | Only way to program the 8259A (ICW1–4, masks, EOI) | `unsafe fn` whose `# Safety` requires a write-safe PIC port; all callers pass a master/slave command/data port with a documented ICW/OCW/mask value. `outb_wait` adds a throwaway write to the conventional I/O-delay port `0x80`. Device-only effect, `nomem`/`nostack`. | Reasoned + QEMU |
| P3 | `pic.rs` · `init()` | ICW1–ICW4 `outb` sequence + final mask writes | Remap both PICs to `0x20`–`0x2F` in 8086 cascade mode and mask all lines | Standard, well-defined 8259A init sequence; each `outb` targets a constant PIC port with a defined value; only reconfigures where the PICs vector and which lines are masked. Runs once, boot core, interrupts off → no concurrent PIC access. | Reasoned + QEMU (timer IRQ delivered to vector 32) |
| P4 | `pic.rs` · `mask_irq()` / `unmask_irq()` | `inb` then `outb` of the IMR | Open/close a single IRQ line (e.g. IRQ0 for the PIT) | Read-modify-write of one mask bit (`line < 8`) on the master/slave IMR; device-only effect (enables/disables one line). `inb`/`outb` contracts hold. | Reasoned + QEMU |
| P6 | `pic.rs` · `mask_all()` / `masks()` | `outb(0xFF)` to both IMRs; `inb` of both IMRs | Retire the 8259 once device IRQs go through the IOAPIC (SMP 3b-ii; ACPI `PCAT_COMPAT`), and read the masks back as boot evidence | The writes are exactly `init`'s (P3) final mask writes; the reads are P1's pure IMR reads. Device-only; cannot corrupt memory. Called by `kernel::ioapic` with IF = 0 on the BSP. | Reasoned + QEMU (`[ioapic] … pic=masked …` — read back, both IMRs `0xFF`) |
| P5 | `pic.rs` · `end_of_interrupt()` | `outb(PIC_EOI)` to master (and slave if a slave line) | Tell the PIC the serviced interrupt is done so it delivers further IRQs | Writes the non-specific EOI (OCW2 `0x20`) to the master command port, plus the slave for vectors `0x28`–`0x2F`; vectors outside `0x20`–`0x2F` are ignored. EOI is device-only; cannot corrupt memory. | Reasoned + QEMU (sustained 100 Hz ticks) |

## 2f. `hal::pit` — 8254 PIT channel-0 timer (sub-project #2)

Programs PIT channel 0 (ports `0x40`/`0x43`) as a ~100 Hz rate generator
(mode 2, divisor 11931 of the 1.193182 MHz input), whose output drives the
master PIC's IRQ0 → vector `0x20`. A free-running `static AtomicU64 TICKS` is
incremented by the kernel's vector-32 handler via the safe `on_tick`, which also
calls `pic::end_of_interrupt`. The only privileged op is the channel-0
programming write; `TICKS` is a plain atomic (no `unsafe`), and `ticks`/`on_tick`
are safe API.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| T1 | `pit.rs` · `outb()` | `out dx, al` (port write) | Only way to program PIT channel 0 | `unsafe fn` whose `# Safety` requires a write-safe PIT port; all callers pass `0x40`/`0x43` with a defined mode/reload value. Device-only effect, `nomem`/`nostack`. | Reasoned + QEMU |
| T2 | `pit.rs` · `init()` | mode-byte + lo/hi reload `outb` sequence | Configure channel 0 to ~100 Hz rate-generator mode | Documented 8254 channel-0 programming sequence (`0x34` then divisor low/high); only sets the PIT's mode and reload count — device-only, cannot alias Rust memory. Runs once, boot core, interrupts off. | Reasoned + QEMU (clock advances 1 s/s on the boot screen) |

> **SMP 3b-ii:** the device handlers (`pit::on_tick`, `keyboard::on_irq`,
> `mouse::on_irq`, `e1000::on_irq`) no longer call `pic::end_of_interrupt`
> directly; they call `ioapic::device_eoi(vector)` (§2m, IO4), which issues P5
> only when the LAPIC does **not** have the vector in service — i.e. only for a
> legacy virtual-wire delivery. With the IOAPIC route live (8259 masked, LINT0
> masked) P5 is unreachable; it remains for the rollback / no-IOAPIC fallback.

> The PIT's IRQ0 handler (`hal::pit::on_tick`) does a `fetch_add` on the
> `AtomicU64 TICKS` and a `pic::end_of_interrupt` — both safe. The privileged EOI
> port write lives in `hal::pic` (P5), so the kernel's registered vector-32
> handler stays `#![forbid(unsafe_code)]`-clean.

## 2g. `hal::keyboard` — PS/2 (i8042) keyboard on IRQ1 (sub-project #3)

Captures keyboard scancodes from the legacy PS/2 controller. The IRQ1 handler
(`on_irq`, called from the kernel's registered vector-33 handler) reads one byte
from the data port `0x60` on **every** interrupt (mandatory: the i8042 will not
raise another IRQ1 until its output buffer is drained), pushes the raw byte into
a lock-free SPSC ring built from plain atomics (no `unsafe`), then EOIs via
`hal::pic`. `init` programs the i8042 configuration byte to enable the keyboard
interrupt (IRQ1) before unmasking the PIC line. **All scancode decoding** (the
`0xE0` extended-prefix state machine, make/break mapping) lives in the safe
`kernel` crate (`kernel::input`), not the TCB. All hardware access is funnelled
through two private primitives, `inb`/`outb`, each documented with a `# Safety`
section. The public surface (`init`, `on_irq`, `poll_scancode`) is **safe**;
`poll_scancode` and the ring are pure atomics. `init` runs once on the boot core
with interrupts disabled; `on_irq` runs inside the IRQ1 interrupt gate
(interrupts already masked) — single-core, no SMP lock.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| K1 | `keyboard.rs` · `inb()` | `in al, dx` (port read) | Only way to read the i8042 data (`0x60`) and status (`0x64`) registers | `unsafe fn` whose `# Safety` requires a read-safe PS/2 port; all callers pass `0x60`/`0x64`. Pure device read (draining the scancode / reading status), `nomem`/`nostack`. | Reasoned + QEMU (keystroke → `[input]` serial line) |
| K2 | `keyboard.rs` · `outb()` | `out dx, al` (port write) | Only way to send i8042 commands (`0x64`) and write the config byte (`0x60`) | `unsafe fn` whose `# Safety` requires a write-safe PS/2 port; all callers pass `0x60`/`0x64` with documented i8042 command/config values. Device-only effect (which interrupts the controller raises / which ports are clocked), `nomem`/`nostack`. | Reasoned + QEMU |
| K3 | `keyboard.rs` · `wait_input_empty()` / `wait_output_full()` | `inb(0x64)` status poll | Gate command/data writes and the config read on the controller's buffer state | Reads the read-only status register in a **bounded** loop (so a wedged controller cannot hang boot); no side effect relevant to memory safety. `inb`'s contract holds. | Reasoned + QEMU |
| K4 | `keyboard.rs` · `init()` | read-modify-write of the i8042 config byte (`0x20` read → set IRQ1 bit, clear clock-disable → `0x60` write), then drain a stale byte | Enable IRQ1 generation; firmware may leave it disabled, in which case the keyboard never raises an interrupt | Standard i8042 config-byte programming; each `inb`/`outb` targets a constant PS/2 port with a defined value; only toggles controller interrupt/clock bits — device-only, cannot alias Rust memory. Runs once, boot core, interrupts off. | Reasoned + QEMU (after this, IRQ1 fires on keypress) |
| K6 | `keyboard.rs` · `drain_stale_output()` | `inb(0x64)` then, if output-full, `inb(0x60)` | Re-arm IRQ1/IRQ12 after the 8259 → IOAPIC switch: an edge raised in the switch window is lost and the i8042 raises none until its buffer is drained | Exactly `init`'s stale-byte drain (K4): two pure device reads of the i8042 status/data ports. Discards at most one boot-time byte. Called once by `kernel::ioapic::init`, IF = 0. | Reasoned + QEMU (keystrokes injected after boot arrive: `[ioapic] kbd: … ok`, `[shell] ran: about`) |
| K5 | `keyboard.rs` · `on_irq()` | `inb(0x60)` scancode read | Drain the scancode byte (mandatory — i8042 stops raising IRQ1 until read) | Reached only from the IRQ1 interrupt gate; a single pure device read of the data port, then a `fetch`-free atomic push to the ring and a `pic::end_of_interrupt`. Cannot corrupt memory. | Reasoned + QEMU (sustained keystrokes delivered) **SMP 3b-ii:** the read is now gated on the i8042 status register (`0x64`: output-full set and the AUX bit clear for the keyboard / set for the mouse), drained in a loop bounded at 16, so a spurious, late or foreign IRQ reads nothing rather than a stale or other-device byte; EOI via `ioapic::device_eoi` (IO4). |

> The keyboard's raw-scancode ring (`RING`/`HEAD`/`TAIL`) is built from plain
> `AtomicU8`/`AtomicUsize` (no `unsafe`); `poll_scancode` is safe API. The
> *decoding* state machine and the lock-screen logic live in `kernel::input`
> under `#![forbid(unsafe_code)]`, so the privileged surface stays tiny.

## 2h. `hal::mouse` — PS/2 (i8042 aux device) mouse on IRQ12 (sub-project #3, pointer)

Captures pointer movement + button packets from the legacy PS/2 mouse (the i8042
**auxiliary** device). The mouse shares the keyboard's data port (`0x60`) but is
wired to **IRQ12**, which lives on the **slave** PIC (line 4 → vector `0x2C`).
The i8042 raises one IRQ12 per *byte*, so the IRQ handler (`on_irq`, called from
the kernel's registered vector-`0x2C` handler) reads one byte from `0x60` on
**every** interrupt (mandatory — the i8042 will not raise another IRQ12 until its
output buffer is drained), reassembles the 3-byte movement packet across three
interrupts, decodes `{ dx, dy, buttons }` (sign + overflow bits) and pushes a
`MouseEvent` into a lock-free SPSC ring of plain atomics (no `unsafe`), then EOIs
**both** PICs via `hal::pic` (a slave-PIC line must EOI the slave *and* the
master — see P5). `init` enables the aux device (`0xA8`), sets the config byte's
port-2 interrupt-enable bit, tells the mouse to use defaults (`0xF6`) and stream
(`0xF4`) via the `0xD4` write-to-aux prefix, then unmasks **IRQ12 and the IRQ2
cascade** (without the cascade unmasked the slave PIC reaches the CPU for no
line). **All pointer policy** (cursor position, screen clamping, hit-test
click-to-focus, cursor damage) lives in the safe `kernel::wm` module, *not* the
TCB. All hardware access goes through two private primitives, `inb`/`outb`, each
with a `# Safety` section. The public surface (`init`, `on_irq`, `poll_event`) is
**safe**. `init` runs once on the boot core with interrupts disabled; `on_irq`
runs inside the IRQ12 interrupt gate (interrupts already masked) — single-core, no
SMP lock. Packet decoding (`decode_delta`/`decode_packet`) is pure logic with
co-located host unit tests.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| MS1 | `mouse.rs` · `inb()` | `in al, dx` (port read) | Only way to read the i8042 data (`0x60`) and status (`0x64`) registers | `unsafe fn` whose `# Safety` requires a read-safe PS/2 port; all callers pass `0x60`/`0x64`. Pure device read (draining a packet byte / reading status / a mouse ack), `nomem`/`nostack`. | Reasoned + QEMU (cursor moves; click changes focus) |
| MS2 | `mouse.rs` · `outb()` | `out dx, al` (port write) | Only way to send i8042 commands (`0x64`) and config/mouse data bytes (`0x60`) | `unsafe fn` whose `# Safety` requires a write-safe PS/2 port; all callers pass `0x60`/`0x64` with documented i8042/mouse command/config values (`0xA8`/`0x20`/`0x60`/`0xD4` + `0xF6`/`0xF4` + the config byte). Device-only effect, `nomem`/`nostack`. | Reasoned + QEMU |
| MS3 | `mouse.rs` · `wait_input_empty()` / `wait_output_full()` | `inb(0x64)` status poll | Gate command/data writes + the config/ack reads on the controller's buffer state | Reads the read-only status register in a **bounded** loop (so a wedged controller cannot hang boot); no memory-safety-relevant side effect. `inb`'s contract holds. | Reasoned + QEMU |
| MS4 | `mouse.rs` · `write_to_mouse()` | `outb(0x64,0xD4)` → `outb(0x60,cmd)` → `inb(0x60)` ack | Forward a command to the mouse (the `0xD4` prefix routes the next data byte to the aux device) and drain its `0xFA` ack | Each step targets a constant PS/2 port with a documented value after gating on buffer state; the ack read clears the output buffer so a stray ack cannot masquerade as the first packet byte. Device-only; cannot alias Rust memory. Runs in `init`, boot core, interrupts off. | Reasoned + QEMU |
| MS5 | `mouse.rs` · `init()` | enable-aux (`0xA8`) + config-byte read-modify-write (set port-2 IRQ, clear port-2 clock-disable) + stale-byte drain | Enable IRQ12 generation; firmware may leave the aux port/IRQ12 disabled, in which case the mouse never raises an interrupt | Standard i8042 aux/config programming; each `inb`/`outb` targets a constant PS/2 port with a defined value; only toggles which interrupts the controller raises / which ports are clocked — device-only, cannot alias Rust memory. Runs once, boot core, interrupts off; then unmasks IRQ12 + the IRQ2 cascade on the PIC. | Reasoned + QEMU (IRQ12 fires on pointer motion) |
| MS6 | `mouse.rs` · `on_irq()` | `inb(0x60)` packet-byte read | Drain the next packet byte (mandatory — i8042 stops raising IRQ12 until read) | Reached only from the IRQ12 interrupt gate; a single pure device read of the data port, then plain-atomic packet reassembly + a `pic::end_of_interrupt` (both PICs). Cannot corrupt memory. | Reasoned + QEMU (sustained packets delivered) **SMP 3b-ii:** the read is now gated on the i8042 status register (`0x64`: output-full set and the AUX bit clear for the keyboard / set for the mouse), drained in a loop bounded at 16, so a spurious, late or foreign IRQ reads nothing rather than a stale or other-device byte; EOI via `ioapic::device_eoi` (IO4). |

> The mouse's decoded-event ring (`RING_DX`/`RING_DY`/`RING_BTN` + `HEAD`/`TAIL`)
> and the 3-byte reassembly state (`PHASE`/`PKT0`/`PKT1`) are plain
> `AtomicI16`/`AtomicU8`/`AtomicUsize` (no `unsafe`); `poll_event` is safe API. The
> cursor model, screen clamping, and hit-test click-to-focus live in `kernel::wm`
> under `#![forbid(unsafe_code)]`, so the privileged surface stays tiny (read a
> byte, reassemble, EOI). The dual-PIC EOI itself is `hal::pic` (P5).

## 2i. `hal::apic` — Local APIC: x2APIC MSRs or xAPIC MMIO (SMP phases 1–2)

Enables the BSP's Local APIC in **x2APIC** mode as the first step toward SMP, in
**virtual-wire** configuration so the existing 8259 PIC / PIT / keyboard / mouse /
NIC IRQ path keeps working unchanged: LVT LINT0 is programmed as `ExtINT` (the
PIC's INTR passes straight through — the CPU's INTA cycle still fetches the vector
from the PIC, and the existing handlers still EOI the *PIC*, never the LAPIC) and
LINT1 as `NMI`. The public surface (`enable_bsp`, `id`, `logical_cpu_count`) is
**safe** and returns plain integers / `Option<u32>`; `logical_cpu_count` and the
private `has_x2apic` are pure `cpuid` reads (via §8's `raw`, Q1) and add **no**
new privileged op; their bitfield decode is split into pure const fns
(`ecx_has_x2apic` / `ebx_logical_cpu_count`) covered by host unit tests — plus an
in-tree Kani harness (not yet discharged live; see §3) — since no emulated boot
exercises the x2APIC-present branch. The only
new `unsafe` is the MSR access, reusing the
already-documented `cpu::read_msr` / `cpu::write_msr` primitives (C9/C10) — so this
module adds two new *call sites*, not new raw instructions. `enable_bsp` runs once
on the BSP at boot, after the PIC/PIT are programmed and with interrupts disabled;
the `kmain` caller then opens the interrupt window briefly and asserts the PIT
still ticks across the switch (a broken virtual wire fails the boot test instead
of silently stopping the clock). **Phase 2** adds `enable_ap` (AP3) — the same
sequence on an application processor, with LINT0 **masked** so only the BSP is an
`ExtINT` sink (a second one would double-deliver every PIC IRQ) — and the safe
`cpuid_apic_id` (pure `cpuid`, no privileged op; decode `initial_apic_id_from_ebx`
host-tested + Kani-proved), which identifies the calling core in any LAPIC mode
so the safe kernel can find its per-CPU slot even under TCG where `id()` is `None`.

**PR-2 (per-CPU scheduler) made the register access dual-path.** Where x2APIC is
advertised every register is an MSR (`0x800 + offset/16`, C9/C10); where it is not
(QEMU TCG) the same registers are 32-bit MMIO words on the LAPIC page
(`IA32_APIC_BASE[..12]`, normally `0xFEE0_0000`), which `enable_bsp` maps **once**,
uncached, through the audited `mm::map_mmio` (§5f) and publishes in
`XAPIC_MMIO_BASE` — the LAPIC sits at the same physical address on every core, so
one mapping serves them all (AP4). `enable_bsp`/`enable_ap` program the same
virtual-wire configuration over either path (AP1/AP3 now name `reg_write`, which
dispatches on the live mode). The two SMP operations the scheduler needs —
`send_ipi` (AP5: a fixed, edge, physical-destination IPI, so a core idling in
`sti; hlt` learns it has work) and `eoi` (AP6) — exist on both paths, so
cross-core scheduling is exercised on every TCG boot test, not only under KVM.
Under TCG the BSP path re-asserts exactly the virtual-wire state firmware boots
in, so the `kmain` timer-liveness check still guards it. **Phase 3** adds the
**per-core LAPIC timer** (AP7): the BSP calibrates it against the PIT once
(`kernel::interrupts::init_lapic_timer`, masked one-shot countdown over 10 PIT
ticks), then every core — BSP and each AP as it comes up — runs it periodic at the
PIT's 100 Hz on vector `0xF1`, whose handler EOIs the LAPIC and runs
`sched::on_tick` on *that* core. The PIT becomes wall clock only.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| AP4 | `apic.rs` · `map_xapic_mmio()` + `reg_read()`/`reg_write()` (xAPIC arm) | `mm::map_mmio(IA32_APIC_BASE & ADDR_MASK, 4 KiB)` once; then `read_volatile`/`write_volatile` of a `u32` at `base + reg` | Reach the LAPIC where no x2APIC MSRs exist (TCG): software-enable APs, send IPIs, EOI | The physical base comes from the architectural `IA32_APIC_BASE` (pure MSR read, C9) and is only used if the LAPIC is hardware-enabled; `map_mmio` is the audited uncached (PCD+PWT) mapping the NIC already uses, so the page is a real device window, not RAM. Every `reg` offset in the module is a named constant `< 0x1000`, 16-byte aligned, so each 4-byte volatile access is in bounds and aligned; volatile because it is a device register. The mapping is installed by the BSP before any AP is released and never unmapped, and the base is published with `Release`/read with `Acquire`. Device-register access cannot alias Rust memory. | Reasoned + QEMU TCG (`[smp] xAPIC (MMIO) enabled … timer live`, every AP `lapic=xapic`, and the pinned-task proof's IPI delivery) |
| AP5 | `apic.rs` · `send_ipi()` | x2APIC: `write_msr(0x830, dest<<32 \| vector)`; xAPIC: `reg_write(ICR_HIGH, dest<<24)`, `reg_write(ICR_LOW, vector)`, bounded poll of `ICR_LOW.bit12` | Wake another core (`kernel::sched::spawn_on` and, since A25, `kernel::sched::unpark` → reschedule IPI). Not reentrant on one core under xAPIC (two ICR writes): both callers send with `IF = 0`, so an IRQ-context `unpark` can never split another send's writes | Fixed delivery, edge, physical destination, reserved bits zero — an architectural command word; the destination is a LAPIC ID the bootloader enumerated. Sending an interrupt cannot alias Rust memory; what the *receiving* core does is decided by its IDT, and the kernel registers the reschedule handler (vector `0xF0`) before any AP is released. The xAPIC poll is a read-only wait, bounded by `ICR_SEND_SPIN_LIMIT` so a misbehaving APIC cannot hang the sender. Returns `false` (sends nothing) without an access path. | Reasoned + QEMU (`[sched] pinned: … ran-on=cpuN … ok` under TCG; the same line under KVM exercises the MSR arm) |
| AP6 | `apic.rs` · `eoi()` | `reg_write(EOI, 0)` (MSR `0x80B` or MMIO `0xB0`) | Acknowledge a LAPIC-delivered interrupt (the reschedule IPI; later the LAPIC timer) so the in-service bit clears | Write-only register whose value is ignored; acknowledging cannot alias Rust memory. Called only from `kernel::interrupts::handle_resched_ipi` (a LAPIC-delivered vector); PIC-routed IRQs still EOI the PIC, and the spurious vector owes none. No-op without an access path. | Reasoned + QEMU (a second IPI to the same core is delivered — the AP idle is woken again after its first task exits) |
| AP7 | `apic.rs` · `timer_start_calibration()` / `timer_current_count()` / `timer_start_periodic()` | `reg_write` of `TIMER_DIV` (÷16), `LVT_TIMER` (masked one-shot, or periodic \| vector), `TIMER_INIT`; `reg_read` of `TIMER_CUR` | Give every core its own scheduler tick — the PIT reaches only the BSP | Programs only the calling core's timer registers over the live access path (AP4/C9/C10): divider, mode + vector, initial count (the write that starts it), and a read-only current count. Calibration runs **masked**, so no interrupt can fire whatever the LVT vector field holds; the periodic start names vector `0xF1`, whose handler the kernel registered before any core's timer starts. A zero count is refused. A timer is a counter plus an interrupt source — it cannot alias Rust memory. | Reasoned + QEMU TCG and KVM (`[timer] lapic: N counts/tick … scheduler tick on every core`; per-AP `tick=lapic`; `[sched] ap-preemptive: cpuN … tick-preempted>=1 … ok` — two non-yielding tasks on an AP switched only by that core's own tick, GEMM state bit-exact across every preemption) |
| AP1 | `apic.rs` · `enable_bsp()` | `cpu::read_msr(IA32_APIC_BASE)` + up to 2× `cpu::write_msr` (`IA32_APIC_BASE` → EN (only if disabled) → EN\|EXTD) **where x2APIC is advertised**, else `map_xapic_mmio` (AP4); then `reg_write` of `SVR` / `LVT LINT0` / `LVT LINT1` over the live path | Switch the LAPIC to x2APIC mode (or reach it over MMIO) and program virtual-wire routing | Guarded by `has_x2apic()` (cpuid leaf 1 ECX bit 21) ⇒ every MSR is implemented, no `#GP`. `IA32_APIC_BASE` is read-modify-written, only OR-ing bits in (never clearing the base address). If EN is clear the sequence sets EN alone first (enter xAPIC) **then** EN\|EXTD, because a direct disabled→x2APIC jump is an illegal transition (`#GP`); EN is normally already set after reset/Limine so that extra write is skipped. After EXTD the `0x800`-range registers are accessible. `SVR` = software-enable \| vector `0xFF`; `LINT0` = ExtINT (front-ends the already-configured PIC), `LINT1` = NMI. Reconfigures interrupt *routing* only — cannot alias or corrupt Rust-managed memory. | Reasoned. **The write sequence runs only where x2APIC is present (KVM / real hardware).** QEMU **TCG** (CI/sandbox) cannot advertise x2APIC under any CPU model (QEMU 8.2), so the boot test exercises the `has_x2apic()`-gated **fallback** (`[smp] x2APIC not advertised…`) and confirms no regression — the enable path itself is verified by reasoning + on KVM/hardware — now automated by `cargo xtask test-kvm` / the `kvm-smp.yml` CI job, which boots under `-enable-kvm -cpu host` and asserts the `[smp] x2APIC enabled … timer live` line (the C1 evidence for issue #10). See the design-doc Testing note. |
| AP3 | `apic.rs` · `enable_ap()` | `cpu::read_msr(IA32_APIC_BASE)` + up to 2× `cpu::write_msr` (EN (if clear) → EN\|EXTD) where x2APIC is advertised, else the shared MMIO mapping (AP4); then `reg_write` of `SVR` / `LVT LINT0 = masked` / `LVT LINT1 = NMI` | Put each AP's LAPIC into x2APIC mode (an x2APIC ID, spurious vector, NMI routing; ready as an IPI / LAPIC-timer target) without making it a second PIC sink | Same guard and MSR discipline as AP1, executed on the calling AP's own (MSR-mapped, per-core) LAPIC; only bits are OR-ed into `IA32_APIC_BASE`; LINT0 **masked**, not `ExtINT`, so the PIC's INTR still reaches exactly one core — the existing PIT/keyboard/mouse/NIC handlers and their PIC EOIs stay single-delivery. Routing only; cannot alias or corrupt Rust memory. `None` (no-op) where x2APIC is not advertised. | Reasoned + QEMU: the MSR arm runs where x2APIC is present (the `kvm-smp.yml` job's `-smp 4` boot prints `lapic=x2apic` per AP), the MMIO arm on every TCG boot (`lapic=xapic` per AP); the software-enable is what lets the pinned-task proof's IPI reach the AP on both |
| AP2 | `apic.rs` · `id()` | `cpu::read_msr(IA32_APIC_BASE)` then, iff `EXTD` set, `cpu::read_msr(0x802)` (x2APIC ID) | Report the BSP's x2APIC ID in the bring-up line | **Self-guarding:** reads `IA32_APIC_BASE` (always implemented — cannot `#GP`), and only reads `0x802` when `EXTD` is set (x2APIC mode active), else returns `None`. So the safe wrapper never faults regardless of call order (reading `0x802` in xAPIC mode would `#GP`). Both are pure read-only register accesses with no side effect — cannot corrupt memory. | Reasoned (same env caveat as AP1 — the `0x802` read runs only on the x2APIC-present path, not under TCG). |

**SMP 3b-ii (IOAPIC routing)** adds two LAPIC operations, both over the live
access path (AP4 / C9 / C10), no new raw instruction:

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| AP8 | `apic.rs` · `eoi_if_in_service()` | one `access_mode()` lookup, then `reg_read(ISR word)` — MSR `0x810..=0x817` or MMIO `0x100..=0x170` — and, iff the vector's bit is set, AP6's EOI write over the same path | Decide, per device interrupt, whether the LAPIC delivered it (and so is owed the EOI) — `ioapic::device_eoi` (IO4) | The ISR read is a read-only register: no side effect, cannot alias Rust memory. The offset comes from the pure `isr_slot` (host-tested; Kani `isr_slot_is_exact`: every vector maps to one of the eight 16-byte-aligned ISR words and a bit `< 32`, bijectively), so the access is always one of the eight architectural ISR registers. The EOI is AP6 verbatim. The access path is resolved once per IRQ (one `IA32_APIC_BASE` read — each MSR read is a VM exit on KVM). `false` without an access path (then the 8259 is the only possible deliverer). | Reasoned + Kani (decode) + QEMU (every PIT tick, keystroke, mouse byte and NIC IRQ after the switch EOIs the LAPIC; the PIT keeps ticking for the whole boot — a missed EOI would block every vector of its priority class) |
| AP9 | `apic.rs` · `mask_lint0()` / `lint0_extint()` / `lint0_masked()` | `reg_write(LVT LINT0, masked)` / `reg_write(LVT LINT0, ExtINT)` / `reg_read(LVT LINT0)` on the calling core | Take the 8259 out of the virtual wire once the IOAPIC carries device IRQs; restore it on rollback; read it back as evidence | The masked value is exactly AP3's (every AP already runs with it); ExtINT is exactly AP1's. Routing only — cannot alias Rust memory. Called by `kernel::ioapic` on the BSP with IF = 0. | Reasoned + QEMU (`[ioapic] … lint0=masked …`, read back; keyboard evidence line re-reads it at the first keystroke) |

> AP bring-up and per-CPU state shipped in phase 2 (§2k); device-IRQ routing
> through the IOAPIC shipped in 3b-ii (§2m). LINT0 = ExtINT now exists only
> between `enable_bsp` and `kernel::ioapic::init`, and on the rollback path.

## 2l. `hal::acpi` — RSDP + bounded firmware-table reader (SMP 3b-ii)

`hal` does **no** ACPI parsing: the RSDP → RSDT/XSDT → MADT walk and every byte
decode are `kernel::acpi` (safe, `&[u8] -> Result` decoders, 4 Kani harnesses, a
200 000-mutant fuzz test over QEMU's real MADT). `hal` supplies the RSDP's
physical address and a reader that **copies** firmware bytes into a
kernel-owned buffer — the kernel never holds a reference into firmware memory.
`read_phys` refuses empty or > 16 KiB requests and any range that overlaps
memory the kernel owns or may own (`mm::overlaps_kernel_owned`: `USABLE`,
`BOOTLOADER_RECLAIMABLE`, `EXECUTABLE_AND_MODULES`, `FRAMEBUFFER`; fails closed
without a memory map), then maps the span through `mm::map_firmware_ro` — the
§5f bump window with `PageFlags::kernel_ro()` (present, read-only, NX, no
PCD/PWT, so the MTRRs decide the memory type and a table the HHDM also maps WB
is not aliased UC). Limine base revision 3 no longer promises the HHDM covers
ACPI/reserved memory, which is why the span is mapped rather than HHDM-offset.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| AC1 | `acpi.rs` · `rsdp_phys()`; `mm/bootinfo.rs` · `overlaps_kernel_owned()` | read the `#[used]` `RsdpRequest` / `MemoryMapRequest` responses (crate-safe `get_response()`; listed for the same reason as B1) | Where the ACPI tables start; which physical ranges the kernel owns | The B1 pattern: a response is `Some` only if Limine filled it before `_start`; only scalars are copied out. Revision 3 reports the RSDP physically; a value ≥ the HHDM offset (revision-0 style) is converted back. | Reasoned + QEMU (the walk finds QEMU's RSDT and MADT on every boot) |
| AC2 | `acpi.rs` · `read_phys()` | `ptr::read_volatile(*const u8)` over the span `map_firmware_ro` just mapped | Copy RSDP/RSDT/XSDT/MADT bytes into the kernel's fixed buffers | Every byte `src + i`, `i < len`, lies in pages mapped present+read-only by the call itself (offset-preserving, never unmapped). The span is validated by `mm::phys_span` inside `map_window` **before** anything is mapped: non-empty, no `u64` overflow on `phys + len` or the page round-up, and ending at or below `1 << width`, where width is `MAXPHYADDR` (CPUID `0x8000_0008`, fallback 36) reduced for AMD memory encryption when `0x8000_001F` advertises SME (`min(width, C-bit) - EBX[11:6]`, as Linux) — a leaf is built as `phys | flags` unmasked, so without this an address with bits 52–62 set would alias a low (kernel) frame and pass the raw-value overlap check. **Residual:** Intel TME-MK KeyID bits (top of `MAXPHYADDR`, active only once firmware sets `IA32_TME_ACTIVATE`) are not subtracted — that MSR is not read. `map_window` then refuses any **page-rounded** span overlapping kernel-owned memory (all callers), so the range overlaps no kernel-owned RAM, so no Rust reference or writer exists for it — a volatile `u8` load there is a firmware/device read, not a racing access to Rust memory; `u8` has no alignment/validity requirement. Bounded by `MAX_READ` (16 KiB) and the caller's buffer, never by a firmware length. **MMIO-window bound:** each call bump-allocates fresh VA in the §5f window and never frees it; the walk makes ~10 calls of ≤ 8 KiB at boot, so the cost is a few pages of VA and page-table frames, once. | Reasoned + Kani (`mm::phys_span_proofs::phys_span_is_bounded`, `phys_addr_bits_decode_is_clamped`) + host tests (`phys_span_tests`, incl. `K \| 1 << 52` and `0xFFFF_FFFF_FFFF_FFC0`) + QEMU + host tests of every consumer path (`kernel::acpi::tests::discover`) |

> `mm::map_firmware_ro` and the refactored `map_mmio` share one body
> (`map_window`); no new raw page-table op — the same M6–M9 `map_page` path
> with different leaf flags. `map_window` now validates every span with the pure
> `mm::phys_span` against this CPU's `MAXPHYADDR` before mapping (see AC2 and
> §5f) and returns `MmioError::BadRange` instead of overflowing.

## 2m. `hal::ioapic` — IOAPIC redirection + device EOI (SMP 3b-ii)

Mechanism only; policy (which ISA IRQ → which GSI, vector and CPU) is
`kernel::ioapic`, from the MADT the kernel parsed. `IoApic` is a sealed handle
(private fields, only `IoApic::map` constructs it), so a kernel-held handle
always names a validated, mapped, version-checked window. One global
`SpinMutex` pairs every `IOREGSEL` select with its `IOWIN` access across all
IOAPICs and cores; it is never taken in interrupt context (IO4 touches only the
LAPIC), so it needs no interrupt masking. Redirection-entry packing is pure and
Kani-proved: `to_raw`/`from_raw` round-trip exactly, `to_raw` never sets a
read-only (delivery status, remote IRR), reserved or logical-destination bit
(`redirection_entry_round_trips_and_sets_only_writable_bits`,
`redirection_entry_from_raw_is_total`), and an unmasked fixed/lowest-priority
entry hal accepts never targets an exception vector
(`programmable_entries_never_target_exception_vectors`).

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| IO1 | `ioapic.rs` · `IoApic::map()` | `mm::map_mmio(phys, 0x20)` of a **firmware-supplied** address (no raw op; composes §5f) | Reach the IOAPIC's registers | The address is untrusted (MADT type 1). It is the MADT's 32-bit field (`IoApic::map(u32)`), and `map_window` independently refuses any span past the usable address width (incl. the SME reduction; TME-MK KeyID bits are a documented residual, AC2) or overflowing (`mm::phys_span`), and any page-rounded span overlapping kernel-owned memory; it must be 16-byte aligned (both registers 4-byte aligned inside one window) and overlap no kernel-owned RAM (`mm::overlaps_kernel_owned`). **Claim, narrowed:** a lying table can never make IO2/IO3 store to kernel memory; it *can* make `hal` read and write two registers of whatever other device MMIO sits at that address — the residual trust this kernel places in firmware, as every OS that honours the MADT does. Mapped uncached (PCD+PWT) as a device window, never unmapped. The version register must then read back plausibly (not all-ones, ≥ 2 pins) or the handle is refused. | Reasoned + QEMU (`pins=24` read back from QEMU's IOAPIC at `0xFEC0_0000`) |
| IO2 | `ioapic.rs` · `sel_read()` / `sel_write()` | `write_volatile(IOREGSEL, reg)` then `read_volatile`/`write_volatile(IOWIN)` — aligned `u32`s at `base + 0x00` / `base + 0x10` | The IOAPIC's only register interface is indirect | `base` is IO1's validated mapping; both offsets are inside the 0x20-byte window and 4-byte aligned; volatile because they are device registers. Both helpers take an `&IoApicLocked` — a private newtype only `lock_ioapic()` (i.e. `IOAPIC_LOCK`) can construct, so no other lock's guard type-checks — so a select can never be issued without *this* lock, and every multi-register sequence (ID+version in `map`, the three writes of `write_entry`, the two reads of `read_entry`) runs under **one** acquisition — no other core can interleave a select or a half-entry. Device-register access cannot alias Rust memory. | Reasoned + QEMU (the version register reads back `pins=24`; every routed source delivers after IO3 writes through this path) |
| IO3 | `ioapic.rs` · `write_entry()` / `mask_pin()` | IO2 writes of redirection-table registers `0x10 + 2·pin` (low) and `+1` (high), one lock acquisition | Program a pin: vector, delivery mode, physical destination, polarity, trigger, mask | `pin` ≤ the version register's max redirection entry (else refused), so the index names a real entry. The entry must be `is_programmable`: masked entries may hold anything; an **unmasked** entry must be **fixed** delivery of a vector ≥ `0x20` — SMI/NMI/INIT/ExtINT would let a device line reset or seize a core, lowest-priority needs a logical destination `hal` never programs, and an exception vector would enter an ISR stub whose error-code expectation does not match (stack misinterpretation). Write order under one lock: low dword **masked**, then high (destination), then the final low — the pin never delivers a half-written entry, and no other writer can interleave. Packing is the Kani-proved `to_raw`. Effect: interrupt routing only; what a delivered vector does is decided by the IDT, and the kernel registers every routed vector's handler before routing it. | Reasoned + Kani (packing; `programmable_entries_never_target_exception_vectors`: every unmasked programmable entry is fixed delivery of a vector ≥ `0x20`) + QEMU (`routed=pit,kbd,mouse,nic`, PIT live through GSI 2, keyboard IRQs via GSI 1) |
| IO4 | `ioapic.rs` · `device_eoi()` | none new — AP8 (ISR read + conditional LAPIC EOI) **or** P5 (8259 EOI) | Every device handler must EOI exactly the controller that delivered it | A LAPIC-delivered interrupt (IOAPIC message) sets the vector's ISR bit; a virtual-wire ExtINT delivery never does. Reading the ISR at handler time therefore identifies the deliverer from hardware state, with no software flag that could disagree during the switch-over or after a rollback. For a level-triggered pin (the NIC, GSI 11) the LAPIC EOI's broadcast clears the IOAPIC's remote IRR (EOI-broadcast suppression is never enabled: SVR bit 12 stays 0). | Reasoned + QEMU (sustained PIT/keyboard/NIC delivery after the switch) |

## 2j. `hal::simd` — AVX/AVX-512 vector state + int8 GEMM (AI/ML compute)

The first vector code in the TCB. Two jobs: (1) `enable()` turns on vector state so
`avx`/`avx2`/`avx512f`/`avx512_vnni` instructions don't `#UD` — `CR4.OSXSAVE` (via
the existing `write_cr4`, C8) then `XCR0 |= x87|SSE|AVX` (via `xsetbv`, C12;
read-back via `xgetbv`, C11), `cpuid`-gated on `xsave`+`avx`, plus — **only** when
`avx512f` is advertised — the three AVX-512 component bits
(`opmask|ZMM_Hi256|Hi16_ZMM`); and (2) three **safe** wrappers over an
int8·int8→i32 matrix multiply — `gemm_i8_avx2()` (256-bit `YMM`, 8 columns/step),
`gemm_i8_avx512()` (512-bit `ZMM`, 16 columns/step, `VPMULLD` broadcast), and
`gemm_i8_avx512vnni()` (512-bit `ZMM`, fused `VPDPBUSD` dot-product) — each with a
hand-written inline `asm!` inner step (VEX / EVEX). VNNI needs no extra privileged
setup: it reuses the `avx512f` `ZMM` state. The public surface (`enable`, the three
`*_ready` gates, the three `gemm_i8_*` wrappers) is **safe**; the vector-state
privileged writes are C11/C12 above, and the only new raw ops are the kernels'
in-bounds vector load/stores (SM1 for AVX2, SM2 for AVX-512F, SM3 for VNNI). The
`kernel` crate stays `#![forbid(unsafe_code)]` — it calls the safe wrappers, each of
which returns `false` (→ next tier / scalar fallback) whenever its tier is not
verified usable.

**Why `asm!`, not intrinsics.** The bare-metal target `x86_64-unknown-none`
(soft-float baseline) does **not** codegen `core::arch` SIMD intrinsics to VEX/EVEX
instructions — they emit as calls that never lower to `vpmulld`, and passing
`__m256i`/`__m512i` across that call on the soft-float ABI corrupts the vectors
(wrong results on *real* hardware). Inline `asm!` emits the instructions
unconditionally, with the vectors living entirely inside each block (only
`i32`/pointers cross the boundary), so there is no vector-ABI dependency.

**Self-test gate.** `enable()` runs each vector kernel on fixed input (multiple
shapes: single block, multi-block+tail, ±127 extremes, `k` not ÷ 4) and compares it
to a scalar computation; `avx2_ready()`/`avx512_ready()`/`avx512vnni_ready()` (cached
atoms) report a tier usable **only** on a bit-exact match. So a vector unit that
computes incorrectly can never make the kernel ship garbage — this caught a
soft-float codegen problem during bring-up (fall back to scalar, not wrong output)
and backstops any future CPU/emulator/toolchain regression. The AVX2 self-test
passes under both TCG (`-cpu Haswell`) and KVM (`-cpu host`); the AVX-512F and VNNI
self-tests run only where `avx512f`/`avx512_vnni` are advertised (KVM `-cpu host` on
AVX-512 silicon; never under TCG's `Haswell`), so on a non-AVX-512 host those
`*_ready()` gates stay false and the tiers are simply skipped. The boot log's
`[simd] … avx2=ok avx512f=… avx512-vnni=…` line reports each tier's self-test
result.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| SM1 | `simd.rs` · `avx2_madd8` (inline `asm!`), called by `gemm_i8_avx2_impl` | VEX `asm!`: `vmovd`/`vpbroadcastd` + `vpmovsxbd`(m64) + `vpmulld` + `vpaddd`(m256) + `vmovdqu` store — one 256-bit int8→i32 multiply-accumulate of 8 columns | Vectorised int8 GEMM (8 int32 columns/step) | Reached only from the safe `gemm_i8_avx2`, which runs it **only** when `avx2_ready()` is true — i.e. after `enable` turned on AVX state **and** the self-test executed this exact kernel correctly on this core (so the VEX instructions are legal, no `#UD`). Each `asm!` block reads 8 bytes of `b` and read-writes 8×i32 of `c`, bounded by `j + 8 <= n` (vector path) or `j < n` (scalar tail) within the caller-validated (overflow-checked) `m`/`k`/`n` slice lengths; `vmovdqu` is the **unaligned** store (no alignment precondition); `a`/`b` shared, `c` exclusive. `ymm0`/`ymm1` declared clobbered; no `nomem` (reads/writes `[b]`/`[c]`), `nostack`, sets no flags. **Interrupts:** may be enabled — `isr_common` (I1) per-IRQ-saves vector state and CI verifies handlers are vector-free. Bit-identical to the scalar reference (`wrapping_add` is associative). | Reasoned + host differential tests (AVX2 == scalar over many shapes incl. an i32-wrap case + a 300-shape pseudo-random sweep) + **TCG *and* KVM boot** (`[ml] … active=avx2` asserted). Miri/Kani-opaque (inline asm), like the other HAL asm |
| SM2 | `simd.rs` · `avx512_madd16` (inline `asm!`), called by `gemm_i8_avx512_impl` | EVEX `asm!`: `vmovd`/`vpbroadcastd`(`zmm`) + `vpmovsxbd`(m128→`zmm`) + `vpmulld`(`zmm`) + `vpaddd`(m512) + `vmovdqu32` store — one 512-bit int8→i32 multiply-accumulate of 16 columns | Wider vectorised int8 GEMM (16 int32 columns/step) — the AVX-512F sibling of SM1 | Reached only from the safe `gemm_i8_avx512`, which runs it **only** when `avx512_ready()` is true — i.e. after `enable` turned on AVX-512 (`ZMM`) state **and** the self-test executed this exact kernel correctly on this core (so the EVEX instructions are legal, no `#UD`). Each `asm!` block reads 16 bytes of `b` and read-writes 16×i32 of `c`, bounded by `j + 16 <= n` (vector path) or `j < n` (scalar tail) within the caller-validated (overflow-checked) `m`/`k`/`n` slice lengths; `vmovdqu32` is the **unaligned** store (no alignment precondition); `a`/`b` shared, `c` exclusive. `zmm0`/`zmm1` declared clobbered; no `nomem` (reads/writes `[b]`/`[c]`), `nostack`, sets no flags. **Interrupts:** may be enabled — `isr_common` (I1) per-IRQ-saves vector state and CI verifies handlers are vector-free. Bit-identical to the scalar reference (`wrapping_add` is associative). | Reasoned + host differential tests (AVX-512F == scalar over the full shape sweep incl. an i32-wrap case, confirmed run on an `avx512f`+`vnni` host — the achieved dynamic coverage). **In-kernel ZMM path OBSERVED:** the `kvm-smp` job booted on a VNNI-capable KVM runner (a superset of AVX-512F) with the archived serial log's `[simd]` line showing `avx512f=ok` (the AVX-512F self-test ran and matched scalar at CPL-0) and `active=avx512-vnni`. Reachable only under KVM on AVX-512 silicon (TCG drops the bits), so it is opportunistic, not every-run. Miri/Kani-opaque (inline asm), like the other HAL asm |
| SM3 | `simd.rs` · `vnni_dp16` (inline `asm!`), called by `gemm_i8_avx512vnni_impl` | EVEX `asm!`: `vmovd`/`vpbroadcastd`(`zmm`) + `vmovdqu32` load(m512) + `vpdpbusd`(`zmm`,m512) + `vmovdqu32` store — one 512-bit fused unsigned×signed 4×int8 dot-product-accumulate over 16 lanes (64 int8 MACs) | Throughput int8 GEMM tier (`VPDPBUSD`, the fused VNNI dot-product) | Reached only from the safe `gemm_i8_avx512vnni`, which runs it **only** when `avx512vnni_ready()` is true — i.e. after `enable` turned on AVX-512 (`ZMM`) state (VNNI reuses it — no extra XCR0 bits) **and** the self-test executed this exact kernel correctly on this core (so the EVEX instruction is legal, no `#UD`). Each `asm!` block reads 64 packed bytes of `b` (a stack-resident B panel) and read-writes 16×i32 of `c`, the caller bounding `c` by `j + 16 <= n` (vector path) or `j < n` (scalar tail) within the overflow-checked `m`/`k`/`n` lengths; both `vmovdqu32`/`vpdpbusd`(m512) are **unaligned** (no alignment precondition); `a` (biased in a GPR) and `b` shared, `c` exclusive. `zmm0`/`zmm1` declared clobbered; no opmask/`k`-reg (unmasked EVEX); no `nomem` (reads/writes `[b]`/`[c]`), `nostack`, sets no flags. **Interrupts:** may be enabled — `isr_common` (I1) per-IRQ-saves vector state and CI verifies handlers are vector-free. **Bit-identical** to the scalar reference via the unsigned/signed **bias correction** `Σ(a+128)·b − 128·Σb = Σa·b` — a ring identity mod 2³² (`VPDPBUSD` wraps, it is not the saturating `VPDPBUSDS`). | Reasoned + host differential tests (VNNI == scalar over the full shape sweep incl. `k` not ÷ 4, `n` not ÷ 16, ±127, and an i32-wrap case, run on an `avx512vnni` host). The **bias-correction ring identity** — the one novel-vs-SM1/SM2 part — has an *always-on, hardware-independent* guard: a pure model `vnni_cell_bias` (no `asm!`) checked vs. the scalar dot product by host tests that run on every runner + under Miri (2000-shape sweep + a wrap case); Kani harnesses cover the identity symbolically and are **enforced**: `proofs::vnni_bias_correction_one_lane_is_exact` (real functions, one lane, all 2¹⁶ byte pairs) plus `proofs::vnni_bias_correction_step_is_exact` (the inductive step over an arbitrary accumulator state, which extends the result to every lane count) are run by the **gating** `kani-hal` CI job as of 2026-07-25. They replaced a single fixed `K = 4` equivalence that cost 858 s and was never discharged live. The always-on host tests + Miri remain the multi-lane guard on the real functions. **In-kernel path OBSERVED:** the `kvm-smp` job booted a VNNI KVM runner asserting `[ml] … active=avx512-vnni; int8 GEMM ok` — so the `VPDPBUSD` kernel + packing/bias computed the identity·B proof correctly at CPL-0 (serial log archived). Opportunistic (VNNI runner assignment is non-deterministic), not every-run. The `asm!` step itself is Miri/Kani-opaque, like the other HAL asm |

> The `enable`/`avx2_ready`/`avx512_ready`/`avx512vnni_ready`/`self_test` logic is
> pure control-flow over the already-documented C8/C11/C12 privileged ops plus
> SM1/SM2/SM3 — it introduces no *other* raw op. The `*_ready` gates read a `static
> AtomicU8` (no `unsafe`). The int8-GEMM loop/packing/bias-correction structure,
> quantization, and tier dispatch live in the **safe** `kernel::ml` and safe parts of
> `hal::simd` (`gemm_i8_avx512vnni_impl`'s packing is safe Rust); only the `asm!`
> inner steps and the vector-state enable are in the TCB. **Interrupts (precondition
> lifted):** the `gemm_i8_*` wrappers are now safe with interrupts **enabled** — the
> ISR stubs (I1) do not save vector state by the GP path, but (a) on this soft-float
> target no compiled handler contains vector instructions (machine-checked by `cargo
> xtask check-no-vector`, so an IRQ cannot clobber the accumulators) and (b)
> `isr_common` additionally `xsave`/`xrstor`s the vector state per IRQ (I1). Proven
> by `kernel::ml::prove_interrupts_on`. The one remaining interrupts-related case is a
> future **preemptive context switch** (per-task save via C13/C14), since a switch
> resumes a different task's vector code. Vector state is **per-core**: each AP must
> `enable()` before any GEMM once SMP lands.

---

## 2k. `hal::smp` — application-processor bring-up over the Limine MP protocol (SMP, phase 2)

Brings every firmware-reported logical CPU into the kernel. The design doc
(`docs/specs/2026-07-16-smp-ap-bringup-design.md`) sketched a hand-written 16-bit
real-mode trampoline, AP bootstrap page tables, a `<1 MiB` reservation, ICR MSR
writes and a MADT parser (rows SMP1–SMP6 + ACPI1–2 there). None of that landed:
the bootloader we already trust for the BSP's mode switch, page tables, HHDM and
memory map performs INIT–SIPI–SIPI and the 16→32→64 walk for every AP itself
(Limine MP request, honoured before `_start`) and parks each AP in 64-bit mode on
the kernel's page tables, interrupts masked, on its own 64 KiB stack in
bootloader-reclaimable memory — which our frame allocator never hands out (it
seeds from `USABLE` only, invariant §4.8), so those stacks, like the BSP's Limine
stack `kmain` runs on, are ours for the whole run. Writing a function pointer to
the CPU's `goto_address` slot releases it. It works under QEMU **TCG** (xAPIC
INIT-SIPI-SIPI), so phase 2 is proven on every `make test`, not only on KVM. The
public surface (`cpus`, `bsp_lapic_id`, `set_ap_main`, `start_cpu`, `CpuDesc`,
`ApInfo`, `MAX_CPUS`) is **safe**; per-CPU state lives in the safe kernel
(`kernel::smp`, a fixed atomics-only array indexed by dense cpu index — zero TCB,
no `%gs`/`swapgs`). Only the BSP prints (the serial console guard is not a
multi-core lock); APs publish into their slot and the BSP reports after `online`.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| SMP1 | `smp.rs` · `cpus()` / `bsp_lapic_id()` / `start_cpu()` | read the `#[used]` `MpRequest`'s response; `MpResponse::cpus()` reconstructs `&[&Cpu]` over the bootloader-filled array | The firmware CPU list (LAPIC IDs, BSP) without a MADT parser | Same pattern as `bootinfo` (B1): the response is `Some` only if Limine filled it before `_start`; the `Cpu` array lives in bootloader-reclaimable memory the allocator never reuses, so the borrow is valid for the whole run; only scalars are copied out (`CpuDesc`), nothing bootloader-owned escapes. | Reasoned + QEMU (`-smp 4` enumerates 4 CPUs, BSP apic 0) |
| SMP2 | `smp.rs` · `enter_ap_entry()` (from `park_cpu()` early, or `start_cpu()`) | `cpu.extra.store(cpu_index)` then `cpu.goto_address.write(ap_entry)` — sends a Limine-parked AP into `ap_entry`, **at most once** per AP (`PARKED` swap); `start_cpu` then sets the AP's `RELEASED` flag and sends the kernel's wake IPI (`apic::send_ipi`, AP-IPI row) | The only way to start a Limine-parked AP. Done early (`park_cpu`, right after `apic::enable_bsp`) because an AP left in Limine's `pause` loop never exits under VirtualBox/Hyper-V NEM, which starves VirtualBox's device timers with 2+ vCPUs (the BSP's first PIT wait hangs) | Both are atomic stores through the crate's safe API (the protocol orders the AP's `extra` read after the `SeqCst` `goto_address` store). Refused unless `1 <= cpu_index < MAX_CPUS` and the entry is not the BSP; `start_cpu` also refuses without a registered `ApMain` and when the AP was parked under another index (`IndexMismatch`) — so `ap_entry` always finds a valid table slot, its own release flag, and a non-null main when released. The obligation that `ap_entry` is a valid entry for Limine's documented AP state is discharged at SMP3. | Reasoned + QEMU (`[smp] cpuN online …` per AP) + VirtualBox 7.2.10 on Hyper-V NEM (4 vCPUs boot only with the early park) |
| SMP3 | `smp.rs` · `ap_entry` (`unsafe extern "C" fn(&Cpu) -> !`) | the AP's fixed privileged sequence: `gdt::init_ap` (G1–G6) → `idt::load` (I6) → `simd::enable` (C8/C11/C12) → `apic::enable_ap` (AP3) → `transmute::<*mut (), ApMain>` → kernel `ap_main` | Give the AP the tables/state the BSP has, in an order that makes "OSXSAVE before first interrupt" structural, then hand it to safe Rust | Invoked only by hardware, once per AP, via SMP2, with `cpu` = that AP's bootloader-owned entry (valid for the run); Limine guarantees 64-bit mode, the kernel's page tables, IF = 0 and a private stack. Every step reuses an audited primitive — **no new instruction**. Its only `sti` is the release wait after `apic::enable_ap`: check `RELEASED` with IF = 0, then `cpu::enable_interrupts_and_halt` (one `sti; hlt` block, C-row) and `cpu::disable_interrupts` — so the first interrupt on an AP still comes only after its own `simd::enable`, a wake IPI sent before the `hlt` stays pending and wakes it, and `ApMain` is entered with IF = 0. Before release only the kernel's wake IPI (handler: EOI only) and LAPIC spurious can reach it (LINT0 masked, timer unarmed, IOAPIC routes to the BSP); with no LAPIC access path it polls instead of halting. The `transmute` is the `interrupts::handler_for` (X1) scheme: the pointer was produced only by `set_ap_main` casting a valid `ApMain`, and `start_cpu` refused to release the AP while it was null (a defensive `halt_loop` covers the impossible case). Reads `extra`/`lapic_id` as plain scalars. | Reasoned + QEMU (`cargo xtask test`, TCG `-smp 4`: three APs each install their own GDT/TSS, load the IDT, enable vector state, run the int8 GEMM proof **on their own core** and publish `online`; the BSP asserts `lapic-match=yes` — the arriving AP's `cpuid` APIC ID equals the slot it was started as — and `gemm=ok` per AP, and the summary `online=4/4 aps-ok=3` is a hard boot-test assertion) |

> **Not in the TCB:** the trampoline, bootstrap page tables, low-memory
> reservation, ICR writes, MADT parser and `udelay` the design doc planned. The
> hand-rolled path remains the fallback if SentinelOS ever ships its own boot
> stage; until then, trusting Limine's AP path is the same trust we already place
> in its BSP path.

## 2n. `hal::rtc` — CMOS real-time clock, read-only (VM polish)

Reads the MC146818-compatible RTC's raw time/date registers for the lock-screen date and clock. Read-only, on the BSP only: once at boot, then ~10 times a second by `kmain`'s idle loop for the on-screen clock (counting PIT ticks drifts under a hypervisor); decoding (BCD/binary, 12/24 h, century, weekday) is safe arithmetic in `kernel::wall`, outside the TCB. Index writes keep port `0x70` bit 7 clear, so the firmware's NMI mask is left as it was.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| RTC1 | `rtc.rs` · `cmos_read()` | `out 0x70, al` (register index, `& 0x7F`) then `in al, 0x71` | The only way to read the RTC | Port I/O touches no Rust memory (`nomem`, `nostack`, `preserves_flags`). Only read-only time/date/status registers are selected (0x00–0x0B, 0x32), so the read changes no device state. Not atomic across cores: the contract is a single caller, and every caller runs on the BSP (boot, then `kmain`'s idle loop, which only the BSP runs). | Reasoned + QEMU, VirtualBox (`[rtc] YYYY-MM-DD HH:MM:SS` matches the host clock; the polled lock-screen clock keeps host time) |
| RTC2 | `rtc.rs` · `read_once()` / `read()` | callers of RTC1 | Avoid a read that straddles the once-a-second update | Bounded waits only: UIP poll capped at 100 000 reads, read-until-stable capped at 8 attempts (then `None`, and the UI keeps its fixed fallback), so a missing or stuck RTC cannot hang boot. | Reasoned |

## 5. `hal::mm` — memory management (sub-project #2 part 1)

Brings the kernel from "no heap" to a working `#[global_allocator]`: a physical
frame allocator over the firmware memory map, virtual page mapping **on top of**
Limine's already-active 4-level paging + HHDM, and a free-list kernel heap. The
public API is **entirely safe** — `mm::init()` returns a `Result`, the frame
allocator and heap expose safe `alloc`/`dealloc`, and the `kernel` crate only
*declares* the `#[global_allocator]` static (declaring a static is not `unsafe`),
so `kernel` stays `#![forbid(unsafe_code)]`. The single `unsafe impl GlobalAlloc`
and every raw page-table / frame / heap-header access live here, below.

The pipeline (`mm::init` → frame allocator seed → heap-page mapping → install
global allocator) is single-call, single-core, interrupts already armed. Page
tables and free frames are reached through the HHDM (`virt = phys + hhdm`), which
Limine maps over all physical RAM and keeps live (we never replace CR3).

### 5a. `hal::mm::bootinfo` — Limine memory-map + HHDM requests

Owns `#[used] static MEMORY_MAP_REQUEST: MemoryMapRequest` and `#[used] static
HHDM_REQUEST: HhdmRequest` (same `#[used]` pattern as `FRAMEBUFFER_REQUEST`). The
safe accessors `usable_regions()` (USABLE entries only) and `hhdm_offset()` are
the only places these responses are dereferenced.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| M1 | `mm/bootinfo.rs` · `hhdm_offset()` | deref the Limine **HHDM response** (`get_response()` → read `offset()`) | Only way to learn the `virt = phys + offset` direct-map offset used to reach page-table/frame memory | `get_response()` yields `Some(&HhdmResponse)` only after Limine atomically populated our `#[used]` request before `_start`; we never mutate the request, copy out the plain `u64` offset, and drop the borrow in-expression. | Reasoned + QEMU (Miri/Kani **pending**) |
| M2 | `mm/bootinfo.rs` · `usable_regions()` | deref the Limine **memory-map response** (`get_response()` → `entries()` slice → read `base`/`length`/`entry_type`) | Only way to learn which physical RAM the frame allocator may use | Response populated by Limine before `_start` (as M1); `entries()` reconstructs a slice from the bootloader-filled array; the borrow stays in the function and each `base`/`length` scalar is copied out into a `UsableRegion`. No response ⇒ empty iterator (never UB). Only `EntryType::USABLE` is surfaced, so reserved/ACPI/framebuffer/loader/kernel regions can never be handed out. | Reasoned + QEMU (Miri/Kani **pending**) |

### 5b. `hal::mm::frame` — physical frame allocator (intrusive free list)

A LIFO free list of 4 KiB frames seeded from the USABLE regions. Each free frame
stores the physical address of the next free frame in its own first 8 bytes,
reached through the HHDM. Safe API: `alloc_frame()` / `dealloc_frame()` /
`free_frames()`. Frame 0 and unaligned addresses are rejected, so a null-like
physical address can never be returned. State lives behind a `SpinMutex` (§5e).

**Live stats accessor (`mm::stats() -> MemStats`).** A purely-safe addition for
the shell's `mem` command: it reads the boot-time frame total from a
`static AtomicUsize` (`TOTAL_FRAMES`, stored once by `init` right after the free
list is seeded), the live free count from `FRAME_ALLOCATOR.free_frames()`, and
the heap size from the `HEAP_SIZE` constant. Reading an atomic and a spin-locked
count is not an `unsafe` operation, so it adds **no** new `unsafe` op to the TCB
(no new row below) — it only *reports* state the allocator already owns.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| M3 | `mm/frame.rs` · `FrameAllocator::init()` | `ptr::write((frame + hhdm) as *mut u64, next)` — store the next-pointer into each free frame | Build the intrusive free list without side metadata | `frame` is a 4 KiB-aligned address inside a USABLE region (so real, unowned RAM); Limine HHDM-maps all RAM, so `frame + hhdm` is a valid, writable, 8-byte-aligned virtual address; the frame is being placed on the list for the first time ⇒ unaliased. Frame 0 is skipped. Single-call, interrupts-armed, single-core. | Reasoned + QEMU |
| M4 | `mm/frame.rs` · `FrameAllocator::alloc_frame()` | `ptr::read((head + hhdm) as *const u64)` — read the next-pointer back | Pop the list head | `head` is a frame the allocator itself pushed (so real, aligned RAM, HHDM-mapped); the read recovers exactly the next-pointer written by M3/M6; it is the last access to the link field before the frame leaves the list ⇒ unaliased. | Reasoned + QEMU |
| M5 | `mm/frame.rs` · `FrameAllocator::dealloc_frame()` | `ptr::write((phys + hhdm) as *mut u64, head)` — push a frame back | Return a frame to the list | `phys` is 4 KiB-aligned (checked) and non-zero (checked); the caller has relinquished it, so `phys + hhdm` is a valid, writable, 8-byte-aligned, unaliased HHDM address for the link write. | Reasoned + QEMU |

### 5c. `hal::mm::paging` — virtual mapping on top of Limine's paging

Reaches the active PML4 via `CR3` + HHDM and installs new 4 KiB leaf mappings,
allocating + zeroing intermediate tables from the frame allocator. Safe API:
`ActivePageTable::map_page(virt, phys, flags, frames)`. We build **on** Limine's
tables (never replace CR3); `map_page` floors `virt`/`phys` to frames, refuses to
silently overwrite a present leaf (`MapError::AlreadyMapped`), and flushes the
TLB. `PageFlags` is a safe value type over the leaf permission bits.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| M6 | `mm/paging.rs` · `ActivePageTable::pml4_phys()` | `mov {}, cr3` (read CR3) | Locate the active top-level page table | Privileged-but-side-effect-free register read; ring 0; `nomem`/`nostack`/`preserves_flags`. The PML4 base is masked out with `ADDR_MASK` (bits 12..51). Cannot violate memory safety. | Reasoned + QEMU |
| M7 | `mm/paging.rs` · `read_entry()` / `write_entry()` | `ptr::read` / `ptr::write` of a `u64` at `(table + hhdm) + index*8` | Read/insert page-table entries | `unsafe fn`s whose contract requires `table` to be a live table frame and `index < 512`; upheld by `map_page` (passes the CR3 PML4 or a child from `next_table_create`, plus 9-bit indices). Target is within the 4 KiB frame, 8-byte-aligned, HHDM-mapped (writable — RAM is writable and our table frames are USABLE RAM). Single-core/caller-serialised ⇒ no concurrent writer. | Reasoned + QEMU |
| M8 | `mm/paging.rs` · `new_table()` | manual `ptr::write(ptr.add(i), 0u64)` loop zeroing a fresh table frame | A new intermediate/leaf table must start all-non-present | The frame is freshly `alloc_frame`d (4 KiB-aligned USABLE RAM, HHDM-mapped, exclusively owned); each `ptr.add(i)` for `i < 512` is within the frame, 8-byte-aligned, writable, unaliased. **Deliberately a `u64` loop, not `ptr::write_bytes`** — `write_bytes` lowers to a `memset` libcall that *faults* on this higher-half static-relocation target (the `.got`/`.rela` sections it needs are discarded by the linker script; confirmed via QEMU). | Reasoned + QEMU (memset-libcall fault reproduced and avoided) |
| M9 | `mm/paging.rs` · `flush_tlb()` | `invlpg [mem]` | Drop any stale TLB entry for a newly-mapped page | Invalidates one page's cached translation; reads no Rust-modelled memory, no stack, preserves flags. Flushing a stale translation can only make accesses more correct — never UB. | Reasoned + QEMU |

### 5d. `hal::mm::heap` — free-list kernel heap + `GlobalAlloc`

A first-fit free list of variable-size blocks over a fixed higher-half window
(`HEAP_START = 0xFFFF_F000_0000_0000`, `HEAP_SIZE = 4 MiB`) that `mm::init` maps
to physical frames before use. Free-block headers live inside the free memory
itself. `LockedHeap` (a `SpinMutex<Heap>`) is the `#[global_allocator]` type the
`kernel` crate declares as a `static`. Alignments above 16 fail with null (the
kernel never requests more); `dealloc` coalesces with the adjacent free block.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| M10 | `mm/heap.rs` · `Heap::install` / `alloc` / `dealloc` / `coalesce_from` | `ptr::write` / `ptr::read` of `FreeBlock` headers at block addresses inside the heap window | Maintain the free list with in-band metadata | All pointers are `ALIGN`(16)-aligned addresses inside the `[HEAP_START, HEAP_START+HEAP_SIZE)` region that `mm::init` mapped writable to real frames; headers are written only into free/just-freed blocks (unaliased); split/coalesce arithmetic keeps every header within its mapped block; the list is serialised by the enclosing `SpinMutex`. `dealloc` reconstructs the same block size from the `Layout` the runtime passes back. | Reasoned + QEMU (heap `Vec`/`Box` allocation proven at boot) |
| M11 | `mm/heap.rs` · `unsafe impl GlobalAlloc for LockedHeap` | implement `alloc` / `dealloc` | Install a `#[global_allocator]` so `alloc` (`Box`/`Vec`/`String`) works | Delegates to the free-list `Heap` under its `SpinMutex` (exclusive access per op). `alloc` returns null or a ≥`layout.size()`-byte block carved from the mapped heap, `ALIGN`-aligned (larger alignments → null, which `GlobalAlloc` permits); blocks are removed from the list on `alloc` and only re-added on `dealloc`, so no two live allocations overlap. `dealloc` is only ever called with a pointer/layout this allocator returned. | Reasoned + QEMU (boot proof: `[mem] heap ok: allocated NNN bytes`) |
| M12 | `mm/heap.rs` · `unsafe impl Send for Heap` | mark the free-list state `Send` | Let `SpinMutex<Heap>` be `Sync` and back the global-allocator `static` | `Heap`'s only non-`Send` field is the `head` raw pointer, which is null or points into the fixed heap window (valid for the program's life); it is never shared outside the `SpinMutex` that serialises all access. Moving a `Heap` does not invalidate the pointer. | Reasoned |

### 5e. `hal::mm::sync` — minimal spin mutex

A tiny `AtomicBool` compare-exchange spinlock so `mm`'s statics (and, since it was
promoted to `hal::sync`, the scheduler's queues and task table, the console guard,
and the heap) are `Sync`. Since SMP phase 2 it **genuinely contends across cores**
— the `Acquire` on acquisition / `Release` on drop pairing is what makes that
sound. It never disables interrupts itself, so a waiter on the *same* core as
a holder that cannot run would spin forever. The rule the kernel's locks follow
(corrected in the FS-1a review — this paragraph used to say every kernel lock
is taken with interrupts already masked, which was never true of the heap):

- **Locks reachable from IRQ context are only taken with `IF = 0`** on the
  local core: the scheduler's per-core queues and task table (`kernel::sched`'s
  locking discipline) and §1's console guard. An interrupt can then never land
  on a core that holds one.
- **Locks never taken from IRQ context may be held with `IF = 1`, provided no
  same-core waiter spins** (the holder can be preempted, and a spinning waiter
  on its core would never let it run again). `kernel::sfs`'s `Sfs` lock meets
  this by disabling preemption while it is held, so no other task runs on that
  core until it is released; `kernel::blk::ata`'s `CHANNEL` by having waiters
  yield instead of spinning.
- **The allocator locks** — the heap's (§5d) and the frame allocator's (§5b) —
  are taken with `IF = 1` from any task, and a same-core waiter *does* spin.
  That is safe only while the waiter is itself preemptible (`IF = 1`,
  preemption enabled): the next tick switches the core to the holder. Hence
  the rule: never allocate or free with interrupts or preemption disabled, or
  under a lock of the first two kinds, while another task on this core may be
  suspended inside the allocator. kmain's `IF = 0` boot sequence qualifies only
  because it is never preempted: the other BSP tasks run solely during its
  yields, none of which happens inside an allocation — the reason `kernel::sched` frees exited
  tasks only from the idle task, with both enabled (FS-1a review fix; it used
  to free them inside `reschedule`, with `IF = 0`). A task blocked in
  `sched::park` is not inside the allocator (it parked voluntarily), so the
  `sfs-commit` task no longer counts against this rule while parked (A25); it
  does whenever it is runnable, which is why kmain still allocates before
  starting it. Park/unpark add no lock: they use the scheduler's two, in the
  same queue → table order.

`try_lock` (safe; same `Acquire`) lets a caller bound its wait — the console
guard uses it so a fault report can never deadlock behind a wedged holder, and
`CHANNEL`'s waiters use it to yield.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| M13 | `mm/sync.rs` · `SpinGuard` `Deref`/`DerefMut` | `&*self.mutex.data.get()` / `&mut *…` — form a reference to the `UnsafeCell` interior | A mutex must hand out `&`/`&mut` to the guarded value while locked | Holding a `SpinGuard` proves the lock is acquired and is the unique guard (only one passes the `compare_exchange`), so forming the shared/exclusive reference is sound and cannot alias another guard's. Released on `Drop`. | Reasoned |
| M14 | `mm/sync.rs` · `unsafe impl Send + Sync for SpinMutex<T>` | mark the mutex `Send`/`Sync` (for `T: Send`) | Allow the guarded value to be shared/sent behind the lock | Mutual exclusion via the `locked` atomic means the inner `T` is never accessed by two threads at once — exactly the `Sync` invariant; sending the owned mutex is sound for `T: Send`. | Reasoned |

> **`fmt`-free serial helpers.** `mm`'s boot proof needs to print dynamic numbers,
> but `println!("{}", n)` *faults* on this target — `core::fmt`'s argument path
> needs `.got`/`.rela` relocations the linker script discards (same root cause as
> the `memset` fault in M8; both reproduced in QEMU). So `hal::serial` gained two
> **safe**, `fmt`-free helpers — `write_str(&str)` and `write_dec(u64)` (digits
> generated into a stack buffer, emitted with interrupts masked) — which the
> `kernel` crate uses to print `[mem] heap ok: allocated NNN bytes …`. No new
> `unsafe`: they reuse the existing `Serial::write_bytes` path (S1–S5).

### 5f. `hal::mm` — device-MMIO mapping + DMA frames (sub-project #6)

Two **safe** additions to the `mm` public API so a device driver (the NIC) can
reach memory-mapped registers and DMA buffers without writing `unsafe` itself:

- `mm::map_mmio(phys, len) -> VirtAddr` — maps a device's physical BAR window
  into a higher-half MMIO virtual window (`0xFFFF_F100_…`, clear of the heap)
  **uncached** (`PageFlags::mmio()` sets PCD+PWT), via the existing
  `ActivePageTable::map_page` (M6–M9). It adds **no** new raw op — it composes
  the already-documented paging primitives; the only new code is a safe bump
  cursor (an `AtomicUsize`) for laying out successive mappings. The PCD+PWT bits
  are a pure value change in `PageFlags::bits()` (safe).
- `mm::DmaFrame::alloc()` — allocates one 4 KiB frame from the global
  `FRAME_ALLOCATOR` (M3–M5) and records both its physical address (for a DMA
  descriptor) and its HHDM virtual address (for CPU access). The frame is zeroed
  with an explicit `u64` loop, exactly as `new_table` (M8) — never
  `ptr::write_bytes` (the `memset` libcall faults on this target).

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| M15 | `mm/mod.rs` · `DmaFrame::alloc()` | `ptr::write((phys + hhdm) as *mut u64, 0)` loop zeroing the frame | A DMA ring/buffer frame must start zeroed | `phys` is a fresh `alloc_frame` result (4 KiB-aligned USABLE RAM, HHDM-mapped, exclusively owned); each `ptr.add(i)` for `i < 512` is in the 4 KiB frame, 8-byte-aligned, writable, unaliased. Explicit `u64` loop (not `write_bytes`) for the same memset-fault reason as M8. | Reasoned + QEMU (NIC rings DMA correctly; pcap shows valid frames) |

> `map_mmio`'s mapping writes go through `ActivePageTable::map_page` (M6–M9,
> already documented); the only difference is the leaf flags carry PCD+PWT for an
> uncached device window. No new raw page-table op is introduced. The MMIO
> *accesses* themselves (volatile loads/stores to the mapped window) live in
> `hal::e1000` and are documented in §6b (N3/N4).
>
> **SMP 3b-ii amendment.** `map_mmio` and `map_firmware_ro` share
> `map_window`, which first computes the page span with the pure
> `mm::phys_span(phys, len, phys_addr_bits())`, then refuses any page-rounded
> span overlapping kernel-owned memory (`MmioError::OverlapsKernelMemory` —
> every caller, incl. the e1000 BAR and the xAPIC page): `None` — and
> `MmioError::BadRange` — for an empty request, a `u64` overflow of
> `phys + len` or of the page round-up, or a span ending above
> `1 << width` (CPUID `0x8000_0008` EAX[7:0], fallback 36; reduced to
> `min(width, C-bit) - reduction` when `0x8000_001F` advertises SME; clamped
> to `[32, 52]`; TME-MK KeyID bits are a residual, see AC2). `map_page` builds the leaf as `phys | flags` with no mask, so
> before this a caller-supplied address with bits 52–62 set would have mapped
> the low frame those bits alias (and slipped past any raw-value range check),
> and bits between `MAXPHYADDR` and 51 would fault with `RSVD`. Kani:
> `phys_span_is_bounded` (every accepted span is page-aligned, covers the
> request and ends at or below `1 << bits`), `phys_addr_bits_decode_is_clamped`.

### 5g. `hal::mm` — guard-paged kernel-thread stacks (`kernel::sched`, PR-A)

One **safe** addition to the `mm` public API for the cooperative scheduler
(`docs/specs/2026-07-15-scheduler-design.md`): `mm::alloc_kernel_stack(pages)`
allocates a dedicated, dynamically frame-allocated kernel stack for a spawned
task, with an unmapped guard page immediately below it (M1: a stack overflow
walks into a never-present page and `#PF`s, instead of silently scribbling over
whatever comes next in the stack VA window). Reserves `pages + 1` pages from a
dedicated bump-allocated VA window (`STACK_WINDOW_BASE`, laid out exactly like
`MMIO_WINDOW_BASE`, §5f), maps the upper `pages` `PageFlags::kernel_rw()` via the
already-audited `ActivePageTable::map_page` (M6–M9), and **never maps** the
lowest page. Like `map_mmio`, this introduces **no new raw page-table op** — it
composes the already-documented frame-alloc/`map_page` primitives — so the row
below documents the *composition's* safety-relevant property (the guard
invariant), not a new instruction class.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| 5g | `mm/mod.rs` · `alloc_kernel_stack()` | frame-alloc + `map_page` loop over the upper `pages` pages of a `pages + 1`-page bump-allocated span | Per-task guard-paged kernel stacks (M1) for `kernel::sched::spawn` | Reuses audited `FRAME_ALLOCATOR::alloc_frame` (M4) / `ActivePageTable::map_page` (M6–M9) unchanged; maps exactly `pages` pages `kernel_rw()` starting one page above the bump-allocated span's base, and **never** maps the lowest page (the guard) — no `unsafe` block is added here beyond what M4/M6–M9 already cover. `KernelStack::top()` is always `PAGE_SIZE`-aligned (hence 16-byte aligned), which `hal::context::Context::for_new_task` (§9) relies on for the fabricated frame's trampoline-`call` alignment. | Reasoned + QEMU (boot proof: `kernel::sched::spawn` allocates a stack for each of the two proof tasks without error) |

> **Guard-page verification, downgraded from a live overflow fault.** The design
> doc's original test was a deliberate stack-overflow `#PF`. That would turn a
> passing boot into "a fault is expected here," which is a worse default-boot
> posture than every other proof in this registry (all of which prove a *positive*
> — something worked — not a *deliberately triggered* fault). Instead,
> `mm::stack_guard_is_unmapped(&stack)` performs a **read-only page-table walk**
> (a new safe query, `ActivePageTable::is_mapped`, built from a read-only sibling
> of `next_table_create` — `next_table_walk` — that never allocates a missing
> table, unlike `map_page`) confirming the guard page's leaf entry is genuinely
> absent. It has no side effect on the page tables and cannot fault. `kernel::sched::spawn`
> calls it once per spawned task and reports the result over serial
> (`[sched] spawn 'A': stack ok, guard-page unmapped=true`). `cargo xtask test`
> asserts this in **both directions**: the passing form (`guard-page
> unmapped=true`) must appear at least once, and the failing form (`guard-page
> unmapped=false`) must never appear anywhere in the log — so neither a walk
> that never ran nor one that ran and failed can slip through.
> `is_mapped`/`next_table_walk` add **no new unsafe op** — they call the
> already-documented, `unsafe fn` `read_entry` (M7) with the exact same
> preconditions `next_table_create` already discharges, just without the
> allocate-on-absent branch. A genuine "actually recurse/overflow into the guard
> page" QEMU test was deliberately **not** added (default- or feature-gated) —
> this read-only walk was judged sufficient evidence for PR-A, and it keeps every
> boot path (default and test) fault-free. If a live overflow-fault test is
> wanted later, it belongs behind an explicit opt-in (e.g. a `#[cfg(feature =
> "debug-guard-fault")]` recursion probe), never in the default `cargo xtask
> test` path.

---

## 6. `hal::pci` + `hal::e1000` — networking (sub-project #6)

Brings up QEMU's Intel **e1000** (82540EM, vendor `0x8086` device `0x100E`): PCI
config-space enumeration to find it, MMIO BAR mapping (via `mm::map_mmio`, §5f),
reset + RX/TX descriptor-ring setup in DMA RAM (via `mm::DmaFrame`, §5f), MAC
read, and an RX interrupt. The privileged surface is two families of raw ops:
**port I/O** of the PCI config ports (`0xCF8`/`0xCFC`), and **volatile MMIO**
loads/stores to the mapped e1000 register window + the descriptor/buffer DMA
memory. The public API (`pci::scan_for`, `PciDevice::*`, `e1000::init`/`mac`/
`send_frame`/`poll_frame`/`on_irq`/`irq`) is **safe**, and **all** scancode-style
protocol logic (Ethernet/ARP/IPv4/ICMP parsing + building) lives in the safe
`kernel::net` module under `#![forbid(unsafe_code)]`, **not** the TCB.

### 6a. `hal::pci` — PCI configuration-space access mechanism #1

All config access goes through two private 32-bit port primitives, `inl`/`outl`,
each with a `# Safety` section; the address-port write + data-port read/write
pair is never interleaved (single-core init). The public surface (`scan_for`,
`PciDevice` BAR/IRQ readers, `enable_bus_master`) is **safe**.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| N1 | `pci.rs` · `inl()` | `in eax, dx` (32-bit port read) | Only way to read the PCI config data port (`0xCFC`) | `unsafe fn` whose `# Safety` requires a read-safe config port; every caller passes `0xCFC`. Pure device read, `nomem`/`nostack`. | Reasoned + QEMU (e1000 found at bus 0; vendor 0x8086) |
| N2 | `pci.rs` · `outl()` | `out dx, eax` (32-bit port write) | Select a config register (`0xCF8`) and write the command register (`0xCFC`) | `unsafe fn` whose `# Safety` requires a write-safe config port; every caller passes `0xCF8`/`0xCFC` with the enable-bit address word or a command-register value (bus-master/memory-space). Device-only effect, `nomem`/`nostack`. | Reasoned + QEMU (bus-master enabled; DMA works) |

### 6b. `hal::e1000` — Intel 82540EM NIC driver

The driver maps BAR0 uncached (`mm::map_mmio`, §5f), allocates the RX/TX rings
and per-descriptor 2048-byte packet buffers as `mm::DmaFrame`s (§5f, M15), and
talks to the device through **volatile** 32-bit MMIO accesses and **volatile**
descriptor/buffer reads/writes. Driver state is a single `static` behind a tiny
local spin mutex (single-core ⇒ never spins). `init` runs once with interrupts
disabled; `send_frame`/`poll_frame`/`on_irq` take the lock briefly.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| N3 | `e1000.rs` · `Mmio::read()` | `ptr::read_volatile(*const u32)` of a register | Read an e1000 register (status, ICR, RDH/TDH, RAL/RAH) | `base` is the virtual base of BAR0 mapped writable+uncached over the device's 128 KiB window; every `reg` is a documented register offset within it and a multiple of 4 (aligned), so the load is in-bounds + aligned. Volatile ⇒ not elided/reordered; the only side effects (e.g. ICR read-to-clear) are accounted for by the driver. | Reasoned + QEMU (MAC read; rings advance; link up) |
| N4 | `e1000.rs` · `Mmio::write()` | `ptr::write_volatile(*mut u32)` of a register | Program the device (CTRL/RCTL/TCTL, ring bases, IMS, tails) | As N3: `base + reg` is a 4-byte-aligned address in the mapped writable BAR window; the store only affects the NIC (config / ring tail / interrupt mask) and cannot alias Rust memory. | Reasoned + QEMU (TX/RX confirmed in pcap) |
| N5 | `e1000.rs` · `read_*_desc`/`write_*_desc` | `ptr::read_volatile`/`write_volatile` of a 16-byte `RxDesc`/`TxDesc` in the ring frame | Maintain the DMA descriptor rings the NIC reads/writes | The ring is a `DmaFrame` (4 KiB, HHDM-mapped, exclusively owned); index `i < 32` and `32 × 16 = 512 ≤ 4096`, so the descriptor is fully in-frame and 16-byte-aligned. Writes are unaliased w.r.t. the NIC: we only advance the ring tail (handing a descriptor to the device) **after** writing it, and read a descriptor's status only to observe the NIC's completion writeback. | Reasoned + QEMU (DD bits observed; pcap frames) |
| N6 | `e1000.rs` · `copy_into_buf`/`copy_out_of_buf` | `ptr::write_volatile`/`read_volatile` of bytes in a packet `DmaFrame` | Stage an outgoing frame / extract a received one | `buf` is a 4 KiB `DmaFrame`; the copy is bounded to `min(len, 2048) ≤ 4096`, byte-aligned, in-frame. The TX buffer is filled before the descriptor tail is advanced (unaliased); the RX buffer is read only after its descriptor reports DD (frame complete, not being written). | Reasoned + QEMU (ARP/ICMP payloads correct in pcap) |
| N7 | `e1000.rs` · `unsafe impl Sync for NicLock` + `with()` `&mut *UnsafeCell` | Share the driver `static` and form `&mut Nic` while the lock is held | The driver state must live in a `static` and be mutated behind a lock | Access is serialised by the `locked` atomic (only one critical section at a time); the inner reference never escapes the closure. **`with()` masks interrupts on the calling core for the critical section** (restoring the prior IF): `on_irq` takes the same lock from the NIC handler, and the Net app reaches `with()` from the idle loop with IF = 1 (`net::status` → `link_up`/`mac`), so an IRQ landing inside that section would spin forever on its own core (found by inspection while routing the line through the IOAPIC, SMP 3b-ii; no boot test exercised it). Same pattern as `mm::sync` (M13/M14). The `Nic`'s raw addresses (MMIO base, DMA frames) are valid for the program's life. | Reasoned + QEMU |

> **Protocol stack is out of the TCB.** Ethernet/ARP/IPv4/ICMP framing,
> checksums, and the reply logic live entirely in `kernel::net`
> (`#![forbid(unsafe_code)]`): pure byte arithmetic over slices, with co-located
> unit tests. The TCB's job is only to move bytes to/from the wire (N3–N7) and
> ack the RX interrupt (`on_irq` reads ICR + EOIs via `ioapic::device_eoi`, IO4). The kernel's
> registered NIC-vector handler is a one-line safe `fn(&InterruptFrame)`.

## 7. `hal::ata` — legacy ATA (IDE) PIO disk driver (storage persistence)

Drives a legacy parallel-ATA hard disk on the **primary** IDE channel using
*programmed I/O*: the CPU moves each 512-byte sector through the 16-bit data
register (`0x1F0`) one word at a time, polling the status register (`0x1F7`) for
the BSY/DRQ handshake. **No DMA, no interrupts** — the whole driver is four port
primitives plus a request→poll→transfer state machine. It backs the on-disk
filesystem persistence in `kernel::fs` (so files survive a reboot). The primary
channel uses the standard PC legacy ports: command block `0x1F0..=0x1F7` and the
control-block Alternate Status register `0x3F6`. Addressing is 28-bit LBA
(LBA28). The public surface (`identify`, `read_sectors`, `write_sectors`,
`flush` — split out of `write_sectors` in SentinelFS FS-1b — `DiskInfo`,
`AtaError`) is **safe** and returns `Result` so the kernel degrades
to an in-memory filesystem when no disk is attached. All hardware access is
funnelled through four private primitives — `inb`/`outb` (8-bit) and `inw`/`outw`
(16-bit) — each with a `# Safety` rustdoc section. The serialiser, CRC, and tree
walk all live in `kernel::fs` under `#![forbid(unsafe_code)]`, **not** the TCB.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| A1 | `ata.rs` · `inb()` | `in al, dx` (8-bit port read) | Read the ATA status (`0x1F7`) / alternate-status (`0x3F6`) / LBA-mid/hi registers | `unsafe fn` whose `# Safety` requires a read-safe ATA register; all callers pass a primary-channel command/control-block port. Pure device read, `nomem`/`nostack`. | Reasoned + QEMU |
| A2 | `ata.rs` · `outb()` | `out dx, al` (8-bit port write) | Program the seccount/LBA/drive-select registers and issue command bytes (`IDENTIFY`/`READ`/`WRITE`/`FLUSH CACHE`). **Amended in SentinelFS FS-1b:** `FLUSH CACHE` is no longer issued at the end of every `write_sectors`; it is the separate public `flush()` (select master → `wait_not_busy` → `FLUSH CACHE` → `wait_not_busy` → ERR/DF check), and `write_sectors` now ends by waiting for BSY to clear and checking ERR/DF. The pre-FS-1b code wrote `FLUSH CACHE` straight after the data phase without waiting for BSY (a command written to a busy drive is ignored); fixed. One new call site of this primitive: `flush()`'s drive select (`0x1F6` ← `0xE0`). **Amended again in FS-1b (time-bounded waits):** BSY/DRQ waits end at a TSC deadline (C16; ≥ 0.8 s per sector, ≥ 8 s per `FLUSH CACHE`, at any plausible TSC rate, plus a read-count backstop) instead of after 100 000 status reads — under host write pressure QEMU's asynchronous IDE completion outlasted the count (FS-1c CI, reproduced on main 1/18 under `dd`). After any `Timeout` the channel is **software-reset** before the error returns (`reset_channel`: Device Control `0x3F6` ← `SRST | nIEN` (`0x06`), hold ≥ 25 000 TSC cycles (≥ 5 µs at ≤ 5 GHz), ← `nIEN` (`0x02`), wait ≥ 10 M cycles (≥ 2 ms), then a BSY wait bounded by ≥ 31 s — the ATA limit), because a timed-out command can still be running or stopped mid-transfer with DRQ pending, and the next command must not start against it. Two new call sites: those two Device Control writes. | `unsafe fn` whose `# Safety` requires a write-safe ATA register; all callers pass a primary command-block port (`0x1F2..=0x1F7`) with a defined LBA/seccount/command byte, or the control-block Device Control register (`0x3F6`) with `SRST | nIEN` or `nIEN` — after a reset the driver states "no device interrupts" (it polls; nothing in the kernel handles IRQ14) instead of inheriting whatever firmware left. Sets up/starts a device operation only; device-only effect, `nomem`/`nostack`. The FS-1b flush split changes *when* the command byte `0xE7` is written and adds one drive-select write with the value `select_lba`/`identify` already write. The timeout recovery adds a **new port and values** — Device Control `0x3F6` with `0x06` then `0x02` — whose effect is likewise device-only (a drive reset; interrupt gating of a line the kernel never services), so the argument is the same: no write here can alias or corrupt Rust-managed memory. What the split weakens is **durability**, not memory safety: a `write_sectors` that returns `Ok` may sit in the drive's cache until the next `flush()`; SentinelFS's commit protocol and the toy `kernel::fs` both call `flush()` where they need durability (invariant 16), and the evidence that the protocol tolerates exactly that is the host crash matrix (`kernel::sfs::crash`: every write index × unflushed subsets in any order × torn superblock sectors); the QEMU torn-commit stage (`cache=writeback`, SIGKILL mid-commit — not a power cut: QEMU's writes survive in order) adds that on the real transport a commit's first writes land only in free blocks and the previous generation mounts byte-exactly. | Reasoned + QEMU (incl. the FS-1b torn-commit stage) |
| A3 | `ata.rs` · `inw()` | `in ax, dx` (16-bit port read) | Pull one PIO data word from the data register (`0x1F0`) during a sector read | `unsafe fn` whose `# Safety` requires the read-safe data port; the sole caller (`read_sectors`, and the IDENTIFY block) reads `0x1F0` **only after DRQ is asserted** (the drive is offering a word). Pure device read, `nomem`/`nostack`. | Reasoned + QEMU |
| A4 | `ata.rs` · `outw()` | `out dx, ax` (16-bit port write) | Push one PIO data word into the data register (`0x1F0`) during a sector write | `unsafe fn` whose `# Safety` requires the write-safe data port; the sole caller (`write_sectors`) writes `0x1F0` **only after DRQ is asserted** (the drive is ready for a word). Device-only effect, `nomem`/`nostack`. | Reasoned + QEMU |

> **Bounded polling, no hangs.** Every BSY/DRQ wait (`wait_not_busy`,
> `wait_for_drq`) spins a fixed budget (`POLL_LIMIT`) and then returns
> `AtaError::Timeout`, so a wedged or absent controller can never hang boot. An
> absent channel is detected early (`status == 0xFF` floating bus → `NoDevice`),
> and an ATAPI signature in LBA-mid/hi is rejected as `NoDevice`, so the kernel
> always falls back to the seeded in-memory filesystem rather than faulting.
>
> **Persistence layer is out of the TCB.** The on-disk image format (superblock
> magic + CRC-32 + the recursively serialised VFS tree), the (de)serialiser, and
> the load/save orchestration all live in `kernel::fs::disk`
> (`#![forbid(unsafe_code)]`): pure byte arithmetic over slices and `Vec`s, with
> co-located host unit tests (round-trip, truncation/bad-tag rejection, CRC
> known-vectors). The TCB's job is only to move 512-byte sectors to/from the
> media (A1–A4). Since SentinelFS FS-1b `write_sectors` is **unflushed** and
> `flush()` (`FLUSH CACHE`) is a separate public call; `kernel::fs`'s save
> ends with one `flush()`, and SentinelFS issues two per commit (spec §8).
>
> **Command serialisation moved to the kernel (SentinelFS FS-1a).** A command
> is a request→poll→transfer sequence that must not interleave with another on
> the channel. That used to hold because `kernel::fs` was the only caller; since
> FS-1a the `sfs-commit` task drives the same disk, so `kernel::blk::ata` holds a
> kernel-side lock (`CHANNEL`) around every `hal::ata` call, and it is the only
> kernel file allowed to name `hal::ata` (`cargo xtask check-ata-callers`, run in
> CI). This protects **disk integrity, not memory safety**: interleaved commands
> could only corrupt a transfer, never memory, so rows A1–A4 are unchanged —
> still `nomem` port I/O whose soundness never depended on the caller being
> single-threaded. (Doc-only change; `hal::ata`'s code is untouched.)
>
> **FS-1b API split (row A2 amended).** `hal::ata` gained a public `flush()`
> and `write_sectors` stopped flushing; `CHANNEL` serialises `flush()` like
> every other command (one command per lock hold), and invariant 16 (§4) makes
> the command-serialisation rule part of the registry rather than a convention
> recorded in a note. Evidence: `cargo +nightly miri test -p hal` and the hal
> Kani suite green — the flush split itself is port I/O, Miri/Kani-opaque like
> A1–A4; the time-bounded waits that came with it add a pure helper,
> `poll_until`, with host tests (also under Miri) and a Kani harness (below) — `make test`'s double boot (the toy FS's
> `persistence PROVEN` line now depends on its explicit `flush()`), and the
> torn-commit stage (QEMU `cache=writeback`, the kernel halted after the
> k-th block write of a commit, QEMU SIGKILLed, the next boot mounts
> generation N−1 intact — which proves the CoW writes land only in free
> blocks; SIGKILL keeps QEMU's writes in order, so flush ordering is proven
> by the host crash matrix, not by this stage). As built: `[sfs] torn-commit: cut-after=2
> recovered-gen=3 data-intact=yes ok` with exactly the 2 cut blocks changed on
> disk and both superblock slots untouched.
>
> **Measured TSC rate (rows A2 and C16, 2026-11-06).** The ATA budgets are now
> durations (`SECTOR_US` 0.8 s, `FLUSH_US` 8 s, `RESET_US` 31 s, `SRST_HOLD_US`
> 5 µs, `SRST_SETTLE_US` 2 ms) converted by `cycles_for` at the measured rate
> + 25 %, so a wedged drive holds `CHANNEL` about 50 s on any TSC instead of
> ~41 s at 5 GHz and ~7 min at 0.5 GHz. Before the measurement, or if it is
> refused, `cycles_for` gives exactly the FS-1b cycle budgets (compile-time
> asserts). No new `unsafe`, no new port, no new instruction.
>
> **FS-1b time-bounded waits (rows A2 and C16).** The status waits end at a TSC
> deadline instead of after 100 000 reads, and a timed-out command resets the
> channel (SRST) before returning. Evidence: host tests of the pure wait loop
> (`hal::ata::wait_tests`, also under Miri), Kani `poll_until_is_a_deadline`
> (0.4 s: a timeout is always a passed deadline or the backstop, a ready drive is
> never reported as one), and `make test` green, also under concurrent host
> `dd … conv=fdatasync` load — the condition that made the read-count bound fail
> in FS-1c's CI (one run here; the reported rate was 1/18 on main).

## 8. `hal::cpuid` — CPU identification (hardware report)

Wraps the `cpuid` instruction so the shell's `cpuinfo` command can report what the
processor actually is (vendor + brand strings, family/model/stepping) and what it
can do (feature flags from leaf 1 ECX/EDX + leaf 7 EBX). `cpuid` takes its *leaf*
in `eax` (and a *sub-leaf* in `ecx`) and returns the selected information word in
`eax`/`ebx`/`ecx`/`edx`. It is the **only** privileged op in the module; everything
else — vendor/brand string assembly, the family/model/stepping decode, and the
feature-bit checks — is pure, safe bit arithmetic (with co-located unit tests). The
public surface (`cpuid::info`, `cpuid::raw`, `max_standard_leaf`,
`max_extended_leaf`, and the `CpuInfo`/`Feature`/`FamilyModelStepping`/`CpuidString`
types) is **entirely safe**, so the `kernel` crate formats the report without any
`unsafe`.

| # | Location | Unsafe op | Why needed | Soundness argument | Verification |
|---|----------|-----------|------------|--------------------|--------------|
| Q1 | `cpuid.rs` · `raw()` | `cpuid` (via `asm!`, with a `rbx`↔scratch `mov`/`xchg` because LLVM reserves `rbx`) | The only way to query the CPU's vendor/brand/feature identification leaves | `cpuid` reads `eax`/`ecx`, writes `eax`/`ebx`/`ecx`/`edx`, touches no memory (`nomem`), uses no stack (`nostack`), and does not affect RFLAGS (`preserves_flags`). It is legal at CPL 3+, so the kernel (CPL 0) may always issue it. We hand `ebx` through a scratch GP register and swap it around the instruction (`mov tmp, rbx; cpuid; xchg tmp, rbx`) because LLVM forbids naming the reserved `rbx` in `out`/`inout`; the swap leaves `rbx` restored and recovers cpuid's `ebx` into `tmp`. Reading CPU identification cannot create UB or alter memory validity/aliasing — it only observes the processor's own description. Unsupported leaves return implementation-defined data, never UB (callers gate on `max_standard_leaf`/`max_extended_leaf`). | Reasoned + QEMU (`cpuinfo` prints the live vendor/brand/features) |

> The string assembly (`CpuidString` — collect register bytes, truncate at the
> first NUL/non-ASCII, trim trailing padding, return a `&str`), the
> `FamilyModelStepping::from_eax` extended-field combining, and the feature-bit
> masks are pure safe logic and are covered by `cpuid.rs`'s `#[cfg(test)]` unit
> tests (Kani candidates — all bit arithmetic, no I/O).

> **`devices` / PCI device list (no new `unsafe`).** The shell's `devices`
> command and `hal::pci::list_devices` (the whole-bus enumeration behind it) add
> **no** new privileged op: they compose the already-documented config-port reads
> (N1/N2) into a fixed-capacity inventory and tag each function with a human name
> by pure table lookup. The framebuffer resolution and RAM/heap figures the
> command also prints come from the existing safe `hal::framebuffer::get` (F1) and
> `hal::mm::stats` accessors.

## 9. `hal::context` — kernel-thread context switch (PR-A + PR-B of the scheduler design)

The trusted core of the cooperative kernel-thread scheduler
(`docs/specs/2026-07-15-scheduler-design.md`, `kernel::sched`): one
`global_asm!` register switch (`sentinel_gpr_switch`), a first-run trampoline
(`sentinel_task_entry_trampoline`), a fabricated-frame builder
(`Context::for_new_task`), and the eager per-task vector save/restore bracket
around the switch (`switch`, reusing `cpu::xsave`/`cpu::xrstor`, C13/C14).
Everything else the scheduler needs (the run queue, task lifetime,
`spawn`/`yield_now`/`exit`, `pick_next`) is safe Rust in `kernel::sched`
(`#![forbid(unsafe_code)]`); `switch` is a **safe** function because `Context`
is a sealed capability (fields private; only `adopt_running`/`for_new_task`
build one) and `TaskHandle` is a `Copy` token minted from a live `&mut
Context` — see the design doc's "sealed capability" argument, mirrored in
`context.rs`'s module docs.

| # | Location | Unsafe op | Why | Soundness | Verification |
|---|----------|-----------|-----|-----------|--------------|
| CX1 | `context.rs` · `sentinel_gpr_switch` (`global_asm!`) | push/pop callee regs, `mov [rdi],rsp` / `mov rsp,rsi`, `ret` | Stable-Rust register switch (no `naked_fn`/`x86-interrupt`) | Saves/restores exactly SysV callee-saved regs (`rbp,rbx,r12-r15`) + `rsp`; caller-saved regs handled by the `extern "C"` boundary; `next.rsp` always a valid fabricated (`for_new_task`) or saved (prior `switch`) frame (sealed `Context`); jumped/`ret`-ed into, never data-deref'd. Contains **no** vector instruction (`cargo xtask check-no-vector` enforces this — confirmed passing). | Reasoned + QEMU (PR-A interleave boot proof: `[sched] cooperative: A0 B0 A1 B1 A2 B2 ok`, deterministic and asserted verbatim by `cargo xtask test`) |
| CX2 | `context.rs` · `sentinel_task_entry_trampoline` (`global_asm!`) | `mov rdi,r13; call r12; ud2` | Land a first-run task in its shim (`kernel::sched::task_shim`) | `r12`/`r13` are set by the fabricated frame (CX3); the shim is `-> !`, so a return would be a bug — `ud2` traps it instead of falling through to garbage | Reasoned + QEMU (every spawned task's first run in the PR-A boot proof exercises this path) |
| CX3 | `context.rs` · `Context::for_new_task` | raw `u64` writes of the 7-qword initial frame to `stack.top() - 56` | Seed the fabricated switch frame `sentinel_gpr_switch`'s pop sequence expects | Writes only within the caller-owned, exclusively-mapped `hal::mm::KernelStack` (§5g) below `stack.top()` (a multiple of `PAGE_SIZE`, hence far larger than 56 and 8-byte-aligned); frame layout matches CX1's pop order exactly (r15..rbp then a return address). `stack.top()` being `PAGE_SIZE`-aligned (⇒ 16-byte aligned) is also what makes the trampoline's first `call` (inside CX2) SysV-legal — `switch` reaches the trampoline via `ret`, not `call`, so no extra push shifts alignment before that `call`. | Reasoned + QEMU (fabricated frames run every spawned task correctly in the PR-A boot proof — a wrong layout/alignment would hang or triple-fault, per the design doc's bring-up debugging notes) |
| CX4 | `context.rs` · `switch` | deref `prev`/`next` `TaskHandle` + `cpu::xsave`/`cpu::xrstor` (C13/C14) | Save/restore per-task vector state around the GP swap | Handles are sealed tokens minted (`TaskHandle::new`, itself safe) from live `&mut Context` references that, by `kernel::sched`'s invariant (a `Box<Task>` is dropped only in the exit/reap path, after the task can never again be a switch target), outlive their uses; the kernel always calls `switch` with interrupts disabled, and — since PR-2 made scheduling per-core — every task is **pinned** to one core whose queue alone ever holds it, so only that core's `reschedule_locked_on` ever mints or uses handles to it: no cross-core aliasing is possible by construction (a `Context` is never touched by two cores). **PR-B**: this now holds for *two* call paths, not one — the cooperative path (`kernel::sched::reschedule`, which explicitly `cli`s first) and the **timer-preemption** path (`kernel::sched::on_tick` → `reschedule_locked`, called directly from timer-IRQ context where the interrupt gate already cleared `IF`) — both disable interrupts before ever calling `switch`, and neither re-enables them until after it returns (see `kernel::sched`'s interrupt-flag-discipline docs). The `xsave`/`xrstor` bracket is gated on `crate::cpu::osxsave_enabled()` — a **live read of the executing core's `CR4.OSXSAVE`** (originally a `pub(crate)` getter over the global `VECTOR_SAVE_ARMED` flag; replaced in SMP phase 2 because that flag was BSP-global while `OSXSAVE` is per-core) — so it **never** runs before `simd::enable` has set that bit on *this* core (which `enable` does only after verifying the save area fits and round-trips; on failure it clears the bit): the same per-core test `isr_common` (I1) performs in assembly, applied to a second call site. `prev_ctx.xsave`/`next_ctx.xsave` satisfy C13/C14's contract via `XsaveArea`'s runtime-aligned window (CX6). | Reasoned + QEMU + **security-engineer gate for PR-B: SIGNED OFF** — the combined PR-B review explicitly covered the H2 security angle and verified requirements #1–#5 in code: the eager `xsave`/`xrstor` bracket runs identically (no bypass) on both the cooperative and ISR-tail switch paths, first-run switch-in restores an all-zero image (architectural init — never inherits prior registers), and zeroize-on-Drop still runs for a preempted-then-exited task; the follow-up re-read lifted the unrelated B1 liveness BLOCK (PR-A's tasks do no vector work, so this bracket only round-tripped an *empty* vector state there; the *payoff* proof — a GEMM task's live YMM/ZMM accumulators surviving genuine, timer-driven preemption bit-exact, with a second task also making progress — is PR-B's boot proof, `kernel::sched::prove_preemptive`, marker `[sched] preemptive: gemm-iters=N gemm-exact=yes spin-iters=N preempted=N ok`, asserted by `cargo xtask test`) |
| CX5 | `context.rs` · `unsafe impl Send for Context` | mark `Context` `Send` | `kernel::sched`'s `hal::sync::SpinMutex<SchedState>` (holding `BTreeMap<TaskId, Box<Task>>`, and `Task` embeds a `Context`) needs `Send` on its contents for the mutex to be `Sync` (mirrors `hal::mm::heap`'s `unsafe impl Send for Heap`, M12) | `Context`'s only non-`Send` field is the `xsave: *mut u8` raw pointer, which addresses a heap allocation (`Box<XsaveArea>`) that is always owned by, and moves as one unit with, the *same* `Task` as this `Context` — never a "shared" pointer in the aliasing sense. Nothing reads/writes through it except `switch` (CX4), with interrupts disabled, never re-entrantly, and — tasks being pinned (PR-2) — only ever on the one core the task belongs to, so there is never a concurrent access to race. `Send` is needed because the `Box<Task>` lives in the cross-core `TASKS` slab (`SpinMutex<TaskTable>`), which requires its contents `Send` to be `Sync`; the *access* pattern remains one core per `Context`. | Reasoned (not exercised in a way distinguishable from single-threaded use; SMP-forward note in the design doc applies here too — see "SMP-forward" section) |
| CX6 | `context.rs` · `XsaveArea::as_mut_ptr` | `self.0.as_mut_ptr().add(offset)` — runtime pointer offset to a 64-byte-aligned window inside oversized, default-aligned backing storage | `XsaveArea` cannot be `#[repr(align(64))]`: it is boxed directly by the `forbid(unsafe_code)` `kernel` crate (`Box::new(XsaveArea::new_init())`), and the kernel heap allocator (`hal::mm::heap`, §5d) only honours alignments up to 16 bytes — a 64-byte-aligned `Layout` request would return null (a failed allocation), which is exactly what PR-A's first implementation hit at boot (`memory allocation of 4096 bytes failed`) before this fix. So `XsaveArea` holds `XSAVE_AREA_SIZE + 64` bytes of plain (1-byte-aligned) storage and computes a 64-byte-aligned `XSAVE_AREA_SIZE`-byte window into it on every access — the same "reserve extra, align at runtime" technique `isr_common`'s **on-stack** save area uses (`sub rsp, area_size; and rsp, -64`), just applied to a heap allocation instead of a stack pointer. | `window_offset()` returns `base.wrapping_neg() & 63`, always in `0..64` (a power-of-two mask), so `offset + XSAVE_AREA_SIZE <= 63 + XSAVE_AREA_SIZE < self.0.len()` (`= XSAVE_AREA_SIZE + 64`) — always in bounds; `base + offset` is a multiple of 64 by construction — always aligned. Recomputed from `self`'s **current** address on every call (never cached), so it stays correct across the moves a fresh `XsaveArea` typically undergoes before reaching its final `Box` (a plain byte array's move is a bitwise copy, which changes its address) — only the address at the point of use matters. Host + Miri unit tests (`context::tests::as_mut_ptr_window_is_64_byte_aligned_and_in_bounds`) assert the alignment/bounds property directly. | Reasoned + host tests + Miri (`cargo +nightly miri test -p hal context::`, 0 UB) + QEMU (every `switch` call with the vector bracket armed exercises this pointer) |

> **Deviations from the design doc's sketch, and why.** CX5 and CX6 are **not**
> in the design doc's original `hal::context` sketch — both were required fixes
> discovered during implementation, not scope creep:
> - **CX5 (`Send`)** — the design's `Task`/`SchedState` sketch does not mention
>   `Send`/`Sync` bounds at all; the compiler requires it the moment `Context`
>   (holding a raw pointer) is stored inside a `Box<Task>` inside a
>   `BTreeMap` inside a `SpinMutex`-guarded `static`. Structurally identical to
>   the already-established `Heap`/`SpinMutex<T>` pattern (M12/M14), just a new
>   instance of it.
> - **CX6 (runtime alignment)** — the design's `XsaveArea` sketch is
>   `#[repr(C, align(64))]` over a plain `[u8; XSAVE_AREA_SIZE]`. That is exactly
>   what PR-A's first implementation shipped, and it **failed at boot**: the
>   kernel heap allocator's `alloc()` (§5d) rejects any `Layout` with
>   `align() > 16` (returning null, its documented, deliberate behaviour — no
>   caller before this had ever requested more than 16), and `kernel::sched`
>   boxes an `XsaveArea` directly. The fix keeps the *external* contract
>   identical (`new_init`/`zeroize`/the pointer `switch` passes to C13/C14 are
>   unchanged in shape) and confines the new unsafe entirely to `XsaveArea`'s
>   own accessor, so no other part of the design (`Context`, `switch`,
>   `kernel::sched`) had to change.
> - **`kernel::sched`'s internal task-struct shape** also differs in minor,
>   non-`unsafe`-relevant ways from the design's sketch (e.g. `Task.stack` is
>   `Option<hal::mm::KernelStack>` — `None` for the adopted idle task, whose
>   stack was never allocated by `alloc_kernel_stack`; the `handle` sketch
>   field is not stored — `TaskHandle`s are minted fresh from a live `&mut
>   Context` at each use rather than cached). None of these touch the TCB;
>   they are safe-Rust implementation choices in `#![forbid(unsafe_code)]`
>   `kernel::sched`.

> **PR-B additions (no new TCB `unsafe` op).** Landed entirely in safe
> `kernel::sched` plus one re-exposed (not new) `hal` primitive:
> - **`Task.slice: u32`** (deferred from PR-A, per the bullet above) is now
>   live: initialised to `TIME_SLICE_TICKS` (10 ticks / 100 ms at
>   `hal::pit::TICK_HZ`) and decremented once per tick by `on_tick`.
> - **`kernel::interrupts::handle_timer`** now calls `sched::on_tick()` after
>   `hal::pit::on_tick()` (still safe; no new `unsafe`).
> - **Interrupt-flag discipline fix** (PR-A combined-review carry-item):
>   `reschedule` no longer unconditionally `sti`s at its tail. It is split
>   into `reschedule_locked` (never touches `IF`; the sole caller from
>   timer-IRQ context, `on_tick`, invokes this directly — it is *already*
>   running with `IF` clear from the interrupt gate and must return leaving it
>   clear, so the ISR stub's own `iretq` restores the *interrupted* task's own
>   saved flags) and `reschedule` (the voluntary/cooperative wrapper used by
>   `yield_now`/`exit`/the deferred `preempt_enable` drain, which saves the
>   caller's actual `IF` state via the new `hal::cpu::interrupts_enabled()`
>   and restores exactly that — not an unconditional `sti` — around
>   `reschedule_locked`). `task_prologue`'s unconditional `sti` was reviewed
>   and left unchanged: a freshly-trampolined task never has a pending
>   `iretq` of its own (whichever stack it lands on is brand new), so
>   establishing its preemptible baseline there is never "early" relative to
>   any interrupt return, regardless of whether the switch that started it was
>   cooperative or timer-driven.
> - **`hal::cpu::interrupts_enabled()`** (new `pub fn`) is a thin wrapper over
>   the *already-audited* `serial::interrupts_enabled` primitive (visibility
>   widened from private to `pub(crate)`; see §1 S6), used by a new private
>   `kernel::sched::with_interrupts_disabled` helper that guards every other
>   `SCHED`-locking accessor (`spawn`/`current_id`/`task_ids`/`task_name`/
>   `task_stack_pages`/`init`) against the same reentrant-timer-preemption
>   hazard: `hal::sync::SpinMutex` does **not** itself disable interrupts (it
>   is a plain spinlock), so any of these holding `SCHED`'s lock with
>   interrupts enabled would otherwise be vulnerable to `on_tick` trying to
>   re-acquire the same lock from a nested timer IRQ and spinning forever on
>   the single core that can never release it — a self-deadlock. Adds
>   **zero** new `unsafe` operations (it is a safe fn calling a safe fn).
> - **PR-B boot proof** (`kernel::sched::prove_preemptive`): a "gemm" task
>   (loops a fixed int8 GEMM) and a "spin" task (loops a counter) are spawned
>   and **never call `yield_now`**; only the timer can switch them. Evidence
>   line: `[sched] preemptive: gemm-iters=N gemm-exact=yes spin-iters=N
>   preempted=N ok` — asserted by `cargo xtask test` requiring `gemm-exact=yes`,
>   `preempted>=1`, and both iteration counts `>0` (not an exact string match,
>   since iteration/preemption counts are inherently timing-dependent).

## 3. Verification roadmap (sub-project #2+)

| Tool | Applicable to | Status |
|------|---------------|--------|
| Manual review + adversarial review (kernel-reviewer) | all entries | scheduled (build sequence step 6) |
| QEMU boot evidence | S1–S5, C3–C4 (serial output + clean halt); F1–F2 (framebuffer plotted in QEMU once the boot screen renders); **M1–M14 (`cargo xtask test` boots, maps the heap, and allocates: `[mem] heap ok: allocated NNN bytes` — `Box`/`Vec` through the global allocator — before the banner + `boot-bringup-ok`)**; **A1–A4 (`cargo xtask test` attaches a persistent IDE disk; `kernel::fs` logs `[fs] loaded filesystem from disk` / `[fs] no valid image on disk; seeding + saving` proving IDENTIFY + sector read/write; reboot-persistence demonstrated by writing a file then re-launching QEMU on the same image)**; **AP1–AP2 (`cargo xtask test` boots the guest with `-smp 4`; because QEMU 8.2 TCG cannot advertise x2APIC, `kernel` logs the `has_x2apic()`-gated fallback `[smp] x2APIC not advertised; staying on legacy xAPIC/PIC` and still reaches the banner + `boot-bringup-ok` — proving graceful degradation + no regression. The x2APIC *enable* path (`[smp] x2APIC enabled …; timer live (N ticks)`) runs on KVM / real hardware)**; **SMP1–SMP3 + G6 + I6 + AP3 + the live-`CR4` gate in I1/CX4 (`cargo xtask test`, TCG `-smp 4`: the bootloader parks 3 APs, `kernel::smp::bring_up_aps` releases each into `hal::smp::ap_entry`, and the BSP asserts one `[smp] cpuN online: apic-id=N lapic-match=yes x2apic=… simd=yes gemm=ok` line per AP plus the summary `[smp] online=4/4 … aps-ok=3` — every AP on its own GDT/TSS + the shared IDT, with its own vector state live and bit-exact; `lapic=x2apic` per AP and the AP3 write sequence are additionally exercised by the `kvm-smp.yml` job)**; **AP7 + the per-core tick (`cargo xtask test`, TCG `-smp 4`: `[timer] lapic: … scheduler tick on every core`, `tick=lapic` per AP, and `[sched] ap-preemptive: cpuN gemm-iters=N gemm-exact=yes spin-iters=N tick-preempted=N ok` — the PR-B payoff proof on an application processor, with `tick-preempted` counting only that core's own LAPIC-timer switches)**; **AP4–AP6 + C15 + the per-CPU scheduler (`cargo xtask test`, TCG `-smp 4`: `kernel::sched::prove_pinned` places a task on an application processor with `spawn_on`, `send_ipi` wakes that core out of `sti; hlt`, its `on_resched_ipi` switches to the task at the ISR tail, the task records its own core from `cpuid` and exits back to the AP idle, and the BSP asserts `[sched] pinned: target=cpuN ran-on=cpuN bsp=cpu0 distinct=yes ok` — the whole cross-core path, over the MMIO arm under TCG and the MSR arm under KVM)**; **CX1–CX4 + 5g (`cargo xtask test` spawns two kernel threads that interleave via voluntary `yield_now`/`hal::context::switch`, asserting the exact deterministic marker `[sched] cooperative: A0 B0 A1 B1 A2 B2 ok` — a wrong fabricated-frame layout, a misaligned trampoline `call`, or a corrupted register/stack swap would hang, triple-fault, or print a different interleave, all of which fail the assertion; each spawn also logs the guard-page read-only-walk result, `guard-page unmapped=true`)** | via `cargo xtask test` (test-engineer) |
| QEMU **fault tests** (the #2a evidence) | G1–G5, I1–I5, X1 — `int3` → `EXCEPTION: BREAKPOINT`, deliberate #PF → `EXCEPTION: PAGE FAULT` + no reset loop, forced #DF on the IST stack → `EXCEPTION: DOUBLE FAULT` | via `cargo xtask test-faults` (test-engineer, build sequence step 4) — **this is the primary correctness check for the ISR/asm + descriptor-table loads** |
| Miri | pure logic helpers only (cannot model port I/O / `hlt`/`cli`/`sti` / descriptor loads / ISR stubs / CR3 / `invlpg` / raw page-table writes / inline `asm!` such as `cpuid`/`rdmsr`/`wrmsr`) | **live** — `.github/workflows/verify.yml` runs `cargo +nightly miri test -p hal` (and, scoped to `kernel::ml`, `cargo +nightly miri test -p kernel ml::`; scoped to `kernel::sched`, `cargo +nightly miri test -p kernel sched::` — the pure `pick_next` queue-policy tests) on every kernel change (33 hal tests, 0 UB, as of this writing — re-run `cargo +nightly miri test -p hal --target x86_64-unknown-linux-gnu` to get the current count); covers new test-exercised paths automatically as they are added. Includes CX6's runtime alignment arithmetic (`context::tests::as_mut_ptr_window_is_64_byte_aligned_and_in_bounds`, `new_init_is_all_zero`, `zeroize_clears_a_dirtied_area`) and `kernel::sched`'s 8 queue-policy tests (round-robin rotation, exit-vs-requeue, Invariant #4 no-lost/no-duplicated-ids, `preempt_disable`/`preempt_enable` round-trip) — both 0 UB. **Honesty note:** under Miri, `std::is_x86_feature_detected!` always reports `false` (Miri has no CPUID model), so **every** `hal::simd` hardware differential test (`kernels_match_scalar_*`, `kernels_extremes_do_not_diverge`, `kernels_i32_accumulator_wraps_like_scalar`) silently early-returns without exercising any GEMM kernel or its pointer arithmetic — Miri's real `hal::simd` coverage is the **pure logic**: the always-on `vnni_cell_bias` bias-correction model tests and `wrappers_reject_bad_dims_and_unready`'s dimension/readiness rejection paths, not the vector kernels (`avx2_madd8`/`avx512_madd16`/`vnni_dp16`) or their `unsafe` pointer arithmetic, which stay Miri-opaque like the rest of the inline `asm!` in this registry. Similarly, `hal::context`'s `sentinel_gpr_switch`/`sentinel_task_entry_trampoline`/`for_new_task`'s frame write/`switch`'s `xsave`/`xrstor` bracket are Miri-opaque (register/stack swap + privileged vector instructions) — only CX6's alignment arithmetic is Miri-exercised, per the design doc's "What Miri/Kani can cover" section |
| Kani (bounded model checking) | bit-level helpers (e.g. IF/LSR masks, newline translation, gate/TSS descriptor bit-packing, RFLAGS/error-code decoders, **framebuffer `pack_rgb` channel packing + `byte_offset`/`fill_rect` bounds/clip arithmetic**, **`mm` address-index decomposition `VirtAddr::table_indices`, frame-align math, `PageFlags` bit-packing, and `align_up`/free-block split arithmetic**, **the AI/ML tier-dispatch total-function proof (`kernel::ml::proofs::capability_from_flags_is_total`) and the VNNI bias-correction ring identity (`hal::simd::proofs::vnni_bias_correction_is_exact`)**) | **harnesses written in-tree**, `#[cfg(kani)]`: `cpuid::FamilyModelStepping::from_eax` (total + bounded over all 2³² inputs), `ata::validate` (the read/write safety gate — proves no unsafe request is accepted), `apic::{ecx_has_x2apic, ebx_logical_cpu_count}` (total + bit-exact / clamped-to-`1..=255` over all inputs), `simd::proofs::{vnni_bias_correction_one_lane_is_exact, vnni_bias_correction_step_is_exact}`, and `kernel::ml::proofs::{capability_from_flags_is_total, checked_shape_two_factor_is_total, checked_shape_matches_checked_mul_bounded}`. Run with `cargo kani -p hal` / `cargo kani -p kernel`. **Status as of 2026-07-25: discharged live.** The hal harnesses run in the **gating** `kani-hal` job (6/6, ~52 s); the kernel harnesses run in `kani-kernel`, which stays `continue-on-error` only until a green run promotes it (6/6, ~63 s locally). The earlier claim that the Kani toolchain could not fetch its bundle in the dev sandbox was **wrong** — it installs and runs fine, and local iteration is how the two intractable harnesses below were found and fixed. The always-on host tests (and Miri) remain a parallel guard, not the sole one. Sched coverage now exists: `sched::proofs::{invariant4_no_lost_or_duplicated_ids_bounded, preempt_count_nesting_never_underflows, tick_action_suppression_dominates}` cover the design doc's bounded-model-checking targets (Invariant #4 over symbolic yield/exit interleavings, `PREEMPT_COUNT` never underflowing, and the cooperative-proof preemption suppression). Invariant #4 is proven over **8 symbolic scheduler passes across a 6-id universe** (2026-07-26) — enough to saturate the reachable space, since round-robin rotation has period 6 and at most 5 tasks can exit before the queue drains. It was previously pinned at depth 2 by a CBMC memory ceiling; that ceiling was `VecDeque`'s heap model, not the policy, and was removed by making `pick_next` generic over a minimal `ReadyQueue` trait so the proof drives the real function over an allocation-free queue. More harnesses per the list at left to follow |
| Kani — SMP 3b-ii additions (2026-10-04) | hal: `ioapic::proofs::{redirection_entry_round_trips_and_sets_only_writable_bits, redirection_entry_from_raw_is_total, programmable_entries_never_target_exception_vectors}`, `apic::proofs::isr_slot_is_exact`, `mm::phys_span_proofs::{phys_span_is_bounded, phys_addr_bits_decode_is_clamped}`; kernel: `acpi::proofs::{madt_walk_is_total_and_tiles, one_entry_decode_is_total_and_exact, push_respects_capacity, madt_body_smoke_46, rsdp_decode_is_total, root_entry_is_total}` | **discharged locally**, each harness alone (wall incl. cached build; review round 2): hal 4 / 3 / 1 / 3 / 4 / 1 s; kernel 9 / 44 (33 s verification; symbolic `MadtInfo` start) / 6 / 48 (43 s verification; `cover!(r.is_ok())` satisfied) / 14 / 6 s — every one under the 60 s rule. The original monolithic `madt_body_decode_is_total_and_bounded` (333 s) was split compositionally: the walk (`for_each_entry`) is proved total and exactly tiling (with an always-`Ok` closure: error propagation is host-tested, not proved), each structure's decode total and exact **from any in-capacity accumulator state**, `push` capacity-safe, plus a composed 46-byte smoke (48 bytes measured 68 s). Full suites: see the PR. Miri: `hal` and `kernel acpi:: ioapic::` clean; the latter is a new step in `verify.yml` |
| Fuzzing | `Serial::write_bytes` newline translation over arbitrary inputs | **pending** |
| Fuzzing (deterministic mutation, host test) | `kernel::acpi::parse_madt` over 200 000 mutants of QEMU's real MADT (byte flips, length rewrites, truncation, half re-checksummed so mutants reach the structure walk; 42 158 (21 %) parse, the test requires > 20 000) | **live** in `cargo test` (300 mutants under Miri). Not coverage-guided: a `cargo-fuzz` lane is still the memory-boundary gate's precondition (STATE.md) |

> **#2a note:** the GDT/TSS/IDT loads and the raw ISR stubs are not Miri- or
> Kani-executable (no model for `lgdt`/`lidt`/`ltr`/`iretq` or the stub asm). Their
> correctness is verified by the **QEMU fault tests** above (int3 / #PF / #DF
> serial markers + no triple-fault reboot loop), plus the emitted-assembly audit
> already performed for the per-vector error-code logic. Pure helpers (gate/TSS
> bit-packing, decoders) remain Kani candidates.

## 4. Invariants the rest of the kernel relies on

1. `serial::init()` is called exactly once before the first `print!`/`println!`.
2. No `panic!`/`unwrap` on the normal print path — `_print` drops the
   (infallible) formatting `Result` to stay panic-free (spec §8).
3. `cpu::halt_loop()` never returns and never unwinds (`panic = "abort"`).
4. The `kernel` crate touches hardware *only* through these safe wrappers; it
   never writes `unsafe` itself.
5. `interrupts::init()` (which calls `gdt::init()` then `idt::init()`, in that
   order) is called **exactly once** on the boot core with interrupts disabled,
   **before** `kmain` does anything that could fault. GDT before IDT: the IDT's
   gates reference the GDT's kernel-code selector and the IST the TSS arms.
   Application processors never call it: each runs `gdt::init_ap(slot)` (its own
   tables, G6) then `idt::load()` (the BSP's finished IDT, I6) from
   `hal::smp::ap_entry`, and no AP is released before `interrupts::init()` has
   completed on the BSP.
6. Handlers registered via `interrupts::set_handler()` are plain safe
   `fn(&InterruptFrame)` and must not assume they can resume (this slice reports
   and halts); the trampoline calls the registered handler, or `hal`'s built-in
   `default_handler` (report + `halt_loop`) when none is registered — so an
   unhandled exception still produces a serial report instead of a triple fault.
7. `framebuffer::Framebuffer::get()` is the **only** place the Limine framebuffer
   response is dereferenced; it returns `None` (never UB) when no framebuffer was
   provided. All drawing through the returned handle is safe and bounds-checked
   — an off-screen coordinate is a no-op and `fill_rect` clips — so the `ui`
   crate (and `kernel`) can draw without writing `unsafe`. Write coordination is
   the caller's responsibility (single-core at bring-up); the handle exposes no
   interior mutability.
8. `mm::init()` is called **exactly once**, early in `kmain` (after
   `interrupts::init()`, before any heap allocation), and builds **on top of**
   Limine's active paging + HHDM — it never reloads CR3. It returns a `Result`;
   the global allocator is installed only on `Ok`, so no allocation must occur
   before a successful `init`. The frame allocator only ever yields
   `EntryType::USABLE` RAM (never reserved/ACPI/framebuffer/loader/kernel), is
   4 KiB-aligned, and never returns physical frame 0. The `kernel` crate only
   *declares* the `#[global_allocator]` static (`hal::mm::LockedHeap`) — declaring
   a static is **not** `unsafe`, so `kernel` stays `#![forbid(unsafe_code)]`.
9. On this higher-half, statically-relocated target, the `core::fmt` argument path
   and the `memset`/`memcpy` compiler libcalls **fault** (they need `.got`/`.rela`
   relocations the linker script discards). Therefore `mm` zeroes page-table
   frames with an explicit `u64` loop (never `ptr::write_bytes`), and dynamic
   boot output uses the `fmt`-free `hal::serial::write_str`/`write_dec` helpers
   rather than `println!("{}", …)`. Both are reproduced + avoided (see M8 / §5e).
10. **AP entry ordering.** There is exactly one application-processor entry,
    `hal::smp::ap_entry` (SMP3), and its sequence is fixed: private GDT/TSS →
    shared IDT → `simd::enable` → `apic::enable_ap` → the kernel's registered
    `ApMain`. It contains no `sti`; the kernel's `ap_main` publishes `online`
    and only then enables interrupts. So on every core `CR4.OSXSAVE` is decided
    (set, or verified-unfit and cleared) before that core's first interrupt —
    and `isr_common` / `context::switch` check the live bit regardless.
11. **`OSXSAVE` ⇒ save contract.** `simd::enable` leaves `CR4.OSXSAVE` set on a
    core only if that core's `cpuid`-`0xD` `xsave` size fits `VECTOR_SAVE_AREA_MAX`
    and an `xsave`/`xrstor` round-trip passed there; otherwise it clears the bit
    and returns `false` (scalar tiers only on that core). The per-IRQ and
    per-task vector saves rely on exactly this: a set bit is the whole
    precondition, per core, with no software flag to keep in sync.
12. **Console writes are serialised across cores.** `hal::serial`'s guard masks
    interrupts on the calling core *and* holds the cross-core `CONSOLE_LOCK`
    (bounded wait, then write anyway — a fault report must never deadlock).
    Bring-up output is still BSP-only by design (APs publish into their
    `kernel::smp::PerCpu` slot and the BSP reports), so the boot-proof text stays
    deterministic in order; the lock exists for everything after that.
13. **Scheduler locks: one order, no allocation underneath.** `kernel::sched`
    takes a core's queue lock before the task table, never the reverse, always
    with interrupts masked on the local core, never across `context::switch`,
    and **never while allocating or freeing** — both locks are taken from IRQ
    context (BSP timer tick, AP reschedule IPI), and an allocation under either
    would form a cycle with the heap lock held by an interrupted task on another
    core. The task table is a fixed slab and every ready queue a fixed ring so
    that this is structural, not disciplinary.
14. **IPIs are the only cross-core control path.** A core acts on another core's
    state only by pushing to its queue (under that queue's lock) and sending the
    reschedule vector (`0xF0`); the target does the switch itself, at its ISR
    tail, exactly like a timer tick. Tasks never migrate. Every core has its
    own LAPIC-timer tick (phase 3), so tasks on any core are timer-preempted;
    the PIT (BSP only, via the IOAPIC since SMP 3b-ii) is the wall clock
    `hal::pit::ticks` and the LAPIC timer's calibration reference, nothing else.
15. **The PIT wall clock advances only when the BSP services IRQ0; nothing that
    waits across cores may time itself on it.** (Retired as a hazard in SMP
    phase 3b-i, 2026-09-18.) The safe kernel's `kernel::clock::mono_ticks` is
    the max over per-core aligned tick counts — advanced by *any* core's LAPIC
    tick, never backwards, at most one per tick (Kani) — so a BSP spinning with
    `IF = 0` no longer freezes the clock another core's work is timing itself
    against, as long as that core is ticking. `sched::wait_on_other_core` and
    the preemption-proof tasks tick off it; proven at boot by
    `[clock] mono: … pit-frozen=yes bsp-stalled-advance=yes rate-ok=yes ok`.
    The one place that still needs the interrupt window is
    `kernel::smp::wait_online`: it waits for an AP whose timer is not running
    yet, so only the BSP's own tick can carry either clock there. The PIT
    remains the wall clock for uptime display and the LAPIC calibration
    reference (invariant 14).
16. **ATA commands are serialised by `kernel::blk::ata`'s `CHANNEL` lock, and
    durability needs an explicit `flush()`.** (SentinelFS FS-1b.) Every
    `hal::ata` entry point — `identify`, `read_sectors`, `write_sectors`,
    `flush` — is one command sequence that must not interleave with another on
    the primary channel; `hal::ata` does not lock, the kernel does:
    `kernel::blk::ata` holds `CHANNEL` (a `hal::sync::SpinMutex`, waiters
    yield instead of spinning, §5e) around exactly one call, and it is the only
    kernel file that may name `hal::ata` (`cargo xtask check-ata-callers`, a CI
    step). Interleaving would corrupt a transfer, never memory (rows A1–A4 stay
    sound regardless). `write_sectors` returning `Ok` means the drive accepted
    the data, possibly only into its write cache; only a later successful
    `flush()` makes it durable, and between two flushes the drive may persist
    any subset of the sectors written (a single sector is atomic). Callers that
    promise durability flush: `kernel::fs` once per save, SentinelFS twice per
    commit (dirty blocks → flush → superblock → flush). Every status wait ends
    at a TSC deadline (C16), and a command that times out leaves the channel
    **reset** (SRST) before `Timeout` is returned, so a timeout never leaves a
    half-finished command or a pending DRQ for the next caller of the lock;
    the lock is held across the reset (it is part of the command's call).
17. **Device-IRQ routing (SMP 3b-ii).** (Numbered 17: FS-1b adds invariant 16, the ATA channel lock.) Once `kernel::ioapic::init` succeeds,
    every device IRQ the kernel uses reaches the CPU by exactly one path: an
    IOAPIC redirection entry, fixed delivery, physical destination = the BSP's
    APIC ID, vector unchanged from the 8259 era (`0x20 + ISA IRQ`; overrides
    decide the GSI, so the PIT is `GSI 2 → 0x20` under QEMU). The 8259 is fully
    masked and the BSP's LINT0 masked (both read back as evidence), so there is
    no second deliverer; the switch happens with IF = 0 on the BSP before any AP
    runs, masking every pin first and opening only the routed ones. Every
    handler EOIs through `ioapic::device_eoi`, which picks the controller from
    the LAPIC's in-service register (IO4). Routing is **BSP-only by decision**:
    the PIT is the wall clock (invariants 14–15, `clock::prove_mono`'s
    `pit-frozen=yes`), and the keyboard/mouse rings and NIC frames are consumed
    by the BSP idle loop and are not audited for a producer on another core.
    Any lock a device handler takes must be taken with interrupts masked
    everywhere else (N7). Every unmasked entry is fixed delivery of a vector
    ≥ `0x20` (IO3), and no GSI carries two routes. The NIC's line (its PCI
    interrupt-line register) is routed **only** when an ISA-bus override
    declares that line level-triggered and its GSI is still free
    (`kernel::ioapic::pci_legacy_route`); otherwise the NIC stays polled. That
    is correct where the firmware's PIRQ steering also drives the IOAPIC pin of
    that number (QEMU's ICH9); the general source is the ACPI `_PRT` (AML),
    which this kernel does not interpret. On any failure before or during the switch (no MADT, an
    unmappable or implausible IOAPIC, an unroutable ISA IRQ, the PIT not seen
    ticking through the IOAPIC within a bounded spin) the 8259 virtual wire is
    left or restored intact.
