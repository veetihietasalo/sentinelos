---
name: virtualbox-vm
description: SentinelOS boots in VirtualBox 7.2 on Hyper-V (NEM) only because APs are parked early (hal::smp::park_cpu); VM settings that match QEMU's devices
type: reference
owner: kernel-engineer
date: 2026-11-06
source: branch fix/ap-park-early (VirtualBox serial logs, 2026-11-06)
---

VirtualBox 7.2.10 on Windows with WSL2 on runs through Hyper-V (NEM, "AMD-V is not available"). There, a vCPU spinning in Limine's `goto_address` loop never exits to VirtualBox, which runs device timers on its last vCPU's thread: with 2+ vCPUs the PIT never fires and the BSP hangs at its first timer wait (`kernel/src/lib.rs`, after the `[simd]` line). 1 vCPU always booted. Halting the APs fixed it, hence `kernel::smp::park_aps` right after `apic::enable_bsp`.

VM settings that match the QEMU devices: chipset PIIX3 + PIIX4 IDE (legacy 0x1F0, disk on primary master, ISO on secondary master), NIC 82540EM (= e1000), BIOS firmware, APIC on (VirtualBox refuses a 64-bit guest without it), UART1 0x3F8 IRQ 4 to a file for the serial log. Disk: a fixed 16 MiB VDI.

**Why:** QEMU TCG runs all vCPUs in one emulator loop and never shows this; the first non-QEMU boot did.

**How to apply:** don't add code that keeps a vCPU spinning without exits before the kernel has the PIT; prefer `sti; hlt` waits. Re-check a 4-vCPU VirtualBox boot after SMP or timer changes. `make test` (QEMU) doesn't cover it.
