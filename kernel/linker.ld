/* Higher-half x86_64 linker script for SentinelOS — Limine + rust-lld */
/* Limine maps the kernel at KERNEL_OFFSET using its "higher-half" scheme. */
/* The virtual address here must match the load address Limine places us at. */

ENTRY(_start)

KERNEL_OFFSET = 0xFFFFFFFF80000000;

SECTIONS
{
    . = KERNEL_OFFSET + 1M;

    /* ── text ─────────────────────────────────────────────────────────── */
    .text ALIGN(4K) :
    {
        *(.text .text.*)
    }

    /* ── read-only data ───────────────────────────────────────────────── */
    .rodata ALIGN(4K) :
    {
        *(.rodata .rodata.*)
    }

    /* ── initialised data ─────────────────────────────────────────────── */
    .data ALIGN(4K) :
    {
        *(.data .data.*)
    }

    /* ── zero-initialised data ────────────────────────────────────────── */
    .bss ALIGN(4K) :
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        _bss_end = .;
    }

    /* ── boot stack (16 KiB) ──────────────────────────────────────────── */
    .stack ALIGN(4K) :
    {
        _stack_bottom = .;
        . += 16K;
        _stack_top = .;
    }

    /* Discard debug / note sections to keep the image small */
    /DISCARD/ :
    {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
    }
}
