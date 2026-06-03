/* Higher-half x86_64 linker script for SentinelOS — Limine + rust-lld */
/* Limine maps the kernel at KERNEL_OFFSET using its "higher-half" scheme. */
/*                                                                          */
/* PHDRS: Each permission group gets its own PT_LOAD segment so Limine     */
/* never sees two PHDRs with conflicting flags on the same 4 KiB page.     */
/* We do NOT use -pie so there is no PT_DYNAMIC; just three PT_LOADs.      */

ENTRY(_start)

KERNEL_OFFSET = 0xFFFFFFFF80000000;

PHDRS
{
    text    PT_LOAD FLAGS(5);   /* R + X */
    rodata  PT_LOAD FLAGS(4);   /* R     */
    data    PT_LOAD FLAGS(6);   /* R + W */
}

SECTIONS
{
    . = KERNEL_OFFSET + 1M;

    /* ── text ─────────────────────────────────────────────────────────── */
    .text ALIGN(4K) :
    {
        *(.text .text.*)
    } :text

    /* ── read-only data ───────────────────────────────────────────────── */
    .rodata ALIGN(4K) :
    {
        *(.rodata .rodata.*)
    } :rodata

    /* ── initialised data ─────────────────────────────────────────────── */
    .data ALIGN(4K) :
    {
        *(.data .data.*)
    } :data

    /* ── zero-initialised data ────────────────────────────────────────── */
    .bss ALIGN(4K) :
    {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        _bss_end = .;
    } :data

    /* ── boot stack (16 KiB) ──────────────────────────────────────────── */
    .stack ALIGN(4K) :
    {
        _stack_bottom = .;
        . += 16K;
        _stack_top = .;
    } :data

    /* Discard unwanted sections */
    /DISCARD/ :
    {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
        *(.dynamic)
        *(.dynsym)
        *(.dynstr)
        *(.rela.*)
        *(.got .got.*)
        *(.plt .plt.*)
        *(.interp)
    }
}
