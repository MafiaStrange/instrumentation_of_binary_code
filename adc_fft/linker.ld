ENTRY(_start)

SECTIONS
{
    . = 0x400000;

    .interp : { *(.interp) }

    . = ALIGN(0x1000);

    .text : {
        *(.text)
        *(.text.*)
    }

    .rodata : {
        *(.rodata)
        *(.rodata.*)
    }

    .data : {
        *(.data)
        *(.data.*)
    }

    .bss : {
        *(.bss)
        *(COMMON)
    }

    /* Required for libc startup */
    .preinit_array : {
        __preinit_array_start = .;
        KEEP (*(.preinit_array))
        __preinit_array_end = .;
    }

    .init_array : {
        __init_array_start = .;
        KEEP (*(SORT_BY_INIT_PRIORITY(.init_array.*) .init_array))
        __init_array_end = .;
    }

    .fini_array : {
        __fini_array_start = .;
        KEEP (*(SORT_BY_INIT_PRIORITY(.fini_array.*) .fini_array))
        __fini_array_end = .;
    }

    /* Optional hook section (if you want) */
    . = 0x500000;
    .hook : {
        KEEP(*(.hook))
    }

    _end = .;

    /* Placeholders for __ehdr_start if you need it */
    PROVIDE(__ehdr_start = 0x400000);
}
