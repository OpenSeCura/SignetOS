/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

OUTPUT_ARCH("riscv")
ENTRY(_compartment_start)

PHDRS
{
    comp_seg PT_LOAD FLAGS(7);
}

SECTIONS
{
    . = 0x0;

    .text : ALIGN(16) {
        *(.text.entry)
        . = ALIGN(16);
        *(.text*)
        . = ALIGN(16);
    } :comp_seg

    .rodata : ALIGN(16) {
        _rodata_start = .;
        /*
         * The manifest (user/manifest.hpp) leads .rodata so that it is
         * read-only and inside the executable prefix like the rest of it,
         * and the header can point at it. An image that declares none has
         * _manifest_start == _manifest_end.
         */
        . = ALIGN(16);
        _manifest_start = .;
        KEEP(*(.manifest))
        _manifest_end = .;
        . = ALIGN(16);
        *(.rodata*)
        . = ALIGN(16);
        _rodata_end = .;
    } :comp_seg

    __cap_relocs : ALIGN(16) {
        . = ALIGN(16);
        __start___cap_relocs = .;
        ___cap_relocs_start = .;
        *(__cap_relocs)
        __stop___cap_relocs = .;
        ___cap_relocs_end = .;
        . = ALIGN(16);
    } :comp_seg

    .got : ALIGN(16) {
        . = ALIGN(16);
        _got_start = .;
        *(.got*)
        /*
         * [0, _got_end) is the executable prefix that becomes the
         * compartment's entry (PCC) bounds in init::image_code_window, which
         * insists on exact bounds. A capability's bounds are only exact when
         * base and top are aligned to a power of two that grows with the
         * length (roughly len / 2^10 on RV64), so a prefix that merely ends
         * 16-byte aligned is representable or not depending on where the
         * linker happens to stop: a 24 KiB shell ending at 0x6010 was not,
         * and failed to load. Padding to a page (the image is installed at a
         * page-aligned address) keeps the prefix exact up to several MiB.
         */
        . = ALIGN(4096);
        _got_end = .;
    } :comp_seg

    .data : ALIGN(16) {
        _data_start = .;
        *(.data*)
        . = ALIGN(16);
        _data_end = .;
    } :comp_seg

    .bss : ALIGN(16) {
        _bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(16);
        _bss_end = .;
    } :comp_seg
}
