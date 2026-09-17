/*
 * Copyright 2026 Google LLC (Cherified Team)
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
ENTRY(_start)

PHDRS
{
    seg PT_LOAD FLAGS(7);
}

SECTIONS
{
    /* Where OpenSBI's fw_jump hands control to the S-mode payload. */
    . = 0x80200000;

    .text : ALIGN(4096) {
        *(.text.boot)
        *(.text.trap)
        *(.text*)
    } :seg

    .rodata : ALIGN(16) {
        *(.rodata*)
        . = ALIGN(16);
    } :seg

    __cap_relocs : ALIGN(16) {
        __start___cap_relocs = .;
        ___cap_relocs_start = .;
        *(__cap_relocs)
        __stop___cap_relocs = .;
        ___cap_relocs_end = .;
        . = ALIGN(16);
    } :seg

    .got : ALIGN(16) {
        _got_start = .;
        *(.got*)
        . = ALIGN(16);
        _got_end = .;
    } :seg

    .data : ALIGN(16) {
        *(.data*)
        . = ALIGN(16);
    } :seg

    .bss.stack (NOLOAD) : ALIGN(65536) {
        _stack_base = .;
        . += 65536;
        _stack_top = .;
    } :seg

    .bss : ALIGN(16) {
        _bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(16);
        _bss_end = .;
    } :seg
}
