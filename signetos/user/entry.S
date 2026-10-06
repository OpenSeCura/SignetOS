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

/*
 * entry.S - SignetOS User Compartment Entry Header & Trampoline
 *
 * Linked at offset 0 of every standalone user compartment image
 * (`src/user/compartment.ld`).
 *
 * Layout (80 bytes, 16-byte aligned, matching `CompartmentImageHeader` in
 * `signetos/init.hpp`):
 *   0x00: j _compartment_trampoline (4B) + 3 NOPs (12B)
 *   0x10: magic ("SIGNCOMP" = 0x5349474e434f4d50)
 *   0x18: ___cap_relocs_start
 *   0x20: ___cap_relocs_end
 *   0x28: _rodata_end
 *   0x30: _bss_end
 *   0x38: _got_end (executable prefix: .text .. .got)
 *   0x40: _manifest_start (the `.manifest` block, `user/manifest.hpp`)
 *   0x48: _manifest_end   (== _manifest_start when the image has none)
 *   0x50: _compartment_trampoline -> jumps to `compartment_main`
 */

    .section .text.entry, "ax", @progbits
    .align 4
    .option capmode
    .option norvc

    .globl _compartment_start
    .type _compartment_start, @function
_compartment_start:
    j       _compartment_trampoline
    nop
    nop
    nop
    .quad   0x5349474e434f4d50          /* +16: magic ("SIGNCOMP") */
    .quad   ___cap_relocs_start         /* +24: __cap_relocs start offset */
    .quad   ___cap_relocs_end           /* +32: __cap_relocs end offset */
    .quad   _rodata_end                 /* +40: end of .text + .rodata */
    .quad   _bss_end                    /* +48: total in-memory footprint */
    .quad   _got_end                    /* +56: end of .got (PCC bound) */
    .quad   _manifest_start             /* +64: .manifest block start */
    .quad   _manifest_end               /* +72: .manifest block end */

    .align 4
_compartment_trampoline:
    j       compartment_main
    .size _compartment_start, . - _compartment_start
