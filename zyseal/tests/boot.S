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

/*
 * boot.S - minimal bare-metal entry for the standalone Zyseal test.
 *
 * Deliberately independent of SignetOS: no MMU, no trap vector, no DTB.
 * Just enough to get into pure-capability mode with a stack and call C.
 */

    .section .text.boot, "ax", @progbits
    .align 4
    .globl _start
_start:
    /* Switch the CPU to pure-capability pointer mode (PCC.P = 0). */
    .word   0x12001033              /* modesw.cap */

    /* Root capability spanning the whole address space, derived from PCC. */
    auipcc  cs11, 0
    scaddr  cs11, cs11, zero
    auipcc  cs10, 0                 /* root CODE capability (RX, from PCC) */

    /* 64 KiB bounded stack, growing down from _stack_top. */
    llc     ct0, _stack_base
    scaddr  csp, cs11, t0
    li      t1, 65536
    scbndsr csp, csp, t1
    cadd    csp, csp, t1

    /* Capability global pointer (the .got may well be empty here). */
    llc     ct0, _got_start
    scaddr  cgp, cs11, t0

    /* Process __cap_relocs (emitted by lld --local-caprelocs=legacy). */
    llc     ca4, ___cap_relocs_start
    scaddr  ca4, cs11, a4
    llc     ca5, ___cap_relocs_end
    scaddr  ca5, cs11, a5
    bgeu    a4, a5, .Lrelocs_done
.Lreloc_loop:
    ld      t0, 0(ca4)              /* slot to fill */
    scaddr  ct3, cs11, t0
    ld      t1, 8(ca4)              /* target object base */
    beqz    t1, .Lreloc_null
    ld      t4, 32(ca4)             /* flags; bit 63 => function pointer */
    bgez    t4, .Lreloc_data
    scaddr  ct5, cs10, t1
    j       .Lreloc_store
.Lreloc_data:
    scaddr  ct5, cs11, t1
.Lreloc_store:
    ld      t2, 16(ca4)             /* offset within object */
    cadd    ct5, ct5, t2
    csc     ct5, 0(ct3)
    j       .Lnext_reloc
.Lreloc_null:
    csc     cnull, 0(ct3)
.Lnext_reloc:
    caddi   ca4, ca4, 40            /* 40 bytes per record */
    bltu    a4, a5, .Lreloc_loop
.Lrelocs_done:
    fence   rw, rw
    fence.i

    /* Zero .bss, 16 bytes (one capability) at a time. */
    llc     ca4, _bss_start
    scaddr  ca4, cs11, a4
    llc     ca5, _bss_end
    scaddr  ca5, cs11, a5
    bgeu    a4, a5, .Lbss_done
.Lbss_loop:
    csc     cnull, 0(ca4)
    caddi   ca4, ca4, 16
    bltu    a4, a5, .Lbss_loop
.Lbss_done:
    fence   rw, rw
    fence.i

    /* Trap vector, and cs9 = capability to g_trap_state (see trap.S). */
    llc     ct0, _trap_entry
    csrw    stvecc, ct0
    llc     ct0, g_trap_state
    scaddr  cs9, cs11, t0

    /*
     * test_main(root_data_capability, root_code_capability)
     *
     * cs10 is the RX capability derived from PCC at the top of this file. The
     * misuse tests need it to build an *unsealed, executable* capability to
     * jump to; you cannot get one from a C function pointer, because in
     * purecap a function pointer is already a sentry (CT=1).
     */
    cmv     ca0, cs11
    cmv     ca1, cs10
    llc     ct0, test_main
    cjalr   cra, ct0

_hang:
    wfi
    j       _hang
