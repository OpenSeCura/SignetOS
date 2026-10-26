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
 * early_trap.S - Machine Trap and Interrupt Vector
 *
 * Installed in `mtvecc` by `boot.S` step 8. Everything runs in M-mode and
 * nothing is delegated, so every exception and interrupt arrives here.
 *
 * Saves the interrupted context (all 31 general-purpose capability registers
 * and `mepcc`) into a 640-byte `TrapFrame` on the current hart's kernel stack
 * (`mscratchc`, or `csp` if in boot/host context) without clobbering any
 * register, then calls `__signetos_trap_dispatch`.
 *
 * An interrupt wakes this hart's interrupt handler thread (thread.hpp, THE
 * INTERRUPT HANDLER): the interrupted thread stays parked in that
 * `TrapFrame`, and the dispatcher resumes the handler thread from where it
 * waits, so it does not come back here. Synchronous faults go to the
 * faulting compartment's own fault handler (`compartment_error_handler`),
 * if it installed one, or unwind it. A fault handler runs on a narrowed
 * stack capability with `(ErrorState, mtval, mepc, mtval2, cap_table_rw)`
 * in `(ca0, a1, a2, a3, ca4)` (fault.hpp) and all other registers scrubbed.
 * On return the `TrapFrame` is reloaded from the ErrorState or unwound, per
 * the handler's verdict in `a0`, and `mret` executed.
 *
 * INTERRUPT MASKING (see `asm_macros.h`): the hardware clears `mstatus.MIE`
 * on entry. Just before entering a fault handler, step 3 sets `MIE` from the
 * frame's `handler_mie`: the faulting code's `MIE`, so an interrupt can be
 * taken on top of it and return into it. `unwind::resume` sets
 * `mstatus.MPIE` from the `mstatus` recorded in the frame it resumes, so the
 * final `mret` gives that context back exactly the `MIE` it had.
 *
 * NO MACROS: every register sequence is written out in place, as in
 * `switch.S`. Only the `TRAP_FRAME_*` offsets and `mstatus` bits come from
 * `asm_macros.h`.
 */

#include <signetos/asm_macros.h>

    .section .text.trap, "ax", @progbits
    .align 4
    .globl _early_trap_entry
    .option capmode
    .option norvc

_early_trap_entry:
    /*
     * 1. Push a `TrapFrame` onto the current hart's kernel stack (`mscratchc`
     *    or `csp`), saving all 31 GPRs and `mepcc`.
     *
     *    Nothing may be clobbered before it is saved, so the frame is carved
     *    with two swaps: `ct0` <-> `mscratchc` (the interrupted `ct0` sits in
     *    the CSR while `ct0` is the kernel SP), then `ct1` is saved and used
     *    as scratch to swap the interrupted `ct0` back out, leaving
     *    `mscratchc` exactly as it was (= frame + TRAP_FRAME_SIZE, which is
     *    what `.Ltrap_restore` re-derives).
     */
    csrrw   ct0, mscratchc, ct0         /* ct0 = ksp, mscratchc = trapped ct0 */
    caddi   ct0, ct0, -TRAP_FRAME_SIZE  /* ct0 = frame base */
    csc     ct1,  80(ct0)               /* frame->t[1]; ct1 is scratch below */
    caddi   ct1, ct0, TRAP_FRAME_SIZE   /* ct1 = original ksp */
    csc     ct1, FRAME_LINK(ct0)        /* frame->active_kernel_sp */
    csrrw   ct1, mscratchc, ct1         /* ct1 = trapped ct0, mscratchc = ksp */
    csc     ct1,  64(ct0)               /* frame->t[0] = trapped ct0 */
    csc     cra,   0(ct0)
    csc     csp,  16(ct0)
    csc     cgp,  32(ct0)
    csc     ctp, FRAME_TP(ct0)
    csc     ct2,  96(ct0)
    csc     ct3, 112(ct0)
    csc     ct4, 128(ct0)
    csc     ct5, 144(ct0)
    csc     ct6, 160(ct0)
    csc     cs0, 176(ct0)
    csc     cs1, 192(ct0)
    csc     cs2, 208(ct0)
    csc     cs3, 224(ct0)
    csc     cs4, 240(ct0)
    csc     cs5, 256(ct0)
    csc     cs6, 272(ct0)
    csc     cs7, 288(ct0)
    csc     cs8, 304(ct0)
    csc     cs9, 320(ct0)
    csc     cs10, 336(ct0)
    csc     cs11, 352(ct0)
    csc     ca0, 368(ct0)
    csc     ca1, 384(ct0)
    csc     ca2, 400(ct0)
    csc     ca3, 416(ct0)
    csc     ca4, 432(ct0)
    csc     ca5, 448(ct0)
    csc     ca6, 464(ct0)
    csc     ca7, 480(ct0)
    csrr    ct1, mepcc
    csc     ct1, TRAP_FRAME_MEPCC(ct0)
    cmv     csp, ct0

    /*
     * 2. Call `__signetos_trap_dispatch(mcause, mtval, mtval2, frame)`. An
     *    interrupt handed to the interrupt handler thread does not come
     *    back (the thread is resumed from there). Otherwise three outcomes
     *    in `ca0`:
     *      - a tagged `CT = 1` hardware sentry: enter it (step 3) — the
     *        faulting compartment's fault handler;
     *      - `nullptr`: handled in-kernel, resume the frame as it is;
     *      - an untagged non-null sentinel: a fault nobody can handle — the
     *        dispatcher has marked the frame and pointed `mscratchc` at it,
     *        so go straight to step 4 with verdict 0 (`fault::UNWIND`), as
     *        if a handler had returned it.
     */
    csrr    a0, mcause
    csrr    a1, mtval
    csrr    a2, 0x34b                   /* 0x34b = mtval2 (CHERI fault info) */
    cmv     ca3, csp                    /* ca3 = TrapFrame* */
    cjal    cra, __signetos_trap_dispatch
    gctag   t0, ca0
    bnez    t0, .Ltrap_deliver
    beqz    a0, .Ltrap_restore
    li      a0, 0                       /* verdict = fault::UNWIND */
    j       .Lhandler_returned

.Ltrap_deliver:

    /*
     * 3. Enter the faulting compartment's fault handler (`ca0`) with:
     *      ca0 = its ErrorState (fault.hpp)   a1  = mtval
     *      a2  = mepc                         a3  = mtval2
     *      ca4 = rw_table                     cgp = rw_table
     *      csp = narrowed handler_sp
     *    all other registers scrubbed to `cnull`, everything below `csp` zeroed
     *    (what the faulting code left there; the ErrorState sits just above
     *    `csp`), and `mstatus.MIE` set from the frame's `handler_mie`.
     *
     *    `MIE` is set last, after the CSRs have been read: from then on an
     *    interrupt can be taken here, and it is an ordinary trap (`mscratchc`
     *    points at this frame, so the new frame goes below it, and every
     *    register set up here is saved and restored).
     */
    cmv     ct0, ca0                    /* ct0 = handler CT = 1 sentry */
    clc     ct3, TRAP_FRAME_HANDLER_SP(csp)
    mv      t4, t3                      /* up to the handler's csp */
    cjal    cra, __signetos_zero_stack  /* switch.S */
    /* Everything except ct0 and csp (replaced below) and cra (set by cjalr). */
    cmv     ctp, cnull
    cmv     ct1, cnull
    cmv     ct2, cnull
    cmv     ct3, cnull
    cmv     ct4, cnull
    cmv     ct5, cnull
    cmv     ct6, cnull
    cmv     cs0, cnull
    cmv     cs1, cnull
    cmv     cs2, cnull
    cmv     cs3, cnull
    cmv     cs4, cnull
    cmv     cs5, cnull
    cmv     cs6, cnull
    cmv     cs7, cnull
    cmv     cs8, cnull
    cmv     cs9, cnull
    cmv     cs10, cnull
    cmv     cs11, cnull
    cmv     ca0, cnull
    cmv     ca1, cnull
    cmv     ca2, cnull
    cmv     ca3, cnull
    cmv     ca4, cnull
    cmv     ca5, cnull
    cmv     ca6, cnull
    cmv     ca7, cnull
    clc     ca0, TRAP_FRAME_HANDLER_CA0(csp) /* the ErrorState */
    csrr    a1, mtval
    csrr    ca2, mepcc
    scaddr  ca2, cnull, a2              /* a2 = integer address of mepcc */
    ld      a3, TRAP_FRAME_HANDLER_A3(csp) /* mtval2 */
    clc     ca4, TRAP_FRAME_RW_TABLE(csp)
    ld      ra, TRAP_FRAME_HANDLER_MIE(csp) /* ra = handler_mie; cjalr overwrites it */
    clc     csp, TRAP_FRAME_HANDLER_SP(csp)
    cmv     cgp, ca4
    csrs    mstatus, ra
    cjalr   cra, ct0

    /*
     * 4. Handler returned: mask (a fault handler may come back with
     *    interrupts enabled; an interrupt taken before this instruction is
     *    an ordinary trap, as in step 3), then pop the `TrapFrame` in C++
     *    (`__signetos_trap_return` = `unwind::resume`). If the code under it
     *    was in a compartment that has been destroyed and swept, it unwinds
     *    further; `a0` says what kind of frame it stopped at (UNWIND_*;
     *    UNWIND_NONE does not come back), and that frame sits just below the
     *    new `mscratchc`.
     *
     *    The handler's `a0` is left in place as `__signetos_trap_return`'s
     *    argument: the verdict (`fault::UNWIND` or `INSTALL_CONTEXT`).
     */
    csrci   mstatus, MSTATUS_MIE
.Lhandler_returned:
    csrr    csp, mscratchc
    cjal    cra, __signetos_trap_return
    li      t0, UNWIND_RETURN_FRAME
    beq     a0, t0, .Lresume_return_frame

    /*
     *    Resume a `TrapFrame`: the one just popped, directly below the kernel
     *    SP, after zeroing the whole stack its handler was lent. Also the
     *    switcher's way out when its unwind stops at a `TrapFrame` (switch.S,
     *    `.Lresume_trap_frame`).
     */
    .globl __signetos_resume_trap_frame
__signetos_resume_trap_frame:
    csrr    csp, mscratchc
    caddi   csp, csp, -TRAP_FRAME_SIZE  /* csp = TrapFrame* to resume */
    clc     ct3, TRAP_FRAME_HANDLER_SP(csp)
    gcbase  t4, ct3
    gclen   t5, ct3
    add     t4, t4, t5
    cjal    cra, __signetos_zero_stack  /* switch.S */

.Ltrap_restore:
    /*
     * 5. Restore `mepcc` and all 31 GPRs from the `TrapFrame` at `csp`, then
     *    `mret` (`MIE := MPIE`, mode := MPP). The frame is not wiped: nothing
     *    reads a popped frame (switch.S, POPPED FRAMES ARE NOT WIPED).
     *
     *    `MPP` must be forced back to M: every `mret` sets it to U, so if
     *    the handler switched threads and the thread that ran meanwhile took
     *    and returned from a trap of its own, `MPP` is stale by the time this
     *    context resumes. Everything in SignetOS runs in M-mode, and no
     *    `mret` may leave it.
     *
     *    The kernel SP is re-installed as `frame + TRAP_FRAME_SIZE` (every
     *    frame is carved from `mscratchc`, so that is where it was), then
     *    every register is reloaded with `csp`, the base, last.
     */
    li      t0, MSTATUS_MPP
    csrs    mstatus, t0
    clc     ct0, TRAP_FRAME_MEPCC(csp)
    csrw    mepcc, ct0
    caddi   ct0, csp, TRAP_FRAME_SIZE
    csrw    mscratchc, ct0
    clc     cra,   0(csp)
    clc     cgp,  32(csp)
    clc     ctp, FRAME_TP(csp)
    clc     ct0,  64(csp)
    clc     ct1,  80(csp)
    clc     ct2,  96(csp)
    clc     ct3, 112(csp)
    clc     ct4, 128(csp)
    clc     ct5, 144(csp)
    clc     ct6, 160(csp)
    clc     cs0, 176(csp)
    clc     cs1, 192(csp)
    clc     cs2, 208(csp)
    clc     cs3, 224(csp)
    clc     cs4, 240(csp)
    clc     cs5, 256(csp)
    clc     cs6, 272(csp)
    clc     cs7, 288(csp)
    clc     cs8, 304(csp)
    clc     cs9, 320(csp)
    clc     cs10, 336(csp)
    clc     cs11, 352(csp)
    clc     ca0, 368(csp)
    clc     ca1, 384(csp)
    clc     ca2, 400(csp)
    clc     ca3, 416(csp)
    clc     ca4, 432(csp)
    clc     ca5, 448(csp)
    clc     ca6, 464(csp)
    clc     ca7, 480(csp)
    clc     csp,  16(csp)               /* the base, last */
    mret

.Lresume_return_frame:
    /*
     * The unwind stopped at a `ReturnFrame` (the handler's `TrapFrame`, and
     * whatever was above it, belonged to destroyed compartments): leave
     * through the switcher's restore sequence, which derives the frame from
     * `mscratchc`, gives the caller `args[0]` and `ret`s.
     */
    j       __signetos_resume_return_frame
