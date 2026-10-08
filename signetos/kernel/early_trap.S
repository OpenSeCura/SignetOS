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
 * early_trap.S - Supervisor Trap and Interrupt Vector
 *
 * Installed in `stvecc` by `boot.S` step 8.
 *
 * Saves the interrupted context (all 31 general-purpose capability registers
 * and `sepcc`) into a 592-byte `TrapFrame` on the current hart's kernel stack
 * (`sscratchc`, or `csp` if in boot/host context) without clobbering any
 * register, then calls `__signetos_trap_dispatch`.
 *
 * If a compartment has bound a handler sentry via `sys_trap_bind`, invokes the
 * handler on a narrowed stack capability with `(scause, stval, sepc, stval2,
 * cap_table_rw, cap_table_ro)` in `(a0, a1, a2, a3, ca4, ca5)` and all other
 * registers scrubbed, then restores the `TrapFrame` on return and executes
 * `sret`.
 *
 * INTERRUPT MASKING (see `asm_macros.h`): the hardware clears `sstatus.SIE`
 * on entry. Just before entering the handler, step 3 sets `SIE` from the
 * frame's `handler_sie`, which the dispatcher chose: 0 for an interrupt
 * handler (and every gate it calls restores the masked state on return),
 * the interrupted code's `SIE` for an exception handler, so an interrupt can
 * be taken on top of it and return into it. `__signetos_trap_return` sets
 * `sstatus.SPIE` from the `sstatus` the dispatcher recorded, so the final
 * `sret` gives the interrupted context back exactly the `SIE` it had.
 *
 * NO MACROS: every register sequence is written out in place, as in
 * `switch.S`. Only the `TRAP_FRAME_*` offsets and `sstatus` bits come from
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
     * 1. Push a `TrapFrame` onto the current hart's kernel stack (`sscratchc`
     *    or `csp`), saving all 31 GPRs and `sepcc`.
     *
     *    Nothing may be clobbered before it is saved, so the frame is carved
     *    with two swaps: `ct0` <-> `sscratchc` (the interrupted `ct0` sits in
     *    the CSR while `ct0` is the kernel SP), then `ct1` is saved and used
     *    as scratch to swap the interrupted `ct0` back out, leaving
     *    `sscratchc` exactly as it was (= frame + TRAP_FRAME_SIZE, which is
     *    what `.Ltrap_restore` re-derives).
     */
    csrrw   ct0, sscratchc, ct0         /* ct0 = ksp, sscratchc = trapped ct0 */
    caddi   ct0, ct0, -TRAP_FRAME_SIZE  /* ct0 = frame base */
    csc     ct1,  80(ct0)               /* frame->t[1]; ct1 is scratch below */
    caddi   ct1, ct0, TRAP_FRAME_SIZE   /* ct1 = original ksp */
    csc     ct1, FRAME_LINK(ct0)        /* frame->active_kernel_sp */
    csrrw   ct1, sscratchc, ct1         /* ct1 = trapped ct0, sscratchc = ksp */
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
    csrr    ct1, sepcc
    csc     ct1, TRAP_FRAME_SEPCC(ct0)
    cmv     csp, ct0

    /*
     * 2. Call `__signetos_trap_dispatch(scause, stval, stval2, frame)`.
     *    Returns a `CT = 1` hardware sentry in `ca0` if a compartment handler
     *    is bound to this vector, or `nullptr` if handled in-kernel.
     */
    csrr    a0, scause
    csrr    a1, stval
    csrr    a2, 0x14b                   /* 0x14b = stval2 (CHERI fault info) */
    cmv     ca3, csp                    /* ca3 = TrapFrame* */
    cjal    cra, __signetos_trap_dispatch
    beqz    a0, .Ltrap_restore

    /*
     * 3. Invoke the bound compartment trap handler (`ca0`) with:
     *      a0  = scause        a1  = stval
     *      a2  = sepc          a3  = stval2
     *      ca4 = rw_table      cgp = rw_table
     *      csp = narrowed handler_sp
     *    all other registers scrubbed to `cnull`, and `sstatus.SIE` set from
     *    the frame's `handler_sie`.
     *
     *    `SIE` is set last, after the CSRs have been read: from then on an
     *    interrupt can be taken here, and it is an ordinary nested trap
     *    (`sscratchc` points at this frame, so the nested frame goes below
     *    it, and every register set up here is saved and restored).
     */
    cmv     ct0, ca0                    /* ct0 = handler CT = 1 sentry */
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
    csrr    a0, scause
    csrr    a1, stval
    csrr    ca2, sepcc
    scaddr  ca2, cnull, a2              /* a2 = integer address of sepcc */
    csrr    a3, 0x14b                   /* a3 = stval2 */
    clc     ca4, TRAP_FRAME_RW_TABLE(csp)
    ld      ra, TRAP_FRAME_HANDLER_SIE(csp) /* ra = handler_sie; cjalr overwrites it */
    clc     csp, TRAP_FRAME_HANDLER_SP(csp)
    cmv     cgp, ca4
    csrs    sstatus, ra
    cjalr   cra, ct0

    /*
     * 4. Handler returned: mask (an exception handler may come back with
     *    interrupts enabled; an interrupt taken before this instruction is
     *    an ordinary nested trap, as in step 3), scrub the handler's
     *    narrowed stack and pop the `TrapFrame` from the hart's `sscratchc`
     *    in C++ (`__signetos_trap_return` = `unwind::resume`). If the
     *    interrupted code's compartment has been destroyed and swept it
     *    unwinds further; `a0` says what kind of frame it stopped at
     *    (UNWIND_*; UNWIND_NONE does not come back), and that frame sits
     *    just below the new `sscratchc`.
     */
    csrci   sstatus, SSTATUS_SIE
    csrr    csp, sscratchc
    cjal    cra, __signetos_trap_return
    li      t0, UNWIND_RETURN_FRAME
    beq     a0, t0, .Lresume_return_frame

    /*
     *    Resume a `TrapFrame`: the one just popped, directly below the kernel
     *    SP. Also the switcher's way out when its unwind stops at a
     *    `TrapFrame` (switch.S, `.Lresume_trap_frame`).
     */
    .globl __signetos_resume_trap_frame
__signetos_resume_trap_frame:
    csrr    csp, sscratchc
    caddi   csp, csp, -TRAP_FRAME_SIZE  /* csp = TrapFrame* to resume */

.Ltrap_restore:
    /*
     * 5. Restore `sepcc` and all 31 GPRs from the `TrapFrame` at `csp`, wiping
     *    every slot of the frame, then `sret` (`SIE := SPIE`, mode := SPP).
     *
     *    `SPP` must be forced back to S: every `sret` clears it to U, so if
     *    the handler switched threads and the thread that ran meanwhile took
     *    and returned from a trap of its own, `SPP` is stale by the time this
     *    context resumes. Everything in SignetOS runs in S-mode.
     *
     *    The trap-only slots (512..560) are wiped first, while `csp` is
     *    still the frame. Then `ct6` becomes the base for the 32 shared slots:
     *    it is the last register reloaded, so its saved value is parked in
     *    `sscratchc` meanwhile and swapped back by the final `csrrw`, which at
     *    the same time re-installs the kernel SP as `frame + TRAP_FRAME_SIZE`
     *    (every frame is carved from `sscratchc`, so that is where it was).
     *    Interrupts are masked throughout; a trap in this window would push
     *    onto the parked value.
     */
    li      t0, SSTATUS_SPP
    csrs    sstatus, t0
    clc     ct0, TRAP_FRAME_SEPCC(csp)
    csrw    sepcc, ct0
    csc     cnull, TRAP_FRAME_SEPCC(csp)
    csc     cnull, TRAP_FRAME_HANDLER_SP(csp)
    csc     cnull, TRAP_FRAME_RW_TABLE(csp)
    csc     cnull, TRAP_FRAME_SSTATUS(csp)  /* sstatus and handler_sie */
    cmv     ct6, csp                    /* ct6 = frame base; csp reloaded last */
    clc     ct5, 160(ct6)               /* ct5 = saved ct6 */
    csrw    sscratchc, ct5              /* park saved ct6 in sscratchc */
    csc     cnull, 160(ct6)
    clc     cra,   0(ct6)
    csc     cnull, 0(ct6)
    clc     cgp,  32(ct6)
    csc     cnull, 32(ct6)
    clc     ctp, FRAME_TP(ct6)
    csc     cnull, FRAME_TP(ct6)
    clc     ct0,  64(ct6)
    csc     cnull, 64(ct6)
    clc     ct1,  80(ct6)
    csc     cnull, 80(ct6)
    clc     ct2,  96(ct6)
    csc     cnull, 96(ct6)
    clc     ct3, 112(ct6)
    csc     cnull, 112(ct6)
    clc     ct4, 128(ct6)
    csc     cnull, 128(ct6)
    clc     ct5, 144(ct6)
    csc     cnull, 144(ct6)
    clc     cs0, 176(ct6)
    csc     cnull, 176(ct6)
    clc     cs1, 192(ct6)
    csc     cnull, 192(ct6)
    clc     cs2, 208(ct6)
    csc     cnull, 208(ct6)
    clc     cs3, 224(ct6)
    csc     cnull, 224(ct6)
    clc     cs4, 240(ct6)
    csc     cnull, 240(ct6)
    clc     cs5, 256(ct6)
    csc     cnull, 256(ct6)
    clc     cs6, 272(ct6)
    csc     cnull, 272(ct6)
    clc     cs7, 288(ct6)
    csc     cnull, 288(ct6)
    clc     cs8, 304(ct6)
    csc     cnull, 304(ct6)
    clc     cs9, 320(ct6)
    csc     cnull, 320(ct6)
    clc     cs10, 336(ct6)
    csc     cnull, 336(ct6)
    clc     cs11, 352(ct6)
    csc     cnull, 352(ct6)
    clc     ca0, 368(ct6)
    csc     cnull, 368(ct6)
    clc     ca1, 384(ct6)
    csc     cnull, 384(ct6)
    clc     ca2, 400(ct6)
    csc     cnull, 400(ct6)
    clc     ca3, 416(ct6)
    csc     cnull, 416(ct6)
    clc     ca4, 432(ct6)
    csc     cnull, 432(ct6)
    clc     ca5, 448(ct6)
    csc     cnull, 448(ct6)
    clc     ca6, 464(ct6)
    csc     cnull, 464(ct6)
    clc     ca7, 480(ct6)
    csc     cnull, 480(ct6)
    csc     cnull, FRAME_LINK(ct6)      /* active_kernel_sp */
    clc     csp,  16(ct6)
    csc     cnull, 16(ct6)
    caddi   ct6, ct6, TRAP_FRAME_SIZE   /* ct6 = kernel SP above the frame */
    csrrw   ct6, sscratchc, ct6         /* sscratchc = kernel SP, ct6 = saved ct6 */
    sret

.Lresume_return_frame:
    /*
     * The unwind stopped at a `ReturnFrame` (the handler's `TrapFrame`, and
     * whatever was above it, belonged to destroyed compartments): leave
     * through the switcher's restore sequence, which derives the frame from
     * `sscratchc`, gives the caller `args[0]` and `ret`s.
     */
    j       __signetos_resume_return_frame
