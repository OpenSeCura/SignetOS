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
 * switch.S - SignetOS Synchronous Kernel Transitions
 *
 * Implements the control-flow transitions between user
 * compartments, threads, and the kernel:
 *
 *   1. THE SWITCHER (`sys_compartment_invoke`):
 *      Caller -> Callee -> Caller, where the callee is a compartment entry
 *      point or one of the kernel's own system calls. This is the only
 *      `CT = 1` sentry a compartment ever holds; every system call is an
 *      `OType::EntryPoint` record (`syscall::gate`) passed to it in `ca0`.
 *
 *      Pushes a `ReturnFrame` (callee-saved registers, the five argument
 *      registers `ca1..ca5`) onto the thread's kernel stack (`mscratchc`),
 *      calls `__signetos_switcher_prepare` to resolve the target record and
 *      narrow the caller's stack, then enters the callee with a `CT = 2`
 *      return sentry in `cra`:
 *
 *        compartment callee   csp = everything below the caller's csp,
 *                             cgp = its table, ca0..ca4 = args[0..4], every
 *                             other register scrubbed, caller's MIE restored.
 *        kernel callee        csp = exactly `min_stack` bytes below the
 *             (ENTRY_FLAG_TRUSTED)  caller's csp, ca0..ca4 = args[0..4],
 *                             nothing scrubbed, interrupts stay masked.
 *
 *      On return, calls `__signetos_switcher_return` to pop the `ReturnFrame`,
 *      zeroes the callee's stack region, restores the caller's state and
 *      `MIE`, and scrubs all volatile registers (`ct0..ct6`, `ca1..ca7`).
 *      `ca0` carries the callee's checked return value, or the `Status` of a
 *      refused call.
 *
 *   2. THREAD CONTEXT SWITCHER (`sys_thread_switch`, `__thread_restore`,
 *      `__thread_exit_to_host`, `__thread_start`):
 *      Outgoing Thread (or Kernel Host) -> Incoming Thread.
 *      Saves all 31 capability registers in a `SwitchFrame` on the outgoing
 *      kernel stack, calls `__signetos_thread_dispatch`, and restores the
 *      incoming thread's `SwitchFrame`. `sys_thread_switch` is a kernel entry
 *      like any other (reached through the switcher), except that it needs no
 *      user stack at all: its frame goes on the kernel stack and its C++ runs
 *      there. The host (`init::launch`) calls it directly.
 *
 * INTERRUPT MASKING: see `asm_macros.h`. Every entry below masks first; the
 * caller's `MIE` is re-established only by the last few instructions before
 * control returns to user code, after every kernel frame has been popped.
 *
 * STACK ZEROING: a compartment never sees what other code left on the
 * thread's stack. Everything below the `csp` a compartment callee or a trap
 * handler starts with is zeroed just before it is entered, and the whole
 * slice it was lent (`callee_sp`, `handler_sp`) when the frame that lent it
 * is resumed. Both are done here and in `early_trap.S`, with
 * `__signetos_zero_stack` (section 3). Unwinding past dead frames zeroes only
 * the slice of the frame it resumes: every slice above it was carved from
 * that one, so it covers them all.
 *
 * POPPED FRAMES ARE NOT WIPED: once a frame is popped nothing reads it again
 * (every field is written before it is read, at push or by the C++ that set
 * the frame up) and no compartment holds the kernel stack's bounds.
 *
 * NO MACROS: every register sequence in this file is written out in place so
 * each path reads top to bottom. Only constants come from `asm_macros.h`: the
 * frame offsets (`RET_FRAME_*`, `FRAME_SP`, `SWITCH_FRAME_SIZE`), which
 * `switcher.cpp` static_asserts against `ReturnFrame`, and the `mstatus`,
 * `ENTRY_TRUSTED` and `Status` values.
 */

#include <signetos/asm_macros.h>

    .section .text, "ax", @progbits
    .option capmode
    .option norvc

/* =========================================================================
 * 1. THE SWITCHER (`sys_compartment_invoke`)
 * =========================================================================
 * Inputs:
 *   ca0       = target `OType::EntryPoint` handle (`CT = 18`)
 *   ca1..ca5  = arguments; the callee receives ca1..ca5 as its ca0..ca4
 * Output:
 *   ca0       = callee's return value, or `Status` if the call was refused
 */

    .align 4
    .globl sys_compartment_invoke
    .type sys_compartment_invoke, @function
sys_compartment_invoke:
    /*
     * 1. Mask interrupts (keeping the caller's `mstatus` in `t2`, a volatile
     *    register that is scrubbed on every exit path), read the current
     *    hart's kernel stack pointer from `mscratchc` (`ct0`) and verify that
     *    there is a kernel stack with enough space for a `ReturnFrame` plus
     *    the headroom its callee may need on it.
     */
    csrrci  t2, mstatus, MSTATUS_MIE
    csrr    ct0, mscratchc
    gctag   t1, ct0
    beqz    t1, .Lno_kernel_stack
    gcbase  t1, ct0
    addi    t1, t1, RET_FRAME_MIN_FREE
    bltu    t0, t1, .Lno_kernel_stack

    /*
     * 2. Push a `ReturnFrame` onto the thread's kernel stack (`ct1`) and save
     *    the caller's callee-saved registers, previous kernel SP, and the
     *    five argument registers.
     */
    caddi   ct1, ct0, -RET_FRAME_SIZE
    csc     cra,   0(ct1)               /* ReturnFrame::ra */
    csc     csp,  FRAME_SP(ct1)         /* ReturnFrame::sp (full bounds) */
    csc     cgp,  32(ct1)               /* ReturnFrame::gp */
    csc     ct0, FRAME_LINK(ct1)        /* ReturnFrame::prev_ksp */
    csc     cs0,  64(ct1)               /* ReturnFrame::s[0..11] */
    csc     cs1,  80(ct1)
    csc     cs2,  96(ct1)
    csc     cs3, 112(ct1)
    csc     cs4, 128(ct1)
    csc     cs5, 144(ct1)
    csc     cs6, 160(ct1)
    csc     cs7, 176(ct1)
    csc     cs8, 192(ct1)
    csc     cs9, 208(ct1)
    csc     cs10, 224(ct1)
    csc     cs11, 240(ct1)
    csc     ctp, RET_FRAME_TP(ct1)      /* ReturnFrame::tp */
    csc     ca1, RET_FRAME_ARG0(ct1)
    csc     ca2, RET_FRAME_ARG1(ct1)
    csc     ca3, RET_FRAME_ARG2(ct1)
    csc     ca4, RET_FRAME_ARG3(ct1)
    csc     ca5, RET_FRAME_ARG4(ct1)
    sd      t2,  RET_FRAME_MSTATUS(ct1)
    sd      zero, RET_FRAME_FLAGS(ct1)
    csc     cnull, RET_FRAME_CALLEE_COMP(ct1) /* set by _prepare if it enters */
    cmv     csp, ct1

    /*
     * 3. Resolve the target record (`ca0`), validate and narrow the caller's
     *    stack in C++ (`__signetos_switcher_prepare(entry_point, frame)`).
     *    On refusal (`a0 == 0`) the `Status` is already in `args[0]`: unwind
     *    the `ReturnFrame` and return it to the caller.
     */
    cmv     ca1, csp                    /* ca1 = ReturnFrame* */
    cjal    cra, __signetos_switcher_prepare
    cmv     ct1, csp                    /* ct1 = ReturnFrame* (if unwinding) */
    beqz    a0, .Lcomp_pop_frame

    /*
     * 4. Load the callee's environment. `ct0` = its `CT = 1` sentry, `ca0..ca4`
     *    = its five arguments, `cgp` = its table (null for the kernel). The
     *    `ReturnFrame` is now the hart's kernel SP, so a trap from here on
     *    nests correctly below it.
     */
    cmv     ct0, ca0
    ld      t1,  RET_FRAME_FLAGS(csp)
    clc     ca0, RET_FRAME_ARG0(csp)
    clc     ca1, RET_FRAME_ARG1(csp)
    clc     ca2, RET_FRAME_ARG2(csp)
    clc     ca3, RET_FRAME_ARG3(csp)
    clc     ca4, RET_FRAME_ARG4(csp)
    clc     cgp, RET_FRAME_CALLEE_GP(csp)
    andi    t1, t1, ENTRY_TRUSTED
    bnez    t1, .Lenter_kernel

    /*
     * 4a. Compartment callee: zero everything below its `csp` (what the
     *     caller's own calls left there), give it the caller's `MIE`, scrub
     *     every other register, and jump (`cjalr` seals `.Lcomp_restore` into
     *     `cra` as a `CT = 2` return sentry).
     */
    clc     ct3, RET_FRAME_CALLEE_SP(csp)
    mv      t4, t3                      /* up to its csp */
    cjal    cra, __signetos_zero_stack
    ld      t1,  RET_FRAME_MSTATUS(csp)
    clc     csp, RET_FRAME_CALLEE_SP(csp)
    andi    t1, t1, MSTATUS_MIE
    beqz    t1, 1f
    csrsi   mstatus, MSTATUS_MIE
1:
    /* Everything except ct0 (sentry), csp, cgp, ca0..ca4 and cra (set by cjalr). */
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
    cmv     ca5, cnull
    cmv     ca6, cnull
    cmv     ca7, cnull
    cjalr   cra, ct0

.Lcomp_restore:
    /*
     * 5. Callee returned via `cra` with its result in `ca0`. Mask, then pop
     *    the top `ReturnFrame` and scrub the callee's stack in C++
     *    (`__signetos_switcher_return(ret)` = `unwind::resume`), which also
     *    checks what the caller gets back in `ca0` and leaves it in
     *    `args[0]`. If the caller's compartment has been destroyed and swept
     *    it unwinds further; `a0` says what kind of frame it stopped at
     *    (UNWIND_*), and that frame sits just below the new `mscratchc`.
     */
    csrci   mstatus, MSTATUS_MIE
    csrr    csp, mscratchc
    cjal    cra, __signetos_switcher_return
    beqz    a0, .Lcomp_bad_return
    li      t0, UNWIND_TRAP_FRAME
    beq     a0, t0, .Lresume_trap_frame

    /*
     *    Resume a `ReturnFrame`: the one just popped, directly below the
     *    kernel SP. Also the trap vector's way out when its unwind stops at a
     *    `ReturnFrame` (early_trap.S step 4).
     */
    .globl __signetos_resume_return_frame
__signetos_resume_return_frame:
    csrr    ct1, mscratchc
    caddi   ct1, ct1, -RET_FRAME_SIZE   /* ct1 = ReturnFrame* to resume */
    /* Zero the whole slice the callee was lent (null for `thread_switch`). */
    clc     ct3, RET_FRAME_CALLEE_SP(ct1)
    gcbase  t4, ct3
    gclen   t5, ct3
    add     t4, t4, t5
    cjal    cra, __signetos_zero_stack

.Lcomp_pop_frame:
    /*
     * 6. Restore caller's callee-saved registers and full `csp`, load the
     *    caller's `ca0` from `args[0]`, scrub all volatile registers, and
     *    return. A refused call comes straight here: its callee never ran.
     */
    clc     cra,   0(ct1)               /* ReturnFrame::ra */
    clc     csp,  FRAME_SP(ct1)         /* ReturnFrame::sp (full bounds) */
    clc     cgp,  32(ct1)               /* ReturnFrame::gp */
    clc     ctp, RET_FRAME_TP(ct1)      /* ReturnFrame::tp */
    clc     cs0,  64(ct1)               /* ReturnFrame::s[0..11] */
    clc     cs1,  80(ct1)
    clc     cs2,  96(ct1)
    clc     cs3, 112(ct1)
    clc     cs4, 128(ct1)
    clc     cs5, 144(ct1)
    clc     cs6, 160(ct1)
    clc     cs7, 176(ct1)
    clc     cs8, 192(ct1)
    clc     cs9, 208(ct1)
    clc     cs10, 224(ct1)
    clc     cs11, 240(ct1)
    ld      t2,  RET_FRAME_MSTATUS(ct1)
    clc     ca0, RET_FRAME_ARG0(ct1)

    /*
     * Common exit to user code. `t2` holds the caller's `mstatus` as sampled
     * on entry (every path that reaches here has loaded it): re-enable
     * interrupts only if the caller had them enabled. Every kernel frame has
     * been popped by now, so a trap taken between `csrsi` and `ret` carves
     * its `TrapFrame` from `mscratchc` over dead stack only.
     */
.Lscrub_caller_and_ret:
    cmv     ct0, cnull
    andi    t2, t2, MSTATUS_MIE
    beqz    t2, 1f
    csrsi   mstatus, MSTATUS_MIE
1:
    cmv     ct1, cnull
    cmv     ct2, cnull
    cmv     ct3, cnull
    cmv     ct4, cnull
    cmv     ct5, cnull
    cmv     ct6, cnull
    cmv     ca1, cnull
    cmv     ca2, cnull
    cmv     ca3, cnull
    cmv     ca4, cnull
    cmv     ca5, cnull
    cmv     ca6, cnull
    cmv     ca7, cnull
    ret

.Lenter_kernel:
    /*
     *     Kernel callee (`ENTRY_FLAG_TRUSTED`): pivot onto the narrowed slice
     *     of the caller's stack and call. Interrupts stay masked; nothing is
     *     scrubbed, the kernel keeps the caller's registers to itself and the
     *     return path scrubs them.
     *     TODO: revisit
     */
    clc     csp, RET_FRAME_CALLEE_SP(csp)
    cjalr   cra, ct0
    j       .Lcomp_restore

.Lno_kernel_stack:
    /*
     * No kernel stack, or no room on it: nothing was pushed. Hand the caller
     * `Status::NoKernelStack` through the common exit, which also restores its
     * `MIE` from `t2`.
     */
    li      a0, STATUS_NO_KERNEL_STACK
    j       .Lscrub_caller_and_ret

.Lcomp_bad_return:
    /*
     * Nothing to return to: a return sentry was used without a matching
     * `ReturnFrame` (replayed, or consumed by an earlier return), or every
     * frame beneath was in a destroyed compartment (`unwind::resume` says
     * which on the console). Either way the thread ends. `csp` is the kernel
     * stack here.
     */
    li      a0, -1
    cjal    cra, sys_thread_exit
    unimp                               /* host context: thread::exit returned */

.Lresume_trap_frame:
    /*
     * The unwind stopped at a `TrapFrame` (the frames above it were in
     * destroyed compartments): leave through the trap vector's restore
     * sequence, which derives the frame from `mscratchc` and `mret`s.
     * Interrupts are masked, as that sequence requires.
     */
    j       __signetos_resume_trap_frame
    .size sys_compartment_invoke, . - sys_compartment_invoke


/* =========================================================================
 * 2. THREAD CONTEXT SWITCHER (`sys_thread_switch` & lifecycle helpers)
 * ========================================================================= */

    .align 4
    .globl sys_thread_switch
    .type sys_thread_switch, @function
sys_thread_switch:
    /*
     * 1. Mask interrupts (already masked when entered through the switcher;
     *    the host runs masked), then push a `SwitchFrame` onto the current
     *    thread's kernel stack and save all 31 capability registers. `csp` is
     *    whatever the caller handed over and is never used: the frame and the
     *    C++ below both live on the kernel stack.
     */
    csrci   mstatus, MSTATUS_MIE
    /*
     * Carve the frame from `mscratchc` without losing any register: swap
     * `ct0` with `mscratchc` (caller's `ct0` is now in the CSR, `ct0` is the
     * kernel SP), save `ct1` so it can serve as scratch, swap the caller's
     * `ct0` back out through `ct1` and leave `mscratchc` exactly as it was
     * (= frame + SWITCH_FRAME_SIZE, the invariant `__thread_restore` relies
     * on). Same sequence as `_early_trap_entry` step 1 in `early_trap.S`.
     */
    csrrw   ct0, mscratchc, ct0         /* ct0 = ksp, mscratchc = caller's ct0 */
    caddi   ct0, ct0, -SWITCH_FRAME_SIZE /* ct0 = frame base */
    csc     ct1,  80(ct0)               /* frame->t[1]; ct1 is scratch below */
    caddi   ct1, ct0, SWITCH_FRAME_SIZE /* ct1 = original ksp */
    csc     ct1, FRAME_LINK(ct0)        /* frame->active_kernel_sp */
    csrrw   ct1, mscratchc, ct1         /* ct1 = caller's ct0, mscratchc = ksp */
    csc     ct1,  64(ct0)               /* frame->t[0] = caller's ct0 */
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

    /*
     * 2. Call `__signetos_thread_dispatch(thread_handle, saved_frame)`.
     *    Returns the `SwitchFrame*` to restore in `ca0` (the incoming thread's
     *    frame on success, or `saved_frame` with `frame->a[0] = Status` on
     *    refusal).
     */
    cmv     csp, ct0
    cmv     ca1, ct0
    cjal    cra, __signetos_thread_dispatch
    .size sys_thread_switch, . - sys_thread_switch

    /*
     * 3. `__thread_restore(Capability next_ksp)`
     *    Re-installs `mscratchc = frame + SWITCH_FRAME_SIZE`, restores all 31
     *    capability registers from the `SwitchFrame` at `ca0` and jumps to
     *    `cra` -- always still masked. Every frame restored here
     *    resumes kernel code that unmasks on its own way out: the switcher's
     *    `.Lcomp_restore` (a thread parked by `sys_thread_switch`),
     *    `__thread_start` (a new thread) or the host loop (which never
     *    unmasks).
     */
    .align 4
    .globl __thread_restore
    .type __thread_restore, @function
__thread_restore:
    /*
     * `ct6` is the frame base, reloaded last. Same sequence as
     * `.Ltrap_restore` in `early_trap.S`, except that the base comes from
     * `ca0`, not `csp`.
     */
    cmv     ct6, ca0                    /* ct6 = frame base */
    caddi   ct5, ct6, SWITCH_FRAME_SIZE
    csrw    mscratchc, ct5              /* kernel SP: just above the frame */
    clc     cra,   0(ct6)
    clc     csp,  16(ct6)
    clc     cgp,  32(ct6)
    clc     ctp, FRAME_TP(ct6)
    clc     ct0,  64(ct6)
    clc     ct1,  80(ct6)
    clc     ct2,  96(ct6)
    clc     ct3, 112(ct6)
    clc     ct4, 128(ct6)
    clc     ct5, 144(ct6)
    clc     cs0, 176(ct6)
    clc     cs1, 192(ct6)
    clc     cs2, 208(ct6)
    clc     cs3, 224(ct6)
    clc     cs4, 240(ct6)
    clc     cs5, 256(ct6)
    clc     cs6, 272(ct6)
    clc     cs7, 288(ct6)
    clc     cs8, 304(ct6)
    clc     cs9, 320(ct6)
    clc     cs10, 336(ct6)
    clc     cs11, 352(ct6)
    clc     ca0, 368(ct6)
    clc     ca1, 384(ct6)
    clc     ca2, 400(ct6)
    clc     ca3, 416(ct6)
    clc     ca4, 432(ct6)
    clc     ca5, 448(ct6)
    clc     ca6, 464(ct6)
    clc     ca7, 480(ct6)
    clc     ct6, 160(ct6)               /* the base, last */
    ret
    .size __thread_restore, . - __thread_restore

    /*
     * `__thread_exit_to_host(ThreadState* t, Capability host_ksp)`
     * Pivots `csp` onto `host_ksp` (`ca1`) BEFORE `__signetos_teardown_thread`
     * frees the dying thread's `state_page` and stack, then restores the host
     * context.
     */
    .align 4
    .globl __thread_exit_to_host
    .type __thread_exit_to_host, @function
__thread_exit_to_host:
    cmv     csp, ca1
    cmv     cs0, ca1
    cjal    cra, __signetos_teardown_thread
    cmv     ca0, cs0
    j       __thread_restore
    .size __thread_exit_to_host, . - __thread_exit_to_host

    /*
     * `__thread_start`
     * Initial trampoline for a newly created thread (`ct0` = entry sentry,
     * `ca0` = `initial_arg`, `cgp` = compartment cap table, `csp` = `user_sp`).
     * A new thread is plain user code, so it starts unmasked. If the entry
     * ever returns, the thread ends: `thread::exit` runs on the thread's own
     * kernel stack (the user stack is whatever the entry left behind).
     *
     * The entry sentry was resolved when the thread was created. If its
     * compartment has been destroyed and swept since, `ct0` has lost its tag
     * (the sweep scans the frame it was loaded from): jumping to it would
     * fault in kernel text and halt the machine, so the thread ends instead.
     *
     * A new thread reaches it through `__thread_restore`'s `ret`, and a return
     * only goes through a return sentry, which only the hardware makes, as
     * the link of a jump (toolchain/sentries). `__thread_start_link` makes one
     * by jumping from the instruction just before `__thread_start`, so
     * nothing may come between the two.
     */
    .align 4
    .globl __thread_start_link
    .type __thread_start_link, @function
__thread_start_link:
    cmv     ct1, cra
    cjal    cra, .Lthread_start_linked  /* cra = return sentry to __thread_start */
    .size __thread_start_link, . - __thread_start_link

    .globl __thread_start
    .type __thread_start, @function
__thread_start:
    gctag   t1, ct0
    beqz    t1, 1f
    csrsi   mstatus, MSTATUS_MIE
    cjalr   cra, ct0
    csrci   mstatus, MSTATUS_MIE
    csrr    csp, mscratchc
    li      a0, 0
    cjal    cra, sys_thread_exit
    unimp
1:
    csrr    csp, mscratchc
    li      a0, -1
    cjal    cra, sys_thread_exit
    unimp
    .size __thread_start, . - __thread_start

    /* The rest of `__thread_start_link`: hand the link back in `ca0`. */
.Lthread_start_linked:
    cmv     ca0, cra
    cmv     cra, ct1
    ret


/* =========================================================================
 * 3. STACK ZEROING (`__signetos_zero_stack`)
 * =========================================================================
 * Zeroes `[base(ct3), t4)`: `ct3` is a stack capability (its address is
 * ignored), `t4` the address to stop at -- its `csp` to zero below a stack
 * pointer, its top to zero all of it. Nothing if `ct3` is untagged. Both ends
 * are 16-byte aligned: every stack slice is (`switcher::narrow_stack`).
 * Clobbers `ct3`, `t5`; called with `cjal cra` and returns with `ret`.
 * Interrupts are masked throughout.
 */
    .align 4
    .globl __signetos_zero_stack
    .type __signetos_zero_stack, @function
__signetos_zero_stack:
    gctag   t5, ct3
    beqz    t5, 2f
    gcbase  t5, ct3
    scaddr  ct3, ct3, t5                /* from the base */
1:
    bgeu    t3, t4, 2f
    csc     cnull, 0(ct3)
    caddi   ct3, ct3, 16
    j       1b
2:
    ret
    .size __signetos_zero_stack, . - __signetos_zero_stack
