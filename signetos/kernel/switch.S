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
 *      registers `ca1..ca5`) onto the thread's kernel stack (`sscratchc`),
 *      calls `__signetos_switcher_prepare` to resolve the target record and
 *      narrow the caller's stack, then enters the callee with a `CT = 1`
 *      return sentry in `cra`:
 *
 *        compartment callee   csp = everything below the caller's csp,
 *                             cgp = its table, ca0 = args[0], every other
 *                             register scrubbed, caller's SIE restored.
 *        kernel callee        csp = exactly `min_stack` bytes below the
 *             (ENTRY_FLAG_TRUSTED)  caller's csp, ca0..ca4 = args[0..4],
 *                             nothing scrubbed, interrupts stay masked.
 *
 *      On return, calls `__signetos_switcher_return` to pop the `ReturnFrame`
 *      and scrub the callee's stack region, restores the caller's state and
 *      `SIE`, and scrubs all volatile registers (`ct0..ct6`, `ca1..ca7`).
 *      `ca0` carries the kernel callee's checked return value, `0` after a
 *      compartment callee, or the `Status` of a refused call.
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
 * caller's `SIE` is re-established only by the last few instructions before
 * control returns to user code, after every kernel frame has been popped.
 *
 * NO MACROS: every register sequence in this file is written out in place so
 * each path reads top to bottom. Only constants come from `asm_macros.h`: the
 * frame offsets (`RET_FRAME_*`, `FRAME_SP`, `SWITCH_FRAME_SIZE`), which
 * `sentry.cpp` static_asserts against `ReturnFrame`, and the `sstatus`,
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
 *   ca0       = target `OType::EntryPoint` handle (`CT = 12`)
 *   ca1..ca5  = arguments; a compartment callee receives ca1 as its ca0, a
 *               kernel callee receives ca1..ca5 as its ca0..ca4
 * Output:
 *   ca0       = kernel callee's return value / 0 after a compartment callee /
 *               `Status` if the call was refused
 */

    .align 4
    .globl sys_compartment_invoke
    .type sys_compartment_invoke, @function
sys_compartment_invoke:
    /*
     * 1. Mask interrupts (keeping the caller's `sstatus` in `t2`, a volatile
     *    register that is scrubbed on every exit path), read the current
     *    hart's kernel stack pointer from `sscratchc` (`ct0`) and verify that
     *    there is a kernel stack with enough space for a `ReturnFrame` plus
     *    the headroom its callee may need on it.
     */
    csrrci  t2, sstatus, SSTATUS_SIE
    csrr    ct0, sscratchc
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
    csc     ctp,  48(ct1)               /* ReturnFrame::tp */
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
    csc     ct0, RET_FRAME_PREV_KSP(ct1)
    csc     ca1, RET_FRAME_ARG0(ct1)
    csc     ca2, RET_FRAME_ARG1(ct1)
    csc     ca3, RET_FRAME_ARG2(ct1)
    csc     ca4, RET_FRAME_ARG3(ct1)
    csc     ca5, RET_FRAME_ARG4(ct1)
    sd      t2,  RET_FRAME_SSTATUS(ct1)
    sd      zero, RET_FRAME_FLAGS(ct1)
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
     * 4. Load the callee's environment. `ct0` = its `CT = 1` sentry, `ca0` =
     *    its first argument, `cgp` = its table (null for the kernel). The
     *    `ReturnFrame` is now the hart's kernel SP, so a trap from here on
     *    nests correctly below it.
     */
    cmv     ct0, ca0
    ld      t1,  RET_FRAME_FLAGS(csp)
    clc     ca0, RET_FRAME_ARG0(csp)
    clc     cgp, RET_FRAME_CALLEE_GP(csp)
    andi    t1, t1, ENTRY_TRUSTED
    bnez    t1, .Lenter_kernel

    /*
     * 4a. Compartment callee: give it the caller's `SIE`, scrub every other
     *     register, and jump (`cjalr` seals `.Lcomp_restore` into `cra` as a
     *     `CT = 1` return sentry).
     */
    ld      t1,  RET_FRAME_SSTATUS(csp)
    clc     csp, RET_FRAME_CALLEE_SP(csp)
    andi    t1, t1, SSTATUS_SIE
    beqz    t1, 1f
    csrsi   sstatus, SSTATUS_SIE
1:
    /* Everything except ct0 (sentry), csp, cgp, ca0 and cra (set by cjalr). */
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
    cmv     ca1, cnull
    cmv     ca2, cnull
    cmv     ca3, cnull
    cmv     ca4, cnull
    cmv     ca5, cnull
    cmv     ca6, cnull
    cmv     ca7, cnull
    cjalr   cra, ct0

.Lcomp_restore:
    /*
     * 5. Callee returned via `cra` with its result in `ca0`. Mask, then
     *    validate and pop the top `ReturnFrame` and scrub the callee's stack
     *    in C++ (`__signetos_switcher_return(ret)`), which also decides what
     *    the caller gets back in `ca0` and leaves it in `args[0]`.
     */
    csrci   sstatus, SSTATUS_SIE
    csrr    csp, sscratchc
    cjal    cra, __signetos_switcher_return
    beqz    a0, .Lcomp_bad_return
    cmv     ct1, ca0                    /* ct1 = popped ReturnFrame* */

.Lcomp_pop_frame:
    /*
     * 6. Restore caller's callee-saved registers and full `csp`, load the
     *    caller's `ca0` from `args[0]`, wipe the popped `ReturnFrame`, scrub
     *    all volatile registers, and return.
     */
    clc     cra,   0(ct1)               /* ReturnFrame::ra */
    clc     csp,  FRAME_SP(ct1)         /* ReturnFrame::sp (full bounds) */
    clc     cgp,  32(ct1)               /* ReturnFrame::gp */
    clc     ctp,  48(ct1)               /* ReturnFrame::tp */
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
    ld      t2,  RET_FRAME_SSTATUS(ct1)
    clc     ca0, RET_FRAME_ARG0(ct1)
    /* Wipe all 25 slots of the popped frame. */
    csc     cnull,   0(ct1)             /* ra */
    csc     cnull,  FRAME_SP(ct1)       /* sp */
    csc     cnull,  32(ct1)             /* gp */
    csc     cnull,  48(ct1)             /* tp */
    csc     cnull,  64(ct1)             /* s[0..11] */
    csc     cnull,  80(ct1)
    csc     cnull,  96(ct1)
    csc     cnull, 112(ct1)
    csc     cnull, 128(ct1)
    csc     cnull, 144(ct1)
    csc     cnull, 160(ct1)
    csc     cnull, 176(ct1)
    csc     cnull, 192(ct1)
    csc     cnull, 208(ct1)
    csc     cnull, 224(ct1)
    csc     cnull, 240(ct1)
    csc     cnull, RET_FRAME_PREV_KSP(ct1)
    csc     cnull, RET_FRAME_ARG0(ct1)
    csc     cnull, RET_FRAME_ARG1(ct1)
    csc     cnull, RET_FRAME_ARG2(ct1)
    csc     cnull, RET_FRAME_ARG3(ct1)
    csc     cnull, RET_FRAME_ARG4(ct1)
    csc     cnull, RET_FRAME_CALLEE_SP(ct1)
    csc     cnull, RET_FRAME_CALLEE_GP(ct1)
    csc     cnull, RET_FRAME_SSTATUS(ct1) /* sstatus + flags */

    /*
     * Common exit to user code. `t2` holds the caller's `sstatus` as sampled
     * on entry (every path that reaches here has loaded it): re-enable
     * interrupts only if the caller had them enabled. Every kernel frame has
     * been popped and wiped by now, so a trap taken between `csrsi` and `ret`
     * carves its `TrapFrame` from `sscratchc` over dead stack only.
     */
.Lscrub_caller_and_ret:
    cmv     ct0, cnull
    andi    t2, t2, SSTATUS_SIE
    beqz    t2, 1f
    csrsi   sstatus, SSTATUS_SIE
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
     * 4b. Kernel callee (`ENTRY_FLAG_TRUSTED`): pass the remaining arguments
     *     through, pivot onto the narrowed slice of the caller's stack, and
     *     call. Interrupts stay masked; nothing is scrubbed, the kernel keeps
     *     the caller's registers to itself and the return path scrubs them.
     */
    clc     ca1, RET_FRAME_ARG1(csp)
    clc     ca2, RET_FRAME_ARG2(csp)
    clc     ca3, RET_FRAME_ARG3(csp)
    clc     ca4, RET_FRAME_ARG4(csp)
    clc     csp, RET_FRAME_CALLEE_SP(csp)
    cjalr   cra, ct0
    j       .Lcomp_restore

.Lno_kernel_stack:
    /*
     * No kernel stack, or no room on it: nothing was pushed. Hand the caller
     * `Status::NoKernelStack` through the common exit, which also restores its
     * `SIE` from `t2`.
     */
    li      a0, STATUS_NO_KERNEL_STACK
    j       .Lscrub_caller_and_ret

.Lcomp_bad_return:
    /*
     * A return sentry was used without a matching `ReturnFrame` (replayed, or
     * the frame was consumed by an earlier return). The thread cannot be
     * trusted to continue: end it. `csp` is the kernel stack here.
     */
    li      a0, -1
    cjal    cra, sys_thread_exit
    unimp                               /* host context: thread::exit returned */
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
    csrci   sstatus, SSTATUS_SIE
    /*
     * Carve the frame from `sscratchc` without losing any register: swap
     * `ct0` with `sscratchc` (caller's `ct0` is now in the CSR, `ct0` is the
     * kernel SP), save `ct1` so it can serve as scratch, swap the caller's
     * `ct0` back out through `ct1` and leave `sscratchc` exactly as it was
     * (= frame + SWITCH_FRAME_SIZE, the invariant `__thread_restore` relies
     * on). Same sequence as `_early_trap_entry` step 1 in `early_trap.S`.
     */
    csrrw   ct0, sscratchc, ct0         /* ct0 = ksp, sscratchc = caller's ct0 */
    caddi   ct0, ct0, -SWITCH_FRAME_SIZE /* ct0 = frame base */
    csc     ct1,  80(ct0)               /* frame->t[1]; ct1 is scratch below */
    caddi   ct1, ct0, SWITCH_FRAME_SIZE /* ct1 = original ksp */
    csrrw   ct1, sscratchc, ct1         /* ct1 = caller's ct0, sscratchc = ksp */
    csc     ct1,  64(ct0)               /* frame->t[0] = caller's ct0 */
    csc     cra,   0(ct0)
    csc     csp,  16(ct0)
    csc     cgp,  32(ct0)
    csc     ctp,  48(ct0)
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
     *    Restores all 31 capability registers from the `SwitchFrame` at `ca0`,
     *    wipes the frame to `cnull`, re-installs `sscratchc = frame + 512`, and
     *    jumps to `cra` -- always still masked. Every frame restored here
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
     * `ct6` is the frame base for the whole sequence and the last register
     * reloaded: its saved value is parked in `sscratchc` meanwhile and swapped
     * back by the final `csrrw`, which at the same time re-installs the kernel
     * SP (`frame + SWITCH_FRAME_SIZE`). Each of the 32 slots is loaded and then
     * overwritten with `cnull`, so the popped frame leaves no capability on
     * the kernel stack. Same sequence as `.Ltrap_restore` in `early_trap.S`,
     * except that the base comes from `ca0`, not `csp`.
     */
    cmv     ct6, ca0                    /* ct6 = frame base */
    clc     ct5, 160(ct6)               /* ct5 = saved ct6 */
    csrw    sscratchc, ct5              /* park saved ct6 in sscratchc */
    csc     cnull, 160(ct6)
    clc     cra,   0(ct6)
    csc     cnull, 0(ct6)
    clc     cgp,  32(ct6)
    csc     cnull, 32(ct6)
    clc     ctp,  48(ct6)
    csc     cnull, 48(ct6)
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
    csc     cnull, 496(ct6)             /* active_kernel_sp */
    clc     csp,  16(ct6)
    csc     cnull, 16(ct6)
    caddi   ct6, ct6, SWITCH_FRAME_SIZE /* ct6 = kernel SP above the frame */
    csrrw   ct6, sscratchc, ct6         /* sscratchc = kernel SP, ct6 = saved ct6 */
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
     */
    .align 4
    .globl __thread_start
    .type __thread_start, @function
__thread_start:
    csrsi   sstatus, SSTATUS_SIE
    cjalr   cra, ct0
    csrci   sstatus, SSTATUS_SIE
    csrr    csp, sscratchc
    li      a0, 0
    cjal    cra, sys_thread_exit
    unimp
    .size __thread_start, . - __thread_start
