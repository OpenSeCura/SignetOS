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

#pragma once

/*
 * asm_macros.h - Shared CHERI RISC-V Kernel Frame Layout Constants
 *
 * Constants only (no assembler macros: `switch.S` and `early_trap.S` write
 * every register sequence out in place). Included by `kernel/switch.S`,
 * `kernel/early_trap.S`, and by `sentry.cpp`, which
 * static_asserts the offsets against the C++ structs they describe.
 *
 * PER-HART KERNEL STACK POINTER (`mscratchc`)
 * -------------------------------------------
 * Each hart stores its active thread's kernel stack pointer in its `mscratchc`
 * capability CSR (the boot kernel stack when running in host context with no
 * active user thread). Because `mscratchc` is a machine CSR, compartments
 * (which lack `AccessSystemRegs`) cannot read or modify it, and each hart has
 * its own independent register with no global `.bss` state.
 *
 * The kernel stack holds frames only: a thread's `SwitchFrame`, the
 * `TrapFrame`s of traps taken in it, and one `ReturnFrame` per call that is
 * in progress through the switcher. Kernel C++ that runs on behalf of a call
 * (a system call body) runs on the caller's own stack, narrowed, exactly like
 * a compartment callee does; only the switcher's own helpers and the trap
 * dispatcher run on the kernel stack, directly below the frame they manage.
 *
 * KERNEL STACK FRAME LAYOUTS
 * --------------------------
 * Every frame keeps its FRAME LINK at offset 48 (below). The rest of the
 * layouts follow.
 *
 * 1. `SwitchFrame` (512 bytes = 32 capabilities, `thread.hpp`) and
 *    `TrapFrame`   (640 bytes = 37 capabilities + 6 integers, `trap.hpp`)
 *    share the same layout for offsets 0..496:
 *
 *      Offset    Field              Register(s)
 *      ------    -----              -----------
 *        0       ra                 cra
 *       16       sp                 csp
 *       32       gp                 cgp
 *       48       active_kernel_sp   FRAME LINK: kernel SP above this frame
 *       64..160  t[0..6]            ct0..ct6
 *      176..352  s[0..11]           cs0..cs11
 *      368..480  a[0..7]            ca0..ca7
 *      496       tp                 ctp
 *
 *    `TrapFrame` appends three trap-specific capability slots, four
 *    integers in two more 16-byte slots, one more capability, then the
 *    handler's arguments:
 *      512       mepcc              interrupted PC capability
 *      528       handler_sp         narrowed stack for bound trap handler
 *      544       handler_rw_table   handler compartment cap table (`cgp`)
 *      560       mstatus            integer `mstatus` at trap entry (only
 *                                   bit 7, `MPIE`, is consulted: it is the
 *                                   `MIE` the interrupted code had)
 *      568       handler_mie        `MSTATUS_MIE` or 0: what the trap vector
 *                                   sets in `mstatus` just before it enters
 *                                   the bound handler
 *      576       flags              TRAP_FLAG_* (trap.hpp): fault delivery
 *      584       fault_status       for a fault frame, the `Status` whoever
 *                                   is beneath gets if it is unwound
 *      592       handler_comp       the handler's compartment handle (null if
 *                                   no handler was entered)
 *      608       handler_ca0        the handler's `ca0`: the integer `mcause`
 *                                   for an interrupt, the ErrorState for a
 *                                   fault (fault.hpp)
 *      624       handler_a3         the handler's `a3` (`mtval2`)
 *      632       (reserved)
 *
 * 2. `ReturnFrame` (416 bytes = 26 capability slots, `switcher.hpp`):
 *    Saves the caller's callee-saved state across a synchronous
 *    `sys_compartment_invoke` call on the same thread:
 *
 *      Offset    Field              Register(s)
 *      ------    -----              -----------
 *        0       ra                 caller cra
 *       16       sp                 caller csp (full un-narrowed bounds)
 *       32       gp                 caller cgp (caller capability table)
 *       48       prev_ksp           FRAME LINK: kernel SP above this frame
 *       64..240  s[0..11]           caller cs0..cs11
 *      256       tp                 caller ctp
 *      272..336  args[0..4]         caller ca1..ca5 = callee ca0..ca4; args[0]
 *                                   is reused for the caller's ca0 on return
 *      352       callee_sp          narrowed stack capability for callee
 *      368       callee_gp          capability table for callee
 *      384       mstatus            integer `mstatus` of the caller at entry
 *                                   (only bit 3, `MIE`, is consulted)
 *      392       flags              `EntryRecord::flags` of the callee
 *      400       callee_comp        the callee's compartment handle (null for
 *                                   a kernel entry)
 *
 *    `callee_comp` and `handler_comp` are how the trap dispatcher tells which
 *    compartment faulted: the frame directly under a fault's `TrapFrame`
 *    entered the code that was running (trap.hpp, WHO FAULTED).
 *
 * FRAME LINK
 * ----------
 * Offset 48 of every frame on a kernel stack holds the kernel SP from just
 * above it: a capability with the kernel stack's own bounds and address
 * `frame + size`. Every push sequence writes it (`sys_compartment_invoke`,
 * `sys_thread_switch`, the trap vector, `thread::create`), and no compartment
 * can hold a capability with those bounds, so it is what identifies a frame
 * and its kind (`unwind::kind_at`): the address says how big the frame is.
 * Popping a frame is setting `mscratchc` to it.
 *
 * INTERRUPT MASKING RULE
 * ----------------------
 * Everything runs in M-mode and nothing is delegated, so `mstatus.MIE` masks
 * every interrupt. Kernel code (C++ and these transitions) always runs with
 * `mstatus.MIE = 0`. Every entry into the kernel from user code
 * (`sys_compartment_invoke`, the switcher's return path `.Lcomp_restore`,
 * the trap vector) masks as its first instruction; `MIE` is set again only
 * on the way back out to user code, and only to the value the interrupted or
 * calling user context had: `1` for ordinary thread code, `0` inside the
 * dynamic extent of an interrupt handler (which must stay masked until its
 * own `mret`), never for the boot/host context. The switcher saves that
 * value in its `ReturnFrame` and restores it when the call returns, whether
 * the callee was a compartment or the kernel and whether or not the thread
 * was switched out in between. A compartment callee runs with the caller's
 * `MIE`; a kernel entry runs masked. A brand-new thread is unmasked by
 * `__thread_start`.
 *
 * Trap handlers. An interrupt handler always runs masked. An exception
 * handler runs with the `MIE` of the code that raised the exception, the way
 * a callee runs with its caller's: over ordinary thread code it runs
 * unmasked, so an interrupt that arrives meanwhile is handled on top of it
 * and returns into it. Except: if the kernel stack has no room for that
 * interrupt (KERNEL-STACK ROOM, check 3), it runs masked. The dispatcher
 * records the interrupted `mstatus` in the `TrapFrame` and decides
 * `handler_mie`; the trap vector sets `MIE` from `handler_mie` just before
 * it enters the handler; and the trap's final `mret` gives the interrupted
 * code back the `MIE` it had (the recorded `MPIE`), whatever trapped or
 * switched threads in between.
 */

#define FRAME_SP                16
#define FRAME_LINK              48
/* Where `ctp` is saved: SwitchFrame / TrapFrame, and ReturnFrame. */
#define FRAME_TP                496
#define RET_FRAME_TP            256

#define SWITCH_FRAME_SIZE       512

#define TRAP_FRAME_MEPCC        512
#define TRAP_FRAME_HANDLER_SP   528
#define TRAP_FRAME_RW_TABLE     544
#define TRAP_FRAME_MSTATUS      560
#define TRAP_FRAME_HANDLER_MIE  568
#define TRAP_FRAME_FLAGS        576
#define TRAP_FRAME_FAULT_STATUS 584
#define TRAP_FRAME_HANDLER_COMP 592
#define TRAP_FRAME_HANDLER_CA0  608
#define TRAP_FRAME_HANDLER_A3   624
#define TRAP_FRAME_SIZE         640

#define RET_FRAME_ARG0          272
#define RET_FRAME_ARG1          288
#define RET_FRAME_ARG2          304
#define RET_FRAME_ARG3          320
#define RET_FRAME_ARG4          336
#define RET_FRAME_CALLEE_SP     352
#define RET_FRAME_CALLEE_GP     368
#define RET_FRAME_MSTATUS       384
#define RET_FRAME_FLAGS         392
#define RET_FRAME_CALLEE_COMP   400
#define RET_FRAME_SIZE          416

/*
 * KERNEL-STACK ROOM
 * -----------------
 * Three checks, one constant. Together they keep this true: wherever a trap
 * can be taken, the kernel stack has room for its `TrapFrame` and for
 * dispatching it -- to a handler, to ending the thread, or to a halt. The
 * trap vector itself checks nothing (it has no free register before it
 * stores), so this is what keeps it from overflowing the kernel stack.
 *
 *   1. `sys_compartment_invoke` pushes a `ReturnFrame` only if at least
 *      RET_FRAME_MIN_FREE bytes are free. That covers the frame (416) plus
 *      the most its callee puts on the kernel stack: `_prepare` (160, plus
 *      `sentry::resolve` 128, at -O2), or for `sys_thread_switch` the
 *      `SwitchFrame` (512) and `__signetos_thread_dispatch` (leaf); or, for
 *      a fault inside the callee (compartment code, or a kernel bug), one
 *      `TrapFrame` (640) plus the trap dispatcher's deepest path
 *      (`__signetos_trap_dispatch` with `dispatch_fault` inlined, 448, +
 *      `fault_report`/`trap_report` 144 + the console helpers, 64 = 656), so
 *      the fault is delivered or reported instead of overflowing. 416 + 640
 *      + 656 = 1712, rounded up.
 *   2. `__signetos_switcher_prepare` enters a compartment callee that will
 *      run with interrupts enabled (its caller's `MIE` was set) only if,
 *      below the `ReturnFrame`, TRAP_FRAME_SIZE + RET_FRAME_MIN_FREE bytes
 *      are free: such code can be ticked at any instruction, and the trap
 *      taken there must satisfy check 3. A callee that runs masked (called
 *      from an interrupt handler) cannot be ticked, and a fault in it fits
 *      in what check 1 left (640 + 656 < 1728 - 416), so it needs nothing
 *      more.
 *   3. `__signetos_trap_dispatch` enters a handler -- a bound interrupt
 *      handler or the faulting compartment's fault handler (fault.hpp) --
 *      only if at least RET_FRAME_MIN_FREE bytes are free below the
 *      `TrapFrame`: enough for the handler's one kernel call (the tick
 *      handler's `sys_thread_switch` goes through check 1), and enough to
 *      dispatch a fault inside the handler (640 + 656). A fault handler
 *      that would run unmasked (INTERRUPT MASKING RULE) can be ticked at
 *      its first instruction, so, as in check 2, it runs unmasked only if
 *      TRAP_FRAME_SIZE + RET_FRAME_MIN_FREE bytes are free; with less it
 *      runs masked. A fault inside a handler is never delivered again: it
 *      unwinds (fault.hpp), so a faulting handler costs one more
 *      `TrapFrame` at most. A fault with less than RET_FRAME_MIN_FREE free
 *      below its `TrapFrame` is reported and unwound, not delivered.
 *
 * On a 8048-byte thread kernel stack (two pages, `THREAD_STATE_PAGES`, less
 * the 144-byte `ThreadState`) this allows a thread thirteen nested
 * compartment calls with interrupts enabled (each 416 bytes; check 2 refuses
 * the fourteenth at 2224 free), kernel calls on top of them down to check 1,
 * and, inside a handler, further compartment calls down to check 1 (the
 * console's keystroke chain and the disk's completion chain each nest two:
 * handler -> uart RX / blk IRQ entry -> sched.wake). Handler frames live on
 * the interrupted thread's kernel stack, so how deep a handler chain can nest
 * depends on how deep that thread was: a two-call chain fits over a thread
 * at compartment depth 12 (3056 free before the `TrapFrame`) but not depth
 * 13 (its second call is refused at 1584 free), and a fault handler runs
 * unmasked over a thread at compartment depth 0 to 12 but masked at 13 (2000
 * free below the `TrapFrame`, short of 640 + 1728). With one page (3792
 * bytes) the numbers were four nested calls, the chain over depth 3 but not
 * 4, unmasked over depth 0 to 2 -- and a program the shell runs on its own
 * thread sits at depth 4 when it waits for the disk (shell -> program -> fs
 * -> blk -> sched.block), so its wake was refused and lost; that is why there
 * are two pages. Measured high-water of a thread's kernel stack, before the
 * `TrapFrame` grew from 576 to 640 bytes and the `ReturnFrame` from 400 to
 * 416 (add the difference for the frames on each path): 1888 bytes under the
 * test image, 2416 under the production demo (tick handler preempting a
 * thread that was itself inside the switcher). The test image goes deeper on
 * purpose: `PREEMPT.11c` traps thirteen compartment calls deep, about 6500
 * bytes by the frame sizes above. Frame sizes are from `llvm-objdump` of the
 * -O2 kernel; re-measure if the trap path or these helpers grow.
 */
#define RET_FRAME_MIN_FREE      1728

/* `sentry::ENTRY_FLAG_TRUSTED` (sentry.hpp), as tested on `RET_FRAME_FLAGS`. */
#define ENTRY_TRUSTED           1

/* `Status::NoKernelStack` (types.hpp): the switcher's refusal when the thread's
 * kernel stack has no room for a frame, returned to the caller in a0. */
#define STATUS_NO_KERNEL_STACK  40

/* `unwind::Kind` (unwind.hpp): what `__signetos_switcher_return` and
 * `__signetos_trap_return` hand back in a0 -- the kind of the frame the
 * kernel has unwound to, which decides whether the exit is `ret` from a
 * `ReturnFrame` or `mret` from a `TrapFrame`. 0 means nothing to resume. */
#define UNWIND_NONE             0
#define UNWIND_RETURN_FRAME     1
#define UNWIND_TRAP_FRAME       2

/* `mstatus` bits. MPP is a two-bit field; both bits set is M-mode. */
#define MSTATUS_MIE             0x8
#define MSTATUS_MPIE            0x80
#define MSTATUS_MPP             0x1800
