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
 * The kernel stack holds frames only: the `TrapFrame`s of traps taken in the
 * thread and the one it is parked in while it does not run (thread.hpp,
 * PARKED THREADS), and one `ReturnFrame` per call that is in progress
 * through the switcher. Kernel C++ that runs on behalf of a call
 * (a system call body) runs on the caller's own stack, narrowed, exactly like
 * a compartment callee does; only the switcher's own helpers and the trap
 * dispatcher run on the kernel stack, directly below the frame they manage.
 *
 * KERNEL STACK FRAME LAYOUTS
 * --------------------------
 * Every frame keeps its FRAME LINK at offset 48 (below). The rest of the
 * layouts follow.
 *
 * 1. `TrapFrame` (640 bytes = 37 capabilities + 6 integers, `trap.hpp`):
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
 *      512       mepcc              where `mret` resumes it
 *      528       handler_sp         the handler's stack (null: no handler)
 *      544       handler_rw_table   handler compartment cap table (`cgp`)
 *      560       mstatus            integer `mstatus` (only bit 7, `MPIE`,
 *                                   is consulted: the `MIE` the frame
 *                                   resumes with)
 *      568       handler_mie        `MSTATUS_MIE` or 0: what the trap vector
 *                                   sets in `mstatus` just before it enters
 *                                   the handler
 *      576       flags              TRAP_FLAG_* (trap.hpp)
 *      584       fault_status       for a fault frame, the `Status` whoever
 *                                   is beneath gets if it is unwound
 *      592       handler_comp       the handler's compartment handle (null if
 *                                   no handler was entered)
 *      608       handler_ca0        the fault handler's `ca0`: its
 *                                   ErrorState (fault.hpp)
 *      624       handler_a3         the fault handler's `a3`: `mtval2`
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
 * `sys_thread_switch`, the trap vector, `thread::create`), and no
 * compartment can hold a capability with those bounds, so it is what
 * identifies a frame and its kind (`unwind::kind_at`): the address says how
 * big the frame is. Popping a frame is setting `mscratchc` to it.
 *
 * INTERRUPT MASKING RULE
 * ----------------------
 * Everything runs in M-mode and nothing is delegated, so `mstatus.MIE` masks
 * every interrupt. Kernel code (C++ and these transitions) always runs with
 * `mstatus.MIE = 0`. Every entry into the kernel from user code
 * (`sys_compartment_invoke`, the switcher's return path `.Lcomp_restore`,
 * the trap vector) masks as its first instruction; `MIE` is set again only
 * on the way back out to user code, and only to the value the interrupted or
 * calling user context had: `1` for ordinary thread code, `0` in the
 * interrupt handler thread (masked from its first instruction, thread.hpp),
 * never for the boot/host context. The switcher saves that value in its
 * `ReturnFrame` and restores it when the call returns, whether the callee
 * was a compartment or the kernel and whether or not the thread was switched
 * out in between. A compartment callee runs with the caller's `MIE`; a
 * kernel entry runs masked. A brand-new thread is unmasked by
 * `__thread_start`, unless it is an interrupt handler. A parked thread
 * resumes with the `MIE` its `TrapFrame` records: the interrupted code's, or
 * 0 for one parked by `sys_thread_switch` or `sys_trap_wait`, whose own way
 * out restores its caller's.
 *
 * A fault handler runs with the `MIE` of the code that raised the fault, the
 * way a callee runs with its caller's: over ordinary thread code it runs
 * unmasked, and an interrupt that arrives meanwhile parks it like any other
 * code. The dispatcher records the faulting `mstatus` in the `TrapFrame` and
 * sets `handler_mie`; the trap vector sets `MIE` from `handler_mie` just
 * before it enters the handler; and the trap's final `mret` gives the
 * faulting code back the `MIE` it had (the recorded `MPIE`), whatever trapped
 * or switched threads in between.
 */

#define FRAME_SP                16
#define FRAME_LINK              48
/* Where `ctp` is saved: TrapFrame, and ReturnFrame. */
#define FRAME_TP                496
#define RET_FRAME_TP            256

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
 * Two checks, one constant. Together they keep this true: wherever a trap
 * can be taken, the kernel stack has room for its `TrapFrame` and for
 * dispatching it -- to the interrupt handler's thread, to a fault handler,
 * or to unwinding. The trap vector itself checks nothing (it has no free
 * register before it stores), so this is what keeps it from overflowing the
 * kernel stack. No interrupt handler runs on the interrupted thread (trap.hpp),
 * so an interrupt costs that thread its `TrapFrame` and the dispatcher, up
 * to where the handler is resumed on its own kernel stack
 * (`__thread_resume_on`).
 *
 *   1. `sys_compartment_invoke` pushes a `ReturnFrame` only if at least
 *      RET_FRAME_MIN_FREE bytes are free. That covers the frame (416) plus
 *      the most its callee puts on the kernel stack: `_prepare` (128, plus
 *      `sentry::resolve` 128); for `sys_thread_switch` the `TrapFrame` it
 *      parks its caller in (640) and `__signetos_thread_dispatch` with the
 *      resume path under it (432; `sys_trap_wait`'s is the same frame and
 *      400); or a trap in the callee -- an interrupt anywhere in compartment
 *      code, or a fault (compartment code, or a kernel bug) -- one
 *      `TrapFrame` (640) plus the trap dispatcher's deepest path
 *      (`__signetos_trap_dispatch` 272 + `debug::fault_report` 112 +
 *      `uart::print_dec` 48 = 432; waking the handler is 272 + 16), so the
 *      trap is dispatched instead of overflowing. 416 + 640 + 432 = 1488,
 *      with room to spare.
 *   2. `__signetos_trap_dispatch` enters a fault handler (fault.hpp) only if
 *      at least RET_FRAME_MIN_FREE bytes are free below the fault's
 *      `TrapFrame`: enough for the handler's kernel calls (check 1), and for
 *      a trap inside the handler (640 + 432). A fault inside a fault handler
 *      is never delivered again: it unwinds (fault.hpp), so a faulting
 *      handler costs one more `TrapFrame` at most. A fault with less than
 *      RET_FRAME_MIN_FREE free below its `TrapFrame` is reported and unwound,
 *      not delivered.
 *
 * On a 8048-byte thread kernel stack (two pages, `THREAD_STATE_PAGES`, less
 * the 144-byte `ThreadState`) this allows a thread sixteen nested
 * compartment calls (each 416 bytes; check 1 refuses the seventeenth at 1392
 * free), and kernel calls on top of them down to check 1. Frame sizes are
 * from `llvm-objdump` of the -O2 kernel; re-measure if the trap path or these
 * helpers grow.
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
