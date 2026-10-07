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
 * PER-HART KERNEL STACK POINTER (`sscratchc`)
 * -------------------------------------------
 * Each hart stores its active thread's kernel stack pointer in its `sscratchc`
 * capability CSR (the boot kernel stack when running in host context with no
 * active user thread). Because `sscratchc` is a supervisor CSR, compartments
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
 * 1. `SwitchFrame` (512 bytes = 32 capabilities, `thread.hpp`) and
 *    `TrapFrame`   (576 bytes = 35 capabilities + 2 integers, `trap.hpp`)
 *    share the same layout for offsets 0..496:
 *
 *      Offset    Field              Register(s)
 *      ------    -----              -----------
 *        0       ra                 cra
 *       16       sp                 csp
 *       32       gp                 cgp
 *       48       tp                 ctp
 *       64..160  t[0..6]            ct0..ct6
 *      176..352  s[0..11]           cs0..cs11
 *      368..480  a[0..7]            ca0..ca7
 *      496       active_kernel_sp   per-hart `sscratchc` kernel SP
 *
 *    `TrapFrame` appends three trap-specific capability slots, then two
 *    integers that share one more 16-byte slot:
 *      512       sepcc              interrupted PC capability
 *      528       handler_sp         narrowed stack for bound trap handler
 *      544       handler_rw_table   handler compartment cap table (`cgp`)
 *      560       sstatus            integer `sstatus` at trap entry (only
 *                                   bit 5, `SPIE`, is consulted: it is the
 *                                   `SIE` the interrupted code had)
 *      568       handler_sie        `SSTATUS_SIE` or 0: what the trap vector
 *                                   sets in `sstatus` just before it enters
 *                                   the bound handler
 *
 * 2. `ReturnFrame` (400 bytes = 25 capability slots, `sentry.hpp`):
 *    Saves the caller's callee-saved state across a synchronous
 *    `sys_compartment_invoke` call on the same thread:
 *
 *      Offset    Field              Register(s)
 *      ------    -----              -----------
 *        0       ra                 caller cra
 *       16       sp                 caller csp (full un-narrowed bounds)
 *       32       gp                 caller cgp (caller capability table)
 *       48       tp                 caller ctp
 *       64..240  s[0..11]           caller cs0..cs11
 *      256       prev_ksp           previous `sscratchc` kernel SP
 *      272..336  args[0..4]         caller ca1..ca5 = callee ca0..ca4; args[0]
 *                                   is reused for the caller's ca0 on return
 *      352       callee_sp          narrowed stack capability for callee
 *      368       callee_gp          capability table for callee
 *      384       sstatus            integer `sstatus` of the caller at entry
 *                                   (only bit 1, `SIE`, is consulted)
 *      392       flags              `EntryRecord::flags` of the callee
 *
 * INTERRUPT MASKING RULE
 * ----------------------
 * Kernel code (C++ and these transitions) always runs with `sstatus.SIE = 0`.
 * Every entry into the kernel from user code (`sys_compartment_invoke`, the
 * switcher's return path `.Lcomp_restore`, the trap vector) masks as its
 * first instruction; `SIE` is set again only on the way back out to user
 * code, and only to the value the interrupted or calling user context had:
 * `1` for ordinary thread code, `0` inside the dynamic extent of an interrupt
 * handler (which must stay masked until its own `sret`), never for the
 * boot/host context. The switcher saves that value in its `ReturnFrame` and
 * restores it when the call returns, whether the callee was a compartment or
 * the kernel and whether or not the thread was switched out in between. A
 * compartment callee runs with the caller's `SIE`; a kernel entry runs
 * masked. A brand-new thread is unmasked by `__thread_start`.
 *
 * Trap handlers. An interrupt handler always runs masked. An exception
 * handler runs with the `SIE` of the code that raised the exception, the way
 * a callee runs with its caller's: over ordinary thread code it runs
 * unmasked, so an interrupt that arrives meanwhile is handled on top of it
 * and returns into it. Except: if the kernel stack has no room for that
 * interrupt (KERNEL-STACK ROOM, check 3), it runs masked. The dispatcher
 * records the interrupted `sstatus` in the `TrapFrame` and decides
 * `handler_sie`; the trap vector sets `SIE` from `handler_sie` just before
 * it enters the handler; and the trap's final `sret` gives the interrupted
 * code back the `SIE` it had (the recorded `SPIE`), whatever trapped or
 * switched threads in between.
 */

#define FRAME_SP                16

#define SWITCH_FRAME_SIZE       512

#define TRAP_FRAME_SEPCC        512
#define TRAP_FRAME_HANDLER_SP   528
#define TRAP_FRAME_RW_TABLE     544
#define TRAP_FRAME_SSTATUS      560
#define TRAP_FRAME_HANDLER_SIE  568
#define TRAP_FRAME_SIZE         576

#define RET_FRAME_PREV_KSP      256
#define RET_FRAME_ARG0          272
#define RET_FRAME_ARG1          288
#define RET_FRAME_ARG2          304
#define RET_FRAME_ARG3          320
#define RET_FRAME_ARG4          336
#define RET_FRAME_CALLEE_SP     352
#define RET_FRAME_CALLEE_GP     368
#define RET_FRAME_SSTATUS       384
#define RET_FRAME_FLAGS         392
#define RET_FRAME_SIZE          400

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
 *      RET_FRAME_MIN_FREE bytes are free. That covers the frame (400) plus
 *      the most its callee puts on the kernel stack: `_prepare` (144, plus
 *      `sentry::resolve` 112, at -O2), or for `sys_thread_switch` the
 *      `SwitchFrame` (512) and `__signetos_thread_dispatch` (leaf); or, for
 *      a kernel bug that faults inside a kernel callee, one `TrapFrame`
 *      (592) plus the trap dispatcher's deepest path (368 + `trap_report`
 *      144 + its `field` 48 = 560; ending a thread is 368 + 128 = 496), so
 *      the report comes out instead of a second overflow. 400 + 592 + 560 =
 *      1552, rounded up.
 *   2. `__signetos_switcher_prepare` enters a compartment callee that will
 *      run with interrupts enabled (its caller's `SIE` was set) only if,
 *      below the `ReturnFrame`, TRAP_FRAME_SIZE + RET_FRAME_MIN_FREE bytes
 *      are free: such code can be ticked at any instruction, and the trap
 *      taken there must satisfy check 3. A callee that runs masked (called
 *      from an interrupt handler) cannot be ticked, and a fault in it fits
 *      in what check 1 left (592 + 560 < 1200), so it needs nothing more.
 *   3. `__signetos_trap_dispatch` enters a bound handler only if at least
 *      RET_FRAME_MIN_FREE bytes are free below the `TrapFrame`: enough for
 *      the handler's one kernel call (the tick handler's `sys_thread_switch`
 *      goes through check 1), and enough to dispatch a fault inside the
 *      handler (592 + 560) and end the thread if check 3 then fails. An
 *      exception handler that would run unmasked (INTERRUPT MASKING RULE)
 *      can be ticked at its first instruction, so, as in check 2, it runs
 *      unmasked only if TRAP_FRAME_SIZE + RET_FRAME_MIN_FREE bytes are free;
 *      with less it runs masked. A fault inside a handler is dispatched to
 *      the handler again while check 3 passes (a thread interrupted at
 *      depth 0 has room for three such levels), so a handler that keeps
 *      faulting ends its thread within a few levels rather than running the
 *      kernel stack down.
 *
 * On a 7728-byte thread kernel stack (two pages, `THREAD_STATE_PAGES`, less
 * the 464-byte `ThreadState`) this allows a thread thirteen nested
 * compartment calls with interrupts enabled (each 400 bytes; check 2 refuses
 * the fourteenth at 2128 free), kernel calls on top of them down to check 1,
 * and, inside a handler, further compartment calls down to check 1 (the
 * console's keystroke chain and the disk's completion chain each nest two:
 * handler -> uart RX / blk IRQ entry -> sched.wake). Handler frames live on
 * the interrupted thread's kernel stack, so how deep a handler chain can nest
 * depends on how deep that thread was: a two-call chain fits over a thread
 * at compartment depth 12 (2928 free before the `TrapFrame`) but not depth
 * 13 (its second call is refused at 1536 free), and an exception handler
 * runs unmasked over a thread at compartment depth 0 to 12 but masked at 13.
 * With one page (3792 bytes) the numbers were four nested calls, the chain
 * over depth 3 but not 4, unmasked over depth 0 to 2 -- and a program the
 * shell runs on its own thread sits at depth 4 when it waits for the disk
 * (shell -> program -> fs -> blk -> sched.block), so its wake was refused
 * and lost; that is why there are two pages. Measured high-water of a
 * thread's kernel stack, before the `TrapFrame` grew from 576 to 592 bytes
 * (add 16 for the one on each path): 1888 bytes under the test image, 2416
 * under the production demo (tick handler preempting a thread that was
 * itself inside the switcher). The test image goes deeper on purpose:
 * `PREEMPT.11c` traps thirteen compartment calls deep, about 6270 bytes by
 * the frame sizes above. Re-measure if the trap path or these helpers grow.
 */
#define RET_FRAME_MIN_FREE      1600

/* `sentry::ENTRY_FLAG_TRUSTED` (sentry.hpp), as tested on `RET_FRAME_FLAGS`. */
#define ENTRY_TRUSTED           1

/* `Status::NoKernelStack` (types.hpp): the switcher's refusal when the thread's
 * kernel stack has no room for a frame, returned to the caller in a0. */
#define STATUS_NO_KERNEL_STACK  40

/* `sstatus` bits. */
#define SSTATUS_SIE             2
#define SSTATUS_SPIE            0x20
#define SSTATUS_SPP             0x100
