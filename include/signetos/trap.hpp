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

//
// trap.hpp - SignetOS trap dispatch: delivering interrupts and faults
//
// Two interrupts leave the kernel, each to the one handler `init` installed
// for it (irq.hpp, which also keeps every hart's `mie` and timer in line).
// Synchronous exceptions have no handler there: a fault is handled by the
// compartment that raised it, through the fault handler it installed in its
// own descriptor (fault.hpp, PER-COMPARTMENT FAULTS below).
//
// Everything runs in M-mode and nothing is delegated, so every trap is taken
// in M-mode, by the kernel. When an installed interrupt fires, or compartment
// code faults:
//   1. `_early_trap_entry` saves all 31 capability registers (`cra`, `csp`,
//      `cgp`, `ctp`, `ct0`..`ct6`, `cs0`..`cs11`, `ca0`..`ca7`), `mepcc`, and
//      the hart's `mscratchc` kernel SP into a 640-byte `TrapFrame` on the
//      active kernel stack.
//   2. `__signetos_trap_dispatch` picks the handler -- the interrupt's
//      installed `OType::EntryPoint`, or the faulting compartment's fault
//      handler --
//      as a `CT = 1` hardware sentry. The handler runs below the interrupted
//      `csp`, narrowed by the same stack rule as a callee's
//      (`switcher::narrow_stack`: permissions including StoreLocal, the
//      handler's `min_stack` free, exactly representable, never the kernel
//      stack), and makes its kernel calls on the interrupted kernel stack,
//      which must have `RET_FRAME_MIN_FREE` below the `TrapFrame`. An
//      interrupted thread that fails either cannot be preempted and is ended
//      there (`trap.cpp`, `end_interrupted_thread`); a fault that fails
//      either is reported and unwound instead of delivered.
//   3. The handler sentry is invoked with `(ca0, mtval, mepc, mtval2,
//      cap_table)` in `(ca0, a1, a2, a3, ca4)` (with `cgp = ca4`) and all
//      other registers scrubbed to `cnull`. For an interrupt `ca0` is the
//      integer `mcause`; for a fault it is the compartment's ErrorState
//      (fault.hpp), at the top of the handler's stack.
//   4. Because `mscratchc` points to the `TrapFrame` while the handler runs,
//      the handler may freely invoke syscalls or call `sys_thread_switch` to
//      preempt the interrupted thread. An interrupt handler runs with
//      interrupts masked. A fault handler runs with the interrupted code's
//      `MIE`, so over thread code an interrupt can be handled on top of it
//      and return into it (asm_macros.h, INTERRUPT MASKING RULE).
//   5. When the handler returns, the kernel scrubs the handler's narrowed
//      stack and pops the `TrapFrame` (`__signetos_trap_return` =
//      `unwind::resume`). An interrupted context is always resumed; a
//      faulting one only on the handler's INSTALL_CONTEXT verdict, with the
//      register file it left in the ErrorState, and otherwise unwound: the
//      frame beneath gets `Status::Faulted` in a0. `_early_trap_entry` then
//      restores `mepcc` and all 31 capability registers of whatever frame it
//      stopped at and executes `mret` (or returns through the switcher).
//
// PER-COMPARTMENT FAULTS
// ----------------------
// The faulting compartment is named by the frame directly beneath the
// fault's `TrapFrame`, never by anything the compartment controls (its
// `cgp`, its table): a `ReturnFrame`'s `callee_comp` (the canonical handle
// the switcher recorded from the entry record), a `TrapFrame`'s
// `handler_comp` (if that frame is itself a fault frame, the fault was in a
// fault handler: never delivered again, it unwinds), or, at the bottom of a
// thread, the owner of the thread's entry sentry. `compartment::open` then
// checks that compartment is still live.
//
// A synchronous fault raised by kernel code (`mepcc` with AccessSystemRegs)
// is never delivered to a handler: it is a kernel bug and halts the machine.
//

#include <stddef.h>
#include <stdint.h>
#include <signetos/types.hpp>

namespace signetos::trap {

constexpr uint64_t INTERRUPT_BIT = (1ULL << 63);

// Standard RISC-V synchronous exception codes (mcause with bit 63 == 0).
// Everything runs in M-mode, so an `ecall` is always EXC_ECALL_M.
constexpr uint64_t EXC_INST_MISALIGNED  = 0;
constexpr uint64_t EXC_INST_ACCESS      = 1;
constexpr uint64_t EXC_ILLEGAL_INST     = 2;
constexpr uint64_t EXC_BREAKPOINT       = 3;
constexpr uint64_t EXC_LOAD_MISALIGNED  = 4;
constexpr uint64_t EXC_LOAD_ACCESS      = 5;
constexpr uint64_t EXC_STORE_MISALIGNED = 6;
constexpr uint64_t EXC_STORE_ACCESS     = 7;
constexpr uint64_t EXC_ECALL_U          = 8;
constexpr uint64_t EXC_ECALL_S          = 9;
constexpr uint64_t EXC_ECALL_M          = 11;
constexpr uint64_t EXC_INST_PAGE_FAULT  = 12;
constexpr uint64_t EXC_LOAD_PAGE_FAULT  = 13;
constexpr uint64_t EXC_STORE_PAGE_FAULT = 15;
constexpr uint64_t EXC_CHERI            = 28;

// Standard RISC-V M-mode interrupt causes (mcause with bit 63 == 1).
constexpr uint64_t IRQ_M_SOFT  = INTERRUPT_BIT | 3;
constexpr uint64_t IRQ_M_TIMER = INTERRUPT_BIT | 7;
constexpr uint64_t IRQ_M_EXT   = INTERRUPT_BIT | 11;

// Not a hardware cause: what the IRQ_M_TIMER handler gets as its cause when
// the running thread waits for a page (vm.hpp, PAGING, FAULTS). It is to
// block that thread and wake the pager, whose tid it gets in a3 (0: none);
// the pager wakes it once the page is in.
constexpr uint64_t PAGE_WAIT = INTERRUPT_BIT | 0x100;

using Status = signetos::Status;
using signetos::status_name;

// `TrapFrame::flags`.
//
// TRAP_FLAG_FAULT marks a frame pushed for a fault in compartment code
// (fault.hpp): whether a handler was delivered on it or not, it is resumed
// only on its handler's INSTALL_CONTEXT verdict, and otherwise skipped, the
// frame beneath getting `fault_status`. A fault taken while the frame
// beneath is such a frame is a fault in a fault handler, and is never
// delivered.
constexpr uint64_t TRAP_FLAG_FAULT = 1u << 4;

// Saved context pushed onto the active kernel stack by `_early_trap_entry`
// before dispatching a trap or interrupt.
struct alignas(16) TrapFrame {
  Capability ra;                //   0
  Capability sp;                //  16
  Capability gp;                //  32
  Capability active_kernel_sp;  //  48 FRAME LINK (asm_macros.h), written
                                //     by the trap vector at push
  Capability t[7];              //  64..160
  Capability s[12];             // 176..352
  Capability a[8];              // 368..480
  Capability tp;                // 496
  Capability mepcc;             // 512
  Capability handler_sp;        // 528 (populated by __signetos_trap_dispatch)
  Capability handler_rw_table;  // 544 (populated by __signetos_trap_dispatch)
  // Both populated by __signetos_trap_dispatch for a handler it delivers
  // (asm_macros.h, INTERRUPT MASKING RULE):
  uint64_t mstatus;             // 560 `mstatus` at entry; its MPIE is the
                                //     interrupted code's MIE
  uint64_t handler_mie;         // 568 MSTATUS_MIE if the handler runs with
                                //     interrupts enabled, else 0
  uint64_t flags;               // 576 TRAP_FLAG_* above
  uint64_t fault_status;        // 584 a fault frame: the `Status` the frame
                                //     beneath gets if this one is skipped
                                //     (Faulted, or CompartmentDestroyed)
  Capability handler_comp;      // 592 the delivered handler's compartment
                                //     handle; null if none was delivered
                                //     (WHO FAULTED)
  // The handler's ca0 and a3, written by __signetos_trap_dispatch (a1 and a2
  // are always mtval and mepc, read from the CSRs): for an interrupt the
  // integer `mcause` and `mtval2`; for a fault its ErrorState (fault.hpp) and
  // `mtval2`.
  Capability handler_ca0;       // 608
  uint64_t handler_a3;          // 624
  uint64_t reserved_;           // 632 (keeps the frame a capability multiple)
};

static_assert(sizeof(TrapFrame) == 40 * sizeof(Capability),
              "TrapFrame must be 37 capabilities and six integers (640 "
              "bytes)");

// The fault handler delivered on fault frame `frame` returned INSTALL_CONTEXT
// (fault.hpp): loads `frame`'s registers from the ErrorState the handler
// left, and its `mepcc` from the faulting PCC re-addressed to the
// ErrorState's `pc`. False, with `frame` untouched, if there is no
// ErrorState or the new `mepcc` is not a valid capability; the frame is then
// unwound as for any other verdict (unwind.cpp).
bool install_context(TrapFrame* frame);

}  // namespace signetos::trap
