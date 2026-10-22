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
 * trap.cpp - SignetOS trap dispatch: the two interrupt handlers and faults
 *
 * Called from _early_trap_entry (early_trap.S) when a synchronous exception or
 * asynchronous interrupt reaches the machine trap vector. Everything runs in
 * M-mode and nothing is delegated, so that is every trap there is.
 *
 * A synchronous fault raised by kernel code (`mepcc` carries AccessSystemRegs)
 * is a kernel bug: `debug::trap_report()` prints it and halts.
 *
 * A fault in compartment code goes to that compartment's fault handler
 * (fault.hpp, `dispatch_fault`). The tick and the external interrupt go to
 * the handlers `init` installed (irq.hpp, INTERRUPT HANDLERS):
 * `__signetos_trap_dispatch` resolves the handler and `_early_trap_entry`
 * invokes it with the interrupted context saved in a `TrapFrame` on the
 * active kernel stack -- provided the
 * interrupted context can take a trap at all: its kernel stack must have the
 * room of asm_macros.h (KERNEL-STACK ROOM, check 3) and its `csp` must pass
 * the stack rule every callee's stack passes (`switcher::narrow_stack`), since
 * the handler runs below it. A thread that fails either cannot be preempted
 * and is ended on the spot (`end_interrupted_thread`); in host context the
 * machine halts.
 *
 * An interrupt with no handler that resolves is silenced at its source on
 * this hart (`irq::silence`) and returned from.
 *
 * Who each interrupt goes to, the tick, and keeping every hart's `mie` and
 * timer in line are irq.cpp's. This file decides which `MIE` a handler runs
 * with and which the interrupted context resumes with (see asm_macros.h,
 * INTERRUPT MASKING RULE).
 */

#include <signetos/asm_macros.h>
#include <signetos/compartment.hpp>
#include <signetos/debug/report.hpp>
#include <signetos/fault.hpp>
#include <signetos/irq.hpp>
#include <signetos/debug/inspect.hpp>
#include <signetos/sealing.hpp>
#include <signetos/sentry.hpp>
#include <signetos/switcher.hpp>
#include <signetos/thread.hpp>
#include <signetos/trap.hpp>
#include <signetos/unwind.hpp>
#include <signetos/vm.hpp>
#include <stddef.h>
#include <stdint.h>

using namespace signetos;

namespace {

// `_early_trap_entry` addresses the frame by these offsets.
static_assert(offsetof(trap::TrapFrame, mepcc) == TRAP_FRAME_MEPCC);
static_assert(offsetof(trap::TrapFrame, handler_sp) == TRAP_FRAME_HANDLER_SP);
static_assert(offsetof(trap::TrapFrame, handler_rw_table) ==
              TRAP_FRAME_RW_TABLE);
static_assert(offsetof(trap::TrapFrame, mstatus) == TRAP_FRAME_MSTATUS);
static_assert(offsetof(trap::TrapFrame, handler_mie) ==
              TRAP_FRAME_HANDLER_MIE);
static_assert(offsetof(trap::TrapFrame, flags) == TRAP_FRAME_FLAGS);
static_assert(offsetof(trap::TrapFrame, fault_status) ==
              TRAP_FRAME_FAULT_STATUS);
static_assert(offsetof(trap::TrapFrame, handler_comp) ==
              TRAP_FRAME_HANDLER_COMP);
static_assert(offsetof(trap::TrapFrame, handler_ca0) ==
              TRAP_FRAME_HANDLER_CA0);
static_assert(offsetof(trap::TrapFrame, handler_a3) == TRAP_FRAME_HANDLER_A3);
static_assert(sizeof(trap::TrapFrame) == TRAP_FRAME_SIZE);

}  // namespace

namespace signetos::trap {
namespace {


// The stack an interrupt handler runs on: the interrupted context's own stack,
// everything below its `csp`, by the rule the switcher applies to every
// callee (`switcher::narrow_stack`, with the handler's `min_stack`). One check
// the switcher never needs: it must not be the kernel stack the `TrapFrame`
// sits on, or the handler could read the interrupted registers out of it.
// `frame` carries that stack's bounds.
Capability handler_stack(Capability interrupted_sp, uint64_t min_stack,
                         TrapFrame* frame, Status* out_status) {
  Capability h_sp =
      switcher::narrow_stack(interrupted_sp, min_stack, 0, out_status);
  if (!capability_is_valid(h_sp)) {
    return nullptr;
  }
  const Capability kstack = reinterpret_cast<Capability>(frame);
  const uint64_t k_lo = capability_get_base(kstack);
  const uint64_t k_hi = k_lo + capability_get_length(kstack);
  const uint64_t h_lo = capability_get_base(h_sp);
  const uint64_t h_hi = h_lo + capability_get_length(h_sp);
  if (h_lo < k_hi && h_hi > k_lo) {
    *out_status = Status::InvalidCapability;
    return nullptr;
  }
  return h_sp;
}

// Ends the interrupted thread because it cannot take the trap it just took
// (`why`, `status`). A thread that cannot take a trap cannot be preempted,
// so it is not resumed. If this was the tick, the timer is re-armed first so
// the remaining threads keep being scheduled; any other interrupt stays
// pending and is delivered to the next context that unmasks. `thread::exit`
// does not return in a thread. In host context there is no thread to end:
// the machine halts.
[[noreturn]] void end_interrupted_thread(const char* why, Status status,
                                         uint64_t mcause, uint64_t mtval,
                                         uint64_t mtval2,
                                         const TrapFrame* frame) {
  const uint64_t mepc = capability_get_address(frame->mepcc);
  debug::interrupted_thread_ending(why, status, mcause, mepc);
  if (mcause == IRQ_M_TIMER) {
    irq::rearm_tick();
  }
  thread::exit(-1);
  debug::trap_report("in host context, and the host cannot take this trap", mcause,
              mepc, mtval, mtval2, capability_get_address(frame->sp));
}

// What `__signetos_trap_dispatch` returns to make `_early_trap_entry` unwind
// at once, without entering a handler: neither null (resume) nor a tagged
// sentry (enter it). early_trap.S tells the three apart.
Capability unwind_sentinel() {
  return reinterpret_cast<Capability>(static_cast<uintptr_t>(1));
}

// Sets `frame` up for `entry` -- an interrupt handler, or a
// compartment's fault handler -- to run on `h_sp` (the trap vector zeroes it
// below its address before entering it, early_trap.S step 3)
// with `a0`/`a3` as its first capability and last integer arguments, and
// returns the sentry `_early_trap_entry` enters it through. `flags` are the
// TRAP_FLAG_* of the delivery. `async`: an interrupt, whose handler always
// runs masked.
Capability deliver(TrapFrame* frame, const sentry::Entry& entry,
                   Capability h_sp, uint64_t flags, Capability a0, uint64_t a3,
                   bool async) {
  // `frame->active_kernel_sp` was written by the trap vector at push
  // (asm_macros.h, FRAME LINK).
  thread::set_kernel_sp(reinterpret_cast<Capability>(frame));
  frame->handler_sp = h_sp;
  frame->handler_rw_table = entry.table;
  // Whose code runs above this frame (WHO FAULTED).
  frame->handler_comp = entry.owner;
  frame->handler_ca0 = a0;
  frame->handler_a3 = a3;
  frame->flags = flags;

  // The MIE the handler runs with (asm_macros.h, INTERRUPT MASKING RULE): an
  // interrupt handler, masked; a fault handler, the interrupted code's.
  // Unmasked, it can be interrupted at its first instruction, so, like an
  // unmasked callee (KERNEL-STACK ROOM, check 2), it also needs room for one
  // more `TrapFrame` that still passes check 3; with less it runs masked.
  //
  // `mstatus` is as the trap left it: its MPIE is the MIE the interrupted
  // code had (the dispatcher runs masked, so nothing has changed it since).
  // The copy recorded here is what `__signetos_trap_return` resumes the
  // interrupted code with.
  uint64_t mstatus = 0;
  __asm__ volatile("csrr %0, mstatus" : "=r"(mstatus));
  const bool unmasked =
      !async && (mstatus & MSTATUS_MPIE) != 0 &&
      thread::kernel_stack_free(reinterpret_cast<Capability>(frame)) >=
          TRAP_FRAME_SIZE + RET_FRAME_MIN_FREE;
  frame->mstatus = mstatus;
  frame->handler_mie = unmasked ? MSTATUS_MIE : 0;

  // User-space trap delivery: verify that the handler's hardware sentry
  // (`ct0`), stack (`csp`), capability table (`ca4`/`cgp`) and, if it is a
  // capability, first argument (`ca0`) are restricted and do not overlap
  // kernel memory before `early_trap.S` enters it.
  inspect::assert_user_capability(entry.sentry, "trap_dispatch:hw_sentry");
  inspect::assert_user_capability(frame->handler_sp,
                                  "trap_dispatch:handler_sp");
  inspect::assert_user_capability(frame->handler_rw_table,
                                  "trap_dispatch:rw_table");
  if (capability_is_valid(frame->handler_ca0)) {
    inspect::assert_user_capability(frame->handler_ca0, "trap_dispatch:ca0");
  }
  return entry.sentry;
}

// Abandons the faulting code without entering any handler: `frame` becomes a
// fault frame that `unwind::resume` skips, giving the frame beneath `status`
// (unwind.hpp). `_early_trap_entry` goes straight to its return path.
Capability unwind_now(TrapFrame* frame, Status status) {
  frame->flags |= TRAP_FLAG_FAULT;
  frame->fault_status = static_cast<uint64_t>(status);
  frame->handler_sp = nullptr;
  frame->handler_ca0 = nullptr;
  thread::set_kernel_sp(reinterpret_cast<Capability>(frame));
  return unwind_sentinel();
}

// Where `frame` keeps register xn (fault::ErrorState numbering), n = 1..31.
Capability* frame_reg(TrapFrame* frame, uint32_t n) {
  if (n == 1) return &frame->ra;
  if (n == 2) return &frame->sp;
  if (n == 3) return &frame->gp;
  if (n == 4) return &frame->tp;
  if (n <= 7) return &frame->t[n - 5];    // t0..t2 = x5..x7
  if (n <= 9) return &frame->s[n - 8];    // s0..s1 = x8..x9
  if (n <= 17) return &frame->a[n - 10];  // a0..a7 = x10..x17
  if (n <= 27) return &frame->s[n - 16];  // s2..s11 = x18..x27
  return &frame->t[n - 25];               // t3..t6 = x28..x31
}

// Copies the faulting context in `frame` into the ErrorState at `es`, on the
// faulting compartment's own stack (fault.hpp). Every register is the
// compartment's own; the program counter goes as a plain address, so the
// handler never holds the faulting PCC.
void save_context(TrapFrame* frame, Capability es, uint64_t mcause,
                  uint64_t mtval, uint64_t mtval2) {
  auto* state = reinterpret_cast<fault::ErrorState*>(es);
  state->regs[0] = nullptr;
  for (uint32_t n = 1; n < 32; ++n) {
    state->regs[n] = *frame_reg(frame, n);
  }
  state->pc = capability_get_address(frame->mepcc);
  state->mcause = mcause;
  state->mtval = mtval;
  state->mtval2 = mtval2;
}

// A synchronous exception raised by compartment code (fault.hpp): find which
// compartment was running from the frame beneath `frame` (WHO FAULTED) and
// deliver its fault handler with the faulting context in an ErrorState at the top of the
// stack below the faulting `csp` -- or, if it cannot be delivered, report the
// fault and unwind.
Capability dispatch_fault(uint64_t mcause, uint64_t mtval, uint64_t mtval2,
                          TrapFrame* frame) {
  const uint64_t mepc = capability_get_address(frame->mepcc);

  // WHO FAULTED: the frame beneath this one entered the code that was
  // running and recorded whose it is; with nothing beneath, it is the
  // thread's initial compartment.
  const Capability below = frame->active_kernel_sp;
  Capability handle = nullptr;  // the faulting compartment
  switch (unwind::kind_at(below)) {
    case unwind::KIND_RETURN_FRAME: {
      handle = reinterpret_cast<switcher::ReturnFrame*>(below)->callee_comp;
      break;
    }
    case unwind::KIND_TRAP_FRAME: {
      auto* t = reinterpret_cast<TrapFrame*>(below);
      if ((t->flags & TRAP_FLAG_FAULT) != 0) {
        // A fault in a fault handler is never delivered (fault.hpp).
        const compartment::Compartment* x = compartment::open(t->handler_comp);
        debug::fault_report("in its fault handler; unwinding", x ? x->uid : 0, mcause,
                     mepc, mtval, mtval2);
        return unwind_now(frame, Status::Faulted);
      }
      handle = t->handler_comp;
      break;
    }
    default: {
      if (thread::current_tid() == 0) {
        debug::trap_report("raised in host context, where no compartment is running",
                    mcause, mepc, mtval, mtval2,
                    capability_get_address(frame->sp));
      }
      sentry::Entry start{};
      if (sentry::resolve(thread::current_entry_sentry(), &start) !=
          Status::Ok) {
        return unwind_now(frame, Status::CompartmentDestroyed);
      }
      handle = start.owner;
      break;
    }
  }
  if (capability_get_address(handle) == 0) {
    // Compartment code no kernel frame entered: a kernel bug.
    debug::trap_report("raised by compartment code that no kernel frame entered",
                mcause, mepc, mtval, mtval2, capability_get_address(frame->sp));
  }
  const compartment::Compartment* x = compartment::open(handle);
  if (x == nullptr) {
    // Destroyed while its code ran (swept or not): nobody to hand it to, and
    // whoever is beneath hears what it would have on any other return.
    return unwind_now(frame, Status::CompartmentDestroyed);
  }

  // The handler makes its kernel calls on this kernel stack (asm_macros.h,
  // KERNEL-STACK ROOM, check 3). Without the room, no handler can run, but
  // unwinding needs none.
  if (thread::kernel_stack_free(reinterpret_cast<Capability>(frame)) <
      RET_FRAME_MIN_FREE) {
    debug::fault_report("no kernel stack for its fault handler; unwinding", x->uid,
                 mcause, mepc, mtval, mtval2);
    return unwind_now(frame, Status::Faulted);
  }

  sentry::Entry e{};
  if (!compartment::fault_entry(handle, &e)) {
    debug::fault_report("no fault handler; unwinding", x->uid, mcause, mepc, mtval,
                 mtval2);
    return unwind_now(frame, Status::Faulted);
  }

  // Everything below the faulting `csp`, by the stack rule, with room for
  // the ErrorState at its top and the handler's `min_stack` below that.
  Status status = Status::Ok;
  const Capability h_sp = handler_stack(
      frame->sp, e.min_stack + sizeof(fault::ErrorState), frame, &status);
  const uint64_t es_addr =
      capability_get_address(h_sp) - sizeof(fault::ErrorState);
  const Capability es = capability_set_bounds(
      capability_set_address(h_sp, es_addr), sizeof(fault::ErrorState));
  if (!capability_is_valid(h_sp) || !capability_is_valid(es)) {
    debug::fault_report("no room on its stack for its fault handler; unwinding",
                 x->uid, mcause, mepc, mtval, mtval2);
    return unwind_now(frame, Status::Faulted);
  }

  // The handler's `csp` starts just below the ErrorState: the trap vector
  // zeroes everything below that, and the ErrorState itself is filled in
  // whole here.
  const Capability handler =
      deliver(frame, e, capability_set_address(h_sp, es_addr), TRAP_FLAG_FAULT,
              es, mtval2, false);
  save_context(frame, es, mcause, mtval, mtval2);
  return handler;
}

}  // namespace

bool install_context(TrapFrame* frame) {
  if (!capability_is_valid(frame->handler_ca0)) {
    return false;
  }
  const auto* state =
      reinterpret_cast<const fault::ErrorState*>(frame->handler_ca0);
  // The faulting PCC with only its address changed: the handler moves the
  // program counter within its own code and nowhere else.
  const Capability pcc = capability_set_address(frame->mepcc, state->pc);
  if (!capability_is_valid(pcc)) {
    return false;
  }
  for (uint32_t n = 1; n < 32; ++n) {
    *frame_reg(frame, n) = state->regs[n];
  }
  frame->mepcc = pcc;
  return true;
}


extern "C" Capability __signetos_trap_dispatch(uint64_t mcause, uint64_t mtval,
                                               uint64_t mtval2,
                                               TrapFrame* frame) {
  const bool async = (mcause & INTERRUPT_BIT) != 0;
  const uint64_t mepc = capability_get_address(frame->mepcc);
  // What an interrupt handler gets as its cause and a3: the trap's own,
  // unless a thread waits for a page (below).
  uint64_t handler_cause = mcause;
  uint64_t handler_a3 = mtval2;
  frame->flags = 0;
  frame->fault_status = 0;
  frame->handler_comp = nullptr;
  frame->handler_sp = nullptr;
  frame->handler_ca0 = nullptr;

  // A synchronous fault raised by kernel code is a kernel bug, and no
  // compartment's handler may stand in for the kernel: report and halt. Kernel
  // code is known by its PCC: only the kernel's own text runs with
  // AccessSystemRegs; every compartment entry, including the kernel-text
  // stubs the test suites run as compartments, is CodeRx without it. An
  // interrupt on kernel code is not a fault -- the switcher unmasks a few
  // instructions before it returns to its caller, and the trap vector a few
  // before it enters an exception handler and after it comes back -- and is
  // delivered like any other.
  if (!async &&
      (capability_get_perms(frame->mepcc) & perms::AccessSystemRegs) != 0) {
    debug::trap_report("raised by kernel code (mepcc carries AccessSystemRegs)",
                mcause, mepc, mtval, mtval2,
                capability_get_address(frame->sp));
  }

  // A software interrupt is a poke from the kernel (irq.hpp, THE SOFTWARE
  // INTERRUPT IS THE KERNEL'S): a handler was installed, so this hart brings
  // its `mie` and timer in line, and the interrupted context resumes.
  if (mcause == IRQ_M_SOFT) {
    irq::on_poke();
    return nullptr;
  }

  // A synchronous exception raised by compartment code is that compartment's
  // fault, for its own handler (fault.hpp) -- unless it is a page fault on
  // pageable memory, which is paging's: the access runs again, once the page
  // is in (vm.hpp, PAGING, FAULTS). The per-vector table holds only
  // interrupts.
  if (!async) {
    // MPIE is the MIE the faulting code had: only code that can be
    // interrupted can wait for a page.
    uint64_t mstatus = 0;
    __asm__ volatile("csrr %0, mstatus" : "=r"(mstatus));
    const vm::Fault paging =
        (mcause == EXC_INST_PAGE_FAULT || mcause == EXC_LOAD_PAGE_FAULT ||
         mcause == EXC_STORE_PAGE_FAULT)
            ? vm::fault(mtval, (mstatus & MSTATUS_MPIE) != 0,
                        thread::current_tid())
            : vm::Fault::No;
    if (paging == vm::Fault::No) {
      return dispatch_fault(mcause, mtval, mtval2, frame);
    }
    if (paging == vm::Fault::Retry) {
      return nullptr;
    }
    // Waiting for a page: the scheduler's tick handler is told so
    // (PAGE_WAIT), blocks the thread and wakes the pager, which wakes the
    // thread again once the page is in; the access then runs again.
    mcause = IRQ_M_TIMER;
    handler_cause = PAGE_WAIT;
    handler_a3 = vm::pager_tid();
  }

  // The installed handler, if it still resolves: `resolve` refuses an entry
  // whose compartment has been destroyed.
  {
    const Capability handler = irq::handler_for(mcause);
    sentry::Entry entry{};
    if (handler != nullptr &&
        sentry::resolve(handler, &entry) == Status::Ok &&
        (entry.flags & sentry::ENTRY_FLAG_TRUSTED) == 0) {
      // The handler makes its kernel calls on this kernel stack and runs on
      // the interrupted context's own stack, below its `csp`. The context
      // must be able to carry both (asm_macros.h, KERNEL-STACK ROOM, check
      // 3, and the stack rule of every callee). If it cannot, it cannot take
      // any trap, and a thread that cannot take a trap cannot be preempted:
      // it is ended rather than resumed.
      if (thread::kernel_stack_free(reinterpret_cast<Capability>(frame)) <
          RET_FRAME_MIN_FREE) {
        end_interrupted_thread("no room on its kernel stack for the handler",
                               Status::NoKernelStack, mcause, mtval, mtval2,
                               frame);
      }
      Status status = Status::Ok;
      Capability h_sp =
          handler_stack(frame->sp, entry.min_stack, frame, &status);
      if (!capability_is_valid(h_sp)) {
        end_interrupted_thread("its stack cannot host the handler", status,
                               mcause, mtval, mtval2, frame);
      }
      if (async && mcause == IRQ_M_TIMER) {
        // Re-arm before the handler runs: this clears MTIP, so a handler
        // that simply returns is safe, and the period does not drift with
        // the handler's running time.
        irq::rearm_tick();
      }
      return deliver(
          frame, entry, h_sp, 0,
          reinterpret_cast<Capability>(static_cast<uintptr_t>(handler_cause)),
          handler_a3, true);
    }
  }

  // An interrupt with no handler that resolves: silence it on this hart and
  // return to the interrupted PC. This is a hart whose poke has not arrived
  // yet, or a handler whose compartment has been destroyed. A thread waiting
  // for a page with no tick to give way to just runs again.
  if (async) {
    irq::silence(mcause);
  }
  (void)mepc;
  return nullptr;
}

extern "C" uint64_t __signetos_trap_return(uint64_t verdict) {
  // Pop the handler's `TrapFrame` (the assembly then zeroes the stack loaned
  // to the handler) and resume the interrupted code with the MIE it had -- or,
  // if its compartment has been destroyed and swept while the handler ran, the
  // nearest live frame beneath (unwind.hpp). A fault frame is resumed only
  // on its handler's INSTALL_CONTEXT `verdict`, with the context it left
  // (fault.hpp); otherwise the faulting code is abandoned and the frame
  // beneath it gets the fault's status. The
  // top frame must be a `TrapFrame` the dispatcher pushed for a handler, not
  // something else reached through a stashed trap-return sentry (e.g. a
  // handler's own `ReturnFrame` from a call into itself); `resume` refuses
  // anything else before it reads from the frame.
  const bool top_ok =
      unwind::kind_at(thread::current_kernel_sp()) == unwind::KIND_TRAP_FRAME;
  const unwind::Kind kind =
      unwind::resume(unwind::KIND_TRAP_FRAME, nullptr, verdict);
  if (kind == unwind::KIND_NONE) {
    // If anything was popped, `resume` has already said why the thread ends.
    if (!top_ok) {
      debug::thread_ending("trap", "trap return with nothing to return to");
    }
    thread::exit(-1);
    debug::panic("trap: trap return with nothing to return to");
  }
  return kind;
}

}  // namespace signetos::trap
