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
 * trap.cpp - SignetOS trap dispatch, reporting and user trap binding
 *
 * Called from _early_trap_entry (early_trap.S) when a synchronous exception or
 * asynchronous interrupt reaches the machine trap vector. Everything runs in
 * M-mode and nothing is delegated, so that is every trap there is.
 *
 * A synchronous fault raised by kernel code (`mepcc` carries AccessSystemRegs)
 * is a kernel bug: `trap_report()` prints it and halts, whatever is bound.
 *
 * Otherwise, if a compartment has bound an `OType::EntryPoint` (CT = 18)
 * handler sentry to the vector via `sys_trap_bind`, `__signetos_trap_dispatch`
 * resolves it and `_early_trap_entry` invokes it with the interrupted context
 * saved in a `TrapFrame` on the active kernel stack -- provided the
 * interrupted context can take a trap at all: its kernel stack must have the
 * room of asm_macros.h (KERNEL-STACK ROOM, check 3) and its `csp` must pass
 * the stack rule every callee's stack passes (`sentry::narrow_stack`), since
 * the handler runs below it. A thread that fails either cannot be preempted
 * and is ended on the spot (`end_interrupted_thread`); in host context the
 * machine halts.
 *
 * An unbound asynchronous interrupt is silenced at its source on this hart
 * (the timer is disarmed, any other has its `mie` bit cleared) and returned
 * from; an unbound synchronous exception is reported and halts the machine.
 *
 * Each hart keeps its `mie` and timer in line with the trap table, and the
 * software interrupt is the kernel's own poke that tells a hart to do so
 * (see trap.hpp, SEVERAL HARTS and THE SOFTWARE INTERRUPT IS THE KERNEL'S).
 *
 * The kernel also owns the periodic tick behind `IRQ_M_TIMER` (see trap.hpp,
 * THE KERNEL TICK), and decides which `MIE` a handler runs with and which
 * the interrupted context resumes with (see asm_macros.h, INTERRUPT MASKING
 * RULE).
 */

#include <signetos/asm_macros.h>
#include <signetos/clint.hpp>
#include <signetos/compartment.hpp>
#include <signetos/fault.hpp>
#include <signetos/inspect.hpp>
#include <signetos/lock.hpp>
#include <signetos/sealing.hpp>
#include <signetos/sentry.hpp>
#include <signetos/thread.hpp>
#include <signetos/trap.hpp>
#include <signetos/uart.hpp>
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

// Standard RISC-V synchronous causes, indexed by exception code.
const char* const kStandardCause[16] = {
    "Instruction address misaligned",  // 0
    "Instruction access fault",        // 1
    "Illegal instruction",             // 2
    "Breakpoint",                      // 3
    "Load address misaligned",         // 4
    "Load access fault",               // 5
    "Store/AMO address misaligned",    // 6
    "Store/AMO access fault",          // 7
    "Environment call from U-mode",    // 8
    "Environment call from S-mode",    // 9
    "reserved (10)",                   // 10
    "Environment call from M-mode",    // 11
    "Instruction page fault",          // 12
    "Load page fault",                 // 13
    "reserved (14)",                   // 14
    "Store/AMO page fault",            // 15
};

// This CHERI implementation raises one unified exception code for every
// capability check failure rather than a family of them, and reports which
// check failed separately in mtval2. Verified against the running machine and
// against target/riscv/cpu_bits.h in the QEMU tree:
//     RISCV_EXCP_CHERI = 0x1c
constexpr uint64_t kCheriFault = 28;

// mtval2 layout for mcause 28, from cpu_helper.c:
//     cheri_exc_info = cheri093_cap_cause(cause) | (type << 16)
// Values from Cheri093CapExcCause / Cheri093CapExcType in
// target/riscv/cheri-archspecific-early.h.
const char* cheri_violation(uint64_t mtval2) {
  switch (mtval2 & 0xffff) {
    case 0:
      return "tag violation (the capability was not valid)";
    case 1:
      return "seal violation (the capability was sealed)";
    case 2:
      return "permission violation";
    case 3:
      return "invalid address violation";
    case 4:
      return "bounds violation (address outside base..top)";
    default:
      return "unknown violation";
  }
}

const char* cheri_access(uint64_t mtval2) {
  switch ((mtval2 >> 16) & 0xff) {
    case 0:
      return "instruction fetch";
    case 1:
      return "data access";
    case 2:
      return "branch or jump";
    default:
      return "unknown access";
  }
}

// Turns an exception code into text. Returns null for codes this kernel has no
// name for, so the caller can still print the number on its own.
const char* cause_text(uint64_t code) {
  if (code < 16) {
    return kStandardCause[code];
  }
  if (code == kCheriFault) {
    return "CHERI fault";
  }
  return nullptr;
}

// One "  label : 0x...." line.
void field(const char* label, uint64_t value) {
  uart::print("  ");
  uart::print(label);
  uart::print(" : 0x");
  uart::print_hex64(value);
  uart::print("\n");
}

bool s_in_trap_report = false;

//
// Reports a synchronous exception and halts the machine.
//
// why    - one line on why nothing short of halting is possible
// mcause - machine cause register; the interrupt bit is known to be clear
// mepc   - address of the faulting instruction, read out of mepcc
// mtval  - trap value register; its meaning depends on the cause
// mtval2 - for a CHERI fault, which capability check failed
// ssp    - stack pointer at the point of the fault, for orientation
//
[[noreturn]] void trap_report(const char* why, uint64_t mcause, uint64_t mepc,
                              uint64_t mtval, uint64_t mtval2, uint64_t ssp) {
  if (s_in_trap_report) {
    for (;;) {
      __asm__ volatile("wfi");
    }
  }
  s_in_trap_report = true;
  // This hart may hold the console lock (a fault inside a print); from here
  // on prints do not wait for it.
  uart::halting();

  uart::print("\n");
  uart::print(
      "########################################################################"
      "########\n");
  uart::print("# TRAP: synchronous exception -- the kernel is halting\n");
  uart::print("# ");
  uart::print(why);
  uart::print("\n");
  uart::print(
      "########################################################################"
      "########\n");

  // The cause first, since it decides what is worth looking at next.
  uart::print("  mcause : ");
  uart::print_dec(mcause);
  const char* text = cause_text(mcause);
  if (text != nullptr) {
    uart::print("  (");
    uart::print(text);
    uart::print(")");
  } else {
    uart::print("  (unrecognised exception code)");
  }
  uart::print("\n");

  // For a CHERI fault the code above is the same for every kind of
  // violation, so this line is the one that says what actually went wrong.
  if (mcause == kCheriFault) {
    uart::print("  detail : ");
    uart::print(cheri_violation(mtval2));
    uart::print(", on ");
    uart::print(cheri_access(mtval2));
    uart::print("\n");
  }

  // mepc is the instruction that faulted, not the one after it, so the
  // address can be looked up directly in the disassembly:
  //   llvm-objdump -d --start-address=0x... signetos.elf
  field("mepc  ", mepc);

  // The address the instruction was trying to reach.
  field("mtval ", mtval);
  field("mtval2", mtval2);
  field("sp    ", ssp);

  uart::print(
      "########################################################################"
      "########\n");

  // Exit non-zero so a scripted run can tell a fault from a clean finish.
  uart::qemu_poweroff(1);
}

// Reports, without halting, a fault in compartment code that no handler of
// the compartment's took (`why`). The trap path then unwinds it.
void fault_report(const char* why, uint64_t comp_uid, uint64_t mcause,
                  uint64_t mepc, uint64_t mtval, uint64_t mtval2) {
  uart::print("[fault] compartment ");
  uart::print_dec(comp_uid);
  uart::print(", thread ");
  uart::print_dec(signetos::thread::current_tid());
  uart::print(": ");
  const char* text = cause_text(mcause);
  uart::print(text != nullptr ? text : "unrecognised exception");
  if (mcause == kCheriFault) {
    uart::print(" (");
    uart::print(cheri_violation(mtval2));
    uart::print(", on ");
    uart::print(cheri_access(mtval2));
    uart::print(")");
  }
  uart::print(" at 0x");
  uart::print_hex64(mepc);
  uart::print(", mtval 0x");
  uart::print_hex64(mtval);
  uart::print("; ");
  uart::print(why);
  uart::print("\n");
}

}  // namespace

namespace signetos::trap {
namespace {

SpinLock s_lock;
TrapSlot s_slots[MAX_TRAP_SLOTS];

// `mie` bits. `MSTATUS_MPIE` comes from asm_macros.h.
constexpr uint64_t MIE_MSIE = 1ULL << 3;
constexpr uint64_t MIE_MTIE = 1ULL << 7;
constexpr uint64_t SOFT_CODE = IRQ_M_SOFT & ~INTERRUPT_BIT;
constexpr uint64_t TIMER_CODE = IRQ_M_TIMER & ~INTERRUPT_BIT;

uint64_t tick_ticks() { return clint::us_to_ticks(TICK_US); }

// The harts that have run `init_hart`, one bit per hart number: the harts a
// poke is sent to.
uint64_t s_harts_up = 0;

void arm_tick() {
  __asm__ volatile("csrs mie, %0" : : "r"(MIE_MTIE));
  clint::set_timer(clint::now() + tick_ticks());
}

// Clears MTIE as well, so on each hart MTIE is set exactly while that hart's
// tick is armed (`sync_this_hart` reads it that way).
void disarm_tick() {
  clint::set_timer(clint::TIMER_OFF);
  __asm__ volatile("csrc mie, %0" : : "r"(MIE_MTIE));
}

// Slot write/read protocol (trap.hpp, `TrapSlot`). Writers are system calls
// and run masked under `s_lock`; the trap dispatcher and `sync_this_hart`
// only read.
void slot_write_begin(TrapSlot* slot) {
  slot->seq += 1;  // odd: in progress
  __atomic_thread_fence(__ATOMIC_RELEASE);
}

void slot_write_end(TrapSlot* slot) {
  __atomic_thread_fence(__ATOMIC_RELEASE);
  slot->seq += 1;  // even: stable
}

TrapSlot read_slot(const TrapSlot* slot) {
  TrapSlot copy{};
  for (;;) {
    const uint64_t before = __atomic_load_n(&slot->seq, __ATOMIC_ACQUIRE);
    if ((before & 1) != 0) {
      continue;  // a writer is mid-update
    }
    copy.owner_comp = slot->owner_comp;
    copy.target_sentry = slot->target_sentry;
    copy.owner_comp_uid = slot->owner_comp_uid;
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (__atomic_load_n(&slot->seq, __ATOMIC_RELAXED) == before) {
      copy.seq = before;
      return copy;
    }
  }
}

void clear_slot(TrapSlot* slot) {
  slot_write_begin(slot);
  slot->owner_comp_uid = 0;
  slot->owner_comp = nullptr;
  slot->target_sentry = nullptr;
  slot_write_end(slot);
}

bool irq_bound(uint64_t code) {
  return read_slot(&s_slots[MAX_EXCEPTION_VECTORS + code]).owner_comp_uid != 0;
}

// Brings this hart's `mie` and timer in line with the trap table: the poke
// bit always set, every other interrupt's bit set exactly while its slot is
// bound, and the tick armed exactly while the timer slot is bound. Nothing
// here is device-specific: code 11 is one bit like the rest, and what sits
// behind it is `trap_mgr`'s business.
void sync_this_hart() {
  uint64_t on = MIE_MSIE;
  uint64_t off = 0;
  for (uint64_t code = 0; code < MAX_INTERRUPT_VECTORS; ++code) {
    if (code == SOFT_CODE || code == TIMER_CODE) {
      continue;
    }
    if (irq_bound(code)) {
      on |= 1ULL << code;
    } else {
      off |= 1ULL << code;
    }
  }
  __asm__ volatile("csrs mie, %0" : : "r"(on));
  __asm__ volatile("csrc mie, %0" : : "r"(off));

  uint64_t mie = 0;
  __asm__ volatile("csrr %0, mie" : "=r"(mie));
  const bool armed = (mie & MIE_MTIE) != 0;
  if (irq_bound(TIMER_CODE)) {
    if (!armed) {
      arm_tick();
    }
  } else if (armed) {
    disarm_tick();
  }
}

// Pokes every other hart that is up. The fence makes the table writes before
// it visible to a poked hart before that hart can read the table; the poked
// hart fences too (`__signetos_trap_dispatch`).
void poke_other_harts() {
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
  const uint64_t others = __atomic_load_n(&s_harts_up, __ATOMIC_SEQ_CST) &
                          ~(1ULL << thread::this_hart());
  if (others != 0) {
    clint::send_ipi(others);
  }
}

bool slot_index(uint64_t mcause, size_t* out_idx) {
  const uint64_t code = mcause & ~INTERRUPT_BIT;
  if ((mcause & INTERRUPT_BIT) != 0) {
    if (code >= MAX_INTERRUPT_VECTORS) {
      return false;
    }
    *out_idx = MAX_EXCEPTION_VECTORS + static_cast<size_t>(code);
    return true;
  }
  if (code >= MAX_EXCEPTION_VECTORS) {
    return false;
  }
  *out_idx = static_cast<size_t>(code);
  return true;
}

TrapSlot* unseal_auth(Capability auth_cap) {
  Capability open = sealing::unseal_as(OType::Trap, auth_cap);
  if (!capability_is_valid(open)) {
    return nullptr;
  }
  if (capability_get_length(open) != sizeof(TrapSlot)) {
    return nullptr;
  }
  const uint64_t addr = capability_get_base(open);
  const uint64_t base =
      capability_get_address(reinterpret_cast<Capability>(&s_slots[0]));
  const uint64_t total_bytes = sizeof(s_slots);
  if (addr < base || addr + sizeof(TrapSlot) > base + total_bytes) {
    return nullptr;
  }
  const size_t offset = static_cast<size_t>(addr - base);
  if ((offset % sizeof(TrapSlot)) != 0) {
    return nullptr;
  }
  return &s_slots[offset / sizeof(TrapSlot)];
}

// The stack a bound handler runs on: the interrupted context's own stack,
// everything below its `csp`, by the rule the switcher applies to every
// callee (`sentry::narrow_stack`, with the handler's `min_stack`). One check
// the switcher never needs: it must not be the kernel stack the `TrapFrame`
// sits on, or the handler could read the interrupted registers out of it.
// `frame` carries that stack's bounds.
Capability handler_stack(Capability interrupted_sp, uint64_t min_stack,
                         TrapFrame* frame, Status* out_status) {
  Capability h_sp =
      sentry::narrow_stack(interrupted_sp, min_stack, 0, out_status);
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
  uart::print("[trap] ending thread ");
  uart::print_dec(thread::current_tid());
  uart::print(": ");
  uart::print(why);
  uart::print(" (");
  uart::print(status_name(status));
  uart::print("), mcause 0x");
  uart::print_hex64(mcause);
  uart::print(" at 0x");
  uart::print_hex64(mepc);
  uart::print("\n");
  if (mcause == IRQ_M_TIMER) {
    clint::set_timer(clint::now() + tick_ticks());
  }
  thread::exit(-1);
  trap_report("in host context, and the host cannot take this trap", mcause,
              mepc, mtval, mtval2, capability_get_address(frame->sp));
}

// What `__signetos_trap_dispatch` returns to make `_early_trap_entry` unwind
// at once, without entering a handler: neither null (resume) nor a tagged
// sentry (enter it). early_trap.S tells the three apart.
Capability unwind_sentinel() {
  return reinterpret_cast<Capability>(static_cast<uintptr_t>(1));
}

// Sets `frame` up for `entry` -- a handler bound to an interrupt, or a
// compartment's fault handler -- to run on `h_sp` (zeroed first if `zero`)
// with `a0`/`a3` as its first capability and last integer arguments, and
// returns the sentry `_early_trap_entry` enters it through. `flags` are the
// TRAP_FLAG_* of the delivery. `async`: an interrupt, whose handler always
// runs masked.
Capability deliver(TrapFrame* frame, const sentry::Entry& entry,
                   Capability h_sp, bool zero, uint64_t flags, Capability a0,
                   uint64_t a3, bool async) {
  // `frame->active_kernel_sp` was written by the trap vector at push
  // (asm_macros.h, FRAME LINK).
  thread::set_kernel_sp(reinterpret_cast<Capability>(frame));
  frame->handler_sp = h_sp;
  if (zero) {
    sentry::zero_stack(h_sp);  // what the interrupted code left below its csp
  }
  frame->handler_rw_table = entry.table;
  // Whose code runs above this frame (WHO FAULTED).
  frame->handler_comp = entry.owner;
  frame->handler_ca0 = a0;
  frame->handler_a3 = a3;
  frame->flags = flags;
  // What a kill does to the handler (unwind.hpp, KILLED THREADS).
  if (const compartment::Compartment* owner = compartment::open(entry.owner)) {
    if ((__atomic_load_n(&owner->flags, __ATOMIC_ACQUIRE) &
         compartment::FLAG_TRUSTED_TO_FINISH) != 0) {
      frame->flags |= sentry::ENTRY_FLAG_TRUSTED_TO_FINISH;
    }
  }

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

// True if `a` and `b` are handles to the same compartment.
bool same_compartment(Capability a, Capability b) {
  return capability_is_valid(a) && capability_is_valid(b) &&
         capability_get_base(a) == capability_get_base(b);
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
      handle = reinterpret_cast<sentry::ReturnFrame*>(below)->callee_comp;
      break;
    }
    case unwind::KIND_TRAP_FRAME: {
      auto* t = reinterpret_cast<TrapFrame*>(below);
      if ((t->flags & TRAP_FLAG_FAULT) != 0) {
        // A fault in a fault handler is never delivered (fault.hpp).
        const compartment::Compartment* x = compartment::open(t->handler_comp);
        fault_report("in its fault handler; unwinding", x ? x->uid : 0, mcause,
                     mepc, mtval, mtval2);
        return unwind_now(frame, Status::Faulted);
      }
      handle = t->handler_comp;
      break;
    }
    default: {
      if (thread::current_tid() == 0) {
        trap_report("raised in host context, where no compartment is running",
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
    trap_report("raised by compartment code that no kernel frame entered",
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
    fault_report("no kernel stack for its fault handler; unwinding", x->uid,
                 mcause, mepc, mtval, mtval2);
    return unwind_now(frame, Status::Faulted);
  }

  sentry::Entry e{};
  if (sentry::resolve_fault(x->fault_handler, &e) != Status::Ok ||
      (e.flags & sentry::ENTRY_FLAG_FAULT) == 0 ||
      !same_compartment(e.owner, handle)) {
    fault_report("no fault handler; unwinding", x->uid, mcause, mepc, mtval,
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
    fault_report("no room on its stack for its fault handler; unwinding",
                 x->uid, mcause, mepc, mtval, mtval2);
    return unwind_now(frame, Status::Faulted);
  }

  // `deliver` zeroes the whole stack, the ErrorState's place included, before
  // the context is copied in; the handler's `csp` starts below it.
  const Capability handler =
      deliver(frame, e, capability_set_address(h_sp, es_addr), true,
              TRAP_FLAG_FAULT, es, mtval2, false);
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

void init() {
  s_lock = SpinLock{};
  for (TrapSlot& slot : s_slots) {
    slot = TrapSlot{};
  }
}

void init_hart() {
  // A known start, so that MTIE means "this hart's tick is armed" from here
  // on: only the poke bit on, the timer off, and no poke pending (the one
  // that started a secondary hart is still set, thread.cpp).
  clint::set_timer(clint::TIMER_OFF);
  clint::clear_ipi();
  __asm__ volatile("csrw mie, %0" : : "r"(MIE_MSIE));

  // Publish this hart, then read the table. A binder does the opposite --
  // writes the table, then reads `s_harts_up` (`poke_other_harts`). Both
  // sides write, fence, then read, so at least one sees the other: either
  // the binder pokes this hart, or the sync below sees the binding.
  __atomic_fetch_or(&s_harts_up, 1ULL << thread::this_hart(),
                    __ATOMIC_SEQ_CST);
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
  sync_this_hart();
}

void sync_all_harts() {
  sync_this_hart();
  poke_other_harts();
}

Capability authority_for(uint64_t mcause) {
  // The software interrupt is the kernel's poke (trap.hpp, THE SOFTWARE
  // INTERRUPT IS THE KERNEL'S). Nobody may bind it, so no authority for it
  // exists.
  if (mcause == IRQ_M_SOFT) {
    return nullptr;
  }
  // Exceptions are not bindable either: a synchronous fault is delivered to
  // the faulting compartment's own fault handler (`fault.hpp`), never to a
  // global one, so no authority over an exception slot is ever minted.
  if ((mcause & INTERRUPT_BIT) == 0) {
    return nullptr;
  }
  size_t idx = 0;
  if (!slot_index(mcause, &idx)) {
    return nullptr;
  }
  Capability slot_cap = reinterpret_cast<Capability>(&s_slots[idx]);
  slot_cap = capability_set_bounds(slot_cap, sizeof(TrapSlot));
  slot_cap = capability_and_perms(slot_cap, perms::Load | perms::Store);
  return sealing::seal_as(OType::Trap, slot_cap);
}

Status bind(Capability comp, Capability auth_cap, Capability target_sentry) {
  compartment::Compartment comp_info{};
  if (!compartment::query(comp, &comp_info)) {
    return Status::InvalidCompartment;
  }

  TrapSlot* slot = unseal_auth(auth_cap);
  if (slot == nullptr) {
    return Status::InvalidAuthority;
  }
  // Belt and braces: `authority_for` never mints an exception-slot handle,
  // but refuse one here as well so the dispatcher never has to consider it.
  if (slot < &s_slots[MAX_EXCEPTION_VECTORS]) {
    return Status::InvalidAuthority;
  }
  if ((capability_get_perms(auth_cap) & perms::Load) == 0) {
    return Status::InsufficientPermission;
  }

  // Both handles are kept in the slot until unbound. A local copy (one the
  // holder relabelled, or that came through a stack) is not accepted: nothing
  // the kernel remembers may be local.
  if ((capability_get_perms(comp) & perms::Global) == 0 ||
      (capability_get_perms(target_sentry) & perms::Global) == 0) {
    return Status::InvalidSentry;
  }

  // The handler must be one of `comp`'s own entries. The dispatcher runs the
  // handler with `comp`'s tables and counts it inside `comp`, so an entry of
  // some other compartment -- whose code would then run with this one's
  // tables in `cgp` -- is refused. A kernel entry is refused too: a system
  // call is not a trap handler.
  sentry::Entry entry{};
  if (sentry::resolve(target_sentry, &entry) != Status::Ok ||
      (entry.flags & sentry::ENTRY_FLAG_TRUSTED) != 0 ||
      !capability_is_valid(entry.owner) ||
      capability_get_base(entry.owner) !=
          capability_get_base(comp_info.self_page)) {
    return Status::InvalidSentry;
  }

  Locked hold(s_lock);
  slot_write_begin(slot);
  slot->owner_comp_uid = comp_info.uid;
  slot->owner_comp = comp;
  slot->target_sentry = target_sentry;
  slot_write_end(slot);
  sync_all_harts();
  return Status::Ok;
}

Status unbind(Capability comp, Capability auth_cap) {
  compartment::Compartment comp_info{};
  if (!compartment::query(comp, &comp_info)) {
    return Status::InvalidCompartment;
  }

  TrapSlot* slot = unseal_auth(auth_cap);
  if (slot == nullptr) {
    return Status::InvalidAuthority;
  }
  if ((capability_get_perms(auth_cap) & perms::Load) == 0) {
    return Status::InsufficientPermission;
  }

  Locked hold(s_lock);
  if (slot->owner_comp_uid == 0 || slot->owner_comp_uid != comp_info.uid) {
    return Status::NotBoundToCompartment;
  }

  clear_slot(slot);
  sync_all_harts();
  return Status::Ok;
}

size_t purge_compartment(uint64_t comp_uid) {
  if (comp_uid == 0) {
    return 0;
  }
  Locked hold(s_lock);
  size_t purged = 0;
  for (size_t i = 0; i < MAX_TRAP_SLOTS; ++i) {
    if (s_slots[i].owner_comp_uid == comp_uid) {
      clear_slot(&s_slots[i]);
      purged += 1;
    }
  }
  if (purged != 0) {
    sync_all_harts();
  }
  return purged;
}

bool is_bound(uint64_t mcause, uint64_t* out_owner_uid) {
  size_t idx = 0;
  if (!slot_index(mcause, &idx)) {
    return false;
  }
  const TrapSlot slot = read_slot(&s_slots[idx]);
  if (slot.owner_comp_uid == 0) {
    return false;
  }
  if (out_owner_uid != nullptr) {
    *out_owner_uid = slot.owner_comp_uid;
  }
  return true;
}

size_t bound_count() {
  size_t n = 0;
  for (size_t i = 0; i < MAX_TRAP_SLOTS; ++i) {
    if (read_slot(&s_slots[i]).owner_comp_uid != 0) {
      n += 1;
    }
  }
  return n;
}

extern "C" Capability __signetos_trap_dispatch(uint64_t mcause, uint64_t mtval,
                                               uint64_t mtval2,
                                               TrapFrame* frame) {
  const bool async = (mcause & INTERRUPT_BIT) != 0;
  const uint64_t mepc = capability_get_address(frame->mepcc);
  frame->flags = 0;
  frame->fault_status = 0;
  frame->handler_comp = nullptr;
  frame->handler_sp = nullptr;
  frame->handler_ca0 = nullptr;

  // A synchronous fault raised by kernel code is a kernel bug, and no handler
  // a compartment bound may stand in for the kernel: report and halt. Kernel
  // code is known by its PCC: only the kernel's own text runs with
  // AccessSystemRegs; every compartment entry, including the kernel-text
  // stubs the test suites run as compartments, is CodeRx without it. An
  // interrupt on kernel code is not a fault -- the switcher unmasks a few
  // instructions before it returns to its caller, and the trap vector a few
  // before it enters an exception handler and after it comes back -- and is
  // delivered like any other.
  if (!async &&
      (capability_get_perms(frame->mepcc) & perms::AccessSystemRegs) != 0) {
    trap_report("raised by kernel code (mepcc carries AccessSystemRegs)",
                mcause, mepc, mtval, mtval2,
                capability_get_address(frame->sp));
  }

  // A software interrupt is a poke from the kernel (trap.hpp, THE SOFTWARE
  // INTERRUPT IS THE KERNEL'S): the trap table has changed, so this hart
  // brings its `mie` and timer in line with it, and the interrupted context
  // resumes. The poke is cleared (this hart's `msip`) before the table is
  // read, so a poke sent after that sets it again and brings this hart back
  // here.
  if (mcause == IRQ_M_SOFT) {
    clint::clear_ipi();
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    sync_this_hart();
    return nullptr;
  }

  // A synchronous exception raised by compartment code is that compartment's
  // fault, for its own handler (fault.hpp). The per-vector table holds only
  // interrupts.
  if (!async) {
    return dispatch_fault(mcause, mtval, mtval2, frame);
  }

  // The slot is read once, into a copy (trap.hpp, `TrapSlot`). The dispatcher
  // never writes the table: a binding whose owner is gone is treated as
  // unbound here and left for `purge_compartment`, which destroy runs.
  size_t idx = 0;
  if (slot_index(mcause, &idx)) {
    const TrapSlot slot = read_slot(&s_slots[idx]);
    compartment::Compartment comp_info{};
    sentry::Entry entry{};
    if (slot.owner_comp_uid != 0 &&
        compartment::query(slot.owner_comp, &comp_info) &&
        comp_info.uid == slot.owner_comp_uid &&
        sentry::resolve(slot.target_sentry, &entry) == Status::Ok &&
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
      if (mcause == IRQ_M_TIMER) {
        // Re-arm before the handler runs: this clears MTIP, so a handler
        // that simply returns is safe, and the period does not drift with
        // the handler's running time.
        clint::set_timer(clint::now() + tick_ticks());
      }
      return deliver(frame, entry, h_sp, true, 0,
                     reinterpret_cast<Capability>(
                         static_cast<uintptr_t>(mcause)),
                     mtval2, true);
    }
  }

  // Unbound asynchronous interrupt: silence that source on this hart only
  // and return to the interrupted PC. With `mie` following the table this is
  // a hart whose poke has not arrived yet, or a binding whose owner has just
  // been destroyed. The timer is disarmed (MTIP can only be cleared by
  // reprogramming it); any other source has its `mie` bit cleared.
  if (mcause == IRQ_M_TIMER) {
    disarm_tick();
  } else {
    __asm__ volatile("csrc mie, %0" : : "r"(1ULL << (mcause & ~INTERRUPT_BIT)));
  }
  (void)mepc;
  return nullptr;
}

extern "C" uint64_t __signetos_trap_return(uint64_t verdict) {
  // Pop the handler's `TrapFrame`, scrub the stack loaned to the handler and
  // resume the interrupted code with the MIE it had -- or, if its
  // compartment has been destroyed and swept while the handler ran, the
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
      uart::print("[trap] ending thread ");
      uart::print_dec(thread::current_tid());
      uart::print(": trap return with nothing to return to\n");
    }
    thread::exit(-1);
    uart::panic("trap: trap return with nothing to return to");
  }
  return kind;
}

}  // namespace signetos::trap
