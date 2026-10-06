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
 * asynchronous interrupt reaches the supervisor trap vector.
 *
 * A synchronous fault raised by kernel code (`sepcc` carries AccessSystemRegs)
 * is a kernel bug: `trap_report()` prints it and halts, whatever is bound.
 *
 * Otherwise, if a compartment has bound an `OType::EntryPoint` (CT = 12)
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
 * (the timer is disarmed, any other has its `sie` bit cleared) and returned
 * from; an unbound synchronous exception is reported and halts the machine.
 *
 * Each hart keeps its `sie` and timer in line with the trap table, and the
 * software interrupt is the kernel's own poke that tells a hart to do so
 * (see trap.hpp, SEVERAL HARTS and THE SOFTWARE INTERRUPT IS THE KERNEL'S).
 *
 * The kernel also owns the periodic tick behind `IRQ_S_TIMER` (see trap.hpp,
 * THE KERNEL TICK), and decides which `SIE` a handler runs with and which
 * the interrupted context resumes with (see asm_macros.h, INTERRUPT MASKING
 * RULE).
 */

#include <signetos/asm_macros.h>
#include <signetos/compartment.hpp>
#include <signetos/inspect.hpp>
#include <signetos/lock.hpp>
#include <signetos/sbi.hpp>
#include <signetos/sealing.hpp>
#include <signetos/sentry.hpp>
#include <signetos/thread.hpp>
#include <signetos/trap.hpp>
#include <signetos/uart.hpp>
#include <signetos/vm.hpp>
#include <stddef.h>
#include <stdint.h>

using namespace signetos;

namespace {

// `_early_trap_entry` addresses the frame by these offsets.
static_assert(offsetof(trap::TrapFrame, sepcc) == TRAP_FRAME_SEPCC);
static_assert(offsetof(trap::TrapFrame, handler_sp) == TRAP_FRAME_HANDLER_SP);
static_assert(offsetof(trap::TrapFrame, handler_rw_table) ==
              TRAP_FRAME_RW_TABLE);
static_assert(offsetof(trap::TrapFrame, sstatus) == TRAP_FRAME_SSTATUS);
static_assert(offsetof(trap::TrapFrame, handler_sie) ==
              TRAP_FRAME_HANDLER_SIE);
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
// check failed separately in stval2. Verified against the running machine and
// against target/riscv/cpu_bits.h in the QEMU tree:
//     RISCV_EXCP_CHERI = 0x1c
constexpr uint64_t kCheriFault = 28;

// stval2 layout for scause 28, from cpu_helper.c:
//     cheri_exc_info = cheri093_cap_cause(cause) | (type << 16)
// Values from Cheri093CapExcCause / Cheri093CapExcType in
// target/riscv/cheri-archspecific-early.h.
const char* cheri_violation(uint64_t stval2) {
  switch (stval2 & 0xffff) {
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

const char* cheri_access(uint64_t stval2) {
  switch ((stval2 >> 16) & 0xff) {
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
// scause - supervisor cause register; the interrupt bit is known to be clear
// sepc   - address of the faulting instruction, read out of sepcc
// stval  - trap value register; its meaning depends on the cause
// stval2 - for a CHERI fault, which capability check failed
// ssp    - stack pointer at the point of the fault, for orientation
//
[[noreturn]] void trap_report(const char* why, uint64_t scause, uint64_t sepc,
                              uint64_t stval, uint64_t stval2, uint64_t ssp) {
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
  uart::print("  scause : ");
  uart::print_dec(scause);
  const char* text = cause_text(scause);
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
  if (scause == kCheriFault) {
    uart::print("  detail : ");
    uart::print(cheri_violation(stval2));
    uart::print(", on ");
    uart::print(cheri_access(stval2));
    uart::print("\n");
  }

  // sepc is the instruction that faulted, not the one after it, so the
  // address can be looked up directly in the disassembly:
  //   llvm-objdump -d --start-address=0x... signetos.elf
  field("sepc  ", sepc);

  // The address the instruction was trying to reach.
  field("stval ", stval);
  field("stval2", stval2);
  field("sp    ", ssp);

  uart::print(
      "########################################################################"
      "########\n");

  // Exit non-zero so a scripted run can tell a fault from a clean finish.
  uart::qemu_poweroff(1);
}

}  // namespace

namespace signetos::trap {
namespace {

SpinLock s_lock;
TrapSlot s_slots[MAX_TRAP_SLOTS];

// `sie` and `sip` bits. `SSTATUS_SPIE` comes from asm_macros.h.
constexpr uint64_t SIE_SSIE = 1ULL << 1;
constexpr uint64_t SIE_STIE = 1ULL << 5;
constexpr uint64_t SIP_SSIP = 1ULL << 1;
constexpr uint64_t SOFT_CODE = IRQ_S_SOFT & ~INTERRUPT_BIT;
constexpr uint64_t TIMER_CODE = IRQ_S_TIMER & ~INTERRUPT_BIT;

uint64_t tick_ticks() { return sbi::us_to_ticks(TICK_US); }

// The harts that have run `init_hart`, one bit per hart number: the harts a
// poke is sent to.
uint64_t s_harts_up = 0;

void arm_tick() {
  __asm__ volatile("csrs sie, %0" : : "r"(SIE_STIE));
  sbi::set_timer(sbi::now() + tick_ticks());
}

// Clears STIE as well, so on each hart STIE is set exactly while that hart's
// tick is armed (`sync_this_hart` reads it that way).
void disarm_tick() {
  sbi::set_timer(sbi::TIMER_OFF);
  __asm__ volatile("csrc sie, %0" : : "r"(SIE_STIE));
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

// Brings this hart's `sie` and timer in line with the trap table: the poke
// bit always set, every other interrupt's bit set exactly while its slot is
// bound, and the tick armed exactly while the timer slot is bound. Nothing
// here is device-specific: code 9 is one bit like the rest, and what sits
// behind it is `trap_mgr`'s business.
void sync_this_hart() {
  uint64_t on = SIE_SSIE;
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
  __asm__ volatile("csrs sie, %0" : : "r"(on));
  __asm__ volatile("csrc sie, %0" : : "r"(off));

  uint64_t sie = 0;
  __asm__ volatile("csrr %0, sie" : "=r"(sie));
  const bool armed = (sie & SIE_STIE) != 0;
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
    sbi::send_ipi(others);
  }
}

bool slot_index(uint64_t scause, size_t* out_idx) {
  const uint64_t code = scause & ~INTERRUPT_BIT;
  if ((scause & INTERRUPT_BIT) != 0) {
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
                                         uint64_t scause, uint64_t stval,
                                         uint64_t stval2,
                                         const TrapFrame* frame) {
  const uint64_t sepc = capability_get_address(frame->sepcc);
  uart::print("[trap] ending thread ");
  uart::print_dec(thread::current_tid());
  uart::print(": ");
  uart::print(why);
  uart::print(" (");
  uart::print(status_name(status));
  uart::print("), scause 0x");
  uart::print_hex64(scause);
  uart::print(" at 0x");
  uart::print_hex64(sepc);
  uart::print("\n");
  if (scause == IRQ_S_TIMER) {
    sbi::set_timer(sbi::now() + tick_ticks());
  }
  thread::exit(-1);
  trap_report("in host context, and the host cannot take this trap", scause,
              sepc, stval, stval2, capability_get_address(frame->sp));
}

Capability advance_sync_sepcc(Capability sepcc) {
  const uint64_t addr = capability_get_address(sepcc);
  uint64_t step = 4;
  if (capability_is_valid(sepcc) && !sealing::is_sealed(sepcc) &&
      (capability_get_perms(sepcc) & perms::Load) != 0) {
    const uint64_t base = capability_get_base(sepcc);
    const uint64_t len = capability_get_length(sepcc);
    if (addr >= base && addr + 2 <= base + len) {
      const uint16_t insn16 = *reinterpret_cast<const uint16_t*>(sepcc);
      if ((insn16 & 0x3u) != 0x3u) {
        step = 2;
      }
    }
  }
  return capability_set_address(sepcc, addr + step);
}

}  // namespace

void init() {
  s_lock = SpinLock{};
  for (TrapSlot& slot : s_slots) {
    slot = TrapSlot{};
  }
}

void init_hart() {
  // A known start, so that STIE means "this hart's tick is armed" from here
  // on: only the poke bit on, the timer off.
  sbi::set_timer(sbi::TIMER_OFF);
  __asm__ volatile("csrw sie, %0" : : "r"(SIE_SSIE));

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

Capability authority_for(uint64_t scause) {
  // The software interrupt is the kernel's poke (trap.hpp, THE SOFTWARE
  // INTERRUPT IS THE KERNEL'S). Nobody may bind it, so no authority for it
  // exists.
  if (scause == IRQ_S_SOFT) {
    return nullptr;
  }
  size_t idx = 0;
  if (!slot_index(scause, &idx)) {
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

bool is_bound(uint64_t scause, uint64_t* out_owner_uid) {
  size_t idx = 0;
  if (!slot_index(scause, &idx)) {
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

extern "C" Capability __signetos_trap_dispatch(uint64_t scause, uint64_t stval,
                                               uint64_t stval2,
                                               TrapFrame* frame) {
  const bool async = (scause & INTERRUPT_BIT) != 0;
  const uint64_t sepc = capability_get_address(frame->sepcc);

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
      (capability_get_perms(frame->sepcc) & perms::AccessSystemRegs) != 0) {
    trap_report("raised by kernel code (sepcc carries AccessSystemRegs)",
                scause, sepc, stval, stval2,
                capability_get_address(frame->sp));
  }

  // A software interrupt is a poke from the kernel (trap.hpp, THE SOFTWARE
  // INTERRUPT IS THE KERNEL'S): the trap table has changed, so this hart
  // brings its `sie` and timer in line with it, and the interrupted context
  // resumes. SSIP is cleared before the table is read, so a poke sent after
  // that sets it again and brings this hart back here.
  if (scause == IRQ_S_SOFT) {
    __asm__ volatile("csrc sip, %0" : : "r"(SIP_SSIP));
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    sync_this_hart();
    return nullptr;
  }

  // The slot is read once, into a copy (trap.hpp, `TrapSlot`). The dispatcher
  // never writes the table: a binding whose owner is gone is treated as
  // unbound here and left for `purge_compartment`, which destroy runs.
  size_t idx = 0;
  if (slot_index(scause, &idx)) {
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
                               Status::NoKernelStack, scause, stval, stval2,
                               frame);
      }
      Status status = Status::Ok;
      Capability h_sp =
          handler_stack(frame->sp, entry.min_stack, frame, &status);
      if (!capability_is_valid(h_sp)) {
        end_interrupted_thread("its stack cannot host the handler", status,
                               scause, stval, stval2, frame);
      }

      // The interrupted thread is inside the handler's compartment while the
      // handler runs (compartment.hpp, WHO IS INSIDE). If that compartment is
      // being destroyed, the binding is as good as gone: the trap is handled
      // below as unbound.
      if (thread::enter_compartment(entry.owner) == Status::Ok) {
        frame->active_kernel_sp = thread::current_kernel_sp();
        thread::set_kernel_sp(reinterpret_cast<Capability>(frame));
        frame->handler_sp = h_sp;
        frame->handler_rw_table = compartment::table_writable(slot.owner_comp);

        // The SIE the handler runs with (asm_macros.h, INTERRUPT MASKING
        // RULE): an interrupt handler, masked; an exception handler, the
        // interrupted code's. Unmasked, it can be interrupted at its first
        // instruction, so, like an unmasked callee (KERNEL-STACK ROOM, check
        // 2), it also needs room for one more `TrapFrame` that still passes
        // check 3; with less it runs masked.
        //
        // `sstatus` is as the trap left it: its SPIE is the SIE the
        // interrupted code had (the dispatcher runs masked, so nothing has
        // changed it since). The copy recorded here is what
        // `__signetos_trap_return` resumes the interrupted code with.
        uint64_t sstatus = 0;
        __asm__ volatile("csrr %0, sstatus" : "=r"(sstatus));
        const bool unmasked =
            !async && (sstatus & SSTATUS_SPIE) != 0 &&
            thread::kernel_stack_free(reinterpret_cast<Capability>(frame)) >=
                TRAP_FRAME_SIZE + RET_FRAME_MIN_FREE;
        frame->sstatus = sstatus;
        frame->handler_sie = unmasked ? SSTATUS_SIE : 0;

        // User-space trap delivery: verify that the bound handler's hardware sentry (`ct0`), narrowed
        // stack capability (`csp`), and capability table (`ca4`/`cgp`) are
        // restricted and do not overlap kernel memory before `early_trap.S`
        // enters the handler.
        inspect::assert_user_capability(entry.sentry,
                                        "trap_dispatch:hw_sentry");
        inspect::assert_user_capability(frame->handler_sp,
                                        "trap_dispatch:handler_sp");
        inspect::assert_user_capability(frame->handler_rw_table,
                                        "trap_dispatch:rw_table");

        if (async) {
          if (scause == IRQ_S_TIMER) {
            // Re-arm before the handler runs: this clears STIP, so a handler
            // that simply returns is safe, and the period does not drift
            // with the handler's running time.
            sbi::set_timer(sbi::now() + tick_ticks());
          }
        } else if (scause != EXC_INST_PAGE_FAULT &&
                   scause != EXC_LOAD_PAGE_FAULT &&
                   scause != EXC_STORE_PAGE_FAULT) {
          frame->sepcc = advance_sync_sepcc(frame->sepcc);
        }
        return entry.sentry;
      }
    }
  }

  // Unbound asynchronous interrupt: silence that source on this hart only
  // and return to the interrupted PC. With `sie` following the table this is
  // a hart whose poke has not arrived yet, or a binding whose owner is being
  // destroyed. The timer is disarmed (STIP can only be cleared by
  // reprogramming it); any other source has its `sie` bit cleared.
  if (async) {
    if (scause == IRQ_S_TIMER) {
      disarm_tick();
    } else {
      __asm__ volatile("csrc sie, %0" : : "r"(1ULL << (scause & ~INTERRUPT_BIT)));
    }
    return nullptr;
  }

  // Unbound synchronous exception: report and halt.
  trap_report("no handler is bound to this exception", scause, sepc, stval,
              stval2, capability_get_address(frame->sp));
}

extern "C" TrapFrame* __signetos_trap_return() {
  TrapFrame* frame = reinterpret_cast<TrapFrame*>(thread::current_kernel_sp());
  thread::set_kernel_sp(frame->active_kernel_sp);

  // Scrub the stack region loaned to the handler, `[base, top)` of the
  // narrowed `handler_sp`, so nothing the handler left behind reaches the
  // interrupted thread (the same rule `__signetos_switcher_return` applies
  // to a callee's stack).
  Capability h_sp = frame->handler_sp;
  if (capability_is_valid(h_sp)) {
    const uint64_t base = capability_get_base(h_sp);
    const size_t count = capability_get_length(h_sp) / sizeof(Capability);
    Capability* slot =
        reinterpret_cast<Capability*>(capability_set_address(h_sp, base));
    for (size_t i = 0; i < count; ++i) {
      slot[i] = nullptr;
    }
  }

  // `sret` sets `SIE := SPIE`. The SPIE the hardware holds now is stale if
  // anything trapped or switched threads while the handler ran, so set it
  // from the `sstatus` recorded when this trap was taken: the interrupted
  // code resumes with exactly the SIE it had.
  thread::left_compartment();
  if ((frame->sstatus & SSTATUS_SPIE) != 0) {
    __asm__ volatile("csrs sstatus, %0" : : "r"(SSTATUS_SPIE));
  } else {
    __asm__ volatile("csrc sstatus, %0" : : "r"(SSTATUS_SPIE));
  }
  return frame;
}

}  // namespace signetos::trap
