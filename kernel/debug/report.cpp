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
 * report.cpp - The kernel's diagnostics, as console text (debug/report.hpp)
 */

#include <signetos/debug/report.hpp>
#include <signetos/hw/uart.hpp>
#include <signetos/thread.hpp>

namespace signetos::debug {
namespace {

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

}  // namespace

[[noreturn]] void panic(const char* msg) {
  uart::halting();
  uart::print("[PANIC] ");
  uart::print(msg);
  uart::print("\n");
  uart::qemu_poweroff(1);
}

//
// Reports a synchronous exception and halts the machine.
//
// why    - one line on why nothing short of halting is possible
// mcause - machine cause register; the interrupt bit is known to be clear
// mepc   - address of the faulting instruction, read out of mepcc
// mtval  - trap value register; its meaning depends on the cause
// mtval2 - for a CHERI fault, which capability check failed
// sp     - stack pointer at the point of the fault, for orientation
//
void trap_report(const char* why, uint64_t mcause, uint64_t mepc,
                              uint64_t mtval, uint64_t mtval2, uint64_t sp) {
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
  field("sp    ", sp);

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
  uart::print_dec(thread::current_tid());
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

void thread_ending(const char* who, const char* why) {
  uart::print("[");
  uart::print(who);
  uart::print("] ending thread ");
  uart::print_dec(thread::current_tid());
  uart::print(": ");
  uart::print(why);
  uart::print("\n");
}

void harts_online(uint64_t online, uint64_t total, uint64_t boot_hart) {
  uart::print("[smp]      ");
  uart::print_dec(online);
  uart::print("/");
  uart::print_dec(total);
  uart::print(" hart(s) online in M-mode (boot hart ");
  uart::print_dec(boot_hart);
  uart::print(")\n");
}

void boot_capability(const char* label, Capability cap) {
  uart::print_cap(label, cap);
}

#ifdef SIGNETOS_TRACE_SWITCH
// The kernel UART is polled, so this is safe on the masked tick path.
void trace_switch(uint64_t prev_tid, uint64_t tid) {
  uart::print("[switch] ");
  if (prev_tid != 0) {
    uart::print("tid ");
    uart::print_dec(prev_tid);
  } else {
    uart::print("host");
  }
  uart::print(" -> tid ");
  uart::print_dec(tid);
  uart::print("\n");
}
#endif

}  // namespace signetos::debug
