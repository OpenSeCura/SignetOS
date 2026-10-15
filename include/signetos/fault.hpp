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
// fault.hpp - Per-compartment fault handlers: the ABI shared by the kernel and
// compartments
//
// The kernel provides mechanism only. What a fault means, and what to do
// about it, is the faulting compartment's business.
//
// WHO HANDLES A FAULT
// -------------------
// A synchronous exception raised by compartment code (a CHERI fault, an
// illegal instruction, a misaligned access, ...) is handled by THAT
// compartment, never by another one: by its fault handler, one entry point
// held in a kernel-written field of its descriptor (compartment.hpp).
//
// WHAT THE KERNEL DOES
// --------------------
//   1. Copies the faulting register file into an ErrorState at the top of
//      the stack below the faulting `csp` (the program counter as a plain
//      address: the handler never holds the faulting PCC).
//   2. Runs the handler on the rest of that stack, below the ErrorState, with
//      `ca0` = the ErrorState and `cgp` = the compartment's own table.
//   3. If the handler returns INSTALL_CONTEXT, loads the register file back
//      from the ErrorState and resumes at its `pc`. The resumed PCC is the
//      faulting PCC with only its address changed, so a handler can move the
//      program counter within its own code and nowhere else. Anything else
//      unwinds: the faulting activation is abandoned, its caller gets
//      Status::Faulted in a0, and a thread whose own code faulted (no caller)
//      ends.
//
// Skipping the faulting instruction, retrying it, repairing a register or
// jumping to a recovery point are all edits the handler makes to the
// ErrorState before returning INSTALL_CONTEXT.
//
// WHEN THE KERNEL UNWINDS WITHOUT ASKING
// --------------------------------------
//   - The compartment has no handler.
//   - There is no room below the faulting `csp` for the ErrorState plus the
//     handler's `min_stack`.
//   - The fault is inside the handler itself (it is never delivered again).
// Each is reported on the console.
//
// There is no limit on how often one activation may fault. A handler that
// keeps resuming code that keeps faulting is a busy loop like any other: no
// kernel state grows (INSTALL_CONTEXT pops the trap frame before the code
// runs again), the tick still preempts it, and a kill takes effect the next
// time the handler returns. A compartment that wants a limit counts in its
// own handler.
//
// HOW A HANDLER IS INSTALLED
// --------------------------
// `sys_sentry(comp, code, KIND_HANDLER)`. The code must lie in `comp`'s own
// memory (as for any entry point), the handle needs Permit_Store, and the
// handler can be set once. The record is marked as a fault entry, which the
// switcher, `sys_thread_create` and `sys_trap_bind` all refuse, and its
// handle is never handed back: only the fault path can enter it. The loader
// installs it from the image header (`compartment_error_handler`;
// user/entry.S) before the compartment's first instruction, if the image
// defines one: a handler is optional. Most use the runtime's default
// (`SIGNETOS_DEFAULT_FAULT_HANDLER`, user/runtime.hpp), which prints one line
// describing the fault and unwinds.
//

#include <stdint.h>

#include <signetos/types.hpp>

namespace signetos::fault {

// The faulting context, as the handler sees it (`ca0`). `regs[n]` is
// register xn (`regs[0]`, x0, is always null): REG_* below.
struct alignas(16) ErrorState {
  Capability regs[32];
  uint64_t pc;      // address of the faulting instruction; where an
                    // INSTALL_CONTEXT resumes
  uint64_t mcause;  // the raw trap cause
  uint64_t mtval;   // the raw trap value (the faulting address, usually)
  uint64_t mtval2;  // the raw CHERI fault information (decode() below)
};
static_assert(sizeof(ErrorState) == 34 * sizeof(Capability),
              "ErrorState is 32 capabilities and four integers");

// clang-format off
enum Reg : uint32_t {
  REG_RA = 1, REG_SP = 2, REG_GP = 3, REG_TP = 4,
  REG_T0 = 5, REG_T1 = 6, REG_T2 = 7,
  REG_S0 = 8, REG_S1 = 9,
  REG_A0 = 10, REG_A1 = 11, REG_A2 = 12, REG_A3 = 13,
  REG_A4 = 14, REG_A5 = 15, REG_A6 = 16, REG_A7 = 17,
  REG_S2 = 18, REG_S11 = 27,
  REG_T3 = 28, REG_T6 = 31,
};
// clang-format on

// What the handler wants done (a0 on return). INSTALL_CONTEXT is
// deliberately unlikely, so that a handler returning garbage unwinds.
enum Verdict : uint64_t {
  UNWIND = 0,
  INSTALL_CONTEXT = 0x5e5e,
};

// `sys_sentry`'s `kind`.
enum Kind : uint64_t {
  KIND_ENTRY = 0,    // an ordinary entry point: the handle is returned
  KIND_HANDLER = 1,  // install as the compartment's fault handler
};

// --- Decoding (for handlers; the kernel does not interpret faults) ----------

// What kind of fault it was, derived from `mcause`.
enum Class : uint64_t {
  CLASS_CAPABILITY = 1,       // a CHERI check failed; see `detail`
  CLASS_ILLEGAL_INSTRUCTION,  // mcause 2
  CLASS_MISALIGNED,           // mcause 0, 4, 6
  CLASS_MEMORY,      // access and page faults: mcause 1, 5, 7, 12, 13, 15
  CLASS_BREAKPOINT,  // mcause 3
  CLASS_ECALL,       // mcause 8, 9, 11 (nothing is an ecall here)
  CLASS_OTHER,       // anything else
};

// For CLASS_CAPABILITY, `detail` = violation | (access << 8).
enum Violation : uint64_t {
  VIOLATION_TAG = 0,         // the capability was not valid
  VIOLATION_SEAL = 1,        // the capability was sealed
  VIOLATION_PERMISSION = 2,  // it lacked a permission the access needed
  VIOLATION_ADDRESS = 3,     // the address was not representable / invalid
  VIOLATION_BOUNDS = 4,      // the access was outside base..top
  VIOLATION_UNKNOWN = 0xff,
};

enum Access : uint64_t {
  ACCESS_FETCH = 0,  // instruction fetch
  ACCESS_DATA = 1,   // load or store
  ACCESS_JUMP = 2,   // branch or jump target
  ACCESS_UNKNOWN = 0xff,
};

// The CHERI fault cause on this implementation (one code for every CHERI
// check; `mtval2` says which).
constexpr uint64_t MCAUSE_CHERI = 28;

constexpr uint64_t detail_violation(uint64_t detail) { return detail & 0xff; }
constexpr uint64_t detail_access(uint64_t detail) {
  return (detail >> 8) & 0xff;
}

// `mcause` (and, for a CHERI fault, `mtval2`) as a Class and, for
// CLASS_CAPABILITY, a detail.
struct Decoded {
  uint64_t cls;
  uint64_t detail;
};
constexpr Decoded decode(uint64_t mcause, uint64_t mtval2) {
  switch (mcause) {
    case MCAUSE_CHERI: {
      const uint64_t v = mtval2 & 0xffff;
      const uint64_t a = (mtval2 >> 16) & 0xff;
      return {CLASS_CAPABILITY,
              (v <= VIOLATION_BOUNDS ? v : VIOLATION_UNKNOWN) |
                  ((a <= ACCESS_JUMP ? a : ACCESS_UNKNOWN) << 8)};
    }
    case 2:
      return {CLASS_ILLEGAL_INSTRUCTION, 0};
    case 0:
    case 4:
    case 6:
      return {CLASS_MISALIGNED, 0};
    case 1:
    case 5:
    case 7:
    case 12:
    case 13:
    case 15:
      return {CLASS_MEMORY, 0};
    case 3:
      return {CLASS_BREAKPOINT, 0};
    case 8:
    case 9:
    case 11:
      return {CLASS_ECALL, 0};
    default:
      return {CLASS_OTHER, 0};
  }
}

// Names for a console report.
constexpr const char* class_name(uint64_t cls) {
  switch (cls) {
    case CLASS_CAPABILITY:
      return "CHERI fault";
    case CLASS_ILLEGAL_INSTRUCTION:
      return "illegal instruction";
    case CLASS_MISALIGNED:
      return "misaligned access";
    case CLASS_MEMORY:
      return "access or page fault";
    case CLASS_BREAKPOINT:
      return "breakpoint";
    case CLASS_ECALL:
      return "ecall";
    default:
      return "unknown fault";
  }
}
constexpr const char* violation_name(uint64_t violation) {
  switch (violation) {
    case VIOLATION_TAG:
      return "tag";
    case VIOLATION_SEAL:
      return "seal";
    case VIOLATION_PERMISSION:
      return "permission";
    case VIOLATION_ADDRESS:
      return "address";
    case VIOLATION_BOUNDS:
      return "bounds";
    default:
      return "unknown";
  }
}
constexpr const char* access_name(uint64_t access) {
  switch (access) {
    case ACCESS_FETCH:
      return "instruction fetch";
    case ACCESS_DATA:
      return "data access";
    case ACCESS_JUMP:
      return "branch or jump";
    default:
      return "unknown access";
  }
}

}  // namespace signetos::fault
