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
 * fault.cpp - A program that exercises its compartment's fault handler
 *
 * Defines its own `compartment_error_handler` (signetos/fault.hpp,
 * user/entry.S), so the loader installs it, then faults on purpose.
 * `run fault.bin MODE`:
 *
 *   skip      an out-of-bounds load; the handler moves the pc past the load
 *             and returns INSTALL_CONTEXT. The program carries on after the
 *             load, reports what the handler saw and exits 0.
 *   retry     the same load; the handler returns INSTALL_CONTEXT unchanged
 *             twice (the load faults again each time), then skips it.
 *   fix       a load through a null `ca1`; the handler puts a valid
 *             capability in `ca1` and retries, so the load succeeds.
 *   unwind    the same out-of-bounds load; the handler returns UNWIND. The
 *             program's own activation is abandoned, so the thread ends and
 *             the shell reports that it returned without a status.
 *   double    the handler itself faults. A fault in a handler is never
 *             delivered: the kernel reports it and unwinds, as `unwind`.
 *   overflow  unbounded recursion until the stack runs out. There is no room
 *             below `csp` for the handler, so the kernel reports that and
 *             unwinds without running it.
 *   loop      the handler retries the same load unchanged, over and over.
 *             The kernel sets no limit; the handler keeps its own count and
 *             unwinds after LOOP_LIMIT faults.
 */

#include "runtime.hpp"

namespace signetos::user {
namespace {

#define FAULT_MANIFEST(X)                           \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke) \
  M_SERVICE(X, UART_SENTRY, "uart")
SIGNETOS_MANIFEST(FAULT_MANIFEST, 64 * 1024)

enum Mode : uint64_t {
  MODE_NONE,
  MODE_SKIP,
  MODE_RETRY,
  MODE_FIX,
  MODE_UNWIND,
  MODE_DOUBLE,
  MODE_OVERFLOW,
  MODE_LOOP,
  MODE_COUNT,
};
const char* const MODE_NAMES[MODE_COUNT] = {
    "", "skip", "retry", "fix", "unwind", "double", "overflow", "loop"};

Capability s_invoke = nullptr;
Capability s_uart = nullptr;
volatile uint64_t s_mode = MODE_NONE;

// What the handler saw, for the program to report after it resumes.
volatile uint64_t s_calls = 0;
volatile uint64_t s_mcause = 0;
volatile uint64_t s_mtval2 = 0;
volatile uint64_t s_depth = 0;

// How many faults `loop` takes before its handler gives up.
constexpr uint64_t LOOP_LIMIT = 10000;

alignas(16) volatile uint32_t s_small[4];
volatile uint32_t s_fixed = 42;  // what `fix` loads once the handler repairs

void out(const char* msg) { print(s_invoke, s_uart, msg); }
void out_dec(const char* p, uint64_t v, const char* s) {
  print_dec(s_invoke, s_uart, p, v, s);
}

// A load 64 bytes past the end of a 16-byte object: a CHERI bounds fault.
uint32_t load_out_of_bounds() {
  Capability c = capability_set_bounds(
      reinterpret_cast<Capability>(const_cast<uint32_t*>(&s_small[0])),
      sizeof(s_small));
  c = capability_set_address(c, capability_get_base(c) + 64);
  return *reinterpret_cast<volatile uint32_t*>(c);
}

// A load through `ca1` = `c`, in assembly so the register is known: the
// handler for `fix` repairs `ca1` in the ErrorState.
__attribute__((noinline)) uint32_t load_through_ca1(Capability c) {
  uint64_t v;
  __asm__ volatile(
      "cmv ca1, %1\n"
      "lw %0, 0(ca1)\n"
      : "=&r"(v)
      : "C"(c)
      : "a1", "memory");
  return static_cast<uint32_t>(v);
}

// Recurses until the stack is gone; the frame is big so that takes a while
// and the fault comes from a store through `csp`.
__attribute__((noinline)) uint64_t recurse(uint64_t n) {
  volatile uint64_t frame[32];
  for (uint64_t i = 0; i < 32; ++i) {
    frame[i] = n + i;
  }
  s_depth = n;
  if (n == ~0ULL) {
    return 0;  // never: the stack runs out long before
  }
  return recurse(n + 1) + frame[n & 31];
}

bool str_eq(const char* a, const char* b) {
  while (*a != '\0' && *a == *b) {
    ++a;
    ++b;
  }
  return *a == *b;
}

// Moves the pc past the faulting instruction and resumes there.
uint64_t skip(fault::ErrorState* state) {
  const uint64_t len = instruction_length(state->pc);
  if (len == 0) {
    return fault::UNWIND;
  }
  state->pc += len;
  return fault::INSTALL_CONTEXT;
}

}  // namespace

SIGNETOS_FAULT_HANDLER compartment_error_handler(fault::ErrorState* state) {
  s_calls = s_calls + 1;
  s_mcause = state->mcause;
  s_mtval2 = state->mtval2;
  switch (s_mode) {
    case MODE_SKIP:
      return skip(state);
    case MODE_RETRY:
      return (s_calls < 3) ? fault::INSTALL_CONTEXT : skip(state);
    case MODE_FIX:
      state->regs[fault::REG_A1] =
          reinterpret_cast<Capability>(const_cast<uint32_t*>(&s_fixed));
      return fault::INSTALL_CONTEXT;
    case MODE_LOOP:
      if (s_calls < LOOP_LIMIT) {
        return fault::INSTALL_CONTEXT;
      }
      out_dec("[fault]    handler: gave up after ", s_calls,
              " faults; unwinding\n");
      return fault::UNWIND;
    case MODE_DOUBLE:
      out("[fault]    handler: faulting inside the handler\n");
      return load_out_of_bounds();  // never returns
    default:
      out("[fault]    handler: unwinding\n");
      return fault::UNWIND;
  }
}

extern "C" int64_t compartment_main(Capability arg) {
  Capability* rw = rw_table();
  s_invoke = rw[SLOT_SYS_COMP_INVOKE];
  s_uart = rw[SLOT_UART_SENTRY];
  if (!sealing::is_sealed_as(OType::EntryPoint, s_uart)) {
    return -1;
  }
  if (!capability_is_valid(arg) || sealing::is_sealed(arg) ||
      !capability_has_perms(arg, perms::Load | perms::Store) ||
      capability_get_length(arg) < sizeof(init::AppRequest)) {
    return -1;
  }
  auto* req = reinterpret_cast<init::AppRequest*>(arg);
  req->args[init::APP_ARGS_MAX - 1] = '\0';

  for (uint64_t m = MODE_SKIP; m < MODE_COUNT; ++m) {
    if (str_eq(req->args, MODE_NAMES[m])) {
      s_mode = m;
    }
  }
  if (s_mode == MODE_NONE) {
    out("[fault]    usage: run fault.bin "
        "skip|retry|fix|unwind|double|overflow|loop\n");
    req->status = 1;
    return 1;
  }

  if (s_mode == MODE_OVERFLOW) {
    out("[fault]    recursing until the stack runs out\n");
    recurse(0);
    out("[fault]    BUG: came back from unbounded recursion\n");
    return -1;
  }

  uint32_t v = 0;
  if (s_mode == MODE_FIX) {
    out("[fault]    loading through a null ca1\n");
    v = load_through_ca1(nullptr);
  } else {
    out("[fault]    loading out of bounds\n");
    v = load_out_of_bounds();
  }
  const fault::Decoded d = fault::decode(s_mcause, s_mtval2);
  out_dec("[fault]    resumed after the load; handler ran ", s_calls,
          " time(s)");
  out_dec(", class ", d.cls, "");
  out_dec(", violation ", fault::detail_violation(d.detail), "");
  out_dec(", access ", fault::detail_access(d.detail), "");
  out_dec(", loaded ", v, "\n");
  req->status = 0;
  return 0;
}

}  // namespace signetos::user
