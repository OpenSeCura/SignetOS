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
 * sweeper.cpp - SignetOS Revocation Sweeper
 *
 * The thread that finishes revocation sweeps (revoke.hpp, A SWEEP). A sweep
 * is started by whoever wants memory back (`sys_revoke_start`), and from
 * then on a page is checked before the first capability is loaded from it,
 * at the expense of the thread that loads it. The pages nobody touches are
 * this thread's: it asks the kernel to check a few at a time
 * (`sys_revoke_step`) until none is left, which is what completes the sweep,
 * and sleeps while there is no sweep to finish.
 *
 * It is a thread like any other. `init` makes it on this compartment's
 * entry and registers it under a scheduler node of its own (init.cpp), and
 * that node's budget is all the processor time sweeping in the background
 * can take, whoever starts sweeps and however often: with the budget spent,
 * the sweep waits for the next period. Nothing here decides when a sweep
 * runs or what one costs.
 *
 * WHAT IT HOLDS
 *   `revoke_step`, the switcher, the console, `sched.block` to sleep, and
 *   `sentry` and `naming.publish` for its one entry point. No memory beyond
 *   its image, and no capability to anyone else's: the kernel does the
 *   checking, and tells it only whether a sweep is running.
 *
 *   sweeper.stop()   ends the thread, for the shell's `shutdown`: the machine
 *                    stops once no thread is left.
 *
 * The first invocation is `init`'s: it checks what it was given, publishes
 * `sweeper.stop` and says so. The second is the sweeper thread's, and returns
 * only once it has been stopped.
 */

#include "runtime.hpp"

namespace signetos::user {
namespace {

// SWEEP_STRESS=1 (Makefile), a test build: the sweeper also starts sweeps,
// one after another, and checks one page at a time with a sleep after each,
// so that pages stay stale for as long as possible.
#if defined(SIGNETOS_SWEEP_STRESS)
#define SWEEPER_STRESS_MANIFEST(X) M_SYSCALL(X, SYS_REVOKE_START, revoke_start)
#else
#define SWEEPER_STRESS_MANIFEST(X)
#endif

// --- What `sweeper` asks `init` for (user/manifest.hpp) ----------------------
#define SWEEPER_MANIFEST(X)                                  \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)          \
  M_SYSCALL(X, SYS_REVOKE_STEP, revoke_step)                 \
  M_SYSCALL(X, SYS_SENTRY, sentry)                           \
  M_SERVICE(X, UART_SENTRY, "uart")                          \
  M_SERVICE(X, SCHED_BLOCK, "sched.block")                   \
  M_SERVICE(X, NAMING_PUBLISH, "naming.publish")             \
  SWEEPER_STRESS_MANIFEST(X)
SIGNETOS_MANIFEST(SWEEPER_MANIFEST, 64 * 1024)

// Runtime slot: the entry point minted at startup.
constexpr size_t SLOT_STOP_ENTRY =
    compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 0;

// Pages asked for in one call. A call runs with interrupts masked, as every
// kernel call does, so this is how long the machine goes without one.
//
// How long it sleeps when no sweep is running, before it looks again: the
// longest a sweep that has just been started waits for it.
#if defined(SIGNETOS_SWEEP_STRESS)
constexpr size_t PAGES_PER_STEP = 1;
constexpr uint64_t IDLE_US = 2'000;  // and after every step
#else
constexpr size_t PAGES_PER_STEP = 16;
constexpr uint64_t IDLE_US = 20'000;
#endif

bool s_online = false;
bool s_stop = false;

}  // namespace

SIGNETOS_DEFAULT_FAULT_HANDLER("sweeper")

extern "C" int64_t sweeper_stop_entry() {
  __atomic_store_n(&s_stop, true, __ATOMIC_RELEASE);
  return 0;
}

extern "C" int64_t compartment_main(Capability arg) {
  (void)arg;
  Capability* rw = rw_table();
  const Capability gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  const Capability gate_step = rw[SLOT_SYS_REVOKE_STEP];
  const Capability uart_sentry = rw[SLOT_UART_SENTRY];
  const Capability sched_block = rw[SLOT_SCHED_BLOCK];

  if (!s_online) {
    const Capability self_comp = rw[compartment::SLOT_SELF];
    const Capability gate_sentry = rw[SLOT_SYS_SENTRY];
    const Capability naming_publish = rw[SLOT_NAMING_PUBLISH];
    if (!sealing::is_entry(gate_invoke) ||
        !sealing::is_sealed_as(OType::EntryPoint, gate_step) ||
        !sealing::is_sealed_as(OType::EntryPoint, gate_sentry) ||
        !sealing::is_sealed_as(OType::EntryPoint, sched_block) ||
        !sealing::is_sealed_as(OType::EntryPoint, naming_publish)) {
      return -1;
    }
    const Capability stop = mint_entry(
        gate_invoke, gate_sentry, self_comp,
        reinterpret_cast<const void*>(&sweeper_stop_entry));
    if (!sealing::is_sealed_as(OType::EntryPoint, stop) ||
        publish_name(gate_invoke, naming_publish, "sweeper.stop", stop) !=
            init::NAMING_OK) {
      print(gate_invoke, uart_sentry,
            "[sweeper]  WARNING: could not mint or publish sweeper.stop\n");
      return -1;
    }
    rw[SLOT_STOP_ENTRY] = stop;
    s_online = true;
    print(gate_invoke, uart_sentry,
          "[sweeper]  Revocation sweeper online: sweeper.stop published\n");
    return 0;
  }

  using FnStep = decltype(&sys_revoke_step);
  while (!__atomic_load_n(&s_stop, __ATOMIC_ACQUIRE)) {
    // 1: more pages. 0: no sweep is running. 2: the sweep waits for the
    // pager, and there is nothing to check meanwhile (syscall.hpp).
    const uint64_t left =
        syscall::call<FnStep>(gate_invoke, gate_step, PAGES_PER_STEP);
#if defined(SIGNETOS_SWEEP_STRESS)
    if (left == 0) {
      syscall::call<decltype(&sys_revoke_start)>(gate_invoke,
                                                 rw[SLOT_SYS_REVOKE_START]);
    }
    invoke<int64_t>(gate_invoke, sched_block, IDLE_US);
#else
    if (left != 1) {
      invoke<int64_t>(gate_invoke, sched_block, IDLE_US);
    }
#endif
  }
  return 0;
}

}  // namespace signetos::user
