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
 * smp_selftest.cpp - Boot-time test of a sweep's start with a thread running
 * on another hart (SMP_SELFTEST=1)
 *
 * Every thread runs on the boot hart (DESIGN.md §4.4), so nothing in an
 * ordinary run shows what the start of a sweep does to a hart that is in
 * the middle of a compartment's code (revoke.hpp, SEVERAL HARTS). This puts
 * a thread there: a few instructions (smp_stub.S) that the first parked
 * hart is made to run, and that it goes on running, asleep, until the
 * machine stops.
 *
 * The thread holds a capability in a register and in a page of its own,
 * the box. The boot hart frees what the capability is to and starts a
 * sweep. The thread reports, in the box, that its register lost the tag
 * (only the stop can do that: its loop touches no memory), that the copy it
 * then loaded from the box had lost it (a load from a stale page, checked
 * on that hart), and that a capability to memory nobody freed kept its tag.
 * After that every sweep the system starts stops the thread again, and it
 * counts them; `smp_self_test_report` prints the count at power-off.
 */

#include <signetos/compartment.hpp>
#include <signetos/debug/report.hpp>
#include <signetos/hw/clint.hpp>
#include <signetos/hw/uart.hpp>
#include <signetos/quota.hpp>
#include <signetos/revoke.hpp>
#include <signetos/sentry.hpp>
#include <signetos/smp.hpp>
#include <signetos/thread.hpp>
#include <signetos/vm.hpp>

namespace signetos::debug {
namespace {

constexpr uint64_t PAGE = vm::PAGE_SIZE;

// The box (smp_stub.S has the same offsets): capabilities by slot, words by
// index.
constexpr size_t SLOT_VICTIM = 0;
constexpr size_t SLOT_SELF = 1;
constexpr size_t WORD_STATE = 8;
constexpr size_t WORD_IN_PAGE = 9;
constexpr size_t WORD_KEPT = 10;
constexpr size_t WORD_ROUNDS = 11;
constexpr size_t WORD_LOST = 12;

// The thread, until the hart it is for has taken it; that hart; and the box,
// which is never freed. Only its words are read through this: integers.
Capability s_thread = nullptr;
uint64_t s_hart = ~0ULL;
volatile uint64_t* s_words = nullptr;

void check(bool ok, const char* what) {
  if (!ok) {
    uart::print("[smp]      self-test FAILED: ");
    uart::print(what);
    uart::print("\n");
    panic("smp self-test");
  }
}

// Until word `index` of the box has reached `value`, or for a while: a few
// seconds under QEMU, which runs one hart at a time and gives the other hart
// its turn every tenth of a second. The other hart is doing the work; this
// one only has to keep out of its way.
bool wait_for(size_t index, uint64_t value) {
  for (uint64_t i = 0; i < 400'000'000ULL; ++i) {
    if (s_words[index] >= value) {
      return true;
    }
  }
  return false;
}

}  // namespace

void smp_self_test(Capability vm_root, Capability thread_root) {
  const uint64_t others =
      smp::online_mask() & ~(1ULL << thread::this_hart());
  if (others == 0) {
    uart::print("[smp]      self-test skipped: this machine has one hart\n");
    return;
  }
  uint64_t hart = 0;
  while (((others >> hart) & 1) == 0) {
    hart += 1;
  }

  // A compartment with two pages: the box, and the page to be freed.
  Capability q = quota::derive(vm_root, 64 * PAGE, perms::Load | perms::Store);
  Capability comp = compartment::create(q, nullptr, 0);
  Capability box = compartment::allocate(comp, q, PAGE, 0);
  Capability victim = compartment::allocate(comp, q, PAGE, 0);
  check(capability_is_valid(box) && capability_is_valid(victim),
        "a compartment with two pages");
  auto* slots = reinterpret_cast<volatile Capability*>(box);
  s_words = reinterpret_cast<volatile uint64_t*>(box);
  slots[SLOT_VICTIM] = victim;
  slots[SLOT_SELF] = box;

  // Its code: the stub, entered as that compartment's.
  Capability pcc = nullptr;
  Capability first = nullptr;
  Capability last = nullptr;
  __asm__ volatile("auipcc %0, 0" : "=C"(pcc));
  __asm__ volatile("llc %0, __smp_test_thread" : "=C"(first));
  __asm__ volatile("llc %0, __smp_test_thread_end" : "=C"(last));
  const Capability code = capability_set_bounds(
      capability_set_address(pcc, capability_get_address(first)),
      capability_get_address(last) - capability_get_address(first));
  const Capability entry = sentry::create_kernel(comp, code, perms::CodeRx);
  check(capability_is_valid(entry), "an entry point over the stub");
  const Capability t = thread::create(thread_root, 4 * PAGE, entry, box);
  check(capability_is_valid(t), "a thread for it");

  // Handed to the other hart, which is parked and takes it at its next poke
  // (`smp_self_test_poke`).
  s_thread = t;
  __atomic_store_n(&s_hart, hart, __ATOMIC_RELEASE);
  clint::send_ipi(1ULL << hart);
  check(wait_for(WORD_STATE, 1),
        "the other hart runs the thread, which holds the capability");
  check(thread::state_on(hart) != 0, "and the kernel knows it runs a thread");

  // Freed, and a sweep started and left alone: this hart checks no page.
  check(compartment::deallocate(comp, q, victim) == Status::Ok,
        "free what the capability is to");
  const uint64_t epoch = revoke::start();
  check(revoke::completed_epoch() < epoch,
        "a sweep has started and is not complete");
  check(wait_for(WORD_STATE, 2),
        "the thread's register lost its tag when the sweep started");
  check(wait_for(WORD_STATE, 3), "the thread went on and reported");
  check(s_words[WORD_IN_PAGE] == 1,
        "the copy it loaded from its page had lost its tag too");
  check(s_words[WORD_KEPT] == 2,
        "a capability to memory that was not freed kept its tag");
  check(!vm::is_stale(capability_get_base(box)),
        "its page was checked on its own hart, by that load");

  while (revoke::step(revoke::STEP_MAX) == revoke::STEP_MORE) {
  }
  check(revoke::completed_epoch() == epoch, "the sweep completes");
  uart::print("[smp]      self-test passed: hart ");
  uart::print_dec(hart);
  uart::print(" ran a thread through the start of a sweep\n");
}

void smp_self_test_poke() {
  if (thread::this_hart() != __atomic_load_n(&s_hart, __ATOMIC_ACQUIRE) ||
      !capability_is_valid(s_thread)) {
    return;
  }
  const Capability t = s_thread;
  s_thread = nullptr;
  // Comes back only if the switch is refused or the thread has ended, and
  // it is meant to do neither.
  thread::dispatch(t);
  check(false, "the thread stayed on its hart");
}

void smp_self_test_report() {
  if (s_words == nullptr) {
    return;
  }
  uart::print("[smp]      the thread on hart ");
  uart::print_dec(s_hart);
  uart::print(": stopped for ");
  uart::print_dec(s_words[WORD_ROUNDS]);
  uart::print(" more sweeps, and ");
  uart::print(s_words[WORD_LOST] == 0 ? "kept" : "LOST");
  uart::print(" its capability\n");
}

}  // namespace signetos::debug
