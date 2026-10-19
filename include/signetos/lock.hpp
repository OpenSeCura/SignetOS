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
 * lock.hpp - The kernel's locks
 *
 * WHAT IS LOCKED
 * --------------
 * Kernel state is protected by per-object locks and fine-grained subsystem
 * locks rather than a single global kernel lock:
 *
 *   1. `Compartment::lock`  per-compartment lock protecting `ranges` and
 *                           `entries` chains (at most one held at a time).
 *   2. `QuotaNode::lock`    per-quota-node lock protecting the node's ledger
 *                           counters, flags and child list. Only
 *                           `quota::destroy`'s walk down a subtree holds more
 *                           than one, each parent's taken before its
 *                           child's (quota.hpp, LOCKING).
 *   3. `revoke::s_lock`     protects the revocation marks (revoke.hpp,
 *                           MARKING RANGES) and the epochs, and serializes
 *                           sweeps.
 *   4. `Tree::owed_lock`    leaf lock protecting a quota tree's owed list
 *                           (quota.hpp, OWED).
 *   5. `vm::s_lock`         protects the virtual address free list and Sv39
 *                           page tables (never held while zeroing pages).
 *   6. `frame::s_lock`      leaf lock protecting the physical frame bitmap.
 *   7. `irq::s_lock`        leaf lock serializing the two handler installs
 *                           (`irq::install`).
 *   8. `uart::s_lock`       leaf lock protecting console line output.
 *
 * Locks are acquired strictly in the order listed above (outermost to
 * innermost). Pure capability-derivation and read-only syscalls (`sys_seal`,
 * `sys_unseal`, `sys_type_mint`, `sys_type_derive`, `sys_revoke_query`,
 * `sys_thread_tid`) take no lock at all.
 *
 * A revocation sweep refunds what quota nodes are owed after it has let go
 * of `revoke::s_lock`. It runs only when asked for (`sys_revoke_sweep`, or the
 * boot self-test), never inside another kernel call.
 *
 * HOW IT IS SAFE TO HOLD
 * ----------------------
 * Kernel code always runs with interrupts masked (asm_macros.h, INTERRUPT
 * MASKING RULE), so a hart holding a lock cannot be preempted, switched away
 * from, or re-entered: a lock is always released soon, and never waited for
 * by the hart that holds it. `acquire` checks the rule and panics if it
 * finds interrupts unmasked, because a lock taken unmasked can hang a single
 * hart silently (the holder is switched out, the next thread spins forever).
 * Nothing under a lock calls into user code or waits for another hart for
 * anything but a lock lower in the hierarchy.
 */

#pragma once

#include <stdint.h>
#include <signetos/asm_macros.h>
#include <signetos/debug/report.hpp>

namespace signetos {

struct SpinLock {
  uint32_t held = 0;

  void acquire() {
    uint64_t mstatus;
    __asm__ volatile("csrr %0, mstatus" : "=r"(mstatus));
    if ((mstatus & MSTATUS_MIE) != 0) {
      debug::panic("lock: taken with interrupts unmasked");
    }
    for (;;) {
      if (__atomic_exchange_n(&held, 1u, __ATOMIC_ACQUIRE) == 0) {
        return;
      }
      // Wait reading, not writing, until it looks free, then try again.
      while (__atomic_load_n(&held, __ATOMIC_RELAXED) != 0) {
      }
    }
  }

  void release() { __atomic_store_n(&held, 0u, __ATOMIC_RELEASE); }
};

// Holds a lock for the rest of the enclosing scope.
class Locked {
 public:
  explicit Locked(SpinLock& lock) : lock_(lock) { lock_.acquire(); }
  ~Locked() { lock_.release(); }
  Locked(const Locked&) = delete;
  Locked& operator=(const Locked&) = delete;

 private:
  SpinLock& lock_;
};

}  // namespace signetos
