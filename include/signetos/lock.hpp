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
 *   2. `QuotaNode::lock`    per-quota-node lock protecting ledger counters and
 *                           the child list (`parent->lock` is acquired before
 *                           `node->lock` in `quota::destroy`; nothing else
 *                           holds two).
 *   3. `revoke::s_lock`     protects the pending revocation table `g_pending`
 *                           and serializes `revoke::sweep()`.
 *   4. `vm::s_lock`         protects the virtual address free list and Sv39
 *                           page tables (never held while zeroing pages).
 *   5. `frame::s_lock`      leaf lock protecting the physical frame bitmap.
 *   6. `trap::s_lock`       leaf lock serializing `s_slots` writes and
 *                           `sync_all_harts()`.
 *   7. `uart::s_lock`       leaf lock protecting console line output.
 *
 * Locks are acquired strictly in the order listed above (outermost to
 * innermost). Pure capability-derivation and read-only syscalls (`sys_seal`,
 * `sys_unseal`, `sys_type_mint`, `sys_type_derive`, `sys_revoke_derive`,
 * `sys_revoke_query`, `sys_thread_tid`) take no lock at all.
 *
 * `vm::alloc_pages` may run a revocation sweep, which takes `revoke::s_lock`
 * and then refunds into quota nodes. So it is never called with a
 * `QuotaNode::lock` or `revoke::s_lock` held.
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
#include <signetos/uart.hpp>

namespace signetos {

struct SpinLock {
  uint32_t held = 0;

  void acquire() {
    uint64_t sstatus;
    __asm__ volatile("csrr %0, sstatus" : "=r"(sstatus));
    if ((sstatus & SSTATUS_SIE) != 0) {
      uart::panic("lock: taken with interrupts unmasked");
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
