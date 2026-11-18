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
 * revoke.cpp - SignetOS revocation (revoke.hpp)
 */

#include <signetos/compartment.hpp>
#include <signetos/lock.hpp>
#include <signetos/quota.hpp>
#include <signetos/revoke.hpp>
#include <signetos/sealing.hpp>
#include <signetos/smp.hpp>
#include <signetos/thread.hpp>
#include <signetos/vm.hpp>
#include <signetos/debug/report.hpp>

// sweep.S: runs `__signetos_check_pages(va, len)` on `stack`.
extern "C" size_t __signetos_check_on(signetos::Capability stack, uint64_t va,
                                      size_t len);
// sweep.S: stores `cleared` in `*slot` if `*slot` is still exactly `seen`.
// 1 if it did.
extern "C" uint64_t __signetos_clear_tag_if(signetos::Capability* slot,
                                            signetos::Capability seen,
                                            signetos::Capability cleared);

namespace signetos::revoke {

bool g_checking = false;

namespace {

SpinLock s_lock;

// EPOCHS. How many sweeps have started, and how many have completed: a sweep
// is running exactly while the two differ. Written under `s_lock`.
uint64_t g_started = 0;
uint64_t g_completed = EPOCH_NONE;

// How far the sweeper has got (`vm::check_some`), while `g_checking`.
uint64_t s_cursor = 0;

// True while a sweep with no stale page left waits for its checks of swap
// (SWAP).
bool s_waiting = false;

// True from the moment a hart has decided to start a sweep until it has
// (SEVERAL HARTS): it lets go of `s_lock` to stop the others, and nobody
// else starts one meanwhile. Nothing else about the sweep has changed yet.
bool s_starting = false;

// The pages a sweep's start keeps (`begin_locked`). Under `s_lock`.
uint64_t s_keep[vm::MAX_KEPT];
static_assert(thread::MAX_HARTS * thread::THREAD_STATE_PAGES + 2 <=
              vm::MAX_KEPT);

// The marks (revoke.hpp, MARKING RANGES) live in the two revocation bitmaps
// (vm.hpp, REVOCATION BITMAP), reached through this view of both.
// `[s_marked_lo[w], s_marked_hi[w])` covers the addresses of bitmap `w`
// marked since it was last cleared; it is empty if nothing is. Under
// `s_lock`.
Capability s_bitmap = nullptr;
uint64_t s_marked_lo[2] = {~0ULL, ~0ULL};
uint64_t s_marked_hi[2] = {0, 0};

// TWO BITMAPS: the one sweep `epoch` works from, and clears.
unsigned bitmap_for(uint64_t epoch) { return static_cast<unsigned>(epoch & 1); }

// The word of bitmap `which` holding the mark for `va`, which lies in a
// revocable allocation, and the mark's bit in it: byte
// (va - DYNAMIC_BASE) / 128 of the bitmap, bit ((va - DYNAMIC_BASE) / 16) % 8
// of that byte.
volatile uint64_t* mark_word(uint64_t va, unsigned which) {
  return reinterpret_cast<volatile uint64_t*>(
      capability_set_address(s_bitmap, vm::bitmap_of(va, which) & ~7ULL));
}
uint64_t mark_bit(uint64_t va) {
  return 1ULL << (((va - vm::DYNAMIC_BASE) / 16) % 64);
}

// Marks `[base, top)`, which lies in one revocable allocation, in bitmap
// `which`.
void mark(uint64_t base, uint64_t top, unsigned which) {
  for (uint64_t va = base; va < top; va += 16) {
    *mark_word(va, which) |= mark_bit(va);
  }
  const uint64_t lo = vm::bitmap_of(base, which);
  const uint64_t hi = vm::bitmap_of(top - 1, which) + 1;
  s_marked_lo[which] = lo < s_marked_lo[which] ? lo : s_marked_lo[which];
  s_marked_hi[which] = hi > s_marked_hi[which] ? hi : s_marked_hi[which];
}

// In either bitmap (TWO BITMAPS).
bool is_marked(uint64_t va) {
  return ((*mark_word(va, 0) | *mark_word(va, 1)) & mark_bit(va)) != 0;
}

bool any_marked(unsigned which) {
  return s_marked_lo[which] < s_marked_hi[which];
}

// Clears every mark of bitmap `which`: zeroes its pages in the marked span
// that are still mapped (those of allocations the sweep has just reclaimed
// are gone).
void clear_marks(unsigned which) {
  for (uint64_t page = s_marked_lo[which] & ~(vm::PAGE_SIZE - 1);
       page < s_marked_hi[which]; page += vm::PAGE_SIZE) {
    if (vm::leaf_flags(page) == 0) {
      continue;
    }
    volatile uint64_t* w = reinterpret_cast<volatile uint64_t*>(
        capability_set_address(s_bitmap, page));
    for (size_t i = 0; i < vm::PAGE_SIZE / sizeof(uint64_t); ++i) {
      w[i] = 0;
    }
  }
  s_marked_lo[which] = ~0ULL;
  s_marked_hi[which] = 0;
}

bool running() { return g_started != g_completed; }

} // namespace

void init() {
  s_lock = SpinLock{};
  g_checking = false;
  s_waiting = false;
  s_starting = false;
  s_cursor = 0;
  g_started = 0;
  g_completed = EPOCH_NONE;
  s_bitmap = vm::bitmap_view();
  for (unsigned w = 0; w < 2; ++w) {
    s_marked_lo[w] = ~0ULL;
    s_marked_hi[w] = 0;
  }
}

uint64_t completed_epoch() {
  return __atomic_load_n(&g_completed, __ATOMIC_ACQUIRE);
}

uint64_t next_epoch() {
  return __atomic_load_n(&g_started, __ATOMIC_ACQUIRE) + 1;
}

Status revoke(Capability comp, Capability mem_cap, uint64_t* out_epoch) {
  // The range comes from the caller's capability to it.
  if (!capability_is_valid(mem_cap) || sealing::is_sealed(mem_cap)) {
    return Status::InvalidCapability;
  }
  const uint64_t mem_base = capability_get_base(mem_cap);
  const uint64_t mem_len = capability_get_length(mem_cap);
  const uint64_t mem_top = mem_base + mem_len;
  if (mem_len == 0 || mem_top < mem_base) {
    return Status::InvalidRange;
  }
  // Marked 16 bytes at a time (MARKING RANGES).
  if ((mem_base | mem_len) % 16 != 0) {
    return Status::BadAlignment;
  }

  // WHO MAY REVOKE: the owner, for memory strictly inside one of its
  // allocations, which must be revocable so that it has bitmap pages.
  Status owned = Status::Ok;
  if (!compartment::owns_inside(comp, mem_base, mem_len, &owned)) {
    return owned;
  }
  if ((vm::leaf_flags(mem_base) & vm::pte::Revocable) == 0) {
    return Status::NotInRange;
  }

  // Into the next sweep's bitmap, whether or not one is running now (TWO
  // BITMAPS), and that sweep's is the epoch the range belongs to.
  Locked hold(s_lock);
  const uint64_t epoch = g_started + 1;
  mark(mem_base, mem_top, bitmap_for(epoch));
  if (out_epoch != nullptr) {
    *out_epoch = epoch;
  }
  return Status::Ok;
}

// THE BASE RULE. Standing kernel authorities (sealing and ASR capabilities,
// the roots of whole address ranges) are never revoked.
bool is_revoked(Capability cap) {
  const uint64_t p = capability_get_perms(cap);
  // Never revoke kernel system capabilities (return addresses, trap/switcher
  // sentries) or sealing authorities.
  if ((p & (perms::AccessSystemRegs | perms::Seal | perms::Unseal)) != 0) {
    return false;
  }
  const uint64_t base = capability_get_base(cap);
  const uint64_t len = capability_get_length(cap);
  // Only the pool (vm.hpp, LAYOUT) is ever freed or revoked. Never revoke the
  // standing kernel derivation roots (e.g. `vm::s_dynamic`,
  // `sentry::s_root_code_cap`), whose base is the base of the whole space.
  if (base < vm::DYNAMIC_BASE || base >= vm::BITMAP_BASE ||
      len >= vm::DYNAMIC_TOP - vm::DYNAMIC_BASE) {
    return false;
  }

  // A quarantined page, one a waiting sweep has reclaimed (Held: SWAP), or a
  // marked granule of a revocable one.
  const uint64_t flags = vm::leaf_flags(base);
  if ((flags & vm::pte::Quarantined) != 0 ||
      vm::pte_kind(flags) == vm::pte::KindHeld) {
    return true;
  }
  return (flags & vm::pte::Revocable) != 0 && is_marked(base);
}

// Clears the tag of the revoked capability at `slot`. Another hart may store
// to the page while it is checked (SEVERAL HARTS). What it stores is not
// revoked, and must not be lost: the tag is cleared only if the capability
// looked at is still the one there, and otherwise the new one is looked at.
// Out of line: it is rare, and `scan`'s loop over every slot of every page
// is what a sweep costs.
[[gnu::noinline]] static void clear_revoked(Capability* slot) {
  for (;;) {
    const Capability seen = *slot;
    if (!capability_is_valid(seen) || !is_revoked(seen) ||
        __signetos_clear_tag_if(slot, seen, capability_clear_tag(seen)) != 0) {
      return;
    }
  }
}

void scan(Capability view) {
  if (!capability_is_valid(view)) {
    return;
  }
  Capability* slots = reinterpret_cast<Capability*>(view);
  const size_t count = capability_get_length(view) / sizeof(Capability);
  for (size_t c = 0; c < count; ++c) {
    if (capability_is_valid(slots[c]) && is_revoked(slots[c])) {
      clear_revoked(&slots[c]);
    }
  }
}

// KERNEL LOADS, and the fault. On the hart's own stack whenever a thread is
// running (thread.hpp, `spare_stack`): the thread's kernel stack has room
// for a trap and little more (asm_macros.h, KERNEL-STACK ROOM), and what
// checks a page should not be standing on one. Unless the kernel is on that
// stack already: in host context, and for the moment in which the host
// switches to a thread, when the stack counts as spare but the code doing
// the switching is still on it.
// What `check_slow` runs. A `len` of 0 is the fault's: the one page at `va`,
// and 1 if the load is to run again.
extern "C" size_t __signetos_check_pages(uint64_t va, size_t len) {
  return len == 0 ? (vm::check_fault(va) ? 1 : 0) : vm::check_pages(va, len);
}

size_t check_slow(uint64_t va, size_t len) {
  const Capability stack = thread::spare_stack();
  const uint64_t sp = capability_get_address(__builtin_cheri_stack_get());
  const uint64_t base = capability_get_base(stack);
  const bool on_it = sp >= base && sp - base < capability_get_length(stack);
  return capability_is_valid(stack) && !on_it
             ? __signetos_check_on(stack, va, len)
             : __signetos_check_pages(va, len);
}

bool on_fault(uint64_t addr) {
  return check_slow(addr & ~(vm::PAGE_SIZE - 1), 0) != 0;
}

namespace {

// Ends the running sweep, its marks having done their job: the addresses it
// reclaimed are free for reuse (SWAP). Caller holds `s_lock`.
void complete_locked() {
  vm::release_held();
  clear_marks(bitmap_for(g_started));
  __atomic_store_n(&g_completed, g_started, __ATOMIC_RELEASE);
}

// Completes the running sweep if none of its work is left: no stale page,
// and no check of swap. True if it did. Caller holds `s_lock`.
bool finish_locked() {
  if (!running() || checking() || (s_waiting && vm::checks_pending())) {
    return false;
  }
  s_waiting = false;
  complete_locked();
  return true;
}

// No page is stale any more, so every capability in RAM that pointed into
// memory freed before the sweep started has lost its tag. Capabilities on
// disk have not been seen (SWAP): if there are any, the pager reads them
// back to be checked, and the sweep waits. Either way the quarantined pages
// are unmapped and their frames freed now; with paging their addresses stay
// Held until the sweep is complete. Caller holds `s_lock`.
void end_checking_locked() {
  __atomic_store_n(&g_checking, false, __ATOMIC_RELEASE);
  s_waiting = vm::start_checks();
  vm::reclaim_quarantined();
}

// A SWEEP, its start. The pages kept across the step are the ones the code
// of each hart is running on and returns through. For this hart: the
// thread's state pages, where the switcher saved the caller's registers and
// from where it gives them back, and the slice of the caller's stack this
// system call runs on. For every other hart, which is stopped (SEVERAL
// HARTS): the state pages of the thread it was running, where the trap that
// stopped it saved that thread's registers. A hart in host context (the boot
// self-test, a parked hart) has none: its stacks are the kernel's own.
// Caller holds `s_lock`, and has stopped the other harts.
void begin_locked() {
  uint64_t* const keep = s_keep;
  size_t n = 0;
  auto add = [&](uint64_t page) {
    for (size_t i = 0; i < n; ++i) {
      if (keep[i] == page) {
        return;
      }
    }
    if (n == vm::MAX_KEPT) {
      debug::panic("revoke: a sweep started on a stack of too many pages");
    }
    keep[n++] = page;
  };
  auto add_state = [&](uint64_t state) {
    if (state != 0) {
      for (size_t i = 0; i < thread::THREAD_STATE_PAGES; ++i) {
        add(state + (i * vm::PAGE_SIZE));
      }
    }
  };
  add_state(thread::current_state());
  const uint64_t others =
      smp::online_mask() & ~(1ULL << thread::this_hart());
  for (uint64_t h = 0; h < thread::MAX_HARTS; ++h) {
    if (((others >> h) & 1) != 0) {
      add_state(thread::state_on(h));
    }
  }
  const Capability sp = __builtin_cheri_stack_get();
  const uint64_t base = capability_get_base(sp);
  const uint64_t top = base + capability_get_length(sp);
  if (base >= vm::DYNAMIC_BASE && top <= vm::BITMAP_BASE) {
    for (uint64_t page = base & ~(vm::PAGE_SIZE - 1); page < top;
         page += vm::PAGE_SIZE) {
      add(page);
    }
  }

  s_cursor = 0;
  __atomic_store_n(&g_checking, true, __ATOMIC_RELEASE);
  vm::new_generation(keep, n);
}

} // namespace

// What is owed for freed memory (quota.hpp, OWED) is refunded when the sweep
// that reclaimed it completes, once `s_lock` is let go: a refund takes quota
// node locks, which come before it (lock.hpp). A refund can free a quota
// node whose last bytes these were; its page is owed in turn and waits for
// the next sweep. `epoch` is the sweep that completed, or EPOCH_NONE.
static void settle(uint64_t epoch) {
  if (epoch != EPOCH_NONE) {
    quota::settle_owed(epoch);
  }
}

uint64_t start() {
  uint64_t completed = EPOCH_NONE;
  uint64_t epoch = 0;
  bool begin = false;
  {
    Locked hold(s_lock);
    if (finish_locked()) {
      completed = g_completed;
    }
    // Also what a second hart is told that asks while the first is still
    // stopping the others: what it freed, it freed before the step.
    epoch = g_started + 1;
    if (!running() && !s_starting) {
      bool something =
          any_marked(bitmap_for(epoch)) || vm::quarantined_pages() > 0;
#if defined(SIGNETOS_SWEEP_STRESS)
      something = true;  // every start is a real one (Makefile)
#endif
      if (something) {
        s_starting = true;
        begin = true;
      } else {
        // Nothing to revoke: no page becomes stale, and nothing is owed.
        __atomic_store_n(&g_started, epoch, __ATOMIC_RELEASE);
        complete_locked();
      }
    }
  }
  if (begin) {
    // SEVERAL HARTS. Every hart takes the step together. The others are
    // stopped first, with no lock held here: one that is inside the kernel
    // finishes what it is doing, which may need `s_lock`, before it stops.
    // Once they have, nothing else runs, and the lock is there for the
    // taking.
    smp::stop_others();
    {
      Locked hold(s_lock);
      __atomic_store_n(&g_started, epoch, __ATOMIC_RELEASE);
      begin_locked();
      s_starting = false;
    }
    smp::release_others();
  }
  settle(completed);
  return epoch;
}

uint64_t query() {
  uint64_t completed = EPOCH_NONE;
  {
    Locked hold(s_lock);
    if (finish_locked()) {
      completed = g_completed;
    }
  }
  settle(completed);
  return completed_epoch();
}

uint64_t step(size_t pages) {
  uint64_t completed = EPOCH_NONE;
  uint64_t left = STEP_IDLE;
  {
    Locked hold(s_lock);
    // At least one page, so that every call gets somewhere.
    const size_t n = pages == 0 ? 1 : pages < STEP_MAX ? pages : STEP_MAX;
    if (checking() && vm::check_some(&s_cursor, n)) {
      end_checking_locked();
    }
    if (finish_locked()) {
      completed = g_completed;
    }
    left = !running() ? STEP_IDLE : checking() ? STEP_MORE : STEP_WAIT;
  }
  settle(completed);
  return left;
}

void sweep() {
  start();
  // Until it is complete, or all that is left is the wait for the pager.
  while (step(STEP_MAX) == STEP_MORE) {
  }
}

} // namespace signetos::revoke
