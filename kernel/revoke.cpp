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
#include <signetos/hw/clint.hpp>
#include <signetos/lock.hpp>
#include <signetos/quota.hpp>
#include <signetos/revoke.hpp>
#include <signetos/sealing.hpp>
#include <signetos/vm.hpp>

namespace signetos::revoke {

namespace {

SpinLock s_lock;

// True while a sweep waits for its checks of swap (SWAP).
bool s_waiting = false;

// Epoch 0 means "no sweep has ever completed", so the first epoch handed out is 1.
uint64_t g_pending_epoch   = 1;
uint64_t g_completed_epoch = EPOCH_NONE;

// The marks (revoke.hpp, MARKING RANGES) live in the revocation bitmap
// (vm.hpp, REVOCATION BITMAP), reached through this view of it.
// `[s_marked_lo, s_marked_hi)` covers the bitmap addresses marked since the
// last sweep; it is empty if nothing is. Under `s_lock`.
Capability s_bitmap = nullptr;
uint64_t s_marked_lo = ~0ULL;
uint64_t s_marked_hi = 0;

// The bitmap word holding the mark for `va`, which lies in a revocable
// allocation, and the mark's bit in it: byte (va - DYNAMIC_BASE) / 128 of
// the bitmap, bit ((va - DYNAMIC_BASE) / 16) % 8 of that byte.
volatile uint64_t* mark_word(uint64_t va) {
  return reinterpret_cast<volatile uint64_t*>(
      capability_set_address(s_bitmap, vm::bitmap_of(va) & ~7ULL));
}
uint64_t mark_bit(uint64_t va) {
  return 1ULL << (((va - vm::DYNAMIC_BASE) / 16) % 64);
}

// Marks `[base, top)`, which lies in one revocable allocation.
void mark(uint64_t base, uint64_t top) {
  for (uint64_t va = base; va < top; va += 16) {
    *mark_word(va) |= mark_bit(va);
  }
  const uint64_t lo = vm::bitmap_of(base);
  const uint64_t hi = vm::bitmap_of(top - 1) + 1;
  s_marked_lo = lo < s_marked_lo ? lo : s_marked_lo;
  s_marked_hi = hi > s_marked_hi ? hi : s_marked_hi;
}

bool is_marked(uint64_t va) { return (*mark_word(va) & mark_bit(va)) != 0; }

bool any_marked() { return s_marked_lo < s_marked_hi; }

// Clears every mark: zeroes the bitmap pages in the marked span that are still
// mapped (those of allocations the sweep has just reclaimed are gone).
void clear_marks() {
  for (uint64_t page = s_marked_lo & ~(vm::PAGE_SIZE - 1); page < s_marked_hi;
       page += vm::PAGE_SIZE) {
    if (vm::leaf_flags(page) == 0) {
      continue;
    }
    volatile uint64_t* w = reinterpret_cast<volatile uint64_t*>(
        capability_set_address(s_bitmap, page));
    for (size_t i = 0; i < vm::PAGE_SIZE / sizeof(uint64_t); ++i) {
      w[i] = 0;
    }
  }
  s_marked_lo = ~0ULL;
  s_marked_hi = 0;
}

} // namespace

void init() {
  s_lock = SpinLock{};
  s_waiting = false;
  g_pending_epoch = 1;
  g_completed_epoch = EPOCH_NONE;
  s_bitmap = vm::bitmap_view();
  s_marked_lo = ~0ULL;
  s_marked_hi = 0;
}

uint64_t completed_epoch() {
  return __atomic_load_n(&g_completed_epoch, __ATOMIC_ACQUIRE);
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

  Locked hold(s_lock);
  if (s_waiting) {
    return Status::Busy;  // a sweep is waiting for its checks (SWAP)
  }
  mark(mem_base, mem_top);
  if (out_epoch != nullptr) {
    *out_epoch = g_pending_epoch;
  }
  return Status::Ok;
}

namespace {

// THE BASE RULE: true if `cap` is a valid capability whose base lies in a
// marked range or a quarantined page. Standing kernel authorities (sealing
// and ASR capabilities, the roots of whole address ranges) are never revoked.
bool should_revoke(Capability cap) {
  if (!capability_is_valid(cap)) {
    return false;
  }
  const uint64_t p = capability_get_perms(cap);
  // Never revoke kernel system capabilities (return addresses, trap/switcher
  // sentries) or sealing authorities.
  if ((p & (perms::AccessSystemRegs | perms::Seal | perms::Unseal)) != 0) {
    return false;
  }
  const uint64_t base = capability_get_base(cap);
  const uint64_t len = capability_get_length(cap);
  // Only the dynamic space is ever freed or revoked. Never revoke the
  // standing kernel derivation roots (e.g. `vm::s_dynamic`,
  // `sentry::s_root_code_cap`), whose base is the base of the whole space.
  if (base < vm::DYNAMIC_BASE || base >= vm::DYNAMIC_TOP ||
      len >= vm::DYNAMIC_TOP - vm::DYNAMIC_BASE) {
    return false;
  }

  // THE BASE RULE: a quarantined page, or a marked granule of a revocable one
  // (called by the sweep with `s_lock` held).
  const uint64_t flags = vm::leaf_flags(base);
  if ((flags & vm::pte::Quarantined) != 0) {
    return true;
  }
  return (flags & vm::pte::Revocable) != 0 && is_marked(base);
}

// Clears the tag on every capability in `view` that should_revoke picks.
void scan(Capability view) {
  if (!capability_is_valid(view)) {
    return;
  }
  Capability* slots = reinterpret_cast<Capability*>(view);
  const size_t count = capability_get_length(view) / sizeof(Capability);
  for (size_t c = 0; c < count; ++c) {
    if (capability_is_valid(slots[c]) && should_revoke(slots[c])) {
      slots[c] = capability_clear_tag(slots[c]);
    }
  }
}

#define KERNEL_SYM_ADDR(sym)                     \
  ([]() -> uint64_t {                            \
    Capability c;                                \
    __asm__ volatile("llc %0, " #sym : "=C"(c)); \
    return capability_get_address(c);            \
  }())

// When the last sweep ended, in `time` ticks, if there has been one (WHEN A
// SWEEP RUNS).
bool s_swept = false;
uint64_t s_last_sweep_end = 0;

// True if a sweep would have anything to do. Caller holds `s_lock`.
bool anything_pending() {
  return any_marked() || vm::quarantined_pages() > 0;
}

// Ends the sweep, its marks having done their job. Caller holds `s_lock`.
void complete_locked() {
  clear_marks();
  const uint64_t swept = g_pending_epoch;
  __atomic_store_n(&g_completed_epoch, swept, __ATOMIC_RELEASE);
  __atomic_store_n(&g_pending_epoch, swept + 1, __ATOMIC_RELEASE);
}

// The sweep proper. Caller holds `s_lock`.
void sweep_locked() {
  if (anything_pending()) {
    // 1. Scan kernel `.data`, `.bss.stack`, and `.bss` (`[_data_start,
    //    _kernel_end)`), which includes the boot stack and all static state.
    //    The image is identity-mapped; `phys_view` is the one standing
    //    capability that spans it.
    if (vm::is_initialized()) {
      const uint64_t data_start = KERNEL_SYM_ADDR(_data_start);
      const uint64_t kernel_end = KERNEL_SYM_ADDR(_kernel_end);
      scan(vm::phys_view(data_start, kernel_end - data_start));
    }

    // 2. Scan all live mapped pages in the dynamic address space
    //    (compartment capability tables, heap/data/code allocations, thread
    //    stacks, and thread kernel stacks).
    uint64_t cursor = 0;
    for (Capability page = vm::next_live_page(&cursor);
         capability_is_valid(page); page = vm::next_live_page(&cursor)) {
      scan(page);
    }

    // 3. Capabilities on disk have not been seen (SWAP): if there are any,
    //    the pager reads them back to be checked, and the sweep waits.
    s_waiting = vm::start_checks();

    // 4. All capabilities pointing into quarantined pages now have their
    //    hardware tags cleared. Unmap every quarantined page, free its
    //    physical frame, and return its virtual address range to the
    //    reusable pool -- or, while the sweep waits, leave it Held.
    vm::reclaim_quarantined(s_waiting);
    s_swept = true;
    s_last_sweep_end = clint::now();
  }

  // 5. Every capability based in a marked granule is gone too, so the marks
  //    have done their job. Not before: a capability scanned late may be
  //    based in a range whose own page was scanned early.
  if (!s_waiting) {
    complete_locked();
  }
}

// Sweeps, unless `limited` and a sweep has ended less than SWEEP_INTERVAL_US
// ago with something to scan.
//
// What is owed for freed memory (quota.hpp, OWED) is refunded after the
// sweep, once `s_lock` is let go: a refund takes quota node locks, which come
// before it (lock.hpp). A refund can free a quota node whose last bytes these
// were; its page is owed in turn and waits for the next sweep.
__attribute__((noinline)) void try_sweep(bool limited) {
  {
    Locked hold(s_lock);
    // A sweep waiting for its checks completes once they are done (SWAP).
    if (s_waiting) {
      if (!vm::checks_pending()) {
        vm::release_held();
        s_waiting = false;
        complete_locked();
      }
      return;
    }
    if (limited && s_swept && anything_pending() &&
        clint::now() <
            s_last_sweep_end + clint::us_to_ticks(SWEEP_INTERVAL_US)) {
      return;
    }
    sweep_locked();
  }
  quota::settle_owed();
}

// Follows every call into a sweep. The clobbers make the caller's prologue
// spill all callee-saved capability registers into its frame, which the
// sweep scans, and its epilogue reload them from there, so none keeps a
// capability the sweep revoked; the temporaries are scrubbed.
__attribute__((always_inline)) inline void scrub_registers() {
  __asm__ volatile(
      "cmv ct0, cnull\n\t"
      "cmv ct1, cnull\n\t"
      "cmv ct2, cnull\n\t"
      "cmv ct3, cnull\n\t"
      "cmv ct4, cnull\n\t"
      "cmv ct5, cnull\n\t"
      "cmv ct6, cnull\n\t"
      "cmv ca0, cnull\n\t"
      "cmv ca1, cnull\n\t"
      "cmv ca2, cnull\n\t"
      "cmv ca3, cnull\n\t"
      "cmv ca4, cnull\n\t"
      "cmv ca5, cnull\n\t"
      "cmv ca6, cnull\n\t"
      "cmv ca7, cnull\n\t"
      :
      :
      : "cs0", "cs1", "cs2", "cs3", "cs4", "cs5", "cs6", "cs7", "cs8", "cs9",
        "cs10", "cs11", "ct0", "ct1", "ct2", "ct3", "ct4", "ct5", "ct6", "ca0",
        "ca1", "ca2", "ca3", "ca4", "ca5", "ca6", "ca7", "memory");
}

}  // namespace

uint64_t query() {
  try_sweep(true);
  scrub_registers();
  return completed_epoch();
}

void sweep() {
  try_sweep(false);
  scrub_registers();
}

} // namespace signetos::revoke
