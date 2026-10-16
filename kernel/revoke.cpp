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
#include <signetos/vm.hpp>

namespace signetos::revoke {

namespace {

SpinLock s_lock;

// A range awaiting the next sweep. Every pending range belongs to the current
// pending epoch, so the epoch is not stored per range.
struct PendingRange {
    uint64_t base;
    uint64_t top;
};

// One page of the backlog. The header mirrors a compartment range page (`next`
// at 0, `funder` at 16) and the rule is the same: a range is only recorded on
// a page bought by the registering caller's own quota, so a caller that keeps
// registering runs out of its own memory and nobody else's.
constexpr size_t PENDING_HEADER = 48;
constexpr size_t RANGES_PER_PENDING_PAGE =
    (vm::PAGE_SIZE - PENDING_HEADER) / sizeof(PendingRange);

struct PendingPage {
    Capability next;    // the next page in the chain, or null
    Capability funder;  // the QuotaVm handle charged for this page
    uint64_t count;     // ranges in use, from the front
    uint64_t pad;
    PendingRange ranges[RANGES_PER_PENDING_PAGE];
};
static_assert(offsetof(PendingPage, funder) == compartment::CAP_BYTES);
static_assert(offsetof(PendingPage, ranges) == PENDING_HEADER);
static_assert(sizeof(PendingPage) <= vm::PAGE_SIZE);

// Head of the chain of pending pages. Null when the backlog is empty. Lives in
// `.bss`, which the sweep scans; it survives because nothing registers a range
// over kernel bookkeeping pages.
Capability g_pending_pages = nullptr;

// Epoch 0 means "no sweep has ever completed", so the first epoch handed out is 1.
uint64_t g_pending_epoch   = 1;
uint64_t g_completed_epoch = EPOCH_NONE;

PendingPage* page_of(Capability page_cap) {
  return reinterpret_cast<PendingPage*>(page_cap);
}

// True if two quota handles name the same node. Comparing bases rather than
// whole capabilities means a caller may present any copy of the handle.
bool same_quota(Capability a, Capability b) {
  return capability_is_valid(a) && capability_is_valid(b) &&
         capability_get_base(a) == capability_get_base(b);
}

// A page funded by `mem_quota` with a free record, or null. Caller holds
// `s_lock`. Pages funded by other quotas are skipped even when they have room.
PendingPage* find_room(Capability mem_quota) {
  for (Capability p = g_pending_pages; capability_is_valid(p);
       p = page_of(p)->next) {
    PendingPage* page = page_of(p);
    if (page->count < RANGES_PER_PENDING_PAGE &&
        same_quota(page->funder, mem_quota)) {
      return page;
    }
  }
  return nullptr;
}

// Detaches the whole backlog and returns its chain of pages. Caller holds
// `s_lock`.
Capability take_pages() {
  Capability p = g_pending_pages;
  g_pending_pages = nullptr;
  return p;
}

// Frees a chain detached by take_pages() back into quarantine and refunds each
// page's funder. Caller must NOT hold `s_lock`: a refund takes quota node
// locks, which come before it (lock.hpp). The pages are reclaimed by the sweep
// after the one that retires them, like any other freed kernel bookkeeping
// page.
void release_pages(Capability p) {
  while (capability_is_valid(p)) {
    const Capability next = page_of(p)->next;
    const Capability funder = page_of(p)->funder;
    vm::free_pages(p);
    quota::refund(funder, vm::PAGE_SIZE);
    p = next;
  }
}

// True if `address` lies in a range awaiting the sweep. Caller holds
// `s_lock`.
bool in_pending_range(uint64_t address) {
  for (Capability p = g_pending_pages; capability_is_valid(p);
       p = page_of(p)->next) {
    const PendingPage* page = page_of(p);
    for (uint64_t i = 0; i < page->count; ++i) {
      if (address >= page->ranges[i].base && address < page->ranges[i].top) {
        return true;
      }
    }
  }
  return false;
}

} // namespace

void init() {
  s_lock = SpinLock{};
  // A no-op at boot; the tests re-init with ranges queued.
  release_pages(take_pages());
  g_pending_epoch = 1;
  g_completed_epoch = EPOCH_NONE;
}

size_t pending_count() {
  Locked hold(s_lock);
  size_t n = 0;
  for (Capability p = g_pending_pages; capability_is_valid(p);
       p = page_of(p)->next) {
    n += page_of(p)->count;
  }
  return n;
}
uint64_t completed_epoch() {
  return __atomic_load_n(&g_completed_epoch, __ATOMIC_ACQUIRE);
}
uint64_t pending_epoch() {
  return __atomic_load_n(&g_pending_epoch, __ATOMIC_ACQUIRE);
}

Status revoke(Capability comp, Capability mem_cap, Capability mem_quota,
              uint64_t* out_epoch) {
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

  // WHO MAY REVOKE: the owner, for memory strictly inside one of its
  // allocations.
  Status owned = Status::Ok;
  if (!compartment::owns_inside(comp, mem_base, mem_len, &owned)) {
    return owned;
  }

  // The backlog is paid for. The record goes on a page funded by
  // `mem_quota`; a page is bought from it when none of its pages has room.
  // `quota::charge` is the full check on the handle when a page is bought
  // (genuine QuotaVm, Permit_Load); the type check here keeps a stray
  // capability with a matching base from riding on an existing page.
  if (!sealing::is_sealed_as(OType::QuotaVm, mem_quota)) {
    return Status::InvalidCapability;
  }
  {
    Locked hold(s_lock);
    if (PendingPage* page = find_room(mem_quota)) {
      page->ranges[page->count] = PendingRange{mem_base, mem_top};
      __atomic_store_n(&page->count, page->count + 1, __ATOMIC_RELEASE);
      if (out_epoch != nullptr) {
        *out_epoch = g_pending_epoch;
      }
      return Status::Ok;
    }
  }

  // Bought outside `s_lock`: `vm::alloc_pages` may run a sweep when memory is
  // short, and the sweep takes `s_lock`.
  const Status paid = quota::charge(mem_quota, vm::PAGE_SIZE);
  if (paid != Status::Ok) {
    return paid;
  }
  Capability fresh = vm::alloc_pages(1);  // zeroed, so count starts at 0
  if (!capability_is_valid(fresh)) {
    quota::refund(mem_quota, vm::PAGE_SIZE);
    return Status::NoMemory;
  }
  PendingPage* page = page_of(fresh);
  page->funder = mem_quota;
  page->ranges[0] = PendingRange{mem_base, mem_top};
  page->count = 1;

  Locked hold(s_lock);
  page->next = g_pending_pages;
  g_pending_pages = fresh;
  if (out_epoch != nullptr) {
    *out_epoch = g_pending_epoch;
  }
  return Status::Ok;
}

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
  // Never revoke standing kernel derivation roots (e.g. `vm::s_dynamic`,
  // `sentry::s_root_code_cap`, `vm::s_direct`), whose base is the base of
  // the whole dynamic space.
  if (len >= vm::DYNAMIC_TOP - vm::DYNAMIC_BASE || base >= vm::DIRECT_BASE) {
    return false;
  }

  // THE BASE RULE: a queued range (called by the sweep with `s_lock` held),
  // or a quarantined page.
  if (in_pending_range(base)) {
    return true;
  }
  return vm::quarantined_pages() > 0 && base >= vm::DYNAMIC_BASE &&
         base < vm::DYNAMIC_TOP && vm::is_quarantined(base);
}

namespace {

#define KERNEL_SYM_ADDR(sym)                     \
  ([]() -> uint64_t {                            \
    Capability c;                                \
    __asm__ volatile("llc %0, " #sym : "=C"(c)); \
    return capability_get_address(c);            \
  }())

// The sweep proper, under `s_lock`. Returns the backlog it retired, for the
// caller to release once the lock is dropped.
Capability sweep_locked() {
  Locked hold(s_lock);
  Capability retired = nullptr;
  if (capability_is_valid(g_pending_pages) || vm::quarantined_pages() > 0) {
    // 1. Scan kernel `.data`, `.bss.stack`, and `.bss` (`[_data_start,
    //    _kernel_end)`), which includes the boot stack and all static state.
    //    The image is identity-mapped; `phys_view` is the one standing
    //    capability that spans it.
    if (vm::is_initialized()) {
      const uint64_t data_start = KERNEL_SYM_ADDR(_data_start);
      const uint64_t kernel_end = KERNEL_SYM_ADDR(_kernel_end);
      const Capability view = vm::phys_view(data_start, kernel_end - data_start);
      Capability* slots = reinterpret_cast<Capability*>(view);
      const size_t count =
          capability_is_valid(view) ? (kernel_end - data_start) / sizeof(Capability) : 0;
      for (size_t c = 0; c < count; ++c) {
        if (capability_is_valid(slots[c]) && should_revoke(slots[c])) {
          slots[c] = capability_clear_tag(slots[c]);
        }
      }
    }

    // 2. Scan all live mapped pages in the dynamic address space
    //    (compartment capability tables, heap/data/code allocations, thread
    //    stacks, and thread kernel stacks).
    vm::sweep_live_pages();

    // 3. All capabilities pointing into quarantined pages now have their
    //    hardware tags cleared. Unmap every quarantined page, free its
    //    physical frame, and return its virtual address range to the
    //    reusable pool.
    vm::reclaim_quarantined();

    // 4. The backlog is retired. Its pages are given back and whoever paid is
    //    refunded by the caller, outside `s_lock`.
    retired = take_pages();
  }

  const uint64_t swept = g_pending_epoch;
  __atomic_store_n(&g_completed_epoch, swept, __ATOMIC_RELEASE);
  __atomic_store_n(&g_pending_epoch, swept + 1, __ATOMIC_RELEASE);
  return retired;
}

__attribute__((noinline)) void do_sweep() {
  release_pages(sweep_locked());
}

}  // namespace

void sweep() {
  // Clobbering `cs0..cs11` forces the compiler to spill all callee-saved
  // capability registers into this stack frame in the prologue (before
  // `do_sweep()` scans the stack) and reload them from those swept stack
  // slots in the epilogue.
  do_sweep();
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

} // namespace signetos::revoke
