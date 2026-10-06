/*
 * Copyright 2026 Google LLC (Cherified Team)
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
 * revoke.cpp - SignetOS Revocation Authority Subsystem
 *
 * See revoke.hpp for the 0-byte hardware-sealed OType::Revoker model.
 */

#include <signetos/compartment.hpp>
#include <signetos/lock.hpp>
#include <signetos/quota.hpp>
#include <signetos/revoke.hpp>
#include <signetos/sealing.hpp>
#include <signetos/vm.hpp>

namespace signetos::revoke {

namespace {

constexpr uint64_t kRevokerPerms = perms::Load | perms::Store;

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

// Frees every pending page back into quarantine and refunds its funder. Caller
// holds `s_lock`. The pages are reclaimed by the sweep after the one that
// retires them, like any other freed kernel bookkeeping page.
void release_pages() {
  Capability p = g_pending_pages;
  g_pending_pages = nullptr;
  while (capability_is_valid(p)) {
    const Capability next = page_of(p)->next;
    const Capability funder = page_of(p)->funder;
    vm::free_pages(p);
    quota::refund(funder, vm::PAGE_SIZE);
    p = next;
  }
}

// Unseals `handle` as `OType::Revoker` and verifies the canonical shape of a
// kernel-minted revoker capability: non-empty bounds, `address == base`, and
// permissions carrying at most `Permit_Load | Permit_Store`.
Capability unseal_revoker(Capability handle) {
  Capability open = sealing::unseal_as(OType::Revoker, handle);
  if (!capability_is_valid(open)) {
    return nullptr;
  }
  const uint64_t base = capability_get_base(open);
  const uint64_t len = capability_get_length(open);
  const uint64_t addr = capability_get_address(open);
  const uint64_t p = capability_get_perms(open);
  if (len == 0 || base + len < base || addr != base ||
      (p & ~(kRevokerPerms | perms::Levels)) != 0) {
    return nullptr;
  }
  return open;
}

// Seals an unsealed capability covering `[base, base + len)` as an
// `OType::Revoker` handle carrying `perms_mask & (Permit_Load | Permit_Store)`.
Capability seal_revoker(Capability cap, uint64_t perms_mask) {
  const uint64_t base = capability_get_base(cap);
  const uint64_t len = capability_get_length(cap);
  if (!capability_is_valid(cap) || sealing::is_sealed(cap) || len == 0 ||
      base + len < base) {
    return nullptr;
  }
  Capability c = capability_set_address(cap, base);
  c = capability_and_perms(c, perms_mask & kRevokerPerms);
  if (!capability_is_valid(c)) {
    return nullptr;
  }
  return sealing::seal_as(OType::Revoker, c);
}

} // namespace

void init() {
  s_lock = SpinLock{};
  release_pages();  // a no-op at boot; the tests re-init with ranges queued
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

Capability create_root(Capability mem_cap, Status* out_status) {
  if (!capability_is_valid(mem_cap) || sealing::is_sealed(mem_cap)) {
    return fail_with(out_status, Status::InvalidCapability);
  }
  if (!capability_has_perms(mem_cap, perms::Load | perms::Store)) {
    return fail_with(out_status, Status::InsufficientPermission);
  }
  const uint64_t base = capability_get_base(mem_cap);
  const uint64_t len = capability_get_length(mem_cap);
  if (len == 0 || base + len < base) {
    return fail_with(out_status, Status::InvalidRange);
  }
  Capability handle = seal_revoker(mem_cap, kRevokerPerms);
  if (!capability_is_valid(handle)) {
    return fail_with(out_status, Status::InvalidCapability);
  }
  if (out_status != nullptr) {
    *out_status = Status::Ok;
  }
  return handle;
}

Capability create(Capability comp, Capability mem_cap, Status* out_status) {
  if (!capability_is_valid(mem_cap) || sealing::is_sealed(mem_cap)) {
    return fail_with(out_status, Status::InvalidCapability);
  }
  if (!capability_has_perms(mem_cap, perms::Load | perms::Store)) {
    return fail_with(out_status, Status::InsufficientPermission);
  }
  const uint64_t base = capability_get_base(mem_cap);
  const uint64_t len = capability_get_length(mem_cap);
  Status own_status = Status::Ok;
  if (!compartment::owns_range(comp, base, len, &own_status)) {
    return fail_with(out_status, own_status);
  }
  return create_root(mem_cap, out_status);
}

Capability derive(Capability parent_handle, uint64_t base, uint64_t top,
                  uint64_t perms_mask, Status* out_status) {
  Capability open_parent = unseal_revoker(parent_handle);
  if (!capability_is_valid(open_parent)) {
    return fail_with(out_status, Status::InvalidCapability);
  }
  if (!capability_has_perms(open_parent, perms::Store)) {
    return fail_with(out_status, Status::InsufficientPermission);
  }
  if (top <= base) {
    return fail_with(out_status, Status::InvalidRange);
  }
  const uint64_t parent_base = capability_get_base(open_parent);
  const uint64_t parent_top = parent_base + capability_get_length(open_parent);
  if (base < parent_base || top > parent_top) {
    return fail_with(out_status, Status::NotInRange);
  }
  const uint64_t len = top - base;
  Capability child = capability_set_address(open_parent, base);
  child = capability_set_bounds(child, len);
  if (!capability_is_valid(child) || capability_get_base(child) != base ||
      capability_get_length(child) != len) {
    return fail_with(out_status, Status::InvalidRange);
  }
  Capability handle = seal_revoker(child, perms_mask);
  if (!capability_is_valid(handle)) {
    return fail_with(out_status, Status::InvalidCapability);
  }
  if (out_status != nullptr) {
    *out_status = Status::Ok;
  }
  return handle;
}

Capability derive(Capability parent_handle, Capability sub_cap,
                  uint64_t perms_mask, Status* out_status) {
  if (!capability_is_valid(sub_cap) || sealing::is_sealed(sub_cap)) {
    return fail_with(out_status, Status::InvalidCapability);
  }
  const uint64_t base = capability_get_base(sub_cap);
  const uint64_t len = capability_get_length(sub_cap);
  if (len == 0 || base + len < base) {
    return fail_with(out_status, Status::InvalidRange);
  }
  return derive(parent_handle, base, base + len, perms_mask, out_status);
}

Status register_range(Capability revoker_handle, Capability mem_cap,
                      Capability mem_quota, uint64_t* out_epoch) {
  // 1. Authenticate the OType::Revoker handle in hardware.
  Capability open_auth = unseal_revoker(revoker_handle);
  if (!capability_is_valid(open_auth)) {
    return Status::InvalidCapability;
  }

  // 2. Operational authority (`Permit_Load`) is required to register.
  if (!capability_has_perms(open_auth, perms::Load)) {
    return Status::InsufficientPermission;
  }

  // 3. The range to revoke comes from the caller's memory capability.
  if (!capability_is_valid(mem_cap)) {
    return Status::InvalidCapability;
  }
  const uint64_t mem_base = capability_get_base(mem_cap);
  const uint64_t mem_len = capability_get_length(mem_cap);
  if (mem_len == 0) {
    return Status::InvalidRange;
  }
  const uint64_t mem_top = mem_base + mem_len;
  if (mem_top < mem_base) {
    return Status::InvalidRange;  // wrapped
  }

  // 4. Containment is checked against the unsealed revoker's hardware bounds.
  const uint64_t auth_base = capability_get_base(open_auth);
  const uint64_t auth_top = auth_base + capability_get_length(open_auth);
  if (mem_base < auth_base || mem_top > auth_top) {
    return Status::NotInRange;
  }

  // 5. The backlog is paid for. The record goes on a page funded by
  //    `mem_quota`; a page is bought from it when none of its pages has room.
  //    `quota::charge` is the full check on the handle when a page is bought
  //    (genuine QuotaVm, Permit_Load); the type check here keeps a stray
  //    capability with a matching base from riding on an existing page.
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

bool is_pending(uint64_t address) {
  Locked hold(s_lock);
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
  const uint64_t addr = capability_get_address(cap);
  // Never revoke standing kernel derivation roots (e.g. `vm::s_dynamic`,
  // `sentry::s_root_code_cap`, `vm::s_direct`, `tests::g_root_cap`).
  if (len >= vm::DYNAMIC_TOP - vm::DYNAMIC_BASE || base >= vm::DIRECT_BASE) {
    return false;
  }
  const uint64_t top = (base + len < base) ? ~uint64_t{0} : (base + len);
  const bool is_revoker = sealing::is_sealed_as(OType::Revoker, cap);

  // 1. Explicitly registered revocation ranges (`revoke::register_range`).
  //    For a `capability_revoker_t` (`OType::Revoker`), registering a chunk
  //    or resetting its own `[base, top)` arena must not self-revoke the
  //    revoker handle; a revoker handle is only revoked by a pending range
  //    when a strictly wider parent range encompasses `[base, top)`.
  //    Called by the sweep with `s_lock` already held.
  for (Capability pg = g_pending_pages; capability_is_valid(pg);
       pg = page_of(pg)->next) {
    const PendingPage* page = page_of(pg);
    for (uint64_t i = 0; i < page->count; ++i) {
      const uint64_t r_base = page->ranges[i].base;
      const uint64_t r_top = page->ranges[i].top;
      if (is_revoker) {
        if (len > 0 && r_base <= base && r_top >= top &&
            (r_base < base || r_top > top)) {
          return true;
        }
      } else if ((addr >= r_base && addr < r_top) ||
                 (len > 0 && base < r_top && top > r_base)) {
        return true;
      }
    }
  }

  // 2. Quarantined dynamic pages (`vm::free_pages`). When backing pages are
  //    unmapped/quarantined, every capability overlapping them -- including
  //    any `OType::Revoker` handle over that VM allocation -- is revoked.
  if (vm::quarantined_pages() > 0) {
    if (addr >= vm::DYNAMIC_BASE && addr < vm::DYNAMIC_TOP &&
        vm::is_quarantined(addr)) {
      return true;
    }
    if (len > 0 && top > vm::DYNAMIC_BASE && base < vm::DYNAMIC_TOP) {
      const uint64_t clip_lo =
          (base < vm::DYNAMIC_BASE) ? vm::DYNAMIC_BASE : base;
      const uint64_t clip_hi = (top > vm::DYNAMIC_TOP) ? vm::DYNAMIC_TOP : top;
      if (clip_hi > clip_lo &&
          vm::range_has_quarantined(clip_lo,
                                    static_cast<size_t>(clip_hi - clip_lo))) {
        return true;
      }
    }
  }
  return false;
}

namespace {

#define KERNEL_SYM_ADDR(sym)                     \
  ([]() -> uint64_t {                            \
    Capability c;                                \
    __asm__ volatile("llc %0, " #sym : "=C"(c)); \
    return capability_get_address(c);            \
  }())

__attribute__((noinline)) void do_sweep() {
  Locked hold(s_lock);
  if (capability_is_valid(g_pending_pages) || vm::quarantined_pages() > 0) {
    // 1. Scan kernel `.data`, `.bss.stack`, and `.bss` (`[_data_start,
    //    _kernel_end)`), which includes the boot stack and all static state.
    if (vm::is_initialized()) {
      const uint64_t data_start = KERNEL_SYM_ADDR(_data_start);
      const uint64_t kernel_end = KERNEL_SYM_ADDR(_kernel_end);
      for (uint64_t pa = data_start; pa < kernel_end; pa += vm::PAGE_SIZE) {
        Capability page = vm::phys_view(pa, vm::PAGE_SIZE);
        if (!capability_is_valid(page)) {
          continue;
        }
        Capability* slots = reinterpret_cast<Capability*>(page);
        constexpr size_t kCapsPerPage = vm::PAGE_SIZE / sizeof(Capability);
        for (size_t c = 0; c < kCapsPerPage; ++c) {
          const Capability cap = slots[c];
          if (capability_is_valid(cap) && should_revoke(cap)) {
            slots[c] = capability_clear_tag(cap);
          }
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

    // 4. The backlog is retired: give its pages back and refund whoever paid.
    release_pages();
  }

  const uint64_t swept = g_pending_epoch;
  __atomic_store_n(&g_completed_epoch, swept, __ATOMIC_RELEASE);
  __atomic_store_n(&g_pending_epoch, swept + 1, __ATOMIC_RELEASE);
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

bool query(Capability handle, RevokerAuthority* out_copy) {
  Capability open = unseal_revoker(handle);
  if (!capability_is_valid(open)) {
    return false;
  }
  if (out_copy != nullptr) {
    out_copy->base = capability_get_base(open);
    out_copy->top = out_copy->base + capability_get_length(open);
  }
    return true;
}

} // namespace signetos::revoke
