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
 * compartment.cpp - SignetOS protection domains
 *
 * See compartment.hpp for the page layout and the authentication model.
 */

#include <signetos/compartment.hpp>
#include <signetos/quota.hpp>
#include <signetos/sealing.hpp>
#include <signetos/sentry.hpp>
#include <signetos/trap.hpp>

namespace signetos::compartment {
namespace {

using sentry::ENTRIES_PER_PAGE;
using sentry::ENTRY_PAGE_HEADER;
using sentry::EntryRecord;

size_t s_live_count = 0;

// The next UID to hand out. Starts at 1 so 0 always means "no compartment",
// and only ever increases, so a UID is never reused.
uint64_t s_next_uid = 1;

// A range page starts with its `next` pointer, so the page capability itself
// addresses that pointer.
Capability* next_of(Capability range_page) {
  return reinterpret_cast<Capability*>(range_page);
}

// The quota that paid for this page, stored 16 bytes in, behind `next`.
Capability* funder_of(Capability range_page) {
  Capability f = capability_set_address(
      range_page, capability_get_base(range_page) + CAP_BYTES);
  return reinterpret_cast<Capability*>(f);
}

// The record array, bounded so it cannot reach back over the `next` pointer.
Range* records_of(Capability range_page) {
  Capability r = capability_set_address(
      range_page, capability_get_base(range_page) + RANGE_PAGE_HEADER);
  r = capability_set_bounds(r, RANGES_PER_PAGE * sizeof(Range));
  return reinterpret_cast<Range*>(r);
}

// True if two quota handles name the same node. Comparing bases rather than
// whole capabilities means a caller may present any copy of the handle.
bool same_quota(Capability a, Capability b) {
  return capability_is_valid(a) && capability_is_valid(b) &&
         capability_get_base(a) == capability_get_base(b);
}

// The record for the allocation BASED at `va`, searched across every page in
// this compartment's chain, whichever quota funded it. `out_funder` receives
// the quota that paid, which is the funder of the page holding the record.
//
// Matching on the base means a capability pointing into the middle of an
// allocation does not find it, and a compartment that does not own the range
// does not find it either -- it is not in this chain.
//
// TODO: this is very slow. It reads every record on every page until it hits a
// match, so a compartment holding N allocations costs O(N) per lookup, and a
// miss always costs the full N. Every free touches it. A sorted structure or a
// hash keyed on `va` would be better, but both cost memory that has to come out
// of the quota, so leaving it linear until the cost actually shows up.
Range* find_range(Capability comp_page, uint64_t va, Capability* out_funder) {
  if (va == 0) {
    return nullptr;  // 0 is the free marker, never a real allocation
  }
  const Compartment* c = reinterpret_cast<const Compartment*>(comp_page);
  for (Capability p = c->ranges; capability_is_valid(p); p = *next_of(p)) {
    Range* records = records_of(p);
    for (size_t i = 0; i < RANGES_PER_PAGE; ++i) {
      if (capability_is_valid(records[i].cap) &&
          capability_get_base(records[i].cap) == va) {
        if (out_funder != nullptr) {
          *out_funder = *funder_of(p);
        }
        return &records[i];
      }
    }
  }
  return nullptr;
}

// A free record on a page funded by `mem_quota`, or null if there is none.
//
// Pages funded by other quotas are skipped even when they have room: a quota
// pays for its own bookkeeping and no one else's.
//
// TODO: also very slow, and worse than find_range -- the free slot is usually
// on the last matching page, so this walks nearly the whole chain on every
// allocation. A per-quota free list would make it O(1).
Range* find_free_record(Capability comp_page, Capability mem_quota) {
  const Compartment* c = reinterpret_cast<const Compartment*>(comp_page);
  for (Capability p = c->ranges; capability_is_valid(p); p = *next_of(p)) {
    if (!same_quota(*funder_of(p), mem_quota)) {
      continue;  // somebody else's page
    }
    Range* records = records_of(p);
    for (size_t i = 0; i < RANGES_PER_PAGE; ++i) {
      if (!capability_is_valid(records[i].cap)) {
        return &records[i];
      }
    }
  }
  return nullptr;
}

// True if [base, base + len) lies wholly inside one allocation recorded in
// this compartment's range chain.
bool owns(Capability comp_page, uint64_t base, uint64_t len) {
  const Compartment* c = reinterpret_cast<const Compartment*>(comp_page);
  for (Capability p = c->ranges; capability_is_valid(p); p = *next_of(p)) {
    const Range* records = records_of(p);
    for (size_t i = 0; i < RANGES_PER_PAGE; ++i) {
      if (!capability_is_valid(records[i].cap)) {
        continue;
      }
      const uint64_t start = capability_get_base(records[i].cap);
      const uint64_t end = start + capability_get_length(records[i].cap);
      if (base >= start && len <= end - base && base < end) {
        return true;
      }
    }
  }
  return false;
}

// The entry record array of an entry page. Entry pages share the range page
// header layout (`next`, `funder`), so next_of and funder_of apply to them.
EntryRecord* entries_of(Capability entry_page) {
  Capability r = capability_set_address(
      entry_page, capability_get_base(entry_page) + ENTRY_PAGE_HEADER);
  r = capability_set_bounds(r, ENTRIES_PER_PAGE * sizeof(EntryRecord));
  return reinterpret_cast<EntryRecord*>(r);
}

// A free entry record (null `code`) in this compartment's entry chain, or
// null if every page is full.
EntryRecord* find_free_entry(Capability comp_page) {
  const Compartment* c = reinterpret_cast<const Compartment*>(comp_page);
  for (Capability p = c->entries; capability_is_valid(p); p = *next_of(p)) {
    EntryRecord* records = entries_of(p);
    for (size_t i = 0; i < ENTRIES_PER_PAGE; ++i) {
      if (!capability_is_valid(records[i].pcc)) {
        return &records[i];
      }
    }
  }
  return nullptr;
}

// Unseals `handle` and returns a writable kernel capability to the whole
// page the compartment occupies.
//
// `yunseal` proves the handle came from this kernel, since only the holder of
// the OTYPE_COMPARTMENT authority can produce CT 7. The handle is bounded to
// `sizeof(Compartment)` and stores `self_page` at offset 0 so the kernel loads
// the full-page capability directly from the unsealed struct.
Capability unseal(Capability handle) {
  // `LoadMutable` is required on top of the usual `Load | LoadCapability`:
  // without it the table capabilities read back through the handle would
  // silently lose `Permit_Store`.
  Compartment* c = sealing::open_live<Compartment>(
      OType::Compartment, handle, FLAG_LIVE,
      perms::Load | perms::LoadCapability | perms::LoadMutable);
  return reinterpret_cast<Capability>(c);
}

// A capability covering slots [first, first + count) of the table in `page`.
Capability table_slice(Capability page, size_t first, size_t count) {
  const uint64_t va =
      capability_get_base(page) + TABLE_OFFSET + first * CAP_BYTES;
  Capability slice = capability_set_address(page, va);
  slice = capability_set_bounds(slice, count * CAP_BYTES);
  return capability_is_valid(slice) ? slice : nullptr;
}

// What a compartment gets for memory it may store capabilities into: the same
// capability without StoreLocal. Thread stacks are local (`thread::create`),
// so through this view a store of a stack pointer -- or anything derived from
// one -- drops its tag. A capability table or an allocation can therefore
// never carry a pointer into a thread's stack to another thread, and the only
// StoreLocal memory a compartment ever holds is its own thread stacks, which
// is what lets the switcher recognise a real thread stack by that permission.
Capability user_view(Capability cap) {
  return capability_restrict_levels(cap, perms::StoreLocal);
}

}  // namespace

void init() {
  s_live_count = 0;
  s_next_uid = 1;
}

size_t live_count() { return __atomic_load_n(&s_live_count, __ATOMIC_RELAXED); }

Capability create(Capability mem_quota, Capability initial_capabilities,
                  Status* out_status) {
  // Every early exit goes through here so the status is never forgotten.

  // How many capabilities to seed. The count comes from the array's own
  // bounds, which is why sys_compartment_create needs no count argument.
  size_t seed_count = 0;
  if (capability_is_valid(initial_capabilities)) {
    // TODO this needs to have a max value or have a sensible size check for
    // obvious reasons.
    seed_count = capability_get_length(initial_capabilities) / CAP_BYTES;

    // Loading through a capability without Permit_Load_Capability yields
    // untagged data, so the copies would arrive as dead bit patterns.
    constexpr uint64_t needed = perms::Load | perms::LoadCapability;
    if ((capability_get_perms(initial_capabilities) & needed) != needed) {
      return fail_with(out_status, Status::InvalidCapability);
    }

    // Make sure we are not tricked into copying the kernel stack to the
    //  new comp as an initial arg capability
    const Capability sp = __builtin_cheri_stack_get();
    const uint64_t sp_base = capability_get_base(sp);
    const uint64_t sp_top = sp_base + capability_get_length(sp);
    const uint64_t seeds_base = capability_get_base(initial_capabilities);
    const uint64_t seeds_top =
        seeds_base + capability_get_length(initial_capabilities);
    if (seeds_base < sp_top && sp_base < seeds_top) {
      return fail_with(out_status, Status::NotInRange);
    }
  }

  // Slots 0-1 hold `SLOT_SELF` and `SLOT_VM_QUOTA`; the seeds follow. The
  // table is as many pages as that takes (one for up to `CAP_SLOTS` slots),
  // and a seed array that would need more than `MAX_COMPARTMENT_PAGES` is
  // refused, which also bounds how much a creator can ask the kernel to copy.
  const size_t pages = pages_for_slots(RW_SLOT_SEED_BASE + seed_count);
  if (pages > MAX_COMPARTMENT_PAGES) {
    return fail_with(out_status, Status::TooManyCapabilities);
  }
  const size_t slots = slots_in_pages(pages);
  const uint64_t cost = pages * vm::PAGE_SIZE;

  // Bill the pages before allocating them. charge() is also the check on
  // mem_quota: it unseals the handle, proving it is a genuine quota, and it
  // requires Permit_Load.
  const Status charged = quota::charge(mem_quota, cost);
  if (charged != Status::Ok) {
    return fail_with(out_status, charged);
  }

  // One allocation: struct at the front, table behind it. Comes back zeroed,
  // so every slot starts empty and untagged.
  Capability page = vm::alloc_pages(pages);
  if (!capability_is_valid(page)) {
    quota::refund(mem_quota, cost);
    return fail_with(out_status, Status::NoMemory);
  }

  // The table slice is what `cgp` will be. Its bounds must be exactly
  // representable, which they are for every size up to the maximum (the
  // header offset and the page-aligned top are far more aligned than the
  // encoding asks); checked rather than assumed.
  Capability table = table_slice(page, 0, slots);
  if (!capability_is_valid(table)) {
    vm::free_pages(page);
    quota::refund(mem_quota, cost);
    return fail_with(out_status, Status::InvalidRange);
  }

  // The handle names the struct, not the page, so unsealing it cannot reach
  // the table. Its base is still the page base, which is what unseal()
  // reads.
  Capability handle = capability_set_bounds(page, sizeof(Compartment));
  handle = sealing::seal_as(OType::Compartment, handle);
  if (!capability_is_valid(handle)) {
    vm::free_pages(page);
    quota::refund(mem_quota, cost);
    return fail_with(out_status, Status::InvalidCapability);
  }

  // Consumed only now that the compartment definitely exists, so a failed
  // creation does not burn a UID.
  const uint64_t uid = __atomic_fetch_add(&s_next_uid, 1, __ATOMIC_RELAXED);

  Compartment* c = reinterpret_cast<Compartment*>(page);
  c->self_page = page;
  c->quota = mem_quota;  // kept so destroy can refund the pages later
  c->ranges = nullptr;   // no memory owned yet, so no range pages
  c->entries = nullptr;  // no entry points yet, so no entry pages
  c->uid = uid;
  c->table_slots = slots;
  c->flags = FLAG_LIVE;
  c->inside = 0;
  c->lock = SpinLock{};

  // The table is filled through the same view the compartment itself gets
  // (no StoreLocal), so a local capability among the seeds -- a pointer into
  // the creator's thread stack -- arrives untagged, exactly as it would if the
  // compartment had tried to store it there itself.
  Capability* slot = reinterpret_cast<Capability*>(user_view(table));
  slot[SLOT_SELF] = handle;         // so code inside can name its own domain
  slot[SLOT_VM_QUOTA] = mem_quota;  // its allocation authority

  const Capability* seeds =
      reinterpret_cast<const Capability*>(initial_capabilities);
  for (size_t i = 0; i < seed_count; ++i) {
    slot[RW_SLOT_SEED_BASE + i] = seeds[i];
  }

  __atomic_fetch_add(&s_live_count, 1, __ATOMIC_RELAXED);
  if (out_status != nullptr) {
    *out_status = Status::Ok;
  }
  return handle;
}

Capability table_writable(Capability handle) {
  Capability page = unseal(handle);
  if (!capability_is_valid(page)) {
    return nullptr;
  }
  const Compartment* c = reinterpret_cast<const Compartment*>(page);
  return user_view(table_slice(page, 0, c->table_slots));
}

Capability add_entry(Capability comp, Capability code, bool require_owned,
                     Status* out_status) {
  Capability comp_page = unseal(comp);
  if (!capability_is_valid(comp_page) || !capability_is_valid(code)) {
    return fail_with(out_status, Status::InvalidCapability);
  }

  Compartment* c = reinterpret_cast<Compartment*>(comp_page);
  Locked hold(c->lock);
  if ((__atomic_load_n(&c->flags, __ATOMIC_ACQUIRE) &
       (FLAG_LIVE | FLAG_DYING)) != FLAG_LIVE) {
    return fail_with(out_status, Status::InvalidCapability);
  }

  if (require_owned &&
      !owns(comp_page, capability_get_base(code), capability_get_length(code))) {
    return fail_with(out_status, Status::NotOwned);
  }

  EntryRecord* record = find_free_entry(comp_page);
  if (record == nullptr) {
    // Billed to the compartment's own funding quota, like the struct page.
    const Capability funder = c->quota;
    const Status paid = quota::charge(funder, vm::PAGE_SIZE);
    if (paid != Status::Ok) {
      return fail_with(out_status, paid);
    }

    Capability fresh = vm::alloc_pages(1);
    if (!capability_is_valid(fresh)) {
      quota::refund(funder, vm::PAGE_SIZE);
      return fail_with(out_status, Status::NoMemory);
    }

    *next_of(fresh) = c->entries;
    *funder_of(fresh) = funder;
    c->entries = fresh;
    record = &entries_of(fresh)[0];
  }

  record->pcc = code;
  record->cgp = user_view(table_slice(comp_page, 0, c->table_slots));
  record->owner = comp_page;
  record->flags = 0;  // a compartment entry is never trusted
  record->min_stack = sentry::DEFAULT_MIN_STACK;

  Capability out = capability_set_bounds(reinterpret_cast<Capability>(record),
                                         sizeof(EntryRecord));
  if (out_status != nullptr) {
    *out_status = Status::Ok;
  }
  return out;
}

size_t entry_pages(Capability comp) {
  Capability comp_page = unseal(comp);
  if (!capability_is_valid(comp_page)) {
    return 0;
  }
  Compartment* c = reinterpret_cast<Compartment*>(comp_page);
  Locked hold(c->lock);
  if ((__atomic_load_n(&c->flags, __ATOMIC_ACQUIRE) & FLAG_LIVE) == 0) {
    return 0;
  }
  size_t count = 0;
  for (Capability p = c->entries; capability_is_valid(p); p = *next_of(p)) {
    count += 1;
  }
  return count;
}

Capability allocate(Capability comp, Capability mem_quota, size_t size,
                    uint32_t flags, Status* out_status) {
  // TODO
  (void)flags;

  // Whose chain this range will be recorded in.
  Capability comp_page = unseal(comp);
  if (!capability_is_valid(comp_page)) {
    return fail_with(out_status, Status::InvalidCapability);
  }

  // Round up to whole pages. A zero request has nothing to allocate, and
  // anything larger than the whole dynamic address space can never be
  // satisfied -- which also keeps the rounding below from wrapping.
  constexpr uint64_t MAX_REQUEST = vm::DYNAMIC_TOP - vm::DYNAMIC_BASE;
  if (size == 0 || size > MAX_REQUEST) {
    return fail_with(out_status, Status::InvalidSize);
  }
  const size_t pages = (size + vm::PAGE_SIZE - 1) / vm::PAGE_SIZE;
  const uint64_t bytes = pages * vm::PAGE_SIZE;

  Compartment* c = reinterpret_cast<Compartment*>(comp_page);
  Locked hold(c->lock);
  if ((__atomic_load_n(&c->flags, __ATOMIC_ACQUIRE) &
       (FLAG_LIVE | FLAG_DYING)) != FLAG_LIVE) {
    return fail_with(out_status, Status::InvalidCapability);
  }

  // Somewhere to write the record down. Only pages funded by THIS quota are
  // eligible; if none of them has room, buy another and charge it here, so a
  // quota never fills a page somebody else paid for.
  Range* record = find_free_record(comp_page, mem_quota);
  if (record == nullptr) {
    const Status paid = quota::charge(mem_quota, vm::PAGE_SIZE);
    if (paid != Status::Ok) {
      return fail_with(out_status, paid);
    }

    Capability fresh = vm::alloc_pages(1);
    if (!capability_is_valid(fresh)) {
      quota::refund(mem_quota, vm::PAGE_SIZE);
      return fail_with(out_status, Status::NoMemory);
    }

    // Head insertion, O(1). The page arrives zeroed, so every record in it
    // is already free and its own `next` is already null before it is
    // overwritten with the old head.
    *next_of(fresh) = c->ranges;
    *funder_of(fresh) = mem_quota;  // so destroy refunds whoever paid
    c->ranges = fresh;
    record = &records_of(fresh)[0];
  }

  // Bill the memory itself. charge() also validates mem_quota: it unseals the
  // handle and requires Permit_Load.
  const Status charged = quota::charge(mem_quota, bytes);
  if (charged != Status::Ok) {
    return fail_with(out_status, charged);
  }

  // Reserve addresses, take frames, map them. Comes back zeroed.
  Capability memory = vm::alloc_pages(pages);
  if (!capability_is_valid(memory)) {
    quota::refund(mem_quota, bytes);
    return fail_with(out_status, Status::NoMemory);
  }

  // Write the record last, so no failure above can leave a half-filled one.
  // A range page bought a moment ago but left unused by a later failure stays
  // attached and is used by the next allocation from the same quota.
  //
  // No quota field: the page's funder is the quota, and it already matches.
  record->cap = memory;

  if (out_status != nullptr) {
    *out_status = Status::Ok;
  }
  // The record keeps the full capability (the kernel frees through it); the
  // compartment's copy cannot hold a local capability.
  return user_view(memory);
}

Status deallocate(Capability comp, Capability mem_quota,
                  Capability mem_capability) {
  Capability comp_page = unseal(comp);
  if (!capability_is_valid(comp_page)) {
    return Status::InvalidCapability;
  }

  Compartment* c = reinterpret_cast<Compartment*>(comp_page);
  Locked hold(c->lock);
  if ((__atomic_load_n(&c->flags, __ATOMIC_ACQUIRE) &
       (FLAG_LIVE | FLAG_DYING)) != FLAG_LIVE) {
    return Status::InvalidCapability;
  }

  // Searched in THIS compartment's chain, so finding it is what proves
  // ownership -- another compartment's allocation is not in here. The
  // capability is used only for its base, so a narrowed one pointing into the
  // middle matches nothing rather than freeing a fraction.
  Capability funder = nullptr;
  Range* range =
      find_range(comp_page, capability_get_base(mem_capability), &funder);
  if (range == nullptr) {
    return Status::NotFound;
  }

  // The refund is made to the page's funder, never to the caller's handle.
  // Requiring them to name the same node means a caller cannot allocate
  // against one budget and quietly credit another.
  if (!same_quota(mem_quota, funder)) {
    return Status::WrongQuota;
  }

  // Free through the capability stored in the record so the WHOLE range is
  // released, even if the caller passed a truncated capability.
  Capability whole = range->cap;
  const uint64_t bytes = capability_get_length(whole);
  if (!vm::free_pages(whole)) {
    return Status::InvalidCapability;
  }

  quota::refund(funder, bytes);

  range->cap = nullptr;  // frees the record
  return Status::Ok;
}

// NOTE: Implemented for now as a synchronous up-front memory copy; we will
// return later to make this lazy page-table copy-on-write.
Capability cow(Capability comp, Capability mem_quota, Capability src_memory,
               size_t len, Status* out_status) {
  if (len == 0 || (len & (vm::PAGE_SIZE - 1)) != 0) {
    return fail_with(out_status, Status::InvalidSize);
  }
  if (!capability_is_valid(src_memory) || sealing::is_sealed(src_memory)) {
    return fail_with(out_status, Status::InvalidCapability);
  }
  if (!capability_has_perms(src_memory, perms::Load)) {
    return fail_with(out_status, Status::InsufficientPermission);
  }
  // Only global memory may be cloned. A local source is a thread stack (or
  // derived from one), and this body runs on a slice of the caller's stack
  // (switch.S, `.Lenter_kernel`): the copy below would pick up, tags intact,
  // the capabilities the kernel itself spilled there -- this frame and the
  // dead frames of `allocate()` and its callees. A stack is not something to
  // clone anyway; it can only ever hold its own thread's state.
  if (!capability_has_perms(src_memory, perms::Global)) {
    return fail_with(out_status, Status::InsufficientPermission);
  }

  const uint64_t src_base = capability_get_base(src_memory);
  const uint64_t src_len = capability_get_length(src_memory);
  const uint64_t src_addr = capability_get_address(src_memory);
  if (src_addr < src_base || len > src_len ||
      src_addr - src_base > src_len - len) {
    return fail_with(out_status, Status::NotInRange);
  }

  const uint64_t first_page = src_addr & ~(vm::PAGE_SIZE - 1);
  const uint64_t end_addr = src_addr + len;
  for (uint64_t va = first_page; va < end_addr; va += vm::PAGE_SIZE) {
    constexpr uint64_t kNeeded = vm::pte::Valid | vm::pte::Read;
    if ((vm::leaf_flags(va) & kNeeded) != kNeeded) {
      return fail_with(out_status, Status::InvalidRange);
    }
  }

  Capability dst = allocate(comp, mem_quota, len, 0, out_status);
  if (!capability_is_valid(dst)) {
    return nullptr;
  }

  if ((src_addr & (CAP_BYTES - 1)) == 0 &&
      capability_has_perms(src_memory, perms::LoadCapability)) {
    const auto* src_caps = reinterpret_cast<const Capability*>(src_memory);
    auto* dst_caps = reinterpret_cast<Capability*>(dst);
    const size_t n_caps = len / CAP_BYTES;
    for (size_t i = 0; i < n_caps; ++i) {
      dst_caps[i] = src_caps[i];
    }
  } else {
    const auto* src_bytes = reinterpret_cast<const uint8_t*>(src_memory);
    auto* dst_bytes = reinterpret_cast<uint8_t*>(dst);
    for (size_t i = 0; i < len; ++i) {
      dst_bytes[i] = src_bytes[i];
    }
  }

  return dst;
}

uint64_t phys(Capability comp, Capability mem_capability) {
  if (!capability_is_valid(mem_capability) ||
      sealing::is_sealed(mem_capability)) {
    return 0;
  }
  const uint64_t base = capability_get_base(mem_capability);
  const uint64_t len = capability_get_length(mem_capability);
  if (len == 0 || (base & (vm::PAGE_SIZE - 1)) != 0 ||
      !owns_range(comp, base, len)) {
    return 0;
  }
  const uint64_t pa = vm::translate(base);
  if (pa == 0) {
    return 0;
  }
  for (uint64_t off = vm::PAGE_SIZE; off < len; off += vm::PAGE_SIZE) {
    if (vm::translate(base + off) != pa + off) {
      return 0;
    }
  }
  return pa;
}

Status destroy(Capability handle) {
  Capability comp_page = unseal(handle);
  if (!capability_is_valid(comp_page)) {
    return Status::InvalidCapability;
  }

  Compartment* c = reinterpret_cast<Compartment*>(comp_page);
  Capability funding = nullptr;
  uint64_t cost = 0;
  {
    Locked hold(c->lock);
    if ((__atomic_load_n(&c->flags, __ATOMIC_SEQ_CST) &
         (FLAG_LIVE | FLAG_DYING)) != FLAG_LIVE) {
      return Status::InvalidCapability;
    }

    // Mark first, then look (WHO IS INSIDE, compartment.hpp). `enter` does the
    // opposite -- counts first, then looks -- so one of the two always sees the
    // other. Full-strength atomics on both sides: this is the one place where
    // the ordering of a write and a read on different harts is the whole point.
    __atomic_fetch_or(&c->flags, FLAG_DYING, __ATOMIC_SEQ_CST);
    if (__atomic_load_n(&c->inside, __ATOMIC_SEQ_CST) != 0) {
      __atomic_fetch_and(&c->flags, ~FLAG_DYING, __ATOMIC_SEQ_CST);
      // While the mark was up, an interrupt bound to this compartment that
      // arrived on another hart was treated as unbound and silenced there
      // (trap.cpp). The binding stands, so bring every hart back in line.
      trap::sync_all_harts();
      return Status::Busy;
    }

    // That was the last check. Everything after this point must succeed,
    // because once the first page is released there is nothing to roll back to.

    // Copied out now: it lives in the page this function frees last, and a
    // freed page is not to be read, even though it is still mapped. The
    // allocation's length is what `create` billed, however many pages the
    // table spans.
    funding = c->quota;
    cost = capability_get_length(comp_page);

    // Walk the chain, releasing what each page describes and then the page.
    for (Capability p = c->ranges; capability_is_valid(p);) {
      // Read before p is freed. The page stays mapped after free_pages, but
      // it is no longer this compartment's and must not be relied on.
      const Capability next = *next_of(p);
      const Capability funder = *funder_of(p);

      // Release every allocation this page still records. They were all
      // funded by `funder` -- that is what sharing a page means.
      Range* records = records_of(p);
      for (size_t i = 0; i < RANGES_PER_PAGE; ++i) {
        if (!capability_is_valid(records[i].cap)) {
          continue;  // free slot, nothing to release
        }
        Capability whole = records[i].cap;
        const uint64_t bytes = capability_get_length(whole);
        if (vm::free_pages(whole)) {
          quota::refund(funder, bytes);
        }
        records[i].cap = nullptr;
      }

      // Now the bookkeeping page itself, refunded to whoever bought it.
      vm::free_pages(p);
      quota::refund(funder, vm::PAGE_SIZE);
      p = next;
    }
    c->ranges = nullptr;

    // Purge any hardware trap/interrupt bindings registered to this compartment
    // (design_spec.md section 5.4).
    trap::purge_compartment(c->uid);

    // Release the entry chain. Every record is cleared first so a sentry that
    // still names one resolves to nothing, then the page is refunded.
    for (Capability p = c->entries; capability_is_valid(p);) {
      const Capability next = *next_of(p);
      const Capability funder = *funder_of(p);
      EntryRecord* records = entries_of(p);
      for (size_t i = 0; i < ENTRIES_PER_PAGE; ++i) {
        records[i] = EntryRecord{};
      }
      vm::free_pages(p);
      quota::refund(funder, vm::PAGE_SIZE);
      p = next;
    }
    c->entries = nullptr;

    // This is what kills a stale handle. The page is quarantined below, not
    // unmapped, so a stale handle still unseals and still reaches the struct;
    // unseal() refuses it because this flag is clear and self_page is null.
    // FLAG_DYING stays set, so an `enter` that read its record just before it
    // was cleared is refused by that too.
    __atomic_fetch_and(&c->flags, ~FLAG_LIVE, __ATOMIC_SEQ_CST);
    c->self_page = nullptr;
  }

  __atomic_fetch_sub(&s_live_count, 1, __ATOMIC_RELAXED);

  // Last, because everything above reads through it. The UID is deliberately
  // not reclaimed (design_spec.md section 5.4).
  vm::free_pages(comp_page);
  quota::refund(funding, cost);
  return Status::Ok;
}

bool enter(Capability page) {
  if (!capability_is_valid(page)) {
    return false;
  }
  Compartment* c = reinterpret_cast<Compartment*>(page);
  // Count first, then look: the mirror image of destroy.
  __atomic_fetch_add(&c->inside, 1, __ATOMIC_SEQ_CST);
  const uint32_t flags = __atomic_load_n(&c->flags, __ATOMIC_SEQ_CST);
  if ((flags & (FLAG_LIVE | FLAG_DYING)) != FLAG_LIVE) {
    __atomic_fetch_sub(&c->inside, 1, __ATOMIC_SEQ_CST);
    return false;
  }
  return true;
}

void leave(Capability page) {
  if (!capability_is_valid(page)) {
    return;
  }
  Compartment* c = reinterpret_cast<Compartment*>(page);
  __atomic_fetch_sub(&c->inside, 1, __ATOMIC_SEQ_CST);
}

bool query(Capability handle, Compartment* out_copy) {
  Capability page = unseal(handle);
  if (!capability_is_valid(page)) {
    return false;
  }
  if (out_copy != nullptr) {
    *out_copy = *reinterpret_cast<const Compartment*>(page);
  }
  return true;
}

bool query_range(Capability comp, uint64_t va, Range* out_copy,
                 Capability* out_funder) {
  Capability comp_page = unseal(comp);
  if (!capability_is_valid(comp_page)) {
    return false;
  }
  Compartment* c = reinterpret_cast<Compartment*>(comp_page);
  Locked hold(c->lock);
  if ((__atomic_load_n(&c->flags, __ATOMIC_ACQUIRE) & FLAG_LIVE) == 0) {
    return false;
  }
  Capability funder = nullptr;
  const Range* range = find_range(comp_page, va, &funder);
  if (range == nullptr) {
    return false;
  }
  if (out_copy != nullptr) {
    *out_copy = *range;
  }
  if (out_funder != nullptr) {
    *out_funder = funder;
  }
  return true;
}

bool owns_range(Capability comp, uint64_t base, uint64_t len,
                Status* out_status) {
  Capability comp_page = unseal(comp);
  if (!capability_is_valid(comp_page)) {
    if (out_status != nullptr) {
      *out_status = Status::InvalidCapability;
    }
    return false;
  }
  if (len == 0 || base + len < base) {
    if (out_status != nullptr) {
      *out_status = Status::InvalidRange;
    }
    return false;
  }
  Compartment* c = reinterpret_cast<Compartment*>(comp_page);
  Locked hold(c->lock);
  if ((__atomic_load_n(&c->flags, __ATOMIC_ACQUIRE) & FLAG_LIVE) == 0) {
    if (out_status != nullptr) {
      *out_status = Status::InvalidCapability;
    }
    return false;
  }
  if (!owns(comp_page, base, len)) {
    if (out_status != nullptr) {
      *out_status = Status::NotInRange;
    }
    return false;
  }
  if (out_status != nullptr) {
    *out_status = Status::Ok;
  }
  return true;
}

// TODO: slow for the same reason -- counts by reading every record on every
// page, with no early exit. A running total on the Compartment would remove it.
size_t range_count(Capability comp) {
  Capability comp_page = unseal(comp);
  if (!capability_is_valid(comp_page)) {
    return 0;
  }
  Compartment* c = reinterpret_cast<Compartment*>(comp_page);
  Locked hold(c->lock);
  if ((__atomic_load_n(&c->flags, __ATOMIC_ACQUIRE) & FLAG_LIVE) == 0) {
    return 0;
  }
  size_t used = 0;
  for (Capability p = c->ranges; capability_is_valid(p); p = *next_of(p)) {
    const Range* records = records_of(p);
    for (size_t i = 0; i < RANGES_PER_PAGE; ++i) {
      if (capability_is_valid(records[i].cap)) {
        used += 1;
      }
    }
  }
  return used;
}

size_t range_pages(Capability comp) {
  Capability comp_page = unseal(comp);
  if (!capability_is_valid(comp_page)) {
    return 0;
  }
  Compartment* c = reinterpret_cast<Compartment*>(comp_page);
  Locked hold(c->lock);
  if ((__atomic_load_n(&c->flags, __ATOMIC_ACQUIRE) & FLAG_LIVE) == 0) {
    return 0;
  }
  size_t count = 0;
  for (Capability p = c->ranges; capability_is_valid(p); p = *next_of(p)) {
    count += 1;
  }
  return count;
}

}  // namespace signetos::compartment
