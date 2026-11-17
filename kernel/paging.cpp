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
 * paging.cpp - SignetOS paging (vm.hpp, PAGING)
 *
 * Built only with SIGNETOS_PAGING. Decides which pageable pages are in RAM,
 * and carries a page's bytes and capabilities to swap and back. It reads page
 * entries and changes them only through `give_frame_locked` and
 * `take_frame_locked` (vm_pages.hpp).
 */

#include <signetos/debug/report.hpp>
#include <signetos/frame.hpp>
#include <signetos/lock.hpp>
#include <signetos/revoke.hpp>
#include <signetos/sealing.hpp>
#include <signetos/vm.hpp>
#include <signetos/vm_pages.hpp>
#if defined(SIGNETOS_SWAP_HASH)
#include <signetos/lib/blake2b.hpp>
#endif

namespace signetos::vm {
namespace {

// Everything here runs under `s_lock`.

constexpr size_t CAPS_PER_PAGE = PAGE_SIZE / sizeof(Capability);
constexpr size_t TAG_BYTES = CAPS_PER_PAGE / 8;

// The pages brought in last, which the clock passes over: as many as one
// instruction can touch, rounded up.
constexpr size_t RECENT = 4;

// What the kernel keeps beside each slot that holds a page (CAPABILITIES).
struct SlotInfo {
  uint8_t tags[TAG_BYTES];  // a bit per granule that held a capability
#if defined(SIGNETOS_SWAP_HASH)
  uint8_t digest[blake2b::DIGEST_BYTES];
#endif
};

// The job handed out to the pager (THE PAGER), until it says it is done.
enum : uint64_t { JOB_NONE, JOB_IN, JOB_OUT, JOB_CHECK };
struct Job {
  uint64_t op;     // JOB_*
  uint64_t slot;   // the slot read or written
  uint64_t va;     // JOB_IN, JOB_OUT: the page
  uint64_t frame;  // JOB_IN: the frame it comes in on
};

// A thread waiting for a page (FAULTS), until the pager wakes it. tid 0:
// unused. More waiters than this are not noted: each wakes when the block
// it was put in times out, and tries again.
constexpr size_t MAX_WAITERS = 32;
struct Waiter {
  uint64_t va;
  uint64_t tid;
};

struct Paging {
  SlotInfo* slots;      // one per slot (SWAP)
  uint64_t* slot_used;  // a bit per slot: it holds a page
  uint64_t slot_hint;   // where the search for a free one starts
  Capability scratch;   // a page of the kernel's, where a check's copy goes
  uint64_t hand;        // the page the clock looks at next
  uint64_t recent[RECENT];
  size_t recent_next;
  bool refill;          // FRAMES: pages go out until `high` frames are free
  Waiter waiters[MAX_WAITERS];
  uint64_t pager;       // the pager's tid, once it has asked for a job
  Job job;
  uint64_t check_next;  // the slot the checks look at next; none: the count
#if defined(SIGNETOS_PAGE_TEST)
  uint64_t evict_next;  // PAGE_TEST_EVICT: the pages still to send out
  uint64_t evict_end;
#endif
  uint64_t reads, writes, checks, digest_errors;  // PAGE_TEST_*
};
Paging s_paging;

// How many slots of swap there are (SWAP). 0 until paging is set up; set
// last, and once.
size_t s_slot_count = 0;
size_t slot_count() { return __atomic_load_n(&s_slot_count, __ATOMIC_ACQUIRE); }

// The boot root, kept by set_retag_root to build capabilities again, and
// where the CT field sits in the upper word of a capability's bits.
Capability s_retag_root = nullptr;
uint64_t s_ct_shift = 0;
constexpr uint64_t CT_MASK = 0x1F;

bool in_pool(uint64_t va) { return va >= DYNAMIC_BASE && va < BITMAP_BASE; }

// What `page_next` returns for a job (vm.hpp, THE PAGER).
uint64_t request(uint64_t slot_or_tid, uint64_t op) {
  return (slot_or_tid << PAGE_SLOT_SHIFT) | op;
}

volatile uint64_t* frame_words(uint64_t pa) {
  return reinterpret_cast<volatile uint64_t*>(phys_view(pa, PAGE_SIZE));
}
volatile Capability* frame_caps(uint64_t pa) {
  return reinterpret_cast<volatile Capability*>(phys_view(pa, PAGE_SIZE));
}

bool has_tag(const SlotInfo& info, size_t i) {
  return ((info.tags[i / 8] >> (i % 8)) & 1) != 0;
}
bool has_tags(const SlotInfo& info) {
  for (const uint8_t b : info.tags) {
    if (b != 0) {
      return true;
    }
  }
  return false;
}

// FRAMES: the three marks, in free frames. Policy, and a guess.
size_t reserve_frames() { return frame::pool_pages() / 64; }
size_t low_frames() { return 2 * reserve_frames(); }
size_t high_frames() { return 3 * reserve_frames(); }

// Whether a pageable page may take a frame now.
bool frame_to_spare() { return frame::free_pages() > reserve_frames(); }

// SWAP: which slots hold a page.
bool slot_in_use(uint64_t slot) {
  return ((s_paging.slot_used[slot / 64] >> (slot % 64)) & 1) != 0;
}
void set_slot_in_use(uint64_t slot, bool on) {
  const uint64_t bit = 1ULL << (slot % 64);
  uint64_t& word = s_paging.slot_used[slot / 64];
  word = on ? (word | bit) : (word & ~bit);
}

// A free slot, which now holds a page. A page with a frame to lose always
// finds one: no more pageable pages are in use than there are slots (vm.hpp,
// SWAP), and every slot in use holds a page that has no frame.
uint64_t take_slot_locked() {
  const uint64_t count = slot_count();
  for (uint64_t looked = 0; looked < count; ++looked) {
    const uint64_t slot = (s_paging.slot_hint + looked) % count;
    if (!slot_in_use(slot)) {
      set_slot_in_use(slot, true);
      s_paging.slot_hint = slot + 1;
      return slot;
    }
  }
  debug::panic("paging: more pageable pages than slots of swap");
}

// `slot` holds a page no more.
void free_slot_locked(uint64_t slot) {
  if (slot >= slot_count() || !slot_in_use(slot)) {
    debug::panic("paging: a slot freed that holds no page");
  }
  set_slot_in_use(slot, false);
}

#if defined(SIGNETOS_SWAP_HASH)
// DIGESTS: of a page's bytes, never of `blk`'s buffer, which it could change
// while they are hashed.
void digest_page(const volatile uint64_t* w, uint8_t* out) {
  blake2b::hash256(const_cast<const uint64_t*>(w), PAGE_SIZE, out);
}
bool digest_matches(const SlotInfo& info, const volatile uint64_t* w) {
  uint8_t now[blake2b::DIGEST_BYTES];
  digest_page(w, now);
  uint8_t differ = 0;
  for (size_t i = 0; i < blake2b::DIGEST_BYTES; ++i) {
    differ = static_cast<uint8_t>(differ | (now[i] ^ info.digest[i]));
  }
  return differ == 0;
}
#endif

// Builds again the capability whose bits, without their tag, are the 16
// bytes at `w` (as two words) and `c` (as a capability slot): from the root,
// unsealed, then sealed as it was -- CT 1 through seal_entry, the only way a
// call sentry is made, a kernel type with its authority. It stays plain bytes
// if it is revoked (revoke.hpp, THE BASE RULE), if it is local (pageable
// memory never holds one), or if what comes out is not exactly what went out.
void rebuild_locked(volatile uint64_t* w, volatile Capability* c) {
  const uint64_t lo = w[0];
  const uint64_t hi = w[1];
  const Capability bits = *c;
  if (revoke::is_revoked(bits) ||
      (capability_get_perms(bits) & perms::Global) == 0) {
    return;
  }
  const uint64_t ct = (hi >> s_ct_shift) & CT_MASK;
  w[1] = hi & ~(CT_MASK << s_ct_shift);
  const Capability open = *c;
  Capability built = __builtin_cheri_cap_build(s_retag_root, (__uintcap_t)open);
  if (ct == static_cast<uint64_t>(OType::Sentry)) {
    built = sealing::seal_entry(built);
  } else if (ct != 0) {
    // Null for the types below kOTypeMin, which no page can hold.
    built = sealing::seal_with(sealing::authority_for(static_cast<OType>(ct)),
                               built);
  }
  *c = built;
  if (!capability_is_valid(*c) || w[0] != lo || w[1] != hi) {
    w[0] = lo;  // not what went out: plain bytes again
    w[1] = hi;
  }
}

// Makes page `va`, which is Fresh or Swapped, resident on frame `pa`: zeroed
// if it is Fresh; if it is Swapped, `src` copied in, checked against its
// digest, its capabilities built again, and its slot freed. False, with the
// page as it was, if the copy is not the page that went out.
bool bring_in_locked(uint64_t va, uint64_t pa, Capability src) {
  const uint64_t e = entry_locked(va);
  const bool swapped = pte_kind(e) == pte::KindSwapped;
  volatile uint64_t* w = frame_words(pa);
  if (!swapped) {
    for (size_t i = 0; i < PAGE_SIZE / sizeof(uint64_t); ++i) {
      w[i] = 0;
    }
  } else {
    const auto* from = reinterpret_cast<const volatile uint64_t*>(src);
    for (size_t i = 0; i < PAGE_SIZE / sizeof(uint64_t); ++i) {
      w[i] = from[i];
    }
    const SlotInfo& info = s_paging.slots[pte_slot(e)];
#if defined(SIGNETOS_SWAP_HASH)
    if (!digest_matches(info, w)) {
      s_paging.digest_errors += 1;
      return false;
    }
#endif
    volatile Capability* c = frame_caps(pa);
    for (size_t i = 0; i < CAPS_PER_PAGE; ++i) {
      if (has_tag(info, i)) {
        rebuild_locked(&w[2 * i], &c[i]);
      }
    }
    s_paging.reads += 1;
  }
  give_frame_locked(va, pa);
  __asm__ volatile("fence.i" ::: "memory");  // it may be code
  if (swapped) {
    free_slot_locked(pte_slot(e));
  }
  s_paging.recent[s_paging.recent_next] = va;
  s_paging.recent_next = (s_paging.recent_next + 1) % RECENT;
  return true;
}

bool is_recent(uint64_t va) {
  for (const uint64_t r : s_paging.recent) {
    if (r == va) {
      return true;
    }
  }
  return false;
}

// The clock: the page that goes out next to free a frame, or 0 if none may.
// It is the first from the hand on, once round the pool, that is pageable
// memory with a frame and not one of the last brought in. The hand stays on
// it until it goes.
uint64_t victim_locked() {
  // From the hand to the top of the pool, then all of it from the bottom.
  for (int pass = 0; pass < 2; ++pass) {
    for (uint64_t va = next_resident_pageable_locked(s_paging.hand); va != 0;
         va = next_resident_pageable_locked(va + PAGE_SIZE)) {
      if (!is_recent(va)) {
        s_paging.hand = va;
        return va;
      }
    }
    s_paging.hand = DYNAMIC_BASE;
  }
  return 0;
}

// Sends `va`, a resident page of pageable memory, out: its frame is taken
// away, copied into `buf`, and freed at once, and its tag bitmap and digest
// are kept beside the slot it is given. The write of `buf` to the slot is
// then the job in hand.
void send_out_locked(uint64_t va, Capability buf) {
  const uint64_t slot = take_slot_locked();
  const uint64_t pa = take_frame_locked(va, slot);
  const volatile uint64_t* w = frame_words(pa);
  const volatile Capability* c = frame_caps(pa);
  auto* to = reinterpret_cast<volatile uint64_t*>(buf);
  for (size_t i = 0; i < PAGE_SIZE / sizeof(uint64_t); ++i) {
    to[i] = w[i];
  }
  SlotInfo& info = s_paging.slots[slot];
  for (size_t i = 0; i < CAPS_PER_PAGE; ++i) {
    const uint8_t m = static_cast<uint8_t>(1u << (i % 8));
    info.tags[i / 8] = capability_is_valid(c[i])
                           ? static_cast<uint8_t>(info.tags[i / 8] | m)
                           : static_cast<uint8_t>(info.tags[i / 8] & ~m);
  }
#if defined(SIGNETOS_SWAP_HASH)
  digest_page(w, info.digest);
#endif
  frame::free(pa, 1);
  s_paging.writes += 1;
  s_paging.job = Job{JOB_OUT, slot, va, 0};
}

// Frees a frame by sending out the page the clock picks. False if no page
// may go.
bool free_a_frame_locked(Capability buf) {
  const uint64_t va = victim_locked();
  if (va == 0) {
    return false;
  }
  send_out_locked(va, buf);
  s_paging.hand = va + PAGE_SIZE;
  return true;
}

// Whether page `va` is in use with no frame: what a thread waits for
// (FAULTS).
bool waits_for_frame_locked(uint64_t va) {
  const uint64_t kind = pte_kind(entry_locked(va));
  return kind == pte::KindFresh || kind == pte::KindSwapped;
}

// The first slot from `from` on that holds a page with capabilities in it,
// or the slot count if there is none (REVOCATION).
uint64_t next_check_locked(uint64_t from) {
  for (uint64_t slot = from; slot < slot_count(); ++slot) {
    if (slot_in_use(slot) && has_tags(s_paging.slots[slot])) {
      return slot;
    }
  }
  return slot_count();
}

// Notes thread `tid` as waiting for page `va` (FAULTS).
void add_waiter_locked(uint64_t va, uint64_t tid) {
  Waiter* unused = nullptr;
  for (Waiter& w : s_paging.waiters) {
    if (w.tid == tid) {
      w.va = va;
      return;
    }
    if (w.tid == 0 && unused == nullptr) {
      unused = &w;
    }
  }
  if (unused != nullptr) {
    *unused = Waiter{va, tid};
  }
}

// THE PAGER: the job to do next, most urgent first.
uint64_t next_job_locked(Capability buf) {
  Job& j = s_paging.job;
  if (j.op != JOB_NONE) {  // not done yet: the same again
    return request(j.slot, j.op == JOB_OUT ? PAGE_WRITE : PAGE_READ);
  }

  // FAULTS. A thread whose page is in, or gone, is woken to run its access
  // again.
  for (Waiter& w : s_paging.waiters) {
    if (w.tid != 0 && !waits_for_frame_locked(w.va)) {
      const uint64_t tid = w.tid;
      w = Waiter{};
      return request(tid, PAGE_WAKE);
    }
  }
  // The first of the others gets a frame for its page, after a page has gone
  // out if there is none to spare. If none may go, the frames are held by
  // memory that is not pageable, and the threads go on waiting.
  for (Waiter& w : s_paging.waiters) {
    if (w.tid == 0) {
      continue;
    }
    if (!frame_to_spare()) {
      if (free_a_frame_locked(buf)) {
        return request(j.slot, PAGE_WRITE);
      }
      break;
    }
    const uint64_t pa = frame::alloc(1);
    if (pa == 0) {
      break;
    }
    const uint64_t e = entry_locked(w.va);
    if (pte_kind(e) == pte::KindSwapped) {
      j = Job{JOB_IN, pte_slot(e), w.va, pa};
      return request(j.slot, PAGE_READ);
    }
    bring_in_locked(w.va, pa, nullptr);  // Fresh: zeroed, and in at once
    const uint64_t tid = w.tid;
    w = Waiter{};
    return request(tid, PAGE_WAKE);
  }

  // FRAMES: once fewer than `low` frames are free, pages go out until `high`
  // are.
  const size_t free_frames = frame::free_pages();
  s_paging.refill = free_frames < low_frames() ||
                    (s_paging.refill && free_frames < high_frames());
  if (s_paging.refill && free_a_frame_locked(buf)) {
    return request(j.slot, PAGE_WRITE);
  }

#if defined(SIGNETOS_PAGE_TEST)
  // What a test asked to send out.
  while (s_paging.evict_next < s_paging.evict_end) {
    const uint64_t va = s_paging.evict_next;
    s_paging.evict_next += PAGE_SIZE;
    if (is_pageable_locked(va) && pte_resident(entry_locked(va)) &&
        !is_recent(va)) {
      send_out_locked(va, buf);
      return request(j.slot, PAGE_WRITE);
    }
  }
#endif

  // The checks a sweep waits for (REVOCATION).
  if (s_paging.check_next < slot_count()) {
    const uint64_t slot = next_check_locked(s_paging.check_next);
    s_paging.check_next = slot < slot_count() ? slot + 1 : slot_count();
    if (slot < slot_count()) {
      j = Job{JOB_CHECK, slot, 0, 0};
      return request(slot, PAGE_READ);
    }
  }
  return PAGE_NONE;
}

// THE PAGER: the job handed out is done; `buf` holds what a read read. A
// read whose copy is not the page that went out stays to be done again.
void finish_job_locked(Capability buf) {
  const Job j = s_paging.job;
  if (j.op == JOB_IN) {
    // The page may have been freed and reclaimed while it was read.
    const uint64_t e = entry_locked(j.va);
    if (pte_kind(e) != pte::KindSwapped || pte_slot(e) != j.slot) {
      frame::free(j.frame, 1);
    } else if (!bring_in_locked(j.va, j.frame, buf)) {
      return;
    }
  } else if (j.op == JOB_CHECK && slot_in_use(j.slot)) {
    // Into the kernel's own page first: what is checked is what is decoded.
    volatile uint64_t* w = reinterpret_cast<volatile uint64_t*>(s_paging.scratch);
    const auto* from = reinterpret_cast<const volatile uint64_t*>(buf);
    for (size_t i = 0; i < PAGE_SIZE / sizeof(uint64_t); ++i) {
      w[i] = from[i];
    }
    SlotInfo& info = s_paging.slots[j.slot];
#if defined(SIGNETOS_SWAP_HASH)
    if (!digest_matches(info, w)) {
      s_paging.digest_errors += 1;
      return;
    }
#endif
    const auto* c = reinterpret_cast<const volatile Capability*>(w);
    for (size_t i = 0; i < CAPS_PER_PAGE; ++i) {
      if (has_tag(info, i) && revoke::is_revoked(c[i])) {
        info.tags[i / 8] = static_cast<uint8_t>(info.tags[i / 8] & ~(1u << (i % 8)));
      }
    }
    s_paging.checks += 1;
  }
  s_paging.job = Job{};
}

// `blk`'s page for a transfer (THE PAGER): writable, 4 KiB from its address,
// aligned, resident, and not pageable.
bool is_pager_buffer_locked(Capability c) {
  if (!capability_is_valid(c) || __builtin_cheri_type_get(c) != 0) {
    return false;
  }
  const uint64_t base = capability_get_base(c);
  const uint64_t addr = capability_get_address(c);
  return capability_has_perms(c, perms::Load | perms::Store) &&
         addr % PAGE_SIZE == 0 && addr >= base &&
         base + capability_get_length(c) - addr >= PAGE_SIZE &&
         in_pool(addr) && pte_resident(entry_locked(addr)) &&
         !is_pageable_locked(addr);
}

// True if every page of `[va, va + len)` is resident.
bool resident_locked(uint64_t va, size_t len) {
  if (va + len < va) {
    return false;
  }
  for (uint64_t cur = va & ~(PAGE_SIZE - 1); cur < va + len; cur += PAGE_SIZE) {
    if (!pte_resident(leaf_flags(cur))) {
      return false;
    }
  }
  return true;
}

}  // namespace

Status setup_paging(size_t slots) {
  if (!is_initialized() || !capability_is_valid(s_retag_root)) {
    return Status::NotInitialized;
  }
  // A Swapped entry names its slot in the bits above SlotShift.
  if (slots == 0 || slots > (1ULL << (64 - pte::SlotShift))) {
    return Status::InvalidSize;
  }
  // The kernel's memory for paging, zeroed: a scratch page, a bit per slot,
  // and a SlotInfo per slot.
  const size_t bit_bytes = ((slots + 63) / 64) * sizeof(uint64_t);
  const size_t bytes = PAGE_SIZE + bit_bytes + (slots * sizeof(SlotInfo));
  const Capability mem =
      alloc_pages(round_up_pages((bytes + PAGE_SIZE - 1) / PAGE_SIZE));
  if (!capability_is_valid(mem)) {
    return Status::NoMemory;
  }
  {
    Locked hold(s_lock);
    if (!paging_on()) {
      auto* p = reinterpret_cast<uint8_t*>(mem);
      s_paging.scratch = capability_set_bounds(mem, PAGE_SIZE);
      s_paging.slot_used = reinterpret_cast<uint64_t*>(p + PAGE_SIZE);
      s_paging.slots = reinterpret_cast<SlotInfo*>(p + PAGE_SIZE + bit_bytes);
      s_paging.check_next = slots;
      __atomic_store_n(&s_slot_count, slots, __ATOMIC_RELEASE);
      return Status::Ok;
    }
  }
  free_pages(mem);
  return Status::Busy;
}

bool paging_on() { return slot_count() != 0; }

size_t swap_slots() { return slot_count(); }

void slot_reclaimed_locked(uint64_t slot) { free_slot_locked(slot); }

Fault fault(uint64_t addr, bool can_wait, uint64_t tid) {
  const uint64_t va = addr & ~(PAGE_SIZE - 1);
  if (!paging_on() || !in_pool(va)) {
    return Fault::No;
  }
  Locked hold(s_lock);
  // Paging's only if the page is in use with no frame (FAULTS). No other
  // memory is ever seen so: alloc_pages gives it its frames before it lets
  // go of the lock.
  if (!waits_for_frame_locked(va)) {
    return Fault::No;
  }
  if (pte_kind(entry_locked(va)) == pte::KindFresh && frame_to_spare()) {
    const uint64_t pa = frame::alloc(1);
    if (pa != 0) {
      bring_in_locked(va, pa, nullptr);
      return Fault::Retry;
    }
  }
  // The rest is the pager's to do, and the thread has to wait for it.
  if (!can_wait) {
    return Fault::No;
  }
  add_waiter_locked(va, tid);
  return Fault::Wait;
}

uint64_t page_next(Capability buf, uint64_t tid) {
  Locked hold(s_lock);
  if (!paging_on() || !is_pager_buffer_locked(buf)) {
    return PAGE_NONE;
  }
  __atomic_store_n(&s_paging.pager, tid, __ATOMIC_RELAXED);
  return next_job_locked(buf);
}

uint64_t pager_tid() {
  return __atomic_load_n(&s_paging.pager, __ATOMIC_RELAXED);
}

void page_done(Capability buf) {
  Locked hold(s_lock);
  if (paging_on() && is_pager_buffer_locked(buf)) {
    finish_job_locked(buf);
  }
}

bool start_checks() {
  if (!paging_on()) {
    return false;
  }
  Locked hold(s_lock);
  s_paging.check_next = next_check_locked(0);
  return s_paging.check_next < slot_count();
}

bool checks_pending() {
  Locked hold(s_lock);
  return paging_on() &&
         (s_paging.check_next < slot_count() || s_paging.job.op == JOB_CHECK);
}

bool hold_resident(uint64_t va, size_t len) {
  if (!is_initialized()) {
    return false;
  }
  s_lock.acquire();
  if (!resident_locked(va, len)) {
    s_lock.release();
    return false;
  }
  return true;
}

void release_resident() { s_lock.release(); }

bool set_retag_root(Capability root) {
  s_retag_root = nullptr;
  if (!capability_is_valid(root) ||
      !capability_is_valid(sealing::g_type_root)) {
    return false;
  }
  // Where CT sits in the upper word of a capability's bits: sealing with the
  // type whose bits are all ones changes exactly those bits, all zero while
  // unsealed. Anything else that does not come back exactly is caught as
  // each capability is built (rebuild_locked).
  alignas(16) static Capability probe;
  volatile Capability* slot = &probe;
  const auto* w = reinterpret_cast<const volatile uint64_t*>(slot);
  const Capability data = capability_and_perms(
      capability_set_bounds(capability_set_address(root, DYNAMIC_BASE), 0x40),
      perms::DataRw);
  *slot = data;
  const uint64_t plain = w[1];
  *slot = sealing::seal_with(
      sealing::authority_for(static_cast<OType>(kOTypeMax)), data);
  const uint64_t diff = plain ^ w[1];
  *slot = nullptr;
  if (diff == 0 || (plain & diff) != 0 ||
      diff != (CT_MASK << __builtin_ctzll(diff))) {
    return false;
  }
  s_ct_shift = static_cast<uint64_t>(__builtin_ctzll(diff));
  s_retag_root = root;
  return true;
}

#if defined(SIGNETOS_PAGE_TEST)
uint64_t page_test(uint64_t op, Capability cap) {
  if (!paging_on()) {
    return ~0ULL;
  }
  Locked hold(s_lock);
  switch (op) {
    case PAGE_TEST_SLOTS:
      return slot_count();
    case PAGE_TEST_FREE_FRAMES:
      return frame::free_pages();
    case PAGE_TEST_RESERVE:
      return reserve_frames();
    case PAGE_TEST_READS:
      return s_paging.reads;
    case PAGE_TEST_WRITES:
      return s_paging.writes;
    case PAGE_TEST_CHECKS:
      return s_paging.checks;
    case PAGE_TEST_DIGEST_ERRORS:
      return s_paging.digest_errors;
    case PAGE_TEST_EVICTING:
      return ((s_paging.evict_end - s_paging.evict_next) / PAGE_SIZE) +
             (s_paging.job.op == JOB_OUT ? 1 : 0);
    case PAGE_TEST_EVICT: {
      // The pages `cap` covers, wherever its address is.
      if (!capability_is_valid(cap) || __builtin_cheri_type_get(cap) != 0) {
        return ~0ULL;
      }
      const uint64_t base = capability_get_base(cap);
      const uint64_t top = base + capability_get_length(cap);
      if (base >= top || !in_pool(base) || !in_pool(top - 1)) {
        return ~0ULL;
      }
      s_paging.evict_next = base & ~(PAGE_SIZE - 1);
      s_paging.evict_end = (top + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
      return (s_paging.evict_end - s_paging.evict_next) / PAGE_SIZE;
    }
    default:
      return ~0ULL;
  }
}
#else
uint64_t page_test(uint64_t, Capability) { return ~0ULL; }  // not built in
#endif

}  // namespace signetos::vm
