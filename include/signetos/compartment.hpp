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

#pragma once

//
// compartment.hpp - SignetOS protection domains
//
// A compartment is not an execution context. It is a container of capabilities:
// the tracking struct plus the capability table that is the domain's root of
// authority. Threads are separate and can move between compartments.
//
// WHERE A COMPARTMENT LIVES
//
// One page, billed to the memory quota the creator supplies. The struct sits at
// the start of the page and the capability table fills the rest, so creating a
// compartment is one allocation and destroying it is one free.
//
//   offset    0   struct Compartment       32 bytes used, TABLE_OFFSET reserved
//   offset  256   Capability table[240]    3840 bytes
//   offset 4096   end of page
//
// AUTHENTICATION VS ACCESS
//
// The handle is sealed under OTYPE_COMPARTMENT, which only the kernel can
// produce, so unsealing it proves it is genuine. The handle is bounded to
// `sizeof(Compartment)` and carries `self_page` at offset 0 so the kernel can
// load the full page capability directly from the unsealed struct.
//

#include <stdint.h>
#include <stddef.h>
#include <signetos/lock.hpp>
#include <signetos/types.hpp>
#include <signetos/vm.hpp>

namespace signetos::compartment {

// How big a compartment is, stated in pages: the struct and the table share
// one allocation of `pages` contiguous pages, and the table fills everything
// after the header. `COMPARTMENT_PAGES` is the minimum (and the common case);
// a creator whose seed array does not fit in one page gets as many pages as
// it needs, up to `MAX_COMPARTMENT_PAGES`, billed to the same quota. The
// array's bounds are the request, so there is no size argument: pad the
// array with nulls to buy room for authorities to be stored later.
//
// Two units are needed and they must not be allowed to drift: vm::alloc_pages
// counts PAGES, quota::charge counts BYTES. Deriving the second from the first
// means a compartment is never billed for memory it did not get.
constexpr size_t   COMPARTMENT_PAGES     = 1;
constexpr size_t   MAX_COMPARTMENT_PAGES = 16;  // 64 KiB: 4080 slots
constexpr uint64_t COMPARTMENT_COST      = COMPARTMENT_PAGES * vm::PAGE_SIZE;

// Where the capability table starts within the first page. Larger than the
// struct needs so that adding a field later does not move the table or change
// the slot count.
constexpr size_t TABLE_OFFSET = 256;

// Bytes per capability. Capabilities must be stored at a multiple of this or
// the hardware drops the tag on the store.
constexpr size_t CAP_BYTES = 16;

// Slots in a table of `pages` pages: everything after the header.
constexpr size_t slots_in_pages(size_t pages) {
    return (pages * vm::PAGE_SIZE - TABLE_OFFSET) / CAP_BYTES;
}

// Pages a table of `slots` slots needs (at least one).
constexpr size_t pages_for_slots(size_t slots) {
    const size_t pages =
        (TABLE_OFFSET + slots * CAP_BYTES + vm::PAGE_SIZE - 1) / vm::PAGE_SIZE;
    return pages < COMPARTMENT_PAGES ? COMPARTMENT_PAGES : pages;
}

// Slots in the smallest (one-page) table, which is what a compartment created
// with up to `CAP_SLOTS - RW_SLOT_SEED_BASE` seeds gets; `Compartment::table_slots`
// is the actual count for a given compartment.
constexpr size_t CAP_SLOTS     = slots_in_pages(COMPARTMENT_PAGES);
constexpr size_t MAX_CAP_SLOTS = slots_in_pages(MAX_COMPARTMENT_PAGES);

// Slots 0-1 are the compartment's identity and funding VM quota; slots 2 and
// up receive the `initial_capabilities` array passed to
// `sys_compartment_create` and serve as the compartment's own capability table
// (`cgp` on entry).
constexpr size_t SLOT_SELF         = 0;  // this compartment's sealed handle
constexpr size_t SLOT_VM_QUOTA     = 1;  // capability_quota_vm_t that funded it
constexpr size_t RW_SLOT_SEED_BASE = 2;  // first seed slot in the table

// Set while the compartment is in use, cleared by destroy. This is what refuses
// a stale handle: a destroyed compartment's page is quarantined, not unmapped
// (vm.hpp), so the handle still unseals and still reaches the struct until the
// revocation sweep clears its tag.
constexpr uint32_t FLAG_LIVE = (1u << 0);
// Set by `trust_to_finish`, never cleared: a killed thread inside this
// compartment is left to finish its call (unwind.hpp, KILLED THREADS).
constexpr uint32_t FLAG_TRUSTED_TO_FINISH = (1u << 1);

using Status = signetos::Status;
using signetos::status_name;

// The kernel's tracking anchor for one domain.
//
// `self_page` is first because a capability must sit at a 16-byte boundary, and
// the page base is page-aligned; putting it at offset 0 means no padding field.
struct Compartment {
    Capability self_page;  // writable kernel capability to the whole allocation
                           // (struct and table); its length is what was billed
    Capability quota;      // the handle that funded this page, for the refund
    Capability ranges;     // head of the range page chain. Null until the first
                           // allocation. See "WHO OWNS WHICH MEMORY" below.
    Capability entries;    // head of the entry page chain (sys_sentry records).
                           // Null until the first entry point is minted.
    uint64_t   uid;        // monotonic, never reused. 0 is never issued.
    uint64_t   table_slots;  // slots in the table behind this header
    uint32_t   flags;
    SpinLock   lock;       // protects `ranges` and `entries` chains
};

static_assert(sizeof(Compartment) <= TABLE_OFFSET,
              "the struct must fit in the header, ahead of the table");
static_assert(TABLE_OFFSET + CAP_SLOTS * CAP_BYTES == COMPARTMENT_COST,
              "the header plus the table must exactly fill the allocation");
static_assert(pages_for_slots(CAP_SLOTS) == COMPARTMENT_PAGES &&
                  pages_for_slots(CAP_SLOTS + 1) == COMPARTMENT_PAGES + 1,
              "pages_for_slots must round up exactly at the page boundary");

//
// DESTROY WHILE THREADS ARE INSIDE
//
// Nothing counts the threads running, parked or handling a trap in a
// compartment's code, and destroy does not wait for them. It can afford not
// to: every page it releases is quarantined, not unmapped (vm.hpp), so a
// thread inside keeps running intact code on an intact table until the
// revocation sweep clears every capability into the compartment. From then on
// such a thread's next return into the compartment -- through the switcher or
// out of a trap handler -- finds the saved return address untagged, and the
// kernel pops that frame and resumes the nearest live one beneath with
// Status::CompartmentDestroyed (unwind.hpp). What the compartment can no
// longer do once destroy has run is anything that needs its handle: allocate,
// mint entries, bind traps. A thread created to start in it, and not yet run,
// ends at its first instruction once the sweep has cleared its entry sentry
// (`__thread_start`).
//

//
// WHO OWNS WHICH MEMORY
//
// There is one address space, so the page tables cannot answer this: every
// compartment's pages are interleaved in the same tables with nothing marking
// them apart. Ownership is not recoverable by walking, so it is written down
// when memory is allocated.
//
// Each compartment keeps its own chain of range pages, hanging off `ranges` in
// its tracking struct. A page is taken from vm::alloc_pages and CHARGED TO THE
// QUOTA FUNDING THE ALLOCATION THAT NEEDED IT, like every other kernel
// structure. There is no global table: a compartment that fills its chain has
// spent its own budget doing so and has affected nobody else.
//
// Being in a compartment's chain is what proves ownership, so a record carries
// no owner field and deallocate needs no UID comparison. Another compartment
// asking to free this memory simply does not find it.
//
// Range page layout, one page:
//
//   offset    0   Capability next          head-inserted chain, null at the end
//   offset   16   Capability funder        the quota that paid for this page
//   offset   32   Range records[254]
//   offset 4096   end
//
// ONE PAGE HOLDS RECORDS FOR ONE QUOTA ONLY. `funder` is that quota, so it is
// stored once per page rather than once per record, and each record holds the
// 16-byte capability to the allocation itself.
//
// The alternative -- any record on any page -- lets whichever quota happened to
// grow the chain pay 4096 bytes that every other quota then fills for free.
// That cross-subsidy is steerable by an attacker, so a quota funds only the
// pages carrying its own records. The cost is a part-used page per quota, which
// is cheap: address space is the abundant resource here.
//
// So allocate looks for a free record on a page whose funder matches the quota
// paying, and buys a new page if there is none.
//

struct alignas(16) Range {
    Capability cap;  // capability to the allocation. Null means the record is free.
};

// `next` plus `funder`.
constexpr size_t RANGE_PAGE_HEADER = 2 * CAP_BYTES;

// TODO: the chain only grows. A page emptied by deallocate stays attached and
// is reused by the next allocation from the same quota, and the whole chain is
// released when the compartment is destroyed.
constexpr size_t RANGES_PER_PAGE =
    (vm::PAGE_SIZE - RANGE_PAGE_HEADER) / sizeof(Range);

static_assert(sizeof(Range) == 16, "a range record must be exactly 16 bytes");
static_assert(RANGE_PAGE_HEADER + RANGES_PER_PAGE * sizeof(Range) ==
                  vm::PAGE_SIZE,
              "the header plus the records must exactly fill a page");

// Prepares the subsystem. Needs the sealing authority and vm up already.
void init();

// Charges one page to `mem_quota`, builds the struct and the table, and returns
// the sealed handle.
//
// `initial_capabilities` is copied into the capability table starting at
// `RW_SLOT_SEED_BASE` (slot 2, directly after `SLOT_SELF` and `SLOT_VM_QUOTA`).
// Its length is taken from its own bounds, so there is no count argument. Pass
// null for none.
//
// `mem_quota` needs Permit_Load. It is stored in slot 1 unchanged.
Capability create(Capability mem_quota, Capability initial_capabilities,
                  Status* out_status = nullptr);

// The capability table, slots 0..CAP_SLOTS. Null if the handle is not genuine.
Capability table_writable(Capability handle);

// Records `code` as an entry point of `comp` and returns a kernel capability
// bounded to the new sentry::EntryRecord (for sentry::create to seal), or null.
//
// If `require_owned`, `code`'s bounds must lie inside one allocation in
// `comp`'s range chain; otherwise the caller could run arbitrary code with
// `comp`'s capability table in `cgp`. Only kernel-internal callers minting
// entry points over kernel text pass false.
//
// Takes a fresh entry page when the chain is full, charged to the
// compartment's funding quota.
Capability add_entry(Capability comp, Capability code, bool require_owned,
                     Status* out_status = nullptr);

// Number of entry pages in `comp`'s chain. 0 for a bad handle.
size_t entry_pages(Capability comp);

// Allocates `size` bytes rounded up to whole pages, charges them to
// `mem_quota`, and records the range in `comp`'s chain. Returns a capability
// bounded to exactly that range, or null.
//
// Every 127th allocation also takes a fresh range page, charged to the same
// `mem_quota`. That is the only variable cost, and it is paid by the caller
// that made the chain grow.
//
// `flags` changes nothing: all three of FLAG_ZERO, NO_ALIAS and FLAG_PINNED are
// already unconditionally true. alloc_pages always zeroes, vm::reserve never
// reissues an address, and nothing is ever swapped.
Capability allocate(Capability comp, Capability mem_quota, size_t size,
                    uint32_t flags, Status* out_status = nullptr);

// Frees an allocation and credits the bytes back. The range is quarantined, not
// unmapped (see vm.hpp): capabilities to it that are still tagged keep reaching
// its data until the revocation sweep.
//
// `mem_capability` is used only for its BASE, to find the record in `comp`'s
// chain; the range is then freed through a capability rebuilt from the record,
// so a narrowed capability cannot free part of an allocation and leak the
// rest. A compartment that does not own the range does not find it.
//
// The refund goes to the quota stored in the record. `mem_quota` must name that
// same quota or the call is refused, so a refund cannot be misdirected.
Status deallocate(Capability comp, Capability mem_quota,
                  Capability mem_capability);

// Clones `len` bytes starting at `src_memory`'s current address into a new
// allocation owned by `comp` and funded by `mem_quota`. `len` must be a
// non-zero multiple of `vm::PAGE_SIZE`, and `src_memory` must be an unsealed
// capability with `Permit_Load` whose bounds cover `[addr, addr + len)`.
//
// NOTE: Implemented for now as a synchronous up-front memory copy; we will
// return later to make this lazy page-table copy-on-write.
Capability cow(Capability comp, Capability mem_quota, Capability src_memory,
               size_t len, Status* out_status = nullptr);

// `sys_vm_phys`. Physical address of `mem_capability`'s base if its whole
// bounds lie inside one allocation `comp` owns and every page of it is
// physically contiguous with the first; 0 otherwise. `alloc_pages` backs each
// allocation with one frame run mapped linearly, so a single allocation
// always qualifies; the check is still made page by page, not assumed.
uint64_t phys(Capability comp, Capability mem_capability);

// Tears the compartment down completely: every live allocation in its range
// chain, every page of the chain, and finally its own page. Each refund goes to
// the quota that paid for that particular item.
//
// The handle is the only authority required. Holding it is what permits this.
//
// Succeeds whatever threads are inside the compartment: started in it and not
// yet ended, called into it and not yet returned, or running one of its trap
// handlers (DESTROY WHILE THREADS ARE INSIDE above).
//
// There is no "still has allocations" refusal. Nothing outside can enumerate a
// compartment's ranges, so a caller could not empty it first even if asked to,
// and a compartment being destroyed usually has nobody left to do it.
//
// Cannot fail partway: everything that can be rejected is checked before the
// first page is released.
//
// Every released range, and the compartment's own page, is quarantined rather
// than unmapped, so capabilities to them stay usable until the sweep. A stale
// handle to the compartment is refused by the cleared FLAG_LIVE.
//
// TODO: does NOT register the released ranges with the revoker so a sweep can
// clear their tags, after which they could be unmapped and their frames reused.
// deallocate has the same gap. Both need fixing when the revoker is wired up.
Status destroy(Capability handle);

// Kernel-internal introspection. False if the handle is not genuine.
bool query(Capability handle, Compartment* out_copy);

// `sys_compartment_trust_to_finish`: marks the compartment behind `handle`
// trusted to finish (FLAG_TRUSTED_TO_FINISH). `init` marks the core services
// with it at boot.
Status trust_to_finish(Capability handle);

// The record for the allocation based at `va` within `comp`'s chain.
// `out_funder`, if given, receives the quota that paid for it -- which is the
// funder of the page the record sits on.
bool query_range(Capability comp, uint64_t va, Range* out_copy,
                 Capability* out_funder = nullptr);

// True if `comp` is a genuine live compartment and `[base, base + len)` lies
// wholly inside one allocation recorded in `comp`'s range chain.
bool owns_range(Capability comp, uint64_t base, uint64_t len,
                Status* out_status = nullptr);

// Diagnostics for tests.
size_t live_count();
size_t range_count(Capability comp);       // records in use
size_t range_pages(Capability comp);       // pages in the chain

} // namespace signetos::compartment
