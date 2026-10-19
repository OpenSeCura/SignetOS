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
// vm.hpp - SignetOS Sv39 virtual memory
//
// One virtual address space for the whole system. The MMU provides physical
// page backing, demand mapping and CoW write detection only; isolation is
// CHERI's job, so page table entries are permissive.
//
// LAYOUT
//
// Only addresses fixed by hardware are fixed here:
//
//   0x00000000 .. 0x00200000    QEMU test/poweroff device   megapage, boot
//   0x0c000000 .. 0x0c202000    PLIC (delegated to trap_mgr) megapages, boot
//   0x10000000 .. 0x10001000    UART                        4KB page, boot
//   0x80000000 .. 0x81000000    kernel image (identity)     megapages, boot
//   DIRECT_BASE .. + RAM size   the direct map              megapages, boot
//
// Everything from DYNAMIC_BASE (the gigabyte after the kernel image) up to the
// revocation bitmap is one pool of virtual addresses handed out by
// `alloc_pages` as they are asked for. An address is in use exactly while it
// is mapped; the page tables are the only record. There are no per-purpose
// regions: kernel objects and
// compartment memory come from the same pool and are distinguished by who
// holds a capability to them, not by where they sit.
//
// THE DIRECT MAP
//
// All of RAM is mapped once at boot, as data, with 2MB megapages, into the
// Sv39 upper half: physical `pa` is reachable at `DIRECT_BASE + (pa -
// ram_base)`. This is how the kernel reaches a page table or the frame bitmap.
// Only the kernel image is identity-mapped, because the code is linked and
// executing there.
//
// The direct map is reachable only through `s_direct`, a capability derived
// from the boot root and never handed out; `phys_view` narrows it to one range
// at a time. Isolation is CHERI's, not the MMU's (everything runs in M-mode,
// see pte::Permissive), so a standing mapping of RAM costs nothing in
// protection as long as no capability to it escapes; `inspect` refuses any
// outbound capability that is not inside the dynamic space.
//
// Compartment memory is NOT served from the direct map. `alloc_pages` takes
// frames and maps them at fresh addresses in the dynamic space; the direct map
// aliases those frames but no compartment ever holds an address into it.
//
// The direct map is used only for things that have no virtual address of
// their own: page tables, the frame bitmap, and the device tree at boot.
// Anything mapped in the dynamic space is reached at its own address through
// `s_dynamic`, the authority every allocation is derived from; the revocation
// sweep reads pages that way.
//
// FREEING AND QUARANTINE
//
// A capability that is still tagged must always reach valid memory
// (the accessibility invariant). Revocation works by clearing tags in a sweep,
// never by pulling the mapping out from under a capability that is still valid.
//
// So free_pages does not unmap anything. It QUARANTINES the range: the pages
// stay mapped onto the same frames, still holding their data, and each leaf
// entry is marked pte::Quarantined. A stale capability that touches the range
// reads and writes exactly what it did before the free. What quarantine
// guarantees is that the addresses are never handed out again, so no stale
// capability can ever reach somebody else's memory through them.
//
// Freeing a kernel object's page does not make its handles fail, because the
// page is still there. Each object therefore carries its own liveness state
// (FLAG_LIVE in quota and compartment), which destroy clears and every lookup
// checks.
//
// Once a revocation sweep has cleared every tag that could reach a quarantined
// range, nothing can reach it and `reclaim_quarantined` unmaps the pages, frees
// their physical frames, and returns their virtual addresses to the reusable
// pool.
//
// TODO: page out to a backing store. The frames under quarantined memory are
// the only copy of data a stale capability may still read, so they cannot be
// reused until the sweep. A backing store would let the kernel write that data
// to disk, unmap the page, free the frame for reuse straight away, and fault
// the data back into a fresh frame if a stale capability touches the range
// before the sweep reaches it -- the "demand-fill page fault" the invariant
// allows. Without it, freed memory keeps occupying RAM until the sweep.
//

#include <stdint.h>
#include <stddef.h>
#include <signetos/types.hpp>

namespace signetos::vm {

constexpr uint64_t PAGE_SIZE     = 4096ULL;
constexpr uint64_t PAGE_SHIFT    = 12;
constexpr uint64_t MEGAPAGE_SIZE = 2ULL * 1024 * 1024;
constexpr uint64_t GIGAPAGE_SIZE = 1024ULL * 1024 * 1024;

// The kernel image: linked into the first 16MB of RAM (linker.ld) and
// identity-mapped at boot so the addresses the linker produced keep working.
constexpr uint64_t KERNEL_BASE = 0x80000000ULL;
constexpr uint64_t KERNEL_SIZE = 16ULL * 1024 * 1024;

uint64_t kernel_base();  // KERNEL_BASE, as discovered from the DTB

// The dynamically allocated address space: from the first gigabyte boundary
// above the kernel image to the top of the Sv39 lower half.
//
// Sv39 splits its 512GB into a lower half (bit 38 clear) and an upper half
// (bits 63:39 all set); addresses between them are not virtual addresses at all
// and fault before the page tables are read.
//
// The base is gigabyte-aligned rather than KERNEL_BASE + KERNEL_SIZE because
// sentry.cpp holds one capability spanning the whole range, and a ~250GB CHERI
// capability is only representable with a base aligned that coarsely.
constexpr uint64_t DYNAMIC_BASE = 0xC0000000ULL;    // 3GB, next GB above the image
constexpr uint64_t DYNAMIC_TOP  = 0x4000000000ULL;  // top of the lower half

// REVOCATION BITMAP
//
// The top 2GB of the dynamic space is never handed out. It holds the marks
// `revoke` sets (revoke.hpp, MARKING RANGES): one bit per 16 bytes of
// everything below it, so the mark for `va` is a bit in the byte at
// `bitmap_of(va)`, and 4KB of bitmap covers BITMAP_SPAN of addresses. This
// file only lays the region out and maps and unmaps its pages; what the bits
// mean is revoke's. Only revocable allocations (FLAG_REVOCABLE) have bitmap
// pages: their pages carry pte::Revocable, they start on a BITMAP_SPAN
// boundary so that no other revocable allocation shares their bitmap pages,
// and those are mapped, paid for and freed with them. Everywhere else the
// region is unmapped and costs nothing.
constexpr uint64_t BITMAP_BASE = DYNAMIC_TOP - 2 * GIGAPAGE_SIZE;
constexpr uint64_t BITMAP_SPAN = PAGE_SIZE * 128;
constexpr uint64_t bitmap_of(uint64_t va) {
  return BITMAP_BASE + (va - DYNAMIC_BASE) / 128;
}
static_assert(bitmap_of(BITMAP_BASE) <= DYNAMIC_TOP);

// The direct map: all of RAM, kernel-only, at the bottom of the upper half.
constexpr uint64_t DIRECT_BASE = 0xFFFFFFC000000000ULL;

// Sv39 Page Table Entry (PTE) Hardware Flags
namespace pte {
    constexpr uint64_t Valid    = (1ULL << 0);
    constexpr uint64_t Read     = (1ULL << 1);
    constexpr uint64_t Write    = (1ULL << 2);
    constexpr uint64_t Execute  = (1ULL << 3);
    constexpr uint64_t User     = (1ULL << 4);
    constexpr uint64_t Global   = (1ULL << 5);
    constexpr uint64_t Accessed = (1ULL << 6);
    constexpr uint64_t Dirty    = (1ULL << 7);

    // PTE permissions are not a protection mechanism here -- CHERI is. The MMU
    // only provides physical backing, so a normal mapping grants everything and
    // the only reason to withhold a bit is to cause a fault we want.
    //
    // User is never set. Everything runs in M-mode, which the MMU translates
    // under the S-mode rules (toolchain/mmodemmu), and irrespective of SUM
    // those never allow fetching instructions from a U=1 page, so marking a
    // page User would make it unexecutable.
    constexpr uint64_t Permissive = Valid | Read | Write | Execute | Accessed | Dirty;

    // Devices. Execute withheld because there is nothing there to run.
    constexpr uint64_t Mmio       = Valid | Read | Write | Accessed | Dirty;

    // The direct map outside the kernel image: data the kernel reads and
    // writes through `phys_view`, never code.
    constexpr uint64_t KernelData = Valid | Read | Write | Accessed | Dirty;

    // CoW source. Write withheld so a store traps with mcause 15 and the
    // handler can copy the page.
    constexpr uint64_t CowSource  = Valid | Read | Execute | Accessed;

    // Software bit (RSW, bit 8): the hardware ignores it. Set by free_pages on
    // every page of a freed range, which stays mapped until the revocation
    // sweep. See FREEING AND QUARANTINE above.
    constexpr uint64_t Quarantined = (1ULL << 8);

    // Software bit (RSW, bit 9): the page belongs to a revocable allocation,
    // so it has revocation bitmap pages (REVOCATION BITMAP).
    constexpr uint64_t Revocable = (1ULL << 9);
}

// Builds the boot mappings (devices, direct map), derives the two standing
// authorities, and turns the MMU on for this hart (satp, then
// mmodemmu.ENABLE). Call after frame::discover and before frame::init. On
// failure is_initialized() stays false; nothing can be mapped and
// kernel_main must not continue.
void init(Capability root_data_cap);

bool is_initialized();

// First physical address above the kernel image and the direct map's own L1
// tables: where the frame allocator may start carving.
uint64_t boot_reserved_end();

// End (physical) of the direct-mapped RAM: RAM rounded down to a whole
// megapage. Frames above it are not reachable and not in the pool.
uint64_t direct_map_top();

// Writable view of physical [pa, pa + len) through the direct map, or null if
// the range is outside it. Kernel-internal: this is how page tables and the
// frame bitmap are reached. Never hand the result to a compartment.
Capability phys_view(uint64_t pa, size_t len);

// Bounded Load|Store capability to the device range [pa, pa + len), or null
// unless the range lies inside the device gigabyte init() mapped at boot.
// Unlike phys_view this is made to be delegated: `init::launch` puts one
// window over the whole gigabyte in the BootManifest, and `init` carves the
// per-device windows it hands to the drivers from it using the DTB.
Capability device_window(uint64_t pa, size_t len);

//
// Translation
//

// Physical address backing `va`, or 0 if it is not mapped. A quarantined page
// is still mapped, so it translates.
uint64_t translate(uint64_t va);

// True if any page overlapping `[va, va + len)` is mapped and marked
// quarantined.
bool range_has_quarantined(uint64_t va, size_t len);

// The leaf PTE's flag bits for `va`, or 0 if it is not mapped. Lets a caller
// check the permissions a mapping actually got rather than assume them.
uint64_t leaf_flags(uint64_t va);

//
// Page allocation
//
// Finds free virtual addresses, backs them with frames and maps them. This is how
// anything gets usable memory, now that no physical memory is mapped by
// default. It is page granular: there is no heap and no sub-page allocator.
//

// Pages of revocation bitmap a revocable allocation of `pages` pages comes with.
constexpr size_t bitmap_pages(size_t pages) {
  return (pages * PAGE_SIZE + BITMAP_SPAN - 1) / BITMAP_SPAN;
}

// Allocates `pages` contiguous pages at the lowest free addresses that fit
// (up to 2MB within one 2MB region, larger as whole empty 2MB regions).
// Page tables are taken from the frame allocator as needed. Returns a capability bounded to exactly
// that range with DataRw, or null. Contents are zeroed. If `revocable`, the
// range starts on a BITMAP_SPAN boundary and comes with `bitmap_pages(pages)`
// more frames of revocation bitmap (REVOCATION BITMAP), which the caller pays
// for too.
Capability alloc_pages(size_t pages, bool revocable = false);

// Frees an allocation from alloc_pages by quarantining it. Nothing is unmapped
// and no frame is released: the range stays mapped, with its data, until a
// revocation sweep has cleared the tags on capabilities that may still cover
// it. See FREEING AND QUARANTINE above.
//
// Returns the bytes quarantined, the bitmap pages of a revocable range included:
// what its payer goes on paying for until a sweep reclaims it, so the caller
// owes it rather than refunding it (quota.hpp, OWED). Returns 0, and frees
// nothing, if any page is unmapped or already quarantined, so a range cannot
// be freed twice.
uint64_t free_pages(Capability object);

// Walks the live (mapped, not quarantined) pages of the dynamic address space:
// returns a kernel-only view of the first one at or above `*cursor` and moves
// `*cursor` past it, or null when there are no more. Start with `*cursor = 0`.
// What to do with each page is the caller's: the revocation sweep clears tags
// in it.
Capability next_live_page(uint64_t* cursor);

// Unmaps every quarantined page in the dynamic address space, and its bitmap
// page, and frees their frames; the addresses are then free for reuse.
// Called by `revoke::sweep()` after all capability tags pointing into
// quarantined ranges have been cleared.
void reclaim_quarantined();

// Kernel-only read/write view of the whole revocation bitmap (REVOCATION
// BITMAP), for `revoke`, which owns what is in it. Only the pages of
// revocable allocations are mapped: test `leaf_flags` before touching
// anything else.
Capability bitmap_view();

// Diagnostics.
size_t table_pages();         // frames held as page tables (never freed)
size_t allocated_pages();    // pages handed out by alloc_pages and not freed
size_t quarantined_pages();  // pages freed, still mapped, awaiting the sweep

} // namespace signetos::vm
