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
// Everything from DYNAMIC_BASE (the gigabyte after the kernel image) to the top
// of the lower half is one pool of virtual addresses handed out by `reserve` as they
// are asked for. There are no per-purpose regions: kernel objects and
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
// at a time. Isolation is CHERI's, not the MMU's (everything runs in S-mode,
// see pte::Permissive), so a standing mapping of RAM costs nothing in
// protection as long as no capability to it escapes; `inspect` refuses any
// outbound capability that is not inside the dynamic space.
//
// Compartment memory is NOT served from the direct map. `alloc_pages` takes
// frames and maps them at fresh addresses in the dynamic space; the direct map
// aliases those frames but no compartment ever holds an address into it.
//
// FREEING AND QUARANTINE
//
// A capability that is still tagged must always reach valid memory
// (design_spec.md section 4.2, the accessibility invariant). Revocation works
// by clearing tags in a sweep, never by pulling the mapping out from under a
// capability that is still valid.
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

// The direct map: all of RAM, kernel-only, at the bottom of the upper half.
constexpr uint64_t DIRECT_BASE = 0xFFFFFFC000000000ULL;

// Ceiling on how many frames may be held as page tables at once.
//
// This is a cap, not a reservation: page table frames come from the same pool
// as everything else and are taken on demand, so capacity left under the cap
// stays available to compartments. It exists only to stop a pathologically
// fragmented address space from turning the pool into page tables.
//
// One L0 table covers 2MB of addresses and one L1 covers 1GB, so mapping every
// frame in the pool at once takes 1019 tables. 2048 is a backstop with room to
// spare, and costs nothing while unused.
constexpr size_t DEFAULT_MAX_TABLE_PAGES = 2048;

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
    // User is never set. Everything runs in S-mode, and the privileged spec
    // says that irrespective of SUM the supervisor may not fetch instructions
    // from a U=1 page, so marking a page User would make it unexecutable.
    constexpr uint64_t Permissive = Valid | Read | Write | Execute | Accessed | Dirty;

    // Devices. Execute withheld because there is nothing there to run.
    constexpr uint64_t Mmio       = Valid | Read | Write | Accessed | Dirty;

    // The direct map outside the kernel image: data the kernel reads and
    // writes through `phys_view`, never code.
    constexpr uint64_t KernelData = Valid | Read | Write | Accessed | Dirty;

    // CoW source. Write withheld so a store traps with scause 15 and the
    // handler can copy the page.
    constexpr uint64_t CowSource  = Valid | Read | Execute | Accessed;

    // Software bit (RSW, bit 8): the hardware ignores it. Set by free_pages on
    // every page of a freed range, which stays mapped until the revocation
    // sweep. See FREEING AND QUARANTINE above.
    constexpr uint64_t Quarantined = (1ULL << 8);
}

// Builds the boot mappings (devices, direct map), derives the two standing
// authorities, and activates satp. Call after frame::discover and before
// frame::init. On failure is_initialized() stays false; nothing can be mapped
// and kernel_main must not continue.
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

// Changes the ceiling on live page table frames. Defaults to
// DEFAULT_MAX_TABLE_PAGES, so nothing needs to call this; lowering it is how
// the tests reach the refusal path. Does not free tables already built.
void set_max_table_pages(size_t pages);

//
// Virtual address allocation
//

// Reserves `pages` of contiguous virtual address space. Returns the base, or 0
// if the address space is exhausted.
//
// Freed ranges stay quarantined until `revoke::sweep()` clears every capability
// reaching them and returns their addresses via `release`, after which
// `reserve` reuses them before bumping the watermark.
uint64_t reserve(size_t pages);

// Returns an unmapped reservation `[va, va + pages * PAGE_SIZE)` to the
// reusable address pool, coalescing adjacent ranges. Ignored if any page in the
// range is still mapped (including quarantined pages awaiting a sweep).
void release(uint64_t va, size_t pages);

// How much of the address space is still unreserved, in pages.
size_t reservable_pages();

// Maps `pages` 4KB pages at `va` onto physical `pa` with `flags`.
//
// `va` must be in the dynamic address space; the boot mappings are not
// reachable through this. `pa` must be real RAM. Intermediate page tables are
// taken on demand from the frame allocator, so this fails if the pool is empty
// or the page table cap is reached. Fails without changing anything if any page
// in the range is already mapped.
bool map(uint64_t va, uint64_t pa, size_t pages, uint64_t flags);

// Removes `pages` 4KB pages at `va`. Page tables emptied by the removal are not
// reclaimed. Returns false if any page in the range was not mapped.
bool unmap(uint64_t va, size_t pages);

// Physical address backing `va`, or 0 if it is not mapped. A quarantined page
// is still mapped, so it translates.
uint64_t translate(uint64_t va);

// True if `va` is mapped and was freed: quarantined, awaiting the sweep.
bool is_quarantined(uint64_t va);

// True if any page overlapping `[va, va + len)` is mapped and marked
// quarantined.
bool range_has_quarantined(uint64_t va, size_t len);

// The leaf PTE's flag bits for `va`, or 0 if it is not mapped. Lets a caller
// check the permissions a mapping actually got rather than assume them.
uint64_t leaf_flags(uint64_t va);

//
// Page allocation
//
// Reserves virtual addresses, backs them with frames and maps them. This is how
// anything gets usable memory, now that no physical memory is mapped by
// default. It is page granular: there is no heap and no sub-page allocator.
//

// Allocates `pages` contiguous pages. Returns a capability bounded to exactly
// that range with DataRw, or null. Contents are zeroed.
Capability alloc_pages(size_t pages);

// Frees an allocation from alloc_pages by quarantining it. Nothing is unmapped
// and no frame is released: the range stays mapped, with its data, until a
// revocation sweep has cleared the tags on capabilities that may still cover
// it. See FREEING AND QUARANTINE above.
//
// Returns false if any page is unmapped or already quarantined, so a range
// cannot be freed twice.
bool free_pages(Capability object);

// Scans every live (non-quarantined) mapped page in the dynamic address space
// and clears the hardware tag on any capability slot where
// `revoke::should_revoke` returns true. Called by `revoke::sweep()`.
void sweep_live_pages();

// Unmaps every quarantined page in the dynamic address space, frees its
// backing physical frame, and returns its virtual address range to the
// reusable VA pool. Called by `revoke::sweep()` after all capability tags
// pointing into quarantined ranges have been cleared.
void reclaim_quarantined();

// Diagnostics.
size_t table_pages();
size_t max_table_pages();
size_t allocated_pages();    // pages handed out by alloc_pages and not freed
size_t quarantined_pages();  // pages freed, still mapped, awaiting the sweep

//
// Page table dumps. Both read the live tables the hardware walks, so what they
// print is what the MMU sees -- not a record the VM keeps alongside.
//

// One address: the physical address it translates to, the page size of the leaf
// that covers it, and that leaf's flags (Q marks a quarantined page). Says NOT
// MAPPED if there is no leaf.
void dump_mapping(uint64_t va);

// Every valid leaf in the table, in address order. Entries that are contiguous
// in both virtual and physical address and share their flags are printed as one
// run. Returns the number of leaf entries found.
size_t dump_mappings(const char* label);

} // namespace signetos::vm
