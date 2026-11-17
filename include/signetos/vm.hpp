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
//   0x0c000000 .. 0x0c202000    PLIC (delegated to sched)    megapages, boot
//   0x10000000 .. 0x10001000    UART                        4KB page, boot
//   0x80000000 .. 0x81000000    kernel image (identity)     megapages, boot
//   DIRECT_BASE .. + RAM size   the direct map              megapages, boot
//
// Everything from DYNAMIC_BASE (the gigabyte after the kernel image) up to the
// revocation bitmap is one pool of virtual addresses handed out by
// `alloc_pages` as they are asked for. An address is in use exactly while its
// leaf entry is not zero (PAGES); the page tables are the only record. Kernel
// objects and compartment memory come from the same pool and are
// distinguished by who holds a capability to them, not by where they sit.
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

// PAGES
//
// A page of the pool is free (its leaf entry is zero) or in use. A page in
// use either has a frame (it is resident) or it does not, and its entry says
// which (pte, NON-RESIDENT ENTRIES). Two moves change that and nothing else
// does: one gives a page its frame, one takes it away (vm_pages.hpp).
// Allocation reserves addresses; memory that is not pageable is given its
// frames there and then, and keeps them until it is reclaimed.
//
// Pageable memory (PAGING) can be anywhere in the pool. A 2MB region with a
// page in use holds either pageable memory or memory that keeps its frames,
// never both, so where a page is says whether its frame may be taken; an
// empty region can become either. Without SIGNETOS_PAGING nothing is
// pageable, no frame is ever taken away, and every page in use is resident.

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

    // NON-RESIDENT ENTRIES. The hardware ignores a leaf entry whose Valid bit
    // is clear, so its other bits are software's. Zero is a free address; any
    // other entry with Valid clear is an address in use with no frame: one of
    // the kinds below (PAGING). `Quarantined` and `Revocable` keep their
    // meaning.
    constexpr uint64_t KindMask    = 3ULL << 1;
    constexpr uint64_t KindFresh   = 1ULL << 1;  // never touched
    constexpr uint64_t KindSwapped = 2ULL << 1;  // its contents are on disk
    constexpr uint64_t KindHeld    = 3ULL << 1;  // reclaimed, not reusable yet

    // A Swapped entry names the slot of swap its page is in (PAGING, SWAP),
    // in the bits above the flags, where a resident entry names its frame.
    constexpr unsigned SlotShift = 10;
}

// An address is in use while its leaf entry is non-zero; resident while it is
// mapped on a frame. The kind of a non-resident entry, or 0.
constexpr bool pte_in_use(uint64_t e) { return e != 0; }
constexpr bool pte_resident(uint64_t e) { return (e & pte::Valid) != 0; }
constexpr uint64_t pte_kind(uint64_t e) {
  return pte_resident(e) ? 0 : (e & pte::KindMask);
}
constexpr uint64_t pte_slot(uint64_t e) { return e >> pte::SlotShift; }

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

// `pages` rounded up to a count a capability can be bounded to exactly: what
// an allocation of `pages` takes, and is charged for. 0 if `pages` is 0 or
// more than the pool holds.
size_t round_up_pages(size_t pages);

// Allocates `pages` contiguous pages at the lowest free addresses that fit
// (up to 2MB within one 2MB region, larger as whole empty 2MB regions), and
// returns a capability bounded to exactly that range with DataRw, or null.
// `pages` must be its own `round_up_pages`. Contents are zeroed. Page tables
// are taken from the frame allocator as needed. If `revocable`, the range
// starts on a BITMAP_SPAN boundary and comes with `bitmap_pages(pages)` more
// frames of revocation bitmap (REVOCATION BITMAP), which the caller pays for
// too.
//
// `backing` says how the pages get their frames. Null if RAM has not the
// frames (Frames) or no run of them (OneRun), or if swap has not a slot for
// each page (Pageable; PAGING, SWAP): always, unless paging is on.
enum class Backing {
  // A frame each, there and then, kept until the memory is reclaimed. Any
  // free frames: they need not be adjacent in RAM.
  Frames,
  // The same, on adjacent frames in address order: one run of RAM. Only
  // memory a device is pointed at needs it (FLAG_DMA).
  OneRun,
  // None yet: a page gets its frame when it is touched, and may go to swap
  // (PAGING).
  Pageable,
};
Capability alloc_pages(size_t pages, bool revocable = false,
                       Backing backing = Backing::Frames);

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
// quarantined ranges have been cleared. With paging the addresses are left
// Held instead, until the sweep is complete and calls `release_held`
// (PAGING, REVOCATION).
void reclaim_quarantined();

// Kernel-only read/write view of the whole revocation bitmap (REVOCATION
// BITMAP), for `revoke`, which owns what is in it. Only the pages of
// revocable allocations are mapped: test `leaf_flags` before touching
// anything else.
Capability bitmap_view();

// PAGING
//
// Built only with SIGNETOS_PAGING (the Makefile's PAGING), in paging.cpp.
//
// What compartments allocate can move to disk and back. The kernel decides
// everything -- which pages go out, when, and where they come back -- and
// `blk` moves the bytes, because only a thread can wait for the disk. A
// page's state is in its leaf entry: Fresh, resident, Swapped, or Held
// (NON-RESIDENT ENTRIES).
//
// WHAT IS PAGEABLE. A compartment's memory is pageable if its creator made
// it so (compartment.hpp, FLAG_PAGEABLE), DMA memory excepted; the kernel's
// own never is. `init` makes nothing pageable (WHAT MUST NOT WAIT), so what
// pages is the programs the shell runs.
//
// SWAP. No more pageable pages are in use than swap has slots: an
// allocation that would make more is refused. So a page that has to leave
// RAM always has a slot to go to, and what one compartment allocates cannot
// leave another's pages with nowhere to be. A page is given its slot as it
// goes out, and its entry names the slot while it is there. The slot is free
// again once the page is back in, or has been reclaimed. Where the slots are
// on the disk is `blk`'s business.
//
// FAULTS. A page fault is paging's if the page it names is in use and has no
// frame (Fresh or Swapped): only pageable memory is ever seen so. An access
// that runs across two pages names the one that is missing, so one page is
// all a fault is ever about. A Fresh page is zero-filled at once if there is
// a frame to spare (FRAMES). Otherwise the thread is noted as waiting for
// the page, and the scheduler is told to block it and wake the pager
// (trap.hpp, PAGE_WAIT); once the page is in, the pager wakes it, and the
// access runs again. It waits for as long as that takes: a fault on a page
// in use is never turned into an ordinary one for want of a frame. The one
// that is ordinary is that of a thread that faulted with interrupts off,
// which cannot wait.
//
// THE PAGER. One thread of `blk`'s asks for a job (`page_next`), does its
// 4 KiB transfer to or from its slot, and says so (`page_done`), one job at a
// time, and sleeps when there is none. The jobs, most urgent first: wake a
// thread whose page is in (or gone); bring in a page a thread waits for,
// writing one out first if there is no frame to spare; write pages out to
// keep frames free (FRAMES); write out the pages a test asked for; read a
// page back for a check (REVOCATION). A page goes out by a
// clock over the resident pages of pageable memory that passes over the last
// few brought in: its entry becomes Swapped, its bytes are copied into
// `blk`'s buffer, and its frame is freed at once.
//
// ONE HART. Like the sweep, paging relies on every thread running on the
// boot hart (DESIGN.md §4.4): the kernel's own `sfence.vma` is all a page
// needs as it leaves, and nothing pages while a sweep runs.
//
// FRAMES. Three marks, each a number of free frames and a share of RAM. A
// pageable page never takes one of the last `reserve` free frames: those are
// kept for what cannot wait -- page tables, kernel objects, memory that is
// not pageable. Once fewer than `low` are free the pager writes pages out,
// and goes on until `high` are, so that a fault mostly finds a frame to
// spare and need not wait. The pager sees that frames are short when a fault
// has to wait, or on its next round (blk.cpp, PAGING), whichever is first.
//
// CAPABILITIES. A page that goes out leaves, beside its slot, a bitmap of the
// 16-byte granules that held capabilities. When it comes back, each is built
// again from the kernel's root (`set_retag_root`), unless it has been revoked.
// With SWAP_HASH (the default) the kernel also keeps a BLAKE2b-256 digest of
// the page and refuses a copy that does not match -- `blk` then reads it
// again -- so `blk` cannot change a page, or have a capability built that was
// not there. Without it, `blk` is trusted with those.
//
// REVOCATION. A sweep cannot see capabilities on disk. If there are any, it
// asks for them to be checked (`start_checks`): the pager reads each such page
// back, and every capability the sweep revokes is cleared from its bitmap, so
// it is never built again. What a sweep reclaims is Held (frame freed,
// address not reused) and its marks stay until it is complete: at once if
// nothing had to be checked, else when the checks are done. A page that comes
// in meanwhile is checked the same way as it comes in.
//
// KERNEL ACCESS. The kernel never takes a fault on pageable memory. To read
// or write a compartment's memory it takes a ResidentHold, which fails if a
// page is not in RAM; the caller touches the memory and calls again.
//
// WHAT MUST NOT WAIT. Nor may anything the pager needs wait for a page: `blk`
// holding its lock, the scheduler holding its own, or code running with
// interrupts masked (the interrupt handler, and what it calls). That is why
// everything `init` starts stays in RAM. It is
// a rule, not a check: the programs the shell runs reach those services
// only through `fs` and the console, which touch a program's memory only
// while holding nothing the pager needs.

// What paging makes of a page fault (FAULTS). No: an ordinary fault. Retry:
// the page is in now. Wait: the thread waits for it, and is to block until
// the pager wakes it.
enum class Fault { No, Retry, Wait };

#if defined(SIGNETOS_PAGING)

// Sets paging up, once, for `slots` pages of swap. NotInitialized without a
// root to build capabilities from (set_retag_root); Busy if it is set up
// already; InvalidSize if `slots` is 0, or more than an entry can name;
// NoMemory without the memory for what is kept beside each slot.
Status setup_paging(size_t slots);
bool paging_on();

// FAULTS: a page fault at `addr` by thread `tid`, which can wait for a page
// only if `can_wait`. `pager_tid` is the pager's thread, or 0.
Fault fault(uint64_t addr, bool can_wait, uint64_t tid);
uint64_t pager_tid();

// THE PAGER. What `page_next` returns: PAGE_NONE; PAGE_READ or PAGE_WRITE in
// the low byte with the slot above it; or PAGE_WAKE with the tid of a thread
// to wake above it. `buf` is `blk`'s page for the transfer: writable, 4 KiB
// from its address, aligned, and never pageable. `page_next` hands out a
// read or write again until `page_done` says it is done; a wake is handed
// out once, and needs no `page_done`. `tid` is the caller's, which faults
// then wake (FAULTS).
constexpr uint64_t PAGE_NONE = 0;
constexpr uint64_t PAGE_READ = 1;
constexpr uint64_t PAGE_WRITE = 2;
constexpr uint64_t PAGE_WAKE = 3;
constexpr uint64_t PAGE_OP_MASK = 0xFF;
constexpr unsigned PAGE_SLOT_SHIFT = 8;
uint64_t page_next(Capability buf, uint64_t tid);
void page_done(Capability buf);

// REVOCATION, for `revoke`. `start_checks` begins the checks a sweep needs
// and says whether there are any; `checks_pending` whether they are still
// going on. `release_held` frees the addresses the sweep reclaimed, once it
// is complete.
bool start_checks();
bool checks_pending();
void release_held();

// KERNEL ACCESS. Holds the VM lock, and so keeps every page of
// `[va, va + len)` in RAM, while it lives; `ok()` false, holding nothing, if
// any of them is not in RAM. Nothing that takes a lock listed before the VM
// lock (lock.hpp) may be taken while it is held.
bool hold_resident(uint64_t va, size_t len);
void release_resident();
class ResidentHold {
 public:
  ResidentHold(uint64_t va, size_t len) : held_(hold_resident(va, len)) {}
  ~ResidentHold() {
    if (held_) {
      release_resident();
    }
  }
  ResidentHold(const ResidentHold&) = delete;
  ResidentHold& operator=(const ResidentHold&) = delete;
  bool ok() const { return held_; }

 private:
  bool held_;
};

// Keeps `root`, the boot root, to build capabilities again (CAPABILITIES),
// once it has found where a capability's type sits in its bits. Called once
// at boot. False if it cannot: paging then stays off.
bool set_retag_root(Capability root);

// sys_page_test, for the shell's `pagetest`, built in only with PAGE_TEST=1
// (Makefile). EVICT sends the resident pages of the range `cap` covers out,
// and returns how many pages that is. Every other `op` returns one count,
// and takes no `cap`: the kernel writes nothing to its caller's memory.
// ~0 if refused, and always without PAGE_TEST.
constexpr uint64_t PAGE_TEST_EVICT = 0;
constexpr uint64_t PAGE_TEST_SLOTS = 1;          // pages of swap
constexpr uint64_t PAGE_TEST_FREE_FRAMES = 2;    // free frames now
constexpr uint64_t PAGE_TEST_RESERVE = 3;        // of them, the reserve (FRAMES)
constexpr uint64_t PAGE_TEST_READS = 4;          // pages read back for faults
constexpr uint64_t PAGE_TEST_WRITES = 5;         // pages written out
constexpr uint64_t PAGE_TEST_CHECKS = 6;         // pages read back for checks
constexpr uint64_t PAGE_TEST_DIGEST_ERRORS = 7;  // copies refused (SWAP_HASH)
constexpr uint64_t PAGE_TEST_EVICTING = 8;       // pages EVICT has yet to send
uint64_t page_test(uint64_t op, Capability cap);

#else  // !SIGNETOS_PAGING

// Every page in use is resident, so each place the kernel meets paging does
// nothing: no fault is paging's, a sweep has nothing on disk to check,
// memory the kernel is about to touch is always there, and the boot root is
// not kept.
constexpr bool paging_on() { return false; }
inline bool set_retag_root(Capability) { return true; }
inline Fault fault(uint64_t, bool, uint64_t) { return Fault::No; }
inline uint64_t pager_tid() { return 0; }
inline bool start_checks() { return false; }
inline bool checks_pending() { return false; }
inline void release_held() {}
class ResidentHold {
 public:
  ResidentHold(uint64_t, size_t) {}
  bool ok() const { return true; }
};

#endif  // SIGNETOS_PAGING

// Diagnostics.
size_t table_pages();         // frames held as page tables (never freed)
size_t allocated_pages();    // pages handed out by alloc_pages and not freed
size_t quarantined_pages();  // pages freed, still mapped, awaiting the sweep

} // namespace signetos::vm
