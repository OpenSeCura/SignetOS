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
 * vm.cpp - SignetOS virtual memory
 *
 * See vm.hpp for the address space layout and how the direct map reaches page
 * tables.
 */

#include <signetos/frame.hpp>
#include <signetos/lock.hpp>
#include <signetos/hw/platform.hpp>
#include <signetos/sealing.hpp>
#include <signetos/vm.hpp>
#if defined(SIGNETOS_SWAP_HASH)
#include <signetos/lib/blake2b.hpp>
#endif

namespace signetos::vm {
namespace {

// 512 eight-byte entries fill one 4KB page exactly.
constexpr size_t ENTRIES = 512;

SpinLock s_lock;

// Boot tables for the device window and the kernel image. The root stays in
// .bss because satp must point at something before any mapping exists. The
// direct map's L1 tables are not here: there is one per gigabyte of RAM, so
// they are carved from RAM just above the kernel image in init().
//
// The device gigabyte (root entry 0) is mapped as 512 MMIO megapage leaves:
// the kernel does not know which devices the board has beyond its own console,
// poweroff device and CLINT (platform.hpp), and nothing is gained by mapping
// less.
// What a compartment can reach is decided by capability bounds, not by the
// page tables: `init` is handed one window over the gigabyte and carves the
// per-device windows the drivers get from the DTB.
alignas(PAGE_SIZE) uint64_t s_l2_root[ENTRIES];
alignas(PAGE_SIZE) uint64_t s_l1_mmio[ENTRIES];
alignas(PAGE_SIZE) uint64_t s_l1_kernel[ENTRIES];

// Authority covering the direct map, DIRECT_BASE + [0, s_direct_top -
// ram_base), narrowed to one frame at a time by table_view and phys_view.
// Never handed out.
Capability s_direct = nullptr;

// End of the direct-mapped RAM (whole megapages only), and the first physical
// address above the kernel image and the direct map's own L1 tables. Everything
// from there to s_direct_top belongs to the frame allocator.
uint64_t s_direct_top = 0;
uint64_t s_boot_reserved_end = 0;

// Authority covering the whole dynamic address space, narrowed to one object at
// a time by alloc_pages and view. Never handed out.
Capability s_dynamic = nullptr;

// Authority covering the device gigabyte (root entry 0). `device_window`
// derives from it; the window `init` gets is this span minus `StoreLocal`.
Capability s_devices = nullptr;

// The pool alloc_pages hands addresses out of: the dynamic space below the
// revocation bitmap. The page tables are the only record of which of its
// addresses are in use: a page is in use exactly while it is mapped (live or
// quarantined).
//
// Walking the tables to find room would be slow, so each 2MB and each 1GB
// region of the pool keeps a count of its mapped pages. A search skips any
// region without enough unmapped pages, and the sweep skips regions with
// none mapped. The arrays are sized by the address space (about 250KB), not
// by RAM or by how fragmented the pool gets.
constexpr size_t PAGES_PER_2M = MEGAPAGE_SIZE / PAGE_SIZE;        // 512
constexpr size_t REGIONS_PER_1G = GIGAPAGE_SIZE / MEGAPAGE_SIZE;  // 512
constexpr size_t POOL_2M = (BITMAP_BASE - DYNAMIC_BASE) / MEGAPAGE_SIZE;
constexpr size_t POOL_1G = (BITMAP_BASE - DYNAMIC_BASE) / GIGAPAGE_SIZE;
constexpr size_t POOL_PAGES = POOL_2M * PAGES_PER_2M;
static_assert(DYNAMIC_BASE % GIGAPAGE_SIZE == 0 &&
              BITMAP_BASE % GIGAPAGE_SIZE == 0);
uint16_t s_used_2m[POOL_2M];
uint32_t s_used_1g[POOL_1G];

size_t s_table_pages = 0;        // frames currently held as page tables
size_t s_alloc_pages = 0;        // pages currently handed out by alloc_pages
size_t s_quarantined_pages = 0;  // pages freed, still mapped, awaiting a sweep
size_t s_held_pages = 0;         // reclaimed, Held until checks are done

// The pageable region (vm.hpp, PAGING): its first address, set last and
// once, and its size in pages. 0: paging is off.
uint64_t s_region_base = 0;
size_t s_region_pages = 0;

// The top of the part of the pool alloc_pages hands out: the pageable region
// is alloc_pageable_pages's.
uint64_t pinned_pool_top() {
  const uint64_t base = __atomic_load_n(&s_region_base, __ATOMIC_ACQUIRE);
  return base != 0 ? base : BITMAP_BASE;
}

// The paging engine (vm.hpp, PAGING), under `s_lock`.
constexpr size_t CAPS_PER_PAGE = PAGE_SIZE / sizeof(Capability);
constexpr size_t TAG_BYTES = CAPS_PER_PAGE / 8;

// The pages brought in last, which the clock passes over: as many as one
// instruction can touch, rounded up.
constexpr size_t RECENT = 4;

// What the kernel keeps beside each slot (CAPABILITIES).
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
  uint64_t va;     // the page read or written
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
  SlotInfo* slots;     // one per slot
  uint64_t* resident;  // a bit per slot: may be resident (the clock's hint)
  Capability scratch;  // a page of the kernel's, where a check's copy goes
  uint64_t hand;       // the slot the clock looks at next
  uint64_t recent[RECENT];
  size_t recent_next;
  Waiter waiters[MAX_WAITERS];
  uint64_t pager;       // the pager's tid, once it has asked for a job
  Job job;
  uint64_t check_next;  // the slot the checks look at next; none: the end
#if defined(SIGNETOS_PAGE_TEST)
  uint64_t evict_next;  // PAGE_TEST_EVICT: the pages still to send out
  uint64_t evict_end;
#endif
  uint64_t reads, writes, checks, digest_errors;  // PagingStats
};
Paging s_paging;

// The boot root, kept by set_retag_root to build capabilities again, and
// where the CT field sits in the upper word of a capability's bits.
Capability s_retag_root = nullptr;
uint64_t s_ct_shift = 0;
constexpr uint64_t CT_MASK = 0x1F;

// Bits 9:0 of a PTE are flags; everything above is the physical page number.
constexpr uint64_t PTE_FLAG_MASK = 0x3FFULL;

// Builds a page table entry pointing at the frame containing `pa`.
uint64_t pte_make(uint64_t pa, uint64_t flags) {
  // pa >> PAGE_SHIFT turns a byte address into a frame number, and << 10
  // puts that frame number where the hardware reads it, above the flag bits.
  // The mask drops anything a caller passed in outside bits 9:0.
  return ((pa >> PAGE_SHIFT) << 10) | (flags & PTE_FLAG_MASK);
}

// The physical address of whatever an entry points at: a frame of memory if the
// entry is a leaf, the next table down if it is not.
uint64_t pte_addr(uint64_t entry) {
  // Undoes pte_make: >> 10 drops the flags and recovers the frame number,
  // << PAGE_SHIFT turns that frame number back into a byte address.
  return (entry >> 10) << PAGE_SHIFT;
}

// Whether an entry ends the walk or continues it.
bool pte_is_leaf(uint64_t entry) {
  // The hardware distinguishes the two by permissions alone: an entry that
  // grants no access at all is a pointer to the next table, and an entry that
  // grants any access is a leaf naming a page.
  return (entry & (pte::Read | pte::Write | pte::Execute)) != 0;
}

// The physical address of a kernel object.
//
// Only called from init(), before satp is set. With the MMU off, the address in
// a pointer goes to the bus unchanged, so a .bss object's virtual address is
// also its physical address.
uint64_t phys_of(void* p) {
  return capability_get_address(reinterpret_cast<Capability>(p));
}

// Discards any cached translation for one page.
//
// The hardware is allowed to keep translations in the TLB and will not notice
// that a page table in memory has changed, so every write to a live entry has
// to be followed by this or the old translation may still be used.
void flush(uint64_t va) {
  __asm__ volatile("sfence.vma %0, zero" ::"r"(va) : "memory");
}

// The three index fields of a virtual address. Each shift moves that level's
// field down to bit 0, and 0x1FF keeps the nine bits of it.
size_t l2_index(uint64_t va) { return (va >> 30) & 0x1FF; }  // 1GB per entry
size_t l1_index(uint64_t va) { return (va >> 21) & 0x1FF; }  // 2MB per entry
size_t l0_index(uint64_t va) { return (va >> 12) & 0x1FF; }  // 4KB per entry

//
// Reaching page tables.
//
// All of RAM is mapped at boot (the direct map), so a frame holding a page
// table is reachable at DIRECT_BASE + its offset into RAM. table_view narrows
// the direct-map authority to that one frame, so a walk cannot run off the end
// of the table it is reading.
//
uint64_t* table_view(uint64_t pa) {
  if ((pa % PAGE_SIZE) != 0) {
    return nullptr;
  }
  Capability c = phys_view(pa, PAGE_SIZE);
  return capability_is_valid(c) ? reinterpret_cast<uint64_t*>(c) : nullptr;
}

// Allocates a frame, zeroes it, and installs it in `entry` as a table.
bool install_table(uint64_t* entry) {
  const uint64_t pa = frame::alloc(1);
  if (pa == 0) {
    return false;
  }

  uint64_t* table = table_view(pa);
  if (table == nullptr) {
    frame::free(pa, 1);
    return false;
  }
  // Frames come back dirty. Every entry must read as invalid, or the walk
  // will follow whatever the previous owner left behind.
  for (size_t i = 0; i < ENTRIES; ++i) {
    table[i] = 0;
  }

  // Valid with no permissions: that combination is what tells the hardware
  // this entry points at another table rather than at a page.
  __atomic_store_n(entry, pte_make(pa, pte::Valid), __ATOMIC_RELEASE);
  __atomic_store_n(&s_table_pages, s_table_pages + 1, __ATOMIC_RELAXED);
  return true;
}

// Whether the hardware will even look at this address.
//
// Sv39 translates 39-bit addresses, and requires bits 63:39 to all equal bit 38
// so that the unused top of the address cannot be used to smuggle information.
// Anything else faults before the page tables are consulted.
bool va_is_canonical(uint64_t va) {
  const uint64_t high = va >> 39;      // the 25 bits above the range
  return ((va >> 38) & 1)              // is the top translated bit set?
             ? (high == 0x1FFFFFFULL)  // if so, all 25 must be ones
             : (high == 0);            // if not, all 25 must be zeroes
}

// Whether map()/unmap() are allowed to touch this range.
//
// Only the dynamic space is theirs. The boot mappings (devices, kernel image,
// direct map) are excluded, or a caller could repoint the UART or unmap the
// running kernel.
bool range_is_mappable(uint64_t va, size_t pages) {
  const uint64_t span = DYNAMIC_TOP - DYNAMIC_BASE;

  // Bounds the multiply below, so `bytes` cannot wrap.
  if (pages == 0 || pages > span / PAGE_SIZE) {
    return false;
  }
  const uint64_t bytes = pages * PAGE_SIZE;

  // Below the dynamic space, or running off the top of it. Written as
  // `va > DYNAMIC_TOP - bytes` rather than `va + bytes > DYNAMIC_TOP` so the
  // addition cannot wrap past the end and appear to fit.
  return va >= DYNAMIC_BASE && va <= DYNAMIC_TOP - bytes;
}

// Whether a physical range is memory that exists.
//
// A mapping pointing outside RAM would take an access fault on first touch
// instead of reaching a frame.
bool range_is_ram(uint64_t pa, size_t pages) {
  const uint64_t base = frame::ram_base();
  const uint64_t total = frame::ram_bytes();
  const uint64_t bytes = pages * PAGE_SIZE;

  // Checked before the subtraction below, which would otherwise wrap and
  // accept any `pa` for a range larger than RAM.
  if (bytes > total) {
    return false;
  }
  // Start inside RAM, and end inside it too.
  return pa >= base && (pa - base) <= total - bytes;
}

// Walks to the 4KB entry that describes `va`, building the tables on the way
// down if `create` is set. Returns a pointer into the live table.
uint64_t* leaf_slot(uint64_t va, bool create) {
  // The root table is a static array, so it needs no slot to reach.
  uint64_t* l2_entry = &s_l2_root[l2_index(va)];

  if (!(*l2_entry & pte::Valid)) {
    // Nothing below this 1GB of address space yet.
    if (!create || !install_table(l2_entry)) {
      return nullptr;
    }
  } else if (pte_is_leaf(*l2_entry)) {
    // A 1GB page already covers this address. Descending is impossible: it
    // would mean splitting the big page, which nothing here does.
    return nullptr;
  }

  uint64_t* l1_table = table_view(pte_addr(*l2_entry));
  if (l1_table == nullptr) {
    return nullptr;
  }

  // Same two cases one level down, now for 2MB of address space.
  uint64_t* l1_entry = &l1_table[l1_index(va)];
  if (!(*l1_entry & pte::Valid)) {
    if (!create || !install_table(l1_entry)) {
      return nullptr;
    }
  } else if (pte_is_leaf(*l1_entry)) {
    return nullptr;
  }

  uint64_t* l0_table = table_view(pte_addr(*l1_entry));
  if (l0_table == nullptr) {
    return nullptr;
  }
  return &l0_table[l0_index(va)];
}

// The entry that translates `va`, at whichever level it turns out to be a leaf.
// `entry` is 0 if `va` is not mapped; `page_size` is how much the entry covers,
// which is what turns an entry into an address.
struct Leaf {
  uint64_t entry;
  uint64_t page_size;
};

// Read-only walk. Unlike leaf_slot this stops wherever the walk actually ends,
// so it reports the 2MB and 1GB pages the boot mappings use. For an unmapped
// address `entry` is 0 and `page_size` is the size of the hole the walk fell
// into (a missing table covers 1GB or 2MB), so a caller stepping through an
// address range can skip the whole hole at once.
Leaf find_leaf(uint64_t va) {
  if (!va_is_canonical(va)) {
    return {0, PAGE_SIZE};
  }

  const uint64_t l2 = __atomic_load_n(&s_l2_root[l2_index(va)], __ATOMIC_ACQUIRE);
  if (!(l2 & pte::Valid)) {
    return {0, GIGAPAGE_SIZE};  // nothing mapped in this 1GB
  }
  if (pte_is_leaf(l2)) {
    return {l2, GIGAPAGE_SIZE};  // the whole 1GB is one page
  }

  const uint64_t* l1_table = table_view(pte_addr(l2));
  if (l1_table == nullptr) {
    return {0, GIGAPAGE_SIZE};
  }
  const uint64_t l1 = __atomic_load_n(&l1_table[l1_index(va)], __ATOMIC_ACQUIRE);
  if (!(l1 & pte::Valid)) {
    return {0, MEGAPAGE_SIZE};  // nothing mapped in this 2MB
  }
  if (pte_is_leaf(l1)) {
    return {l1, MEGAPAGE_SIZE};  // the whole 2MB is one page
  }

  const uint64_t* l0_table = table_view(pte_addr(l1));
  if (l0_table == nullptr) {
    return {0, MEGAPAGE_SIZE};
  }
  // Last level: either a 4KB page or nothing.
  const uint64_t l0 = __atomic_load_n(&l0_table[l0_index(va)], __ATOMIC_RELAXED);
  return {l0, PAGE_SIZE};  // mapped, in use with no frame (PAGING), or 0
}

// The address just past the page or hole that `find_leaf(va)` reported.
uint64_t next_after(uint64_t va, const Leaf& leaf) {
  return (va & ~(leaf.page_size - 1)) + leaf.page_size;
}

}  // namespace

uint64_t kernel_base() { return frame::ram_base(); }

void init(Capability root_data_cap) {
  s_lock = SpinLock{};
  s_direct = nullptr;
  s_dynamic = nullptr;
  s_direct_top = 0;
  s_boot_reserved_end = 0;
  s_table_pages = 0;
  s_alloc_pages = 0;
  s_quarantined_pages = 0;
  s_held_pages = 0;
  s_region_base = 0;
  s_region_pages = 0;
  s_paging = Paging{};
  s_retag_root = nullptr;

  // .bss is not guaranteed zeroed this early, and a stray set Valid bit would
  // send the hardware walking into nonsense.
  for (size_t i = 0; i < ENTRIES; ++i) {
    s_l2_root[i] = 0;
    s_l1_mmio[i] = 0;
    s_l1_kernel[i] = 0;
  }
  for (size_t i = 0; i < POOL_2M; ++i) {
    s_used_2m[i] = 0;
  }
  for (size_t i = 0; i < POOL_1G; ++i) {
    s_used_1g[i] = 0;
  }

  // Root entry 0 covers VA 0x00000000..0x3FFFFFFF, where the devices are:
  // every megapage of it is an MMIO leaf. The kernel's own console, poweroff
  // device and CLINT have to be inside it (they are the only devices the
  // kernel touches); the rest is reached by capability bounds alone.
  if (platform::test_device_base() >= GIGAPAGE_SIZE ||
      platform::uart_base() >= GIGAPAGE_SIZE ||
      platform::clint_base() >= GIGAPAGE_SIZE) {
    return;
  }
  s_l2_root[0] = pte_make(phys_of(&s_l1_mmio[0]), pte::Valid);
  for (size_t i = 0; i < ENTRIES; ++i) {
    s_l1_mmio[i] = pte_make(static_cast<uint64_t>(i) * MEGAPAGE_SIZE, pte::Mmio);
  }

  // The kernel image, identity-mapped as megapage leaves so the addresses the
  // linker produced keep working after the MMU comes on.
  const uint64_t kbase = kernel_base();
  if (!capability_is_valid(root_data_cap) || kbase != KERNEL_BASE) {
    return;  // leaves is_initialized() false; kernel_main reports it
  }
  s_l2_root[l2_index(kbase)] = pte_make(phys_of(&s_l1_kernel[0]), pte::Valid);
  for (uint64_t pa = kbase; pa < kbase + KERNEL_SIZE; pa += MEGAPAGE_SIZE) {
    s_l1_kernel[l1_index(pa)] = pte_make(pa, pte::Permissive);
  }

  // The direct map: every megapage of RAM, as data, at DIRECT_BASE + offset.
  // This is how the kernel reaches page tables and the frame bitmap.
  const uint64_t direct_top = (kbase + frame::ram_bytes()) & ~(MEGAPAGE_SIZE - 1);
  if (direct_top < kbase + KERNEL_SIZE + MEGAPAGE_SIZE) {
    return;
  }
  const uint64_t direct_len = direct_top - kbase;

  // One L1 table per gigabyte of direct map, carved from the frames right
  // after the kernel image. Physical addressing is still on, so they are
  // written through root_data_cap at their physical address.
  const size_t gbs = (direct_len + GIGAPAGE_SIZE - 1) / GIGAPAGE_SIZE;
  const uint64_t tables_pa = kbase + KERNEL_SIZE;
  Capability t = capability_set_address(root_data_cap, tables_pa);
  t = capability_set_bounds(t, gbs * PAGE_SIZE);
  t = capability_and_perms(t, perms::DataRw);
  if (!capability_is_valid(t)) {
    return;
  }
  auto* tables = reinterpret_cast<uint64_t*>(t);
  for (size_t i = 0; i < gbs * ENTRIES; ++i) {
    tables[i] = 0;
  }
  for (size_t g = 0; g < gbs; ++g) {
    s_l2_root[l2_index(DIRECT_BASE) + g] =
        pte_make(tables_pa + (g * PAGE_SIZE), pte::Valid);
  }
  for (uint64_t off = 0; off < direct_len; off += MEGAPAGE_SIZE) {
    const uint64_t va = DIRECT_BASE + off;
    const size_t g = l2_index(va) - l2_index(DIRECT_BASE);
    tables[(g * ENTRIES) + l1_index(va)] = pte_make(kbase + off, pte::KernelData);
  }
  s_direct_top = direct_top;
  s_boot_reserved_end = tables_pa + (gbs * PAGE_SIZE);

  // The two standing authorities, both narrowed from the root and never
  // handed out: one over the direct map, one over the dynamic space that
  // every object from alloc_pages is derived from.
  Capability d = capability_set_address(root_data_cap, DIRECT_BASE);
  d = capability_set_bounds(d, direct_len);
  d = capability_and_perms(d, perms::DataRw);
  Capability k = capability_set_address(root_data_cap, DYNAMIC_BASE);
  k = capability_set_bounds(k, DYNAMIC_TOP - DYNAMIC_BASE);
  k = capability_and_perms(k, perms::DataRw);
  // And a third over the device gigabyte, for device_window.
  Capability dev = capability_set_address(root_data_cap, 0);
  dev = capability_set_bounds(dev, GIGAPAGE_SIZE);
  dev = capability_and_perms(dev, perms::DataRw);
  if (!capability_is_valid(d) || !capability_is_valid(k) ||
      !capability_is_valid(dev)) {
    return;
  }

  // SUM lets this code read and write pages marked User; MXR lets it read
  // pages marked execute-only. Both are `mstatus` bits, and the M-mode MMU
  // applies them as the S-mode one would (toolchain/mmodemmu).
  constexpr uint64_t MSTATUS_SUM_MXR = (1ULL << 18) | (1ULL << 19);
  __asm__ volatile("csrs mstatus, %0" ::"r"(MSTATUS_SUM_MXR) : "memory");

  // satp names the root table: mode 8 in the top four bits selects Sv39, and
  // the low bits hold the root table's frame number, not its address. Setting
  // mmodemmu.ENABLE (CSR 0x7c0, bit 0) then turns translation on for M-mode,
  // from the next instruction. This code and its stack are in the kernel
  // image, which is identity-mapped, so they stay where they are.
  const uint64_t satp = (8ULL << 60) | (phys_of(&s_l2_root[0]) >> PAGE_SHIFT);
  __asm__ volatile(
      "csrw satp, %0\n\t"
      // Everything cached from before translation was on is now meaningless.
      "sfence.vma zero, zero\n\t"
      "csrsi 0x7c0, 1\n\t" ::"r"(satp)
      : "memory");

  s_direct = d;
  s_dynamic = k;
  s_devices = dev;
}

bool is_initialized() {
  return capability_is_valid(s_direct) && capability_is_valid(s_dynamic);
}

Capability device_window(uint64_t pa, size_t len) {
  // Anything inside the device gigabyte; nothing else is mapped there.
  if (!capability_is_valid(s_devices) || len == 0 || pa + len < pa ||
      pa + len > GIGAPAGE_SIZE) {
    return nullptr;
  }
  Capability c = capability_set_address(s_devices, pa);
  c = capability_set_bounds(c, len);
  // Handed to a compartment: like every non-stack capability it gets, it
  // cannot store local capabilities (see compartment.cpp, `user_view`).
  c = capability_restrict_levels(c, perms::StoreLocal);
  return capability_is_valid(c) ? c : nullptr;
}

uint64_t boot_reserved_end() { return s_boot_reserved_end; }
uint64_t direct_map_top() { return s_direct_top; }

Capability phys_view(uint64_t pa, size_t len) {
  const uint64_t ram_base = kernel_base();
  if (!capability_is_valid(s_direct) || len == 0 || pa < ram_base ||
      pa >= s_direct_top || len > s_direct_top - pa) {
    return nullptr;
  }
  Capability c = capability_set_address(s_direct, DIRECT_BASE + (pa - ram_base));
  c = capability_set_bounds(c, len);
  return capability_is_valid(c) ? c : nullptr;
}

namespace {

// Keeps the region counts in step with the page tables: called with +1 for
// every leaf entry set in the pool and -1 for every one cleared. Bitmap pages
// (at or above BITMAP_BASE) are not in the pool and are not counted.
void count_page(uint64_t va, int delta) {
  if (va < DYNAMIC_BASE || va >= BITMAP_BASE) {
    return;
  }
  const size_t m = (va - DYNAMIC_BASE) / MEGAPAGE_SIZE;
  s_used_2m[m] = static_cast<uint16_t>(s_used_2m[m] + delta);
  s_used_1g[m / REGIONS_PER_1G] =
      static_cast<uint32_t>(s_used_1g[m / REGIONS_PER_1G] + delta);
}

// `va` if its 2MB region of the pool has anything mapped in it, else the start
// of the next region that does, else BITMAP_BASE.
uint64_t next_used(uint64_t va) {
  while (va < BITMAP_BASE) {
    const size_t m = (va - DYNAMIC_BASE) / MEGAPAGE_SIZE;
    const size_t g = m / REGIONS_PER_1G;
    if (s_used_1g[g] == 0) {
      va = DYNAMIC_BASE + ((g + 1) * GIGAPAGE_SIZE);
    } else if (s_used_2m[m] == 0) {
      va = DYNAMIC_BASE + ((m + 1) * MEGAPAGE_SIZE);
    } else {
      return va;
    }
  }
  return BITMAP_BASE;
}

// The L0 table of the 2MB region of the pool at `base`, or null if it has none
// yet, in which case nothing in the region has ever been mapped. The pool is
// only ever mapped with 4KB pages, so there is no bigger leaf to stop at.
const uint64_t* l0_table_of(uint64_t base) {
  const uint64_t l2 = s_l2_root[l2_index(base)];
  if (!(l2 & pte::Valid)) {
    return nullptr;
  }
  const uint64_t* l1_table = table_view(pte_addr(l2));
  if (l1_table == nullptr) {
    return nullptr;
  }
  const uint64_t l1 = l1_table[l1_index(base)];
  if (!(l1 & pte::Valid)) {
    return nullptr;
  }
  return table_view(pte_addr(l1));
}

// First index of `pages` consecutive unmapped entries in the 2MB region at
// `base`, at a multiple of `step` entries, or ENTRIES if there is none.
size_t free_run_in(uint64_t base, size_t pages, size_t step) {
  const uint64_t* l0 = l0_table_of(base);
  if (l0 == nullptr) {
    return 0;
  }
  for (size_t start = 0; start + pages <= ENTRIES;) {
    size_t k = 0;
    while (k < pages && !pte_in_use(l0[start + k])) {
      ++k;
    }
    if (k == pages) {
      return start;
    }
    // Entry start + k is mapped: no run that includes it can work, so try
    // the first aligned start past it.
    start = (start + k + step) / step * step;
  }
  return ENTRIES;
}

// Finds `pages` of unmapped addresses in the pool, starting on a multiple of
// `align` (a power of two from PAGE_SIZE to MEGAPAGE_SIZE), lowest first.
// Returns the start, or 0 if there is no such run.
//
// Up to 2MB is looked for inside one 2MB region: the counts rule out regions
// without enough room, and only a region that might have it has its L0 table
// read. Bigger requests take whole empty 2MB regions. Neither looks for a run
// that straddles a 2MB boundary without filling the regions it touches, which
// costs some fragmentation and keeps the search short.
uint64_t find_room_locked(size_t pages, uint64_t align) {
  const size_t pool_1g = (pinned_pool_top() - DYNAMIC_BASE) / GIGAPAGE_SIZE;
  if (pages <= PAGES_PER_2M) {
    for (size_t g = 0; g < pool_1g; ++g) {
      if (PAGES_PER_2M * REGIONS_PER_1G - s_used_1g[g] < pages) {
        continue;
      }
      for (size_t m = g * REGIONS_PER_1G; m < (g + 1) * REGIONS_PER_1G; ++m) {
        if (PAGES_PER_2M - s_used_2m[m] < pages) {
          continue;
        }
        const uint64_t base = DYNAMIC_BASE + (m * MEGAPAGE_SIZE);
        const size_t i = free_run_in(base, pages, align / PAGE_SIZE);
        if (i < ENTRIES) {
          return base + (i * PAGE_SIZE);
        }
      }
    }
    return 0;
  }

  const size_t need = (pages + PAGES_PER_2M - 1) / PAGES_PER_2M;
  size_t run = 0;  // empty 2MB regions just below m
  for (size_t m = 0; m < pool_1g * REGIONS_PER_1G;) {
    if (m % REGIONS_PER_1G == 0 && s_used_1g[m / REGIONS_PER_1G] == 0) {
      run += REGIONS_PER_1G;
      m += REGIONS_PER_1G;
    } else {
      run = (s_used_2m[m] == 0) ? run + 1 : 0;
      m += 1;
    }
    if (run >= need) {
      return DYNAMIC_BASE + ((m - run) * MEGAPAGE_SIZE);
    }
  }
  return 0;
}

bool unmap_locked(uint64_t va, size_t pages) {
  if (!is_initialized() || (va % PAGE_SIZE) != 0 ||
      !range_is_mappable(va, pages)) {
    return false;
  }

  // Clears whatever is present and reports whether anything was missing, so a
  // caller unmapping a range it believes is mapped finds out if it was wrong.
  bool all_present = true;
  for (size_t i = 0; i < pages; ++i) {
    const uint64_t page_va = va + (i * PAGE_SIZE);
    uint64_t* slot = leaf_slot(page_va, false);
    if (slot == nullptr || !pte_in_use(*slot)) {
      all_present = false;
      continue;
    }
    // Zero clears Valid along with everything else, which is what makes the
    // page unreachable.
    *slot = 0;
    count_page(page_va, -1);
    // Without this the hardware may keep translating the address from a
    // cached copy of the entry just cleared, and the page stays readable.
    flush(page_va);
  }
  // The tables that held these entries stay allocated even if now empty.
  return all_present;
}

bool map_locked(uint64_t va, uint64_t pa, size_t pages, uint64_t flags) {
  // Both addresses must name whole frames, the virtual range must be ours to
  // touch, and the physical range must be memory that exists.
  if (!is_initialized() || (va % PAGE_SIZE) != 0 || (pa % PAGE_SIZE) != 0 ||
      !range_is_mappable(va, pages) || !range_is_ram(pa, pages)) {
    return false;
  }

  // First pass changes nothing. If any page in the range is already mapped,
  // refuse the whole request here rather than overwriting a live mapping
  // halfway through the second pass.
  for (size_t i = 0; i < pages; ++i) {
    const uint64_t* slot = leaf_slot(va + (i * PAGE_SIZE), false);
    if (slot != nullptr && pte_in_use(*slot)) {
      return false;
    }
  }

  // Second pass installs the mappings, building tables as needed.
  for (size_t i = 0; i < pages; ++i) {
    const uint64_t page_va = va + (i * PAGE_SIZE);
    uint64_t* slot = leaf_slot(page_va, true);
    if (slot == nullptr) {
      // Out of frames for a table, or the range runs into an existing
      // megapage. Roll back so a failed map leaves nothing.
      if (i > 0) {
        unmap_locked(va, i);
      }
      return false;
    }
    // Valid is forced on: an entry without it is ignored by the hardware.
    *slot = pte_make(pa + (i * PAGE_SIZE), flags | pte::Valid);
    count_page(page_va, +1);
    // This address may have been mapped before, so drop any stale entry.
    flush(page_va);
  }
  return true;
}

// `bytes` at `va` in the dynamic space, reached through `s_dynamic`.
Capability dynamic_view(uint64_t va, size_t bytes) {
  return capability_set_bounds(capability_set_address(s_dynamic, va), bytes);
}

void zero_page(uint64_t va) {
  volatile uint64_t* w =
      reinterpret_cast<volatile uint64_t*>(dynamic_view(va, PAGE_SIZE));
  for (size_t i = 0; i < PAGE_SIZE / sizeof(uint64_t); ++i) {
    w[i] = 0;
  }
}

// Frees the first `count` bitmap pages of the revocable range at `va`, which
// nothing has seen. Caller holds `s_lock`.
void unmap_bitmap_locked(uint64_t va, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    uint64_t* slot = leaf_slot(bitmap_of(va) + (i * PAGE_SIZE), false);
    frame::free(pte_addr(*slot), 1);
    *slot = 0;
  }
  __asm__ volatile("sfence.vma zero, zero" ::: "memory");
}

// Maps zeroed bitmap pages for the revocable range of `pages` at `va`, which starts
// on a BITMAP_SPAN boundary, so its bitmap starts on a page. All or nothing.
// Caller holds `s_lock`.
bool map_bitmap_locked(uint64_t va, size_t pages) {
  const size_t count = bitmap_pages(pages);
  for (size_t i = 0; i < count; ++i) {
    const uint64_t s = bitmap_of(va) + (i * PAGE_SIZE);
    const uint64_t pa = frame::alloc(1);
    if (pa == 0 || !map_locked(s, pa, 1, pte::KernelData)) {
      if (pa != 0) {
        frame::free(pa, 1);
      }
      unmap_bitmap_locked(va, i);
      return false;
    }
    zero_page(s);
  }
  return true;
}

// --- Paging (vm.hpp, PAGING) -------------------------------------------------
// Everything here runs under `s_lock`.

bool is_pageable_address(uint64_t va) {
  const uint64_t base = __atomic_load_n(&s_region_base, __ATOMIC_ACQUIRE);
  return base != 0 && va >= base && va - base < s_region_pages * PAGE_SIZE;
}
uint64_t slot_of(uint64_t va) { return (va - s_region_base) / PAGE_SIZE; }
uint64_t va_of(uint64_t slot) { return s_region_base + (slot * PAGE_SIZE); }
uint64_t request(uint64_t slot, uint64_t op) {
  return (slot << PAGE_SLOT_SHIFT) | op;
}

volatile uint64_t* frame_words(uint64_t pa) {
  return reinterpret_cast<volatile uint64_t*>(phys_view(pa, PAGE_SIZE));
}
volatile Capability* frame_caps(uint64_t pa) {
  return reinterpret_cast<volatile Capability*>(phys_view(pa, PAGE_SIZE));
}

void set_bit(uint64_t* bits, uint64_t i, bool on) {
  const uint64_t m = 1ULL << (i % 64);
  bits[i / 64] = on ? (bits[i / 64] | m) : (bits[i / 64] & ~m);
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

// Free frames a pageable page may still take: those above the reserve, a
// sixty-fourth of RAM (FRAMES). Negative below it.
int64_t room() {
  return static_cast<int64_t>(frame::free_pages()) -
         static_cast<int64_t>(frame::pool_pages() / 64);
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

// THE BASE RULE (revoke.hpp) for a capability on its way between disk and
// memory, tagged or not: revoked if based in a quarantined or Held page, or
// in a marked granule -- early, for one freed since the last sweep, which
// would revoke it anyway. The standing authorities a sweep passes over are
// passed over here too (revoke.cpp, `should_revoke`). The marks are revoke's,
// read without its lock: one set or cleared meanwhile is one no sweep relies
// on yet, or any more.
bool is_revoked_locked(Capability cap) {
  if ((capability_get_perms(cap) &
       (perms::AccessSystemRegs | perms::Seal | perms::Unseal)) != 0) {
    return false;
  }
  const uint64_t base = capability_get_base(cap);
  if (base < DYNAMIC_BASE || base >= BITMAP_BASE ||
      capability_get_length(cap) >= DYNAMIC_TOP - DYNAMIC_BASE) {
    return false;
  }
  const uint64_t e = find_leaf(base).entry;
  if ((e & pte::Quarantined) != 0 || pte_kind(e) == pte::KindHeld) {
    return true;
  }
  if ((e & pte::Revocable) == 0) {
    return false;  // no marks: its bitmap pages are not even mapped
  }
  const auto* b = reinterpret_cast<const volatile uint8_t*>(
      dynamic_view(bitmap_of(base), 1));
  return ((*b >> (((base - DYNAMIC_BASE) / 16) % 8)) & 1) != 0;
}

// Builds again the capability whose bits, without their tag, are the 16
// bytes at `w` (as two words) and `c` (as a capability slot): from the root,
// unsealed, then sealed as it was -- CT 1 through seal_entry, the only way a
// call sentry is made, a kernel type with its authority. It stays plain bytes
// if it is revoked, if it is local (pageable memory never holds one), or if
// what comes out is not exactly what went out.
void rebuild_locked(volatile uint64_t* w, volatile Capability* c) {
  const uint64_t lo = w[0];
  const uint64_t hi = w[1];
  const Capability bits = *c;
  if (is_revoked_locked(bits) ||
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

// Makes pageable page `va`, whose entry is at `slot`, resident on frame `pa`:
// zeroed if it is Fresh; if it is Swapped, `src` copied in, checked against
// its digest, and its capabilities built again. False, with nothing mapped,
// if the copy is not the page that went out.
bool bring_in_locked(uint64_t va, uint64_t* slot, uint64_t pa, Capability src) {
  const uint64_t e = *slot;
  volatile uint64_t* w = frame_words(pa);
  if (pte_kind(e) == pte::KindFresh) {
    for (size_t i = 0; i < PAGE_SIZE / sizeof(uint64_t); ++i) {
      w[i] = 0;
    }
  } else {
    const auto* from = reinterpret_cast<const volatile uint64_t*>(src);
    for (size_t i = 0; i < PAGE_SIZE / sizeof(uint64_t); ++i) {
      w[i] = from[i];
    }
    const SlotInfo& info = s_paging.slots[slot_of(va)];
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
  *slot = pte_make(pa, pte::Permissive |
                           (e & (pte::Quarantined | pte::Revocable)));
  flush(va);
  __asm__ volatile("fence.i" ::: "memory");  // it may be code
  set_bit(s_paging.resident, slot_of(va), true);
  s_paging.recent[s_paging.recent_next] = va;
  s_paging.recent_next = (s_paging.recent_next + 1) % RECENT;
  return true;
}

// Whether page `va` may go out now: it is resident, and not one of the last
// brought in.
bool can_evict_locked(uint64_t va) {
  const uint64_t* slot = leaf_slot(va, false);
  if (slot == nullptr || !pte_resident(*slot)) {
    set_bit(s_paging.resident, slot_of(va), false);  // a stale hint
    return false;
  }
  for (const uint64_t r : s_paging.recent) {
    if (r == va) {
      return false;
    }
  }
  return true;
}

// The next page the clock hand comes to that may go out, or 0 if a whole
// turn finds none. The resident bits let it skip 64 slots at a time.
uint64_t pick_victim_locked() {
  const uint64_t pages = s_region_pages;
  for (uint64_t looked = 0; looked < pages + 64;) {
    if (s_paging.hand >= pages) {
      s_paging.hand = 0;
    }
    const uint64_t rest =
        s_paging.resident[s_paging.hand / 64] >> (s_paging.hand % 64);
    if (rest == 0) {
      looked += 64 - (s_paging.hand % 64);
      s_paging.hand += 64 - (s_paging.hand % 64);
      continue;
    }
    const uint64_t step = static_cast<uint64_t>(__builtin_ctzll(rest));
    const uint64_t va = va_of(s_paging.hand + step);
    s_paging.hand += step + 1;
    looked += step + 1;
    if (can_evict_locked(va)) {
      return va;
    }
  }
  return 0;
}

// Sends resident page `va` out: unmapped -- every thread runs on this hart
// (vm.hpp, PAGING), so the local flush is all it takes -- copied into `buf`,
// its tag bitmap and digest kept beside its slot, and its frame freed at
// once. Returns the write for the pager.
uint64_t send_out_locked(uint64_t va, Capability buf) {
  uint64_t* slot = leaf_slot(va, false);
  const uint64_t e = *slot;
  const uint64_t pa = pte_addr(e);
  const uint64_t s = slot_of(va);
  *slot = pte::KindSwapped | (e & (pte::Quarantined | pte::Revocable));
  flush(va);
  const volatile uint64_t* w = frame_words(pa);
  const volatile Capability* c = frame_caps(pa);
  auto* to = reinterpret_cast<volatile uint64_t*>(buf);
  for (size_t i = 0; i < PAGE_SIZE / sizeof(uint64_t); ++i) {
    to[i] = w[i];
  }
  SlotInfo& info = s_paging.slots[s];
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
  set_bit(s_paging.resident, s, false);
  s_paging.writes += 1;
  s_paging.job = Job{JOB_OUT, va, 0};
  return request(s, PAGE_WRITE);
}

// The first slot from `from` on whose page is on disk holding capabilities,
// or the region's size if there is none (REVOCATION).
uint64_t next_check_locked(uint64_t from) {
  for (uint64_t s = from; s < s_region_pages; ++s) {
    const uint64_t* slot =
        has_tags(s_paging.slots[s]) ? leaf_slot(va_of(s), false) : nullptr;
    if (slot != nullptr && pte_kind(*slot) == pte::KindSwapped) {
      return s;
    }
  }
  return s_region_pages;
}

// Whether a thread waiting for page `va` still has to: it is in use, and not
// in RAM (FAULTS).
bool still_waited_for_locked(uint64_t va) {
  const uint64_t* slot = leaf_slot(va, false);
  const uint64_t kind = slot != nullptr ? pte_kind(*slot) : 0;
  return kind == pte::KindFresh || kind == pte::KindSwapped;
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
    return request(slot_of(j.va), j.op == JOB_OUT ? PAGE_WRITE : PAGE_READ);
  }
  // A thread whose page is in, or gone: woken, to run the access again.
  for (Waiter& w : s_paging.waiters) {
    if (w.tid != 0 && !still_waited_for_locked(w.va)) {
      const uint64_t tid = w.tid;
      w = Waiter{};
      return request(tid, PAGE_WAKE);
    }
  }
  // A page a thread waits for: read in, or zeroed, if there is a frame for
  // it; else a page goes out first.
  for (const Waiter& w : s_paging.waiters) {
    if (w.tid == 0) {
      continue;
    }
    if (room() <= 0) {
      const uint64_t victim = pick_victim_locked();
      if (victim != 0) {
        return send_out_locked(victim, buf);
      }
      break;
    }
    const uint64_t pa = frame::alloc(1);
    if (pa == 0) {
      break;
    }
    uint64_t* slot = leaf_slot(w.va, false);
    if (pte_kind(*slot) == pte::KindFresh) {
      bring_in_locked(w.va, slot, pa, nullptr);
      return next_job_locked(buf);  // which wakes its thread
    }
    j = Job{JOB_IN, w.va, pa};
    return request(slot_of(w.va), PAGE_READ);
  }
  // The reserve (FRAMES).
  if (room() < 0) {
    const uint64_t victim = pick_victim_locked();
    if (victim != 0) {
      return send_out_locked(victim, buf);
    }
  }
#if defined(SIGNETOS_PAGE_TEST)
  // What a test asked to send out.
  while (s_paging.evict_next < s_paging.evict_end) {
    const uint64_t va = s_paging.evict_next;
    s_paging.evict_next += PAGE_SIZE;
    if (can_evict_locked(va)) {
      return send_out_locked(va, buf);
    }
  }
#endif
  // The checks a sweep waits for (REVOCATION).
  if (s_paging.check_next < s_region_pages) {
    const uint64_t s = next_check_locked(s_paging.check_next);
    s_paging.check_next = s < s_region_pages ? s + 1 : s_region_pages;
    if (s < s_region_pages) {
      j = Job{JOB_CHECK, va_of(s), 0};
      return request(s, PAGE_READ);
    }
  }
  return PAGE_NONE;
}

// THE PAGER: the job handed out is done; `buf` holds what a read read. A
// read whose copy is not the page that went out stays to be done again.
void finish_job_locked(Capability buf) {
  const Job j = s_paging.job;
  uint64_t* slot = j.op != JOB_NONE ? leaf_slot(j.va, false) : nullptr;
  const bool swapped = slot != nullptr && pte_kind(*slot) == pte::KindSwapped;
  if (j.op == JOB_IN) {
    if (!swapped) {
      frame::free(j.frame, 1);  // freed and reclaimed meanwhile
    } else if (!bring_in_locked(j.va, slot, j.frame, buf)) {
      return;
    }
  } else if (j.op == JOB_CHECK && swapped) {
    // Into the kernel's own page first: what is checked is what is decoded.
    volatile uint64_t* w = reinterpret_cast<volatile uint64_t*>(s_paging.scratch);
    const auto* from = reinterpret_cast<const volatile uint64_t*>(buf);
    for (size_t i = 0; i < PAGE_SIZE / sizeof(uint64_t); ++i) {
      w[i] = from[i];
    }
    SlotInfo& info = s_paging.slots[slot_of(j.va)];
#if defined(SIGNETOS_SWAP_HASH)
    if (!digest_matches(info, w)) {
      s_paging.digest_errors += 1;
      return;
    }
#endif
    const auto* c = reinterpret_cast<const volatile Capability*>(w);
    for (size_t i = 0; i < CAPS_PER_PAGE; ++i) {
      if (has_tag(info, i) && is_revoked_locked(c[i])) {
        info.tags[i / 8] = static_cast<uint8_t>(info.tags[i / 8] & ~(1u << (i % 8)));
      }
    }
    s_paging.checks += 1;
  }
  s_paging.job = Job{};
}

// `blk`'s page for a transfer (THE PAGER): writable, 4 KiB from its address,
// aligned, below the pageable region, and resident.
bool is_pager_buffer_locked(Capability c) {
  if (!capability_is_valid(c) || __builtin_cheri_type_get(c) != 0) {
    return false;
  }
  const uint64_t base = capability_get_base(c);
  const uint64_t addr = capability_get_address(c);
  return capability_has_perms(c, perms::Load | perms::Store) &&
         addr % PAGE_SIZE == 0 && addr >= base &&
         base + capability_get_length(c) - addr >= PAGE_SIZE &&
         addr >= DYNAMIC_BASE && addr + PAGE_SIZE <= pinned_pool_top() &&
         pte_resident(find_leaf(addr).entry);
}

// Places the pageable region: `slots` pages from a gigabyte boundary, up to
// the revocation bitmap, never leaving the pool below less room than there is
// RAM, and only where nothing is in use yet.
Status place_region_locked(size_t slots) {
  constexpr uint64_t POOL = BITMAP_BASE - DYNAMIC_BASE;
  const uint64_t ram =
      (frame::ram_bytes() + GIGAPAGE_SIZE - 1) & ~(GIGAPAGE_SIZE - 1);
  const uint64_t span =
      ((slots * PAGE_SIZE) + GIGAPAGE_SIZE - 1) & ~(GIGAPAGE_SIZE - 1);
  if (ram >= POOL || span > POOL - ram) {
    return Status::InvalidSize;
  }
  const uint64_t base = BITMAP_BASE - span;
  if (s_region_base != 0) {
    return Status::Busy;
  }
  for (size_t g = (base - DYNAMIC_BASE) / GIGAPAGE_SIZE; g < POOL_1G; ++g) {
    if (s_used_1g[g] != 0) {
      return Status::Busy;
    }
  }
  s_region_pages = slots;
  s_paging.check_next = slots;
  __atomic_store_n(&s_region_base, base, __ATOMIC_RELEASE);
  return Status::Ok;
}

// The lowest run of `pages` free addresses in the pageable region, starting
// on a multiple of `align`, or 0.
uint64_t find_pageable_room_locked(size_t pages, uint64_t align) {
  const uint64_t base = s_region_base;
  const uint64_t top = base + (s_region_pages * PAGE_SIZE);
  const uint64_t need = pages * PAGE_SIZE;
  for (uint64_t start = base; need <= top - base && start <= top - need;) {
    // The first page in use in [start, start + need), skipping whole empty
    // 2MB regions.
    uint64_t va = start;
    while (va < start + need) {
      const size_t m = (va - DYNAMIC_BASE) / MEGAPAGE_SIZE;
      if (va % MEGAPAGE_SIZE == 0 && s_used_2m[m] == 0) {
        va += MEGAPAGE_SIZE;
        continue;
      }
      const uint64_t* slot = leaf_slot(va, false);
      if (slot != nullptr && pte_in_use(*slot)) {
        break;
      }
      va += PAGE_SIZE;
    }
    if (va >= start + need) {
      return start;
    }
    start = (va + PAGE_SIZE + align - 1) & ~(align - 1);
  }
  return 0;
}

// True if every page of `[va, va + len)` is resident.
bool resident_locked(uint64_t va, size_t len) {
  if (va + len < va) {
    return false;
  }
  for (uint64_t cur = va & ~(PAGE_SIZE - 1); cur < va + len;) {
    const Leaf leaf = find_leaf(cur);
    if (!pte_resident(leaf.entry)) {
      return false;
    }
    cur = next_after(cur, leaf);
  }
  return true;
}

}  // namespace

uint64_t translate(uint64_t va) {
  const Leaf leaf = find_leaf(va);
  if (!pte_resident(leaf.entry)) {
    return 0;
  }
  // The entry names the start of a page; the low bits of the address say how
  // far into it we are. page_size - 1 is the mask for those low bits, and it
  // is wider for a megapage or gigapage than for a 4KB page.
  return pte_addr(leaf.entry) + (va & (leaf.page_size - 1));
}

bool range_has_quarantined(uint64_t va, size_t len) {
  if (!is_initialized() || len == 0 || quarantined_pages() == 0) {
    return false;
  }
  // Clip to the dynamic space: nothing outside it is ever quarantined.
  uint64_t end = (va + len < va) ? DYNAMIC_TOP : va + len;
  if (end > DYNAMIC_TOP) {
    end = DYNAMIC_TOP;
  }
  for (uint64_t cur = (va < DYNAMIC_BASE) ? DYNAMIC_BASE : va; cur < end;) {
    const Leaf leaf = find_leaf(cur);
    if ((leaf.entry & pte::Quarantined) != 0) {
      return true;
    }
    cur = next_after(cur, leaf);  // the next page, or past the hole
  }
  return false;
}

uint64_t leaf_flags(uint64_t va) {
  // An unmapped address gives entry 0, which masks to 0: no flags.
  return find_leaf(va).entry & PTE_FLAG_MASK;
}

Capability alloc_pages(size_t pages, bool revocable) {
  // The bound keeps `bytes` from wrapping; nothing bigger fits the pool.
  if (!is_initialized() || pages == 0 || pages > POOL_PAGES) {
    return nullptr;
  }

  const size_t bytes = pages * PAGE_SIZE;
  const uint64_t flags = pte::Permissive | (revocable ? pte::Revocable : 0);

  // Addresses, the frames to back them, the mapping joining the two, and for
  // a revocable allocation its bitmap pages (REVOCATION BITMAP), each undone
  // if a later one fails. All under one hold of `s_lock`: addresses are in
  // use exactly while they are mapped, so the room found must be mapped
  // before anyone else looks. Running out is not a reason to sweep
  // (revoke.hpp, WHEN A SWEEP RUNS).
  Capability c = nullptr;
  {
    Locked hold(s_lock);
    const uint64_t va =
        find_room_locked(pages, revocable ? BITMAP_SPAN : PAGE_SIZE);
    if (va == 0) {
      return nullptr;
    }

    // Narrow the dynamic authority to exactly this object, so the holder
    // cannot reach a neighbouring allocation by walking off the end.
    // TODO what is s_dynamic and which perms does it have?
    c = dynamic_view(va, bytes);
    if (!capability_is_valid(c) ||
        (capability_get_perms(c) & (perms::Seal | perms::Unseal)) != 0) {
      return nullptr;
    }

    const uint64_t pa = frame::alloc(pages);
    if (pa == 0) {
      return nullptr;
    }
    if (!map_locked(va, pa, pages, flags)) {
      frame::free(pa, pages);
      return nullptr;
    }
    if (revocable && !map_bitmap_locked(va, pages)) {
      unmap_locked(va, pages);
      frame::free(pa, pages);
      return nullptr;
    }
  }

  // Frames are handed out dirty, and this is the first moment the memory is
  // reachable at all, so it is also the first chance to clear whatever the
  // previous owner left in it. Zeroing runs outside `s_lock` and `frame::s_lock`
  // so other harts are not blocked while large allocations are cleared.
  volatile uint8_t* z = reinterpret_cast<volatile uint8_t*>(c);
  for (size_t i = 0; i < bytes; ++i) {
    z[i] = 0;
  }

  __atomic_fetch_add(&s_alloc_pages, pages, __ATOMIC_RELAXED);
  return c;
}

uint64_t free_pages(Capability object) {
  if (!is_initialized() || !capability_is_valid(object)) {
    return 0;
  }

  // What to free is read from the capability itself: where it starts and how
  // long it is. Both were set by alloc_pages and cannot have been widened.
  const uint64_t va = capability_get_base(object);
  const uint64_t bytes = capability_get_length(object);
  if (bytes == 0 || (va % PAGE_SIZE) != 0) {
    return 0;
  }

  // Round up, so a capability covering part of a page still frees that page.
  const size_t pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
  if (!range_is_mappable(va, pages)) {
    return 0;
  }

  Locked hold(s_lock);

  // Every page must be in use (a pageable one may have no frame), not Held,
  // and not already quarantined. All of them are checked before any is
  // changed, so a refused free leaves the range exactly as it was. This is
  // also what refuses freeing the same range twice.
  for (size_t i = 0; i < pages; ++i) {
    const uint64_t* slot = leaf_slot(va + (i * PAGE_SIZE), false);
    if (slot == nullptr || !pte_in_use(*slot) ||
        pte_kind(*slot) == pte::KindHeld || (*slot & pte::Quarantined)) {
      return 0;
    }
  }

  // Quarantine, do NOT unmap or release the virtual address range yet.
  // Capabilities to this range may still be tagged, and until the revocation
  // sweep clears them they must keep reaching the same data (the accessibility
  // invariant). Once `revoke::sweep()` clears all
  // tags pointing into quarantined memory, `reclaim_quarantined()` unmaps the
  // pages and frees their physical frames, and the addresses are free for
  // reuse once unmapped. A revocable range's bitmap pages go with it.
  bool revocable = false;
  for (size_t i = 0; i < pages; ++i) {
    uint64_t* slot = leaf_slot(va + (i * PAGE_SIZE), false);
    *slot |= pte::Quarantined;
    revocable = (*slot & pte::Revocable) != 0;
  }

  __atomic_fetch_sub(&s_alloc_pages, pages, __ATOMIC_RELAXED);
  __atomic_fetch_add(&s_quarantined_pages, pages, __ATOMIC_RELAXED);
  return (pages + (revocable ? bitmap_pages(pages) : 0)) * PAGE_SIZE;
}

// Both passes below walk the pool one page at a time, skipping every 2MB
// region with nothing mapped in it (next_used). The page tables answer one
// question only: is this page mapped, and if not, how far to the next place
// that might be. Pages are read at their own addresses through `s_dynamic`.

Capability next_live_page(uint64_t* cursor) {
  if (!is_initialized()) {
    return nullptr;
  }
  Locked hold(s_lock);
  for (uint64_t va = next_used(*cursor < DYNAMIC_BASE ? DYNAMIC_BASE : *cursor);
       va < BITMAP_BASE;) {
    const Leaf leaf = find_leaf(va);
    if ((leaf.entry & (pte::Valid | pte::Quarantined)) == pte::Valid) {
      *cursor = va + PAGE_SIZE;
      return dynamic_view(va, PAGE_SIZE);
    }
    va = next_used(next_after(va, leaf));
  }
  *cursor = BITMAP_BASE;
  return nullptr;
}

void reclaim_quarantined(bool hold) {
  if (!is_initialized() || quarantined_pages() == 0) {
    return;
  }
  Locked lock(s_lock);
  if (s_quarantined_pages == 0) {
    return;
  }
  for (uint64_t va = next_used(DYNAMIC_BASE); va < BITMAP_BASE;) {
    const Leaf leaf = find_leaf(va);
    uint64_t* slot =
        (leaf.entry & pte::Quarantined) ? leaf_slot(va, false) : nullptr;
    if (slot != nullptr) {
      // Its frame, if it has one (a pageable page may not), goes back to the
      // frame allocator.
      if (pte_resident(leaf.entry)) {
        frame::free(pte_addr(leaf.entry), 1);
      }
      if (hold) {
        *slot = pte::KindHeld;  // unmapped, but not free until release_held
        s_held_pages += 1;
      } else {
        *slot = 0;  // unmapped: nothing can reach it any more
        count_page(va, -1);  // and so free for reuse
      }
      __atomic_fetch_sub(&s_quarantined_pages, 1, __ATOMIC_RELAXED);
      // The bitmap page for this span goes with the page that starts it.
      if ((leaf.entry & pte::Revocable) != 0 && va % BITMAP_SPAN == 0) {
        uint64_t* bit_page = leaf_slot(bitmap_of(va), false);
        frame::free(pte_addr(*bit_page), 1);
        *bit_page = 0;
      }
    }
    va = next_used(next_after(va, leaf));
  }
  __asm__ volatile("sfence.vma zero, zero" ::: "memory");
}

// --- Paging (vm.hpp, PAGING) -------------------------------------------------

Status setup_paging(size_t slots) {
  if (!is_initialized() || !capability_is_valid(s_retag_root)) {
    return Status::NotInitialized;
  }
  if (slots == 0 || slots > (BITMAP_BASE - DYNAMIC_BASE) / PAGE_SIZE) {
    return Status::InvalidSize;
  }
  // The kernel's memory for paging, zeroed, from the pool below the region:
  // a scratch page, a bit per slot for the clock, and a SlotInfo per slot.
  const size_t bit_bytes = ((slots + 63) / 64) * sizeof(uint64_t);
  const size_t bytes = PAGE_SIZE + bit_bytes + (slots * sizeof(SlotInfo));
  const Capability mem = alloc_pages((bytes + PAGE_SIZE - 1) / PAGE_SIZE);
  if (!capability_is_valid(mem)) {
    return Status::NoMemory;
  }
  Status st;
  {
    Locked hold(s_lock);
    auto* p = reinterpret_cast<uint8_t*>(mem);
    s_paging.scratch = capability_set_bounds(mem, PAGE_SIZE);
    s_paging.resident = reinterpret_cast<uint64_t*>(p + PAGE_SIZE);
    s_paging.slots = reinterpret_cast<SlotInfo*>(p + PAGE_SIZE + bit_bytes);
    st = place_region_locked(slots);
  }
  if (st != Status::Ok) {
    free_pages(mem);
  }
  return st;
}

bool paging_on() {
  return __atomic_load_n(&s_region_base, __ATOMIC_ACQUIRE) != 0;
}

size_t round_up_pageable_pages(size_t pages) {
  const size_t region_pages = paging_on() ? s_region_pages : 0;
  if (pages == 0 || pages > region_pages) {
    return 0;
  }
  const size_t rounded =
      __builtin_cheri_round_representable_length(pages * PAGE_SIZE) /
      PAGE_SIZE;
  return rounded <= region_pages ? rounded : 0;
}

Capability alloc_pageable_pages(size_t pages, bool revocable) {
  if (pages == 0 || round_up_pageable_pages(pages) != pages) {
    return nullptr;
  }
  // The capability covers exactly the allocation, never a neighbour: the
  // length is representable (above), and the base is aligned as CHERI needs
  // for it -- and, if revocable, on a BITMAP_SPAN boundary.
  const uint64_t bytes = pages * PAGE_SIZE;
  uint64_t align = ~__builtin_cheri_representable_alignment_mask(bytes) + 1;
  const uint64_t least = revocable ? BITMAP_SPAN : PAGE_SIZE;
  align = align < least ? least : align;
  Capability c = nullptr;
  {
    Locked hold(s_lock);
    const uint64_t va = find_pageable_room_locked(pages, align);
    c = va != 0 ? dynamic_view(va, bytes) : nullptr;
    if (!capability_is_valid(c) || capability_get_base(c) != va ||
        capability_get_length(c) != bytes ||
        (capability_get_perms(c) & (perms::Seal | perms::Unseal)) != 0) {
      return nullptr;
    }
    // Fresh: in use, no frame. Nothing to flush: a free address has no
    // translation cached anywhere.
    auto undo = [&](size_t set) {
      for (size_t j = 0; j < set; ++j) {
        *leaf_slot(va + (j * PAGE_SIZE), false) = 0;
        count_page(va + (j * PAGE_SIZE), -1);
      }
    };
    const uint64_t fresh = pte::KindFresh | (revocable ? pte::Revocable : 0);
    for (size_t i = 0; i < pages; ++i) {
      uint64_t* slot = leaf_slot(va + (i * PAGE_SIZE), true);
      if (slot == nullptr) {
        undo(i);  // out of frames for a table
        return nullptr;
      }
      *slot = fresh;
      count_page(va + (i * PAGE_SIZE), +1);
    }
    if (revocable && !map_bitmap_locked(va, pages)) {
      undo(pages);
      return nullptr;
    }
  }
  __atomic_fetch_add(&s_alloc_pages, pages, __ATOMIC_RELAXED);
  return c;
}

Fault fault(uint64_t addr, bool can_wait, uint64_t tid) {
  if (!paging_on()) {
    return Fault::No;
  }
  // Only a fault in the region is paging's: no allocation runs into it from
  // below, so an access that starts outside it is an ordinary fault, even
  // if the next page is pageable.
  if (!is_pageable_address(addr & ~(PAGE_SIZE - 1))) {
    return Fault::No;
  }
  Locked hold(s_lock);
  // The access may run onto the next page: either may be the one.
  const uint64_t touched[] = {addr, addr + sizeof(Capability) - 1};
  for (const uint64_t a : touched) {
    const uint64_t va = a & ~(PAGE_SIZE - 1);
    if (!is_pageable_address(va)) {
      continue;  // past the region's end: nothing allocated runs into it
    }
    uint64_t* slot = leaf_slot(va, false);
    const uint64_t e = slot != nullptr ? *slot : 0;
    const uint64_t kind = pte_kind(e);
    if (pte_resident(e)) {
      continue;  // in already
    }
    if (kind != pte::KindFresh && kind != pte::KindSwapped) {
      return Fault::No;  // not in use: an ordinary fault
    }
    if (kind == pte::KindFresh && room() > 0) {
      const uint64_t pa = frame::alloc(1);
      if (pa != 0) {
        bring_in_locked(va, slot, pa, nullptr);
        return Fault::Retry;
      }
    }
    if (!can_wait) {
      return Fault::No;
    }
    add_waiter_locked(va, tid);
    return Fault::Wait;
  }
  // Every page it touches is in by now: run it again.
  return Fault::Retry;
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
  return s_paging.check_next < s_region_pages;
}

bool checks_pending() {
  Locked hold(s_lock);
  return paging_on() && (s_paging.check_next < s_region_pages ||
                         s_paging.job.op == JOB_CHECK);
}

void release_held() {
  Locked hold(s_lock);
  for (uint64_t va = next_used(DYNAMIC_BASE);
       s_held_pages != 0 && va < BITMAP_BASE;) {
    const Leaf leaf = find_leaf(va);
    if (pte_kind(leaf.entry) == pte::KindHeld) {
      *leaf_slot(va, false) = 0;  // not mapped since its reclaim's flush
      count_page(va, -1);
      s_held_pages -= 1;
    }
    va = next_used(next_after(va, leaf));
  }
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
  const bool usable = paging_on() && capability_is_valid(cap) &&
                      __builtin_cheri_type_get(cap) == 0;
  const uint64_t addr = usable ? capability_get_address(cap) : 0;
  const uint64_t top =
      usable ? capability_get_base(cap) + capability_get_length(cap) : 0;
  if (op == PAGE_TEST_STATS && usable && capability_has_perms(cap, perms::Store) &&
      addr <= top && top - addr >= sizeof(PagingStats)) {
    PagingStats st{};
    {
      Locked hold(s_lock);
      st.slots = s_region_pages;
      st.free_frames = frame::free_pages();
      st.reserve = frame::pool_pages() / 64;
      st.reads = s_paging.reads;
      st.writes = s_paging.writes;
      st.checks = s_paging.checks;
      st.digest_errors = s_paging.digest_errors;
      st.evicting = ((s_paging.evict_end - s_paging.evict_next) / PAGE_SIZE) +
                    (s_paging.job.op == JOB_OUT ? 1 : 0);
    }
    const ResidentHold resident(addr, sizeof(PagingStats));  // KERNEL ACCESS
    if (!resident.ok()) {
      return ~0ULL;
    }
    *reinterpret_cast<PagingStats*>(cap) = st;
    return 0;
  }
  if (op == PAGE_TEST_EVICT && usable && addr < top &&
      is_pageable_address(addr) && is_pageable_address(top - 1)) {
    Locked hold(s_lock);
    s_paging.evict_next = addr & ~(PAGE_SIZE - 1);
    s_paging.evict_end = (top + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    return (s_paging.evict_end - s_paging.evict_next) / PAGE_SIZE;
  }
  return ~0ULL;
}
#else
uint64_t page_test(uint64_t, Capability) { return ~0ULL; }  // not built in
#endif

Capability bitmap_view() {
  return dynamic_view(BITMAP_BASE, DYNAMIC_TOP - BITMAP_BASE);
}

size_t table_pages() {
  return __atomic_load_n(&s_table_pages, __ATOMIC_RELAXED);
}
size_t allocated_pages() {
  return __atomic_load_n(&s_alloc_pages, __ATOMIC_RELAXED);
}
size_t quarantined_pages() {
  return __atomic_load_n(&s_quarantined_pages, __ATOMIC_RELAXED);
}

} // namespace signetos::vm
