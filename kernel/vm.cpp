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

#include <signetos/debug/report.hpp>
#include <signetos/frame.hpp>
#include <signetos/lock.hpp>
#include <signetos/hw/platform.hpp>
#include <signetos/revoke.hpp>
#include <signetos/sealing.hpp>
#include <signetos/vm.hpp>
#include <signetos/vm_pages.hpp>

// sweep.S: flips `bit` in every valid page table entry of `count` runs
// (pairs of words at `runs`: the address of a run's first entry in the
// direct map, which `direct` spans, and its length), then the hart's
// generation, then flushes the TLB.
extern "C" void __signetos_new_generation(signetos::Capability direct,
                                          const uint64_t* runs, size_t count,
                                          uint64_t bit);

namespace signetos::vm {

SpinLock s_lock;

namespace {

// 512 eight-byte entries fill one 4KB page exactly.
constexpr size_t ENTRIES = 512;

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

// The direct map's own L1 tables: where they start (physical) and how many
// entries they hold. `new_generation` rewrites them.
uint64_t s_direct_tables = 0;
size_t s_direct_entries = 0;

// Authority covering the whole dynamic address space, narrowed to one object at
// a time by alloc_pages and view. Never handed out.
Capability s_dynamic = nullptr;

// Authority covering the device gigabyte (root entry 0). `device_window`
// derives from it; the window `init` gets is this span minus `StoreLocal`.
Capability s_devices = nullptr;

// The pool alloc_pages hands addresses out of: the dynamic space below the
// revocation bitmap. The page tables are the only record of which of its
// addresses are in use: a page is in use exactly while its leaf entry is not
// zero (vm.hpp, PAGES).
//
// Walking the tables to find room would be slow, so each 2MB and each 1GB
// region of the pool keeps a count of its pages in use. A search skips any
// region without enough free pages, and the sweep skips regions with none in
// use. The arrays are sized by the address space (about 250KB), not by RAM or
// by how fragmented the pool gets.
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

// What the allocator keeps for paging, and only with it (vm.hpp, PAGES).
//
// A 2MB region with a page in use holds either pageable memory or memory
// that keeps its frames, never both: a bit per region says which. It is set
// as the first page of an empty region is reserved, and means nothing while
// the region is empty.
#if defined(SIGNETOS_PAGING)
uint64_t s_pageable_2m[(POOL_2M + 63) / 64];
size_t s_pageable_pages = 0;  // pages in use in regions of pageable memory
size_t s_held_pages = 0;      // reclaimed, Held until release_held

void reset_paging_state() {
  for (uint64_t& word : s_pageable_2m) {
    word = 0;
  }
  s_pageable_pages = 0;
  s_held_pages = 0;
}
bool region_is_pageable(size_t m) {
  return ((s_pageable_2m[m / 64] >> (m % 64)) & 1) != 0;
}
void set_region_pageable(size_t m, bool pageable) {
  const uint64_t bit = 1ULL << (m % 64);
  s_pageable_2m[m / 64] = pageable ? (s_pageable_2m[m / 64] | bit)
                                   : (s_pageable_2m[m / 64] & ~bit);
}
// Keeps `s_pageable_pages` in step with the page tables, as count_page does
// the region counts: region `m` is of its kind before the first +1, and
// until the last -1 (reserve_locked).
void count_pageable(size_t m, int delta) {
  if (region_is_pageable(m)) {
    s_pageable_pages = static_cast<size_t>(s_pageable_pages + delta);
  }
}
// Whether swap has a slot for each of `pages` more pageable pages (vm.hpp,
// PAGING, SWAP): it has none until paging is set up.
bool swap_has_room(size_t pages) {
  return s_pageable_pages + pages <= swap_slots();
}
#else
// Nothing is pageable, and there is no swap.
constexpr void reset_paging_state() {}
constexpr bool region_is_pageable(size_t) { return false; }
constexpr void set_region_pageable(size_t, bool) {}
constexpr void count_pageable(size_t, int) {}
constexpr bool swap_has_room(size_t) { return false; }
#endif

// Bits 9:0 of a PTE are flags and bits 53:10 the physical page number. The
// bits above that are the hardware's; the ones used here are pte::CapWrite
// and pte::CapGen.
constexpr uint64_t PTE_FLAG_MASK = 0x3FFULL;
constexpr uint64_t PTE_PPN_MASK = ((1ULL << 54) - 1) & ~PTE_FLAG_MASK;

// The hart's generation (vm.hpp, CHECKED PAGES): pte::CapGen or 0, always
// what `mstatus.UCRG` says. Changed by `new_generation` alone, under
// `s_lock`.
uint64_t s_generation = 0;

// Builds a page table entry pointing at the frame containing `pa`.
uint64_t pte_make(uint64_t pa, uint64_t flags) {
  // pa >> PAGE_SHIFT turns a byte address into a frame number, and << 10
  // puts that frame number where the hardware reads it, above the flag bits.
  // The mask drops anything a caller passed in that is not a flag.
  return ((pa >> PAGE_SHIFT) << 10) |
         (flags & (PTE_FLAG_MASK | pte::CapWrite | pte::CapGen));
}

// The physical address of whatever an entry points at: a frame of memory if the
// entry is a leaf, the next table down if it is not.
uint64_t pte_addr(uint64_t entry) {
  // Undoes pte_make: the mask keeps the frame number alone, >> 10 moves it
  // down to bit 0, << PAGE_SHIFT turns it back into a byte address.
  return ((entry & PTE_PPN_MASK) >> 10) << PAGE_SHIFT;
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

// Whether the range lies in the dynamic space, the only part of the address
// space whose mappings change after boot.
//
// The boot mappings (devices, kernel image, direct map) are excluded, or a
// caller could repoint the UART or unmap the running kernel.
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
  reset_paging_state();

  // Generation 0 (CHECKED PAGES): every entry written below has CapGen
  // clear, so the hart starts with UCRG (mstatus bit 61) clear too.
  s_generation = 0;
  __asm__ volatile("csrc mstatus, %0" ::"r"(MSTATUS_UCRG) : "memory");

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
    s_l1_kernel[l1_index(pa)] = pte_make(pa, pte::Permissive | pte::CapWrite);
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
    tables[(g * ENTRIES) + l1_index(va)] =
        pte_make(kbase + off, pte::KernelData | pte::CapWrite);
  }
  s_direct_top = direct_top;
  s_direct_tables = tables_pa;
  s_direct_entries = gbs * ENTRIES;
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
  count_pageable(m, delta);
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

// First index of `pages` consecutive free entries in the 2MB region at
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
    // Entry start + k is in use: no run that includes it can work, so try
    // the first aligned start past it.
    start = (start + k + step) / step * step;
  }
  return ENTRIES;
}

// The lowest run of `pages` free pages in the pool that starts on a multiple
// of `align` (a power of two, at least PAGE_SIZE), or 0 if there is none.
// The run is for pageable memory, or for memory that is not, and only takes
// from regions that are empty or hold the same (vm.hpp, PAGES).
//
// Up to 2MB is looked for inside one 2MB region: the counts rule out regions
// without enough free pages, and only a region that might have room has its
// L0 table read. Bigger requests take whole empty 2MB regions. Neither looks
// for a run that straddles a 2MB boundary without filling the regions it
// touches, which costs some fragmentation and keeps the search short.
uint64_t find_room_locked(size_t pages, uint64_t align, bool pageable) {
  if (pages <= PAGES_PER_2M && align <= MEGAPAGE_SIZE) {
    for (size_t g = 0; g < POOL_1G; ++g) {
      if (PAGES_PER_2M * REGIONS_PER_1G - s_used_1g[g] < pages) {
        continue;
      }
      for (size_t m = g * REGIONS_PER_1G; m < (g + 1) * REGIONS_PER_1G; ++m) {
        if (PAGES_PER_2M - s_used_2m[m] < pages ||
            (s_used_2m[m] != 0 && region_is_pageable(m) != pageable)) {
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

  const uint64_t bytes = pages * PAGE_SIZE;
  const uint64_t step = align > MEGAPAGE_SIZE ? align : MEGAPAGE_SIZE;
  for (uint64_t va = (DYNAMIC_BASE + step - 1) & ~(step - 1);
       va < BITMAP_BASE && bytes <= BITMAP_BASE - va;) {
    // The first 2MB region of [va, va + bytes) with a page in use.
    uint64_t used = va;
    while (used < va + bytes &&
           s_used_2m[(used - DYNAMIC_BASE) / MEGAPAGE_SIZE] == 0) {
      used += MEGAPAGE_SIZE;
    }
    if (used >= va + bytes) {
      return va;
    }
    va = (used + MEGAPAGE_SIZE + step - 1) & ~(step - 1);
  }
  return 0;
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

// The `k`th bitmap page of the revocable range at `va`: its spans in order, a
// page of each bitmap for each (vm.hpp, REVOCATION BITMAP).
uint64_t bitmap_page(uint64_t va, size_t k) {
  return bitmap_of(va, k % 2) + ((k / 2) * PAGE_SIZE);
}

// Frees the first `count` bitmap pages of the revocable range at `va`, which
// nothing has seen. Caller holds `s_lock`.
void unmap_bitmap_locked(uint64_t va, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    uint64_t* slot = leaf_slot(bitmap_page(va, i), false);
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
    const uint64_t s = bitmap_page(va, i);
    // A bitmap page has one owner (vm.hpp, REVOCATION BITMAP), so its entry
    // is free; anything else is refused.
    uint64_t* slot = leaf_slot(s, true);
    const uint64_t pa =
        slot != nullptr && !pte_in_use(*slot) ? frame::alloc(1) : 0;
    if (pa == 0) {
      unmap_bitmap_locked(va, i);
      return false;
    }
    *slot = pte_make(pa, pte::KernelData);
    flush(s);
    zero_page(s);
  }
  return true;
}

// PAGES (vm.hpp). A pool page's entry is written by `reserve_locked` and
// `unreserve_locked`, by the two moves below them, and as the page is freed
// and reclaimed (free_pages, reclaim_quarantined, release_held); nowhere
// else.

// Fresh or resident -> free, for the `pages` pages at `va`, which nothing has
// seen yet: undoes `reserve_locked`, and gives back any frame a page has been
// given since. If `revocable`, the range's bitmap pages go too.
void unreserve_locked(uint64_t va, size_t pages, bool revocable) {
  for (size_t i = 0; i < pages; ++i) {
    const uint64_t page = va + (i * PAGE_SIZE);
    uint64_t* slot = leaf_slot(page, false);
    if (pte_resident(*slot)) {
      frame::free(pte_addr(*slot), 1);
    }
    *slot = 0;
    flush(page);
    count_page(page, -1);
  }
  if (revocable) {
    unmap_bitmap_locked(va, bitmap_pages(pages));
  }
}

// Free -> Fresh: puts the `pages` free pages at `va` in use, with no frame,
// and gives a revocable range its bitmap pages. All or nothing; it never
// writes an entry that is in use, and never puts pageable memory in a region
// with memory that is not, or the other way round: an empty region becomes
// whichever this is.
bool reserve_locked(uint64_t va, size_t pages, bool revocable, bool pageable) {
  const uint64_t fresh = pte::KindFresh | (revocable ? pte::Revocable : 0);
  size_t done = 0;
  for (; done < pages; ++done) {
    const uint64_t page = va + (done * PAGE_SIZE);
    const size_t m = (page - DYNAMIC_BASE) / MEGAPAGE_SIZE;
    if (s_used_2m[m] != 0 && region_is_pageable(m) != pageable) {
      break;  // the region holds the other kind
    }
    uint64_t* slot = leaf_slot(page, true);
    if (slot == nullptr || pte_in_use(*slot)) {
      break;  // no frame for a page table, or not free after all
    }
    if (s_used_2m[m] == 0) {
      set_region_pageable(m, pageable);
    }
    *slot = fresh;
    count_page(page, +1);
  }
  if (done == pages && (!revocable || map_bitmap_locked(va, pages))) {
    return true;
  }
  // No bitmap page is mapped: map_bitmap_locked is all or nothing.
  unreserve_locked(va, done, false);
  return false;
}

// Fresh -> resident, for each of the `pages` pages at `va`: every page gets
// a frame of RAM. Any free frame will do, unless `one_run`: then they are the
// frames of one run, in order. False if RAM has not got them; a page that
// got its frame before that keeps it until `unreserve_locked`.
bool back_locked(uint64_t va, size_t pages, bool one_run) {
  if (one_run) {
    const uint64_t pa = frame::alloc(pages);
    if (pa == 0) {
      return false;
    }
    for (size_t i = 0; i < pages; ++i) {
      give_frame_locked(va + (i * PAGE_SIZE), pa + (i * PAGE_SIZE));
    }
    return true;
  }
  for (size_t i = 0; i < pages; ++i) {
    const uint64_t pa = frame::alloc(1);
    if (pa == 0) {
      return false;
    }
    give_frame_locked(va + (i * PAGE_SIZE), pa);
  }
  return true;
}

}  // namespace

// THE TWO MOVES (vm.hpp, PAGES): declared in vm_pages.hpp. A move on a page
// in the wrong state is a kernel bug, and halts.

// Fresh or Swapped -> resident, on a frame of RAM.
void give_frame_locked(uint64_t va, uint64_t pa) {
  uint64_t* slot = leaf_slot(va, false);
  const uint64_t kind = slot != nullptr ? pte_kind(*slot) : 0;
  if (kind != pte::KindFresh && kind != pte::KindSwapped) {
    debug::panic("vm: a frame given to a page that is not waiting for one");
  }
  if (pa % PAGE_SIZE != 0 || !range_is_ram(pa, 1)) {
    debug::panic("vm: a page given something that is not a frame of RAM");
  }
  // CHECKED PAGES: what the caller puts on the frame is zeroes or checked,
  // so the page is of the hart's generation. A quarantined page keeps the
  // one it was freed in.
  const uint64_t old = *slot;
  const uint64_t gen =
      (old & pte::Quarantined) != 0 ? (old & pte::CapGen) : s_generation;
  *slot = pte_make(pa, pte::Permissive | pte::CapWrite | gen |
                           (old & (pte::Quarantined | pte::Revocable)));
  flush(va);
}

#if defined(SIGNETOS_PAGING)

bool is_pageable_locked(uint64_t va) {
  if (va < DYNAMIC_BASE || va >= BITMAP_BASE) {
    return false;
  }
  const size_t m = (va - DYNAMIC_BASE) / MEGAPAGE_SIZE;
  return s_used_2m[m] != 0 && region_is_pageable(m);
}

// Resident -> Swapped, for a page of pageable memory. Every thread runs on
// this hart (vm.hpp, PAGING, ONE HART), so the local flush is all it takes.
uint64_t take_frame_locked(uint64_t va, uint64_t slot) {
  uint64_t* entry = is_pageable_locked(va) ? leaf_slot(va, false) : nullptr;
  if (entry == nullptr || !pte_resident(*entry)) {
    debug::panic("vm: a frame taken from a page that may not lose one");
  }
  const uint64_t e = *entry;
  *entry = (slot << pte::SlotShift) | pte::KindSwapped |
           (e & (pte::Quarantined | pte::Revocable | pte::CapGen));
  flush(va);
  return pte_addr(e);
}

uint64_t entry_locked(uint64_t va) {
  const uint64_t* slot = leaf_slot(va, false);
  return slot != nullptr ? *slot : 0;
}

uint64_t next_resident_pageable_locked(uint64_t from) {
  for (uint64_t va = next_used(from < DYNAMIC_BASE ? DYNAMIC_BASE : from);
       va < BITMAP_BASE;) {
    if (!is_pageable_locked(va)) {
      va = next_used((va & ~(MEGAPAGE_SIZE - 1)) + MEGAPAGE_SIZE);
      continue;
    }
    const Leaf leaf = find_leaf(va);
    if (pte_resident(leaf.entry)) {
      return va;
    }
    va = next_used(next_after(va, leaf));
  }
  return 0;
}

#endif

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

size_t round_up_pages(size_t pages) {
  // The bound keeps `pages * PAGE_SIZE` from wrapping; nothing bigger fits.
  if (pages == 0 || pages > POOL_PAGES) {
    return 0;
  }
  const size_t rounded =
      __builtin_cheri_round_representable_length(pages * PAGE_SIZE) / PAGE_SIZE;
  return rounded <= POOL_PAGES ? rounded : 0;
}

Capability alloc_pages(size_t pages, bool revocable, Backing backing) {
  if (!is_initialized() || pages == 0 || round_up_pages(pages) != pages) {
    return nullptr;
  }
  // Pageable says the memory may be paged, not that it must be: with paging
  // off it gets its frames now, like any other (Backing::Frames).
  const bool pageable = backing == Backing::Pageable && paging_on();

  // The capability covers exactly the allocation, never a neighbour: the
  // length is representable (above), and the base is aligned as CHERI needs
  // for it -- and, if revocable, on a BITMAP_SPAN boundary.
  const size_t bytes = pages * PAGE_SIZE;
  uint64_t align = ~__builtin_cheri_representable_alignment_mask(bytes) + 1;
  const uint64_t least = revocable ? BITMAP_SPAN : PAGE_SIZE;
  align = align < least ? least : align;

  // Addresses, and unless the memory is pageable the frames to back them,
  // each undone if a later step fails. All under one hold of `s_lock`: the
  // room found must be reserved before anyone else looks. Running out is not
  // a reason to sweep (revoke.hpp, A SWEEP).
  Capability c = nullptr;
  {
    Locked hold(s_lock);
    // Every pageable page in use has a slot of swap to go to (PAGING, SWAP):
    // there are none, and so no pageable memory, unless paging is on.
    if (pageable && !swap_has_room(pages)) {
      return nullptr;
    }
    // Any other memory needs a frame for every page now. With fewer free
    // than that it is refused here, before addresses are reserved and page
    // tables made for it.
    if (!pageable && frame::free_pages() < pages) {
      return nullptr;
    }
    const uint64_t va = find_room_locked(pages, align, pageable);
    if (va == 0) {
      return nullptr;
    }

    // Narrow the dynamic authority to exactly this object, so the holder
    // cannot reach a neighbouring allocation by walking off the end.
    // TODO what is s_dynamic and which perms does it have?
    c = dynamic_view(va, bytes);
    if (!capability_is_valid(c) || capability_get_base(c) != va ||
        capability_get_length(c) != bytes ||
        (capability_get_perms(c) & (perms::Seal | perms::Unseal)) != 0) {
      return nullptr;
    }

    if (!reserve_locked(va, pages, revocable, pageable)) {
      return nullptr;
    }
    // Pageable pages stay Fresh: each gets a frame when it is touched
    // (PAGING). The rest get theirs now, and keep them. The page tables just
    // made took frames too, so there may not be enough after all.
    if (!pageable && !back_locked(va, pages, backing == Backing::OneRun)) {
      unreserve_locked(va, pages, revocable);
      return nullptr;
    }
  }

  // Frames are handed out dirty, and this is the first moment the memory is
  // reachable at all, so it is also the first chance to clear whatever the
  // previous owner left in it. Zeroing runs outside `s_lock` and `frame::s_lock`
  // so other harts are not blocked while large allocations are cleared. A
  // pageable page is zeroed as it gets its frame.
  if (!pageable) {
    volatile uint8_t* z = reinterpret_cast<volatile uint8_t*>(c);
    for (size_t i = 0; i < bytes; ++i) {
      z[i] = 0;
    }
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

  // A stale page is checked before it is quarantined (below). Done here,
  // the way the kernel checks any page (revoke.hpp, KERNEL LOADS), the scan
  // runs on the hart's own stack and not on the caller's: a thread can be
  // torn down on another thread's kernel stack (thread.cpp, `exit`, when an
  // interrupt handler ends), which has no room for it. Nothing can make a
  // page stale between here and the lock: that takes the start of a sweep,
  // and a sweep does not start while a hart is in the kernel.
  revoke::check(va, pages * PAGE_SIZE);

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
  // invariant). Once a sweep has cleared all
  // tags pointing into quarantined memory, `reclaim_quarantined()` unmaps the
  // pages and frees their physical frames, and the addresses are free for
  // reuse once unmapped. A revocable range's bitmap pages go with it.
  //
  // Each page is left carrying the generation it is freed in, which says
  // which sweep reclaims it; one that is stale is checked first, because
  // capabilities may go on being loaded from it until then (CHECKED PAGES).
  bool revocable = false;
  for (size_t i = 0; i < pages; ++i) {
    const uint64_t page = va + (i * PAGE_SIZE);
    uint64_t* slot = leaf_slot(page, false);
    if (pte_resident(*slot)) {
      check_page_locked(page);
      *slot |= pte::Quarantined;
    } else {
      *slot = (*slot & ~pte::CapGen) | s_generation | pte::Quarantined;
    }
    revocable = (*slot & pte::Revocable) != 0;
  }

  __atomic_fetch_sub(&s_alloc_pages, pages, __ATOMIC_RELAXED);
  __atomic_fetch_add(&s_quarantined_pages, pages, __ATOMIC_RELAXED);
  return (pages + (revocable ? bitmap_pages(pages) : 0)) * PAGE_SIZE;
}

// CHECKED PAGES (vm.hpp).

uint64_t generation() {
  return __atomic_load_n(&s_generation, __ATOMIC_ACQUIRE);
}

// Checks pool page `va` if it is stale: clears what is revoked in it, reading
// it through the direct map, where no load traps, and gives it the hart's
// generation. True if it did. Declared in vm_pages.hpp.
bool check_page_locked(uint64_t va) {
  if (va < DYNAMIC_BASE || va >= BITMAP_BASE) {
    return false;
  }
  va &= ~(PAGE_SIZE - 1);
  uint64_t* slot = leaf_slot(va, false);
  if (slot == nullptr) {
    return false;
  }
  const uint64_t e = *slot;
  if (!pte_resident(e) || (e & pte::Quarantined) != 0 ||
      (e & pte::CapGen) == s_generation) {
    return false;
  }
  revoke::scan(phys_view(pte_addr(e), PAGE_SIZE));
  *slot = e ^ pte::CapGen;
  flush(va);
  return true;
}

size_t check_pages(uint64_t va, size_t len) {
  if (!is_initialized() || len == 0) {
    return 0;
  }
  // Clipped to the pool: nothing outside it is ever stale.
  uint64_t end = va + len < va ? BITMAP_BASE : va + len;
  end = end > BITMAP_BASE ? BITMAP_BASE : end;
  uint64_t cur = (va < DYNAMIC_BASE ? DYNAMIC_BASE : va) & ~(PAGE_SIZE - 1);
  size_t checked = 0;
  Locked hold(s_lock);
  for (; cur < end; cur += PAGE_SIZE) {
    checked += check_page_locked(cur) ? 1 : 0;
  }
  return checked;
}

bool check_fault(uint64_t va) {
  if (!is_initialized() || va < DYNAMIC_BASE || va >= BITMAP_BASE) {
    return false;
  }
  va &= ~(PAGE_SIZE - 1);
  Locked hold(s_lock);
  if (check_page_locked(va)) {
    return true;
  }
  const uint64_t* slot = leaf_slot(va, false);
  if (slot == nullptr || !pte_resident(*slot) ||
      (*slot & pte::Quarantined) != 0 ||
      (*slot & pte::CapGen) != s_generation) {
    return false;
  }
  flush(va);
  return true;
}

bool is_stale(uint64_t va) {
  if (!is_initialized() || va < DYNAMIC_BASE || va >= BITMAP_BASE) {
    return false;
  }
  Locked hold(s_lock);
  const uint64_t* slot = leaf_slot(va & ~(PAGE_SIZE - 1), false);
  return slot != nullptr && pte_resident(*slot) &&
         (*slot & pte::Quarantined) == 0 &&
         (*slot & pte::CapGen) != s_generation;
}

// Walks the pool one page at a time, skipping every 2MB region with nothing
// mapped in it (next_used). It stops after `pages` checks, or after looking
// at LOOKS_PER_CHECK times as many entries: the caller's interrupts are
// masked, and both bound for how long.
bool check_some(uint64_t* cursor, size_t pages) {
  constexpr size_t LOOKS_PER_CHECK = 64;
  if (!is_initialized()) {
    return true;
  }
  Locked hold(s_lock);
  size_t looks = pages * LOOKS_PER_CHECK;
  uint64_t va = next_used(*cursor < DYNAMIC_BASE ? DYNAMIC_BASE : *cursor);
  while (va < BITMAP_BASE) {
    if (pages == 0 || looks == 0) {
      *cursor = va;
      return false;
    }
    const Leaf leaf = find_leaf(va);
    if (check_page_locked(va)) {
      pages -= 1;
    }
    looks -= 1;
    va = next_used(next_after(va, leaf));
  }
  *cursor = BITMAP_BASE;
  return true;
}


void new_generation(const uint64_t* keep, size_t count) {
  if (!is_initialized() || count > MAX_KEPT) {
    debug::panic("vm: a new generation that cannot be started");
  }
  Locked hold(s_lock);

  // Every entry that moves to the new generation with the hart, as runs of
  // entries addressed through the direct map (which maps all of RAM, the
  // kernel image's own table included): the kernel image, the direct map,
  // and the pages the caller keeps.
  struct Run {
    uint64_t at;     // the first entry, in the direct map
    uint64_t count;  // how many
  };
  // Not on the caller's stack, which is a slice of a thread's: under
  // `s_lock`.
  static Run runs[2 + MAX_KEPT];
  static uint64_t frames[MAX_KEPT];
  size_t n = 0;
  const uint64_t ram = kernel_base();
  runs[n++] = {DIRECT_BASE + (phys_of(&s_l1_kernel[l1_index(ram)]) - ram),
               KERNEL_SIZE / MEGAPAGE_SIZE};
  runs[n++] = {DIRECT_BASE + (s_direct_tables - ram), s_direct_entries};
  for (size_t i = 0; i < count; ++i) {
    const bool pool = keep[i] >= DYNAMIC_BASE && keep[i] < BITMAP_BASE &&
                      keep[i] % PAGE_SIZE == 0;
    uint64_t* slot = pool ? leaf_slot(keep[i], false) : nullptr;
    if (slot == nullptr || !pte_resident(*slot) ||
        (*slot & pte::Quarantined) != 0 ||
        (*slot & pte::CapGen) != s_generation) {
      debug::panic("vm: a page kept across generations is not a checked page");
    }
    runs[n++] = {capability_get_address(reinterpret_cast<Capability>(slot)), 1};
    frames[i] = pte_addr(*slot);
  }

  // One step as far as any capability load can tell (sweep.S): between the
  // first entry rewritten and the hart's own bit, nothing loads one.
  __signetos_new_generation(s_direct, reinterpret_cast<const uint64_t*>(runs),
                            n, pte::CapGen);
  __atomic_store_n(&s_generation, s_generation ^ pte::CapGen, __ATOMIC_RELEASE);

  // The kept pages were given the new generation unchecked: check them now,
  // before the caller loads anything it may hand on.
  for (size_t i = 0; i < count; ++i) {
    revoke::scan(phys_view(frames[i], PAGE_SIZE));
  }
}

void reclaim_quarantined() {
  if (!is_initialized() || quarantined_pages() == 0) {
    return;
  }
  Locked lock(s_lock);
  if (s_quarantined_pages == 0) {
    return;
  }
  for (uint64_t va = next_used(DYNAMIC_BASE); va < BITMAP_BASE;) {
    const Leaf leaf = find_leaf(va);
    // Freed before this generation began (CHECKED PAGES): one freed since
    // carries the hart's generation, and is the next sweep's.
    const bool old = (leaf.entry & pte::Quarantined) != 0 &&
                     (leaf.entry & pte::CapGen) != s_generation;
    uint64_t* slot = old ? leaf_slot(va, false) : nullptr;
    if (slot != nullptr) {
      // Its frame, if it has one (a pageable page may not), goes back to the
      // frame allocator; if it is in swap instead, its slot is free.
      if (pte_resident(leaf.entry)) {
        frame::free(pte_addr(leaf.entry), 1);
      } else if (pte_kind(leaf.entry) == pte::KindSwapped) {
        slot_reclaimed_locked(pte_slot(leaf.entry));
      }
#if defined(SIGNETOS_PAGING)
      *slot = pte::KindHeld;  // unmapped, but not free until release_held
      s_held_pages += 1;
#else
      *slot = 0;  // unmapped: nothing can reach it any more
      count_page(va, -1);  // and so free for reuse
#endif
      __atomic_fetch_sub(&s_quarantined_pages, 1, __ATOMIC_RELAXED);
      // The bitmap pages for this span go with the page that starts it.
      if ((leaf.entry & pte::Revocable) != 0 && va % BITMAP_SPAN == 0) {
        for (unsigned which = 0; which < 2; ++which) {
          uint64_t* bit_page = leaf_slot(bitmap_of(va, which), false);
          frame::free(pte_addr(*bit_page), 1);
          *bit_page = 0;
        }
      }
    }
    va = next_used(next_after(va, leaf));
  }
  __asm__ volatile("sfence.vma zero, zero" ::: "memory");
}

#if defined(SIGNETOS_PAGING)
// Held -> free: the addresses can be handed out again.
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
