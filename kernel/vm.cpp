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
#include <signetos/revoke.hpp>
#include <signetos/vm.hpp>

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
constexpr size_t POOL_2M = (SHADOW_BASE - DYNAMIC_BASE) / MEGAPAGE_SIZE;
constexpr size_t POOL_1G = (SHADOW_BASE - DYNAMIC_BASE) / GIGAPAGE_SIZE;
constexpr size_t POOL_PAGES = POOL_2M * PAGES_PER_2M;
static_assert(DYNAMIC_BASE % GIGAPAGE_SIZE == 0 &&
              SHADOW_BASE % GIGAPAGE_SIZE == 0);
uint16_t s_used_2m[POOL_2M];
uint32_t s_used_1g[POOL_1G];

size_t s_table_pages = 0;        // frames currently held as page tables
size_t s_alloc_pages = 0;        // pages currently handed out by alloc_pages
size_t s_quarantined_pages = 0;  // pages freed, still mapped, awaiting a sweep

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
  return {(l0 & pte::Valid) ? l0 : 0, PAGE_SIZE};
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
// (at or above SHADOW_BASE) are not in the pool and are not counted.
void count_page(uint64_t va, int delta) {
  if (va < DYNAMIC_BASE || va >= SHADOW_BASE) {
    return;
  }
  const size_t m = (va - DYNAMIC_BASE) / MEGAPAGE_SIZE;
  s_used_2m[m] = static_cast<uint16_t>(s_used_2m[m] + delta);
  s_used_1g[m / REGIONS_PER_1G] =
      static_cast<uint32_t>(s_used_1g[m / REGIONS_PER_1G] + delta);
}

// `va` if its 2MB region of the pool has anything mapped in it, else the start
// of the next region that does, else SHADOW_BASE.
uint64_t next_used(uint64_t va) {
  while (va < SHADOW_BASE) {
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
  return SHADOW_BASE;
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
    while (k < pages && !(l0[start + k] & pte::Valid)) {
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
  if (pages <= PAGES_PER_2M) {
    for (size_t g = 0; g < POOL_1G; ++g) {
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
  for (size_t m = 0; m < POOL_2M;) {
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
    if (slot == nullptr || !(*slot & pte::Valid)) {
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
    if (slot != nullptr && (*slot & pte::Valid)) {
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

// Frees the first `count` shadow pages of the revocable range at `va`, which
// nothing has seen. Caller holds `s_lock`.
void unmap_shadow_locked(uint64_t va, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    uint64_t* slot = leaf_slot(shadow_of(va) + (i * PAGE_SIZE), false);
    frame::free(pte_addr(*slot), 1);
    *slot = 0;
  }
  __asm__ volatile("sfence.vma zero, zero" ::: "memory");
}

// Maps zeroed shadow for the revocable range of `pages` at `va`, which starts
// on a SHADOW_SPAN boundary, so its shadow starts on a page. All or nothing.
// Caller holds `s_lock`.
bool map_shadow_locked(uint64_t va, size_t pages) {
  const size_t count = shadow_pages(pages);
  for (size_t i = 0; i < count; ++i) {
    const uint64_t s = shadow_of(va) + (i * PAGE_SIZE);
    const uint64_t pa = frame::alloc(1);
    if (pa == 0 || !map_locked(s, pa, 1, pte::KernelData)) {
      if (pa != 0) {
        frame::free(pa, 1);
      }
      unmap_shadow_locked(va, i);
      return false;
    }
    zero_page(s);
  }
  return true;
}

}  // namespace

uint64_t translate(uint64_t va) {
  const Leaf leaf = find_leaf(va);
  if (leaf.entry == 0) {
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
        find_room_locked(pages, revocable ? SHADOW_SPAN : PAGE_SIZE);
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
    if (revocable && !map_shadow_locked(va, pages)) {
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

  // Every page must be mapped and not already quarantined. All of them are
  // checked before any is changed, so a refused free leaves the range exactly
  // as it was. This is also what refuses freeing the same range twice.
  for (size_t i = 0; i < pages; ++i) {
    const uint64_t* slot = leaf_slot(va + (i * PAGE_SIZE), false);
    if (slot == nullptr || !(*slot & pte::Valid) ||
        (*slot & pte::Quarantined)) {
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
  return (pages + (revocable ? shadow_pages(pages) : 0)) * PAGE_SIZE;
}

// Both passes below walk the pool one page at a time, skipping every 2MB
// region with nothing mapped in it (next_used). The page tables answer one
// question only: is this page mapped, and if not, how far to the next place
// that might be. Pages are read at their own addresses through `s_dynamic`.

void sweep_live_pages() {
  if (!is_initialized()) {
    return;
  }
  Locked hold(s_lock);
  for (uint64_t va = next_used(DYNAMIC_BASE); va < SHADOW_BASE;) {
    const Leaf leaf = find_leaf(va);
    if ((leaf.entry & (pte::Valid | pte::Quarantined)) == pte::Valid) {
      Capability page = capability_set_address(s_dynamic, va);
      Capability* slots =
          reinterpret_cast<Capability*>(capability_set_bounds(page, PAGE_SIZE));
      for (size_t c = 0; c < PAGE_SIZE / sizeof(Capability); ++c) {
        if (capability_is_valid(slots[c]) && revoke::should_revoke(slots[c])) {
          slots[c] = capability_clear_tag(slots[c]);
        }
      }
    }
    va = next_used(next_after(va, leaf));
  }
}

void reclaim_quarantined() {
  if (!is_initialized() || quarantined_pages() == 0) {
    return;
  }
  Locked hold(s_lock);
  if (s_quarantined_pages == 0) {
    return;
  }
  for (uint64_t va = next_used(DYNAMIC_BASE); va < SHADOW_BASE;) {
    const Leaf leaf = find_leaf(va);
    uint64_t* slot =
        (leaf.entry & pte::Quarantined) ? leaf_slot(va, false) : nullptr;
    if (slot != nullptr) {
      *slot = 0;  // unmapped: nothing can reach it any more
      frame::free(pte_addr(leaf.entry), 1);
      count_page(va, -1);  // and so free for reuse
      __atomic_fetch_sub(&s_quarantined_pages, 1, __ATOMIC_RELAXED);
      // The shadow page for this span goes with the page that starts it.
      if ((leaf.entry & pte::Revocable) != 0 && va % SHADOW_SPAN == 0) {
        uint64_t* shadow = leaf_slot(shadow_of(va), false);
        frame::free(pte_addr(*shadow), 1);
        *shadow = 0;
      }
    }
    va = next_used(next_after(va, leaf));
  }
  __asm__ volatile("sfence.vma zero, zero" ::: "memory");
}

Capability shadow_view() {
  return dynamic_view(SHADOW_BASE, DYNAMIC_TOP - SHADOW_BASE);
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
