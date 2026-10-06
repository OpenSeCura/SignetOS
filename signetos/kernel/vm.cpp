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
 * vm.cpp - SignetOS Sv39 virtual memory
 *
 * See vm.hpp for the address space layout and how the direct map reaches page
 * tables.
 *
 * SV39 IN ONE PARAGRAPH
 *
 * A virtual address is split into three 9-bit indexes and a 12-bit offset:
 *
 *   bits 38:30  index into the root table   (L2)  each entry covers 1GB
 *   bits 29:21  index into the next table   (L1)  each entry covers 2MB
 *   bits 20:12  index into the last table   (L0)  each entry covers 4KB
 *   bits 11:0   byte offset within the page
 *
 * Nine bits is 512 entries, and 512 entries of 8 bytes is exactly one 4KB page,
 * which is why a page table is one frame. Translation starts at the root table
 * named by satp and follows one entry per level until it reaches an entry that
 * carries permissions rather than pointing further down.
 */

#include <signetos/frame.hpp>
#include <signetos/lock.hpp>
#include <signetos/platform.hpp>
#include <signetos/revoke.hpp>
#include <signetos/uart.hpp>  // the dump functions at the end of this file
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
// the kernel does not know which devices the board has beyond its own console
// and poweroff device (platform.hpp), and nothing is gained by mapping less.
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

// Lowest address above all current and released reservations.
uint64_t s_next_va = DYNAMIC_BASE;

// Coalesced, address-sorted list of unmapped virtual address ranges below
// `s_next_va` that have been reclaimed by a revocation sweep and are ready for
// reuse.
struct FreeRange {
  uint64_t va;
  size_t pages;
};
constexpr size_t MAX_FREE_RANGES = 1024;
FreeRange s_free_ranges[MAX_FREE_RANGES];
size_t s_free_range_count = 0;
size_t s_free_pages = 0;

size_t s_table_pages = 0;        // frames currently held as page tables
size_t s_alloc_pages = 0;        // pages currently handed out by alloc_pages
size_t s_quarantined_pages = 0;  // pages freed, still mapped, awaiting a sweep

// Ceiling on s_table_pages. A limit, not a pool: nothing is set aside, and
// frames below the ceiling are available to everyone until a table needs them.
size_t s_max_table_pages = DEFAULT_MAX_TABLE_PAGES;

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
  // Checked before the frame is taken, so a refusal costs nothing.
  if (s_table_pages >= s_max_table_pages) {
    return false;
  }

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
// so it reports the 2MB and 1GB pages the boot mappings use.
Leaf find_leaf(uint64_t va) {
  constexpr Leaf NONE = {0, PAGE_SIZE};

  if (!va_is_canonical(va)) {
    return NONE;
  }

  const uint64_t l2 = __atomic_load_n(&s_l2_root[l2_index(va)], __ATOMIC_ACQUIRE);
  if (!(l2 & pte::Valid)) {
    return NONE;  // nothing mapped in this 1GB
  }
  if (pte_is_leaf(l2)) {
    return {l2, GIGAPAGE_SIZE};  // the whole 1GB is one page
  }

  const uint64_t* l1_table = table_view(pte_addr(l2));
  if (l1_table == nullptr) {
    return NONE;
  }
  const uint64_t l1 = __atomic_load_n(&l1_table[l1_index(va)], __ATOMIC_ACQUIRE);
  if (!(l1 & pte::Valid)) {
    return NONE;  // nothing mapped in this 2MB
  }
  if (pte_is_leaf(l1)) {
    return {l1, MEGAPAGE_SIZE};  // the whole 2MB is one page
  }

  const uint64_t* l0_table = table_view(pte_addr(l1));
  if (l0_table == nullptr) {
    return NONE;
  }
  // Last level: either a 4KB page or nothing.
  const uint64_t l0 = __atomic_load_n(&l0_table[l0_index(va)], __ATOMIC_RELAXED);
  return (l0 & pte::Valid) ? Leaf{l0, PAGE_SIZE} : NONE;
}

}  // namespace

uint64_t kernel_base() { return frame::ram_base(); }

void init(Capability root_data_cap) {
  s_lock = SpinLock{};
  s_direct = nullptr;
  s_dynamic = nullptr;
  s_direct_top = 0;
  s_boot_reserved_end = 0;
  s_next_va = DYNAMIC_BASE;
  s_free_range_count = 0;
  s_free_pages = 0;
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

  // Root entry 0 covers VA 0x00000000..0x3FFFFFFF, where the devices are:
  // every megapage of it is an MMIO leaf. The kernel's own console and
  // poweroff device have to be inside it (they are the only devices the
  // kernel touches); the rest is reached by capability bounds alone.
  if (platform::test_device_base() >= GIGAPAGE_SIZE ||
      platform::uart_base() >= GIGAPAGE_SIZE) {
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
  // pages marked execute-only.
  constexpr uint64_t SSTATUS_SUM_MXR = (1ULL << 18) | (1ULL << 19);
  __asm__ volatile("csrs sstatus, %0" ::"r"(SSTATUS_SUM_MXR) : "memory");

  // satp turns translation on. Mode 8 in the top four bits selects Sv39, and
  // the low bits hold the root table's frame number, not its address.
  const uint64_t satp = (8ULL << 60) | (phys_of(&s_l2_root[0]) >> PAGE_SHIFT);
  __asm__ volatile(
      "csrw satp, %0\n\t"
      // Everything cached from before translation was on is now meaningless.
      "sfence.vma zero, zero\n\t" ::"r"(satp)
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

void set_max_table_pages(size_t pages) {
  __atomic_store_n(&s_max_table_pages, pages, __ATOMIC_RELAXED);
}

namespace {

// True if any page in `[va, va + pages * PAGE_SIZE)` is currently mapped.
bool any_page_mapped(uint64_t va, size_t pages) {
  uint64_t cur = va;
  const uint64_t end = va + static_cast<uint64_t>(pages) * PAGE_SIZE;
  while (cur < end) {
    const uint64_t l2 = s_l2_root[l2_index(cur)];
    if (!(l2 & pte::Valid)) {
      const uint64_t next_l2 = (cur & ~(GIGAPAGE_SIZE - 1)) + GIGAPAGE_SIZE;
      if (next_l2 <= cur || next_l2 >= end) {
        break;
      }
      cur = next_l2;
      continue;
    }
    if (pte_is_leaf(l2)) {
      return true;
    }
    const uint64_t* l1_table = table_view(pte_addr(l2));
    if (l1_table == nullptr) {
      return true;
    }
    const uint64_t l1 = l1_table[l1_index(cur)];
    if (!(l1 & pte::Valid)) {
      const uint64_t next_l1 = (cur & ~(MEGAPAGE_SIZE - 1)) + MEGAPAGE_SIZE;
      if (next_l1 <= cur || next_l1 >= end) {
        break;
      }
      cur = next_l1;
      continue;
    }
    if (pte_is_leaf(l1)) {
      return true;
    }
    const uint64_t* l0_table = table_view(pte_addr(l1));
    if (l0_table == nullptr) {
      return true;
    }
    const size_t start_i0 = l0_index(cur);
    const uint64_t l1_end = (cur & ~(MEGAPAGE_SIZE - 1)) + MEGAPAGE_SIZE;
    const uint64_t stop = (end < l1_end) ? end : l1_end;
    const size_t count = static_cast<size_t>((stop - cur) / PAGE_SIZE);
    for (size_t i = 0; i < count; ++i) {
      if ((l0_table[start_i0 + i] & pte::Valid) != 0) {
        return true;
      }
    }
    cur = stop;
  }
  return false;
}

uint64_t reserve_locked(size_t pages) {
  if (pages == 0) {
    return 0;
  }
  const uint64_t bytes = static_cast<uint64_t>(pages) * PAGE_SIZE;

  // Reuse a reclaimed virtual address range first (first-fit in ascending
  // address order).
  for (size_t i = 0; i < s_free_range_count; ++i) {
    if (s_free_ranges[i].pages >= pages) {
      const uint64_t va = s_free_ranges[i].va;
      s_free_ranges[i].va += bytes;
      s_free_ranges[i].pages -= pages;
      s_free_pages -= pages;
      if (s_free_ranges[i].pages == 0) {
        for (size_t j = i; j + 1 < s_free_range_count; ++j) {
          s_free_ranges[j] = s_free_ranges[j + 1];
        }
        s_free_range_count -= 1;
      }
      return va;
    }
  }

  // Written as a subtraction from the top rather than `s_next_va + bytes >
  // DYNAMIC_TOP`, so a huge request cannot wrap and appear to fit.
  if (bytes > DYNAMIC_TOP - s_next_va) {
    return 0;
  }

  // Hand out the current mark and push it past the range just taken.
  const uint64_t va = s_next_va;
  s_next_va += bytes;
  return va;
}

void release_locked(uint64_t va, size_t pages) {
  if (!is_initialized() || pages == 0 || (va % PAGE_SIZE) != 0 ||
      !range_is_mappable(va, pages)) {
    return;
  }
  const uint64_t bytes = static_cast<uint64_t>(pages) * PAGE_SIZE;
  if (va + bytes > s_next_va) {
    return;
  }
  // Refuse to recycle addresses that are still mapped (live or quarantined).
  if (any_page_mapped(va, pages)) {
    return;
  }

  size_t idx = 0;
  while (idx < s_free_range_count && s_free_ranges[idx].va < va) {
    ++idx;
  }
  if (idx > 0) {
    const uint64_t prev_end =
        s_free_ranges[idx - 1].va +
        static_cast<uint64_t>(s_free_ranges[idx - 1].pages) * PAGE_SIZE;
    if (prev_end > va) {
      return;
    }
  }
  if (idx < s_free_range_count && va + bytes > s_free_ranges[idx].va) {
    return;
  }

  const bool merge_prev =
      (idx > 0) &&
      (s_free_ranges[idx - 1].va +
           static_cast<uint64_t>(s_free_ranges[idx - 1].pages) * PAGE_SIZE ==
       va);
  const bool merge_next =
      (idx < s_free_range_count) && (va + bytes == s_free_ranges[idx].va);

  if (merge_prev && merge_next) {
    s_free_ranges[idx - 1].pages += pages + s_free_ranges[idx].pages;
    for (size_t j = idx; j + 1 < s_free_range_count; ++j) {
      s_free_ranges[j] = s_free_ranges[j + 1];
    }
    s_free_range_count -= 1;
    s_free_pages += pages;
  } else if (merge_prev) {
    s_free_ranges[idx - 1].pages += pages;
    s_free_pages += pages;
  } else if (merge_next) {
    s_free_ranges[idx].va = va;
    s_free_ranges[idx].pages += pages;
    s_free_pages += pages;
  } else if (va + bytes == s_next_va) {
    s_next_va = va;
  } else if (s_free_range_count < MAX_FREE_RANGES) {
    for (size_t j = s_free_range_count; j > idx; --j) {
      s_free_ranges[j] = s_free_ranges[j - 1];
    }
    s_free_ranges[idx] = {va, pages};
    s_free_range_count += 1;
    s_free_pages += pages;
  }

  if (s_free_range_count > 0) {
    const FreeRange& last = s_free_ranges[s_free_range_count - 1];
    if (last.va + static_cast<uint64_t>(last.pages) * PAGE_SIZE == s_next_va) {
      s_next_va = last.va;
      s_free_pages -= last.pages;
      s_free_range_count -= 1;
    }
  }
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
      // Out of frames, at the table cap, or the range runs into an
      // existing megapage. Roll back so a failed map leaves nothing.
      if (i > 0) {
        unmap_locked(va, i);
      }
      return false;
    }
    // Valid is forced on: an entry without it is ignored by the hardware.
    *slot = pte_make(pa + (i * PAGE_SIZE), flags | pte::Valid);
    // This address may have been mapped before, so drop any stale entry.
    flush(page_va);
  }
  return true;
}

}  // namespace

uint64_t reserve(size_t pages) {
  Locked hold(s_lock);
  return reserve_locked(pages);
}

void release(uint64_t va, size_t pages) {
  Locked hold(s_lock);
  release_locked(va, pages);
}

size_t reservable_pages() {
  Locked hold(s_lock);
  return s_free_pages +
         static_cast<size_t>((DYNAMIC_TOP - s_next_va) / PAGE_SIZE);
}

bool map(uint64_t va, uint64_t pa, size_t pages, uint64_t flags) {
  Locked hold(s_lock);
  return map_locked(va, pa, pages, flags);
}

bool unmap(uint64_t va, size_t pages) {
  Locked hold(s_lock);
  return unmap_locked(va, pages);
}

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

bool is_quarantined(uint64_t va) {
  return (find_leaf(va).entry & pte::Quarantined) != 0;
}

bool range_has_quarantined(uint64_t va, size_t len) {
  if (!is_initialized() || len == 0 || quarantined_pages() == 0) {
    return false;
  }
  uint64_t end = va + len;
  if (end < va) {
    end = DYNAMIC_TOP;
  }
  if (end <= DYNAMIC_BASE || va >= DYNAMIC_TOP) {
    return false;
  }
  uint64_t cur = (va < DYNAMIC_BASE) ? DYNAMIC_BASE : (va & ~(PAGE_SIZE - 1));
  if (end > DYNAMIC_TOP) {
    end = DYNAMIC_TOP;
  }
  end = (end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
  while (cur < end) {
    const uint64_t l2 =
        __atomic_load_n(&s_l2_root[l2_index(cur)], __ATOMIC_ACQUIRE);
    if (!(l2 & pte::Valid) || pte_is_leaf(l2)) {
      const uint64_t next_l2 = (cur & ~(GIGAPAGE_SIZE - 1)) + GIGAPAGE_SIZE;
      if (next_l2 <= cur || next_l2 >= end) {
        break;
      }
      cur = next_l2;
      continue;
    }
    const uint64_t* l1_table = table_view(pte_addr(l2));
    if (l1_table == nullptr) {
      break;
    }
    const uint64_t l1 =
        __atomic_load_n(&l1_table[l1_index(cur)], __ATOMIC_ACQUIRE);
    if (!(l1 & pte::Valid) || pte_is_leaf(l1)) {
      const uint64_t next_l1 = (cur & ~(MEGAPAGE_SIZE - 1)) + MEGAPAGE_SIZE;
      if (next_l1 <= cur || next_l1 >= end) {
        break;
      }
      cur = next_l1;
      continue;
    }
    const uint64_t* l0_table = table_view(pte_addr(l1));
    if (l0_table == nullptr) {
      break;
    }
    const size_t start_i0 = l0_index(cur);
    const uint64_t l1_end = (cur & ~(MEGAPAGE_SIZE - 1)) + MEGAPAGE_SIZE;
    const uint64_t stop = (end < l1_end) ? end : l1_end;
    const size_t count = static_cast<size_t>((stop - cur) / PAGE_SIZE);
    for (size_t i = 0; i < count; ++i) {
      const uint64_t l0 =
          __atomic_load_n(&l0_table[start_i0 + i], __ATOMIC_RELAXED);
      if ((l0 & (pte::Valid | pte::Quarantined)) ==
          (pte::Valid | pte::Quarantined)) {
        return true;
      }
    }
    cur = stop;
  }
  return false;
}

uint64_t leaf_flags(uint64_t va) {
  // An unmapped address gives entry 0, which masks to 0: no flags.
  return find_leaf(va).entry & PTE_FLAG_MASK;
}

Capability alloc_pages(size_t pages) {
  if (!is_initialized() || pages == 0) {
    return nullptr;
  }

  const size_t bytes = pages * PAGE_SIZE;

  // Three separate resources, taken in order, each undone if a later one
  // fails: an address range, the frames to back it, and the mapping joining
  // the two. If either the virtual address space or the physical frame pool is
  // exhausted while quarantined memory awaits reclamation, trigger a
  // revocation sweep and retry once.
  bool swept = false;
  uint64_t va = reserve(pages);
  if (va == 0 && quarantined_pages() > 0) {
    revoke::sweep();
    swept = true;
    va = reserve(pages);
  }
  if (va == 0) {
    return nullptr;
  }

  uint64_t pa = frame::alloc(pages);
  if (pa == 0 && !swept && quarantined_pages() > 0) {
    release(va, pages);
    revoke::sweep();
    va = reserve(pages);
    if (va == 0) {
      return nullptr;
    }
    pa = frame::alloc(pages);
  }
  if (pa == 0) {
    release(va, pages);
    return nullptr;
  }

  if (!map(va, pa, pages, pte::Permissive)) {
    frame::free(pa, pages);
    release(va, pages);
    return nullptr;
  }

  // Narrow the dynamic authority to exactly this object, so the holder cannot
  // reach a neighbouring allocation by walking off the end.
  // TODO what is s_dynamic and which perms does it have?
  Capability c = capability_set_address(s_dynamic, va);
  c = capability_set_bounds(c, bytes);
  if (!capability_is_valid(c) ||
      (capability_get_perms(c) & (perms::Seal | perms::Unseal)) != 0) {
    unmap(va, pages);
    frame::free(pa, pages);
    release(va, pages);
    return nullptr;
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

bool free_pages(Capability object) {
  if (!is_initialized() || !capability_is_valid(object)) {
    return false;
  }

  // What to free is read from the capability itself: where it starts and how
  // long it is. Both were set by alloc_pages and cannot have been widened.
  const uint64_t va = capability_get_base(object);
  const uint64_t bytes = capability_get_length(object);
  if (bytes == 0 || (va % PAGE_SIZE) != 0) {
    return false;
  }

  // Round up, so a capability covering part of a page still frees that page.
  const size_t pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
  if (!range_is_mappable(va, pages)) {
    return false;
  }

  Locked hold(s_lock);

  // Every page must be mapped and not already quarantined. All of them are
  // checked before any is changed, so a refused free leaves the range exactly
  // as it was. This is also what refuses freeing the same range twice.
  for (size_t i = 0; i < pages; ++i) {
    const uint64_t* slot = leaf_slot(va + (i * PAGE_SIZE), false);
    if (slot == nullptr || !(*slot & pte::Valid) ||
        (*slot & pte::Quarantined)) {
      return false;
    }
  }

  // Quarantine, do NOT unmap or release the virtual address range yet.
  // Capabilities to this range may still be tagged, and until the revocation
  // sweep clears them they must keep reaching the same data (the accessibility
  // invariant, design_spec.md section 4.2). Once `revoke::sweep()` clears all
  // tags pointing into quarantined memory, `reclaim_quarantined()` unmaps the
  // pages, frees their physical frames, and returns the virtual addresses to
  // the reusable pool via `release()`.
  for (size_t i = 0; i < pages; ++i) {
    uint64_t* slot = leaf_slot(va + (i * PAGE_SIZE), false);
    *slot |= pte::Quarantined;
  }

  __atomic_fetch_sub(&s_alloc_pages, pages, __ATOMIC_RELAXED);
  __atomic_fetch_add(&s_quarantined_pages, pages, __ATOMIC_RELAXED);
  return true;
}

void sweep_live_pages() {
  if (!is_initialized()) {
    return;
  }
  Locked hold(s_lock);
  const size_t start_i2 = l2_index(DYNAMIC_BASE);
  const size_t end_i2 = l2_index(DYNAMIC_TOP);
  for (size_t i2 = start_i2; i2 < end_i2; ++i2) {
    const uint64_t l2 = s_l2_root[i2];
    if (!(l2 & pte::Valid) || pte_is_leaf(l2)) {
      continue;
    }
    const uint64_t* l1_table = table_view(pte_addr(l2));
    if (l1_table == nullptr) {
      continue;
    }
    for (size_t i1 = 0; i1 < ENTRIES; ++i1) {
      const uint64_t l1 = l1_table[i1];
      if (!(l1 & pte::Valid) || pte_is_leaf(l1)) {
        continue;
      }
      const uint64_t* l0_table = table_view(pte_addr(l1));
      if (l0_table == nullptr) {
        continue;
      }
      for (size_t i0 = 0; i0 < ENTRIES; ++i0) {
        const uint64_t l0 = l0_table[i0];
        if ((l0 & (pte::Valid | pte::Quarantined)) != pte::Valid) {
          continue;
        }
        Capability page = phys_view(pte_addr(l0), PAGE_SIZE);
        if (!capability_is_valid(page)) {
          continue;
        }
        Capability* slots = reinterpret_cast<Capability*>(page);
        constexpr size_t kCapsPerPage = PAGE_SIZE / sizeof(Capability);
        for (size_t c = 0; c < kCapsPerPage; ++c) {
          const Capability cap = slots[c];
          if (capability_is_valid(cap) && revoke::should_revoke(cap)) {
            slots[c] = capability_clear_tag(cap);
          }
        }
      }
    }
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
  const size_t start_i2 = l2_index(DYNAMIC_BASE);
  const size_t end_i2 = l2_index(DYNAMIC_TOP);

  uint64_t va_run_start = 0;
  size_t va_run_pages = 0;
  uint64_t pa_run_start = 0;
  size_t pa_run_pages = 0;

  auto flush_va_run = [&]() {
    if (va_run_pages > 0) {
      release_locked(va_run_start, va_run_pages);
      va_run_pages = 0;
    }
  };
  auto flush_pa_run = [&]() {
    if (pa_run_pages > 0) {
      frame::free(pa_run_start, pa_run_pages);
      pa_run_pages = 0;
    }
  };

  for (size_t i2 = start_i2; i2 < end_i2; ++i2) {
    const uint64_t l2 = s_l2_root[i2];
    if (!(l2 & pte::Valid) || pte_is_leaf(l2)) {
      continue;
    }
    const uint64_t va2 = static_cast<uint64_t>(i2) << 30;
    const uint64_t* l1_table = table_view(pte_addr(l2));
    if (l1_table == nullptr) {
      continue;
    }
    for (size_t i1 = 0; i1 < ENTRIES; ++i1) {
      const uint64_t l1 = l1_table[i1];
      if (!(l1 & pte::Valid) || pte_is_leaf(l1)) {
        continue;
      }
      const uint64_t va1 = va2 | (static_cast<uint64_t>(i1) << 21);
      uint64_t* l0_table = table_view(pte_addr(l1));
      if (l0_table == nullptr) {
        continue;
      }
      for (size_t i0 = 0; i0 < ENTRIES; ++i0) {
        const uint64_t l0 = l0_table[i0];
        if ((l0 & (pte::Valid | pte::Quarantined)) !=
            (pte::Valid | pte::Quarantined)) {
          continue;
        }
        const uint64_t page_va = va1 | (static_cast<uint64_t>(i0) << 12);
        const uint64_t page_pa = pte_addr(l0);

        l0_table[i0] = 0;
        if (s_quarantined_pages > 0) {
          __atomic_fetch_sub(&s_quarantined_pages, 1, __ATOMIC_RELAXED);
        }

        if (pa_run_pages > 0 &&
            page_pa ==
                pa_run_start + static_cast<uint64_t>(pa_run_pages) * PAGE_SIZE) {
          pa_run_pages += 1;
        } else {
          flush_pa_run();
          pa_run_start = page_pa;
          pa_run_pages = 1;
        }

        if (va_run_pages > 0 &&
            page_va ==
                va_run_start + static_cast<uint64_t>(va_run_pages) * PAGE_SIZE) {
          va_run_pages += 1;
        } else {
          flush_va_run();
          va_run_start = page_va;
          va_run_pages = 1;
        }
      }
    }
  }
  flush_pa_run();
  flush_va_run();
  __asm__ volatile("sfence.vma zero, zero" ::: "memory");
}

size_t table_pages() {
  return __atomic_load_n(&s_table_pages, __ATOMIC_RELAXED);
}
size_t max_table_pages() {
  return __atomic_load_n(&s_max_table_pages, __ATOMIC_RELAXED);
}
size_t allocated_pages() {
  return __atomic_load_n(&s_alloc_pages, __ATOMIC_RELAXED);
}
size_t quarantined_pages() {
  return __atomic_load_n(&s_quarantined_pages, __ATOMIC_RELAXED);
}

//
// Dumping the page tables
//
// Everything below reads the live tables the hardware walks. Nothing is cached
// or remembered by the VM: if a mapping is printed here, the MMU can see it.
//

namespace {

// "VRWXUGADQ", with a dash for each bit that is clear. Q is the software
// Quarantined bit (bit 8), not a hardware flag.
void print_flags(uint64_t entry) {
  const char names[] = {'V', 'R', 'W', 'X', 'U', 'G', 'A', 'D', 'Q'};
  for (size_t bit = 0; bit < 9; ++bit) {
    uart::putchar((entry & (1ULL << bit)) ? names[bit] : '-');
  }
}

void print_size(uint64_t page_size) {
  if (page_size == GIGAPAGE_SIZE) {
    uart::print("1G");
  } else if (page_size == MEGAPAGE_SIZE) {
    uart::print("2M");
  } else {
    uart::print("4K");
  }
}

// One line: the address range, where it points, the page size, and the flags.
void print_run(uint64_t va, uint64_t pa, uint64_t page_size, size_t count,
               uint64_t entry) {
  const uint64_t bytes = page_size * count;
  uart::print("  ");
  uart::print_hex64(va);
  uart::print("-");
  uart::print_hex64(va + bytes - 1);
  uart::print(" -> ");
  uart::print_hex64(pa);
  uart::print("  ");
  print_size(page_size);
  uart::print(" x");
  uart::print_dec(count);
  uart::print("\t");
  print_flags(entry);
  uart::print("\n");
}

// Accumulates consecutive entries into one line. A run continues while the
// virtual and physical addresses both advance by exactly one page and the flags
// are unchanged; anything else starts a new run.
struct RunPrinter {
  bool open = false;
  uint64_t va = 0;
  uint64_t pa = 0;
  uint64_t page_size = 0;
  uint64_t flags = 0;
  size_t count = 0;
  size_t lines = 0;

  void add(uint64_t new_va, uint64_t new_pa, uint64_t new_size,
           uint64_t entry) {
    const uint64_t new_flags = entry & PTE_FLAG_MASK;
    if (open && new_size == page_size && new_flags == flags &&
        new_va == va + page_size * count && new_pa == pa + page_size * count) {
      count += 1;  // extends the run
      return;
    }
    flush();
    open = true;
    va = new_va;
    pa = new_pa;
    page_size = new_size;
    flags = new_flags;
    count = 1;
  }

  void flush() {
    if (!open) {
      return;
    }
    print_run(va, pa, page_size, count, flags);
    lines += 1;
    open = false;
  }
};

}  // namespace

void dump_mapping(uint64_t va) {
  Locked hold(s_lock);
  const Leaf leaf = find_leaf(va);
  uart::print("  ");
  uart::print_hex64(va);
  if (leaf.entry == 0) {
    uart::print(" -> NOT MAPPED\n");
    return;
  }
  // The leaf may cover more than 4KB, so the offset within it carries down.
  const uint64_t pa = pte_addr(leaf.entry) + (va & (leaf.page_size - 1));
  uart::print(" -> ");
  uart::print_hex64(pa);
  uart::print("  ");
  print_size(leaf.page_size);
  uart::print("\t");
  print_flags(leaf.entry);
  uart::print("\n");
}

size_t dump_mappings(const char* label) {
  Locked hold(s_lock);
  uart::print("--- page table: ");
  uart::print(label);
  uart::print(" ---\n");

  RunPrinter out;
  size_t leaves = 0;

  for (size_t i2 = 0; i2 < ENTRIES; ++i2) {
    const uint64_t l2 = s_l2_root[i2];
    if (!(l2 & pte::Valid)) {
      continue;  // nothing in this 1GB
    }
    const uint64_t va2 = static_cast<uint64_t>(i2) << 30;
    if (pte_is_leaf(l2)) {
      out.add(va2, pte_addr(l2), GIGAPAGE_SIZE, l2);
      leaves += 1;
      continue;
    }

    const uint64_t* l1_table = table_view(pte_addr(l2));
    if (l1_table == nullptr) {
      continue;
    }
    for (size_t i1 = 0; i1 < ENTRIES; ++i1) {
      const uint64_t l1 = l1_table[i1];
      if (!(l1 & pte::Valid)) {
        continue;  // nothing in this 2MB
      }
      const uint64_t va1 = va2 | (static_cast<uint64_t>(i1) << 21);
      if (pte_is_leaf(l1)) {
        out.add(va1, pte_addr(l1), MEGAPAGE_SIZE, l1);
        leaves += 1;
        continue;
      }

      const uint64_t* l0_table = table_view(pte_addr(l1));
      if (l0_table == nullptr) {
        continue;
      }
      for (size_t i0 = 0; i0 < ENTRIES; ++i0) {
        const uint64_t l0 = l0_table[i0];
        if (!(l0 & pte::Valid)) {
          continue;
        }
        out.add(va1 | (static_cast<uint64_t>(i0) << 12), pte_addr(l0),
                PAGE_SIZE, l0);
        leaves += 1;
      }
    }
  }
  out.flush();

  uart::print("--- ");
  uart::print_dec(leaves);
  uart::print(" leaf entries in ");
  uart::print_dec(out.lines);
  uart::print(" runs, ");
  uart::print_dec(s_table_pages);
  uart::print(" table pages ---\n");
  return leaves;
}

} // namespace signetos::vm
