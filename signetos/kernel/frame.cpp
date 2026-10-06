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

/*
 * frame.cpp - SignetOS physical frame allocator
 *
 * See frame.hpp for when a frame may be freed.
 */

#include <signetos/frame.hpp>
#include <signetos/lock.hpp>
#include <signetos/platform.hpp>

namespace signetos::frame {
namespace {

// Each bitmap word has one bit per frame, packed 64 to a uint64_t. The bitmap
// itself is carved from the start of physical RAM above the kernel image and
// reached through the direct map (`vm::phys_view`), so its size scales with
// the RAM found at boot without any static array in `.bss`.
constexpr size_t FRAMES_PER_WORD = 64;

SpinLock s_lock;

// One bit per frame: set while the frame is allocated, clear while it is free.
uint64_t* s_allocated = nullptr;

uint64_t s_pool_base    = 0;
uint64_t s_pool_bytes   = 0;
size_t   s_pool_pages   = 0;
size_t   s_bitmap_words = 0;

bool s_initialized = false;

size_t s_allocated_count = 0;

bool test_bit(const uint64_t* bm, size_t i) {
    return (bm[i / FRAMES_PER_WORD] >> (i % FRAMES_PER_WORD)) & 1ULL;
}

void set_bit(uint64_t* bm, size_t i) {
    bm[i / FRAMES_PER_WORD] |= (1ULL << (i % FRAMES_PER_WORD));
}

void clear_bit(uint64_t* bm, size_t i) {
    bm[i / FRAMES_PER_WORD] &= ~(1ULL << (i % FRAMES_PER_WORD));
}

// Lowest index starting a run of `pages` free frames, or s_pool_pages.
size_t find_run(size_t pages) {
    size_t run_start = 0;
    size_t run_len   = 0;

    for (size_t w = 0; w < s_bitmap_words; ++w) {
        // Frames under quarantined memory stay allocated until a sweep (see
        // vm.hpp), so the low words fill up and stay full. Skipping them whole
        // keeps allocation from rescanning the entire pool bit by bit.
        const uint64_t taken = s_allocated[w];
        if (taken == ~0ULL) {
            run_len = 0;
            continue;
        }

        for (size_t b = 0; b < FRAMES_PER_WORD; ++b) {
            const size_t i = (w * FRAMES_PER_WORD) + b;
            if (i >= s_pool_pages) {
                return s_pool_pages;
            }
            if (((taken >> b) & 1ULL) == 0) {
                if (run_len == 0) {
                    run_start = i;
                }
                if (++run_len == pages) {
                    return run_start;
                }
            } else {
                run_len = 0;
            }
        }
    }
    return s_pool_pages;
}

// Frame index for a physical address, or s_pool_pages if it is outside the pool
// or not page aligned.
size_t index_of(uint64_t pa) {
    if (pa < s_pool_base || pa >= s_pool_base + s_pool_bytes ||
        (pa % vm::PAGE_SIZE) != 0) {
        return s_pool_pages;
    }
    return (pa - s_pool_base) / vm::PAGE_SIZE;
}

}  // namespace

uint64_t ram_base()   { return platform::ram_base(); }
uint64_t ram_bytes()  { return platform::ram_bytes(); }
uint64_t pool_base()  { return s_pool_base; }
uint64_t pool_bytes() { return s_pool_bytes; }
size_t   pool_pages() { return s_pool_pages; }

void discover(Capability root_data_cap, Capability dtb_cap) {
    platform::discover(root_data_cap, dtb_cap);
}

void init() {
    s_lock            = SpinLock{};
    s_allocated       = nullptr;
    s_pool_base       = 0;
    s_pool_bytes      = 0;
    s_pool_pages      = 0;
    s_bitmap_words    = 0;
    s_allocated_count = 0;
    s_initialized     = false;

    const uint64_t region_base = vm::boot_reserved_end();
    const uint64_t ram_end     = vm::direct_map_top();
    if (region_base == 0 || ram_end <= region_base) {
        return;
    }

    const size_t total_frames =
        static_cast<size_t>((ram_end - region_base) / vm::PAGE_SIZE);
    const size_t max_words =
        (total_frames + FRAMES_PER_WORD - 1) / FRAMES_PER_WORD;
    const size_t bitmap_pages =
        (max_words * sizeof(uint64_t) + vm::PAGE_SIZE - 1) / vm::PAGE_SIZE;

    if (total_frames <= bitmap_pages) {
        return;
    }

    Capability bm_cap =
        vm::phys_view(region_base, bitmap_pages * vm::PAGE_SIZE);
    if (!capability_is_valid(bm_cap)) {
        return;
    }

    s_allocated    = reinterpret_cast<uint64_t*>(bm_cap);
    s_pool_base    = region_base + (bitmap_pages * vm::PAGE_SIZE);
    s_pool_pages   = total_frames - bitmap_pages;
    s_pool_bytes   = static_cast<uint64_t>(s_pool_pages) * vm::PAGE_SIZE;
    s_bitmap_words = (s_pool_pages + FRAMES_PER_WORD - 1) / FRAMES_PER_WORD;

    for (size_t w = 0; w < s_bitmap_words; ++w) {
        s_allocated[w] = 0;
    }
    s_initialized = true;

    // The firmware left the DTB somewhere in RAM, usually inside what is now
    // the pool. `init::launch` copies it for `init` later, so its frames are
    // taken out of circulation here rather than handed to the first caller.
    const uint64_t dtb_lo = platform::dtb_base() & ~(vm::PAGE_SIZE - 1);
    const uint64_t dtb_hi = platform::dtb_base() + platform::dtb_bytes();
    for (uint64_t pa = dtb_lo; platform::dtb_bytes() != 0 && pa < dtb_hi;
         pa += vm::PAGE_SIZE) {
        const size_t i = index_of(pa);
        if (i != s_pool_pages && !test_bit(s_allocated, i)) {
            set_bit(s_allocated, i);
            s_allocated_count += 1;
        }
    }
}

bool is_initialized() { return s_initialized; }

uint64_t alloc(size_t pages) {
    if (!s_initialized || pages == 0 || pages > s_pool_pages) {
        return 0;
    }
    Locked hold(s_lock);

    const size_t start = find_run(pages);
    if (start == s_pool_pages) {
        return 0;
    }

    for (size_t i = start; i < start + pages; ++i) {
        set_bit(s_allocated, i);
    }
    __atomic_store_n(&s_allocated_count, s_allocated_count + pages,
                     __ATOMIC_RELAXED);

    return s_pool_base + (start * vm::PAGE_SIZE);
}

bool free(uint64_t pa, size_t pages) {
    if (!s_initialized || pages == 0) {
        return false;
    }
    Locked hold(s_lock);

    const size_t start = index_of(pa);
    if (start == s_pool_pages || start + pages > s_pool_pages) {
        return false;
    }

    // Every frame must currently be allocated: rejects double-free and any
    // range naming frames that were never handed out.
    for (size_t i = start; i < start + pages; ++i) {
        if (!test_bit(s_allocated, i)) {
            return false;
        }
    }

    for (size_t i = start; i < start + pages; ++i) {
        clear_bit(s_allocated, i);
    }
    __atomic_store_n(&s_allocated_count, s_allocated_count - pages,
                     __ATOMIC_RELAXED);
    return true;
}

bool is_allocated(uint64_t pa) {
    const size_t i = index_of(pa);
    if (i == s_pool_pages) {
        return false;
    }
    Locked hold(s_lock);
    return test_bit(s_allocated, i);
}

size_t free_pages() {
    return s_pool_pages -
           __atomic_load_n(&s_allocated_count, __ATOMIC_RELAXED);
}
size_t allocated_pages() {
    return __atomic_load_n(&s_allocated_count, __ATOMIC_RELAXED);
}

} // namespace signetos::frame
