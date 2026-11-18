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
// vm_pages.hpp - what vm.cpp and paging.cpp give each other
//
// Paging reads the entries of pool pages and changes them only through the
// two moves below (vm.hpp, PAGES), so every write to a page table is in
// vm.cpp. Everything here needs `s_lock` held. Only vm.cpp and paging.cpp
// include this.
//

#include <stddef.h>
#include <stdint.h>
#include <signetos/lock.hpp>

namespace signetos::vm {

// The VM lock (lock.hpp).
extern SpinLock s_lock;

// Gives page `va`, in use with no frame (Fresh or Swapped), the frame `pa`.
// The caller has put in the frame what the page holds, or does so before
// anything can reach the page.
void give_frame_locked(uint64_t va, uint64_t pa);

// Checks pool page `va` if it is stale (vm.hpp, CHECKED PAGES); true if it
// was. Anything else is left alone.
bool check_page_locked(uint64_t va);

#if defined(SIGNETOS_PAGING)

// The leaf entry of pool page `va`: 0 if it is free.
uint64_t entry_locked(uint64_t va);

// Whether `va` is in a region of pageable memory (vm.hpp, PAGES).
bool is_pageable_locked(uint64_t va);

// The first page at or above page address `from` that is pageable memory
// with a frame, or 0 if there is none.
uint64_t next_resident_pageable_locked(uint64_t from);

// Takes the frame of `va`, a resident page of pageable memory, away and
// returns it, leaving the page Swapped in `slot`: the caller saves there
// what the frame holds, then frees it.
uint64_t take_frame_locked(uint64_t va, uint64_t slot);

// paging.cpp's: the page that was Swapped in `slot` has been reclaimed, so
// the slot holds nothing.
void slot_reclaimed_locked(uint64_t slot);

// paging.cpp's: how many slots of swap there are; 0 until paging is set up.
size_t swap_slots();

#else

inline void slot_reclaimed_locked(uint64_t) {}  // no page is ever Swapped

#endif

}  // namespace signetos::vm
