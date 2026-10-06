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
// frame.hpp - SignetOS physical frame allocator
//
// Hands out 4KB physical frames from all RAM above the kernel image.
//
// Frames are physical addresses, not capabilities. A compartment cannot touch
// a frame until vm::map puts it somewhere in the dynamic space; the kernel
// itself reaches frames through the direct map (vm.hpp, THE DIRECT MAP).
//
// WHEN A FRAME MAY BE FREED
//
// Quarantine is a property of VIRTUAL addresses, not of frames. Capabilities
// name virtual addresses, and the accessibility invariant (design_spec.md
// section 4.2) says a capability that is still tagged must keep reaching its
// data. So when memory is freed its virtual range is quarantined but stays
// mapped, and the frames under it stay allocated, until a revocation sweep has
// cleared every tag that could reach the range. See "FREEING AND QUARANTINE"
// in vm.hpp.
//
// `free` therefore returns frames straight to the free list, and the caller
// must guarantee that nothing can reach them any more: no mapping of the frame
// may remain anywhere, and every TLB entry for those mappings must have been
// flushed. Today that holds only for frames that were never exposed (the
// unwind paths in vm.cpp). Once the sweep clears tags, it will also hold for
// frames under a range the sweep has finished with.
//
// TODO: page out to a backing store. Until then, a frame under quarantined
// memory cannot be reused before the sweep, however long that takes. With a
// backing store, its contents could be written to disk, the frame freed and
// reused, and the data faulted back in if a stale capability touches the range
// before the sweep reaches it.
//

#include <stdint.h>
#include <stddef.h>
#include <signetos/types.hpp>
#include <signetos/vm.hpp>

namespace signetos::frame {

// Physical RAM bounds discovered from the Flattened Device Tree (/memory), and
// the frame pool carved above the kernel image and frame bitmap.
uint64_t ram_base();
uint64_t ram_bytes();
uint64_t pool_base();
uint64_t pool_bytes();
size_t   pool_pages();

// Parses physical RAM bounds from the DTB (/memory). Call before vm::init,
// while physical addressing is still active.
void discover(Capability root_data_cap, Capability dtb_cap);

// Call once from kernel_main after vm::init. Carves the bitmap for the
// detected system RAM from the start of the physical pool.
void init();

bool is_initialized();

// Allocates `pages` contiguous frames. Returns the physical address of the
// first, or 0 if no run is available.
//
// The frames are not zeroed and not mapped. The caller must map them before
// touching them.
uint64_t alloc(size_t pages);

// Returns `pages` frames at `pa` to the free list, where they may be handed out
// again immediately. See above for what the caller must guarantee first.
// Returns false unless the range is page aligned and every frame in it is
// currently allocated.
bool free(uint64_t pa, size_t pages);

// True if `pa` names a currently allocated frame.
bool is_allocated(uint64_t pa);

// Diagnostics. Every frame is exactly one of the two, so these always sum to
// POOL_PAGES. Frames under quarantined memory count as allocated.
size_t free_pages();
size_t allocated_pages();

} // namespace signetos::frame
