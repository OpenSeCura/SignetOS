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
// pool.hpp - SignetOS Statically Provisioned Sealed Object Pool
//
// Implements the "Manager-Local Memory Pool" pattern from design_spec.md section 2.4
// with ZERO dynamic kernel heap: every object lives in a fixed-size array in .bss.
//
// Each pool owns one hardware object type. Handles are sealed with `yseal` under
// that type's authority, and a handle is authenticated by `yunseal` under the same
// authority. Forgery is prevented at mint time: a capability carrying CT = QuotaVm
// can only have been produced by the holder of the QuotaVm sealing authority, and
// the kernel is the only holder.
//
// Slot layout
// -----------
// Each slot is [ T value | padding ], padded to kStride. There is no software
// header: the hardware CT field carries the type identity.
//
// Stale-handle (ABA / use-after-free) protection
// ----------------------------------------------
// Sealing says nothing about slot reuse, so a handle to a destroyed object would
// otherwise validate against whichever object later occupies the same slot. Each
// slot is padded to a fixed stride and carries a generation counter bumped on
// release. The generation is encoded in the handle's ADDRESS OFFSET within its
// slot (the bounds still cover the whole slot, so the address stays in bounds,
// and the address of a sealed capability cannot be altered without clearing its
// tag). A handle whose encoded generation does not match the slot's current
// generation is rejected. Full revocation of dangling capabilities remains the
// revoker's job.
//

#include <stdint.h>
#include <stddef.h>
#include <signetos/types.hpp>
#include <signetos/sealing.hpp>

namespace signetos {

// Free-list sentinels
constexpr int32_t POOL_SLOT_NONE   = -1;
constexpr int32_t POOL_SLOT_IN_USE = -2;

// Minimum slot stride; also the number of distinct generations per slot.
constexpr size_t POOL_MIN_STRIDE = 256;

template <typename T, size_t N>
class SealedObjectPool {
public:
    static constexpr size_t kObjectSize = sizeof(T);
    static constexpr size_t kStride =
        (kObjectSize > POOL_MIN_STRIDE)
            ? ((kObjectSize + 15) / 16) * 16
            : POOL_MIN_STRIDE;

    struct alignas(16) Slot {
        T             value;
        unsigned char padding[kStride - kObjectSize];
    };

    // Establishes the arena authority over the backing storage and builds the free list.
    void init(OType type_tag) {
        type_tag_ = type_tag;

        Capability raw = reinterpret_cast<Capability>(&slots_[0]);
        arena_ = capability_set_bounds(raw, sizeof(slots_));
        arena_ = capability_and_perms(arena_, perms::DataRw);

        for (size_t i = 0; i < N; ++i) {
            next_free_[i]  = (i + 1 < N) ? static_cast<int32_t>(i + 1) : POOL_SLOT_NONE;
            generation_[i] = 0;
        }
        free_head_   = (N > 0) ? 0 : POOL_SLOT_NONE;
        free_count_  = N;

        // A pool is unusable unless it can actually mint handles of its type,
        // so the authority is a precondition rather than a per-call check.
        initialized_ = capability_is_valid(arena_) &&
                       otype_is_sealable(type_tag) &&
                       capability_is_valid(sealing::authority_for(type_tag));
    }

    bool is_initialized() const { return initialized_; }
    size_t free_count() const { return free_count_; }
    size_t capacity() const { return N; }
    OType type_tag() const { return type_tag_; }

    // The manager-private arena. Never handed to clients.
    Capability arena() const { return arena_; }

    // Allocates a zeroed slot and returns an opaque sealed handle carrying `handle_perms`.
    // Returns a null capability if the pool is exhausted.
    Capability allocate(uint64_t handle_perms, T** out_object = nullptr) {
        if (!initialized_ || free_head_ == POOL_SLOT_NONE) {
            return nullptr;
        }

        const int32_t idx = free_head_;
        free_head_ = next_free_[idx];
        next_free_[idx] = POOL_SLOT_IN_USE;
        --free_count_;

        T* obj = slot_pointer(static_cast<size_t>(idx));
        if (obj == nullptr) {
            return nullptr;
        }
        zero_object(obj);

        if (out_object != nullptr) {
            *out_object = obj;
        }
        return handle_for_index(idx, handle_perms);
    }

    // Recovers a usable object pointer from a sealed handle.
    // Returns nullptr unless the handle is tagged, carries this pool's object type,
    // refers to a currently allocated slot, and carries the live generation.
    T* unseal(Capability handle) const {
        const int32_t idx = index_of(handle);
        if (idx < 0) {
            return nullptr;
        }
        return slot_pointer(static_cast<size_t>(idx));
    }

    // Validates a handle and returns its slot index, or -1 if it is not a live handle
    // belonging to this pool.
    //
    // Authentication is `yunseal` under this pool's type authority. It succeeds only
    // if the handle is tagged and its CT equals this pool's type exactly -- yunseal
    // requires equality, not a subset -- and only for a caller holding the authority.
    // A handle minted by another pool has a different CT and comes back untagged.
    //
    // The slot is then identified from the handle's BOUNDS. That is addressing, not
    // authentication: the CT field above is what makes the handle unforgeable.
    int32_t index_of(Capability handle) const {
        if (!initialized_ || !capability_is_valid(handle)) {
            return -1;
        }

        // --- Hardware authentication ---
        Capability open = sealing::unseal_as(type_tag_, handle);
        if (!capability_is_valid(open)) {
            return -1;
        }

        // --- Identify the slot from the bounds of the opened capability ---
        const uint64_t arena_base = capability_get_base(arena_);
        const uint64_t base       = capability_get_base(open);
        const uint64_t length     = capability_get_length(open);

        if (base < arena_base) {
            return -1;
        }
        const uint64_t base_offset = base - arena_base;
        if (base_offset % kStride != 0) {
            return -1;  // not aligned to a slot boundary
        }
        const uint64_t idx = base_offset / kStride;
        if (idx >= N) {
            return -1;
        }
        if (length != kStride) {
            return -1;  // bounds do not cover exactly one slot
        }

        // --- Generation is carried as the address offset within the slot ---
        const uint64_t addr = capability_get_address(open);
        if (addr < base || addr >= base + kStride) {
            return -1;
        }
        const uint64_t gen = addr - base;

        if (next_free_[idx] != POOL_SLOT_IN_USE) {
            return -1;  // slot is free: stale or double-free handle
        }
        if (gen != generation_[idx]) {
            return -1;  // slot was recycled: stale handle from a previous generation
        }
        return static_cast<int32_t>(idx);
    }

    // Returns true if the sealed handle carries the requested delegated authority.
    static bool has_perms(Capability handle, uint64_t required) {
        return (capability_get_perms(handle) & required) == required;
    }

    // Returns a slot to the free list, zeroing it and bumping its generation so that
    // every outstanding handle to the old occupant is permanently invalidated.
    bool release(Capability handle) {
        const int32_t idx = index_of(handle);
        if (idx < 0) {
            return false;
        }
        T* obj = slot_pointer(static_cast<size_t>(idx));
        if (obj != nullptr) {
            zero_object(obj);
        }
        generation_[idx] = static_cast<uint32_t>((generation_[idx] + 1) % kStride);
        next_free_[idx]  = free_head_;
        free_head_       = idx;
        ++free_count_;
        return true;
    }

    // Direct kernel-internal object access (no sealing involved).
    // Bounded to the value, so the slot padding is not reachable through it.
    T* slot_pointer(size_t idx) const {
        if (idx >= N) {
            return nullptr;
        }
        const uint64_t addr = capability_get_base(arena_) + (idx * kStride);
        Capability c = sealing::reconstruct(arena_, addr, kObjectSize);
        return reinterpret_cast<T*>(c);
    }

    // Returns the slot index for a raw object pointer, or -1 if out of range.
    int32_t index_of_object(const T* obj) const {
        if (obj == nullptr) {
            return -1;
        }
        const uint64_t addr = capability_get_address(
            reinterpret_cast<Capability>(const_cast<T*>(obj)));
        const uint64_t base = capability_get_base(arena_);
        if (addr < base) {
            return -1;
        }
        const uint64_t offset = addr - base;
        if (offset % kStride != 0) {
            return -1;
        }
        const uint64_t idx = offset / kStride;
        return (idx < N) ? static_cast<int32_t>(idx) : -1;
    }

    // Mints a sealed handle for an allocated slot, encoding its current generation.
    Capability handle_for_index(int32_t idx, uint64_t handle_perms) const {
        if (idx < 0 || static_cast<size_t>(idx) >= N) {
            return nullptr;
        }
        const uint64_t slot_base = capability_get_base(arena_) +
                                   (static_cast<uint64_t>(idx) * kStride);

        // Bounds cover the whole slot so the generation-encoded cursor stays in bounds.
        Capability handle = sealing::reconstruct(arena_, slot_base, kStride);
        if (!capability_is_valid(handle)) {
            return nullptr;
        }
        handle = capability_set_address(handle, slot_base + generation_[idx]);
        handle = capability_and_perms(handle, handle_perms);
        return sealing::seal_as(type_tag_, handle);
    }

    // Current generation of a slot (diagnostics / tests).
    uint32_t generation_of(size_t idx) const {
        return (idx < N) ? generation_[idx] : 0;
    }

private:
    // Byte-wise zeroing is sufficient to clear CHERI validity tags: any non-capability
    // store into a 16-byte granule clears that granule's tag.
    static void zero_object(T* obj) {
        volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(obj);
        for (size_t i = 0; i < kObjectSize; ++i) {
            p[i] = 0;
        }
    }

    Slot     slots_[N];
    int32_t  next_free_[N];
    uint32_t generation_[N];
    int32_t  free_head_  = POOL_SLOT_NONE;
    size_t   free_count_ = 0;
    Capability arena_    = nullptr;
    OType    type_tag_   = OType::QuotaVm;
    bool     initialized_ = false;
};

} // namespace signetos
