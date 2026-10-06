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

#include <stdint.h>
#include <stddef.h>

namespace signetos {

using Capability = void* __capability;
using Sentry = Capability;

// CHERI hardware object types (the capability CT field, 4 bits wide).
//
//   CT = 0        unsealed
//   CT = 1        hardware sentry, produced by the `sentry` instruction. Cannot
//                 be produced or opened by yseal/yunseal, which only accept 2..15.
//   CT = 2..15    object types, applied with yseal and removed with yunseal.
//
// 14 types are available and 11 are used, so 13..15 are spare.
enum class OType : uint64_t {
    Unsealed         = 0,
    Sentry           = 1,
    QuotaVm          = 2,
    QuotaThreadMem   = 3,
    QuotaHeap        = 4,
    QuotaSched       = 5,
    QuotaDisk        = 6,
    Compartment      = 7,
    Thread           = 8,
    Revoker          = 9,
    TypeKey          = 10,  // design_spec.md 2.7
    SealedObject     = 11,  // design_spec.md 2.7

    // The handle to a capability_sentry_t pool object. Distinct from Sentry:
    // Sentry (CT = 1) is the hardware-jumpable code capability kept inside the
    // slot, and yseal cannot produce it. EntryPoint is the opaque data handle
    // the caller holds, which is neither jumpable nor dereferenceable.
    EntryPoint       = 12,
    Trap             = 13,  // design_spec.md 3.6 & 5.6
};

// The range yseal and yunseal will act on. Outside it they clear the tag.
constexpr uint64_t kOTypeMin = 2;
constexpr uint64_t kOTypeMax = 15;

constexpr bool otype_is_sealable(OType t) {
    return static_cast<uint64_t>(t) >= kOTypeMin &&
           static_cast<uint64_t>(t) <= kOTypeMax;
}


// Result of a kernel-internal operation. One enum serves every subsystem; each
// uses the subset it needs. The syscall ABI itself has no status channel
// (design_spec.md section 5), so these never cross into user space.
enum class Status : uint32_t {
    Ok = 0,
    NotInitialized,
    InvalidCapability,
    InsufficientPermission,
    OutOfQuota,
    NoMemory,
    // quotas
    HasChildren,
    StillAllocated,
    // threads
    BadStackSize,
    Busy,
    // compartments
    TooManyCapabilities,
    InvalidSize,
    NotFound,
    WrongQuota,
    NotOwned,
    // sentries
    NotExecutable,
    Unbounded,
    BadAlignment,
    SealFailed,
    InvalidCompartment,
    // revocation
    InvalidRange,
    NotInRange,
    PoolExhausted,
    BacklogFull,
    // traps
    InvalidAuthority,
    InvalidSentry,
    NotBoundToCompartment,
    // init
    CompartmentCreateFailed,
    CodeAllocFailed,
    SentryFailed,
    ThreadCreateFailed,
    DispatchFailed,
    // switcher (sys_compartment_invoke hands these back in a0 when it refuses
    // a call; NoKernelStack is produced by the assembly entry itself, so its
    // value is pinned and mirrored in asm_macros.h)
    StackTooSmall,
    NoKernelStack = 40,
};

inline const char* status_name(Status s) {
    switch (s) {
        case Status::Ok:                      return "Ok";
        case Status::NotInitialized:          return "NotInitialized";
        case Status::InvalidCapability:       return "InvalidCapability";
        case Status::InsufficientPermission:  return "InsufficientPermission";
        case Status::OutOfQuota:              return "OutOfQuota";
        case Status::NoMemory:                return "NoMemory";
        case Status::HasChildren:             return "HasChildren";
        case Status::StillAllocated:          return "StillAllocated";
        case Status::BadStackSize:            return "BadStackSize";
        case Status::Busy:                    return "Busy";
        case Status::TooManyCapabilities:     return "TooManyCapabilities";
        case Status::InvalidSize:             return "InvalidSize";
        case Status::NotFound:                return "NotFound";
        case Status::WrongQuota:              return "WrongQuota";
        case Status::NotOwned:                return "NotOwned";
        case Status::NotExecutable:           return "NotExecutable";
        case Status::Unbounded:               return "Unbounded";
        case Status::BadAlignment:            return "BadAlignment";
        case Status::SealFailed:              return "SealFailed";
        case Status::InvalidCompartment:      return "InvalidCompartment";
        case Status::InvalidRange:            return "InvalidRange";
        case Status::NotInRange:              return "NotInRange";
        case Status::PoolExhausted:           return "PoolExhausted";
        case Status::BacklogFull:             return "BacklogFull";
        case Status::InvalidAuthority:        return "InvalidAuthority";
        case Status::InvalidSentry:           return "InvalidSentry";
        case Status::NotBoundToCompartment:   return "NotBoundToCompartment";
        case Status::CompartmentCreateFailed: return "CompartmentCreateFailed";
        case Status::CodeAllocFailed:         return "CodeAllocFailed";
        case Status::SentryFailed:            return "SentryFailed";
        case Status::ThreadCreateFailed:      return "ThreadCreateFailed";
        case Status::DispatchFailed:          return "DispatchFailed";
        case Status::StackTooSmall:           return "StackTooSmall";
        case Status::NoKernelStack:           return "NoKernelStack";
    }
    return "Unknown";
}

// Records `s` in `*out` (if given) and returns a null capability. The common
// failure path of every `Capability f(..., Status* out_status)` operation.
__attribute__((always_inline)) inline Capability fail_with(Status* out, Status s) {
    if (out != nullptr) {
        *out = s;
    }
    return nullptr;
}

// CHERI Architectural Permission Bitmasks
namespace perms {
    constexpr uint64_t Execute             = __CHERI_CAP_PERMISSION_EXECUTE__;
    constexpr uint64_t Load                = __CHERI_CAP_PERMISSION_READ__;
    constexpr uint64_t Store               = __CHERI_CAP_PERMISSION_WRITE__;
    constexpr uint64_t LoadCapability      = __CHERI_CAP_PERMISSION_CAPABILITY__;
    constexpr uint64_t StoreCapability     = __CHERI_CAP_PERMISSION_CAPABILITY__;
    constexpr uint64_t AccessSystemRegs    = __CHERI_CAP_PERMISSION_ACCESS_SYSTEM_REGISTERS__;
    constexpr uint64_t LoadMutable         = __CHERI_CAP_PERMISSION_LOAD_MUTABLE__;
    constexpr uint64_t Seal                = __CHERI_CAP_PERMISSION_SEAL__;
    constexpr uint64_t Unseal              = __CHERI_CAP_PERMISSION_UNSEAL__;

    // Permit_Load_Mutable. Without it, a capability LOADED through this one
    // comes back with Permit_Store cleared. Any structure that stores
    // capabilities and expects to write through them after reloading needs it;
    // omitting it turns stored pointers silently read-only.
    constexpr uint64_t DataRw = Load | Store | LoadCapability | StoreCapability | LoadMutable;
    constexpr uint64_t CodeRx = Load | Execute | LoadCapability | LoadMutable;
    constexpr uint64_t ReadOnly = Load | LoadCapability;

    // Zylevels1 -- CHERI capability levels (ISA spec section 14). Three more
    // bits in the same acperm/gcperm word as the permissions above:
    //   Global      The GL flag: 1 = global, 0 = local. An information-flow
    //               label rather than an access right; unlike real permissions
    //               it can be cleared even on a sealed capability.
    //   LoadGlobal  LG. A load through a capability WITHOUT it clears Global
    //               (and, if the loaded capability is unsealed, LoadGlobal) on
    //               the capability that was loaded.
    //   StoreLocal  SL. A store through a capability WITHOUT it clears the tag
    //               of any LOCAL capability being stored.
    // Root capabilities carry all three. On a hart without Zylevels1 the bits
    // read as ones and acperm cannot clear them, so keeping them is free.
    //
    // The toolchain only defines the macros when -march includes
    // zcherilevels; we build without it (the ISA bit positions are fixed
    // either way), hence the fallbacks. boot.S carries the same three bits as
    // KERNEL_LEVEL_PERMS for the derivations done before C++ runs.
#ifdef __CHERI_CAP_PERMISSION_CAPABILITY_LEVEL__
    constexpr uint64_t Global     = __CHERI_CAP_PERMISSION_CAPABILITY_LEVEL__;
    constexpr uint64_t LoadGlobal = __CHERI_CAP_PERMISSION_ELEVATE_LEVEL__;
    constexpr uint64_t StoreLocal = __CHERI_CAP_PERMISSION_STORE_LEVEL__;
#else
    constexpr uint64_t Global     = uint64_t{1} << 4;
    constexpr uint64_t LoadGlobal = uint64_t{1} << 2;
    constexpr uint64_t StoreLocal = uint64_t{1} << 3;
#endif
    constexpr uint64_t Levels = Global | LoadGlobal | StoreLocal;
}

// Low-level capability introspection and manipulation helpers
__attribute__((always_inline)) inline bool capability_is_valid(Capability cap) {
    return __builtin_cheri_tag_get(cap) != 0;
}

__attribute__((always_inline)) inline uint64_t capability_get_address(Capability cap) {
    return __builtin_cheri_address_get(cap);
}

__attribute__((always_inline)) inline uint64_t capability_get_base(Capability cap) {
    return __builtin_cheri_base_get(cap);
}

__attribute__((always_inline)) inline uint64_t capability_get_length(Capability cap) {
    return __builtin_cheri_length_get(cap);
}

__attribute__((always_inline)) inline uint64_t capability_get_perms(Capability cap) {
    return __builtin_cheri_perms_get(cap);
}

__attribute__((always_inline)) inline Capability capability_set_address(Capability cap, uint64_t addr) {
    return __builtin_cheri_address_set(cap, addr);
}

__attribute__((always_inline)) inline Capability capability_set_bounds(Capability cap, size_t length) {
    return __builtin_cheri_bounds_set(cap, length);
}

// Restrict a capability to the ACCESS permissions in `perms_mask`.
//
// The Zylevels1 bits (perms::Levels) are always kept: taking a read-only or
// load-only view of a capability must not relabel it as local or withdraw its
// right to store local / load global capabilities. If it did, the first store
// of a local capability through a derived view would silently lose its tag
// (that is exactly how the kernel used to die at boot with Zylevels1 enabled:
// `cra`, made local by the first acperm, was saved through a `csp` that had
// lost StoreLocal). Dropping level bits is a deliberate information-flow
// decision -- use capability_restrict_levels() for that, never a `~` mask here.
__attribute__((always_inline)) inline Capability capability_and_perms(Capability cap, uint64_t perms_mask) {
    return __builtin_cheri_perms_and(cap, perms_mask | perms::Levels);
}

// Drop one or more Zylevels1 bits (`levels` must be a subset of perms::Levels):
// clear perms::Global to make a capability local, perms::StoreLocal to make a
// memory view that refuses local capabilities, perms::LoadGlobal to make loads
// through it come back local. Access permissions are untouched.
__attribute__((always_inline)) inline Capability capability_restrict_levels(Capability cap, uint64_t levels) {
    return __builtin_cheri_perms_and(cap, ~(levels & perms::Levels));
}

__attribute__((always_inline)) inline bool capability_has_perms(Capability cap, uint64_t required) {
    return (__builtin_cheri_perms_get(cap) & required) == required;
}

__attribute__((always_inline)) inline Capability capability_clear_tag(Capability cap) {
    return __builtin_cheri_tag_clear(cap);
}

} // namespace signetos
