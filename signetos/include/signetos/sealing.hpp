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
// sealing.hpp - SignetOS hardware object sealing
//
// Two sealing mechanisms, both performed by hardware:
//
//   seal_as(t, cap)  DATA HANDLE. CT = t, for t in 2..15. Applied with `yseal`
//                    under a sealing authority, removed with `yunseal` under the
//                    same authority. Not dereferenceable and not jumpable.
//
//   seal_entry(cap)  ENTRY POINT (capability_sentry_t). CT = 1, applied by the
//                    ambient `sentry` instruction and unsealed by the hardware
//                    on `jalr`. Jumpable, never dereferenceable.
//
// The two cannot be confused: they occupy different CT values, and yseal refuses
// to produce CT = 1 while yunseal refuses to open it.
//
// SEALING AUTHORITIES
//
// A Zyseal authority is an ordinary capability used as a name rather than as a
// pointer. Its ADDRESS is the object type, its BOUNDS are the range of types it
// is entitled to name, SE-permission allows yseal and US-permission allows
// yunseal. `yseal` succeeds only if the authority is tagged, holds SE, and its
// address lies within its own bounds.
//
// The kernel keeps one capability, g_type_root, covering [2,16) with SE|US and
// no memory permissions at all. Per-type authorities are derived from it on
// demand, so there is no table of authorities to keep consistent.
//
// Neither instruction traps. On refusal the destination is the input operand
// with its tag cleared, so every entry point here returns a null capability
// rather than a tagless one, and the caller gets an unambiguous failure.
//

#include <stdint.h>
#include <stddef.h>
#include <signetos/types.hpp>

namespace signetos::sealing {

// The authority root: address 2, bounds [2,16), permissions SE|US only.
// Established by init_type_root() before any sealing takes place.
inline Capability g_type_root = nullptr;

// Returns the hardware CT-field of `cap`. 0 means unsealed.
inline uint64_t type_of(Capability cap) {
    return static_cast<uint64_t>(__builtin_cheri_type_get(cap));
}

// True if `cap` is sealed, and therefore not dereferenceable.
//
// Derived from the CT field rather than __builtin_cheri_sealed_get(), which
// upstream mis-selected as a bare GCTYPE returning the whole object type
// instead of a boolean (SPEC_CHANGE_NOTES.md F1). The toolchain fix is applied,
// but comparing CT is independent of it.
inline bool is_sealed(Capability cap) {
    return type_of(cap) != static_cast<uint64_t>(OType::Unsealed);
}

// Establishes the authority root from the boot root capability. Call once,
// before any other function here. Returns false if `root` cannot carry it.
//
// All memory permissions are stripped: an authority names a type and must not
// double as a pointer to whatever address that type number happens to be.
inline bool init_type_root(Capability root) {
    if (!capability_is_valid(root)) {
        g_type_root = nullptr;
        return false;
    }
    Capability r = capability_set_address(root, kOTypeMin);
    r = capability_set_bounds(r, kOTypeMax - kOTypeMin + 1);
    r = capability_and_perms(r, perms::Seal | perms::Unseal);
    if (!capability_is_valid(r) ||
        (capability_get_perms(r) & (perms::Seal | perms::Unseal)) !=
            (perms::Seal | perms::Unseal)) {
        g_type_root = nullptr;
        return false;
    }
    g_type_root = r;
    return true;
}

// The authority naming exactly one object type: address t, bounds [t, t+1).
//
// Bounding to a single type is what stops one authority from standing in for
// another. The address of a capability can be moved freely, but yseal checks
// the address against the authority's own bounds, so an authority for type 3
// retargeted at type 4 is refused by the hardware.
inline Capability authority_for(OType t) {
    if (!otype_is_sealable(t) || !capability_is_valid(g_type_root)) {
        return nullptr;
    }
    Capability a = capability_set_address(g_type_root, static_cast<uint64_t>(t));
    a = capability_set_bounds(a, 1);
    return capability_is_valid(a) ? a : nullptr;
}

// Seals `cap` under an explicitly supplied authority.
//
// This is the raw instruction. seal_as() is this with the authority derived
// from g_type_root; the explicit form exists so that a caller can supply a
// deliberately defective authority and observe the hardware refuse it.
//
// Operand order: the intrinsic takes (capability_to_seal, authority), the
// instruction takes (authority, capability_to_seal).
inline Capability seal_with(Capability auth, Capability cap) {
    Capability sealed = __builtin_cheri_seal(cap, auth);
    return capability_is_valid(sealed) ? sealed : nullptr;
}

inline Capability unseal_with(Capability auth, Capability handle) {
    Capability open = __builtin_cheri_unseal(handle, auth);
    return capability_is_valid(open) ? open : nullptr;
}

// Seals `cap` as an object of type `t`. Returns null unless `t` is a sealable
// type, `cap` is tagged and unsealed, and the authority exists.
//
// Bounds, address and permissions are carried through untouched; the only
// change is the CT field. Sealing therefore grants nothing.
inline Capability seal_as(OType t, Capability cap) {
    if (!capability_is_valid(cap) || is_sealed(cap)) {
        return nullptr;
    }
    Capability auth = authority_for(t);
    if (!capability_is_valid(auth)) {
        return nullptr;
    }
    return seal_with(auth, cap);
}

// Opens a handle of type `t`. Returns null unless the handle is tagged and its
// CT is exactly `t`; yunseal requires equality, not a subset.
inline Capability unseal_as(OType t, Capability handle) {
    if (!capability_is_valid(handle)) {
        return nullptr;
    }
    Capability auth = authority_for(t);
    if (!capability_is_valid(auth)) {
        return nullptr;
    }
    return unseal_with(auth, handle);
}

// True if `cap` is a live handle of exactly type `t`.
inline bool is_sealed_as(OType t, Capability cap) {
    return capability_is_valid(cap) && type_of(cap) == static_cast<uint64_t>(t);
}

// Opens a kernel object handle and returns the kernel's writable pointer to
// the live object, or null.
//
// This is THE authentication primitive for page-backed kernel objects (quota
// nodes, compartments, threads). `T` must begin with `Capability self_page`,
// the writable kernel capability the kernel stored in the object when it was
// created, and carry a `uint32_t flags` field with `live_flag` set while the
// object is alive.
//
// Steps, in order:
//   1. `yunseal` under `type` -- only the kernel holds that authority, so a
//      successful unseal proves the handle is genuine.
//   2. The unsealed view must be exactly one `T` and carry `need_perms`
//      (the caller's delegated permissions, which must include enough to read
//      `self_page`).
//   3. `self_page` must be tagged and `live_flag` set; a destroyed object has
//      both cleared, which is what refuses stale handles to quarantined pages.
template <class T>
inline T* open_live(OType type, Capability handle, uint32_t live_flag,
                    uint64_t need_perms = perms::Load | perms::LoadCapability) {
  Capability open = unseal_as(type, handle);
  if (!capability_is_valid(open) || capability_get_length(open) != sizeof(T)) {
    return nullptr;
  }
  if (!capability_has_perms(open, need_perms)) {
    return nullptr;
  }
  const T* ro = reinterpret_cast<const T*>(open);
  if ((ro->flags & live_flag) == 0 || !capability_is_valid(ro->self_page)) {
    return nullptr;
  }
  return reinterpret_cast<T*>(ro->self_page);
}

// Seals an executable capability into an entry point sentry (CT = 1).
//
// Returns a null capability unless ALL of the following hold:
//
//   1. `code_cap` is tagged.
//   2. `code_cap` is unsealed.
//   3. `code_cap` has Permit_Execute. Without it the result would be an
//      unjumpable capability wearing an entry point's name.
//   4. The address is even. ISA 2.9.5: JALR unseals the target only if
//      "rs1.address[0] is zero, and the I-immediate is zero". A sentry at an
//      odd address would stay sealed in PCC and trap.
//
// Permit_Store is stripped to enforce W^X: after `jalr` this capability becomes
// PCC, and a writable PCC would let a compartment rewrite its own code.
//
// The CALLER must bound `code_cap` first. Nothing here can infer the extent of
// a function, and `jalr` installs the sentry as PCC verbatim, so a sentry built
// from a raw &function would hand the callee execute authority over all memory.
inline Capability seal_entry(Capability code_cap) {
    if (!capability_is_valid(code_cap) || is_sealed(code_cap)) {
        return nullptr;
    }
    if ((capability_get_perms(code_cap) & perms::Execute) == 0) {
        return nullptr;
    }
    if ((capability_get_address(code_cap) & 1u) != 0) {
        return nullptr;
    }
    Capability wx = capability_and_perms(code_cap, ~perms::Store);
    Capability sentry = __builtin_cheri_seal_entry(wx);
    return capability_is_valid(sentry) ? sentry : nullptr;
}

// True if `cap` is a jumpable entry point.
inline bool is_entry(Capability cap) {
    return is_sealed_as(OType::Sentry, cap);
}

// True if `cap` is an opaque data handle of some object type.
// Says nothing about WHICH type; use is_sealed_as for that.
inline bool is_data_handle(Capability cap) {
    return capability_is_valid(cap) && type_of(cap) >= kOTypeMin;
}

// Derives a bounded capability to [addr, addr + length) from `authority`.
//
// Pure addressing within memory the caller already owns: the result takes its
// tag and permissions from `authority`, never from any handle. Used by the
// object pools to reach a slot from the arena capability. Returns null if
// `authority` does not cover the requested range.
inline Capability reconstruct(Capability authority, uint64_t addr, size_t length) {
    if (!capability_is_valid(authority) || is_sealed(authority)) {
        return nullptr;
    }
    const uint64_t auth_base = capability_get_base(authority);
    const uint64_t auth_top  = auth_base + capability_get_length(authority);
    if (addr < auth_base || addr + length > auth_top) {
        return nullptr;
    }
    Capability derived = capability_set_address(authority, addr);
    derived = capability_set_bounds(derived, length);
    return capability_is_valid(derived) ? derived : nullptr;
}

// --- Compartment-Minted Sealing Types (design_spec.md §2.7 & §5.4) ----------

// `sys_type_mint`: Bounds `record` to 16 bytes, restricts permissions to
// `Permit_Load | Permit_Store`, and seals it with `OType::TypeKey` (CT = 10).
// Requires `record` to be tagged, unsealed, carry `Permit_Store`, and have at
// least 16 bytes available from its current address.
inline Capability type_mint(Capability record) {
    if (!capability_is_valid(record) || is_sealed(record)) {
        return nullptr;
    }
    if ((capability_get_perms(record) & perms::Store) == 0) {
        return nullptr;
    }
    const uint64_t base = capability_get_base(record);
    const uint64_t len  = capability_get_length(record);
    const uint64_t addr = capability_get_address(record);
    if (addr < base || addr > base + len ||
        (addr & (sizeof(Capability) - 1)) != 0 ||
        (base + len) - addr < sizeof(Capability)) {
        return nullptr;
    }
    Capability key = capability_set_bounds(record, sizeof(Capability));
    key = capability_and_perms(key, perms::Load | perms::Store);
    if (!capability_is_valid(key)) {
        return nullptr;
    }
    return seal_as(OType::TypeKey, key);
}

// `sys_type_derive`: Unseals `key` (`OType::TypeKey`), restricts its
// permissions to `permissions & (Permit_Load | Permit_Store)`, and re-seals
// with `OType::TypeKey`.
inline Capability type_derive(Capability key, uint32_t permissions) {
    Capability open = unseal_as(OType::TypeKey, key);
    if (!capability_is_valid(open)) {
        return nullptr;
    }
    const uint64_t mask =
        static_cast<uint64_t>(permissions) & (perms::Load | perms::Store);
    Capability derived = capability_and_perms(open, mask);
    return seal_as(OType::TypeKey, derived);
}

// `sys_seal`: Verifies `key` (`OType::TypeKey` with `Permit_Store`) and `obj`
// (16-byte aligned, unsealed, carries `Permit_Store | Permit_Store_Capability`,
// and spans a 16-byte header plus >= 1 byte of payload). Stores a
// permissionless, tagged `OType::TypeKey` copy of `key` into the 16-byte header
// at `obj`, and returns a capability addressed at the payload, bounded over
// header + payload, retaining `Permit_Load_Capability`, and sealed with
// `OType::SealedObject` (CT = 11).
inline Capability user_seal(Capability key, Capability obj) {
    if (!is_sealed_as(OType::TypeKey, key) ||
        (capability_get_perms(key) & perms::Store) == 0) {
        return nullptr;
    }
    if (!capability_is_valid(obj) || is_sealed(obj)) {
        return nullptr;
    }
    constexpr uint64_t kReqPerms =
        perms::Load | perms::LoadCapability | perms::Store | perms::StoreCapability;
    if ((capability_get_perms(obj) & kReqPerms) != kReqPerms) {
        return nullptr;
    }

    const uint64_t base = capability_get_base(obj);
    const uint64_t len  = capability_get_length(obj);
    const uint64_t addr = capability_get_address(obj);
    if (addr < base || addr > base + len ||
        (addr & (sizeof(Capability) - 1)) != 0 ||
        (base + len) - addr <= sizeof(Capability)) {
        return nullptr;
    }

    Capability bounded = obj;
    if (addr > base) {
        bounded = capability_set_bounds(obj, (base + len) - addr);
        if (!capability_is_valid(bounded)) {
            return nullptr;
        }
    }

    Capability open_key = unseal_as(OType::TypeKey, key);
    if (!capability_is_valid(open_key)) {
        return nullptr;
    }
    Capability stripped_key =
        seal_as(OType::TypeKey, capability_and_perms(open_key, 0));
    if (!capability_is_valid(stripped_key)) {
        return nullptr;
    }

    // Store the tagged, permissionless OType::TypeKey into the 16-byte header
    // and read it back to verify tag-capable memory.
    *reinterpret_cast<volatile Capability*>(bounded) = stripped_key;
    Capability readback = *reinterpret_cast<volatile Capability*>(bounded);
    if (!capability_is_valid(readback)) {
        return nullptr;
    }

    Capability handle_cap =
        capability_set_address(bounded, addr + sizeof(Capability));
    return seal_as(OType::SealedObject, handle_cap);
}

// `sys_unseal`: Verifies `key` (`OType::TypeKey` with `Permit_Load`) and
// `handle` (`OType::SealedObject`), checks that the 16-byte header preceding
// the payload holds a tagged `OType::TypeKey` capability whose address matches
// `key`, and returns a capability bounded strictly to the payload.
inline Capability user_unseal(Capability key, Capability handle) {
    if (!is_sealed_as(OType::TypeKey, key) ||
        (capability_get_perms(key) & perms::Load) == 0) {
        return nullptr;
    }

    Capability open = unseal_as(OType::SealedObject, handle);
    if (!capability_is_valid(open)) {
        return nullptr;
    }
    constexpr uint64_t kReqLoad = perms::Load | perms::LoadCapability;
    if ((capability_get_perms(open) & kReqLoad) != kReqLoad) {
        return nullptr;
    }

    const uint64_t base         = capability_get_base(open);
    const uint64_t len          = capability_get_length(open);
    const uint64_t payload_addr = capability_get_address(open);
    if (payload_addr < base + sizeof(Capability) ||
        payload_addr >= base + len ||
        (payload_addr & (sizeof(Capability) - 1)) != 0) {
        return nullptr;
    }

    Capability hdr_cap =
        capability_set_address(open, payload_addr - sizeof(Capability));
    Capability hdr = *reinterpret_cast<const Capability*>(hdr_cap);
    if (!capability_is_valid(hdr) || !is_sealed_as(OType::TypeKey, hdr) ||
        capability_get_address(hdr) != capability_get_address(key)) {
        return nullptr;
    }

    Capability payload =
        capability_set_bounds(open, (base + len) - payload_addr);
    return capability_is_valid(payload) ? payload : nullptr;
}

} // namespace signetos::sealing

