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
// vseal.hpp - Compartment-minted sealing types ("virtual sealing")
//
// Hardware object types are scarce (CT is five bits) and fixed at boot. This
// library lets any number of private object types share two of them,
// `OType::TypeKey` and `OType::SealedObject` (CORE_DESIGN.md §2.3):
//
//   1. A TYPE is named by the address of a 16-byte record in its owner's own
//      memory. `mint` returns that record capability, bounded to the record
//      and sealed as `TypeKey`: the KEY. Nothing reads or writes the record;
//      uniqueness follows from memory ownership, so there is no registry.
//      Permit_Store on the key authorises sealing, Permit_Load unsealing, and
//      `derive` re-issues a key with fewer of the two.
//   2. A SEALED OBJECT is a 16-byte header followed by the payload:
//
//        | header: tagged, permissionless copy of the key | payload |
//                                                           ^ address of the
//                                                             handle, and of
//                                                             the payload
//
//      `seal` writes the header through the caller's own capability to the
//      object and returns a handle over header and payload, sealed as
//      `SealedObject`. `unseal` checks that the header holds a TAGGED TypeKey
//      at the key's address and returns the payload alone, bounded so that
//      the holder cannot reach the header and retype the object.
//   3. The header is a capability rather than a type number because whoever
//      sealed the object still holds a writable capability to it: a number
//      could be overwritten, a tagged capability cannot be forged by a store.
//   4. A type lives as long as its record: when the record's memory is freed
//      and swept, every key and every header copy -- all based at the record
//      -- loses its tag and every object of the type becomes unopenable.
//
// WHO RUNS IT
//   Sealing with a hardware type takes that type's Zyseal authority. Whoever
//   holds the `TypeKey` authority can make a key for ANY record address, and
//   so open anyone's objects; the two authorities therefore belong to exactly
//   one compartment, the `sealer` service (external/services/sealer.cpp),
//   which `init` grants them to and which offers these four operations as the
//   `seal.mint`, `seal.derive`, `seal.seal` and `seal.unseal` entry points.
//   Clients trust the sealer for the integrity of their type system, as they
//   trust the scheduler for CPU time; the sealer holds no capability to any
//   client's memory beyond what each call hands it.
//
//   Any compartment that holds SOME pair of type authorities can instantiate
//   this library over them; nothing here is specific to the sealer.
//
// FAILURE
//   Every operation returns a null capability when refused; there is no
//   status channel, as there was none in the kernel calls these replace.
//

#include <stdint.h>
#include <stddef.h>
#include <signetos/sealing.hpp>
#include <signetos/types.hpp>

namespace signetos::user::vseal {

// The two Zyseal authorities, as `init` seeds them (`M_OTYPE`): each is an
// unsealed capability whose address names its OType, bounded to that one
// type, with Permit_Seal and Permit_Unseal and no memory permission.
struct Authority {
  Capability key;     // over OType::TypeKey
  Capability object;  // over OType::SealedObject
};

// True if `a` is a usable pair: each authority tagged, unsealed, carrying
// both Seal and Unseal, and naming exactly its own OType.
inline bool authority_ok(const Authority& a) {
  auto one = [](Capability c, OType t) {
    return capability_is_valid(c) && !sealing::is_sealed(c) &&
           capability_has_perms(c, perms::Seal | perms::Unseal) &&
           capability_get_base(c) == static_cast<uint64_t>(t) &&
           capability_get_address(c) == static_cast<uint64_t>(t) &&
           capability_get_length(c) == 1;
  };
  return one(a.key, OType::TypeKey) && one(a.object, OType::SealedObject);
}

// Mints the key of the type named by `record`'s address: `record` bounded to
// 16 bytes, restricted to Permit_Load | Permit_Store, sealed as TypeKey.
// `record` must be tagged, unsealed, carry Permit_Store (so that the minter
// owns the memory and not merely a view of it), be 16-byte aligned, and have
// 16 bytes available from its address.
inline Capability mint(const Authority& a, Capability record) {
  if (!capability_is_valid(record) || sealing::is_sealed(record)) {
    return nullptr;
  }
  if ((capability_get_perms(record) & perms::Store) == 0) {
    return nullptr;
  }
  const uint64_t base = capability_get_base(record);
  const uint64_t len = capability_get_length(record);
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
  return sealing::seal_with(a.key, key);
}

// Re-issues `key` (a TypeKey) with `permissions & (Permit_Load |
// Permit_Store)`: a key that can only seal, or only unseal. Rights can only
// be dropped; the result is sealed as TypeKey again.
inline Capability derive(const Authority& a, Capability key,
                         uint32_t permissions) {
  Capability open = sealing::unseal_with(a.key, key);
  if (!capability_is_valid(open)) {
    return nullptr;
  }
  const uint64_t mask =
      static_cast<uint64_t>(permissions) & (perms::Load | perms::Store);
  return sealing::seal_with(a.key, capability_and_perms(open, mask));
}

// Seals `obj` under `key`, which must carry Permit_Store. `obj` must be
// unsealed, carry Load | LoadCapability | Store | StoreCapability (the header
// is written through it, and the handle keeps its permissions), be 16-byte
// aligned at its address, and span the 16-byte header plus at least one byte
// of payload. Writes a tagged, permissionless copy of the key into the header
// and returns a capability addressed at the payload, bounded from the header
// to the end of `obj`, sealed as SealedObject.
inline Capability seal(const Authority& a, Capability key, Capability obj) {
  if (!sealing::is_sealed_as(OType::TypeKey, key) ||
      (capability_get_perms(key) & perms::Store) == 0) {
    return nullptr;
  }
  if (!capability_is_valid(obj) || sealing::is_sealed(obj)) {
    return nullptr;
  }
  constexpr uint64_t kReqPerms = perms::Load | perms::LoadCapability |
                                 perms::Store | perms::StoreCapability;
  if ((capability_get_perms(obj) & kReqPerms) != kReqPerms) {
    return nullptr;
  }

  const uint64_t base = capability_get_base(obj);
  const uint64_t len = capability_get_length(obj);
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

  // The header copy: the key with every access permission stripped, so that
  // reading an object's header yields nothing usable, sealed as TypeKey so
  // that only a holder of the authority could have made it.
  Capability open_key = sealing::unseal_with(a.key, key);
  if (!capability_is_valid(open_key)) {
    return nullptr;
  }
  Capability stripped_key =
      sealing::seal_with(a.key, capability_and_perms(open_key, 0));
  if (!capability_is_valid(stripped_key)) {
    return nullptr;
  }

  // Written through the caller's capability, and read back: memory that does
  // not keep tags (a device window) cannot hold a sealed object.
  *reinterpret_cast<volatile Capability*>(bounded) = stripped_key;
  Capability readback = *reinterpret_cast<volatile Capability*>(bounded);
  if (!capability_is_valid(readback)) {
    return nullptr;
  }

  Capability handle_cap =
      capability_set_address(bounded, addr + sizeof(Capability));
  return sealing::seal_with(a.object, handle_cap);
}

// Opens `handle` (a SealedObject) under `key`, which must carry Permit_Load:
// the header just below the payload must hold a TAGGED TypeKey whose address
// is the key's. Returns the payload, bounded to exclude the header, with the
// permissions the object was sealed with.
inline Capability unseal(const Authority& a, Capability key,
                         Capability handle) {
  if (!sealing::is_sealed_as(OType::TypeKey, key) ||
      (capability_get_perms(key) & perms::Load) == 0) {
    return nullptr;
  }

  Capability open = sealing::unseal_with(a.object, handle);
  if (!capability_is_valid(open)) {
    return nullptr;
  }
  constexpr uint64_t kReqLoad = perms::Load | perms::LoadCapability;
  if ((capability_get_perms(open) & kReqLoad) != kReqLoad) {
    return nullptr;
  }

  const uint64_t base = capability_get_base(open);
  const uint64_t len = capability_get_length(open);
  const uint64_t payload_addr = capability_get_address(open);
  if (payload_addr < base + sizeof(Capability) || payload_addr >= base + len ||
      (payload_addr & (sizeof(Capability) - 1)) != 0) {
    return nullptr;
  }

  Capability hdr_cap =
      capability_set_address(open, payload_addr - sizeof(Capability));
  Capability hdr = *reinterpret_cast<const volatile Capability*>(hdr_cap);
  if (!capability_is_valid(hdr) || !sealing::is_sealed_as(OType::TypeKey, hdr) ||
      capability_get_address(hdr) != capability_get_address(key)) {
    return nullptr;
  }

  Capability payload = capability_set_bounds(open, (base + len) - payload_addr);
  return capability_is_valid(payload) ? payload : nullptr;
}

}  // namespace signetos::user::vseal
