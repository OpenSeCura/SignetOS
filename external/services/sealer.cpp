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
 * sealer.cpp - SignetOS User-Space Sealing Service Compartment
 *
 * The one holder of the `OType::TypeKey` and `OType::SealedObject` sealing
 * authorities, which `init` grants it (user/manifest.hpp, M_OTYPE), and so
 * the compartment that runs compartment-minted sealing types for everyone
 * else (user/vseal.hpp; CORE_DESIGN.md §2.3). Four operations, each its own
 * `OType::EntryPoint`, published by name so that a launcher can grant a
 * client exactly the ones it asks for (abi.hpp, "Sealing service"):
 *
 *   seal.mint(record)             -> type key, or null
 *   seal.derive(key, perms)       -> key with a subset of its rights, or null
 *   seal.seal(key, obj)           -> sealed object handle, or null
 *   seal.unseal(key, handle)      -> the object's payload, or null
 *
 * These were kernel calls once (`sys_type_mint` and friends). They never
 * needed anything of the kernel's but the two authorities -- no lock, no
 * memory, no table -- so they are a service now and the kernel is that much
 * smaller. What changes for a caller: the calls run on its thread with
 * interrupts in whatever state it had them, and an object on a page that is
 * out in swap is faulted in rather than refused.
 *
 * WHAT IT HOLDS
 *   The two authorities, `sentry` to mint its entries, the switcher, the
 *   console and `naming.publish`. No VM quota beyond the image `init` funds:
 *   nothing here allocates, and the only memory it ever touches outside its
 *   own is the 16-byte header of an object a caller hands it, through the
 *   caller's own capability. Whoever holds the `TypeKey` authority could
 *   mint a key to any record and open any object it is handed, so a client
 *   trusts the sealer for the integrity of its type system -- and for
 *   nothing else, since the sealer can reach nothing it is not handed.
 *
 * On its first invocation (from `init`, once `naming` is up) the compartment
 * mints the four entry points over its own code, publishes them, and returns;
 * nothing is handed back to the caller. It is never entered again except
 * through those entries.
 */

#include "runtime.hpp"
#include "vseal.hpp"

namespace signetos::user {
namespace {

// --- What `sealer` asks `init` for (user/manifest.hpp) -----------------------
#define SEALER_MANIFEST(X)                                   \
  M_OTYPE(X, SEAL_KEY, ::signetos::OType::TypeKey)           \
  M_OTYPE(X, SEAL_OBJECT, ::signetos::OType::SealedObject)   \
  M_SYSCALL(X, SYS_SENTRY, sentry)                           \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)          \
  M_SERVICE(X, UART_SENTRY, "uart")                          \
  M_SERVICE(X, NAMING_PUBLISH, "naming.publish")
SIGNETOS_MANIFEST(SEALER_MANIFEST, 128 * 1024)

// Runtime slots: the four entry points minted at startup, kept so that the
// table records everything this compartment has made.
constexpr size_t SLOT_MINT_ENTRY   = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 0;
constexpr size_t SLOT_DERIVE_ENTRY = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 1;
constexpr size_t SLOT_SEAL_ENTRY   = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 2;
constexpr size_t SLOT_UNSEAL_ENTRY = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 3;

// The authorities, copied out of the table once they have been checked.
vseal::Authority s_auth;
bool s_online = false;

}  // namespace

SIGNETOS_DEFAULT_FAULT_HANDLER("sealer")

extern "C" Capability sealer_mint_entry(Capability record) {
  return vseal::mint(s_auth, record);
}

extern "C" Capability sealer_derive_entry(Capability key, uint32_t permissions) {
  return vseal::derive(s_auth, key, permissions);
}

extern "C" Capability sealer_seal_entry(Capability key, Capability obj) {
  return vseal::seal(s_auth, key, obj);
}

extern "C" Capability sealer_unseal_entry(Capability key, Capability handle) {
  return vseal::unseal(s_auth, key, handle);
}

extern "C" int64_t compartment_main(Capability arg) {
  (void)arg;  // nothing is handed back: the entries are published by name
  Capability* rw = rw_table();

  const Capability self_comp = rw[compartment::SLOT_SELF];
  const Capability gate_sentry = rw[SLOT_SYS_SENTRY];
  const Capability gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  const Capability uart_sentry = rw[SLOT_UART_SENTRY];
  const Capability naming_publish = rw[SLOT_NAMING_PUBLISH];

  if (s_online) {
    return -1;  // set up once, by `init`
  }
  s_auth.key = rw[SLOT_SEAL_KEY];
  s_auth.object = rw[SLOT_SEAL_OBJECT];
  if (!sealing::is_sealed_as(OType::Compartment, self_comp) ||
      !sealing::is_sealed_as(OType::EntryPoint, gate_sentry) ||
      !sealing::is_entry(gate_invoke) ||
      !sealing::is_sealed_as(OType::EntryPoint, naming_publish) ||
      !vseal::authority_ok(s_auth)) {
    s_auth.key = nullptr;
    s_auth.object = nullptr;
    return -1;
  }

  struct Op {
    const char* name;
    const void* fn;
    size_t slot;
  };
  const Op ops[] = {
      {"seal.mint", reinterpret_cast<const void*>(&sealer_mint_entry),
       SLOT_MINT_ENTRY},
      {"seal.derive", reinterpret_cast<const void*>(&sealer_derive_entry),
       SLOT_DERIVE_ENTRY},
      {"seal.seal", reinterpret_cast<const void*>(&sealer_seal_entry),
       SLOT_SEAL_ENTRY},
      {"seal.unseal", reinterpret_cast<const void*>(&sealer_unseal_entry),
       SLOT_UNSEAL_ENTRY},
  };
  for (const Op& op : ops) {
    const Capability entry = mint_entry(gate_invoke, gate_sentry, self_comp, op.fn);
    if (!sealing::is_sealed_as(OType::EntryPoint, entry) ||
        publish_name(gate_invoke, naming_publish, op.name, entry) !=
            init::NAMING_OK) {
      print(gate_invoke, uart_sentry,
            "[sealer]   WARNING: could not mint or publish an entry point\n");
      s_auth.key = nullptr;
      s_auth.object = nullptr;
      return -1;
    }
    rw[op.slot] = entry;
  }
  s_online = true;

  print(gate_invoke, uart_sentry,
        "[sealer]   Sealing service online: seal.* published\n");
  return 0;
}

}  // namespace signetos::user
