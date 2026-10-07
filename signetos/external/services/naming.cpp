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
 * naming.cpp - SignetOS User-Space Naming & Service Registry Compartment
 *
 * design_spec.md section 3.1.3: a registry where compartments publish and
 * query service sentries.
 *
 * Two operations, each its own `OType::EntryPoint` so a client only ever
 * holds the ones it was given (`abi.hpp`, `NamingRequest`):
 *
 *   publish(req)  records `req->name -> req->sentry`; refuses anything that
 *                 is not an `OType::EntryPoint`, duplicates, and a full table.
 *   lookup(req)   fills `req->sentry` with the published entry point, or
 *                 `nullptr` with `NAMING_NOT_FOUND`.
 *
 * On its first invocation (`arg` = init-owned `NamingInterface`) the
 * compartment mints both entry points over its own code and hands them back;
 * `init` then seeds `lookup` to every service and `publish` to those that
 * export entry points. The table is fixed-size `.bss`: no allocation, so the
 * compartment needs no memory authority at all beyond its own image.
 */

#include "runtime.hpp"

namespace signetos::user {
namespace {

// --- What `naming` asks `init` for (user/manifest.hpp) ------------------------
// `sentry` to mint `publish` and `lookup`; it hands both back to `init` in the
// `NamingInterface` handshake, and `init` decides who gets which.
#define NAMING_MANIFEST(X)                               \
  M_SYSCALL(X, SYS_SENTRY, sentry)                       \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)      \
  M_SERVICE(X, UART_SENTRY, "uart")
SIGNETOS_MANIFEST(NAMING_MANIFEST, 128 * 1024)
// Runtime slots: the two entry points minted in the handshake.
constexpr size_t SLOT_PUBLISH_ENTRY = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 0;
constexpr size_t SLOT_LOOKUP_ENTRY  = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 1;

constexpr size_t MAX_ENTRIES = 64;

struct alignas(16) Entry {
  char name[init::NAME_MAX];
  Capability sentry;
};

Entry s_table[MAX_ENTRIES];
size_t s_count = 0;

// Reads a NUL-terminated name from a Load capability into `out` (1..NAME_MAX-1
// bytes). Returns false if `name_cap` is invalid, sealed, lacks Load, or is not
// NUL-terminated within `NAME_MAX`.
bool read_name(Capability name_cap, char (&out)[init::NAME_MAX]) {
  if (!capability_is_valid(name_cap) || sealing::is_sealed(name_cap) ||
      !capability_has_perms(name_cap, perms::Load)) {
    return false;
  }
  const uint64_t end =
      capability_get_base(name_cap) + capability_get_length(name_cap);
  const uint64_t addr = capability_get_address(name_cap);
  if (end <= addr) {
    return false;
  }
  const uint64_t avail = end - addr;
  const size_t limit =
      avail < init::NAME_MAX ? static_cast<size_t>(avail) : init::NAME_MAX;
  const auto* src = reinterpret_cast<const char*>(name_cap);
  for (size_t i = 0; i < limit; ++i) {
    out[i] = src[i];
    if (out[i] == '\0') {
      for (size_t j = i + 1; j < init::NAME_MAX; ++j) {
        out[j] = '\0';
      }
      return i > 0;
    }
  }
  return false;
}

bool same_name(const char* a, const char* b) {
  for (size_t i = 0; i < init::NAME_MAX; ++i) {
    if (a[i] != b[i]) {
      return false;
    }
    if (a[i] == '\0') {
      return true;
    }
  }
  return true;
}

Entry* find(const char* name) {
  for (size_t i = 0; i < s_count; ++i) {
    if (same_name(s_table[i].name, name)) {
      return &s_table[i];
    }
  }
  return nullptr;
}

}  // namespace

extern "C" int64_t naming_publish_entry(Capability name_cap,
                                        Capability sentry) {
  char name[init::NAME_MAX];
  if (!read_name(name_cap, name) ||
      !sealing::is_sealed_as(OType::EntryPoint, sentry)) {
    return init::NAMING_BAD_REQUEST;
  }
  if (find(name) != nullptr) {
    return init::NAMING_EXISTS;
  }
  if (s_count >= MAX_ENTRIES) {
    return init::NAMING_FULL;
  }
  Entry& e = s_table[s_count];
  for (size_t i = 0; i < init::NAME_MAX; ++i) {
    e.name[i] = name[i];
  }
  e.sentry = sentry;
  s_count += 1;
  return init::NAMING_OK;
}

extern "C" Capability naming_lookup_entry(Capability name_cap) {
  char name[init::NAME_MAX];
  if (!read_name(name_cap, name)) {
    return init::status_cap(init::NAMING_BAD_REQUEST);
  }
  Entry* e = find(name);
  if (e == nullptr) {
    return init::status_cap(init::NAMING_NOT_FOUND);
  }
  return e->sentry;
}

extern "C" int64_t compartment_main(Capability arg) {
  Capability* rw = rw_table();

  Capability self_comp = rw[compartment::SLOT_SELF];
  Capability gate_sentry = rw[SLOT_SYS_SENTRY];
  Capability gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  Capability uart_sentry = rw[SLOT_UART_SENTRY];

  if (!sealing::is_sealed_as(OType::Compartment, self_comp)) {
    return -1;
  }

  // Hand the two operation entry points back to the caller (`init`).
  if (capability_is_valid(arg) &&
      capability_get_length(arg) >= sizeof(init::NamingInterface)) {
    auto* iface = reinterpret_cast<init::NamingInterface*>(arg);
    iface->publish = mint_entry(gate_invoke, gate_sentry, self_comp,
                                reinterpret_cast<const void*>(
                                    &naming_publish_entry));
    iface->lookup = mint_entry(gate_invoke, gate_sentry, self_comp,
                               reinterpret_cast<const void*>(
                                   &naming_lookup_entry));
    rw[SLOT_PUBLISH_ENTRY] = iface->publish;
    rw[SLOT_LOOKUP_ENTRY] = iface->lookup;
  }

  print(gate_invoke, uart_sentry,
        "[naming]   Service registry online (publish/lookup entry points)\n");
  return 0;
}

}  // namespace signetos::user
