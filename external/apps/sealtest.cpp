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
 * sealtest.cpp - A program that exercises compartment-minted sealing types
 *
 * `run sealtest.bin` from the shell (or `sealtest`, which also runs the
 * lifetime check only a memory holder can make). The program is an ordinary
 * client of the `sealer` service (external/services/sealer.cpp): its manifest
 * asks the shell for the four `seal.*` entry points by name, and everything it
 * seals lives in its own `.bss`. It checks, as a peer would see them, the
 * properties CORE_DESIGN.md §2.3 promises:
 *
 *   - a key names its record and nothing else; minting refuses memory the
 *     caller only reads, and records that are misaligned or too small;
 *   - an object sealed under a key opens under that key, and under no other,
 *     to exactly its payload: the header is out of bounds of what comes back;
 *   - a key derived without Permit_Store cannot seal and one derived without
 *     Permit_Load cannot unseal, and neither right comes back by deriving;
 *   - a header rewritten by hand -- a byte copy, or a tagged capability that
 *     is not a TypeKey -- opens nothing; only a holder of the backing memory
 *     AND a key of another type can retype an object, which is the reason
 *     typed memory must stay private to its minter;
 *   - what is not a key, or not a handle, is refused wherever one is needed;
 *   - and, under toolchain/sentries, that a compartment cannot make a call
 *     sentry of its own: `sentry` and `cbld` refuse, so the only one it holds
 *     is the switcher gate the kernel sealed.
 *
 * Exit status is the number of failed checks (0: all passed).
 */

#include "runtime.hpp"

namespace signetos::user {
namespace {

// --- What `sealtest` asks the shell for (user/manifest.hpp) ------------------
#define SEALTEST_MANIFEST(X)                                                \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)                         \
  M_SERVICE(X, UART_SENTRY, "uart")                                         \
  M_SERVICE(X, SEAL_MINT, "seal.mint")                                      \
  M_SERVICE(X, SEAL_DERIVE, "seal.derive")                                  \
  M_SERVICE(X, SEAL_SEAL, "seal.seal")                                      \
  M_SERVICE(X, SEAL_UNSEAL, "seal.unseal")
SIGNETOS_MANIFEST(SEALTEST_MANIFEST, 64 * 1024)

Capability s_invoke = nullptr;
Capability s_uart = nullptr;
Capability s_mint = nullptr;
Capability s_derive = nullptr;
Capability s_seal = nullptr;
Capability s_unseal = nullptr;

uint64_t s_checks = 0;
uint64_t s_failed = 0;

// Two type records and three objects, all in this program's own memory.
constexpr size_t PAYLOAD = 48;
constexpr size_t OBJECT = sizeof(Capability) + PAYLOAD;
alignas(16) Capability s_record_a[1];
alignas(16) Capability s_record_b[1];
alignas(16) uint8_t s_obj_a[OBJECT];
alignas(16) uint8_t s_obj_b[OBJECT];
alignas(16) uint8_t s_obj_c[OBJECT];

void out(const char* msg) { print(s_invoke, s_uart, msg); }

void check(const char* what, bool ok) {
  s_checks += 1;
  if (!ok) {
    s_failed += 1;
    out("[sealtest] FAILED: ");
    out(what);
    out("\n");
  }
}

template <typename T>
Capability cap_of(T* p, size_t len = sizeof(T)) {
  return capability_set_bounds(reinterpret_cast<Capability>(p), len);
}

Capability mint(Capability record) {
  return invoke<Capability>(s_invoke, s_mint, record);
}
Capability derive(Capability key, uint32_t permissions) {
  return invoke<Capability>(s_invoke, s_derive, key, permissions);
}
Capability seal(Capability key, Capability obj) {
  return invoke<Capability>(s_invoke, s_seal, key, obj);
}
Capability unseal(Capability key, Capability handle) {
  return invoke<Capability>(s_invoke, s_unseal, key, handle);
}

bool is_key(Capability c) {
  return sealing::is_sealed_as(OType::TypeKey, c);
}
bool is_handle(Capability c) {
  return sealing::is_sealed_as(OType::SealedObject, c);
}
uint64_t addr(const void* p) {
  return capability_get_address(reinterpret_cast<Capability>(const_cast<void*>(p)));
}

void fill(uint8_t* p, size_t n, uint8_t seed) {
  for (size_t i = 0; i < n; ++i) {
    p[i] = static_cast<uint8_t>(seed + i);
  }
}
bool payload_is(Capability payload, uint8_t seed) {
  const auto* p = reinterpret_cast<const uint8_t*>(payload);
  for (size_t i = 0; i < PAYLOAD; ++i) {
    if (p[i] != static_cast<uint8_t>(seed + i)) {
      return false;
    }
  }
  return true;
}

void run_checks() {
  // --- Keys ------------------------------------------------------------------
  const Capability rec_a = cap_of(&s_record_a[0]);
  const Capability rec_b = cap_of(&s_record_b[0]);
  const Capability key_a = mint(rec_a);
  const Capability key_b = mint(rec_b);
  check("mint returns a TypeKey", is_key(key_a) && is_key(key_b));
  check("a key is bounded to its 16-byte record",
        capability_get_address(key_a) == addr(s_record_a) &&
            capability_get_base(key_a) == addr(s_record_a) &&
            capability_get_length(key_a) == sizeof(Capability));
  check("a fresh key carries Load and Store",
        capability_has_perms(key_a, perms::Load | perms::Store));
  check("minting a read-only record is refused",
        !capability_is_valid(mint(capability_and_perms(rec_a, perms::Load))));
  check("minting a misaligned record is refused",
        !capability_is_valid(
            mint(capability_set_address(cap_of(&s_obj_c[0], OBJECT),
                                        addr(s_obj_c) + 8))));
  check("minting a record shorter than 16 bytes is refused",
        !capability_is_valid(mint(cap_of(&s_obj_c[0], 8))));
  check("minting from a sealed capability is refused",
        !capability_is_valid(mint(key_a)));

  // --- Seal and unseal -------------------------------------------------------
  fill(&s_obj_a[sizeof(Capability)], PAYLOAD, 0x10);
  const Capability obj_a = cap_of(&s_obj_a[0], OBJECT);
  const Capability h_a = seal(key_a, obj_a);
  check("seal returns a SealedObject", is_handle(h_a));
  check("the handle is addressed at the payload and spans the header too",
        capability_get_address(h_a) == addr(s_obj_a) + sizeof(Capability) &&
            capability_get_base(h_a) == addr(s_obj_a) &&
            capability_get_length(h_a) == OBJECT);
  check("the header holds a tagged TypeKey at the key's address",
        is_key(s_record_a[0]) == false &&  // the record itself is untouched
            is_key(*reinterpret_cast<volatile Capability*>(&s_obj_a[0])) &&
            capability_get_address(
                *reinterpret_cast<volatile Capability*>(&s_obj_a[0])) ==
                addr(s_record_a));
  check("the header copy carries no permissions",
        (capability_get_perms(
             *reinterpret_cast<volatile Capability*>(&s_obj_a[0])) &
         (perms::Load | perms::Store | perms::LoadCapability |
          perms::StoreCapability | perms::Execute)) == 0);

  const Capability p_a = unseal(key_a, h_a);
  check("unseal under the right key returns the payload",
        capability_is_valid(p_a) && !sealing::is_sealed(p_a));
  check("the payload excludes the header",
        capability_get_base(p_a) == addr(s_obj_a) + sizeof(Capability) &&
            capability_get_length(p_a) == PAYLOAD);
  check("the payload reads back intact",
        capability_is_valid(p_a) && payload_is(p_a, 0x10));
  check("the payload keeps the object's permissions",
        capability_has_perms(p_a, perms::Load | perms::Store));
  check("unseal under another type's key is refused",
        !capability_is_valid(unseal(key_b, h_a)));

  // --- Derived keys ----------------------------------------------------------
  const Capability k_open = derive(key_a, perms::Load);
  const Capability k_seal = derive(key_a, perms::Store);
  check("derive returns TypeKeys", is_key(k_open) && is_key(k_seal));
  check("derive keeps only the rights asked for",
        !capability_has_perms(k_open, perms::Store) &&
            !capability_has_perms(k_seal, perms::Load));
  check("an unseal-only key opens objects",
        capability_is_valid(unseal(k_open, h_a)));
  fill(&s_obj_b[sizeof(Capability)], PAYLOAD, 0x40);
  const Capability obj_b = cap_of(&s_obj_b[0], OBJECT);
  check("an unseal-only key cannot seal",
        !capability_is_valid(seal(k_open, obj_b)));
  const Capability h_b = seal(k_seal, obj_b);
  check("a seal-only key seals", is_handle(h_b));
  check("a seal-only key cannot unseal",
        !capability_is_valid(unseal(k_seal, h_b)));
  check("what a seal-only key sealed opens under the full key",
        capability_is_valid(unseal(key_a, h_b)) &&
            payload_is(unseal(key_a, h_b), 0x40));
  const Capability k_regrown = derive(k_open, perms::Load | perms::Store);
  check("deriving cannot regain a dropped right",
        is_key(k_regrown) && !capability_has_perms(k_regrown, perms::Store) &&
            !capability_is_valid(seal(k_regrown, cap_of(&s_obj_c[0], OBJECT))));

  // --- Forged headers --------------------------------------------------------
  // The owner of the memory can write the header; nothing it writes by hand
  // is a tagged TypeKey.
  volatile Capability* hdr_a = reinterpret_cast<volatile Capability*>(&s_obj_a[0]);
  const Capability genuine = *hdr_a;
  {
    // A byte-for-byte copy of the genuine header: the tag does not survive.
    alignas(16) uint8_t copy[sizeof(Capability)];
    const auto* src = reinterpret_cast<const volatile uint8_t*>(&s_obj_a[0]);
    for (size_t i = 0; i < sizeof(Capability); ++i) {
      copy[i] = src[i];
    }
    auto* dst = reinterpret_cast<volatile uint8_t*>(&s_obj_a[0]);
    for (size_t i = 0; i < sizeof(Capability); ++i) {
      dst[i] = copy[i];
    }
  }
  check("a byte-copied header is untagged and opens nothing",
        !capability_is_valid(*hdr_a) && !capability_is_valid(unseal(key_a, h_a)));
  *hdr_a = rec_a;  // tagged, right address, but not a TypeKey
  check("an unsealed capability in the header opens nothing",
        !capability_is_valid(unseal(key_a, h_a)));
  *hdr_a = genuine;
  check("the genuine header restored, the object opens again",
        capability_is_valid(unseal(key_a, h_a)));
  // The one thing a memory holder can do: retype an object with a key it
  // holds. It gains nothing it did not have -- it could read the payload
  // through its own capability already -- but it is why typed memory must
  // stay private (CORE_DESIGN.md §2.3).
  *hdr_a = key_b;
  check("the memory's owner can retype an object with another key it holds",
        !capability_is_valid(unseal(key_a, h_a)) &&
            capability_is_valid(unseal(key_b, h_a)));
  *hdr_a = genuine;

  // --- Refusals --------------------------------------------------------------
  check("sealing a read-only object is refused",
        !capability_is_valid(seal(
            key_a, capability_and_perms(cap_of(&s_obj_c[0], OBJECT),
                                        perms::Load | perms::LoadCapability))));
  check("sealing a misaligned object is refused",
        !capability_is_valid(seal(
            key_a, capability_set_address(cap_of(&s_obj_c[0], OBJECT),
                                          addr(s_obj_c) + 8))));
  check("sealing an object with no room for a payload is refused",
        !capability_is_valid(seal(key_a, cap_of(&s_obj_c[0], sizeof(Capability)))));
  check("sealing a sealed handle is refused",
        !capability_is_valid(seal(key_a, h_a)));
  check("sealing with something that is not a key is refused",
        !capability_is_valid(seal(rec_a, cap_of(&s_obj_c[0], OBJECT))) &&
            !capability_is_valid(seal(h_a, cap_of(&s_obj_c[0], OBJECT))));
  check("unsealing something that is not a handle is refused",
        !capability_is_valid(unseal(key_a, obj_a)) &&
            !capability_is_valid(unseal(key_a, key_b)));
  check("unsealing with something that is not a key is refused",
        !capability_is_valid(unseal(rec_a, h_a)) &&
            !capability_is_valid(unseal(h_b, h_a)));
  check("deriving from something that is not a key is refused",
        !capability_is_valid(derive(rec_a, perms::Load)) &&
            !capability_is_valid(derive(h_a, perms::Load)));
  check("null arguments are refused",
        !capability_is_valid(mint(nullptr)) &&
            !capability_is_valid(derive(nullptr, perms::Load)) &&
            !capability_is_valid(seal(key_a, nullptr)) &&
            !capability_is_valid(seal(nullptr, obj_a)) &&
            !capability_is_valid(unseal(key_a, nullptr)) &&
            !capability_is_valid(unseal(nullptr, h_a)));

  // --- Call sentries (toolchain/sentries) ------------------------------------
  // Only the holder of a type 1 authority makes a call sentry, and here that
  // is the kernel: holding its own code is not enough for a compartment.
  check("the switcher gate is a call sentry",
        capability_is_valid(s_invoke) &&
            sealing::type_of(s_invoke) == static_cast<uint64_t>(OType::Sentry));
  Capability pcc;
  __asm__ volatile("auipcc %0, 0" : "=C"(pcc));
  Capability made;
  __asm__ volatile("sentry %0, %1" : "=C"(made) : "C"(pcc));
  check("`sentry` makes no call sentry from a compartment's own code",
        !capability_is_valid(made));
  // `made` is a call sentry's bits without the tag: cbld must not tag them.
  const Capability rebuilt = __builtin_cheri_cap_build(pcc, (__uintcap_t)made);
  check("`cbld` rebuilds no call sentry from a call sentry's bits",
        sealing::type_of(made) == static_cast<uint64_t>(OType::Sentry) &&
            !capability_is_valid(rebuilt));
}

}  // namespace

SIGNETOS_DEFAULT_FAULT_HANDLER("sealtest")

extern "C" int64_t compartment_main(Capability arg) {
  Capability* rw = rw_table();
  s_invoke = rw[SLOT_SYS_COMP_INVOKE];
  s_uart = rw[SLOT_UART_SENTRY];
  if (!sealing::is_sealed_as(OType::EntryPoint, s_uart)) {
    return -1;
  }
  auto* req = (capability_is_valid(arg) && !sealing::is_sealed(arg) &&
               capability_has_perms(arg, perms::Load | perms::Store) &&
               capability_get_length(arg) >= sizeof(init::AppRequest))
                  ? reinterpret_cast<init::AppRequest*>(arg)
                  : nullptr;

  s_mint = rw[SLOT_SEAL_MINT];
  s_derive = rw[SLOT_SEAL_DERIVE];
  s_seal = rw[SLOT_SEAL_SEAL];
  s_unseal = rw[SLOT_SEAL_UNSEAL];
  if (!sealing::is_sealed_as(OType::EntryPoint, s_mint) ||
      !sealing::is_sealed_as(OType::EntryPoint, s_derive) ||
      !sealing::is_sealed_as(OType::EntryPoint, s_seal) ||
      !sealing::is_sealed_as(OType::EntryPoint, s_unseal)) {
    out("[sealtest] the seal.* entry points were not granted\n");
    if (req != nullptr) {
      req->status = -1;
    }
    return -1;
  }

  s_checks = 0;
  s_failed = 0;
  run_checks();

  if (s_failed == 0) {
    print_dec(s_invoke, s_uart, "[sealtest] all ", s_checks, " checks passed\n");
  } else {
    print_dec(s_invoke, s_uart, "[sealtest] ", s_failed, " of ");
    print_dec(s_invoke, s_uart, "", s_checks, " checks FAILED\n");
  }
  const int64_t status = static_cast<int64_t>(s_failed);
  if (req != nullptr) {
    req->status = status;
  }
  return status;
}

}  // namespace signetos::user
