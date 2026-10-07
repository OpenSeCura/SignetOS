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
 * inspect.cpp - SignetOS outbound capability assertion
 *
 * `assert_user_capability` is called at every point where a capability leaves
 * the kernel for a user compartment (syscall gate return, cross-compartment
 * switch, thread creation, trap delivery, init seed table and manifest). It
 * panics the machine if the capability would grant authority the kernel never
 * intends to delegate.
 *
 * What it does NOT try to do: re-prove the shape of every kernel-minted handle.
 * Compartment code derives from `sentry::s_root_code_cap`, user memory from
 * `vm::s_dynamic`, kernel objects from page-backed descriptors; the minting
 * code for each is unit-tested and CHERI monotonicity does the rest. The checks
 * here are the ones with teeth against a kernel bug that leaks real authority.
 */

#include <signetos/inspect.hpp>
#include <signetos/platform.hpp>
#include <signetos/sealing.hpp>
#include <signetos/sentry.hpp>
#include <signetos/uart.hpp>
#include <signetos/vm.hpp>

namespace signetos::inspect {
namespace {

// Reads the 64-bit link-time address of a linker script symbol via PC-relative
// `llc` (`auipcc` + `caddi`) without emitting a `.got` or `__cap_relocs` entry.
#define KERNEL_SYM_ADDR(sym)                         \
  ([]() -> uint64_t {                                \
    Capability c;                                    \
    __asm__ volatile("llc %0, " #sym : "=C"(c));     \
    return capability_get_address(c);                \
  }())

// Link-time layout of the kernel image, as plain integers so that caching it
// in `.bss` leaves no capability behind. Filled on first use.
struct KernelLayout {
  uint64_t k_start;
  uint64_t rodata_start;
  uint64_t rodata_end;
  uint64_t got_end;
  uint64_t bss_start;
  uint64_t bss_end;
  bool ready;
};

KernelLayout s_layout;

const KernelLayout& layout() {
  if (!s_layout.ready) {
    s_layout.k_start = KERNEL_SYM_ADDR(_kernel_start);
    s_layout.rodata_start = KERNEL_SYM_ADDR(_rodata_start);
    s_layout.rodata_end = KERNEL_SYM_ADDR(_rodata_end);
    s_layout.got_end = KERNEL_SYM_ADDR(_got_end);
    s_layout.bss_start = KERNEL_SYM_ADDR(_bss_start);
    s_layout.bss_end = KERNEL_SYM_ADDR(_bss_end);
    s_layout.ready = true;
  }
  return s_layout;
}

#undef KERNEL_SYM_ADDR

[[noreturn]] void panic(const char* site, const char* reason, Capability cap) {
  uart::print(
      "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
      "!!!!!!!!!!\n");
  uart::print("[SECURITY PANIC] Outbound capability violation at ");
  uart::print(site != nullptr ? site : "<unknown>");
  uart::print("\n  Reason: ");
  uart::print(reason);
  uart::print("\n");
  uart::print_cap("  Offending Cap", cap);
  uart::print(
      "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
      "!!!!!!!!\n");
  uart::qemu_poweroff(1);
  while (true) {
  }
}

inline bool within(uint64_t base, uint64_t top, uint64_t lo, uint64_t hi) {
  return base >= lo && top <= hi;
}

}  // namespace

void assert_user_capability(Capability cap, const char* site) {
  // Null or untagged capabilities grant no authority.
  if (!capability_is_valid(cap)) {
    return;
  }

  const uint64_t base = capability_get_base(cap);
  const uint64_t len = capability_get_length(cap);
  const uint64_t perms = capability_get_perms(cap);
  const uint64_t ct = sealing::type_of(cap);
  const bool sealed = sealing::is_sealed(cap);

  // 1. Hardware sealing authority. Compartment-minted types (`sys_type_mint`)
  //    are `OType::TypeKey` handles, not raw `Permit_Seal`/`Unseal`.
  //    If raw Zyseal authority is ever delegated it must be unsealed, carry no
  //    memory/execute/ASR permission, and cover only spare OTypes above
  //    `OType::Trap`.
  if ((perms & (perms::Seal | perms::Unseal)) != 0) {
    constexpr uint64_t kFirstUserOType = static_cast<uint64_t>(OType::Trap) + 1;
    constexpr uint64_t kForbidden = perms::Load | perms::Store | perms::Execute |
                                    perms::LoadCapability | perms::LoadMutable |
                                    perms::AccessSystemRegs;
    if (sealed || (perms & kForbidden) != 0 || len == 0 ||
        base < kFirstUserOType || len > (kOTypeMax + 1 - base)) {
      panic(site, "Seal/Unseal authority over reserved OTypes or with memory perms",
            cap);
    }
    return;
  }

  // 2. W^X.
  if ((perms & (perms::Store | perms::Execute)) ==
      (perms::Store | perms::Execute)) {
    panic(site, "Capability carries both Store and Execute", cap);
  }

  // 3. No ambient roots: never `root_data_cap`, `vm::s_dynamic`, or
  //    `sentry::s_root_code_cap`, and never wrapping the address space.
  constexpr uint64_t kDynamicSpan = vm::DYNAMIC_TOP - vm::DYNAMIC_BASE;
  if (len == 0 || len >= kDynamicSpan || base > (~0ULL - len)) {
    panic(site, "Capability is unbounded or spans the dynamic space", cap);
  }
  const uint64_t top = base + len;

  // The direct map (all of RAM at its physical address) is kernel-only and is
  // caught below: it lies outside every region the allowlist admits.
  const KernelLayout& k = layout();
  const bool in_dyn = within(base, top, vm::DYNAMIC_BASE, vm::DYNAMIC_TOP);

  // 4. CT = 1 hardware sentries: executable, read-only. With ASR it must be a
  //    kernel syscall gate bounded exactly to `[_kernel_start, _got_end)`;
  //    without ASR it is a compartment entry point in dynamic memory (or, for
  //    `sentry::create_kernel` test stubs, inside the kernel's code span).
  if (sealed && ct == static_cast<uint64_t>(OType::Sentry)) {
    if ((perms & perms::Execute) == 0 || (perms & perms::Store) != 0) {
      panic(site, "CT=1 sentry lacks Execute or carries Store", cap);
    }
    if ((perms & perms::AccessSystemRegs) != 0) {
      if (base != k.k_start || top != k.got_end) {
        panic(site, "ASR sentry is not the kernel gate span", cap);
      }
    } else if (len > sentry::MAX_ENTRY_LENGTH ||
               !(in_dyn || within(base, top, k.k_start, k.got_end))) {
      panic(site, "Compartment sentry has invalid bounds", cap);
    }
    return;
  }

  // 5. Everything else -- unsealed data, kernel object handles, user-sealed
  //    objects -- is never executable and never ASR.
  if ((perms & (perms::Execute | perms::AccessSystemRegs)) != 0) {
    panic(site, "Non-sentry capability carries Execute or ASR", cap);
  }

  // 6. Kernel object handles (`yseal`ed with a kernel OType) cannot be
  //    dereferenced without `g_type_root`; their bounds are a kernel descriptor
  //    in dynamic memory or `.bss` and nothing more needs checking.
  const bool user_sealed = ct == static_cast<uint64_t>(OType::TypeKey) ||
                           ct == static_cast<uint64_t>(OType::SealedObject) ||
                           ct > static_cast<uint64_t>(OType::Trap);
  if (sealed && !user_sealed) {
    if (!(in_dyn || within(base, top, k.bss_start, k.bss_end))) {
      panic(site, "Kernel object handle points outside descriptor memory", cap);
    }
    return;
  }

  // 7. Unsealed and user-sealed memory (`sys_unseal` turns the latter back into
  //    a plain pointer) must lie inside the user allowlist: dynamic compartment
  //    memory, the device gigabyte (`vm::device_window`: `init` gets one window
  //    over it and carves the drivers' windows from the DTB), or a read-only
  //    slice of `.rodata` (embedded boot images). The direct map and the
  //    kernel image are not in the list.
  bool allowed = in_dyn || within(base, top, 0, vm::GIGAPAGE_SIZE) ||
                 ((perms & perms::Store) == 0 &&
                  within(base, top, k.rodata_start, k.rodata_end));
  if (!allowed) {
    panic(site, "Capability overlaps kernel/device memory outside user regions",
          cap);
  }
}

}  // namespace signetos::inspect
