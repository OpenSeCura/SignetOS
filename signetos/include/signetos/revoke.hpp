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
// revoke.hpp - SignetOS Revocation Authority Subsystem
//
// Implements design_spec.md section 2.1 (capability_revoker_t), section 4.2
// (Direct Global Sharing / Quarantine and Revocation), and section 5.1
// (sys_revoke_create, sys_revoke_derive, sys_revoke_register, sys_revoke_query).
//
// ZERO-BYTE HARDWARE REVOCATION AUTHORITIES
// -----------------------------------------
// A `capability_revoker_t` is a capability bounded to its authorised virtual
// address range `[base, top)`, stripped to `Permit_Load | Permit_Store` (or a
// subset), and sealed in hardware with `OType::Revoker`. It consumes 0 bytes of
// kernel memory:
//
//   1. Unforgeable: Only the kernel holds the `OType::Revoker` sealing
//      authority (`g_type_root`), so user space cannot execute `yseal` for
//      `OType::Revoker`. Any attempt to alter a sealed handle's bounds,
//      address, or permissions clears its hardware tag.
//   2. Ownership-verified creation (`revoke::create` / `sys_revoke_create`):
//      A compartment can only mint a root revoker over `[base, top)` by
//      presenting both its `capability_compartment_t` (`comp`) and a read/write
//      `mem_cap` whose range lies wholly inside a VM allocation recorded in
//      `comp`'s range chain (`compartment::owns_range`). A peer compartment
//      that merely borrowed a buffer capability does not hold the owner's
//      `comp` handle and cannot obtain revocation authority over it.
//   3. Sub-delegation (`revoke::derive` / `sys_revoke_derive`):
//      Holders with administrative authority (`Permit_Store`) can derive
//      narrower `OType::Revoker` handles over sub-ranges (e.g. for sub-arena
//      allocators) or strip `Permit_Store` to hand out operational-only
//      (`Permit_Load`) authority.
//
// Delegated authority is encoded in the sealed handle's hardware permissions,
// following the same convention as quotas:
//   Permit_Load  -> operational authority     (register ranges for revocation)
//   Permit_Store -> administrative authority  (derive sub-revokers)
//

#include <stdint.h>
#include <stddef.h>
#include <signetos/types.hpp>

namespace signetos::revoke {

// THE BACKLOG IS PAID FOR
// -----------------------
// Ranges awaiting the next sweep are recorded on pages bought, one at a time,
// from the `QuotaVm` the registering caller presents (`sys_revoke_register`):
// a page is charged to that quota when it is needed and refunded when the
// sweep that retires its ranges has run. There is no global limit, so one
// caller filling its own backlog runs out of its own quota and blocks nobody
// else -- the same rule as a compartment's range pages (compartment.hpp, "a
// quota pays for its own bookkeeping").

// Returned when no epoch has completed yet.
constexpr uint64_t EPOCH_NONE = 0;

using Status = signetos::Status;
using signetos::status_name;

// Unsealed bounds snapshot of a `capability_revoker_t` for kernel/test query.
struct RevokerAuthority {
    uint64_t base;  // inclusive
    uint64_t top;   // exclusive
};

// Resets the pending backlog (releasing and refunding any pages) and the
// epoch counters. Called once at boot.
void init();

// Core of `sys_revoke_create`. Mints an `OType::Revoker` handle with
// `Permit_Load | Permit_Store` over `mem_cap`'s bounds `[base, top)` after
// verifying `mem_cap` is tagged, unsealed, carries `Permit_Load | Permit_Store`,
// and lies wholly within a VM allocation owned by `comp`.
Capability create(Capability comp, Capability mem_cap,
                  Status* out_status = nullptr);

// Kernel-internal helper (for boot/tests) that mints an `OType::Revoker`
// handle with `Permit_Load | Permit_Store` directly over `mem_cap`'s bounds.
Capability create_root(Capability mem_cap, Status* out_status = nullptr);

// Core of `sys_revoke_derive`. Unseals `parent_handle` (`OType::Revoker`),
// requires `Permit_Store`, verifies `sub_cap` is tagged, unsealed, non-empty,
// and lies within `parent_handle`'s bounds, and returns a child `OType::Revoker`
// handle bounded to `sub_cap` with permissions restricted to
// `perms_mask & (Permit_Load | Permit_Store)`.
Capability derive(Capability parent_handle, Capability sub_cap,
                  uint64_t perms_mask, Status* out_status = nullptr);

// Convenience overload deriving a child `OType::Revoker` handle over
// `[base, top)` from `parent_handle`.
Capability derive(Capability parent_handle, uint64_t base, uint64_t top,
                  uint64_t perms_mask, Status* out_status = nullptr);

// Core of `sys_revoke_register`. Unseals `revoker_handle` (`OType::Revoker`),
// requires `Permit_Load`, checks that `mem_cap`'s bounds fall entirely within
// `revoker_handle`'s bounds, records the range for the upcoming sweep on a
// page funded by `mem_quota` (a `QuotaVm` handle with `Permit_Load`, charged
// one page when the caller's current page is full), and writes the target
// epoch to `out_epoch`.
Status register_range(Capability revoker_handle, Capability mem_cap,
                      Capability mem_quota, uint64_t* out_epoch = nullptr);

// Core of `sys_revoke_query`. Highest epoch for which the sweep has finished.
uint64_t completed_epoch();

// The epoch that ranges registered right now would be assigned to.
uint64_t pending_epoch();

// Kernel-internal. NOT reachable from user space: design_spec.md section 4.2
// requires that sweeping cannot be triggered or forced by user-space calls.
// The kernel calls this from its own scheduling policy (memory pressure,
// backlog thresholds, idle CPU time).
//
// Scans capability-bearing memory and saved register frames, clears the
// hardware tag on every capability reaching a registered or quarantined range,
// reclaims quarantined VM pages and frames, and advances the completed epoch.
void sweep();

// True if `cap` is a valid capability that targets or overlaps any pending
// revocation range or any quarantined dynamic page. Used by `sweep()`.
bool should_revoke(Capability cap);

// Diagnostics.
size_t pending_count();
bool is_pending(uint64_t address);
bool query(Capability handle, RevokerAuthority* out_copy);

} // namespace signetos::revoke
