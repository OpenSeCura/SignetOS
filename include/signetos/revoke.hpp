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
// revoke.hpp - SignetOS revocation
//
// A sweep clears the tag of every capability that has to die. Which ones
// those are is decided by ONE rule:
//
// THE BASE RULE
// -------------
// A capability is revoked if its BASE lies in memory that is being taken
// back: a quarantined page (`vm::free_pages`), or a range a compartment has
// queued with `revoke`. By monotonicity every capability derived from a range
// has its base inside it, so the rule catches all of them; a capability whose
// base lies outside -- the owner's capability to the allocation the range
// was carved from, or the kernel's own record of that allocation -- was not
// derived from the range and survives. (CHERIoT's revoker applies the same
// rule.)
//
// FREEING AND REVOKING
// --------------------
// Freeing a whole allocation (`sys_vm_deallocate`, compartment destroy)
// quarantines it, and quarantine is all the registration it needs. `revoke`
// is for the other case: invalidating every capability to part of an
// allocation while the owner keeps the allocation and reuses that part, as a
// heap allocator does when it frees an object. The memory is not unmapped or
// reused by the kernel; once the sweep for the returned epoch has finished
// (`completed_epoch`), the owner can safely hand it out again.
//
// WHO MAY REVOKE
// --------------
// The owner, and nobody else: the authority is the compartment handle, and
// the range must lie inside one of that compartment's own allocations
// (`compartment::owns_inside`). It must not include the allocation's first
// byte, because the base of the allocation is the base of the owner's
// capability to it, and of the kernel's record: revoking it would take the
// whole allocation from its owner and leave the kernel unable to free it. An
// allocator keeps a header (or anything) at the start of each allocation it
// carves objects from. Anyone else who needs memory revoked asks the owner.
//
// THE BACKLOG IS PAID FOR
// -----------------------
// Ranges awaiting the next sweep are recorded on pages bought, one at a time,
// from the `QuotaVm` the caller presents: a page is charged to that quota when
// it is needed and refunded when the sweep that retires its ranges has run.
// There is no global limit, so one caller filling its own backlog runs out of
// its own quota and blocks nobody else -- the same rule as a compartment's
// range pages (compartment.hpp, "a quota pays for its own bookkeeping").
//
// WHEN A SWEEP RUNS
// -----------------
// Only when `vm::alloc_pages` runs out of addresses or frames while pages are
// quarantined. A queued range alone does not start one, so its epoch can wait
// indefinitely. TODO: who decides when to sweep (DESIGN.md §4.2).
//

#include <stdint.h>
#include <stddef.h>
#include <signetos/types.hpp>

namespace signetos::revoke {

// Returned when no epoch has completed yet.
constexpr uint64_t EPOCH_NONE = 0;

using Status = signetos::Status;
using signetos::status_name;

// Resets the pending backlog (releasing and refunding any pages) and the
// epoch counters. Called once at boot.
void init();

// Core of `sys_revoke`. Queues `mem_cap`'s bounds `[base, top)` for the next
// sweep, which revokes every capability whose base lies in it (THE BASE
// RULE). `mem_cap` must be tagged and unsealed, and its bounds must lie
// inside one of `comp`'s allocations without including its first byte (WHO
// MAY REVOKE). The record goes on a backlog page funded by `mem_quota` (a
// `QuotaVm` handle with `Permit_Load`, charged one page when none of its
// pages has room). Writes the epoch whose completion means the range has
// been swept to `out_epoch`.
Status revoke(Capability comp, Capability mem_cap, Capability mem_quota,
              uint64_t* out_epoch = nullptr);

// Core of `sys_revoke_query`. Highest epoch for which the sweep has finished.
uint64_t completed_epoch();

// The epoch that ranges queued right now would be assigned to.
uint64_t pending_epoch();

// Kernel-internal. NOT reachable from user space: sweeping cannot be triggered
// or forced by user-space calls (WHEN A SWEEP RUNS).
//
// Scans capability-bearing memory and saved register frames, clears the tag on
// every capability `should_revoke` picks, reclaims quarantined VM pages and
// frames, and advances the completed epoch.
void sweep();

// THE BASE RULE: true if `cap` is a valid capability whose base lies in a
// queued range or a quarantined page. Standing kernel authorities (sealing
// and ASR capabilities, the roots of whole address ranges) are never revoked.
// Used by `sweep()`, which holds the revocation lock.
bool should_revoke(Capability cap);

// Diagnostics.
size_t pending_count();

} // namespace signetos::revoke
