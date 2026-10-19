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
// marked with `revoke`. By monotonicity every capability derived from a range
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
// MARKING RANGES
// --------------
// `revoke` sets one bit per 16 bytes of the range in the revocation
// bitmap (vm.hpp, REVOCATION BITMAP); the sweep tests the bit under each
// capability's base and clears every bit when it ends. The marks belong to
// virtual addresses, as capabilities do, so they stay right however pages
// are backed. Revoking needs no memory: a revocable allocation brings its
// bitmap pages with it, and only those can be revoked from. Both ends of a range
// must be multiples of 16 bytes, so that the bits set cover exactly the
// range.
//
// WHEN A SWEEP RUNS
// -----------------
// When somebody asks (`request`, which is `sys_revoke_sweep`), and at most
// once per SWEEP_INTERVAL_US; the first one is not held back. A sweep stops
// the machine for as long as it takes to scan all live memory, so the
// interval is what bounds the time sweeps take, however many callers ask and
// however often. A caller that needs its memory back sooner waits. Nothing
// else starts one: an allocation that fails, for want of quota or of frames,
// just fails.
//

#include <stdint.h>
#include <stddef.h>
#include <signetos/types.hpp>

namespace signetos::revoke {

// Returned when no epoch has completed yet.
constexpr uint64_t EPOCH_NONE = 0;

using Status = signetos::Status;
using signetos::status_name;

// Resets the epoch counters. Called once at boot.
void init();

// Core of `sys_revoke`. Marks `mem_cap`'s bounds `[base, top)` for the next
// sweep, which revokes every capability whose base lies in them (THE BASE
// RULE). `mem_cap` must be tagged and unsealed, its bounds must start and end
// on a multiple of 16 bytes (MARKING RANGES), and they must lie inside one of
// `comp`'s revocable allocations without including its first byte (WHO MAY
// REVOKE). Writes to `out_epoch` the epoch the range belongs to: it has been
// swept once `completed_epoch()` reaches it.
Status revoke(Capability comp, Capability mem_cap,
              uint64_t* out_epoch = nullptr);

// Core of `sys_revoke_query`. Highest epoch for which the sweep has finished.
uint64_t completed_epoch();

// The epoch that ranges marked right now would be assigned to.
uint64_t pending_epoch();

// The least time between the end of one sweep and the start of the next
// (WHEN A SWEEP RUNS). Policy, and a guess: a heap must hold this long's
// worth of freed memory, and the machine stalls once per this long at most.
constexpr uint64_t SWEEP_INTERVAL_US = 10'000'000;

// Core of `sys_revoke_sweep`. Sweeps and returns 0 if the last sweep ended at
// least SWEEP_INTERVAL_US ago or there is nothing to scan; otherwise returns
// the microseconds until a sweep may run.
uint64_t request();

// Kernel-internal: sweeps now, whatever the interval. The boot self-test's
// way in; nothing reachable from user space calls it.
//
// Scans capability-bearing memory and saved register frames, clears the tag on
// every capability THE BASE RULE picks, reclaims quarantined VM pages and
// frames, clears the marks, and advances the completed epoch.
void sweep();

} // namespace signetos::revoke
