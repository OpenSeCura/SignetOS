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
// inspect.hpp - SignetOS outbound capability assertion
//

#include <signetos/types.hpp>

namespace signetos::inspect {

// Verifies that a capability `cap` about to be handed to a user compartment
// (via a syscall return, initial capability table slot, cross-compartment
// domain switch, thread creation, or user trap delivery) satisfies all kernel
// isolation invariants:
//   1. Never carries hardware sealing or unsealing authority (`Seal | Unseal`)
//      over kernel-reserved OTypes.
//   2. Strictly obeys W^X (`!(Store && Execute)`).
//   3. Is tightly bounded (never `root_data_cap`, `s_dynamic`, or
//      `s_root_code_cap`).
//   4. Never overlaps the kernel's page-table scratch window or physical frame
//      allocator bitmap.
//   5. If sealed, is either a valid `CT = 1` sentry (kernel gate bounded to
//      `[_kernel_start, _got_end)` or compartment entry point) or a
//      non-executable kernel object handle bounded to `<= PAGE_SIZE`.
//   6. If unsealed, carries neither `Execute` nor `AccessSystemRegs`, and lies
//      within the user memory allowlist (dynamic VA space, UART MMIO page,
//      read-only `.rodata` boot images).
// Panics and halts the machine immediately if any invariant is violated.
void assert_user_capability(Capability cap, const char* site);

}  // namespace signetos::inspect
