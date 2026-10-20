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
// smp.hpp - Bringing up the secondary harts
//
// The boot hart starts every other hart present in the DTB: it carves each
// one's stacks, fills in its slot in `_hart_boot_table` (linker.ld) and pokes
// it with an IPI. The parked hart (`.Lsecondary_wait_loop` in boot.S) picks up
// its slot, turns the MMU on and calls `secondary_hart_init`, which runs the
// per-hart initialisation (`thread::init_hart`, `irq::init_hart`).
//

#include <stddef.h>
#include <stdint.h>
#include <signetos/types.hpp>

namespace signetos::smp {

// Brings up every secondary hart present in the DTB (`platform::hart_present`),
// carving each hart's 64 KiB host stack (`csp`) and 16 KiB kernel entry stack
// (`mscratchc`) from the identity-mapped kernel region above `_kernel_end` and
// waiting until each hart has completed `thread::init_hart` and
// `irq::init_hart`. Called on the boot hart, after it has done both itself.
void bring_up_secondary_harts(Capability root_data_cap, uint64_t boot_hart);

// Number of harts that have completed their per-hart initialisation, the boot
// hart included.
size_t online_harts();

}  // namespace signetos::smp
