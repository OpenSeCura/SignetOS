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
// loader.hpp - The code a compartment made from an image runs first
//
// A compartment made from an image loads that image itself, so its creator
// never holds a capability to its memory (compartment.hpp, LOADING ITSELF).
// The code that does it is `boot/loader.cpp`, built like a compartment image
// and embedded in the kernel. The kernel installs it once, at boot, in memory
// nothing can write, and gives every compartment made from an image an entry
// point that runs that one copy with the compartment's own table.
//
// Because every compartment runs the same copy, the loader has no `.data` or
// `.bss`: everything it uses is on its stack or in the compartment's table.
// The kernel will not boot otherwise (`init` below).
//

#include <signetos/types.hpp>

namespace signetos::loader {

using Status = signetos::Status;

// Installs the loader, paid from `system_quota`. Called once at boot, after
// `sentry::init`. Panics if it cannot: no compartment could be made from an
// image without it.
void init(Capability system_quota);

// Fills the loader's slots in `comp`'s table (compartment.hpp, slots 1 to 6)
// and returns the loader's entry point for `comp`, or null. `comp` is the
// compartment's full handle. `image` is passed on read-only and unchecked:
// only the loader can tell whether it is an image, when it reads it.
// `mem_quota` pays for the image's memory.
Capability prepare(Capability comp, Capability mem_quota, Capability image,
                   Status* out_status = nullptr);

}  // namespace signetos::loader
