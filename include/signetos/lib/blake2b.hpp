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
 * blake2b.hpp - BLAKE2b-256 (RFC 7693), unkeyed, in one call
 *
 * The digest the kernel keeps of every page it sends to swap (vm.hpp,
 * PAGING, DIGESTS). Nothing here depends on the rest of the kernel: it reads
 * bytes and writes 32, so it can be checked on any host against any other
 * implementation of RFC 7693.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

namespace signetos::blake2b {

constexpr size_t DIGEST_BYTES = 32;

// The BLAKE2b-256 digest of the `len` bytes at `data`, into `out`. Faster
// when `data` is 8-byte aligned, the same either way.
void hash256(const void* data, size_t len, uint8_t out[DIGEST_BYTES]);

}  // namespace signetos::blake2b
