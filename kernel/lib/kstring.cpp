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
 * kstring.cpp - SignetOS Freestanding Memory Primitives
 *
 * The compiler emits calls to these for aggregate copies and zero-initialization
 * even in a freestanding build, so the kernel must provide them.
 *
 * CHERI note: a 128-bit capability retains its validity tag ONLY if it is copied
 * with a capability load/store pair (`lc`/`sc`) at 16-byte alignment. Byte-wise
 * copying silently clears tags. These implementations therefore copy whole
 * capability granules whenever alignment and length permit, so that kernel
 * structures containing capabilities survive being copied.
 */

#include <stdint.h>
#include <stddef.h>

namespace {

constexpr size_t CAP_SIZE = sizeof(void* __capability);

inline bool cap_aligned(const void* p) {
    return (reinterpret_cast<uintptr_t>(p) % CAP_SIZE) == 0;
}

} // namespace

extern "C" void* memcpy(void* dst, const void* src, size_t n) {
    auto* d = static_cast<unsigned char*>(dst);
    const auto* s = static_cast<const unsigned char*>(src);

    if (cap_aligned(d) && cap_aligned(s)) {
        auto* dc = reinterpret_cast<void* __capability*>(d);
        const auto* sc = reinterpret_cast<void* __capability const*>(s);
        while (n >= CAP_SIZE) {
            *dc++ = *sc++;          // tag-preserving 128-bit copy
            n -= CAP_SIZE;
        }
        d = reinterpret_cast<unsigned char*>(dc);
        s = reinterpret_cast<const unsigned char*>(sc);
    }

    while (n-- > 0) {
        *d++ = *s++;
    }
    return dst;
}

extern "C" void* memset(void* dst, int value, size_t n) {
    auto* d = static_cast<unsigned char*>(dst);
    const auto byte = static_cast<unsigned char>(value);

    // Zeroing whole capability granules also clears their validity tags, which is
    // the desired behaviour when scrubbing a slot before reuse.
    if (byte == 0 && cap_aligned(d)) {
        auto* dc = reinterpret_cast<void* __capability*>(d);
        while (n >= CAP_SIZE) {
            *dc++ = nullptr;
            n -= CAP_SIZE;
        }
        d = reinterpret_cast<unsigned char*>(dc);
    }

    while (n-- > 0) {
        *d++ = byte;
    }
    return dst;
}

