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
 * blake2b.cpp - BLAKE2b-256 (RFC 7693), unkeyed, in one call
 *
 * A straight transcription of RFC 7693 sections 3.1 to 3.3 for one output
 * size and no key, which is all swap needs (vm.hpp, PAGING, DIGESTS). The
 * message is taken 128 bytes at a time; only the last block may be short,
 * and it is the last even when it is full. The byte counter is one word:
 * nothing the kernel hashes is 2^64 bytes long.
 *
 * Why BLAKE2b and not SHA-256: it works in 64-bit words, which is what the
 * machine has, and takes 12 rounds over 128 bytes where SHA-256 takes 64
 * over 64, so a page costs about half as much; and it is as standard (RFC
 * 7693) and as well studied. Being unkeyed is enough here: the digest never
 * leaves the kernel, so matching it takes a second preimage.
 */

#include <signetos/lib/blake2b.hpp>

namespace signetos::blake2b {
namespace {

constexpr size_t BLOCK_BYTES = 128;
constexpr size_t WORDS = BLOCK_BYTES / sizeof(uint64_t);

constexpr uint64_t IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

// Which message words each round's eight G functions take: rounds 10 and 11
// repeat rounds 0 and 1.
constexpr uint8_t SIGMA[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

inline uint64_t rotr64(uint64_t x, unsigned n) {
  return (x >> n) | (x << (64 - n));
}

// The little-endian word at `p`, which need not be aligned.
inline uint64_t load64(const uint8_t* p) {
  uint64_t x = 0;
  for (int i = 7; i >= 0; --i) {
    x = (x << 8) | p[i];
  }
  return x;
}

// The 16 words of the block at `p`: straight off memory where the machine
// and the alignment allow, else a byte at a time.
inline void load_block(const uint8_t* p, uint64_t m[WORDS]) {
  if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ &&
      reinterpret_cast<uintptr_t>(p) % sizeof(uint64_t) == 0) {
    const auto* w = reinterpret_cast<const uint64_t*>(p);
    for (size_t i = 0; i < WORDS; ++i) {
      m[i] = w[i];
    }
    return;
  }
  for (size_t i = 0; i < WORDS; ++i) {
    m[i] = load64(p + (sizeof(uint64_t) * i));
  }
}

// RFC 7693, 3.1: the mixing function on four words of `v`.
inline void g(uint64_t v[16], int a, int b, int c, int d, uint64_t x,
              uint64_t y) {
  v[a] = v[a] + v[b] + x;
  v[d] = rotr64(v[d] ^ v[a], 32);
  v[c] = v[c] + v[d];
  v[b] = rotr64(v[b] ^ v[c], 24);
  v[a] = v[a] + v[b] + y;
  v[d] = rotr64(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d];
  v[b] = rotr64(v[b] ^ v[c], 63);
}

// RFC 7693, 3.2: block `m` into state `h`. `t` is the bytes taken so far,
// this block included; `last` marks the final block.
void compress(uint64_t h[8], const uint64_t m[WORDS], uint64_t t, bool last) {
  uint64_t v[16];
  for (int i = 0; i < 8; ++i) {
    v[i] = h[i];
    v[i + 8] = IV[i];
  }
  v[12] ^= t;  // the low word of the counter; the high word stays 0
  if (last) {
    v[14] = ~v[14];
  }
  for (int r = 0; r < 12; ++r) {
    const uint8_t* s = SIGMA[r];
    g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (int i = 0; i < 8; ++i) {
    h[i] ^= v[i] ^ v[i + 8];
  }
}

}  // namespace

void hash256(const void* data, size_t len, uint8_t out[DIGEST_BYTES]) {
  // RFC 7693, 3.3: the state starts as the IV with the parameter block's
  // first word folded in -- digest length, no key, fanout 1, depth 1.
  uint64_t h[8];
  for (int i = 0; i < 8; ++i) {
    h[i] = IV[i];
  }
  h[0] ^= 0x01010000ULL ^ static_cast<uint64_t>(DIGEST_BYTES);

  const auto* p = static_cast<const uint8_t*>(data);
  uint64_t m[WORDS];
  uint64_t t = 0;
  while (len > BLOCK_BYTES) {
    load_block(p, m);
    t += BLOCK_BYTES;
    compress(h, m, t, false);
    p += BLOCK_BYTES;
    len -= BLOCK_BYTES;
  }
  // The last block, padded with zeros: for an empty message, all zeros.
  uint8_t tail[BLOCK_BYTES] = {};
  for (size_t i = 0; i < len; ++i) {
    tail[i] = p[i];
  }
  load_block(tail, m);
  t += len;
  compress(h, m, t, true);

  for (size_t i = 0; i < DIGEST_BYTES; ++i) {
    out[i] = static_cast<uint8_t>(h[i / 8] >> (8 * (i % 8)));
  }
}

}  // namespace signetos::blake2b
