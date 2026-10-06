/*
 * Copyright 2026 Google LLC (Cherified Team)
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
// fdt.hpp - Flattened Device Tree (DTB) walker
//
// Header-only and freestanding, so the same code reads the DTB in the kernel
// (`kernel/platform.cpp`: RAM, harts, timebase, console, poweroff device --
// what the kernel needs to run itself) and in user space (`user/init.cpp`:
// everything else, which is policy about devices the kernel never touches).
//
//   fdt::Tree tree;
//   if (tree.open(blob, bytes)) {
//     tree.walk([&](const fdt::Node& n) {
//       if (n.compatible("ns16550a")) { uint64_t a, s; n.reg(&a, &s); ... }
//     });
//   }
//
// `walk` visits every node in document order (parents before children) and
// hands each one a `Node` that can look its own properties up by name. The
// node's `#address-cells` / `#size-cells` and its parent's are tracked so
// `reg` decodes correctly at any depth. Nothing is allocated; the whole
// walker is a cursor over the caller's bytes.
//

#include <stddef.h>
#include <stdint.h>

namespace signetos::fdt {

constexpr uint32_t MAGIC        = 0xd00dfeedU;
constexpr uint32_t HEADER_BYTES = 40U;
constexpr uint32_t MAX_BYTES    = 16U * 1024U * 1024U;

constexpr uint32_t TOKEN_BEGIN_NODE = 1U;
constexpr uint32_t TOKEN_END_NODE   = 2U;
constexpr uint32_t TOKEN_PROP       = 3U;
constexpr uint32_t TOKEN_NOP        = 4U;
constexpr uint32_t TOKEN_END        = 9U;

inline uint32_t be32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

inline bool str_eq(const char* a, const char* b) {
  while (*a != '\0' && *a == *b) {
    ++a;
    ++b;
  }
  return *a == *b;
}

// `totalsize` from the 40-byte header, or 0 if the magic is wrong or the
// size is not plausible. Lets a caller size a capability before `open`.
inline uint32_t header_totalsize(const uint8_t* hdr) {
  if (hdr == nullptr || be32(hdr) != MAGIC) {
    return 0;
  }
  const uint32_t total = be32(hdr + 4);
  return (total >= HEADER_BYTES && total <= MAX_BYTES) ? total : 0;
}

// A property's raw bytes. `data == nullptr` means "not present".
struct Prop {
  const uint8_t* data = nullptr;
  uint32_t len = 0;

  bool ok() const { return data != nullptr; }

  // Big-endian cell `i`, or 0 past the end.
  uint32_t u32(uint32_t i = 0) const {
    return (ok() && (i + 1) * 4U <= len) ? be32(data + (i * 4U)) : 0;
  }

  // `n` consecutive cells starting at cell `first`, as one integer.
  uint64_t cells(uint32_t first, uint32_t n) const {
    uint64_t v = 0;
    for (uint32_t c = 0; c < n; ++c) {
      v = (v << 32) | u32(first + c);
    }
    return v;
  }

  // The value is exactly the NUL-terminated string `s`.
  bool is_string(const char* s) const {
    return ok() && len > 0 && data[len - 1] == 0 &&
           str_eq(reinterpret_cast<const char*>(data), s);
  }

  // A `stringlist` value (`compatible`) contains `s` as one of its entries.
  bool has_string(const char* s) const {
    if (!ok()) {
      return false;
    }
    uint32_t i = 0;
    while (i < len) {
      const uint32_t start = i;
      while (i < len && data[i] != 0) {
        ++i;
      }
      if (i >= len) {
        break;
      }
      if (str_eq(reinterpret_cast<const char*>(data + start), s)) {
        return true;
      }
      ++i;
    }
    return false;
  }
};

class Tree;

struct Node {
  const Tree* tree = nullptr;
  const char* name = nullptr;      // "uart@10000000"
  int depth = 0;                   // root is 1
  uint32_t props_begin = 0;        // struct-block offsets of this node's
  uint32_t props_end = 0;          //   own properties (children follow)
  uint32_t addr_cells = 2;         // this node's #address-cells (children)
  uint32_t size_cells = 1;         // this node's #size-cells (children)
  uint32_t parent_addr_cells = 2;  // what `reg` is decoded with
  uint32_t parent_size_cells = 1;

  Prop prop(const char* prop_name) const;

  // `name` is `prefix` or `prefix@...` (so "cpu-map" is not "cpu").
  bool is(const char* prefix) const {
    size_t i = 0;
    while (prefix[i] != '\0') {
      if (name[i] != prefix[i]) {
        return false;
      }
      ++i;
    }
    return name[i] == '\0' || name[i] == '@';
  }

  bool compatible(const char* s) const { return prop("compatible").has_string(s); }

  // Absent `status`, or "okay" / "ok".
  bool status_ok() const {
    const Prop s = prop("status");
    return !s.ok() || s.is_string("okay") || s.is_string("ok");
  }

  bool device_type_is(const char* s) const {
    return prop("device_type").is_string(s);
  }

  // Entry `index` of `reg` as (address, size) in the parent's cell widths.
  bool reg(uint64_t* out_addr, uint64_t* out_size, uint32_t index = 0) const {
    const Prop r = prop("reg");
    const uint32_t ac = parent_addr_cells;
    const uint32_t sc = parent_size_cells;
    if (!r.ok() || ac < 1 || ac > 2 || sc > 2) {
      return false;
    }
    const uint32_t stride = ac + sc;
    if ((index + 1) * stride * 4U > r.len) {
      return false;
    }
    if (out_addr != nullptr) {
      *out_addr = r.cells(index * stride, ac);
    }
    if (out_size != nullptr) {
      *out_size = (sc == 0) ? 0 : r.cells((index * stride) + ac, sc);
    }
    return true;
  }

  uint32_t phandle() const {
    const Prop p = prop("phandle");
    return p.ok() ? p.u32() : prop("linux,phandle").u32();
  }

  // The first interrupt number: `interrupts[0]`, or the specifier of the
  // first `interrupts-extended` pair.
  uint32_t irq() const {
    const Prop i = prop("interrupts");
    if (i.ok() && i.len >= 4) {
      return i.u32(0);
    }
    const Prop e = prop("interrupts-extended");
    return (e.ok() && e.len >= 8) ? e.u32(1) : 0;
  }
};

class Tree {
 public:
  // `blob` must stay valid for the life of the Tree. `avail` is how many
  // bytes of it may be read; the header's `totalsize` must fit inside.
  bool open(const uint8_t* blob, size_t avail) {
    base_ = nullptr;
    if (blob == nullptr || avail < HEADER_BYTES) {
      return false;
    }
    const uint32_t total = header_totalsize(blob);
    if (total == 0 || total > avail) {
      return false;
    }
    const uint32_t off_struct = be32(blob + 8);
    const uint32_t off_strings = be32(blob + 12);
    const uint32_t size_strings = be32(blob + 32);
    const uint32_t size_struct = be32(blob + 36);
    if (off_struct > total || size_struct > total - off_struct ||
        off_strings > total || size_strings > total - off_strings) {
      return false;
    }
    base_ = blob;
    total_ = total;
    off_struct_ = off_struct;
    end_struct_ = off_struct + size_struct;
    off_strings_ = off_strings;
    size_strings_ = size_strings;
    return true;
  }

  bool ok() const { return base_ != nullptr; }
  uint32_t totalsize() const { return total_; }
  const uint8_t* bytes() const { return base_; }

  // Visits every node, parents first: `fn(const Node&)`.
  template <typename F>
  void walk(F&& fn) const {
    if (!ok()) {
      return;
    }
    struct Frame {
      uint32_t addr_cells;
      uint32_t size_cells;
    };
    constexpr int MAX_DEPTH = 16;
    Frame cells[MAX_DEPTH + 1];
    cells[0] = {2, 1};  // what the root's own `reg` would decode with

    uint32_t pos = off_struct_;
    int depth = 0;
    while (pos + 4 <= end_struct_) {
      const uint32_t token = be32(base_ + pos);
      pos += 4;
      if (token == TOKEN_BEGIN_NODE) {
        const char* name = reinterpret_cast<const char*>(base_ + pos);
        while (pos < end_struct_ && base_[pos] != 0) {
          ++pos;
        }
        if (pos >= end_struct_) {
          return;
        }
        pos = (pos + 4U) & ~3U;
        ++depth;

        Node n;
        n.tree = this;
        n.name = name;
        n.depth = depth;
        n.props_begin = pos;
        n.props_end = skip_props(pos);
        const int pidx = (depth - 1 < MAX_DEPTH) ? depth - 1 : MAX_DEPTH;
        n.parent_addr_cells = cells[pidx].addr_cells;
        n.parent_size_cells = cells[pidx].size_cells;
        const Prop ac = n.prop("#address-cells");
        const Prop sc = n.prop("#size-cells");
        if (ac.ok() && ac.len == 4) {
          n.addr_cells = ac.u32();
        }
        if (sc.ok() && sc.len == 4) {
          n.size_cells = sc.u32();
        }
        if (depth <= MAX_DEPTH) {
          cells[depth] = {n.addr_cells, n.size_cells};
        }
        fn(n);
        pos = n.props_end;
      } else if (token == TOKEN_END_NODE) {
        if (depth == 0) {
          return;
        }
        --depth;
      } else if (token == TOKEN_PROP) {
        // Only reached for malformed input: `skip_props` already consumed
        // every property of the node just begun.
        if (pos + 8 > end_struct_) {
          return;
        }
        const uint32_t len = be32(base_ + pos);
        pos = (pos + 8U + len + 3U) & ~3U;
      } else if (token == TOKEN_NOP) {
        continue;
      } else {
        return;  // TOKEN_END or garbage
      }
    }
  }

 private:
  friend struct Node;

  // Advances over the PROP / NOP tokens at `pos`, stopping at the first
  // BEGIN_NODE / END_NODE / END. Returns the offset of that token.
  uint32_t skip_props(uint32_t pos) const {
    while (pos + 4 <= end_struct_) {
      const uint32_t token = be32(base_ + pos);
      if (token == TOKEN_NOP) {
        pos += 4;
        continue;
      }
      if (token != TOKEN_PROP) {
        break;
      }
      if (pos + 12 > end_struct_) {
        return end_struct_;
      }
      const uint32_t len = be32(base_ + pos + 4);
      if (len > end_struct_ - (pos + 12)) {
        return end_struct_;
      }
      pos = (pos + 12U + len + 3U) & ~3U;
    }
    return pos;
  }

  const char* prop_name(uint32_t name_off) const {
    if (name_off >= size_strings_) {
      return "";
    }
    return reinterpret_cast<const char*>(base_ + off_strings_ + name_off);
  }

  const uint8_t* base_ = nullptr;
  uint32_t total_ = 0;
  uint32_t off_struct_ = 0;
  uint32_t end_struct_ = 0;
  uint32_t off_strings_ = 0;
  uint32_t size_strings_ = 0;
};

inline Prop Node::prop(const char* want) const {
  if (tree == nullptr) {
    return Prop{};
  }
  const uint8_t* base = tree->base_;
  uint32_t pos = props_begin;
  while (pos + 4 <= props_end) {
    const uint32_t token = be32(base + pos);
    if (token == TOKEN_NOP) {
      pos += 4;
      continue;
    }
    if (token != TOKEN_PROP || pos + 12 > props_end) {
      break;
    }
    const uint32_t len = be32(base + pos + 4);
    const uint32_t name_off = be32(base + pos + 8);
    if (len > props_end - (pos + 12)) {
      break;
    }
    if (str_eq(tree->prop_name(name_off), want)) {
      return Prop{base + pos + 12, len};
    }
    pos = (pos + 12U + len + 3U) & ~3U;
  }
  return Prop{};
}

}  // namespace signetos::fdt
