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
// hw.hpp - What `init` learns about the board from the device tree
//
// The kernel hands `init` a copy of the DTB and one capability over the
// whole device range (`BootManifest`). This header turns the DTB into the
// facts the drivers need: where the UART, PLIC and virtio transports are,
// which PLIC source each device raises, which PLIC context belongs to each
// hart, and the timer frequency. `init` then carves one window per driver
// out of the manifest's MMIO capability using these addresses.
//
// Header-only and freestanding: nothing here allocates or links a C library.
//

#include <signetos/fdt.hpp>
#include <signetos/platform.hpp>

namespace signetos::user::hw {

constexpr uint32_t IRQ_S_EXT = 9;
constexpr uint64_t PAGE = 0x1000ULL;

inline uint64_t page_down(uint64_t v) { return v & ~(PAGE - 1); }
inline uint64_t page_up(uint64_t v) { return (v + PAGE - 1) & ~(PAGE - 1); }

struct Board {
  uint64_t timebase_hz;

  // Console UART ("ns16550a"): page-rounded window and PLIC source.
  uint64_t uart_base;
  uint64_t uart_size;
  uint32_t uart_irq;

  // PLIC ("riscv,plic0" / "sifive,plic-1.0.0"): window large enough to reach
  // every context the board declares, max source number, and the S-mode
  // context of each hart (PLIC_NO_CONTEXT where a hart has none).
  uint64_t plic_base;
  uint64_t plic_size;
  uint32_t plic_ndev;
  uint32_t plic_s_context[platform::MAX_HARTS];

  // virtio-mmio transports ("virtio,mmio"), sorted by address. One window
  // covers all of them; `virtio_slot_bytes` is the stride between slots.
  size_t   virtio_count;
  uint64_t virtio_base[platform::MAX_VIRTIO_SLOTS];
  uint32_t virtio_irq[platform::MAX_VIRTIO_SLOTS];
  uint64_t virtio_window_base;
  uint64_t virtio_window_size;
  uint64_t virtio_slot_bytes;

  // Written field by field: a `{}` of a struct this size becomes a `memset`
  // call that compartments do not link.
  void clear() {
    timebase_hz = 0;
    uart_base = uart_size = 0;
    uart_irq = 0;
    plic_base = plic_size = 0;
    plic_ndev = 0;
    for (size_t h = 0; h < platform::MAX_HARTS; ++h) {
      plic_s_context[h] = platform::PLIC_NO_CONTEXT;
    }
    virtio_count = 0;
    for (size_t s = 0; s < platform::MAX_VIRTIO_SLOTS; ++s) {
      virtio_base[s] = 0;
      virtio_irq[s] = 0;
    }
    virtio_window_base = virtio_window_size = 0;
    virtio_slot_bytes = PAGE;
  }
};

// Fills `out` from the DTB at `dtb` (`avail` readable bytes). False if the
// blob is not a device tree; `out` is then cleared and every device absent.
inline bool discover(const uint8_t* dtb, size_t avail, Board* out) {
  out->clear();
  fdt::Tree tree;
  if (!tree.open(dtb, avail)) {
    return false;
  }

  // Per-hart interrupt controller phandles, to resolve PLIC contexts after
  // the walk. `cur_hart` is the hart of the most recent `cpu@N` node, so
  // its child `interrupt-controller` can be credited to it.
  uint32_t intc_phandle[platform::MAX_HARTS];
  for (size_t h = 0; h < platform::MAX_HARTS; ++h) {
    intc_phandle[h] = 0;
  }
  uint64_t cur_hart = platform::MAX_HARTS;
  fdt::Prop plic_ext;  // the PLIC's `interrupts-extended`, resolved below
  uint64_t plic_reg_size = 0;

  tree.walk([&](const fdt::Node& n) {
    if (n.is("cpus")) {
      const fdt::Prop tb = n.prop("timebase-frequency");
      if (tb.ok() && (tb.len == 4 || tb.len == 8)) {
        out->timebase_hz = tb.cells(0, tb.len / 4);
      }
      return;
    }
    if (n.is("cpu") && n.device_type_is("cpu")) {
      uint64_t id = 0;
      cur_hart = (n.reg(&id, nullptr) && id < platform::MAX_HARTS)
                     ? id : platform::MAX_HARTS;
      return;
    }
    if (n.compatible("riscv,cpu-intc")) {
      if (cur_hart < platform::MAX_HARTS) {
        intc_phandle[cur_hart] = n.phandle();
      }
      return;
    }
    if (!n.status_ok()) {
      return;
    }
    if (n.compatible("ns16550a") || n.compatible("ns16550")) {
      if (out->uart_base == 0) {
        uint64_t a = 0, s = 0;
        if (n.reg(&a, &s)) {
          out->uart_base = page_down(a);
          out->uart_size = page_up(a + (s ? s : PAGE)) - out->uart_base;
          out->uart_irq = n.irq();
        }
      }
      return;
    }
    if (n.compatible("riscv,plic0") || n.compatible("sifive,plic-1.0.0")) {
      if (out->plic_base == 0) {
        uint64_t a = 0, s = 0;
        if (n.reg(&a, &s)) {
          out->plic_base = a;
          plic_reg_size = s;
          const fdt::Prop ndev = n.prop("riscv,ndev");
          out->plic_ndev = ndev.ok() ? ndev.u32() : platform::DEFAULT_PLIC_NDEV;
          if (out->plic_ndev > platform::PLIC_MAX_SOURCE) {
            out->plic_ndev = platform::PLIC_MAX_SOURCE;
          }
          plic_ext = n.prop("interrupts-extended");
        }
      }
      return;
    }
    if (n.compatible("virtio,mmio")) {
      uint64_t a = 0, s = 0;
      if (!n.reg(&a, &s) || out->virtio_count >= platform::MAX_VIRTIO_SLOTS) {
        return;
      }
      // Insert sorted by address.
      size_t i = out->virtio_count;
      while (i > 0 && out->virtio_base[i - 1] > a) {
        out->virtio_base[i] = out->virtio_base[i - 1];
        out->virtio_irq[i] = out->virtio_irq[i - 1];
        --i;
      }
      out->virtio_base[i] = a;
      out->virtio_irq[i] = n.irq();
      ++out->virtio_count;
      if (s != 0) {
        out->virtio_slot_bytes = s;
      }
      return;
    }
  });

  // PLIC contexts: `interrupts-extended` is (phandle, code) per context, in
  // context order. The S-mode external context of a hart is the entry whose
  // phandle is that hart's cpu-intc and whose code is IRQ_S_EXT.
  uint32_t max_ctx = 0;
  if (out->plic_base != 0) {
    const uint32_t pairs = plic_ext.ok() ? plic_ext.len / 8 : 0;
    for (uint32_t ctx = 0; ctx < pairs; ++ctx) {
      const uint32_t ph = plic_ext.u32(ctx * 2);
      const uint32_t code = plic_ext.u32(ctx * 2 + 1);
      if (code != IRQ_S_EXT || ph == 0) {
        continue;
      }
      for (size_t h = 0; h < platform::MAX_HARTS; ++h) {
        if (intc_phandle[h] == ph &&
            out->plic_s_context[h] == platform::PLIC_NO_CONTEXT) {
          out->plic_s_context[h] = ctx;
          if (ctx > max_ctx) {
            max_ctx = ctx;
          }
        }
      }
    }
    if (pairs == 0) {
      // No map: assume the usual M/S interleave (context 2*hart+1 for S).
      for (size_t h = 0; h < platform::MAX_HARTS && h < platform::DEFAULT_HARTS;
           ++h) {
        out->plic_s_context[h] = static_cast<uint32_t>(2 * h + 1);
        max_ctx = static_cast<uint32_t>(2 * h + 1);
      }
    }
    uint64_t want = platform::plic_window_for_context(max_ctx);
    if (plic_reg_size != 0 && plic_reg_size < want) {
      want = plic_reg_size;
    }
    out->plic_size = page_up(want);
  }

  // virtio window: lowest slot to the end of the highest, page-rounded.
  if (out->virtio_count > 0) {
    if (out->virtio_count > 1) {
      out->virtio_slot_bytes = out->virtio_base[1] - out->virtio_base[0];
    }
    const uint64_t lo = page_down(out->virtio_base[0]);
    const uint64_t hi = page_up(out->virtio_base[out->virtio_count - 1] +
                                out->virtio_slot_bytes);
    out->virtio_window_base = lo;
    out->virtio_window_size = hi - lo;
  }
  return true;
}

}  // namespace signetos::user::hw
