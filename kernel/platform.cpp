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
 * platform.cpp - The kernel's own view of the board, from the DTB
 *
 * Walks the DTB once at boot (while physical addressing is still active) for
 * the five things the kernel needs to run itself: RAM bounds, usable harts,
 * timer frequency, the console UART's registers, and the poweroff device.
 * Device policy (PLIC, interrupt numbers, virtio) is `init`'s business.
 */

#include <signetos/fdt.hpp>
#include <signetos/platform.hpp>

namespace signetos::platform {
namespace {

constexpr uint64_t PAGE_ALIGN = 0x1000ULL;

uint64_t s_ram_base         = DEFAULT_RAM_BASE;
uint64_t s_ram_bytes        = DEFAULT_RAM_BYTES;
uint64_t s_timebase_hz      = DEFAULT_TIMEBASE_HZ;
uint64_t s_clint_base       = DEFAULT_CLINT_BASE;
uint64_t s_test_device_base = DEFAULT_TEST_DEVICE_BASE;
uint64_t s_test_device_size = DEFAULT_TEST_DEVICE_SIZE;
uint64_t s_uart_base        = DEFAULT_UART_BASE;
uint64_t s_uart_size        = DEFAULT_UART_SIZE;
uint64_t s_dtb_base         = 0;
uint64_t s_dtb_bytes        = 0;

size_t s_hart_count = DEFAULT_HARTS;
bool   s_hart_present[MAX_HARTS] = {true, true, true, true};

bool s_discovered = false;

uint64_t round_up_page(uint64_t bytes) {
  if (bytes <= PAGE_ALIGN) {
    return PAGE_ALIGN;
  }
  return (bytes + (PAGE_ALIGN - 1)) & ~(PAGE_ALIGN - 1);
}

// Compares a node name (e.g. `"uart@10000000"`) against the leaf component of
// `/chosen` `stdout-path` (e.g. `"/soc/uart@10000000"` or
// `"/soc/uart@10000000:115200"`).
bool matches_stdout_path(const char* node_name, const fdt::Prop& stdout_path) {
  if (node_name == nullptr || !stdout_path.ok() || stdout_path.len == 0) {
    return false;
  }
  const uint8_t* v = stdout_path.data;
  uint32_t end = 0;
  while (end < stdout_path.len && v[end] != 0 && v[end] != ':') {
    ++end;
  }
  uint32_t slash = end;
  while (slash > 0 && v[slash - 1] != '/') {
    --slash;
  }
  const uint32_t leaf_len = end - slash;
  if (leaf_len == 0) {
    return false;
  }
  for (uint32_t i = 0; i < leaf_len; ++i) {
    if (node_name[i] != static_cast<char>(v[slash + i])) {
      return false;
    }
  }
  return node_name[leaf_len] == '\0';
}

}  // namespace

void discover(Capability root_data_cap, Capability dtb_cap) {
  if (s_discovered) {
    return;
  }
  if (!capability_is_valid(root_data_cap) || !capability_is_valid(dtb_cap)) {
    return;
  }

  const uint64_t dtb_pa = capability_get_address(dtb_cap);
  if (dtb_pa == 0 || (dtb_pa & 0x3ULL) != 0) {
    return;
  }

  // The header first, to learn how big a capability the blob needs.
  Capability hdr_cap = capability_set_address(root_data_cap, dtb_pa);
  hdr_cap = capability_set_bounds(hdr_cap, fdt::HEADER_BYTES);
  hdr_cap = capability_and_perms(hdr_cap, perms::Load);
  if (!capability_is_valid(hdr_cap)) {
    return;
  }
  const uint32_t totalsize =
      fdt::header_totalsize(reinterpret_cast<const uint8_t*>(hdr_cap));
  if (totalsize == 0) {
    return;
  }
  Capability blob_cap = capability_set_address(root_data_cap, dtb_pa);
  blob_cap = capability_set_bounds(blob_cap, totalsize);
  blob_cap = capability_and_perms(blob_cap, perms::Load);
  if (!capability_is_valid(blob_cap)) {
    return;
  }

  fdt::Tree tree;
  if (!tree.open(reinterpret_cast<const uint8_t*>(blob_cap), totalsize)) {
    return;
  }

  // First pass: `/chosen stdout-path`, so a board with several UARTs gets
  // the console on the one the firmware chose.
  fdt::Prop stdout_path;
  tree.walk([&](const fdt::Node& n) {
    if (n.depth == 2 && fdt::str_eq(n.name, "chosen")) {
      stdout_path = n.prop("stdout-path");
      if (!stdout_path.ok()) {
        stdout_path = n.prop("linux,stdout-path");
      }
    }
  });

  bool found_ram = false;
  bool found_clint = false;
  bool found_uart = false;
  bool found_uart_stdout = false;
  bool found_test = false;
  bool in_cpus = false;
  bool dtb_hart_present[MAX_HARTS]{};
  size_t dtb_hart_count = 0;

  tree.walk([&](const fdt::Node& n) {
    if (n.depth == 2) {
      in_cpus = fdt::str_eq(n.name, "cpus");
      if (in_cpus) {
        const fdt::Prop hz = n.prop("timebase-frequency");
        const uint64_t v = (hz.len == 4) ? hz.u32() : (hz.len == 8) ? hz.cells(0, 2) : 0;
        if (v > 0) {
          s_timebase_hz = v;
        }
        return;
      }
      // `/memory@...`
      if (!found_ram && n.status_ok() &&
          (n.is("memory") || n.device_type_is("memory"))) {
        uint64_t base = 0;
        uint64_t size = 0;
        if (n.reg(&base, &size) && size > 0) {
          s_ram_base = base;
          s_ram_bytes = size;
          found_ram = true;
        }
        return;
      }
    }

    // `/cpus/cpu@N`
    if (n.depth == 3 && in_cpus && (n.is("cpu") || n.device_type_is("cpu"))) {
      uint64_t hartid = 0;
      if (n.status_ok() && n.reg(&hartid, nullptr) && hartid < MAX_HARTS &&
          !dtb_hart_present[hartid]) {
        dtb_hart_present[hartid] = true;
        dtb_hart_count += 1;
      }
      return;
    }

    if (n.depth != 2 && n.depth != 3) {
      return;
    }
    if (!n.status_ok() || !n.prop("compatible").ok()) {
      return;
    }

    // Core-Local Interruptor (CLINT: per-hart M-mode timer and software IPIs).
    if (!found_clint &&
        (n.compatible("riscv,clint0") || n.compatible("sifive,clint0"))) {
      uint64_t base = 0;
      uint64_t size = 0;
      if (n.reg(&base, &size) && size > 0) {
        s_clint_base = base;
        found_clint = true;
      }
    }

    // Console UART. Prefer the node `stdout-path` names.
    if (n.compatible("ns16550a") || n.compatible("ns16550")) {
      const bool is_stdout = matches_stdout_path(n.name, stdout_path);
      if (!found_uart || (is_stdout && !found_uart_stdout)) {
        uint64_t base = 0;
        uint64_t size = 0;
        if (n.reg(&base, &size) && size > 0) {
          s_uart_base = base;
          s_uart_size = round_up_page(size);
          found_uart = true;
          found_uart_stdout = is_stdout;
        }
      }
    }

    // Finisher / poweroff device.
    if (!found_test &&
        (n.compatible("sifive,test1") || n.compatible("sifive,test0"))) {
      uint64_t base = 0;
      uint64_t size = 0;
      if (n.reg(&base, &size) && size > 0) {
        s_test_device_base = base;
        s_test_device_size = round_up_page(size);
        found_test = true;
      }
    }
  });

  if (dtb_hart_count > 0) {
    s_hart_count = dtb_hart_count;
    for (size_t h = 0; h < MAX_HARTS; ++h) {
      s_hart_present[h] = dtb_hart_present[h];
    }
  }

  s_dtb_base = dtb_pa;
  s_dtb_bytes = totalsize;
  s_discovered = true;
}

bool is_discovered()        { return s_discovered; }
uint64_t ram_base()         { return s_ram_base; }
uint64_t ram_bytes()        { return s_ram_bytes; }
size_t   hart_count()       { return s_hart_count; }
uint64_t timebase_hz()      { return s_timebase_hz; }
uint64_t clint_base()       { return s_clint_base; }
uint64_t test_device_base() { return s_test_device_base; }
uint64_t test_device_size() { return s_test_device_size; }
uint64_t uart_base()        { return s_uart_base; }
uint64_t uart_size()        { return s_uart_size; }
uint64_t dtb_base()         { return s_dtb_base; }
uint64_t dtb_bytes()        { return s_dtb_bytes; }

bool hart_present(uint64_t hart) {
  return hart < MAX_HARTS && s_hart_present[hart];
}

}  // namespace signetos::platform
