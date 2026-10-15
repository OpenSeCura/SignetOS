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
 * clint.cpp - The machine timer and the cross-hart poke (clint.hpp)
 */

#include <signetos/hw/clint.hpp>

namespace signetos::clint {
namespace {

// Authority over the CLINT window, Load|Store only, narrowed to one register
// per access by `reg`. Never handed out whole.
Capability s_clint = nullptr;

uint64_t this_hart() {
  uint64_t hart;
  __asm__ volatile("csrr %0, mhartid" : "=r"(hart));
  return hart;
}

// The `bytes`-wide register at `offset` in the window.
Capability reg(uint64_t offset, size_t bytes) {
  Capability c =
      capability_set_address(s_clint, capability_get_base(s_clint) + offset);
  return capability_set_bounds(c, bytes);
}

volatile uint32_t* msip(uint64_t hart) {
  return reinterpret_cast<volatile uint32_t*>(
      reg(MSIP_OFFSET + 4 * hart, sizeof(uint32_t)));
}

volatile uint64_t* mtimecmp(uint64_t hart) {
  return reinterpret_cast<volatile uint64_t*>(
      reg(MTIMECMP_OFFSET + 8 * hart, sizeof(uint64_t)));
}

}  // namespace

void init(Capability root_data_cap) {
  if (!capability_is_valid(root_data_cap)) {
    return;
  }
  Capability c = capability_set_address(root_data_cap, platform::clint_base());
  c = capability_set_bounds(c, platform::clint_size());
  s_clint = capability_and_perms(c, perms::Load | perms::Store);
}

void set_timer(uint64_t deadline) {
  *mtimecmp(this_hart()) = deadline;
}

void send_ipi(uint64_t hart_mask) {
  // What the poke announces (the trap table) is written before it.
  __asm__ volatile("fence w, o" ::: "memory");
  for (uint64_t h = 0; h < platform::MAX_HARTS; ++h) {
    if ((hart_mask & (1ULL << h)) == 0 || !platform::hart_present(h)) {
      continue;
    }
    *msip(h) = 1;
  }
}

void clear_ipi() {
  *msip(this_hart()) = 0;
  // The clear lands before anything read after it (the trap table), so a
  // poke sent after that read sets `msip` again instead of being lost.
  __asm__ volatile("fence o, r" ::: "memory");
}

Capability msip_register(uint64_t hart) {
  if (!capability_is_valid(s_clint) || !platform::hart_present(hart)) {
    return nullptr;
  }
  return reg(MSIP_OFFSET + 4 * hart, sizeof(uint32_t));
}

}  // namespace signetos::clint
