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
 * loader.cpp - The code a compartment made from an image runs first
 *
 * See include/signetos/loader.hpp. The kernel installs one copy of this at
 * boot and gives every compartment made from an image an entry point that
 * runs it with that compartment's own table (`cgp`). Its creator calls it
 * once, and it:
 *   1. takes the image out of the table, so that it only ever runs once;
 *   2. takes the rest of what the kernel left it out of the table too
 *      (compartment.hpp, slots 1 to 6), so none of it is left there for the
 *      image, whatever happens next;
 *   3. allocates the compartment's memory and copies the image into it;
 *   4. makes the image's entry point, and installs the image's fault
 *      handler if it has one;
 *   5. returns the entry point, or null if any step failed.
 *
 * Every compartment runs this same copy, so it has no globals: no `.data`
 * and no `.bss` (the kernel will not boot otherwise). Everything it uses is
 * on its stack or in the compartment's table.
 */

#include <signetos/compartment.hpp>
#include <signetos/init.hpp>
#include <signetos/syscall.hpp>
#include <signetos/types.hpp>

namespace signetos {
namespace {

// What the loader works with, taken out of the compartment's table: the
// compartment's own handle (slot 0) and what the kernel left in slots 1 to 6
// (compartment.hpp, LOADING ITSELF).
struct Given {
  Capability self;
  Capability invoke_gate;
  Capability alloc_gate;
  Capability sentry_gate;
  Capability fault_gate;
  Capability image;
  Capability quota;
};

// Loads the image into the compartment, and returns the image's entry point,
// or null.
Capability load(const Given& g) {
  const init::CompartmentImageHeader* hdr = init::image_header(g.image);
  if (hdr == nullptr) {
    return nullptr;
  }

  using FnAlloc = decltype(&sys_vm_allocate);
  const Capability memory =
      syscall::call<FnAlloc>(g.invoke_gate, g.alloc_gate, g.self, g.quota,
                             init::image_alloc_size(hdr, g.image), 0);
  if (!capability_is_valid(memory)) {
    return nullptr;
  }
  init::image_install(memory, g.image, hdr);

  // The entry point, and so the compartment's `pcc`, covers `[0, got_end)`
  // only: its code and read-only data, never its `.data` or `.bss`.
  const Capability code = init::image_code_window(memory, hdr);
  if (!capability_is_valid(code)) {
    return nullptr;
  }
  using FnSentry = decltype(&sys_sentry);
  const Capability entry =
      syscall::call<FnSentry>(g.invoke_gate, g.sentry_gate, g.self, code);
  if (!capability_is_valid(entry)) {
    return nullptr;
  }

  // The image's fault handler (fault.hpp), if it has one. An image that asked
  // for a handler must not run without it, so any failure fails the load.
  //
  // Installed last, and nothing after it may fault: from here on a fault in
  // this compartment would enter the image's own handler, which sees every
  // register, and so everything this function holds.
  Capability handler = nullptr;
  if (!init::image_fault_handler(code, hdr->fault_handler, &handler)) {
    return nullptr;
  }
  using FnFaultInstall = decltype(&sys_fault_install);
  if (handler != nullptr &&
      syscall::call<FnFaultInstall>(g.invoke_gate, g.fault_gate, g.self,
                                    handler) !=
          static_cast<uint64_t>(Status::Ok)) {
    return nullptr;
  }
  return entry;
}

}  // namespace
}  // namespace signetos

using namespace signetos;

extern "C" Capability compartment_main() {
  Capability* table = nullptr;
  __asm__ volatile("cmv %0, cgp" : "=C"(table));

  // Taking the image out of its slot is what makes the image load only once:
  // a second call, even one made at the same time, finds the slot empty and
  // changes nothing. (Slots 1 to 6 stay the loader's for good.)
  const Capability image = __atomic_exchange_n(
      &table[compartment::SLOT_LOADER_IMAGE], nullptr, __ATOMIC_ACQ_REL);
  if (!capability_is_valid(image)) {
    return nullptr;
  }

  // The rest comes out of the table too, before anything that could fail or
  // fault: whatever happens from here on, the image never finds it there.
  const Given g = {table[compartment::SLOT_SELF],
                   table[compartment::SLOT_LOADER_INVOKE],
                   table[compartment::SLOT_LOADER_VM_ALLOCATE],
                   table[compartment::SLOT_LOADER_SENTRY],
                   table[compartment::SLOT_LOADER_FAULT_INSTALL],
                   image,
                   table[compartment::SLOT_LOADER_QUOTA]};
  for (size_t slot = compartment::SLOT_LOADER_INVOKE;
       slot < compartment::RW_SLOT_SEED_BASE; ++slot) {
    table[slot] = nullptr;
  }
  return load(g);
}
