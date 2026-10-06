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
 * loader.cpp - SignetOS User-Space Compartment Loader Service
 *
 * Implements design_spec.md section 3.2 (Creating and Loading a New
 * Compartment).
 *
 * When invoked with `arg == nullptr`, runs its bootstrap self-check and logs
 * readiness via `uart_sentry`.
 * When invoked with a `LoadRequest*` in `arg`, creates a new compartment
 * funded by `req->vm_quota`, seeds its capability table with `req->seeds`,
 * allocates code memory, copies `req->image`, processes its `__cap_relocs`,
 * and mints its `OType::EntryPoint` (CT = 12) sentry into `req->out_sentry`.
 *
 * THE MANIFEST CHECK
 *   The loader holds nothing it could give a new compartment, and interprets
 *   nothing: whoever launches an image reads its manifest (user/manifest.hpp)
 *   and builds the seed array. What the loader does guarantee, to every image,
 *   is that seed slot i is manifest entry i: it refuses an image whose
 *   manifest is malformed, and a seed array whose length is not exactly the
 *   manifest's count. So a program can read `rw[SLOT_X]` knowing that it is
 *   either what it asked for or null, never something else shifted into place.
 */

#include "runtime.hpp"

namespace signetos::user {
namespace {

// --- What `loader` asks `init` for (user/manifest.hpp) ------------------------
// Only kernel entries, and the console: creating a compartment is
// `compartment_create` + `vm_allocate` for its code + `sentry` for its entry,
// each funded by the quota the requester passes in. `init` loads the loader
// itself directly, since it is the thing that loads everything else.
#define LOADER_MANIFEST(X)                               \
  M_SYSCALL(X, SYS_COMP_CREATE, compartment_create)      \
  M_SYSCALL(X, SYS_COMP_DESTROY, compartment_destroy)    \
  M_SYSCALL(X, SYS_VM_ALLOC, vm_allocate)                \
  M_SYSCALL(X, SYS_VM_DEALLOC, vm_deallocate)            \
  M_SYSCALL(X, SYS_SENTRY, sentry)                       \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)      \
  M_SERVICE(X, UART_SENTRY, "uart")
SIGNETOS_MANIFEST(LOADER_MANIFEST, 128 * 1024)

}  // namespace

extern "C" void compartment_main(Capability arg) {
  Capability* rw = rw_table();

  Capability self_comp = rw[compartment::SLOT_SELF];
  Capability vm_quota = rw[compartment::SLOT_VM_QUOTA];

  Capability gate_create = rw[SLOT_SYS_COMP_CREATE];
  Capability gate_alloc = rw[SLOT_SYS_VM_ALLOC];
  Capability gate_sentry = rw[SLOT_SYS_SENTRY];
  Capability gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  Capability uart_sentry = rw[SLOT_UART_SENTRY];

  if (!sealing::is_sealed_as(OType::Compartment, self_comp) ||
      !sealing::is_sealed_as(OType::QuotaVm, vm_quota)) {
    return;
  }

  // Bootstrap ping (`arg == nullptr`): verify capability table and log banner.
  if (!capability_is_valid(arg)) {
    print(gate_invoke, uart_sentry,
          "[loader]   Compartment loader ready (quota_vm + create/alloc/sentry gates)\n");
    return;
  }

  // Service call (`arg == LoadRequest*`): construct and load target compartment.
  if (capability_get_length(arg) < sizeof(init::LoadRequest)) {
    return;
  }
  auto* req = reinterpret_cast<init::LoadRequest*>(arg);
  req->out_comp = nullptr;
  req->out_sentry = nullptr;

  // The image has to be one, its manifest has to be well formed, and the seed
  // array has to match it entry for entry (none at all for an image that asks
  // for nothing).
  const init::CompartmentImageHeader* hdr = init::image_header(req->image);
  if (hdr == nullptr) {
    return;
  }
  init::Manifest manifest;
  if (!init::manifest_of(req->image, hdr, &manifest)) {
    return;
  }
  const size_t seeds_len =
      capability_is_valid(req->seeds) ? capability_get_length(req->seeds) : 0;
  if (seeds_len != static_cast<size_t>(manifest.count) * sizeof(Capability)) {
    return;
  }

  using FnCompCreate = decltype(&sys_compartment_create);
  Capability comp = syscall::call<FnCompCreate>(gate_invoke, gate_create,
                                                req->vm_quota, req->seeds);
  if (!capability_is_valid(comp)) {
    return;
  }

  Capability entry = load_compartment_image(
      gate_invoke, gate_alloc, gate_sentry, comp, req->vm_quota, req->image);
  if (!capability_is_valid(entry)) {
    using FnCompDestroy = decltype(&sys_compartment_destroy);
    Capability gate_destroy = rw[SLOT_SYS_COMP_DESTROY];
    syscall::call<FnCompDestroy>(gate_invoke, gate_destroy, comp);
    return;
  }

  req->out_comp = comp;
  req->out_sentry = entry;
}

}  // namespace signetos::user
