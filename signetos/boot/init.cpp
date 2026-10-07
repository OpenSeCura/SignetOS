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
 * init.cpp - SignetOS Initial User-Space Compartment (`init`)
 *
 * Compiled as a standalone user compartment (`boot/init.bin`) and loaded by
 * `signetos::init::launch()` in `kernel/init.cpp`.
 *
 * `init` is the launcher of the system's services, the way the shell's `run`
 * is the launcher of programs (shell.cpp, "Programs"): every service image
 * carries a manifest (user/manifest.hpp) saying what it needs, and `init`
 * meets each entry from what it holds -- the kernel entries and interrupt
 * authorities the kernel seeded it with, the device windows it carved out of
 * the device tree, the quotas it derives from the roots, the entry points
 * services hand back to it -- or, for an entry it cannot meet, leaves the slot
 * null, and does not start the image at all if the entry was REQUIRED. No
 * service's seed list is written here: the image says, `init` grants
 * (`Launcher::grant` below). What is written here is the order the services
 * come up in, since each one's entry points are what the next one asks for,
 * and the handshakes where two of them have to meet.
 *
 * Bootstrap sequence:
 *   0. Receives a read-only `BootManifest*` in `arg` (`ca0`) carrying a copy
 *      of the device tree, one capability over the whole device MMIO range,
 *      and read-only capabilities to the boot-set images packaged in the
 *      kernel: `uart`, `loader`, `blk` and `fs` -- what it takes to reach the
 *      disk, and nothing more. Reads the board out of the device tree
 *      (`hw.hpp`) and carves one MMIO window per device.
 *   1. Starts `uart` directly (there is no loader yet): the console, and the
 *      one-shot handshake that mints `uart.read`.
 *   2. Starts `loader` directly; everything after goes through it.
 *   3. `blk`: its manifest asks for the virtio window and a DMA arena, which
 *      `init` allocates (`sys_vm_phys` for its physical address, which the
 *      handshake tells the driver).
 *   4. `fs`: asks for `blk.read`/`blk.write`; its VM quota is sized to the
 *      disk; its handshake returns the root `quota_disk` handle and its entry
 *      points. From here on every image is a file read off the disk.
 *   5. `naming`: `init` publishes `uart`, `loader` and `fs.*` on their behalf.
 *   6. `sched`: hands `blk` the scheduler's entries (the disk is polled until
 *      then).
 *   7. `trap_mgr`: routes the UART's and the block device's PLIC sources to
 *      their drivers' interrupt entries.
 *   8. `shell`: its manifest asks for thread memory, `/home` and `/bin`, and
 *      the system's root quotas, which it holds from then on; its thread is
 *      made and registered with the scheduler.
 *   9. Records every handle in its own table for the kernel's tests, then
 *  10. scrubs every authority out of that table and exits: `init` is
 *      transient, and what it held must not outlive it in a table nothing
 *      runs on.
 */

#include <assert.h>

#include <signetos/platform.hpp>

#include "hw.hpp"
#include "runtime.hpp"

namespace signetos::user {
namespace {

using FnInvoke = decltype(&sys_compartment_invoke);

constexpr uint32_t kAdminPerms = perms::Load | perms::Store;

template <typename T>
Capability bounded(T* p) {
  return capability_set_bounds(reinterpret_cast<Capability>(p), sizeof(T));
}

// Compartments link no C library: a struct too large for the compiler to
// zero inline (`T x{}`) would otherwise become a call to `memset`. This loop
// stays a loop under -ffreestanding.
void zero_bytes(void* p, size_t n) {
  auto* d = static_cast<uint8_t*>(p);
  for (size_t i = 0; i < n; ++i) {
    d[i] = 0;
  }
}

// Fills the FS_PATH_MAX-byte path field of an `fs` request: `src`, truncated
// if need be, then NULs to the end -- every byte written, for the same reason.
void set_path(char* dst, const char* src) {
  size_t i = 0;
  for (; i + 1 < init::FS_PATH_MAX && src[i] != '\0'; ++i) {
    dst[i] = src[i];
  }
  for (; i < init::FS_PATH_MAX; ++i) {
    dst[i] = '\0';
  }
}

bool str_eq(const char* a, const char* b) {
  while (*a != '\0' && *a == *b) {
    ++a;
    ++b;
  }
  return *a == *b;
}

// The seed array of the compartment being started: entry i of its manifest
// in element i. In `.bss`, not on the stack -- `sys_compartment_create`
// refuses a seed array that overlaps the stack it runs on -- and one array
// for every launch in turn, since the kernel copies the seeds at creation.
alignas(16) Capability s_seeds[init::MANIFEST_MAX];

// A started compartment: what funds it, the handle, the entry sentry. Any of
// them null if that step failed.
struct Started {
  Capability quota;
  Capability comp;
  Capability sentry;
};

// --- The launcher -------------------------------------------------------------
//
// Everything `init` can grant, gathered as it comes to hold it, and how each
// kind of manifest entry is met from it. The policy is the simplest one for a
// launcher of system images: a service gets whatever it declares, if `init`
// has it. The manifest is then the complete record of what a service holds,
// in the service's own source, and this struct is the complete record of what
// `init` was prepared to hand out. Kept in `.bss` (`s_launcher`): it is
// bigger than a stack frame should be, and zero is the right initial value of
// everything in it.
struct Launcher {
  Capability* rw;          // init's table: kernel entries, IRQ/EXC authorities
  Capability invoke;       // the switcher
  Capability uart;         // the console, once there is one
  Capability self_comp;
  Capability mem_quota;    // the root QuotaVm: every VM quota is a slice of it
  Capability thread_quota; // the root QuotaThreadMem
  Capability gate_q_derive;
  Capability gate_tq_derive;
  Capability gate_vm_alloc;
  Capability gate_vm_dealloc;
  Capability gate_vm_phys;
  Capability gate_comp_create;
  Capability gate_sentry;
  Capability loader;       // `loader`'s entry, once it is up

  // Device windows (step 0), one per MMIO name a manifest can use.
  Capability uart_mmio;
  Capability plic_mmio;
  Capability virtio_mmio;

  // The DMA arena, made for the first DMA entry; one per system.
  Capability dma_window;
  uint64_t dma_phys;

  // Entry points by name: what `init` was handed in handshakes, offered to
  // SERVICE entries. Once `naming` is up, anything published is found too.
  struct Named {
    const char* name;
    Capability cap;
  };
  static constexpr size_t NAMED_MAX = 16;
  Named named[NAMED_MAX];
  size_t named_count;
  Capability naming_lookup;

  // The disk, for DISK entries, and for reading the images that are files.
  Capability fs_root;      // ADMIN handle of the root node: sees every file
  Capability fs_open;
  Capability fs_read;
  Capability fs_close;
  Capability fs_mkdir;
  Capability fs_derive;
  Capability fs_query;
  Capability fs_node_funding;  // the QuotaVm that pays for the nodes

  // The scheduler's root quota, for ROOT_SCHED.
  Capability root_sched;

  // Recorded for step 9 (the kernel's exec tests tear the system down through
  // `init`'s table): the thread-memory quota and the ADMIN disk node the
  // shell asked for.
  Capability shell_t_quota;
  Capability shell_disk_quota;

  void say(const char* msg) const { print(invoke, uart, msg); }
  void say_dec(const char* p, uint64_t v, const char* s) const {
    print_dec(invoke, uart, p, v, s);
  }
  void warn(const char* who, const char* what) const {
    say("[init]     WARNING: ");
    say(who);
    say(": ");
    say(what);
    say("\n");
  }

  void offer(const char* name, Capability cap) {
    if (named_count < NAMED_MAX && capability_is_valid(cap)) {
      named[named_count].name = name;
      named[named_count].cap = cap;
      named_count += 1;
    }
  }

  Capability service(const char* name) const {
    for (size_t i = 0; i < named_count; ++i) {
      if (str_eq(named[i].name, name)) {
        return named[i].cap;
      }
    }
    return capability_is_valid(naming_lookup)
               ? lookup_name(invoke, naming_lookup, name)
               : nullptr;
  }

  Capability vm_quota(size_t bytes) const {
    using Fn = decltype(&sys_quota_vm_derive);
    return syscall::call<Fn>(invoke, gate_q_derive, mem_quota, bytes,
                             kAdminPerms);
  }

  Capability tmem_quota(size_t bytes) const {
    using Fn = decltype(&sys_quota_thread_mem_derive);
    return syscall::call<Fn>(invoke, gate_tq_derive, thread_quota, bytes,
                             kAdminPerms);
  }

  Capability alloc(size_t bytes) const {
    using Fn = decltype(&sys_vm_allocate);
    return syscall::call<Fn>(invoke, gate_vm_alloc, self_comp, mem_quota, bytes,
                             FLAG_ZERO);
  }

  void release(Capability mem) const {
    using Fn = decltype(&sys_vm_deallocate);
    if (capability_is_valid(mem)) {
      syscall::call<Fn>(invoke, gate_vm_dealloc, self_comp, mem_quota, mem);
    }
  }

  // DMA: a zeroed allocation of `init`'s own. `sys_vm_phys` reports its
  // physical base only if the whole arena is one contiguous run, which is
  // what lets a single address describe it to a device. One arena per
  // system, sized by the first image to ask; none on a board without a
  // device window to DMA for.
  Capability dma_arena(uint64_t bytes) {
    if (capability_is_valid(dma_window)) {
      return dma_window;
    }
    if (!capability_is_valid(virtio_mmio) || bytes == 0) {
      return nullptr;
    }
    Capability dma = alloc(static_cast<size_t>(bytes));
    if (!capability_is_valid(dma)) {
      return nullptr;
    }
    using FnPhys = decltype(&sys_vm_phys);
    dma_phys = syscall::call<FnPhys>(invoke, gate_vm_phys, self_comp, dma);
    if (dma_phys == 0) {
      release(dma);
      return nullptr;
    }
    dma_window = dma;
    return dma;
  }

  // The root's free space: what it has neither used nor delegated.
  void disk_free(uint64_t* bytes, uint32_t* inodes) const {
    *bytes = 0;
    *inodes = 0;
    init::FsQueryRequest q{};
    q.quota = fs_root;
    q.status = init::FS_BAD_REQUEST;
    reinterpret_cast<FnInvoke>(invoke)(fs_query, bounded(&q));
    if (q.status == init::FS_OK) {
      const uint64_t taken_bytes = q.used_bytes + q.delegated_bytes;
      const uint32_t taken_inodes = q.used_inodes + q.delegated_inodes;
      *bytes = q.limit_bytes > taken_bytes ? q.limit_bytes - taken_bytes : 0;
      *inodes = q.limit_inodes > taken_inodes ? q.limit_inodes - taken_inodes : 0;
    }
  }

  // fs.quota_derive from the root. Requests that carry a path are too big for
  // `{}` (see zero_bytes): every field by hand.
  Capability disk_derive(const char* path, uint64_t bytes, uint32_t inodes,
                         uint32_t handle_perms, uint64_t flags,
                         int64_t* status) const {
    init::FsDeriveRequest req;
    req.parent = fs_root;
    req.node_funding = fs_node_funding;
    req.out_quota = nullptr;
    req.out_admin = nullptr;
    set_path(req.path, path);
    req.limit_bytes = bytes;
    req.limit_inodes = inodes;
    req.perms = handle_perms;
    req.status = init::FS_BAD_REQUEST;
    req.flags = flags;
    reinterpret_cast<FnInvoke>(invoke)(fs_derive, bounded(&req));
    *status = req.status;
    return req.status == init::FS_OK ? req.out_quota : nullptr;
  }

  // DISK: a node rooted at the directory `/<name>`, made if need be, with
  // the limits asked for clamped to what the root has left (MANIFEST_ALL:
  // all of it -- so DISK entries are met in manifest order, first come first
  // served). An ADMIN node adopts what is already in its directory:
  // ownership is not kept on the disk, so whatever a previous boot left there
  // is the root's at mount, and adopting makes it the holder's again, charges
  // and all; if that would not fit -- leftovers larger than the space they
  // leave free -- the node is derived without, and the leftovers stay the
  // root's, visible to the holder and not its to remove. An OP node adopts
  // nothing: a read-only view owns nothing.
  Capability disk_node(const char* who, const init::ManifestEntry& e) {
    if (!capability_is_valid(fs_root) || !capability_is_valid(fs_mkdir) ||
        !capability_is_valid(fs_derive) || !capability_is_valid(fs_query) ||
        !capability_is_valid(fs_node_funding) || (e.perms & perms::Load) == 0 ||
        e.name[0] == '\0') {
      return nullptr;
    }
    const int64_t mk_st =
        ::signetos::user::invoke<int64_t>(invoke, fs_mkdir, fs_root, ro_str(e.name));
    if (mk_st != init::FS_OK && mk_st != init::FS_EXISTS) {
      say_dec("[init]     WARNING: fs.mkdir failed, status -",
              static_cast<uint64_t>(-mk_st), "\n");
      return nullptr;
    }

    uint64_t free_bytes = 0;
    uint32_t free_inodes = 0;
    disk_free(&free_bytes, &free_inodes);
    uint64_t bytes = e.amount == init::MANIFEST_ALL ? free_bytes : e.amount;
    if (bytes > free_bytes) bytes = free_bytes;
    bytes &= ~(init::FS_BLOCK_BYTES - 1);
    uint32_t inodes = e.count == init::MANIFEST_ALL_INODES ? free_inodes : e.count;
    if (inodes > free_inodes) inodes = free_inodes;

    const uint32_t handle_perms = e.perms & kAdminPerms;
    const bool admin = (handle_perms & perms::Store) != 0;
    int64_t status = init::FS_OK;
    Capability node = nullptr;
    if (admin) {
      node = disk_derive(e.name, bytes, inodes, handle_perms,
                         init::FS_DERIVE_ADOPT, &status);
      if (!capability_is_valid(node)) {
        say("[init]     WARNING: ");
        say(who);
        say(": could not adopt /");
        say(e.name);
        say("'s contents into its node; they stay the root's\n");
      }
    }
    if (!capability_is_valid(node)) {
      node = disk_derive(e.name, bytes, inodes, handle_perms, 0, &status);
    }
    if (!capability_is_valid(node)) {
      say("[init]     WARNING: fs.quota_derive(");
      say(e.name);
      say_dec(") failed, status -", static_cast<uint64_t>(-status), "\n");
      return nullptr;
    }
    if (admin) {
      shell_disk_quota = node;
    }
    return node;
  }

  // The policy: one manifest entry, met from what `init` holds, or null.
  Capability grant_one(const char* who, const init::ManifestEntry& e) {
    switch (e.kind) {
      case init::MANIFEST_SYSCALL:
        return e.count < syscall::kSyscallCount
                   ? rw[init::syscall_slot(static_cast<syscall::Id>(e.count))]
                   : nullptr;
      case init::MANIFEST_IRQ:
        return e.count < trap::MAX_INTERRUPT_VECTORS ? rw[init::irq_slot(e.count)]
                                                     : nullptr;
      case init::MANIFEST_EXC:
        return e.count < trap::MAX_EXCEPTION_VECTORS ? rw[init::exc_slot(e.count)]
                                                     : nullptr;
      case init::MANIFEST_MMIO:
        if (str_eq(e.name, "uart")) return uart_mmio;
        if (str_eq(e.name, "plic")) return plic_mmio;
        if (str_eq(e.name, "virtio")) return virtio_mmio;
        return nullptr;
      case init::MANIFEST_DMA:
        return dma_arena(e.amount);
      case init::MANIFEST_SERVICE:
        return service(e.name);
      case init::MANIFEST_QUOTA_THREAD: {
        Capability q = tmem_quota(static_cast<size_t>(e.amount));
        if (capability_is_valid(q)) {
          shell_t_quota = q;
        }
        return q;
      }
      case init::MANIFEST_ROOT:
        switch (e.count) {
          case init::ROOT_VM: return mem_quota;
          case init::ROOT_THREAD_MEM: return thread_quota;
          case init::ROOT_DISK: return fs_root;
          case init::ROOT_SCHED: return root_sched;
          default: return nullptr;
        }
      case init::MANIFEST_DISK:
        return disk_node(who, e);
      case init::MANIFEST_OTYPE:
        switch (static_cast<OType>(e.count)) {
          case OType::QuotaSched:
            return rw[init::RW_SLOT_SEAL_SCHED];
          case OType::QuotaDisk:
            return rw[init::RW_SLOT_SEAL_DISK];
          default:
            return nullptr;
        }
      default:
        return nullptr;  // FILE, and kinds this init does not know
    }
  }

  // The manifest, entry by entry, into `s_seeds`. True if every REQUIRED
  // entry was met; each that was not is named on the console.
  bool grant(const char* who, const init::Manifest& m) {
    bool ok = true;
    for (uint32_t i = 0; i < m.count; ++i) {
      const init::ManifestEntry& e = m.entries[i];
      s_seeds[i] = grant_one(who, e);
      if (!capability_is_valid(s_seeds[i]) &&
          (e.flags & init::MANIFEST_REQUIRED) != 0) {
        ok = false;
        say("[init]     WARNING: ");
        say(who);
        say(" needs ");
        print_manifest_entry(invoke, uart, e);
        say(", which init cannot give\n");
      }
    }
    return ok;
  }

  // Starts the compartment image `image` (`who` for the console): reads its
  // manifest, grants it, funds it with the VM it asks for plus `extra_vm`,
  // creates and loads it -- through `loader`, or directly while there is none
  // (`direct`). An image that is not one, whose manifest is malformed, or
  // that requires what `init` cannot give is not started.
  Started start(const char* who, Capability image, size_t extra_vm,
                bool direct) {
    Started r{};
    const init::CompartmentImageHeader* hdr = init::image_header(image);
    init::Manifest m;
    if (hdr == nullptr || !init::manifest_of(image, hdr, &m)) {
      warn(who, "not a compartment image, or its manifest is malformed");
      return r;
    }
    if (!grant(who, m)) {
      warn(who, "not started");
      return r;
    }
    const size_t vm_bytes =
        (m.vm_bytes != 0 ? static_cast<size_t>(m.vm_bytes) : 64 * 1024) +
        extra_vm;
    r.quota = vm_quota(vm_bytes);
    if (!capability_is_valid(r.quota)) {
      warn(who, "no VM quota for it");
      return r;
    }
    const Capability seeds =
        m.count == 0 ? nullptr
                     : capability_set_bounds(
                           reinterpret_cast<Capability>(&s_seeds[0]),
                           static_cast<size_t>(m.count) * sizeof(Capability));
    if (direct) {
      using FnCompCreate = decltype(&sys_compartment_create);
      r.comp = syscall::call<FnCompCreate>(invoke, gate_comp_create, r.quota,
                                           seeds);
      r.sentry = load_compartment_image(invoke, gate_vm_alloc, gate_sentry,
                                        r.comp, r.quota, image);
    } else {
      init::LoadRequest req{};
      req.vm_quota = r.quota;
      req.seeds = seeds;
      req.image = image;
      req.out_comp = nullptr;
      req.out_sentry = nullptr;
      reinterpret_cast<FnInvoke>(invoke)(loader, bounded(&req));
      r.comp = req.out_comp;
      r.sentry = req.out_sentry;
    }
    if (!capability_is_valid(r.comp) || !capability_is_valid(r.sentry)) {
      warn(who, "could not be loaded");
    }
    return r;
  }

  // The services that are files on the disk rather than images in the
  // kernel. The file is read through the root `quota_disk` handle (every file
  // is visible to it) into a page-granular, zeroed allocation of `init`'s
  // own, which then stands in for a packaged image -- it is the same shape
  // (`kernel/boot_images.S`: page aligned, zero padded to a page), so its
  // capability is exact and the zero tail `image_install` copies along is
  // bytes `.bss` would have been zeroed to anyway -- and is released again
  // afterwards. The service images sit in `/`, which is the root handle's
  // root directory, so a bare name is their path.
  Capability read_file(const char* name) {
    if (!sealing::is_sealed_as(OType::EntryPoint, fs_open) ||
        !sealing::is_sealed_as(OType::EntryPoint, fs_read) ||
        !sealing::is_sealed_as(OType::EntryPoint, fs_close) ||
        !sealing::is_sealed_as(OType::QuotaDisk, fs_root)) {
      warn(name, "no file system to load it from");
      return nullptr;
    }
    uint64_t size = 0;
    Capability file = ::signetos::user::invoke<Capability>(
        invoke, fs_open, fs_root, ro_str(name), perms::Load, bounded(&size));
    if (!capability_is_valid(file)) {
      warn(name, "not on the disk");
      return nullptr;
    }
    bool ok = size >= sizeof(init::CompartmentImageHeader) &&
              size <= init::FS_MAX_FILE_BYTES;
    Capability buf = nullptr;
    if (ok) {
      const size_t bytes = (static_cast<size_t>(size) + vm::PAGE_SIZE - 1) &
                           ~(vm::PAGE_SIZE - 1);
      buf = alloc(bytes);
      ok = capability_is_valid(buf);
    }
    if (ok) {
      const int64_t n = ::signetos::user::invoke<int64_t>(
          invoke, fs_read, file, buf, 0ULL, size);
      ok = n >= 0 && static_cast<uint64_t>(n) == size;
    }
    ::signetos::user::invoke<int64_t>(invoke, fs_close, file);
    if (!ok) {
      warn(name, "could not be read, or is not a compartment image");
      release(buf);
      return nullptr;
    }
    return buf;
  }

  // `start` for an image that is a file: read, started, released.
  Started start_file(const char* name) {
    Capability buf = read_file(name);
    if (!capability_is_valid(buf)) {
      return Started{};
    }
    Started r = start(name, buf, 0, false);
    release(buf);
    return r;
  }
};

Launcher s_launcher;

}  // namespace

extern "C" int64_t compartment_main(Capability arg) {
  Capability* rw = rw_table();
  Launcher& L = s_launcher;

  L.rw = rw;
  L.mem_quota = rw[compartment::SLOT_VM_QUOTA];
  L.self_comp = rw[compartment::SLOT_SELF];
  L.thread_quota = rw[init::RW_SLOT_THREAD_QUOTA];
  L.invoke = rw[init::syscall_slot(syscall::Id::compartment_invoke)];
  L.gate_q_derive = rw[init::syscall_slot(syscall::Id::quota_vm_derive)];
  L.gate_tq_derive = rw[init::syscall_slot(syscall::Id::quota_thread_mem_derive)];
  L.gate_vm_alloc = rw[init::syscall_slot(syscall::Id::vm_allocate)];
  L.gate_vm_dealloc = rw[init::syscall_slot(syscall::Id::vm_deallocate)];
  L.gate_vm_phys = rw[init::syscall_slot(syscall::Id::vm_phys)];
  L.gate_comp_create = rw[init::syscall_slot(syscall::Id::compartment_create)];
  L.gate_sentry = rw[init::syscall_slot(syscall::Id::sentry)];
  Capability gate_thread_create =
      rw[init::syscall_slot(syscall::Id::thread_create)];
  Capability gate_thread_exit = rw[init::syscall_slot(syscall::Id::thread_exit)];

  assert(sealing::is_sealed(L.gate_vm_phys));
  assert(sealing::is_sealed(L.gate_vm_alloc));

  // Every kernel entry is an `OType::EntryPoint` handle passed to the
  // switcher (`invoke`, the only sentry a compartment jumps to). A local copy:
  // the launcher is scrubbed in step 10, and the exit comes after.
  const Capability invoke = L.invoke;
  auto comp_invoke = reinterpret_cast<FnInvoke>(invoke);
  auto thread_create = [&](auto... a) {
    using Fn = decltype(&sys_thread_create);
    return syscall::call<Fn>(invoke, gate_thread_create, a...);
  };
  auto thread_exit = [&](auto... a) {
    using Fn = decltype(&sys_thread_exit);
    return syscall::call<Fn>(invoke, gate_thread_exit, a...);
  };
  auto say = [&](const char* msg) { L.say(msg); };

  if (!capability_is_valid(arg) ||
      capability_get_length(arg) < sizeof(init::BootManifest)) {
    thread_exit(-1);
    return -1;
  }
  const auto* manifest = reinterpret_cast<const init::BootManifest*>(arg);

  // =========================================================================
  // 0. The board: what the device tree says, and one MMIO window per device
  // =========================================================================
  // `manifest->mmio` covers every device. It is narrowed here, once, to
  // exactly the registers each driver needs -- the windows a manifest's MMIO
  // entry can name -- and the wide window is used for nothing else (the
  // kernel reclaims the manifest after `init` exits).
  hw::Board board;
  hw::discover(reinterpret_cast<const uint8_t*>(manifest->dtb),
               capability_is_valid(manifest->dtb)
                   ? capability_get_length(manifest->dtb)
                   : 0,
               &board);
  auto window = [&](uint64_t base, uint64_t len) -> Capability {
    const Capability all = manifest->mmio;
    if (!capability_is_valid(all) || len == 0 ||
        base < capability_get_base(all) || base + len < base ||
        base + len > capability_get_base(all) + capability_get_length(all)) {
      return nullptr;
    }
    Capability c = capability_set_address(all, base);
    c = capability_set_bounds(c, len);
    return capability_is_valid(c) ? c : nullptr;
  };
  L.uart_mmio = window(board.uart_base, board.uart_size);
  L.plic_mmio = window(board.plic_base, board.plic_size);
  L.virtio_mmio = window(board.virtio_window_base, board.virtio_window_size);

  assert(board.uart_base != 0);
  assert(capability_is_valid(L.uart_mmio));
  assert(capability_is_valid(L.plic_mmio));

  // =========================================================================
  // 1. `uart`: the console (direct load, before there is a loader)
  // =========================================================================
  // Its manifest asks for the UART window, `sentry` and the switcher: it
  // drives the device and nothing else. Its interrupt entry is routed to it
  // by `trap_mgr` (step 7), and `compartment_invoke` is how it notifies
  // whoever is waiting for input.
  const Started uart = L.start("uart", manifest->uart_img, 0, true);
  // The first word to `uart` must be the console-input handshake: it mints
  // `uart.read` and `uart.irq` for whoever calls first and never again
  // (abi.hpp, `UartInterface`), and only the shell's manifest asks for
  // `read`; `irq` goes nowhere but the interrupt route set up in step 7.
  init::UartInterface uart_if{};
  if (capability_is_valid(uart.sentry)) {
    comp_invoke(uart.sentry, bounded(&uart_if));
  }
  L.uart = uart.sentry;
  L.offer("uart", uart.sentry);
  L.offer("uart.read", uart_if.read);
  const Capability uart_irq = uart_if.irq;

  say("[init]     UART compartment online; bootstrapping core services...\n");

  // =========================================================================
  // 2. `loader` (direct load, then used for everything else)
  // =========================================================================
  const Started loader = L.start("loader", manifest->loader_img, 0, true);
  L.loader = loader.sentry;
  L.offer("loader", loader.sentry);
  if (capability_is_valid(loader.sentry)) {
    comp_invoke(loader.sentry, nullptr);
  }

  // =========================================================================
  // 3. `blk`: the block driver
  // =========================================================================
  // Its manifest is the only one that asks for the virtio window and a DMA
  // arena, so `blk` is the only compartment that sees either. There is no
  // scheduler for it to sleep in yet (that is a file on its own disk): it
  // polls until step 6 hands it the scheduler's entries, and its interrupt
  // entry is routed to it by `trap_mgr` in step 7.
  const Started blk = L.start("blk", manifest->blk_img, 0, false);
  // One-shot handshake (abi.hpp, `BlkInterface`): the driver gets what it
  // cannot learn from its capabilities -- the arena's physical address and
  // the slot geometry -- and hands back `read`, `write` and `irq`.
  init::BlkInterface blk_if{};
  blk_if.dma_phys = L.dma_phys;
  blk_if.virtio_slot_bytes = board.virtio_slot_bytes;
  blk_if.virtio_count = static_cast<uint32_t>(board.virtio_count);
  blk_if.status = init::BLK_NO_DEVICE;
  if (capability_is_valid(blk.sentry)) {
    comp_invoke(blk.sentry, bounded(&blk_if));
  }
  if (blk_if.status != init::BLK_OK) {
    L.say_dec("[init]     WARNING: no block device (blk status -",
              static_cast<uint64_t>(-blk_if.status),
              "); the file system will not be mounted\n");
  }
  // Offered to whoever asks -- and only `fs`'s manifest does: the disk is
  // reachable through `quota_disk` handles and through nothing else.
  L.offer("blk.read", blk_if.read);
  L.offer("blk.write", blk_if.write);

  // =========================================================================
  // 4. `fs`: the file system
  // =========================================================================
  // `fs` allocates its in-memory block bitmap (`s_bitmap`), inode table
  // (`s_inodes`, 128 B/inode) and owner table (`s_owner`, 16 B/inode) out of
  // its own VM quota at mount time, sized to the disk (`default_geometry` in
  // `boot/fs.cpp`: 1 bitmap block per 32768 disk blocks, 1 inode per 16 disk
  // blocks). That is added to what its manifest asks for, which covers code,
  // stack, `.bss` and the root quota node.
  const uint64_t disk_blocks = blk_if.capacity_sectors / 8;
  const uint64_t bitmap_blocks = (disk_blocks + 32768 - 1) / 32768;
  const uint64_t want_inodes =
      (disk_blocks / 16 >= 64) ? (disk_blocks / 16) : 64;
  const uint64_t inode_blocks = (want_inodes + 32 - 1) / 32;
  const uint64_t owner_blocks =
      (inode_blocks * 32 * sizeof(Capability) + init::FS_BLOCK_BYTES - 1) /
      init::FS_BLOCK_BYTES;
  const size_t fs_table_bytes =
      static_cast<size_t>(bitmap_blocks + inode_blocks + owner_blocks) *
      init::FS_BLOCK_BYTES;
  const Started fs = L.start("fs", manifest->fs_img, fs_table_bytes, false);
  // `fs` mounts (formatting a blank disk) and hands back the root
  // `quota_disk` handle -- the authority over the whole disk -- together with
  // its operation entry points, which `init` publishes once `naming` is up.
  init::FsInterface fs_if;
  zero_bytes(&fs_if, sizeof(fs_if));  // too big for `{}` (see zero_bytes)
  fs_if.capacity_sectors = blk_if.capacity_sectors;
  fs_if.status = init::FS_NOT_MOUNTED;
  if (capability_is_valid(fs.sentry)) {
    comp_invoke(fs.sentry, bounded(&fs_if));
  }
  if (fs_if.status != init::FS_OK || !capability_is_valid(fs_if.root_quota)) {
    L.say_dec("[init]     WARNING: fs handshake returned status -",
              static_cast<uint64_t>(-fs_if.status),
              "; nothing can be loaded from the disk\n");
  }
  L.fs_root = fs_if.root_quota;
  L.fs_open = fs_if.open;
  L.fs_read = fs_if.read;
  L.fs_close = fs_if.close;
  L.fs_mkdir = fs_if.mkdir;
  L.fs_derive = fs_if.quota_derive;
  L.fs_query = fs_if.quota_query;
  L.offer("fs", fs.sentry);
  // Disk-quota nodes are paid for by their creator, like the scheduler's:
  // this quota funds the nodes `init` derives for DISK entries.
  L.fs_node_funding = L.vm_quota(64 * 1024);

  // From here on every service is a file on the disk.

  // =========================================================================
  // 5. `naming`
  // =========================================================================
  const Started naming = L.start_file("naming.bin");
  // `naming` hands back its two operation entry points; from here on a
  // manifest can ask for `naming.lookup` or `naming.publish`, and `service`
  // finds anything published as well.
  init::NamingInterface naming_if{};
  if (capability_is_valid(naming.sentry)) {
    comp_invoke(naming.sentry, bounded(&naming_if));
  }
  const Capability naming_publish = naming_if.publish;
  const Capability naming_lookup = naming_if.lookup;
  const bool have_naming =
      sealing::is_sealed_as(OType::EntryPoint, naming_publish) &&
      sealing::is_sealed_as(OType::EntryPoint, naming_lookup);
  if (!have_naming) {
    say("[init]     WARNING: no naming service; nothing will be published\n");
  }
  L.offer("naming.publish", naming_publish);
  L.offer("naming.lookup", naming_lookup);
  L.naming_lookup = have_naming ? naming_lookup : nullptr;
  auto publish = [&](const char* name, Capability entry) {
    if (have_naming) {
      publish_name(L.invoke, naming_publish, name, entry);
    }
  };
  auto lookup = [&](const char* name) -> Capability {
    return have_naming ? lookup_name(L.invoke, naming_lookup, name) : nullptr;
  };

  publish("uart", uart.sentry);
  publish("loader", loader.sentry);
  // `fs` came up before `naming` existed, so its entry points are published
  // on its behalf, under the names its clients (the shell, the programs the
  // shell runs) ask for.
  publish("fs", fs.sentry);
  publish("fs.quota_derive", fs_if.quota_derive);
  publish("fs.quota_destroy", fs_if.quota_destroy);
  publish("fs.quota_query", fs_if.quota_query);
  publish("fs.create", fs_if.create);
  publish("fs.mkdir", fs_if.mkdir);
  publish("fs.open", fs_if.open);
  publish("fs.close", fs_if.close);
  publish("fs.read", fs_if.read);
  publish("fs.write", fs_if.write);
  publish("fs.unlink", fs_if.unlink);
  publish("fs.list", fs_if.list);

  // =========================================================================
  // 6. `sched`
  // =========================================================================
  const Started sched = L.start_file("sched.bin");
  // `sched` hands back the root `quota_sched` handle and its dispatcher entry
  // point; it publishes its operations ("sched.*") itself.
  init::SchedInterface sched_if{};
  sched_if.timebase_hz = board.timebase_hz;
  if (capability_is_valid(sched.sentry)) {
    comp_invoke(sched.sentry, bounded(&sched_if));
  }
  L.root_sched = sched_if.root_quota;
  L.offer("sched", sched.sentry);
  Capability sched_run = sched_if.run;
  const Capability sched_quota_derive = lookup("sched.quota_derive");
  const Capability sched_thread_register = lookup("sched.thread_register");
  if (!capability_is_valid(L.root_sched) || !capability_is_valid(sched_run)) {
    say("[init]     WARNING: sched handshake returned no root quota / run "
        "entry\n");
  }
  if (!capability_is_valid(sched_quota_derive) ||
      !capability_is_valid(sched_thread_register)) {
    say("[init]     WARNING: sched.* entry points not found in naming\n");
  }

  // Scheduler nodes are paid for by their creator: this quota funds the node
  // `init` derives for the shell below.
  const Capability sched_node_funding = L.vm_quota(64 * 1024);

  // Now that there is a scheduler, `blk` can sleep in it instead of polling.
  // Without it the disk still works, polled.
  if (blk_if.status == init::BLK_OK) {
    const Capability s_block = lookup("sched.block");
    const Capability s_wake = lookup("sched.wake");
    const Capability s_self = lookup("sched.self");
    int64_t st = init::BLK_BAD_REQUEST;
    if (sealing::is_sealed_as(OType::EntryPoint, s_block) &&
        sealing::is_sealed_as(OType::EntryPoint, s_wake) &&
        sealing::is_sealed_as(OType::EntryPoint, s_self)) {
      st = ::signetos::user::invoke<int64_t>(invoke, blk.sentry, s_block,
                                             s_wake, s_self);
    }
    if (st != init::BLK_OK) {
      say("[init]     WARNING: blk has no scheduler entries; the block device "
          "will poll\n");
    }
  }

  // =========================================================================
  // 7. `trap_mgr`
  // =========================================================================
  // Its manifest is the only one that asks for the PLIC or `IRQ_S_EXT`: it
  // decides which handler each device interrupt reaches.
  const Started trap_mgr = L.start_file("trap_mgr.bin");
  // Like `uart`, `trap_mgr` hands its routing entry to whoever brings it up
  // and to nobody else: `irq_route` is not published by name.
  init::TrapMgrInterface tm_if{};
  tm_if.plic_ndev = board.plic_ndev;
  for (size_t h = 0; h < platform::MAX_HARTS; ++h) {
    tm_if.plic_s_context[h] = board.plic_s_context[h];
  }
  if (capability_is_valid(trap_mgr.sentry)) {
    comp_invoke(trap_mgr.sentry, bounded(&tm_if));
  }
  const bool have_irq_route =
      sealing::is_sealed_as(OType::EntryPoint, tm_if.irq_route);

  // Platform wiring: a device's PLIC source reaches its driver's interrupt
  // entry. IRQ_OK, or the reason it is not.
  auto route_irq = [&](Capability handler, uint32_t source) -> int64_t {
    if (!have_irq_route || source == 0 ||
        !sealing::is_sealed_as(OType::EntryPoint, handler)) {
      return init::IRQ_BAD_REQUEST;
    }
    return ::signetos::user::invoke<int64_t>(
        invoke, tm_if.irq_route, handler, static_cast<uint64_t>(source));
  };
  // The UART's, which is what makes console input interrupt driven.
  if (route_irq(uart_irq, board.uart_irq) != init::IRQ_OK) {
    say("[init]     WARNING: the UART interrupt is not routed; console input "
        "will not wake\n");
  }
  // The block device's. Without the route the driver keeps polling.
  if (blk_if.status == init::BLK_OK) {
    const uint32_t source = (blk_if.slot < platform::MAX_VIRTIO_SLOTS)
                                ? board.virtio_irq[blk_if.slot]
                                : 0;
    if (route_irq(blk_if.irq, source) != init::IRQ_OK) {
      say("[init]     WARNING: the block device interrupt is not routed; "
          "the block device will poll\n");
    }
  }

  // =========================================================================
  // 8. `shell`
  // =========================================================================
  // The shell's manifest asks for the thread memory its workers run on, its
  // place on the disk -- `/home` as an ADMIN node with everything the
  // system's images leave free, `/bin` as a budget-less read-only view of the
  // programs (abi.hpp, "File system") -- and the system's root quotas: `init`
  // exits in a moment and scrubs its own table (step 10), so the shell is
  // their long-lived holder. All of it is granted by `Launcher::grant` as the
  // image starts; what is left here is its thread.
  const Started shell = L.start_file("shell.bin");
  const uint64_t timebase_hz = board.timebase_hz;
  Capability hz_cap = capability_and_perms(
      capability_set_bounds(
          reinterpret_cast<Capability>(const_cast<uint64_t*>(&timebase_hz)),
          sizeof(timebase_hz)),
      perms::Load);
  if (capability_is_valid(shell.sentry)) {
    comp_invoke(shell.sentry, hz_cap);
  }

  // The shell's CPU bandwidth: half the machine (50 ms per 100 ms period),
  // interactive class, administrative handle so it can sub-divide it for its
  // own threads.
  Capability shell_sched_quota = nullptr;
  if (capability_is_valid(sched_quota_derive) &&
      capability_is_valid(L.root_sched)) {
    init::SchedDeriveRequest dreq{};
    dreq.parent = L.root_sched;
    dreq.node_funding = sched_node_funding;
    dreq.budget_us = 50'000;
    dreq.period_us = 100'000;
    dreq.deadline_us = 0;
    dreq.policy_id = init::POLICY_SCHED_DEFAULT;
    dreq.perms = kAdminPerms;
    dreq.priority_class = init::PRIORITY_INTERACTIVE;
    dreq.status = init::SCHED_BAD_REQUEST;
    comp_invoke(sched_quota_derive, bounded(&dreq));
    if (dreq.status == init::SCHED_OK) {
      shell_sched_quota = dreq.out_quota;
    } else {
      L.say_dec(
          "[init]     WARNING: sched.quota_derive(shell) failed, status -",
          static_cast<uint64_t>(-dreq.status), "\n");
    }
  }

  // The shell's initial thread starts with its `quota_sched` handle as the
  // argument, and is handed to the scheduler, which runs it once `init` has
  // exited and the kernel starts driving the dispatcher.
  Capability shell_thread = nullptr;
  if (capability_is_valid(shell.sentry) &&
      capability_is_valid(L.shell_t_quota)) {
    shell_thread = thread_create(L.shell_t_quota, 16 * 1024, shell.sentry,
                                 shell_sched_quota);
  }
  if (capability_is_valid(shell_thread) &&
      capability_is_valid(sched_thread_register) &&
      capability_is_valid(shell_sched_quota)) {
    const int64_t tid = ::signetos::user::invoke<int64_t>(
        invoke, sched_thread_register, shell_thread, shell_sched_quota);
    if (tid <= 0) {
      say("[init]     WARNING: sched.thread_register(shell) failed\n");
    }
  } else {
    say("[init]     WARNING: no shell thread or no scheduler; nothing to "
        "dispatch\n");
    sched_run = nullptr;  // nothing to dispatch: let the kernel return
  }

  // =========================================================================
  // 9. Record all provisioned handles in `init`'s capability table
  // =========================================================================
  rw[init::RW_SLOT_UART_QUOTA] = uart.quota;
  rw[init::RW_SLOT_UART_COMP] = uart.comp;
  rw[init::RW_SLOT_UART_SENTRY] = uart.sentry;
  rw[init::RW_SLOT_LOADER_QUOTA] = loader.quota;
  rw[init::RW_SLOT_LOADER_COMP] = loader.comp;
  rw[init::RW_SLOT_LOADER_SENTRY] = loader.sentry;
  rw[init::RW_SLOT_NAMING_QUOTA] = naming.quota;
  rw[init::RW_SLOT_NAMING_COMP] = naming.comp;
  rw[init::RW_SLOT_NAMING_SENTRY] = naming.sentry;
  rw[init::RW_SLOT_SCHED_QUOTA] = sched.quota;
  rw[init::RW_SLOT_SCHED_COMP] = sched.comp;
  rw[init::RW_SLOT_SCHED_SENTRY] = sched.sentry;
  rw[init::RW_SLOT_TRAP_MGR_QUOTA] = trap_mgr.quota;
  rw[init::RW_SLOT_TRAP_MGR_COMP] = trap_mgr.comp;
  rw[init::RW_SLOT_TRAP_MGR_SENTRY] = trap_mgr.sentry;
  rw[init::RW_SLOT_FS_QUOTA] = fs.quota;
  rw[init::RW_SLOT_FS_COMP] = fs.comp;
  rw[init::RW_SLOT_FS_SENTRY] = fs.sentry;
  rw[init::RW_SLOT_SHELL_VM_QUOTA] = shell.quota;
  rw[init::RW_SLOT_SHELL_T_QUOTA] = L.shell_t_quota;
  rw[init::RW_SLOT_SHELL_COMP] = shell.comp;
  rw[init::RW_SLOT_SHELL_SENTRY] = shell.sentry;
  rw[init::RW_SLOT_SHELL_THREAD] = shell_thread;
  rw[init::RW_SLOT_NAMING_PUBLISH] = naming_publish;
  rw[init::RW_SLOT_NAMING_LOOKUP] = naming_lookup;
  rw[init::RW_SLOT_NAMING_PROOF] = lookup("uart");
  rw[init::RW_SLOT_SCHED_NODE_FUNDING] = sched_node_funding;
  rw[init::RW_SLOT_SHELL_SCHED_QUOTA] = shell_sched_quota;
  rw[init::RW_SLOT_BLK_QUOTA] = blk.quota;
  rw[init::RW_SLOT_BLK_COMP] = blk.comp;
  rw[init::RW_SLOT_BLK_SENTRY] = blk.sentry;
  rw[init::RW_SLOT_FS_NODE_FUNDING] = L.fs_node_funding;
  rw[init::RW_SLOT_SHELL_DISK_QUOTA] = L.shell_disk_quota;
  // Read back by the kernel once this thread exits (`init::launch` step 6).
  rw[init::RW_SLOT_SCHED_RUN] = sched_run;

  say("[init]     All core compartments provisioned and verified.\n");

  // =========================================================================
  // 10. Scrub: nothing runs in `init` after this thread exits, so nothing
  //     here may still be able to act. Every kernel gate, every IRQ and
  //     exception authority and both root quotas are cleared from the table,
  //     and the launcher's copies of everything it granted with them. What
  //     stays is inert without a gate: the handles recorded in step 9 and
  //     `RW_SLOT_SCHED_RUN`, which the kernel reads next. The locals this
  //     thread still holds die with its stack.
  // =========================================================================
  for (size_t s = init::RW_SLOT_SYSCALL_BASE; s < init::RW_SLOT_SCHED_RUN;
       ++s) {
    rw[s] = nullptr;
  }
  rw[compartment::SLOT_VM_QUOTA] = nullptr;
  zero_bytes(&s_launcher, sizeof(s_launcher));
  zero_bytes(&s_seeds[0], sizeof(s_seeds));

  thread_exit(0);
  return 0;
}

}  // namespace signetos::user
