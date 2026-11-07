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
// manifest.hpp - What a compartment image asks its launcher for
//
// A compartment holds exactly what whoever created it put in its capability
// table, and nothing else (there is no directory a program can ask). So
// the image has to say what it wants, in a form the launcher can read before
// anything is created: the manifest, a table in the image's `.rodata` that
// `CompartmentImageHeader::manifest_start/end` point at.
//
// THE MANIFEST IS A REQUEST, NEVER AN AUTHORITY
//   It is bytes in a file: it cannot carry a capability and must not be able
//   to confer one. It names kinds of things and their parameters -- how much,
//   where, which permissions -- and the launcher, which holds the authority,
//   applies its own policy to each line and derives every grant from what it
//   holds itself: its disk quota, its VM quota, the sentries it has. A program
//   can never reach further than the launcher that started it. An entry with
//   MANIFEST_REQUIRED that the policy will not meet means the program is not
//   started at all, rather than started with a hole; one without it is a null
//   seed, and the program cannot tell "refused" from "unavailable", which is
//   right.
//
// WHO READS IT
//   The launcher (the shell's `run`, `init` for the services) interprets it
//   and builds the seed array, entry i into seed slot RW_SLOT_SEED_BASE + i.
//   `user::create_compartment` checks that the manifest is well formed and
//   that the seed array has `count` entries, so that an image can rely on
//   slot i being its entry i.
//
// DECLARING ONE
//   An image lists what it needs once, as an X-macro; `SIGNETOS_MANIFEST`
//   turns the list into both the `.manifest` table and the slot constants, so
//   the two cannot disagree:
//
//     #define HELLO_MANIFEST(X)                                       \
//       M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)             \
//       M_SERVICE(X, UART_SENTRY, "uart")                             \
//       M_OWN_DIR(X, HOME)
//     SIGNETOS_MANIFEST(HELLO_MANIFEST, 64 * 1024)
//
//     ... rw[SLOT_UART_SENTRY] ...
//
//   MANIFEST_COUNT is the number of entries, so the first slot after the
//   seeds is `RW_SLOT_SEED_BASE + MANIFEST_COUNT` -- where an image keeps
//   whatever it mints at run time.
//

#include <signetos/compartment.hpp>
#include <signetos/init.hpp>
#include <signetos/syscall.hpp>
#include <signetos/types.hpp>

#include "abi.hpp"

namespace signetos::init {

constexpr uint64_t MANIFEST_MAGIC = 0x5349474e4d4e4654ULL;  // "SIGNMNFT"
// 2: seeds start at `compartment::RW_SLOT_SEED_BASE` (7) instead of slot 1,
// so an image built for version 1 would read the wrong slots and is refused.
constexpr uint32_t MANIFEST_VERSION = 2;
constexpr uint32_t MANIFEST_MAX = 64;  // entries; the table is one page
constexpr size_t MANIFEST_NAME_BYTES = 96;  // ManifestEntry::name, NUL included

// Kinds. Which parameters each uses:
//   SYSCALL       count = syscall::Id; the kernel entry (compartment_invoke is
//                 the switcher, the one every compartment needs)
//   SERVICE       name = an entry point the launcher holds, by the name it is
//                 published under ("uart", "fs.open", "naming.lookup", ...)
//   DIR, FILE,    an fs handle for a request: name = what the image calls
//   QUOTA_DISK    it, perms = FS_* rights wanted. The launcher picks what
//                 fills it. With MANIFEST_OWN, the program's own directory
//                 or disk quota (launch.hpp); for the quota, amount = bytes
//                 it starts with
//   QUOTA_VM      the QuotaVm the compartment is funded from (`vm_bytes`,
//                 derived by the launcher from its own), as an ADMIN handle.
//                 The kernel does not put it in the table: an image that
//                 allocates asks for it here, like for any other quota
//   QUOTA_SCHED   a `quota_sched` node derived under the launcher's own, for
//                 as long as the launcher chooses: amount = budget C (us),
//                 count = period T (us), param = priority class (PRIORITY_*)
//   MMIO          name = a device window: "uart", "plic", "virtio"
//   DMA           amount = bytes of physically contiguous memory
//   QUOTA_THREAD  amount = bytes of thread memory, as an ADMIN QuotaThreadMem
//   ROOT          count = ROOT_*: one of the system's root quotas
//   OTYPE         count = OType: hardware sealing authority for a service OType
// The last five are the system's own: no launcher but `init` can meet them.
// (Kinds 7 and 8, interrupt and exception authorities, are retired: the two
// interrupt handlers are installed by `init` itself, trap.hpp.)
constexpr uint32_t MANIFEST_SYSCALL      = 1;
constexpr uint32_t MANIFEST_SERVICE      = 2;
constexpr uint32_t MANIFEST_DIR          = 3;
constexpr uint32_t MANIFEST_FILE         = 4;
constexpr uint32_t MANIFEST_MMIO         = 5;
constexpr uint32_t MANIFEST_DMA          = 6;
constexpr uint32_t MANIFEST_QUOTA_THREAD = 9;
constexpr uint32_t MANIFEST_ROOT         = 10;
constexpr uint32_t MANIFEST_OTYPE        = 11;
constexpr uint32_t MANIFEST_QUOTA_VM     = 12;
constexpr uint32_t MANIFEST_QUOTA_SCHED  = 13;
constexpr uint32_t MANIFEST_QUOTA_DISK   = 14;

constexpr uint32_t MANIFEST_REQUIRED = 1;  // flags: do not start me without it
constexpr uint32_t MANIFEST_OWN = 2;       // flags: DIR, QUOTA_DISK: my own

constexpr uint32_t ROOT_VM         = 1;  // the root QuotaVm
constexpr uint32_t ROOT_THREAD_MEM = 2;  // the root QuotaThreadMem
constexpr uint32_t ROOT_SCHED      = 4;  // the root quota_sched

struct alignas(16) ManifestHeader {
  uint64_t magic;     // MANIFEST_MAGIC
  uint32_t version;   // MANIFEST_VERSION
  uint32_t count;     // entries following; entry i <-> seed slot SEED_BASE + i
  uint64_t vm_bytes;  // memory the image asks to run on (0: launcher's default)
  uint64_t reserved_;
};
static_assert(sizeof(ManifestHeader) == 32, "ManifestHeader is 32 bytes");

struct alignas(16) ManifestEntry {
  uint32_t kind;            // MANIFEST_*
  uint32_t flags;           // MANIFEST_REQUIRED, MANIFEST_OWN
  uint32_t perms;           // DIR, FILE, QUOTA_DISK: FS_* rights
  uint32_t count;           // SYSCALL: id; ROOT; OTYPE; QUOTA_SCHED: period (us)
  uint64_t amount;          // DMA, QUOTA_THREAD, own QUOTA_DISK: bytes;
                            // QUOTA_SCHED: budget (us)
  uint64_t param;           // QUOTA_SCHED: priority class (PRIORITY_*)
  char name[MANIFEST_NAME_BYTES];  // SERVICE, DIR, FILE, QUOTA_DISK, MMIO; NUL-terminated
};
static_assert(sizeof(ManifestEntry) == 128, "ManifestEntry is 128 bytes");

// A checked view of an image's manifest.
struct Manifest {
  const ManifestEntry* entries;  // `count` of them; nullptr if none
  uint32_t count;
  uint64_t vm_bytes;
};

// Finds and checks the manifest of `image`, whose header `hdr` is
// (`image_header`). True with `*out` filled in -- `count` 0 for an image that
// carries none -- or false if what the header points at is not a well-formed
// manifest: outside the read-only prefix, unaligned, the wrong magic or
// version, too many entries, a size that does not match the count, an entry
// of kind 0 or with a name that is not NUL-terminated. Kinds this header does
// not know are left to the launcher, which cannot meet them.
inline bool manifest_of(Capability image, const CompartmentImageHeader* hdr,
                        Manifest* out) {
  out->entries = nullptr;
  out->count = 0;
  out->vm_bytes = 0;
  const uint64_t start = hdr->manifest_start;
  const uint64_t end = hdr->manifest_end;
  if (start == end) {
    return true;
  }
  const uint64_t image_len = capability_get_length(image);
  if (start < sizeof(CompartmentImageHeader) ||
      (start & (sizeof(Capability) - 1)) != 0 || end < start ||
      end > hdr->rodata_end || end > image_len ||
      end - start < sizeof(ManifestHeader)) {
    return false;
  }
  const auto* base = reinterpret_cast<const uint8_t*>(image);
  const auto* header = reinterpret_cast<const ManifestHeader*>(base + start);
  if (header->magic != MANIFEST_MAGIC || header->version != MANIFEST_VERSION ||
      header->count > MANIFEST_MAX ||
      end - start != sizeof(ManifestHeader) +
                         static_cast<uint64_t>(header->count) *
                             sizeof(ManifestEntry)) {
    return false;
  }
  const auto* entries = reinterpret_cast<const ManifestEntry*>(
      base + start + sizeof(ManifestHeader));
  for (uint32_t i = 0; i < header->count; ++i) {
    if (entries[i].kind == 0) {
      return false;
    }
    bool terminated = false;
    for (size_t j = 0; j < MANIFEST_NAME_BYTES && !terminated; ++j) {
      terminated = entries[i].name[j] == '\0';
    }
    if (!terminated) {
      return false;
    }
  }
  out->entries = entries;
  out->count = header->count;
  out->vm_bytes = header->vm_bytes;
  return true;
}

// True for the kinds met with an fs handle.
inline bool manifest_is_fs(uint32_t kind) {
  return kind == MANIFEST_DIR || kind == MANIFEST_FILE ||
         kind == MANIFEST_QUOTA_DISK;
}

// For a launcher's console: what kind of thing an entry asks for.
inline const char* manifest_kind_name(uint32_t kind) {
  switch (kind) {
    case MANIFEST_SYSCALL: return "syscall";
    case MANIFEST_SERVICE: return "service";
    case MANIFEST_DIR: return "dir";
    case MANIFEST_FILE: return "file";
    case MANIFEST_QUOTA_DISK: return "disk quota";
    case MANIFEST_MMIO: return "mmio";
    case MANIFEST_DMA: return "dma";
    case MANIFEST_QUOTA_THREAD: return "thread memory";
    case MANIFEST_QUOTA_VM: return "vm quota";
    case MANIFEST_QUOTA_SCHED: return "cpu bandwidth";
    case MANIFEST_ROOT: return "root quota";
    case MANIFEST_OTYPE: return "otype";
    default: return "unknown";
  }
}

// ... and which kernel entry a SYSCALL entry names.
inline const char* manifest_syscall_name(uint32_t id) {
  switch (static_cast<syscall::Id>(id)) {
#define SIGNETOS_MANIFEST_SYSCALL_NAME_(n) \
  case syscall::Id::n:                     \
    return #n;
    SIGNETOS_SYSCALLS(SIGNETOS_MANIFEST_SYSCALL_NAME_)
#undef SIGNETOS_MANIFEST_SYSCALL_NAME_
    default: return "?";
  }
}

}  // namespace signetos::init

// --- Declaring a manifest (see the top of the file) ---------------------------
//
// Each M_* line is one entry: the slot's name (SLOT_<name> is generated), then
// the kind's parameters. Everything is REQUIRED unless the _OPT form is used,
// or `flags` is given explicitly (DIR, FILE, QUOTA_DISK).
#define M_SYSCALL(X, slot, id)                                               \
  X(slot, ::signetos::init::MANIFEST_SYSCALL, ::signetos::init::MANIFEST_REQUIRED, \
    0, static_cast<uint32_t>(::signetos::syscall::Id::id), 0, 0, "")
#define M_SERVICE(X, slot, name)                                             \
  X(slot, ::signetos::init::MANIFEST_SERVICE, ::signetos::init::MANIFEST_REQUIRED, \
    0, 0, 0, 0, name)
#define M_SERVICE_OPT(X, slot, name)                                         \
  X(slot, ::signetos::init::MANIFEST_SERVICE, 0, 0, 0, 0, 0, name)
#define M_DIR(X, slot, flags, rights, role)                                  \
  X(slot, ::signetos::init::MANIFEST_DIR, flags, rights, 0, 0, 0, role)
#define M_FILE(X, slot, flags, rights, role)                                 \
  X(slot, ::signetos::init::MANIFEST_FILE, flags, rights, 0, 0, 0, role)
#define M_QUOTA_DISK(X, slot, flags, rights, role)                           \
  X(slot, ::signetos::init::MANIFEST_QUOTA_DISK, flags, rights, 0, 0, 0, role)
// The program's own directory and disk quota (launch.hpp), the quota made
// with `bytes` the first time.
#define M_OWN_DIR(X, slot)                                                   \
  X(slot, ::signetos::init::MANIFEST_DIR,                                    \
    ::signetos::init::MANIFEST_REQUIRED | ::signetos::init::MANIFEST_OWN,    \
    ::signetos::init::FS_ALL, 0, 0, 0, "own")
#define M_OWN_DISK(X, slot, bytes)                                           \
  X(slot, ::signetos::init::MANIFEST_QUOTA_DISK,                             \
    ::signetos::init::MANIFEST_REQUIRED | ::signetos::init::MANIFEST_OWN,    \
    ::signetos::init::FS_READ | ::signetos::init::FS_ADD, 0, bytes, 0, "own")
#define M_MMIO(X, slot, device)                                              \
  X(slot, ::signetos::init::MANIFEST_MMIO, ::signetos::init::MANIFEST_REQUIRED, \
    0, 0, 0, 0, device)
#define M_MMIO_OPT(X, slot, device)                                          \
  X(slot, ::signetos::init::MANIFEST_MMIO, 0, 0, 0, 0, 0, device)
#define M_DMA_OPT(X, slot, bytes)                                            \
  X(slot, ::signetos::init::MANIFEST_DMA, 0, 0, 0, bytes, 0, "")
#define M_QUOTA_VM(X, slot)                                                  \
  X(slot, ::signetos::init::MANIFEST_QUOTA_VM,                               \
    ::signetos::init::MANIFEST_REQUIRED, 0, 0, 0, 0, "")
#define M_QUOTA_THREAD(X, slot, bytes)                                       \
  X(slot, ::signetos::init::MANIFEST_QUOTA_THREAD,                           \
    ::signetos::init::MANIFEST_REQUIRED, 0, 0, bytes, 0, "")
#define M_QUOTA_SCHED(X, slot, budget_us, period_us, priority_class)         \
  X(slot, ::signetos::init::MANIFEST_QUOTA_SCHED,                            \
    ::signetos::init::MANIFEST_REQUIRED, 0, period_us, budget_us,            \
    priority_class, "")
#define M_ROOT_OPT(X, slot, which)                                           \
  X(slot, ::signetos::init::MANIFEST_ROOT, 0, 0, which, 0, 0, "")
#define M_OTYPE(X, slot, otype)                                              \
  X(slot, ::signetos::init::MANIFEST_OTYPE, ::signetos::init::MANIFEST_REQUIRED, \
    0, static_cast<uint32_t>(otype), 0, 0, "")

#define SIGNETOS_MANIFEST_INDEX_(slot, kind, flags, perms, count, amount,    \
                                 param, name)                                \
  MANIFEST_INDEX_##slot,
#define SIGNETOS_MANIFEST_SLOT_(slot, kind, flags, perms, count, amount,     \
                                param, name)                                 \
  [[maybe_unused]] constexpr size_t SLOT_##slot =                             \
      ::signetos::compartment::RW_SLOT_SEED_BASE + MANIFEST_INDEX_##slot;
#define SIGNETOS_MANIFEST_ENTRY_(slot, kind, flags, perms, count, amount,    \
                                 param, name)                                \
  {kind, flags, perms, count, amount, param, name},

// Emits, in the enclosing namespace: `MANIFEST_INDEX_<slot>` and
// `SLOT_<slot>` for every entry, `MANIFEST_COUNT`, and the table itself in
// the `.manifest` section (kept whether or not anything refers to it).
// `vm_bytes` is the memory the image asks to run on.
#define SIGNETOS_MANIFEST(LIST, vm_bytes)                                    \
  enum : uint32_t { LIST(SIGNETOS_MANIFEST_INDEX_) MANIFEST_COUNT };         \
  LIST(SIGNETOS_MANIFEST_SLOT_)                                              \
  struct alignas(16) ManifestBlock {                                         \
    ::signetos::init::ManifestHeader header;                                 \
    ::signetos::init::ManifestEntry entries[MANIFEST_COUNT];                 \
  };                                                                         \
  __attribute__((used, section(".manifest")))                                \
  const ManifestBlock kManifest = {                                          \
      {::signetos::init::MANIFEST_MAGIC, ::signetos::init::MANIFEST_VERSION, \
       MANIFEST_COUNT, (vm_bytes), 0},                                       \
      {LIST(SIGNETOS_MANIFEST_ENTRY_)}};                                     \
  static_assert(MANIFEST_COUNT <= ::signetos::init::MANIFEST_MAX,            \
                "too many manifest entries");
