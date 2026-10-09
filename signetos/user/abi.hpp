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
// abi.hpp - User-space service ABIs and `init` capability-table layout
//
// Cross-compartment calls through the switcher pass up to five arguments in
// `ca0..ca4` (caller `ca1..ca5`) and return a single register result in `ca0`
// (`a0`). Operations whose inputs and outputs fit in registers take them
// directly; operations with wider parameter blocks or multiple outputs
// (`loader`, `quota_derive`, `fs.quota_query`, and one-shot `*Interface` boot
// handshakes) pass a bounded capability to a struct defined below.
//
// Entries that return a `Capability` on success (`naming.lookup`, `fs.create`,
// `fs.open`) return a tagged handle on success and an untagged negative error
// code (`status_cap(err)`) on failure.
//

#include <signetos/init.hpp>

namespace signetos::init {

// Encodes a negative service status code as an untagged Capability return
// value for entries whose success return is a tagged Capability.
__attribute__((always_inline)) inline Capability status_cap(int64_t status) {
  return reinterpret_cast<Capability>(static_cast<uintptr_t>(status));
}

// Extracts the negative status code from a failed Capability return, or
// `fallback` if the call was refused by the switcher (`Status` > 0 or 0).
__attribute__((always_inline)) inline int64_t cap_error(
    Capability cap, int64_t fallback = -1) {
  const int64_t s = static_cast<int64_t>(capability_get_address(cap));
  return s < 0 ? s : fallback;
}

// Request block passed by a launcher (`init` or the shell) to the `loader`
// compartment in `ca0` (`int64_t loader(LoadRequest*)`).
struct alignas(16) LoadRequest {
  Capability vm_quota;      // in: child QuotaVm funding the new compartment
  Capability seeds;         // in: bounded capability to initial seed array
  Capability image;         // in: read-only capability to compartment `.bin`
  Capability out_comp;      // out: created `OType::Compartment` handle
  Capability out_sentry;    // out: minted `OType::EntryPoint` (CT = 12) sentry
};

// ----------------------------------------------------------------------------
// Naming service (`external/services/naming.cpp`)
// ----------------------------------------------------------------------------
//   int64_t    naming.publish(const char* name, Capability sentry)
//   Capability naming.lookup(const char* name) -> EntryPoint or status_cap(NAMING_*)
constexpr size_t NAME_MAX = 32;

constexpr int64_t NAMING_OK          = 0;
constexpr int64_t NAMING_BAD_REQUEST = -1;  // bad name or not an EntryPoint
constexpr int64_t NAMING_NOT_FOUND   = -2;
constexpr int64_t NAMING_EXISTS      = -3;
constexpr int64_t NAMING_FULL        = -4;

// Filled by `naming`'s `compartment_main` when invoked with a writable
// capability to one of these (owned by `init`).
struct alignas(16) NamingInterface {
  Capability publish;       // OType::EntryPoint -> naming_publish_entry
  Capability lookup;        // OType::EntryPoint -> naming_lookup_entry
};

// ----------------------------------------------------------------------------
// Console (`boot/uart.cpp`)
// ----------------------------------------------------------------------------
//   uint64_t uart(const char* str)
//   uint64_t uart.read(Capability buf, Capability wake) -> bytes read
//   uint64_t uart.irq(uint64_t source)
struct alignas(16) UartInterface {
  Capability read;          // OType::EntryPoint -> uart_read_entry
  Capability irq;           // OType::EntryPoint -> uart_irq_entry
};

// ----------------------------------------------------------------------------
// Interrupt routing (`external/services/trap_mgr.cpp`)
// ----------------------------------------------------------------------------
//   int64_t  trap_mgr.irq_route(Capability handler, uint64_t source) -> IRQ_*
//   uint64_t routed_handler(uint64_t source)
constexpr size_t IRQ_MAX_HANDLERS = 4;   // per source

constexpr int64_t IRQ_OK          = 0;
constexpr int64_t IRQ_BAD_REQUEST = -1;  // bad source, or not an EntryPoint
constexpr int64_t IRQ_FULL        = -2;

struct alignas(16) TrapMgrInterface {
  Capability irq_route;     // out: OType::EntryPoint -> trap_mgr_irq_route_entry
  uint32_t plic_ndev;       // in: max PLIC source number (from DTB; 0 = default)
  uint32_t pad_;
  uint32_t plic_s_context[platform::MAX_HARTS];  // in: hart -> S-mode PLIC context
};

// ----------------------------------------------------------------------------
// Scheduler service (`external/services/sched.cpp`)
// ----------------------------------------------------------------------------
//   int64_t  sched.quota_derive(SchedDeriveRequest* req) -> SCHED_*
//   int64_t  sched.quota_destroy(Capability quota) -> SCHED_*
//   int64_t  sched.thread_register(Capability thread, Capability quota) -> tid (>0) or SCHED_* (<0)
//   int64_t  sched.policy_register(Capability root, Capability delegate) -> policy_id (>0) or SCHED_* (<0)
//   int64_t  sched.yield() -> 0
//   int64_t  sched.block(uint64_t timeout_us) -> SCHED_OK, SCHED_TIMED_OUT or SCHED_KILLED
//   int64_t  sched.wake(uint64_t tid) -> SCHED_OK or SCHED_INVALID_THREAD
//   int64_t  sched.thread_kill(Capability thread) -> SCHED_OK, SCHED_PERMISSION or SCHED_INVALID_THREAD
//   uint64_t sched.self() -> tid (0 if unregistered)
//
// A killed thread never sleeps: every `block` it makes returns SCHED_KILLED
// at once. A caller waiting for something certain to happen (a device
// finishing a request it was given) keeps waiting, and so polls; one waiting
// for something that may never happen (input, another thread) gives up.

constexpr uint8_t PRIORITY_RT          = 0;
constexpr uint8_t PRIORITY_INTERACTIVE = 1;
constexpr uint8_t PRIORITY_NORMAL      = PRIORITY_INTERACTIVE;
constexpr uint8_t PRIORITY_BATCH       = 2;

constexpr uint32_t POLICY_SCHED_DEFAULT      = 0;   // resolves to ROUND_ROBIN
constexpr uint32_t POLICY_SCHED_ROUND_ROBIN  = 1;
constexpr uint32_t POLICY_SCHED_FIFO         = 2;
constexpr uint32_t POLICY_SCHED_EDF          = 3;
constexpr uint32_t POLICY_SCHED_FIRST_CUSTOM = 16;  // issued by sched.policy_register

// The root node: the whole machine, C = T.
constexpr uint32_t SCHED_ROOT_PERIOD_US = 1'000'000;

constexpr int64_t SCHED_OK             = 0;
constexpr int64_t SCHED_BAD_REQUEST    = -1;
constexpr int64_t SCHED_INVALID_QUOTA  = -2;
constexpr int64_t SCHED_PERMISSION     = -3;  // handle lacks Store permission
constexpr int64_t SCHED_BANDWIDTH      = -4;  // temporal conservation violated
constexpr int64_t SCHED_NO_MEMORY      = -5;  // node_funding could not pay
constexpr int64_t SCHED_BUSY           = -6;  // node still has children/threads
constexpr int64_t SCHED_FULL           = -7;
constexpr int64_t SCHED_INVALID_THREAD = -8;
constexpr int64_t SCHED_UNKNOWN_POLICY = -9;
constexpr int64_t SCHED_TIMED_OUT      = -10;  // block: the timeout ran out first
constexpr int64_t SCHED_KILLED         = -11;  // block: the caller was killed; it did not sleep

// sched.quota_derive: needs the ADMIN handle of `parent`.
struct alignas(16) SchedDeriveRequest {
  Capability parent;        // in
  Capability node_funding;  // in: QuotaVm that pays for the node's page
  Capability out_quota;     // out: handle of the new node
  uint32_t budget_us;       // in: C
  uint32_t period_us;       // in: T (>= C)
  uint32_t deadline_us;     // in: relative deadline D (0 = T)
  uint32_t policy_id;       // in: POLICY_SCHED_*
  uint32_t perms;           // in: perms::Store -> ADMIN handle, else OP handle
  uint8_t priority_class;   // in: PRIORITY_*
  uint8_t pad_[3];
  int64_t status;           // out: SCHED_*
};

// Filled by `sched`'s `compartment_main` when invoked with a writable
// capability to one of these (owned by `init`).
struct alignas(16) SchedInterface {
  Capability root_quota;    // out: ADMIN handle of the root node
  Capability run;           // out: OType::EntryPoint -> dispatcher (RW_SLOT_SCHED_RUN)
  uint64_t timebase_hz;     // in: `time` CSR frequency in Hz (from DTB; 0 = default)
  uint64_t pad_;
};

// Policy delegate contract.
constexpr uint32_t POLICY_PICK           = 1;
constexpr uint32_t POLICY_THREAD_ADDED   = 2;
constexpr uint32_t POLICY_THREAD_REMOVED = 3;
constexpr uint32_t POLICY_PERIOD_RESET   = 4;

struct alignas(16) PolicyView {
  uint64_t tid;
  uint64_t runtime_us;      // total CPU time charged so far
  uint64_t last_run_us;     // when it was last switched to
  uint32_t deadline_us;     // the node's relative deadline
  uint32_t runnable;
};

struct alignas(16) PolicyRequest {
  uint32_t op;              // POLICY_*
  uint32_t count;           // entries in `threads`
  uint64_t now_us;
  Capability threads;       // PICK: Load-only PolicyView[count]
  uint64_t tid;             // THREAD_ADDED / THREAD_REMOVED
  uint64_t pick;            // out (PICK)
  uint64_t node_id;         // stable per node
  uint64_t pad_;
};

// ----------------------------------------------------------------------------
// Block device driver (`boot/blk.cpp`)
// ----------------------------------------------------------------------------
//   int64_t  blk.read(Capability buf, uint64_t sector, uint64_t count) -> BLK_*
//   int64_t  blk.write(Capability buf, uint64_t sector, uint64_t count) -> BLK_*
//   uint64_t blk.irq(uint64_t source)
//   int64_t  blk(Capability block, Capability wake, Capability self) [2nd call]
constexpr uint64_t BLK_SECTOR_BYTES   = 512;
constexpr uint64_t BLK_MAX_XFER_BYTES = 4096;  // per request: the bounce buffer

constexpr int64_t BLK_OK           = 0;
constexpr int64_t BLK_BAD_REQUEST  = -1;  // bad buffer, count 0 or too large
constexpr int64_t BLK_NO_DEVICE    = -2;  // no virtio-blk device was found
constexpr int64_t BLK_OUT_OF_RANGE = -3;  // past the end of the device
constexpr int64_t BLK_IO_ERROR     = -4;  // the device reported an error
constexpr int64_t BLK_BUSY         = -5;  // a request is already in flight

struct alignas(16) BlkInterface {
  Capability read;          // out: OType::EntryPoint -> blk_read_entry
  Capability write;         // out: OType::EntryPoint -> blk_write_entry
  Capability irq;           // out: OType::EntryPoint -> blk_irq_entry
  uint64_t dma_phys;        // in: physical address of the DMA window's base
  uint64_t virtio_slot_bytes;  // in: stride between slots in the window
  uint64_t capacity_sectors;   // out: device size
  uint32_t virtio_count;    // in: slots in the window
  uint32_t slot;            // out: the slot the device was found in
  int64_t status;           // out: BLK_OK or BLK_NO_DEVICE
  uint64_t pad_;
};

// ----------------------------------------------------------------------------
// File system (`boot/fs.cpp`)
// ----------------------------------------------------------------------------
//   int64_t    fs.quota_derive(FsDeriveRequest* req) -> FS_*
//   int64_t    fs.quota_destroy(Capability quota) -> FS_*
//   int64_t    fs.quota_query(FsQueryRequest* req) -> FS_*
//   Capability fs.create(Capability quota, const char* path, uint32_t perms) -> file or status_cap(FS_*)
//   Capability fs.open(Capability quota, const char* path, uint32_t perms, uint64_t* out_size) -> file or status_cap(FS_*)
//   int64_t    fs.read(Capability file, Capability buf, uint64_t offset, uint64_t length) -> bytes (>=0) or FS_* (<0)
//   int64_t    fs.write(Capability file, Capability buf, uint64_t offset, uint64_t length) -> bytes (>=0) or FS_* (<0)
//   int64_t    fs.close(Capability file) -> FS_*
//   int64_t    fs.mkdir(Capability quota, const char* path) -> FS_*
//   int64_t    fs.unlink(Capability quota, const char* path) -> FS_*
//   int64_t    fs.list(Capability quota, const char* path, Capability entries, uint64_t capacity, uint64_t* out_total) -> count (>=0) or FS_* (<0)

constexpr size_t   FS_NAME_MAX       = 32;         // one component, including the NUL
constexpr size_t   FS_PATH_MAX       = 96;         // a path, including the NUL
constexpr uint64_t FS_BLOCK_BYTES    = 4096;       // allocation unit on disk
constexpr uint64_t FS_DIRECT_BLOCKS  = 16;
constexpr uint64_t FS_INDIRECT_SLOTS = FS_BLOCK_BYTES / sizeof(uint32_t);  // 1024
constexpr uint64_t FS_MAX_FILE_BLOCKS = FS_DIRECT_BLOCKS + FS_INDIRECT_SLOTS;
constexpr uint64_t FS_MAX_FILE_BYTES = FS_MAX_FILE_BLOCKS * FS_BLOCK_BYTES;  // 4,160 KiB

constexpr int64_t FS_OK            = 0;
constexpr int64_t FS_BAD_REQUEST   = -1;   // malformed request or path
constexpr int64_t FS_INVALID_QUOTA = -2;   // not a quota_disk handle
constexpr int64_t FS_PERMISSION    = -3;   // handle lacks Store, or the file is not its to change
constexpr int64_t FS_QUOTA         = -4;   // the quota's bytes or inodes are used up
constexpr int64_t FS_NO_MEMORY     = -5;   // node_funding could not pay; node table or the node's open files full
constexpr int64_t FS_BUSY          = -6;   // quota has children; directory is a node's root
constexpr int64_t FS_NOT_FOUND     = -7;   // nothing of that path under the handle's root
constexpr int64_t FS_EXISTS        = -8;
constexpr int64_t FS_INVALID_FILE  = -9;   // not an open file handle
constexpr int64_t FS_TOO_LARGE     = -10;  // beyond FS_MAX_FILE_BYTES
constexpr int64_t FS_IO_ERROR      = -11;  // the block device failed
constexpr int64_t FS_DISK_FULL     = -12;  // no free block or inode on the disk
constexpr int64_t FS_NOT_MOUNTED   = -13;
constexpr int64_t FS_NOT_DIR       = -14;  // a directory was needed
constexpr int64_t FS_IS_DIR        = -15;  // a file was needed
constexpr int64_t FS_NOT_EMPTY     = -16;  // unlink of a directory with entries

constexpr uint64_t FS_DERIVE_ADOPT = 1;

struct alignas(16) FsDeriveRequest {
  Capability parent;        // in
  Capability node_funding;  // in: QuotaVm that pays for the node's page
  Capability out_quota;     // out: handle of the new node, per `perms`
  Capability out_admin;     // out: its ADMIN handle (the one to destroy it with)
  char path[FS_PATH_MAX];   // in: the child's root directory, under the parent's
  uint64_t limit_bytes;     // in: multiple of FS_BLOCK_BYTES
  uint32_t limit_inodes;    // in
  uint32_t perms;           // in: perms::Store -> ADMIN handle, else OP handle
  int64_t status;           // out: FS_*
  uint64_t flags;           // in: FS_DERIVE_*, or 0
};

// fs.quota_query: either handle.
struct alignas(16) FsQueryRequest {
  Capability quota;         // in
  uint64_t limit_bytes;     // out
  uint64_t used_bytes;      // out: by this node's own files
  uint64_t delegated_bytes; // out: to children
  uint32_t limit_inodes;    // out
  uint32_t used_inodes;     // out
  uint32_t delegated_inodes;// out
  uint32_t pad_;
  int64_t status;           // out
  uint64_t pad2_;
};

constexpr size_t FS_OPEN_PER_NODE = 246;

constexpr uint32_t FS_OWNER_OTHER = 0;  // another node's: read-only to this handle
constexpr uint32_t FS_OWNER_SELF  = 1;  // the listing node's own
constexpr uint32_t FS_OWNER_CHILD = 2;  // a descendant's

struct alignas(16) FsDirEntry {
  char name[FS_NAME_MAX];
  uint64_t size;
  uint32_t inode;
  uint32_t owner;           // FS_OWNER_*
  uint32_t is_dir;
  uint32_t pad_[3];
};

struct alignas(16) FsInterface {
  Capability root_quota;    // out: ADMIN handle of the root node
  Capability quota_derive;  // out: OType::EntryPoint
  Capability quota_destroy; // out: OType::EntryPoint
  Capability quota_query;   // out: OType::EntryPoint
  Capability create;        // out: OType::EntryPoint
  Capability mkdir;         // out: OType::EntryPoint
  Capability open;          // out: OType::EntryPoint
  Capability close;         // out: OType::EntryPoint
  Capability read;          // out: OType::EntryPoint
  Capability write;         // out: OType::EntryPoint
  Capability unlink;        // out: OType::EntryPoint
  Capability list;          // out: OType::EntryPoint
  uint64_t capacity_sectors;// in: the device's size (BlkInterface)
  uint64_t total_bytes;     // out: data bytes the disk can hold
  uint64_t used_bytes;      // out: in use after mount
  int64_t status;           // out: FS_*
  uint32_t total_inodes;    // out
  uint32_t used_inodes;     // out
  uint32_t formatted;       // out: 1 if a fresh file system was written
  uint32_t pad_;
};

// ----------------------------------------------------------------------------
// Applications (`external/apps/*.cpp`)
// ----------------------------------------------------------------------------
constexpr size_t APP_ARGS_MAX = 64;

struct alignas(16) AppRequest {
  char args[APP_ARGS_MAX];  // in: the rest of the command line, NUL-terminated
  int64_t status;           // out: the program's exit status; 0 is success
  uint64_t ticks_per_us;    // in: `time` ticks per us (from DTB timebase-frequency)
};

// ============================================================================
// 1. `init` Compartment Capability Table Layout (`cgp`)
// ============================================================================

constexpr size_t RW_SLOT_PROVISIONED_BASE    = RW_SLOT_SCHED_RUN + 1;
constexpr size_t RW_SLOT_UART_QUOTA          = RW_SLOT_PROVISIONED_BASE + 0;
constexpr size_t RW_SLOT_UART_COMP           = RW_SLOT_PROVISIONED_BASE + 1;
constexpr size_t RW_SLOT_UART_SENTRY         = RW_SLOT_PROVISIONED_BASE + 2;
constexpr size_t RW_SLOT_LOADER_QUOTA        = RW_SLOT_PROVISIONED_BASE + 3;
constexpr size_t RW_SLOT_LOADER_COMP         = RW_SLOT_PROVISIONED_BASE + 4;
constexpr size_t RW_SLOT_LOADER_SENTRY       = RW_SLOT_PROVISIONED_BASE + 5;
constexpr size_t RW_SLOT_NAMING_QUOTA        = RW_SLOT_PROVISIONED_BASE + 6;
constexpr size_t RW_SLOT_NAMING_COMP         = RW_SLOT_PROVISIONED_BASE + 7;
constexpr size_t RW_SLOT_NAMING_SENTRY       = RW_SLOT_PROVISIONED_BASE + 8;
constexpr size_t RW_SLOT_SCHED_QUOTA         = RW_SLOT_PROVISIONED_BASE + 9;
constexpr size_t RW_SLOT_SCHED_COMP          = RW_SLOT_PROVISIONED_BASE + 10;
constexpr size_t RW_SLOT_SCHED_SENTRY        = RW_SLOT_PROVISIONED_BASE + 11;
constexpr size_t RW_SLOT_TRAP_MGR_QUOTA      = RW_SLOT_PROVISIONED_BASE + 12;
constexpr size_t RW_SLOT_TRAP_MGR_COMP       = RW_SLOT_PROVISIONED_BASE + 13;
constexpr size_t RW_SLOT_TRAP_MGR_SENTRY     = RW_SLOT_PROVISIONED_BASE + 14;
constexpr size_t RW_SLOT_FS_QUOTA            = RW_SLOT_PROVISIONED_BASE + 15;
constexpr size_t RW_SLOT_FS_COMP             = RW_SLOT_PROVISIONED_BASE + 16;
constexpr size_t RW_SLOT_FS_SENTRY           = RW_SLOT_PROVISIONED_BASE + 17;
constexpr size_t RW_SLOT_SHELL_VM_QUOTA      = RW_SLOT_PROVISIONED_BASE + 18;
constexpr size_t RW_SLOT_SHELL_T_QUOTA       = RW_SLOT_PROVISIONED_BASE + 19;
constexpr size_t RW_SLOT_SHELL_COMP          = RW_SLOT_PROVISIONED_BASE + 20;
constexpr size_t RW_SLOT_SHELL_SENTRY        = RW_SLOT_PROVISIONED_BASE + 21;
constexpr size_t RW_SLOT_SHELL_THREAD        = RW_SLOT_PROVISIONED_BASE + 22;
constexpr size_t RW_SLOT_NAMING_PUBLISH      = RW_SLOT_PROVISIONED_BASE + 23;
constexpr size_t RW_SLOT_NAMING_LOOKUP       = RW_SLOT_PROVISIONED_BASE + 24;
constexpr size_t RW_SLOT_NAMING_PROOF        = RW_SLOT_PROVISIONED_BASE + 25;
constexpr size_t RW_SLOT_SCHED_NODE_FUNDING  = RW_SLOT_PROVISIONED_BASE + 26;
constexpr size_t RW_SLOT_SHELL_SCHED_QUOTA   = RW_SLOT_PROVISIONED_BASE + 27;
constexpr size_t RW_SLOT_BLK_QUOTA           = RW_SLOT_PROVISIONED_BASE + 28;
constexpr size_t RW_SLOT_BLK_COMP            = RW_SLOT_PROVISIONED_BASE + 29;
constexpr size_t RW_SLOT_BLK_SENTRY          = RW_SLOT_PROVISIONED_BASE + 30;
constexpr size_t RW_SLOT_FS_NODE_FUNDING     = RW_SLOT_PROVISIONED_BASE + 31;
constexpr size_t RW_SLOT_SHELL_DISK_QUOTA    = RW_SLOT_PROVISIONED_BASE + 32;

__attribute__((always_inline)) inline constexpr size_t syscall_slot(
    syscall::Id id) {
  return RW_SLOT_SYSCALL_BASE + static_cast<size_t>(id);
}

__attribute__((always_inline)) inline constexpr size_t irq_slot(uint64_t irq) {
  return RW_SLOT_IRQ_BASE + static_cast<size_t>(irq);
}

__attribute__((always_inline)) inline constexpr size_t exc_slot(uint64_t exc) {
  return RW_SLOT_EXC_BASE + static_cast<size_t>(exc);
}

}  // namespace signetos::init
