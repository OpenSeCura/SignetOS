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
// abi.hpp - Capability-table layouts of the SignetOS core user-space services
//
// This is user-space ABI shared between `init` (which provisions each
// service's capability table) and the services themselves. The kernel does not
// depend on anything in this file.
//

#include <signetos/init.hpp>

namespace signetos::init {

// Request block passed by `init` (or any parent compartment) to the `loader`
// compartment in `ca0` via `sys_compartment_invoke(loader_sentry, &req)`.
struct alignas(16) LoadRequest {
  Capability vm_quota;      // in: child QuotaVm funding the new compartment
  Capability seeds;         // in: bounded capability to initial seed array
  Capability image;         // in: read-only capability to compartment `.bin`
  Capability out_comp;      // out: created `OType::Compartment` handle
  Capability out_sentry;    // out: minted `OType::EntryPoint` (CT = 12) sentry
};

// Naming service (`src/user/naming.cpp`). One request block serves both
// operations; the caller passes a bounded, writable capability to it.
constexpr size_t NAME_MAX = 32;

constexpr int64_t NAMING_OK          = 0;
constexpr int64_t NAMING_BAD_REQUEST = -1;  // bad name or not an EntryPoint
constexpr int64_t NAMING_NOT_FOUND   = -2;
constexpr int64_t NAMING_EXISTS      = -3;
constexpr int64_t NAMING_FULL        = -4;

struct alignas(16) NamingRequest {
  char name[NAME_MAX];      // in: NUL-terminated service name
  Capability sentry;        // publish: in; lookup: out (nullptr if absent)
  int64_t status;           // out: NAMING_*
  uint64_t pad_;
};

// Filled by `naming`'s `compartment_main` when invoked with a writable
// capability to one of these (owned by `init`).
struct alignas(16) NamingInterface {
  Capability publish;       // OType::EntryPoint -> naming_publish_entry
  Capability lookup;        // OType::EntryPoint -> naming_lookup_entry
};

// ----------------------------------------------------------------------------
// Console (`src/user/uart.cpp`)
// ----------------------------------------------------------------------------
// Output is the compartment's main entry point, published as "uart": invoke it
// with a Load-only capability to a NUL-terminated string.
//
// Input is interrupt driven. `uart` mints two more entry points exactly once,
// on its very first invocation, when `init` hands it a writable
// `UartInterface`: `read`, which `init` seeds to the shell alone, and `irq`,
// which `init` routes the UART's PLIC source to through `trap_mgr`. The
// one-shot matters: every service gets to print, but only whoever `init`
// seeds `read` to gets to see what is typed.
struct alignas(16) UartInterface {
  Capability read;          // OType::EntryPoint -> uart_read_entry
  Capability irq;           // OType::EntryPoint -> uart_irq_entry
};

// uart.read: copies whatever the interrupt handler has buffered so far into
// `buf` without blocking and reports how many bytes. `buf` must be writable.
//
// If `wake` is an OType::EntryPoint it is remembered and invoked once, with a
// null argument and from interrupt context, the next time input arrives --
// unless this very call returned data, in which case it is dropped, since the
// caller is about to call again anyway. Between calls the reader sleeps in
// `sched.block`, and `wake` is how it asks to be woken; see shell.cpp.
struct alignas(16) UartReadRequest {
  Capability buf;           // in: writable byte buffer
  Capability wake;          // in: optional OType::EntryPoint
  uint64_t count;           // out: bytes stored; 0 if nothing was pending
  uint64_t pad_;
};

// ----------------------------------------------------------------------------
// Interrupt routing (`src/user/trap_mgr.cpp`; spec 3.6)
// ----------------------------------------------------------------------------
// `trap_mgr` owns the PLIC window and binds `IRQ_S_EXT`. Its handler claims
// each pending source, invokes every entry point routed to that source in
// order with a Load-only `IrqEvent`, then completes the claim. Routed entry
// points run in interrupt context: on the interrupted thread's narrowed
// stack with interrupts masked. They may invoke other compartments but must
// be short and must never block or switch threads.
constexpr size_t IRQ_MAX_HANDLERS = 4;   // per source

constexpr int64_t IRQ_OK          = 0;
constexpr int64_t IRQ_BAD_REQUEST = -1;  // bad source, or not an EntryPoint
constexpr int64_t IRQ_FULL        = -2;

// trap_mgr.irq_route: appends `handler` to the handlers for PLIC `source`,
// enabling the source at the PLIC the first time.
struct alignas(16) IrqRouteRequest {
  Capability handler;       // in: OType::EntryPoint
  uint64_t source;          // in: PLIC source number (1..1023)
  int64_t status;           // out: IRQ_*
};

// What a routed handler is invoked with.
struct alignas(16) IrqEvent {
  uint64_t source;
  uint64_t pad_;
};

// Filled by `trap_mgr`'s `compartment_main` when invoked with a writable
// capability to one of these (owned by `init`). `irq_route` is deliberately
// not published by name: which device reaches which driver is a platform
// decision `init` makes, not something any compartment with `lookup` may.
struct alignas(16) TrapMgrInterface {
  Capability irq_route;     // out: OType::EntryPoint -> trap_mgr_irq_route_entry
  uint32_t plic_ndev;       // in: max PLIC source number (from DTB; 0 = default)
  uint32_t pad_;
  uint32_t plic_s_context[platform::MAX_HARTS];  // in: hart -> S-mode PLIC context
};

// ----------------------------------------------------------------------------
// Scheduler service (`src/user/sched.cpp`; spec 2.4.4, 2.6, 5.7.2)
// ----------------------------------------------------------------------------
// A `quota_sched` handle is a software-sealed `OType::SealedObject` (spec 2.7)
// minted over one of two 16-byte headers at the front of the node's page.
// `sys_seal` demands a writable object, so the Load/Store delegation bits
// cannot ride on the handle's hardware permissions; instead the header the
// handle was sealed over *is* its permission.
constexpr size_t QUOTA_SCHED_ADMIN_HEADER = 0;   // Load|Store: derive/destroy/register
constexpr size_t QUOTA_SCHED_OP_HEADER    = 16;  // Load: register only

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
constexpr int64_t SCHED_PERMISSION     = -3;  // handle lacks the needed header
constexpr int64_t SCHED_BANDWIDTH      = -4;  // temporal conservation violated
constexpr int64_t SCHED_NO_MEMORY      = -5;  // node_funding could not pay
constexpr int64_t SCHED_BUSY           = -6;  // node still has children/threads
constexpr int64_t SCHED_FULL           = -7;
constexpr int64_t SCHED_INVALID_THREAD = -8;
constexpr int64_t SCHED_UNKNOWN_POLICY = -9;
constexpr int64_t SCHED_TIMED_OUT      = -10;  // block: the timeout ran out first

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

// sched.quota_destroy: needs the ADMIN handle; fails BUSY while children or
// registered threads remain.
struct alignas(16) SchedDestroyRequest {
  Capability quota;         // in
  int64_t status;           // out
  uint64_t pad_;
};

// sched.thread_register: either handle; `thread` is an `OType::Thread` with
// Permit_Load (the right to switch to it). The thread is unregistered
// automatically when it exits. `out_tid` is the kernel's id for the thread
// (what `sys_thread_tid` reports for its handle): the scheduler keys its
// records by it, so there is one thread id system-wide. Registering a thread
// that is already registered fails SCHED_INVALID_THREAD.
struct alignas(16) SchedRegisterRequest {
  Capability thread;        // in
  Capability quota;         // in
  uint64_t out_tid;         // out: the thread's id (kernel-assigned)
  int64_t status;           // out
};

// sched.policy_register: needs the ROOT admin handle. Installs a third-party
// sub-scheduler and returns the `policy_id` nodes may be derived with.
struct alignas(16) SchedPolicyRequest {
  Capability root;          // in
  Capability delegate;      // in: OType::EntryPoint speaking PolicyRequest
  uint32_t out_policy_id;   // out
  uint32_t pad_;
  int64_t status;           // out
};

// sched.block (no request, or a SchedBlockRequest): the calling thread
// sleeps until `sched.wake` is called with its tid -- or, given a request
// with a nonzero `timeout_us`, until that many microseconds have passed,
// whichever is first. A wake that arrived while the thread was still running
// is kept and makes the next `block` return at once, so a caller that checks
// a condition, finds nothing, and then blocks can never miss the event that
// arrived in between. `block` can also return with nothing to show for it;
// callers loop. The timeout is what bounds a wake that never comes: one that
// was refused on the way (the waker's call ran out of kernel stack, say), or
// a device that never interrupts. A waiter that uses one turns a lost wake
// into a delay instead of a thread asleep for good.
struct alignas(16) SchedBlockRequest {
  uint64_t timeout_us;      // in: 0 = until woken
  int64_t status;           // out: SCHED_OK woken (or spurious), SCHED_TIMED_OUT
};
//
// sched.wake: safe to call from interrupt context -- it is a leaf update of
// one thread record and never picks or switches. Anyone with the entry point
// and a tid can wake that thread; a spurious wake costs it one trip round its
// loop and nothing else (a capability-shaped wake token is the follow-up).
struct alignas(16) SchedWakeRequest {
  uint64_t tid;             // in: thread id (kernel-assigned; see thread_register)
  int64_t status;           // out: SCHED_OK or SCHED_INVALID_THREAD
};

// sched.self: the tid of the calling thread, for `wake`. The same id the
// kernel reports for the thread's handle (`sys_thread_tid`).
struct alignas(16) SchedSelfRequest {
  uint64_t out_tid;         // out
  int64_t status;           // out
};

// Filled by `sched`'s `compartment_main` when invoked with a writable
// capability to one of these (owned by `init`).
struct alignas(16) SchedInterface {
  Capability root_quota;    // out: ADMIN handle of the root node
  Capability run;           // out: OType::EntryPoint -> dispatcher (RW_SLOT_SCHED_RUN)
  uint64_t timebase_hz;     // in: `time` CSR frequency in Hz (from DTB; 0 = default)
  uint64_t pad_;
};

// Policy delegate contract. The scheduler invokes a node's delegate with a
// `PolicyRequest`; for `POLICY_PICK` it offers a Load-only `PolicyView[count]`
// of the node's ready threads and expects `pick` set to one of their tids
// (0 = no preference). Any other answer falls back to round robin. Built-in
// policies see exactly the same view, so a delegate can do anything they can.
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
// Block device driver (`src/drivers/blk.cpp`)
// ----------------------------------------------------------------------------
// `blk` is the only compartment holding the virtio-mmio window and the DMA
// arena the kernel set aside at boot (`BootManifest::dma_window`). It drives
// one virtio-blk device over the modern MMIO transport, one request at a time,
// through a bounce buffer inside the arena: callers never hand the device
// their own memory, so the device can only ever reach the arena.
//
// Three entry points, minted once on the `BlkInterface` handshake (like
// `uart`): `read` and `write` go to `fs` alone, `irq` is routed to the
// device's PLIC source through `trap_mgr`. Nothing is published by name.
//
// `blk` is part of the boot set -- it is up before `naming`, `sched` and
// `trap_mgr`, which are loaded from the disk it serves -- so it cannot look
// the scheduler up itself. It polls until `init` hands it the scheduler's
// entries in a second call (`BlkSchedRequest`).
constexpr uint64_t BLK_SECTOR_BYTES   = 512;
constexpr uint64_t BLK_MAX_XFER_BYTES = 4096;  // per request: the bounce buffer

constexpr int64_t BLK_OK           = 0;
constexpr int64_t BLK_BAD_REQUEST  = -1;  // bad buffer, count 0 or too large
constexpr int64_t BLK_NO_DEVICE    = -2;  // no virtio-blk device was found
constexpr int64_t BLK_OUT_OF_RANGE = -3;  // past the end of the device
constexpr int64_t BLK_IO_ERROR     = -4;  // the device reported an error
constexpr int64_t BLK_BUSY         = -5;  // a request is already in flight

// blk.read / blk.write: moves `count` sectors starting at `sector` between
// the device and `buf` (`count * 512` bytes; writable for `read`).
struct alignas(16) BlkRequest {
  Capability buf;           // in
  uint64_t sector;          // in: first 512-byte sector
  uint64_t count;           // in: 1..BLK_MAX_XFER_BYTES / 512
  int64_t status;           // out: BLK_*
  uint64_t pad_;
};

// Filled by `blk`'s `compartment_main` when invoked with a writable capability
// to one of these (owned by `init`). The `in` fields are what the driver
// cannot learn from its capabilities alone: the physical address behind the
// DMA window and the shape of the slot window.
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

// A later call to `blk`'s `compartment_main` with a writable capability to
// one of these (only `init` holds the driver's sentry): the scheduler's
// entries, once there is a scheduler. From then on a thread waiting for the
// device sleeps instead of polling.
struct alignas(16) BlkSchedRequest {
  Capability block;         // in: sched.block
  Capability wake;          // in: sched.wake
  Capability self;          // in: sched.self
  int64_t status;           // out: BLK_OK or BLK_BAD_REQUEST
  uint64_t pad_;
};

// ----------------------------------------------------------------------------
// File system (`src/boot/fs.cpp`; spec 2.4.5, 3.8)
// ----------------------------------------------------------------------------
// A hierarchical file system on the `blk` device, with disk space handed out
// through a `quota_disk` tree. A node is a budget (bytes and inodes) *rooted
// at a directory*: every path a handle names is relative to that directory,
// so its holder can reach nothing above it. Every file belongs to the node it
// was created under and is charged to it as it grows; a limit can never be
// exceeded by its holder or by anything derived from it.
//
// What a handle may do (ADMIN = sealed over the Load|Store header):
//   open (read), list, query   either handle; anything under its directory
//   open for writing           ADMIN, and the file is the node's own or a
//                              descendant's
//   create, mkdir              ADMIN; the new inode is the node's and charged
//                              to it, in any directory under its root --
//                              another node's included
//   unlink                     ADMIN, and the file or (empty) directory is the
//                              node's own or a descendant's
//   derive                     ADMIN; the child is rooted at a directory under
//                              the parent's, with a slice of its budget
// So two nodes rooted at the same directory see each other's files but can
// neither change nor remove them; a parent can drop a file into a child's
// directory without paying the child's budget, and the child cannot remove
// it. Nothing an inode carries decides who sees it -- there is no "public"
// bit -- only where it sits and who holds a handle rooted above it. The
// programs the shell can `run` live in `/bin`, which it reaches through a
// 0-byte OP handle rooted there (a DISK entry of its manifest); the system's
// own images sit in `/`, where nothing but the root handle is rooted.
//
// Paths: components separated by '/', each 1..FS_NAME_MAX-1 printable
// non-blank characters and neither "." nor ".."; no leading or trailing '/'.
// The empty path is the handle's own root directory (list, derive).
//
// `quota_disk` handles follow the `quota_sched` convention exactly: a
// software-sealed `OType::SealedObject` over one of two 16-byte headers at the
// front of the node's page, the header being the handle's permission.
constexpr size_t QUOTA_DISK_ADMIN_HEADER = 0;   // Load|Store: derive/destroy/create/mkdir/unlink
constexpr size_t QUOTA_DISK_OP_HEADER    = 16;  // Load: open/read/list only

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
constexpr int64_t FS_PERMISSION    = -3;   // handle lacks the header, or the file is not its to change
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

// fs.quota_derive: needs the ADMIN handle of `parent`. Carves `limit_bytes`
// and `limit_inodes` out of what the parent has not used or delegated, for a
// node rooted at the directory `path` names under the parent's root ("" for
// the parent's own root directory). `out_quota` is the handle asked for by
// `perms`; `out_admin` is the ADMIN handle of the same node -- the same
// capability when ADMIN was asked for -- which the creator keeps, since a
// node is destroyed through its ADMIN handle and nothing else. It gives the
// creator no authority it lacked: it holds ADMIN on the parent, whose budget
// the child's is a slice of.
//
// With FS_DERIVE_ADOPT in `flags` the child starts out owning everything the
// parent owns at or under the child's root -- the root directory itself
// included, if the parent's -- and those inodes and blocks move from the
// parent's use to the child's (FS_QUOTA if they do not fit the child's
// limits, and nothing is created). What is adopted leaves the parent's use as
// the child's limits enter its delegation, so it counts toward what the parent
// can give: a parent that has spent its whole budget on a directory can still
// hand the directory down, limits and all. Ownership is not kept on the disk:
// after a mount every inode is the root node's, and this is how whoever
// re-derives a node hands back what was in its directory before -- `init`
// does it for the shell's `/home`. Without the flag the parent keeps what it
// had there, which the child can see and not change. Either way the parent
// gives away only what is its own.
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

// fs.quota_destroy: needs the ADMIN handle; fails BUSY while children remain.
// Every file the quota owns is unlinked (spec 3.8 cascade), as is every
// directory of its that is then empty; a directory still holding other nodes'
// files, or that another node is rooted at, passes to the parent, with the
// limits. Every file handle opened through the node dies with it.
struct alignas(16) FsDestroyRequest {
  Capability quota;         // in
  int64_t status;           // out
  uint64_t pad_;
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

// fs.create (ADMIN handle: the file is charged to this quota; the directory
// it goes in must exist under the handle's root) and fs.open (either handle:
// anything under the root). Both return a sealed file handle and the file's
// current size. `perms` is what the handle is to allow -- perms::Load, or
// perms::Load | perms::Store -- and it is writable only when Store was asked
// for, through an ADMIN handle whose node owns the file or is an ancestor of
// the owner; anything else is read-only. So a holder that could write can
// open read-only instead, which is how a launcher hands a program a file to
// read and nothing more. FS_IS_DIR if the path names a directory.
//
// The record behind a file handle lives in the page of the node it was opened
// through, which has room for FS_OPEN_PER_NODE of them: a holder that opens
// more gets FS_NO_MEMORY and has used up its own node's page, nobody else's
// (another node is as free to open as before). The handles die with the node.
constexpr size_t FS_OPEN_PER_NODE = 122;

struct alignas(16) FsOpenRequest {
  Capability quota;         // in
  Capability out_file;      // out: OType::SealedObject file handle
  char path[FS_PATH_MAX];   // in: NUL-terminated, relative to the handle's root
  int64_t status;           // out
  uint64_t out_size;        // out: bytes in the file (0 for a new one)
  uint32_t perms;           // in: perms::Load [| perms::Store]
  uint32_t pad_;
  uint64_t pad2_;
};

// fs.read / fs.write: `length` bytes at `offset`. A write past the end grows
// the file, charging whole blocks to the owning quota; FS_QUOTA if that would
// exceed it, in which case nothing is written.
struct alignas(16) FsIoRequest {
  Capability file;          // in
  Capability buf;           // in: writable for read
  uint64_t offset;          // in
  uint64_t length;          // in
  uint64_t out_count;       // out: bytes transferred
  int64_t status;           // out
};

// fs.close: releases the file handle.
struct alignas(16) FsCloseRequest {
  Capability file;          // in
  int64_t status;           // out
  uint64_t pad_;
};

// fs.mkdir: ADMIN handle; a directory charged one inode to the quota, in a
// directory under the handle's root.
// fs.unlink: ADMIN handle of the owning quota (or of an ancestor). Frees the
// file's blocks and inode and refunds the owner. A directory must be empty
// (FS_NOT_EMPTY) and no node's root (FS_BUSY). FS_PERMISSION for something in
// view but owned elsewhere: visible, not this handle's to remove.
struct alignas(16) FsPathRequest {
  Capability quota;         // in
  char path[FS_PATH_MAX];   // in
  int64_t status;           // out
  uint64_t pad_;
};

// fs.list: either handle. The entries of the directory `path` names under
// the handle's root ("" for the root itself), whoever owns them. `owner` says
// whose: what the listing node can change is its own and its descendants';
// the rest is in view and nothing more.
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

struct alignas(16) FsListRequest {
  Capability quota;         // in
  Capability entries;       // in: writable FsDirEntry[capacity]
  char path[FS_PATH_MAX];   // in: the directory, relative to the handle's root
  uint64_t capacity;        // in
  uint64_t out_count;       // out: entries written
  uint64_t out_total;       // out: entries in the directory
  int64_t status;           // out
};

// Filled by `fs`'s `compartment_main` when invoked with a writable capability
// to one of these (owned by `init`). The root handle is the authority over
// the whole disk, rooted at `/`; `init` makes `/home` and `/bin` under it,
// derives from it what the shell gets, and reads the disk-resident service
// images through it.
//
// The operation entry points come back here rather than being published by
// `fs` itself: `fs` is in the boot set and is up before `naming`, which is
// loaded from the disk. `init` publishes each as "fs.<field>" once it can.
struct alignas(16) FsInterface {
  Capability root_quota;    // out: ADMIN handle of the root node
  Capability quota_derive;  // out: OType::EntryPoint, FsDeriveRequest
  Capability quota_destroy; // out: FsDestroyRequest
  Capability quota_query;   // out: FsQueryRequest
  Capability create;        // out: FsOpenRequest
  Capability mkdir;         // out: FsPathRequest
  Capability open;          // out: FsOpenRequest
  Capability close;         // out: FsCloseRequest
  Capability read;          // out: FsIoRequest
  Capability write;         // out: FsIoRequest
  Capability unlink;        // out: FsPathRequest
  Capability list;          // out: FsListRequest
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
// Applications (`src/apps/*.cpp`)
// ----------------------------------------------------------------------------
// A program is a compartment image that is a file on the disk rather than
// part of the system: the shell's `run <file> [args]` reads it through `fs`,
// has `loader` make a compartment of it under a VM sub-quota of the shell's,
// invokes it once on the shell's own thread with one of these, and destroys
// the compartment when it returns. For as long as the call lasts the program
// holds what its manifest asked for and the shell's policy granted (shell.cpp,
// "Programs"), and this block -- nothing else.
constexpr size_t APP_ARGS_MAX = 64;

struct alignas(16) AppRequest {
  char args[APP_ARGS_MAX];  // in: the rest of the command line, NUL-terminated
  int64_t status;           // out: the program's exit status; 0 is success
  uint64_t ticks_per_us;    // in: `time` ticks per us (from DTB timebase-frequency)
};

// ============================================================================
// 1. `init` Compartment Capability Table Layout (`cgp`)
// ============================================================================

// Runtime slots populated by `init` (`src/user/init.cpp`) as it provisions
// child quotas, compartments, service sentries, and the initial shell thread:
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
// `lookup("uart")` as seen by `init`; the exec tests compare it with
// `RW_SLOT_UART_SENTRY` to prove the registry round trip.
constexpr size_t RW_SLOT_NAMING_PROOF        = RW_SLOT_PROVISIONED_BASE + 25;
// VM quota `init` derives to pay for the scheduler nodes it creates, and the
// `quota_sched` handle it derived for the shell's thread.
constexpr size_t RW_SLOT_SCHED_NODE_FUNDING  = RW_SLOT_PROVISIONED_BASE + 26;
constexpr size_t RW_SLOT_SHELL_SCHED_QUOTA   = RW_SLOT_PROVISIONED_BASE + 27;
// The block driver, the VM quota that pays for the disk-quota nodes `init`
// derives, and the `quota_disk` handle it derived for the shell.
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

// ============================================================================
// 2. Every other compartment: its own manifest
// ============================================================================
// There is no table layout here for `uart`, `blk`, `loader`, `fs`, `naming`,
// `sched`, `trap_mgr`, the shell or any program. Each image declares what it
// needs in its own source as a manifest (user/manifest.hpp), which generates
// its slot constants and the `.manifest` table its launcher reads: entry i is
// seed slot RW_SLOT_SEED_BASE + i. `init` is the launcher of the services and
// grants what they declare from what it holds; the shell's `run` is the
// launcher of programs and grants by its own policy (shell.cpp, "Programs").
// What a service hands back at run time (`UartInterface` and the like) is
// described with the request blocks above.

}  // namespace signetos::init
