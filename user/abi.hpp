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
// (`quota_derive`, `fs.stat`, and one-shot `*Interface` boot
// handshakes) pass a bounded capability to a struct defined below.
//
// Entries that return a `Capability` on success (`naming.lookup`, `fs.open`,
// `fs.create`) return a tagged handle on success and an untagged negative error
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
//   uint64_t uart.read(Capability buf) -> bytes read; sleeps until there are some
//   uint64_t uart.irq(Capability irq_wait)   [once, from `init`]
struct alignas(16) UartInterface {
  Capability read;          // OType::EntryPoint -> uart_read_entry
  Capability irq;           // OType::EntryPoint -> uart_irq_entry
};

// ----------------------------------------------------------------------------
// Sealing service (`external/services/sealer.cpp`, user/vseal.hpp)
// ----------------------------------------------------------------------------
//   Capability seal.mint(Capability record)                 -> TypeKey, or null
//   Capability seal.derive(Capability key, uint32_t perms)  -> TypeKey, or null
//   Capability seal.seal(Capability key, Capability obj)    -> SealedObject, or null
//   Capability seal.unseal(Capability key, Capability handle) -> payload, or null
//
// Compartment-minted sealing types (CORE_DESIGN.md §2.3). A key is the
// 16-byte record it was minted from, sealed as `OType::TypeKey`: Permit_Store
// on it authorises `seal`, Permit_Load authorises `unseal`, and `derive`
// re-issues it with a subset of the two. A sealed object is a 16-byte header
// (a tagged copy of the key) followed by the payload; the handle is sealed
// as `OType::SealedObject` and the unsealed payload excludes the header. A
// type dies with its record: once that memory is freed and swept, every key
// and every object of the type is untagged. There is no status channel: a
// refused call returns null, as the kernel calls these replaced did.
//
// Published by the sealer itself; `init` hands nothing back from it.

// ----------------------------------------------------------------------------
// Scheduler service (`external/services/sched.cpp`)
// ----------------------------------------------------------------------------
//   int64_t  sched.quota_derive(SchedDeriveRequest* req) -> SCHED_*
//   int64_t  sched.quota_destroy(Capability parent, Capability child) -> SCHED_*
//   int64_t  sched.quota_query(Capability quota, SchedQueryRequest* req) -> SCHED_*
//   int64_t  sched.thread_register(Capability thread, Capability quota) -> tid (>0) or SCHED_* (<0)
//   int64_t  sched.yield() -> 0
//   int64_t  sched.block(uint64_t timeout_us) -> SCHED_OK, SCHED_TIMED_OUT or SCHED_KILLED
//   int64_t  sched.wake(uint64_t tid) -> SCHED_OK or SCHED_INVALID_THREAD
//   int64_t  sched.thread_kill(Capability thread) -> SCHED_OK, SCHED_PERMISSION or SCHED_INVALID_THREAD
//   int64_t  sched.lock_wait(uint64_t* word, uint64_t seen) -> SCHED_OK, SCHED_OWNER_DEAD or SCHED_DEADLOCK
//   int64_t  sched.lock_wake(uint64_t* word) -> SCHED_OK or SCHED_PERMISSION
//   int64_t  sched.irq_wait(uint64_t timeout_us) -> SCHED_OK, SCHED_TIMED_OUT, SCHED_KILLED or SCHED_BUSY
//   Capability sched.irq_route(uint64_t source) -> irq_wait for it, or null [`init` only]
//
// `block`, `lock_wait`, `lock_wake` and `irq_wait` return SCHED_INVALID_THREAD
// to a thread the scheduler does not run (`init`, before the dispatcher
// starts). A thread reads its own tid, which is what `wake` takes, from
// `utidc` (runtime.hpp, `self_tid`).
//
// A killed thread never sleeps: every `block` it makes returns SCHED_KILLED
// at once. A caller waiting for something certain to happen (a device
// finishing a request it was given) keeps waiting, and so polls; one waiting
// for something that may never happen (input, another thread) gives up.
//
// A device interrupt reaches its driver as an `irq_wait` entry: there is one
// for each PLIC source `init` routes, and it is handed to that device's
// driver and nobody else (sched.cpp, DEVICE INTERRUPTS). `irq_wait` tells the
// PLIC the source's last interrupt has been dealt with, then sleeps until the
// next one (or `timeout_us`; 0: no timeout). One thread waits on a source at a
// time; another gets SCHED_BUSY. A driver deals with an interrupt (reads or
// acknowledges its device) before it waits again.
//
// There is one kind of handle to a node, and whoever holds it has full use of
// the node's time: registering threads on it, deriving from it, querying it.
// A child may not be of a more urgent class than its parent, nor guaranteed
// for longer. Taking a node's time back is not something its own handle can
// do: `quota_destroy` needs the handle of the node it was derived from, and is
// refused until the term it was derived with has ended (`term_us`). It removes
// the node and everything derived under it, and every thread on them stops at
// once. A stopped thread keeps its state and its registration; it carries on
// when `thread_register` puts it on another node, and `thread_kill` puts it
// on the killer's node so that it can run to its end.
//
// A lock is a 64-bit word in the memory of the compartment whose state it
// protects: 0 when free, otherwise the owner's tid, with LOCK_WAITERS set once
// someone waits for it (runtime.hpp, `lock` and `unlock`). A thread that finds
// it taken sets LOCK_WAITERS and calls `lock_wait` with the value it saw; while
// it waits, its node's turns run the owner instead. The owner, seeing
// LOCK_WAITERS as it releases the lock, calls `lock_wake`, which wakes the next
// waiter and returns its tid (> 0) for the caller to store into the word (or 0
// if no waiter remains). If the owner ended holding the lock, the next waiter
// gets it with SCHED_OWNER_DEAD. `word` is an unsealed Load capability to the
// 8-byte word; the scheduler never writes to it.

constexpr uint8_t PRIORITY_RT          = 0;
constexpr uint8_t PRIORITY_INTERACTIVE = 1;
constexpr uint8_t PRIORITY_NORMAL      = PRIORITY_INTERACTIVE;
constexpr uint8_t PRIORITY_BATCH       = 2;

// The root node: the whole machine, C = T.
constexpr uint32_t SCHED_ROOT_PERIOD_US = 1'000'000;

constexpr int64_t SCHED_OK             = 0;
constexpr int64_t SCHED_BAD_REQUEST    = -1;
constexpr int64_t SCHED_INVALID_QUOTA  = -2;
constexpr int64_t SCHED_PERMISSION     = -3;  // not allowed through these handles (above)
constexpr int64_t SCHED_BANDWIDTH      = -4;  // temporal conservation violated
constexpr int64_t SCHED_NO_MEMORY      = -5;  // node_funding could not pay
constexpr int64_t SCHED_BUSY           = -6;  // destroy: the node's term has not ended;
                                              // irq_wait: another thread waits on it
constexpr int64_t SCHED_FULL           = -7;
constexpr int64_t SCHED_INVALID_THREAD = -8;
constexpr int64_t SCHED_TIMED_OUT      = -10;  // block, irq_wait: the timeout ran out first
constexpr int64_t SCHED_KILLED         = -11;  // block, irq_wait: the caller was killed; it did not sleep
constexpr int64_t SCHED_OWNER_DEAD     = -12;  // lock_wait: taken over from an owner that ended
constexpr int64_t SCHED_DEADLOCK       = -13;  // lock_wait: the owner is waiting for the caller

// SchedDeriveRequest::term_us: the deriver may take the node back at any
// time; never; or, for any other value, once that many microseconds have
// passed.
constexpr uint64_t SCHED_REVOCABLE = 0;
constexpr uint64_t SCHED_PERMANENT = ~0ULL;

// A lock word: the owner's tid, and this bit once anyone waits for it.
constexpr uint64_t LOCK_WAITERS = 1ULL << 63;

// sched.quota_derive: `parent` is the handle of the node to derive from.
struct alignas(16) SchedDeriveRequest {
  Capability parent;        // in
  Capability node_funding;  // in: QuotaVm that pays for the node's page
  Capability out_quota;     // out: handle of the new node
  uint64_t term_us;         // in: SCHED_REVOCABLE, SCHED_PERMANENT or a term
  uint32_t budget_us;       // in: C
  uint32_t period_us;       // in: T (>= C)
  uint8_t priority_class;   // in: PRIORITY_*, no more urgent than the parent's
  uint8_t pad_[7];
  int64_t status;           // out: SCHED_*
};

// sched.quota_query. `guaranteed_until_us` is when the node's term ends: 0
// for a revocable node, SCHED_PERMANENT for a permanent one.
struct alignas(16) SchedQueryRequest {
  uint64_t guaranteed_until_us;  // out
  uint32_t budget_us;       // out
  uint32_t period_us;       // out
  uint32_t threads;         // out: registered on it and on the nodes under it
  uint32_t children;        // out: nodes derived directly from it
  uint8_t priority_class;   // out
  uint8_t pad_[7];
  int64_t status;           // out: SCHED_*
};

// Filled by `sched`'s `compartment_main` when invoked with a writable
// capability to one of these (owned by `init`).
struct alignas(16) SchedInterface {
  Capability root_quota;    // out: handle of the root node
  Capability run;           // out: OType::EntryPoint -> dispatcher (RW_SLOT_SCHED_RUN)
  Capability interrupt;     // out: OType::EntryPoint -> the interrupt handler;
                            //      `init` creates a thread on it and installs
                            //      that (thread.hpp, THE INTERRUPT HANDLER)
  Capability irq_route;     // out: OType::EntryPoint -> sched.irq_route
  uint64_t timebase_hz;     // in: `time` CSR frequency in Hz (from DTB; 0 = default)
  uint32_t plic_ndev;       // in: max PLIC source number (from DTB; 0 = default)
  uint32_t pad_;
  uint32_t plic_m_context[platform::MAX_HARTS];  // in: hart -> M-mode PLIC context
};

// The last sector of a disk with a swap region (`tools/signetfs.py swap`):
// the region runs from the end of the file system, `base_sector`, up to this
// sector. Only `blk` reads it (blk.cpp, SWAP): it keeps the region to itself
// and says only how many pages of swap there are.
constexpr uint64_t SWAP_MAGIC = 0x5349474E53574150ULL;  // "SIGNSWAP"
constexpr uint32_t SWAP_VERSION = 1;

struct SwapTrailer {
  uint64_t magic;           // SWAP_MAGIC
  uint32_t version;         // SWAP_VERSION
  uint32_t sector_bytes;    // BLK_SECTOR_BYTES
  uint64_t base_sector;     // the region's first sector
  uint64_t sectors;         // its length, a whole number of pages
};

// ----------------------------------------------------------------------------
// DMA (`boot/dma.cpp`)
// ----------------------------------------------------------------------------
//   int64_t  dma(DmaInterface* iface) -> BLK_* [once, from `init`]
//
// The only compartment that knows a physical address. Run once, before
// `blk`: it sets up the virtio-blk device on a fixed descriptor table in the
// DMA arena and returns, for `blk`, views that cannot reach that table or the
// device's queue registers (dma.cpp, WHY THIS IS ENOUGH).
//
// The arena, as `blk` sees it (`buf`, which starts one page into the arena):
constexpr size_t   DMA_ARENA_BYTES = 4 * 4096;  // descriptor page + `buf`
constexpr size_t   DMA_BUF_AVAIL   = 0x0000;    // avail ring (DMA_QUEUE_SIZE)
constexpr size_t   DMA_BUF_USED    = 0x0100;    // used ring (DMA_QUEUE_SIZE)
constexpr size_t   DMA_BUF_HEADER  = 0x0ff0;    // request header, 16 B
constexpr size_t   DMA_BUF_DATA    = 0x1000;    // data, BLK_XFER_BYTES
constexpr size_t   DMA_BUF_STATUS  = 0x2000;    // status, 1 B
constexpr uint16_t DMA_QUEUE_SIZE  = 4;
// Descriptor chains: what `blk` puts in the avail ring to start a request.
constexpr uint16_t DMA_CHAIN_READ  = 0;
constexpr uint16_t DMA_CHAIN_WRITE = 2;
// `notify` covers these device registers, offsets from its base.
constexpr size_t   DMA_NOTIFY_BASE        = 0x050;  // in the device's slot
constexpr size_t   DMA_NOTIFY_BYTES       = 0x018;
constexpr size_t   DMA_NOTIFY_QUEUE       = 0x050 - DMA_NOTIFY_BASE;
constexpr size_t   DMA_NOTIFY_IRQ_STATUS  = 0x060 - DMA_NOTIFY_BASE;
constexpr size_t   DMA_NOTIFY_IRQ_ACK     = 0x064 - DMA_NOTIFY_BASE;

struct alignas(16) DmaInterface {
  Capability buf;           // out: read/write, the arena past its first page
  Capability notify;        // out: read/write [DMA_NOTIFY_BASE, + BYTES)
  uint64_t virtio_slot_bytes;  // in: stride between slots in the window
  uint64_t capacity_sectors;   // out: device size
  uint32_t virtio_count;    // in: slots in the window
  uint32_t slot;            // out: the slot the device was found in
  int64_t status;           // out: BLK_OK or BLK_NO_DEVICE
};

// ----------------------------------------------------------------------------
// Block device driver (`boot/blk.cpp`)
// ----------------------------------------------------------------------------
//   int64_t  blk.read(Capability buf, uint64_t sector, uint64_t count) -> BLK_*
//   int64_t  blk.write(Capability buf, uint64_t sector, uint64_t count) -> BLK_*
//   uint64_t blk_paging(Capability)        the pager's thread (blk.cpp, PAGING)
//   int64_t  blk.paging_stop() -> BLK_OK   the pager's thread ends
//   int64_t  blk(Capability block, Capability wake, Capability lock_wait,
//                Capability lock_wake, Capability irq_wait) [2nd call]
// Every request is exactly BLK_XFER_BYTES: `count` must be
// BLK_XFER_BYTES / BLK_SECTOR_BYTES (the descriptor chains are fixed, dma.cpp).
constexpr uint64_t BLK_SECTOR_BYTES = 512;
constexpr uint64_t BLK_XFER_BYTES   = 4096;  // per request: the bounce buffer

constexpr int64_t BLK_OK           = 0;
constexpr int64_t BLK_BAD_REQUEST  = -1;  // bad buffer, or count not one page
constexpr int64_t BLK_NO_DEVICE    = -2;  // no virtio-blk device was found
constexpr int64_t BLK_OUT_OF_RANGE = -3;  // past the end of the device
constexpr int64_t BLK_IO_ERROR     = -4;  // the device reported an error
constexpr int64_t BLK_BUSY         = -5;  // a request is already in flight

// `init` passes on what `dma` returned (DmaInterface).
struct alignas(16) BlkInterface {
  Capability read;          // out: OType::EntryPoint -> blk_read_entry
  Capability write;         // out: OType::EntryPoint -> blk_write_entry
  // The pager's two: null in a build without paging (SIGNETOS_PAGING).
  Capability paging;        // out: OType::EntryPoint -> blk_paging_entry
  Capability paging_stop;   // out: OType::EntryPoint -> blk_paging_stop_entry
  Capability buf;           // in: DmaInterface::buf
  Capability notify;        // in: DmaInterface::notify
  uint64_t capacity_sectors;   // in: device size; out: what `read` and
                               //      `write` serve, less any swap region
  uint64_t swap_pages;      // out: pages of swap; 0: none
  uint32_t slot;            // in: the device's slot, for the console
  int64_t status;           // out: BLK_OK or BLK_NO_DEVICE
};

// ----------------------------------------------------------------------------
// File system (`boot/fs.cpp`)
// ----------------------------------------------------------------------------
// A handle names a file, directory or quota and carries FS_* rights. Each kind
// has its own type: OType::FsFile, OType::FsDir, OType::FsQuota. Every
// handle is opened through another one (`from`, `dir`, `parent`), with at most
// its rights, and its memory is paid for by `memory_quota`. fs.close closes a
// handle and every handle opened through it, and gives their memory back.
// Paths are relative, with no ".", ".." or leading '/'; "" is the handle
// itself. A name is one or more printable characters, no blank or '/'.
// Neither names nor paths have a length limit, and a file can grow until its
// quota or the disk is full.
//
//   int64_t    fs.close(Capability handle)
//   Capability fs.open(Capability from, const char* path, uint32_t rights, Capability memory_quota)
//   Capability fs.create(Capability dir, const char* path, Capability payer, uint32_t flags, Capability memory_quota)
//   Capability fs.quota(Capability parent, const char* name, uint64_t limit, Capability memory_quota)
//   int64_t    fs.read(Capability file, Capability buf, uint64_t offset, uint64_t length)
//   int64_t    fs.write(Capability file, Capability buf, uint64_t offset, uint64_t length, Capability payer)
//   int64_t    fs.list(Capability from, const char* path, Capability buf, uint64_t bytes, uint64_t start) -> entries written
//   int64_t    fs.remove(Capability from, const char* path)
//   int64_t    fs.move(Capability from, const char* from_path, Capability dir, const char* path, Capability payer)
//   int64_t    fs.freeze(Capability file)
//   int64_t    fs.stat(Capability handle, FsStat* out)
//   int64_t    fs.link(Capability dir, const char* path, Capability target, uint32_t rights, Capability payer)
// Errors: status_cap(FS_*), or a negative FS_*. A null `dir` to fs.create
// makes a temporary, opened through `payer`; it is removed, and `payer`
// refunded, when the handle fs.create returned is closed, unless it was moved
// into a directory first. A write that extends a file needs ADD on `payer`,
// the quota that pays for the file; otherwise `payer` may be null. fs.quota
// makes quota `name` of `parent`, or sets the limit of the one already there:
// growing takes from `parent`, shrinking stops at what it has used. It needs
// CHANGE on `parent`, and ADD too to make or grow one; the handle has
// `parent`'s rights. fs.remove removes `path` and everything in it; removing a
// link removes the link, not what it names; a quota can only be removed once
// it pays for nothing (FS_IN_USE). fs.move moves entry `from_path` of `from`
// to `path` of `dir`: it needs every right on the directory the entry is in,
// through `from`, and ADD on the destination (CHANGE too to replace a file
// there). A temporary is moved with its own handle as `from` and `from_path`
// "". The entry keeps its payer; a link cannot be moved. A new name longer
// than FS_NAME_INLINE bytes takes blocks of its own: `payer` pays for them,
// and needs ADD and to be the quota that pays for the entry. Otherwise
// `payer` may be null.
//
// LISTING: fs.list writes the entries of `path` under `from` into `buf`, from
// the `start`th on (0 is the first): for each, an FsDirEntry and then its
// name and a NUL, fs_dir_entry_bytes(name_length) bytes in all, as many whole
// ones as fit in `bytes`. It returns how many it wrote, 0 once there are no
// more. If not even the first fits, it writes just that one's FsDirEntry
// (when `bytes` has room for it), whose `name_length` says what it needs, and
// returns FS_TOO_LARGE.
//
// LINKS: fs.link makes entry `path` of `dir` name `target`, with `rights` (at
// most the target handle's, never LINK). The target handle needs LINK. Opening
// through a link gives at most the link's rights.
//
// COSTS: an entry costs its payer a block; a name longer than FS_NAME_INLINE
// bytes, and a file, a block for each FS_BLOCK_BYTES of it, and about one
// more per 1024 of those for the lists that keep track of them. A quota
// costs its parent its limit as well.

constexpr uint64_t FS_BLOCK_BYTES = 4096;  // allocation unit on disk
constexpr size_t   FS_NAME_INLINE = 20;    // a longer name takes blocks

constexpr uint32_t FS_READ   = 1;  // read; list and open inside
constexpr uint32_t FS_ADD    = 2;  // append; create inside; pay with a quota
constexpr uint32_t FS_CHANGE = 4;  // overwrite, freeze, delete; split a quota
constexpr uint32_t FS_ALL    = FS_READ | FS_ADD | FS_CHANGE;
constexpr uint32_t FS_LINK   = 8;  // may be linked to (fs.link)

constexpr uint32_t FS_CREATE_DIR = 1;     // fs.create flag
constexpr uint64_t FS_APPEND = ~0ULL;     // fs.write offset: at the end

constexpr int64_t FS_OK          = 0;
constexpr int64_t FS_BAD_REQUEST = -1;   // malformed request, path or buffer
constexpr int64_t FS_INVALID     = -2;   // not a live handle
constexpr int64_t FS_PERMISSION  = -3;   // missing right
constexpr int64_t FS_QUOTA       = -4;   // disk quota exhausted
constexpr int64_t FS_NO_MEMORY   = -5;   // memory quota exhausted
constexpr int64_t FS_NOT_FOUND   = -6;
constexpr int64_t FS_EXISTS      = -7;
constexpr int64_t FS_FROZEN      = -8;
constexpr int64_t FS_TOO_LARGE   = -9;   // past what an entry can record; fs.list: no room
constexpr int64_t FS_IO_ERROR    = -10;
constexpr int64_t FS_DISK_FULL   = -11;
constexpr int64_t FS_NOT_MOUNTED = -12;
constexpr int64_t FS_NOT_DIR     = -13;  // directory or quota needed
constexpr int64_t FS_IS_DIR      = -14;  // file needed
constexpr int64_t FS_BUSY        = -15;  // lock unavailable
constexpr int64_t FS_IN_USE      = -16;  // a quota that still pays for something

// FsDirEntry and FsStat flags
constexpr uint32_t FS_ENTRY_DIR    = 2;
constexpr uint32_t FS_ENTRY_QUOTA  = 4;
constexpr uint32_t FS_ENTRY_FROZEN = 8;
constexpr uint32_t FS_ENTRY_LINK   = 16;

// What fs.list writes for an entry; its name and a NUL follow.
struct FsDirEntry {
  uint64_t size;            // file: bytes; quota: limit
  uint32_t flags;           // FS_ENTRY_*
  uint32_t name_length;     // bytes, not counting the NUL
};

// The bytes fs.list writes for an entry with a name of `name_length` bytes:
// the next entry is that far on, as aligned as the first.
constexpr uint64_t fs_dir_entry_bytes(uint64_t name_length) {
  return (sizeof(FsDirEntry) + name_length + 1 + alignof(FsDirEntry) - 1) &
         ~(alignof(FsDirEntry) - 1);
}

struct alignas(16) FsStat {
  uint64_t size;            // file: bytes; quota: limit
  uint64_t used;            // quota: used; else what it costs
  uint32_t flags;           // FS_ENTRY_*
  uint32_t rights;          // FS_*
};

// Order of FsInterface::call.
enum : uint32_t {
  FS_CALL_CLOSE, FS_CALL_OPEN, FS_CALL_CREATE, FS_CALL_QUOTA, FS_CALL_READ,
  FS_CALL_WRITE, FS_CALL_LIST, FS_CALL_REMOVE, FS_CALL_MOVE, FS_CALL_FREEZE,
  FS_CALL_STAT, FS_CALL_LINK, FS_CALLS
};
inline constexpr const char* FS_CALL_NAMES[FS_CALLS] = {
    "fs.close", "fs.open",   "fs.create", "fs.quota",  "fs.read", "fs.write",
    "fs.list",  "fs.remove", "fs.move",   "fs.freeze", "fs.stat", "fs.link"};

struct alignas(16) FsInterface {
  Capability memory_quota;    // in: QuotaVm paying for the two handles
  Capability root_dir;        // out: `/`, FS_ALL
  Capability root_quota;      // out: root quota, FS_ALL
  Capability call[FS_CALLS];  // out: OType::EntryPoint
  uint64_t capacity_sectors;  // in: the device's size (BlkInterface)
  uint64_t total_bytes;       // out: root quota limit
  uint64_t used_bytes;        // out: root quota spent
  int64_t status;             // out: FS_*
  uint32_t formatted;         // out: 1 if a fresh file system was written
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
constexpr size_t RW_SLOT_NAMING_QUOTA        = RW_SLOT_PROVISIONED_BASE + 3;
constexpr size_t RW_SLOT_NAMING_COMP         = RW_SLOT_PROVISIONED_BASE + 4;
constexpr size_t RW_SLOT_NAMING_SENTRY       = RW_SLOT_PROVISIONED_BASE + 5;
constexpr size_t RW_SLOT_SCHED_QUOTA         = RW_SLOT_PROVISIONED_BASE + 6;
constexpr size_t RW_SLOT_SCHED_COMP          = RW_SLOT_PROVISIONED_BASE + 7;
constexpr size_t RW_SLOT_SCHED_SENTRY        = RW_SLOT_PROVISIONED_BASE + 8;
constexpr size_t RW_SLOT_FS_QUOTA            = RW_SLOT_PROVISIONED_BASE + 9;
constexpr size_t RW_SLOT_FS_COMP             = RW_SLOT_PROVISIONED_BASE + 10;
constexpr size_t RW_SLOT_FS_SENTRY           = RW_SLOT_PROVISIONED_BASE + 11;
constexpr size_t RW_SLOT_SHELL_VM_QUOTA      = RW_SLOT_PROVISIONED_BASE + 12;
constexpr size_t RW_SLOT_SHELL_T_QUOTA       = RW_SLOT_PROVISIONED_BASE + 13;
constexpr size_t RW_SLOT_SHELL_COMP          = RW_SLOT_PROVISIONED_BASE + 14;
constexpr size_t RW_SLOT_SHELL_SENTRY        = RW_SLOT_PROVISIONED_BASE + 15;
constexpr size_t RW_SLOT_SHELL_THREAD        = RW_SLOT_PROVISIONED_BASE + 16;
constexpr size_t RW_SLOT_NAMING_PUBLISH      = RW_SLOT_PROVISIONED_BASE + 17;
constexpr size_t RW_SLOT_NAMING_LOOKUP       = RW_SLOT_PROVISIONED_BASE + 18;
constexpr size_t RW_SLOT_NAMING_PROOF        = RW_SLOT_PROVISIONED_BASE + 19;
constexpr size_t RW_SLOT_SCHED_NODE_FUNDING  = RW_SLOT_PROVISIONED_BASE + 20;
constexpr size_t RW_SLOT_SHELL_SCHED_QUOTA   = RW_SLOT_PROVISIONED_BASE + 21;
constexpr size_t RW_SLOT_BLK_QUOTA           = RW_SLOT_PROVISIONED_BASE + 22;
constexpr size_t RW_SLOT_BLK_COMP            = RW_SLOT_PROVISIONED_BASE + 23;
constexpr size_t RW_SLOT_BLK_SENTRY          = RW_SLOT_PROVISIONED_BASE + 24;
constexpr size_t RW_SLOT_SEALER_QUOTA        = RW_SLOT_PROVISIONED_BASE + 25;
constexpr size_t RW_SLOT_SEALER_COMP         = RW_SLOT_PROVISIONED_BASE + 26;
constexpr size_t RW_SLOT_SEALER_SENTRY       = RW_SLOT_PROVISIONED_BASE + 27;

__attribute__((always_inline)) inline constexpr size_t syscall_slot(
    syscall::Id id) {
  return RW_SLOT_SYSCALL_BASE + static_cast<size_t>(id);
}

}  // namespace signetos::init
