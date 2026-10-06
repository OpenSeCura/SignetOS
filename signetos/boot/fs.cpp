/*
 * Copyright 2026 Google LLC (Cherified Team)
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
 * fs.cpp - SignetOS User-Space File System Compartment
 *
 * design_spec.md sections 2.4.5 (`struct quota_disk`) and 3.8 (the file
 * system compartment). A hierarchical file system on the `blk` device, with
 * every byte of disk space handed out through a tree of `quota_disk` nodes,
 * each rooted at a directory, so that no holder of a quota -- nor anything
 * derived from it -- can use more of the disk than it was given, or reach
 * anything above the directory it was given.
 *
 * ON DISK (4 KiB blocks, eight 512-byte sectors each)
 *   block 0       Superblock: magic, version 3, geometry scaled to the disk.
 *   bitmap        One bit per block of the disk (`bitmap_blocks` blocks
 *                 starting at `bitmap_block = 1`, 1 block per 128 MiB of
 *                 disk). Bits `[0, data_start)` for the metadata blocks are
 *                 always set.
 *   inode table   `inode_table_blocks` blocks starting at `inode_block`,
 *                 32 inodes of 128 bytes per block (sized at format time to
 *                 1 inode per 64 KiB of disk, minimum 64 inodes). An inode
 *                 holds a name, the inode number of the directory it is in
 *                 (`ROOT_DIR` for `/`), a size, 16 direct block numbers and
 *                 1 single-indirect block number (1,024 additional block
 *                 numbers), so a file can grow up to 1,040 blocks (4,160
 *                 KiB). A directory is an inode flagged INODE_DIR with no
 *                 blocks: its entries are the inodes whose `parent` it is,
 *                 found by scanning the table (one inode per 64 KiB of disk
 *                 keeps that cheap), so there are no directory data blocks
 *                 and no dirent format to keep consistent.
 *   data_start+   Data blocks and single-indirect blocks.
 *   The bitmap, inode table and per-inode owner array are allocated from
 *   `fs`'s VM quota at mount time to match the superblock geometry, and
 *   written through one block at a time after every change.
 *
 * QUOTAS
 *   quota_disk    One page per node, paid for by the caller's `node_funding`
 *                 VM quota (spec 2.4 item 4), software-sealed with a private
 *                 TypeKey and handled exactly like `quota_sched`: two 16-byte
 *                 headers at the front of the page, offset 0 for the ADMIN
 *                 handle (derive/destroy/create/mkdir/unlink/write) and
 *                 offset 16 for the OP handle (open/read/list/query). Which
 *                 header a handle was sealed over is its permission. A node
 *                 has a limit, a use and a delegation, in bytes and in
 *                 inodes, always `used + delegated <= limit`, and a root
 *                 directory. The root node is the data area of the disk and
 *                 all inodes, rooted at `/`.
 *   Paths         Every path a handle names is relative to its node's root
 *                 directory and cannot climb out of it (no "..", no leading
 *                 '/'), so what a holder can reach is settled when the node
 *                 is derived: `fs.quota_derive` takes the directory the child
 *                 is rooted at, which must lie under the parent's own.
 *   Ownership     Every file belongs to the node it was created under, and
 *                 the blocks it grows into are charged to that node and to
 *                 no other: an ancestor writing to it does not pay. Like the
 *                 scheduler's tree, ownership lives in memory only: after a
 *                 reboot every file on the disk belongs to the root again and
 *                 `init` re-derives what it hands out -- with
 *                 FS_DERIVE_ADOPT, so that the shell's node starts out owning
 *                 whatever was left in `/home`, charges and all, instead of
 *                 merely seeing it. Adoption moves only what the parent owns
 *                 at or under the child's root. `rm src/disk.img` starts from
 *                 a blank disk -- minus the system's own images, so rebuild
 *                 it with `make disk.img` (see below).
 *   Visibility    A handle sees everything under its root directory, whoever
 *                 owns it; it can write to and remove only what its own node
 *                 or a descendant owns (abi.hpp has the table). So two nodes
 *                 rooted at one directory see each other's files and cannot
 *                 touch them, and an ancestor can place a file in a child's
 *                 directory that the child can read but not remove. There is
 *                 no "public" bit: where an inode sits and who holds a handle
 *                 rooted above it is the whole of the rule. Destroying a node
 *                 unlinks the files it owns and the directories of its that
 *                 are then empty (spec 3.8 cascade) and hands its limits back
 *                 to the parent; a directory still holding other nodes' files,
 *                 or that another node is rooted at, passes to the parent with
 *                 them. Only its own children stand in a node's way.
 *   Layout        `init` makes `/home` and `/bin`. The shell's node is rooted
 *                 at `/home` with all the space the system's images leave,
 *                 and a second, OP-only, 0-byte node rooted at `/bin` lets it
 *                 read the programs the build put there and nothing else. The
 *                 system's own images sit in `/`, where only the root handle
 *                 is rooted, so nothing the shell holds can so much as name
 *                 them.
 *
 * THE DISK IS ALSO WHERE THE SYSTEM LIVES
 *   `fs` is part of the boot set (`kernel/boot_images.S`): it comes up before
 *   `naming`, `sched`, `trap_mgr` and the shell, because `init` reads those
 *   out of this file system (`tools/signetfs.py` writes them into the disk
 *   image at build time) and loads them through `loader`. Two things follow.
 *   The entry points below are handed back to `init` in the `FsInterface`
 *   handshake rather than published here, since there is nothing to publish
 *   them with yet; `init` publishes them as "fs.*" once `naming` is running.
 *   And the first reads go through a `blk` that polls: the scheduler it
 *   would sleep in is one of the files being read.
 *
 * ENTRY POINTS (each a separate `OType::EntryPoint`; `init` publishes them)
 *   fs.quota_derive   FsDeriveRequest    ADMIN on parent; child rooted at `path`;
 *                                        returns the handle asked for and the
 *                                        child's ADMIN handle (to destroy it with);
 *                                        FS_DERIVE_ADOPT moves the parent's files
 *                                        there to the child
 *   fs.quota_destroy  FsDestroyRequest   ADMIN; BUSY while children remain
 *   fs.quota_query    FsQueryRequest     either
 *   fs.create         FsOpenRequest      ADMIN: a new file owned by the node
 *   fs.mkdir          FsPathRequest      ADMIN: a new directory owned by the node
 *   fs.open           FsOpenRequest      either; writable iff asked, ADMIN and owned
 *   fs.close          FsCloseRequest
 *   fs.read           FsIoRequest
 *   fs.write          FsIoRequest        writable handle; grows the file
 *   fs.unlink         FsPathRequest      ADMIN of the owner or of an ancestor
 *   fs.list           FsListRequest      either; one directory's entries
 *
 * FILE HANDLES
 *   A software-sealed capability, under a second private TypeKey, over an
 *   `OpenFile` record in the page of the node the file was opened through
 *   (the part of the page after the `QuotaDisk` struct: FS_OPEN_PER_NODE
 *   records). So the records are the holder's own memory, bought with the
 *   node: a holder that opens too much exhausts its node and nobody else's,
 *   and when a node is destroyed every handle opened through it dies with the
 *   page. Closing clears the record and its sealing header, so the handle
 *   stops unsealing; a record reused by a later open through the same node is
 *   indistinguishable from the old one to a stale handle, as with any object
 *   named by its address -- but that later open is the same holder's.
 *
 * ONE CALLER AT A TIME
 *   A disk request parks the calling thread in `sched.block` (inside `blk`);
 *   a second thread arriving meanwhile gets FS_BUSY rather than a view of a
 *   half-updated table.
 */

#include "runtime.hpp"

namespace signetos::user {
namespace {

// --- What `fs` asks `init` for (user/manifest.hpp) ----------------------------
// `blk.read` / `blk.write` are asked for here and nowhere else: `fs` is the
// only compartment that can touch the disk, and it only ever does so on behalf
// of a `quota_disk` handle. They are optional because a machine without a
// block device still boots -- the file system then reports itself unmounted.
// No `naming` entry: `fs` hands its entry points back in the `FsInterface`
// handshake and `init` publishes them.
#define FS_MANIFEST(X)                                   \
  M_SYSCALL(X, SYS_VM_ALLOC, vm_allocate)                \
  M_SYSCALL(X, SYS_VM_DEALLOC, vm_deallocate)            \
  M_SYSCALL(X, SYS_TYPE_MINT, type_mint)                 \
  M_SYSCALL(X, SYS_SEAL, seal)                           \
  M_SYSCALL(X, SYS_UNSEAL, unseal)                       \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)      \
  M_SYSCALL(X, SYS_SENTRY, sentry)                       \
  M_SERVICE(X, UART_SENTRY, "uart")                      \
  M_SERVICE_OPT(X, BLK_READ, "blk.read")                 \
  M_SERVICE_OPT(X, BLK_WRITE, "blk.write")
// 128 KiB for code, stack, `.bss` and the root quota node; `init` adds what
// the in-memory tables need for the disk it found (see init.cpp, step 4).
SIGNETOS_MANIFEST(FS_MANIFEST, 128 * 1024)
// Runtime slots: the sealing types for `quota_disk` handles and for open-file
// handles, kept in the table past the seeds.
constexpr size_t SLOT_QUOTA_TYPE_KEY = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 0;
constexpr size_t SLOT_FILE_TYPE_KEY  = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 1;

// --- On-disk format -----------------------------------------------------------

constexpr uint64_t MAGIC   = 0x5349474e45544653ULL;  // "SIGNETFS"
constexpr uint32_t VERSION = 3;

constexpr uint64_t BLOCK_BYTES        = init::FS_BLOCK_BYTES;
constexpr uint64_t SECTORS_PER_BLOCK  = BLOCK_BYTES / init::BLK_SECTOR_BYTES;
constexpr uint64_t BITS_PER_BLOCK     = BLOCK_BYTES * 8;
constexpr uint32_t DIRECT_BLOCKS      = static_cast<uint32_t>(init::FS_DIRECT_BLOCKS);
constexpr uint32_t INDIRECT_SLOTS     = static_cast<uint32_t>(init::FS_INDIRECT_SLOTS);
constexpr uint32_t MAX_FILE_BLOCKS    = static_cast<uint32_t>(init::FS_MAX_FILE_BLOCKS);
constexpr uint64_t SUPER_BLOCK        = 0;

struct Superblock {
  uint64_t magic;
  uint32_t version;
  uint32_t block_bytes;
  uint64_t total_blocks;
  uint64_t data_start;
  uint32_t max_inodes;
  uint32_t inode_table_blocks;
  uint64_t bitmap_block;
  uint64_t inode_block;
  uint32_t bitmap_blocks;
  uint32_t reserved;
};
static_assert(sizeof(Superblock) <= BLOCK_BYTES);

constexpr uint32_t INODE_USED = 1;
// A directory: no blocks of its own; its entries are the inodes whose
// `parent` names it.
constexpr uint32_t INODE_DIR = 2;
// `Inode::parent` of an entry of `/`, which is not itself an inode.
constexpr uint32_t ROOT_DIR = 0xFFFFFFFFu;

struct Inode {
  uint32_t flags;                 // INODE_USED | INODE_DIR, or 0
  uint32_t nblocks;               // number of data blocks in the file
  uint64_t size;                  // bytes; <= nblocks * BLOCK_BYTES
  char name[init::FS_NAME_MAX];   // NUL-terminated
  uint32_t blocks[DIRECT_BLOCKS];
  uint32_t indirect;              // block holding u32[INDIRECT_SLOTS], or 0
  uint32_t parent;                // the directory this is an entry of, or ROOT_DIR
  uint8_t reserved[8];
};
static_assert(sizeof(Inode) == 128);
constexpr uint32_t INODES_PER_BLOCK =
    static_cast<uint32_t>(BLOCK_BYTES / sizeof(Inode));
static_assert(static_cast<uint64_t>(MAX_FILE_BLOCKS) * BLOCK_BYTES ==
              init::FS_MAX_FILE_BYTES);

// --- In-memory objects ----------------------------------------------------------

constexpr size_t MAX_NODES = 32;

// One node per page (spec 2.4.5 `struct quota_disk`). The two sealing
// headers come first (see the file comment); everything else is private. The
// rest of the page, after this struct, holds the node's open-file records
// (`node_files`).
struct alignas(16) QuotaDisk {
  Capability admin_header;  // sys_seal writes the TypeKey here (ADMIN handle)
  Capability op_header;     // ... or here (OP handle)
  struct {
    QuotaDisk* parent;
    QuotaDisk* first_child;
    QuotaDisk* next_sibling;
    QuotaDisk* prev_sibling;
    uint64_t child_count;
  } tree;

  uint64_t limit_bytes;
  uint64_t used_bytes;        // by this node's own files, whole blocks
  uint64_t delegated_bytes;   // the sum of the children's limits
  uint32_t limit_inodes;
  uint32_t used_inodes;
  uint32_t delegated_inodes;
  uint32_t root_dir;          // the directory every path is relative to
  uint32_t file_cursor;       // where the next open-file slot search starts
  uint32_t pad_;

  Capability node_page;       // this page, as returned by sys_vm_allocate
  Capability node_funding;    // the QuotaVm that paid for it
};
static_assert(__builtin_offsetof(QuotaDisk, admin_header) ==
              init::QUOTA_DISK_ADMIN_HEADER);
static_assert(__builtin_offsetof(QuotaDisk, op_header) ==
              init::QUOTA_DISK_OP_HEADER);
static_assert(sizeof(QuotaDisk) % 16 == 0);

// An open file: the 16-byte sealing header, then what the handle names. The
// records sit in the page of the node the file was opened through, so a
// holder that opens too much runs out of its own node's page and nobody
// else's, and its handles die with the node.
struct alignas(16) OpenFile {
  Capability header;  // sys_seal writes the TypeKey here
  uint32_t inode;
  uint32_t in_use;
  uint32_t writable;  // opened through an ADMIN handle (or by create)
  uint32_t pad_;
};
static_assert(sizeof(OpenFile) == 32);

constexpr size_t FILES_PER_NODE =
    (vm::PAGE_SIZE - sizeof(QuotaDisk)) / sizeof(OpenFile);
static_assert(FILES_PER_NODE == init::FS_OPEN_PER_NODE,
              "abi.hpp FS_OPEN_PER_NODE must match the page layout");
static_assert(sizeof(QuotaDisk) + FILES_PER_NODE * sizeof(OpenFile) <=
              vm::PAGE_SIZE);

// --- State -------------------------------------------------------------------------

alignas(16) Capability s_quota_type_record = nullptr;
alignas(16) Capability s_file_type_record = nullptr;
Capability s_self_comp = nullptr;
Capability s_vm_quota = nullptr;
Capability s_quota_key = nullptr;
Capability s_file_key = nullptr;
Capability s_gate_alloc = nullptr;
Capability s_gate_dealloc = nullptr;
Capability s_gate_seal = nullptr;
Capability s_gate_unseal = nullptr;
Capability s_gate_invoke = nullptr;
Capability s_uart = nullptr;
Capability s_blk_read = nullptr;
Capability s_blk_write = nullptr;

QuotaDisk* s_root = nullptr;
QuotaDisk* s_nodes[MAX_NODES];
size_t s_node_count = 0;

// Metadata tables sized from the superblock at mount time and allocated from
// `s_vm_quota`.
uint8_t* s_bitmap = nullptr;
Inode* s_inodes = nullptr;
QuotaDisk** s_owner = nullptr;

alignas(16) uint8_t s_io[BLOCK_BYTES];        // data block in flight
alignas(16) uint32_t s_indirect[INDIRECT_SLOTS];  // cached indirect block
uint32_t s_indirect_blk = 0;                  // block cached in s_indirect (0 = none)

uint64_t s_total_blocks = 0;
uint64_t s_bitmap_block = 1;
uint32_t s_bitmap_blocks = 0;
uint64_t s_inode_block = 0;
uint32_t s_inode_table_blocks = 0;
uint32_t s_max_inodes = 0;
uint64_t s_data_start = 0;

bool s_mounted = false;
bool s_busy = false;
bool s_first_call_done = false;

// --- Small helpers -------------------------------------------------------------------

void out(const char* msg) { print(s_gate_invoke, s_uart, msg); }
void out_dec(const char* p, uint64_t v, const char* s) {
  print_dec(s_gate_invoke, s_uart, p, v, s);
}

template <typename T>
Capability bounded(T* p) {
  return capability_set_bounds(reinterpret_cast<Capability>(p), sizeof(T));
}

void zero_bytes(void* p, size_t n) {
  auto* d = static_cast<uint8_t*>(p);
  for (size_t i = 0; i < n; ++i) {
    d[i] = 0;
  }
}

void copy_bytes(void* dst, const void* src, size_t n) {
  auto* d = static_cast<uint8_t*>(dst);
  const auto* s = static_cast<const uint8_t*>(src);
  for (size_t i = 0; i < n; ++i) {
    d[i] = s[i];
  }
}

// Bytes addressable from `cap`'s current address to the end of its bounds.
uint64_t room(Capability cap) {
  const uint64_t base = capability_get_base(cap);
  const uint64_t end = base + capability_get_length(cap);
  const uint64_t addr = capability_get_address(cap);
  return (addr < base || addr > end) ? 0 : end - addr;
}

// A request must be writable (we report status through it) and whole.
template <typename T>
T* open_request(Capability arg) {
  if (!capability_is_valid(arg) || sealing::is_sealed(arg) ||
      !capability_has_perms(arg, perms::Load | perms::Store) ||
      room(arg) < sizeof(T)) {
    return nullptr;
  }
  return reinterpret_cast<T*>(arg);
}

// A caller's data buffer: unsealed, with `need` permissions and `bytes` of
// room from its address.
bool buffer_ok(Capability buf, uint64_t need, uint64_t bytes) {
  return capability_is_valid(buf) && !sealing::is_sealed(buf) &&
         capability_has_perms(buf, need) && room(buf) >= bytes;
}

// Marks the tables as mid-update on the current thread. `taken` is false if
// another thread already holds them (it is parked in `blk`).
struct BusyScope {
  bool taken;
  BusyScope() : taken(!s_busy) {
    if (taken) {
      s_busy = true;
    }
  }
  ~BusyScope() {
    if (taken) {
      s_busy = false;
    }
  }
};

// --- Names ---------------------------------------------------------------------------

// 1..FS_NAME_MAX-1 printable, non-blank characters, no '/', NUL-terminated
// inside the FS_NAME_MAX-byte field.
bool name_ok(const char* name) {
  size_t len = 0;
  while (len < init::FS_NAME_MAX && name[len] != '\0') {
    const char c = name[len];
    if (c <= ' ' || c > '~' || c == '/') {
      return false;
    }
    len += 1;
  }
  return len != 0 && len < init::FS_NAME_MAX;
}

// A path component: a name that is neither "." nor "..", the only two names
// that would mean something other than an entry.
bool component_ok(const char* comp) {
  if (!name_ok(comp)) {
    return false;
  }
  if (comp[0] == '.' &&
      (comp[1] == '\0' || (comp[1] == '.' && comp[2] == '\0'))) {
    return false;
  }
  return true;
}

bool names_equal(const char* a, const char* b) {
  for (size_t i = 0; i < init::FS_NAME_MAX; ++i) {
    if (a[i] != b[i]) {
      return false;
    }
    if (a[i] == '\0') {
      return true;
    }
  }
  return true;
}

void copy_name(char* dst, const char* src) {
  size_t i = 0;
  for (; i + 1 < init::FS_NAME_MAX && src[i] != '\0'; ++i) {
    dst[i] = src[i];
  }
  for (; i < init::FS_NAME_MAX; ++i) {
    dst[i] = '\0';
  }
}

// --- Block device --------------------------------------------------------------------

// Moves one 4 KiB block between `buf` and the disk through `blk`. The buffer
// handed over is bounded to the block and, for a write, read-only.
int64_t blk_io(Capability entry, uint64_t block, void* buf, bool write) {
  if (!capability_is_valid(entry)) {
    return init::FS_IO_ERROR;
  }
  init::BlkRequest req{};
  Capability b =
      capability_set_bounds(reinterpret_cast<Capability>(buf), BLOCK_BYTES);
  req.buf = write ? capability_and_perms(b, perms::Load) : b;
  req.sector = block * SECTORS_PER_BLOCK;
  req.count = SECTORS_PER_BLOCK;
  req.status = init::BLK_IO_ERROR;
  using FnInvoke = decltype(&sys_compartment_invoke);
  reinterpret_cast<FnInvoke>(s_gate_invoke)(entry, bounded(&req));
  return req.status == init::BLK_OK ? init::FS_OK : init::FS_IO_ERROR;
}

int64_t read_block(uint64_t block, void* buf) {
  return blk_io(s_blk_read, block, buf, false);
}

int64_t write_block(uint64_t block, const void* buf) {
  return blk_io(s_blk_write, block, const_cast<void*>(buf), true);
}

int64_t write_bitmap() {
  for (uint32_t k = 0; k < s_bitmap_blocks; ++k) {
    const int64_t st =
        write_block(s_bitmap_block + k, s_bitmap + k * BLOCK_BYTES);
    if (st != init::FS_OK) {
      return st;
    }
  }
  return init::FS_OK;
}

// Writes the inode-table block holding inode `ino`.
int64_t write_inode_block(uint32_t ino) {
  const uint32_t block = ino / INODES_PER_BLOCK;
  return write_block(s_inode_block + block,
                     &s_inodes[block * INODES_PER_BLOCK]);
}

int64_t load_indirect(uint32_t blk) {
  if (blk == 0) {
    return init::FS_IO_ERROR;
  }
  if (s_indirect_blk == blk) {
    return init::FS_OK;
  }
  const int64_t st = read_block(blk, s_indirect);
  if (st == init::FS_OK) {
    s_indirect_blk = blk;
  }
  return st;
}

int64_t save_indirect(uint32_t blk) {
  s_indirect_blk = blk;
  return write_block(blk, s_indirect);
}

// Resolves block index `bi` (0 .. in.nblocks-1) of `in` to its disk block.
int64_t inode_block_at(const Inode& in, uint32_t bi, uint32_t* out_blk) {
  if (bi >= in.nblocks) {
    return init::FS_IO_ERROR;
  }
  if (bi < DIRECT_BLOCKS) {
    *out_blk = in.blocks[bi];
    return init::FS_OK;
  }
  const int64_t st = load_indirect(in.indirect);
  if (st != init::FS_OK) {
    return st;
  }
  *out_blk = s_indirect[bi - DIRECT_BLOCKS];
  return init::FS_OK;
}

// Total disk blocks (data + indirect metadata block if present) charged to
// an inode with `nblocks` data blocks.
inline uint64_t charged_blocks_for(uint32_t nblocks) {
  return static_cast<uint64_t>(nblocks) + (nblocks > DIRECT_BLOCKS ? 1 : 0);
}

// --- Block bitmap ----------------------------------------------------------------------

inline bool bit_test(uint64_t b) {
  return ((s_bitmap[b >> 3] >> (b & 7)) & 1u) != 0;
}
inline void bit_set(uint64_t b) {
  s_bitmap[b >> 3] = static_cast<uint8_t>(s_bitmap[b >> 3] | (1u << (b & 7)));
}
inline void bit_clear(uint64_t b) {
  s_bitmap[b >> 3] = static_cast<uint8_t>(s_bitmap[b >> 3] & ~(1u << (b & 7)));
}

// Claims one free block after `start_from` into `*out`.
bool claim_one_block(uint64_t* cursor, uint32_t* out) {
  for (uint64_t b = *cursor; b < s_total_blocks; ++b) {
    if (!bit_test(b)) {
      bit_set(b);
      *out = static_cast<uint32_t>(b);
      *cursor = b + 1;
      return true;
    }
  }
  return false;
}

// --- Quota nodes ------------------------------------------------------------------------

inline uint64_t avail_bytes(const QuotaDisk* q) {
  const uint64_t taken = q->used_bytes + q->delegated_bytes;
  return taken >= q->limit_bytes ? 0 : q->limit_bytes - taken;
}

inline uint32_t avail_inodes(const QuotaDisk* q) {
  const uint32_t taken = q->used_inodes + q->delegated_inodes;
  return taken >= q->limit_inodes ? 0 : q->limit_inodes - taken;
}

// True if `q` is `ancestor` or is derived from it.
bool is_within(const QuotaDisk* ancestor, const QuotaDisk* q) {
  for (; q != nullptr; q = q->tree.parent) {
    if (q == ancestor) {
      return true;
    }
  }
  return false;
}

QuotaDisk* node_for_page(uint64_t page_addr) {
  for (size_t i = 0; i < s_node_count; ++i) {
    if (capability_get_base(s_nodes[i]->node_page) == page_addr) {
      return s_nodes[i];
    }
  }
  return nullptr;
}

// True if a node other than `except` is rooted at directory `dir`.
bool node_rooted_at(uint32_t dir, const QuotaDisk* except) {
  for (size_t i = 0; i < s_node_count; ++i) {
    if (s_nodes[i] != except && s_nodes[i]->root_dir == dir) {
      return true;
    }
  }
  return false;
}

struct QuotaRef {
  QuotaDisk* node;  // nullptr: not one of our handles
  bool admin;       // sealed over the ADMIN header
};

// Unseals a quota handle and tells which header it was sealed over.
QuotaRef open_quota(Capability handle) {
  QuotaRef ref{nullptr, false};
  using FnUnseal = decltype(&sys_unseal);
  Capability payload = syscall::call<FnUnseal>(s_gate_invoke, s_gate_unseal,
                                               s_quota_key, handle);
  if (!capability_is_valid(payload)) {
    return ref;
  }
  // `sys_unseal` returns the payload *after* the 16-byte header it checked,
  // so the header this handle was sealed over sits 16 bytes below its base.
  const uint64_t base = capability_get_base(payload);
  const uint64_t off = base & (vm::PAGE_SIZE - 1);
  if (off < sizeof(Capability)) {
    return ref;
  }
  const uint64_t header = off - sizeof(Capability);
  if (header != init::QUOTA_DISK_ADMIN_HEADER &&
      header != init::QUOTA_DISK_OP_HEADER) {
    return ref;
  }
  ref.node = node_for_page(base - off);
  ref.admin = (header == init::QUOTA_DISK_ADMIN_HEADER);
  return ref;
}

Capability seal_node(QuotaDisk* node, bool admin) {
  using FnSeal = decltype(&sys_seal);
  const uint64_t off =
      admin ? init::QUOTA_DISK_ADMIN_HEADER : init::QUOTA_DISK_OP_HEADER;
  Capability obj = capability_set_address(
      node->node_page, capability_get_base(node->node_page) + off);
  return syscall::call<FnSeal>(s_gate_invoke, s_gate_seal, s_quota_key, obj);
}

// A node under `parent` (or the root, for nullptr), rooted where the parent
// is until the caller says otherwise.
QuotaDisk* alloc_node(Capability funding, QuotaDisk* parent) {
  if (s_node_count >= MAX_NODES) {
    return nullptr;
  }
  using FnAlloc = decltype(&sys_vm_allocate);
  Capability page = syscall::call<FnAlloc>(s_gate_invoke, s_gate_alloc,
                                           s_self_comp, funding, vm::PAGE_SIZE,
                                           FLAG_ZERO);
  if (!capability_is_valid(page)) {
    return nullptr;
  }
  QuotaDisk* n = reinterpret_cast<QuotaDisk*>(page);
  n->node_page = page;
  n->node_funding = funding;
  n->tree.parent = parent;
  n->tree.first_child = nullptr;
  n->tree.prev_sibling = nullptr;
  n->tree.next_sibling = nullptr;
  n->tree.child_count = 0;
  n->limit_bytes = 0;
  n->used_bytes = 0;
  n->delegated_bytes = 0;
  n->limit_inodes = 0;
  n->used_inodes = 0;
  n->delegated_inodes = 0;
  n->root_dir = parent != nullptr ? parent->root_dir : ROOT_DIR;
  n->file_cursor = 0;  // the records after the struct are zero (FLAG_ZERO)
  if (parent != nullptr) {
    n->tree.next_sibling = parent->tree.first_child;
    if (parent->tree.first_child != nullptr) {
      parent->tree.first_child->tree.prev_sibling = n;
    }
    parent->tree.first_child = n;
    parent->tree.child_count += 1;
  }
  s_nodes[s_node_count++] = n;
  return n;
}

// The open-file records in `n`'s page, after the struct.
inline OpenFile* node_files(QuotaDisk* n) {
  return reinterpret_cast<OpenFile*>(reinterpret_cast<uint8_t*>(n) +
                                     sizeof(QuotaDisk));
}

void release_file(OpenFile* f);

// Unlinks `n` from the tree, returns its limits to the parent and frees its
// page -- and with it every file opened through it. The caller has already
// dealt with the files it owned.
void free_node(QuotaDisk* n) {
  QuotaDisk* parent = n->tree.parent;
  if (parent != nullptr) {
    if (n->tree.prev_sibling != nullptr) {
      n->tree.prev_sibling->tree.next_sibling = n->tree.next_sibling;
    } else {
      parent->tree.first_child = n->tree.next_sibling;
    }
    if (n->tree.next_sibling != nullptr) {
      n->tree.next_sibling->tree.prev_sibling = n->tree.prev_sibling;
    }
    parent->tree.child_count -= 1;
    parent->delegated_bytes = (parent->delegated_bytes >= n->limit_bytes)
                                  ? parent->delegated_bytes - n->limit_bytes
                                  : 0;
    parent->delegated_inodes = (parent->delegated_inodes >= n->limit_inodes)
                                   ? parent->delegated_inodes - n->limit_inodes
                                   : 0;
  }
  for (size_t i = 0; i < s_node_count; ++i) {
    if (s_nodes[i] == n) {
      s_nodes[i] = s_nodes[s_node_count - 1];
      s_nodes[s_node_count - 1] = nullptr;
      s_node_count -= 1;
      break;
    }
  }
  OpenFile* files = node_files(n);
  for (size_t i = 0; i < FILES_PER_NODE; ++i) {
    if (files[i].in_use != 0) {
      release_file(&files[i]);
    }
  }
  Capability page = n->node_page;
  Capability funding = n->node_funding;
  // The page is quarantined by the kernel, not reused; scrub what we can.
  n->node_page = nullptr;
  n->node_funding = nullptr;
  n->admin_header = nullptr;
  n->op_header = nullptr;
  using FnDealloc = decltype(&sys_vm_deallocate);
  syscall::call<FnDealloc>(s_gate_invoke, s_gate_dealloc, s_self_comp, funding,
                           page);
}

// --- Open files ---------------------------------------------------------------------------

// Unseals a file handle to its record, or nullptr. The record is in the page
// of the node the file was opened through, so the page must be a live node's
// and the offset one of its records; a handle into a destroyed node's page
// finds no node and is dead.
OpenFile* open_file(Capability handle) {
  using FnUnseal = decltype(&sys_unseal);
  Capability payload = syscall::call<FnUnseal>(s_gate_invoke, s_gate_unseal,
                                               s_file_key, handle);
  if (!capability_is_valid(payload)) {
    return nullptr;
  }
  // The payload starts right after the record's header (see open_quota).
  const uint64_t base = capability_get_base(payload);
  const uint64_t off = base & (vm::PAGE_SIZE - 1);
  if (off < sizeof(QuotaDisk) + sizeof(Capability)) {
    return nullptr;
  }
  const uint64_t rec = off - sizeof(Capability) - sizeof(QuotaDisk);
  if (rec % sizeof(OpenFile) != 0 || rec / sizeof(OpenFile) >= FILES_PER_NODE) {
    return nullptr;
  }
  QuotaDisk* n = node_for_page(base - off);
  if (n == nullptr) {
    return nullptr;
  }
  OpenFile* f = &node_files(n)[rec / sizeof(OpenFile)];
  return f->in_use != 0 ? f : nullptr;
}

// A free record of `n`'s, scanning on from the last one handed out so that a
// record is not reused the moment it is closed. nullptr when the node's page
// is full: that holder's problem, and only that holder's.
OpenFile* alloc_file(QuotaDisk* n) {
  OpenFile* files = node_files(n);
  for (size_t k = 0; k < FILES_PER_NODE; ++k) {
    const size_t i = (n->file_cursor + k) % FILES_PER_NODE;
    if (files[i].in_use == 0) {
      n->file_cursor = static_cast<uint32_t>((i + 1) % FILES_PER_NODE);
      return &files[i];
    }
  }
  return nullptr;
}

Capability seal_file(OpenFile* f) {
  using FnSeal = decltype(&sys_seal);
  Capability obj = capability_set_bounds(reinterpret_cast<Capability>(f),
                                         sizeof(OpenFile));
  return syscall::call<FnSeal>(s_gate_invoke, s_gate_seal, s_file_key, obj);
}

void release_file(OpenFile* f) {
  f->header = nullptr;  // the handle stops unsealing from here on
  f->inode = 0;
  f->writable = 0;
  f->in_use = 0;
}

// Closes every handle on inode `ino`, whichever node it was opened through.
void invalidate_open(uint32_t ino) {
  for (size_t j = 0; j < s_node_count; ++j) {
    OpenFile* files = node_files(s_nodes[j]);
    for (size_t i = 0; i < FILES_PER_NODE; ++i) {
      if (files[i].in_use != 0 && files[i].inode == ino) {
        release_file(&files[i]);
      }
    }
  }
}

// --- Inodes and directories ---------------------------------------------------------------

inline bool inode_used(uint32_t ino) {
  return (s_inodes[ino].flags & INODE_USED) != 0;
}

inline bool inode_is_dir(uint32_t ino) {
  return (s_inodes[ino].flags & INODE_DIR) != 0;
}

// The entry called `name` of directory `dir` (ROOT_DIR for `/`), or -1.
int find_in_dir(uint32_t dir, const char* name) {
  for (uint32_t i = 0; i < s_max_inodes; ++i) {
    if (inode_used(i) && s_inodes[i].parent == dir &&
        names_equal(s_inodes[i].name, name)) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

bool dir_empty(uint32_t dir) {
  for (uint32_t i = 0; i < s_max_inodes; ++i) {
    if (inode_used(i) && s_inodes[i].parent == dir) {
      return false;
    }
  }
  return true;
}

// True if inode `ino` is directory `dir` or lies somewhere below it; under
// ROOT_DIR is everything. The walk up is bounded so a damaged parent chain
// cannot loop.
bool under_dir(uint32_t ino, uint32_t dir) {
  if (dir == ROOT_DIR) {
    return true;
  }
  uint32_t d = ino;
  for (uint32_t steps = 0; d != ROOT_DIR && steps <= s_max_inodes; ++steps) {
    if (d == dir) {
      return true;
    }
    d = d < s_max_inodes ? s_inodes[d].parent : ROOT_DIR;
  }
  return false;
}

int find_free_inode() {
  for (uint32_t i = 0; i < s_max_inodes; ++i) {
    if (!inode_used(i)) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

// A path followed from directory `start`. `dir` is the directory the last
// component is an entry of and `leaf` that component; `ino` is its inode
// when `found`. The empty path names `start` itself: `leaf` is "", `found`
// and `ino` is `start`.
struct Walk {
  uint32_t dir;
  uint32_t ino;
  bool found;
  char leaf[init::FS_NAME_MAX];
};

// FS_BAD_REQUEST for a malformed path (abi.hpp, "Paths"); FS_NOT_FOUND when a
// directory on the way is missing or is a file; FS_OK otherwise, `out->found`
// saying whether the last component exists. A handle's paths all start at
// its node's root and only ever go down, so whatever a walk reaches is under
// that root by construction: that is the whole of the visibility check.
int64_t walk(uint32_t start, const char* path, Walk* out) {
  out->dir = start;
  out->ino = start;
  out->found = true;
  out->leaf[0] = '\0';
  size_t len = 0;
  while (len < init::FS_PATH_MAX && path[len] != '\0') {
    len += 1;
  }
  if (len >= init::FS_PATH_MAX) {
    return init::FS_BAD_REQUEST;
  }
  if (len == 0) {
    return init::FS_OK;
  }
  uint32_t dir = start;
  size_t pos = 0;
  while (pos < len) {
    size_t end = pos;
    while (end < len && path[end] != '/') {
      end += 1;
    }
    const size_t clen = end - pos;
    if (clen == 0 || clen >= init::FS_NAME_MAX) {
      return init::FS_BAD_REQUEST;  // a leading, doubled or trailing '/'
    }
    char comp[init::FS_NAME_MAX];
    for (size_t i = 0; i < clen; ++i) {
      comp[i] = path[pos + i];
    }
    comp[clen] = '\0';
    if (!component_ok(comp)) {
      return init::FS_BAD_REQUEST;
    }
    const int ino = find_in_dir(dir, comp);
    if (end == len) {
      out->dir = dir;
      copy_name(out->leaf, comp);
      out->found = ino >= 0;
      out->ino = ino >= 0 ? static_cast<uint32_t>(ino) : 0;
      return init::FS_OK;
    }
    if (ino < 0 || !inode_is_dir(static_cast<uint32_t>(ino))) {
      return init::FS_NOT_FOUND;
    }
    dir = static_cast<uint32_t>(ino);
    pos = end + 1;
  }
  return init::FS_BAD_REQUEST;  // a trailing '/'
}

// Frees everything inode `ino` holds, refunds its owner, invalidates any open
// handle on it and writes both metadata blocks through. Returns the status
// of those writes; the in-memory tables are updated either way. A directory
// holds no blocks, so for one this is the inode and the refund.
int64_t unlink_inode(uint32_t ino) {
  Inode& in = s_inodes[ino];
  QuotaDisk* owner = s_owner[ino];
  const uint32_t nblocks =
      in.nblocks < MAX_FILE_BLOCKS ? in.nblocks : MAX_FILE_BLOCKS;
  const uint32_t direct_n = nblocks < DIRECT_BLOCKS ? nblocks : DIRECT_BLOCKS;
  for (uint32_t i = 0; i < direct_n; ++i) {
    bit_clear(in.blocks[i]);
  }
  if (nblocks > DIRECT_BLOCKS && in.indirect != 0) {
    if (load_indirect(in.indirect) == init::FS_OK) {
      const uint32_t ind_n = nblocks - DIRECT_BLOCKS;
      for (uint32_t i = 0; i < ind_n; ++i) {
        if (s_indirect[i] != 0) {
          bit_clear(s_indirect[i]);
        }
      }
    }
    if (s_indirect_blk == in.indirect) {
      s_indirect_blk = 0;
    }
    bit_clear(in.indirect);
  }
  const uint64_t bytes = charged_blocks_for(nblocks) * BLOCK_BYTES;
  if (owner != nullptr) {
    owner->used_bytes = owner->used_bytes >= bytes ? owner->used_bytes - bytes : 0;
    if (owner->used_inodes > 0) {
      owner->used_inodes -= 1;
    }
  }
  s_owner[ino] = nullptr;
  invalidate_open(ino);
  zero_bytes(&in, sizeof(Inode));
  const int64_t st_bitmap = write_bitmap();
  const int64_t st_inode = write_inode_block(ino);
  return st_bitmap != init::FS_OK ? st_bitmap : st_inode;
}

// A new inode called `name` in directory `dir`, owned by and charged to
// `owner`, written through. The caller has checked the name is free and the
// owner has an inode to spare. Returns the inode number, or a negative FS_*.
int64_t new_inode(QuotaDisk* owner, uint32_t dir, const char* name,
                  uint32_t flags) {
  const int ino = find_free_inode();
  if (ino < 0) {
    return init::FS_DISK_FULL;
  }
  Inode& in = s_inodes[ino];
  zero_bytes(&in, sizeof(Inode));
  in.flags = INODE_USED | flags;
  in.parent = dir;
  copy_name(in.name, name);
  const int64_t st = write_inode_block(static_cast<uint32_t>(ino));
  if (st != init::FS_OK) {
    zero_bytes(&in, sizeof(Inode));
    return st;
  }
  s_owner[ino] = owner;
  owner->used_inodes += 1;
  return ino;
}

// --- Mount ---------------------------------------------------------------------------------

// Computes default geometry scaled to `total_blocks`, matching
// `default_geometry()` in `tools/signetfs.py`.
void default_geometry(uint64_t total_blocks) {
  s_total_blocks = total_blocks;
  s_bitmap_block = 1;
  s_bitmap_blocks = static_cast<uint32_t>(
      (total_blocks + BITS_PER_BLOCK - 1) / BITS_PER_BLOCK);
  s_inode_block = s_bitmap_block + s_bitmap_blocks;
  uint64_t want_inodes = total_blocks / 16;
  if (want_inodes < 64) {
    want_inodes = 64;
  }
  s_inode_table_blocks = static_cast<uint32_t>(
      (want_inodes + INODES_PER_BLOCK - 1) / INODES_PER_BLOCK);
  s_max_inodes = s_inode_table_blocks * INODES_PER_BLOCK;
  s_data_start = s_inode_block + s_inode_table_blocks;
}

// Allocates `s_bitmap`, `s_inodes` and `s_owner` from `s_vm_quota` once the
// geometry is known.
bool alloc_metadata_tables() {
  using FnAlloc = decltype(&sys_vm_allocate);
  const size_t bitmap_bytes = static_cast<size_t>(s_bitmap_blocks) * BLOCK_BYTES;
  const size_t inode_bytes =
      static_cast<size_t>(s_inode_table_blocks) * BLOCK_BYTES;
  const size_t owner_raw = static_cast<size_t>(s_max_inodes) * sizeof(QuotaDisk*);
  const size_t owner_bytes =
      (owner_raw + vm::PAGE_SIZE - 1) & ~(vm::PAGE_SIZE - 1);

  Capability bm = syscall::call<FnAlloc>(
      s_gate_invoke, s_gate_alloc, s_self_comp, s_vm_quota, bitmap_bytes,
      FLAG_ZERO);
  Capability in = syscall::call<FnAlloc>(
      s_gate_invoke, s_gate_alloc, s_self_comp, s_vm_quota, inode_bytes,
      FLAG_ZERO);
  Capability ow = syscall::call<FnAlloc>(
      s_gate_invoke, s_gate_alloc, s_self_comp, s_vm_quota, owner_bytes,
      FLAG_ZERO);
  if (!capability_is_valid(bm) || !capability_is_valid(in) ||
      !capability_is_valid(ow)) {
    return false;
  }
  s_bitmap = reinterpret_cast<uint8_t*>(bm);
  s_inodes = reinterpret_cast<Inode*>(in);
  s_owner = reinterpret_cast<QuotaDisk**>(ow);
  return true;
}

// Writes a blank file system over `s_total_blocks` blocks: an empty `/`.
int64_t format() {
  zero_bytes(s_io, BLOCK_BYTES);
  auto* sb = reinterpret_cast<Superblock*>(s_io);
  sb->magic = MAGIC;
  sb->version = VERSION;
  sb->block_bytes = static_cast<uint32_t>(BLOCK_BYTES);
  sb->total_blocks = s_total_blocks;
  sb->data_start = s_data_start;
  sb->max_inodes = s_max_inodes;
  sb->inode_table_blocks = s_inode_table_blocks;
  sb->bitmap_block = s_bitmap_block;
  sb->inode_block = s_inode_block;
  sb->bitmap_blocks = s_bitmap_blocks;
  sb->reserved = 0;
  int64_t st = write_block(SUPER_BLOCK, s_io);
  if (st != init::FS_OK) {
    return st;
  }
  zero_bytes(s_bitmap, static_cast<size_t>(s_bitmap_blocks) * BLOCK_BYTES);
  for (uint64_t b = 0; b < s_data_start; ++b) {
    bit_set(b);
  }
  st = write_bitmap();
  if (st != init::FS_OK) {
    return st;
  }
  zero_bytes(s_inodes, static_cast<size_t>(s_inode_table_blocks) * BLOCK_BYTES);
  for (uint32_t k = 0; k < s_inode_table_blocks; ++k) {
    st = write_inode_block(k * INODES_PER_BLOCK);
    if (st != init::FS_OK) {
      return st;
    }
  }
  return init::FS_OK;
}

// An inode the table can be trusted on: in bounds, blocks allocated, name
// well formed, in a chain of directories that leads to `/` without looping,
// and not a second entry of that name in its directory. Anything else is
// dropped at mount rather than accounted for.
bool inode_sane(uint32_t ino) {
  const Inode& in = s_inodes[ino];
  if ((in.flags & ~(INODE_USED | INODE_DIR)) != 0 ||
      in.nblocks > MAX_FILE_BLOCKS ||
      in.size > static_cast<uint64_t>(in.nblocks) * BLOCK_BYTES ||
      !name_ok(in.name)) {
    return false;
  }
  if ((in.flags & INODE_DIR) != 0 &&
      (in.nblocks != 0 || in.size != 0 || in.indirect != 0)) {
    return false;
  }
  const uint32_t direct_n =
      in.nblocks < DIRECT_BLOCKS ? in.nblocks : DIRECT_BLOCKS;
  for (uint32_t i = 0; i < direct_n; ++i) {
    const uint64_t b = in.blocks[i];
    if (b < s_data_start || b >= s_total_blocks || !bit_test(b)) {
      return false;
    }
  }
  if (in.nblocks > DIRECT_BLOCKS) {
    if (in.indirect < s_data_start || in.indirect >= s_total_blocks ||
        !bit_test(in.indirect) || load_indirect(in.indirect) != init::FS_OK) {
      return false;
    }
    const uint32_t ind_n = in.nblocks - DIRECT_BLOCKS;
    for (uint32_t i = 0; i < ind_n; ++i) {
      const uint64_t b = s_indirect[i];
      if (b < s_data_start || b >= s_total_blocks || !bit_test(b)) {
        return false;
      }
    }
  }
  // Its place: directories all the way up to `/`, and no further steps than
  // there are inodes (a loop would go on for ever).
  uint32_t steps = 0;
  for (uint32_t p = in.parent; p != ROOT_DIR; p = s_inodes[p].parent) {
    if (p >= s_max_inodes || p == ino || !inode_used(p) || !inode_is_dir(p) ||
        ++steps > s_max_inodes) {
      return false;
    }
  }
  for (uint32_t j = 0; j < ino; ++j) {
    if (inode_used(j) && s_inodes[j].parent == in.parent &&
        names_equal(s_inodes[j].name, in.name)) {
      return false;
    }
  }
  return true;
}

// Reads the metadata into the caches, formatting first if the disk does not
// carry a file system we recognise. FS_NOT_MOUNTED if there is no usable
// device, FS_IO_ERROR if it failed, FS_OK otherwise.
int64_t mount(uint64_t capacity_sectors, uint32_t* formatted) {
  *formatted = 0;
  const uint64_t blocks = capacity_sectors / SECTORS_PER_BLOCK;
  if (blocks <= 4) {
    return init::FS_NOT_MOUNTED;
  }
  int64_t st = read_block(SUPER_BLOCK, s_io);
  if (st != init::FS_OK) {
    return st;
  }
  const auto* sb = reinterpret_cast<const Superblock*>(s_io);
  const uint64_t need_bitmap =
      (sb->total_blocks + BITS_PER_BLOCK - 1) / BITS_PER_BLOCK;
  const bool recognised =
      sb->magic == MAGIC && sb->version == VERSION &&
      sb->block_bytes == BLOCK_BYTES && sb->bitmap_block == 1 &&
      sb->bitmap_blocks >= need_bitmap && sb->bitmap_blocks > 0 &&
      sb->inode_block == sb->bitmap_block + sb->bitmap_blocks &&
      sb->inode_table_blocks > 0 &&
      sb->max_inodes == sb->inode_table_blocks * INODES_PER_BLOCK &&
      sb->data_start == sb->inode_block + sb->inode_table_blocks &&
      sb->total_blocks > sb->data_start && sb->total_blocks <= blocks;
  if (recognised) {
    s_total_blocks = sb->total_blocks;
    s_bitmap_block = sb->bitmap_block;
    s_bitmap_blocks = sb->bitmap_blocks;
    s_inode_block = sb->inode_block;
    s_inode_table_blocks = sb->inode_table_blocks;
    s_max_inodes = sb->max_inodes;
    s_data_start = sb->data_start;
    if (!alloc_metadata_tables()) {
      return init::FS_NO_MEMORY;
    }
    for (uint32_t k = 0; k < s_bitmap_blocks && st == init::FS_OK; ++k) {
      st = read_block(s_bitmap_block + k, s_bitmap + k * BLOCK_BYTES);
    }
    for (uint32_t k = 0; k < s_inode_table_blocks && st == init::FS_OK; ++k) {
      st = read_block(s_inode_block + k, &s_inodes[k * INODES_PER_BLOCK]);
    }
    if (st != init::FS_OK) {
      return st;
    }
  } else {
    default_geometry(blocks);
    if (s_total_blocks <= s_data_start) {
      return init::FS_NOT_MOUNTED;
    }
    if (!alloc_metadata_tables()) {
      return init::FS_NO_MEMORY;
    }
    st = format();
    if (st != init::FS_OK) {
      return st;
    }
    *formatted = 1;
  }
  for (uint64_t b = 0; b < s_data_start; ++b) {
    bit_set(b);  // never hand out the metadata blocks, whatever the bitmap says
  }
  // Dropping an inode can orphan the entries of a directory it was, so go
  // round until a pass drops nothing.
  uint32_t dropped = 0;
  for (bool again = true; again;) {
    again = false;
    for (uint32_t i = 0; i < s_max_inodes; ++i) {
      if (inode_used(i) && !inode_sane(i)) {
        zero_bytes(&s_inodes[i], sizeof(Inode));
        dropped += 1;
        again = true;
      }
    }
  }
  if (dropped != 0) {
    out_dec("[fs]       WARNING: dropped ", dropped,
            " inconsistent inode(s) from the table\n");
  }
  return init::FS_OK;
}

}  // namespace

// --- Entry points ------------------------------------------------------------------------------

extern "C" void fs_quota_derive_entry(Capability arg) {
  auto* req = open_request<init::FsDeriveRequest>(arg);
  if (req == nullptr) {
    return;
  }
  req->out_quota = nullptr;
  req->out_admin = nullptr;
  if (!s_mounted) {
    req->status = init::FS_NOT_MOUNTED;
    return;
  }
  BusyScope busy;
  if (!busy.taken) {
    req->status = init::FS_BUSY;
    return;
  }
  const QuotaRef parent = open_quota(req->parent);
  if (parent.node == nullptr) {
    req->status = init::FS_INVALID_QUOTA;
    return;
  }
  if (!parent.admin) {
    req->status = init::FS_PERMISSION;
    return;
  }
  if (!sealing::is_sealed_as(OType::QuotaVm, req->node_funding) ||
      req->limit_bytes > ~0ULL - (BLOCK_BYTES - 1) ||
      (req->flags & ~init::FS_DERIVE_ADOPT) != 0) {
    req->status = init::FS_BAD_REQUEST;
    return;
  }
  // The child's root: a directory under the parent's own ("" being the
  // parent's own).
  Walk w;
  const int64_t st = walk(parent.node->root_dir, req->path, &w);
  if (st != init::FS_OK) {
    req->status = st;
    return;
  }
  if (!w.found) {
    req->status = init::FS_NOT_FOUND;
    return;
  }
  if (w.leaf[0] != '\0' && !inode_is_dir(w.ino)) {
    req->status = init::FS_NOT_DIR;
    return;
  }
  // Space is handed out in whole blocks.
  const uint64_t limit_bytes =
      (req->limit_bytes + BLOCK_BYTES - 1) & ~(BLOCK_BYTES - 1);
  // Adoption: what the parent owns at or under the child's root becomes the
  // child's, charges included, so it has to fit the child's limits. Counted
  // first, moved last, so that nothing is half done on any failure.
  const bool adopt = (req->flags & init::FS_DERIVE_ADOPT) != 0;
  uint64_t adopt_bytes = 0;
  uint32_t adopt_inodes = 0;
  if (adopt) {
    for (uint32_t i = 0; i < s_max_inodes; ++i) {
      if (inode_used(i) && s_owner[i] == parent.node && under_dir(i, w.ino)) {
        adopt_bytes += charged_blocks_for(s_inodes[i].nblocks) * BLOCK_BYTES;
        adopt_inodes += 1;
      }
    }
    if (adopt_bytes > limit_bytes || adopt_inodes > req->limit_inodes) {
      req->status = init::FS_QUOTA;
      return;
    }
  }
  // The child's limits come out of what the parent has left -- counting what
  // it is about to adopt, which leaves the parent's use as the limits enter
  // its delegation: a parent with nothing to spare can still hand down, whole,
  // a directory it has spent everything on.
  if (limit_bytes > avail_bytes(parent.node) + adopt_bytes ||
      req->limit_inodes > avail_inodes(parent.node) + adopt_inodes) {
    req->status = init::FS_QUOTA;
    return;
  }
  QuotaDisk* n = alloc_node(req->node_funding, parent.node);
  if (n == nullptr) {
    req->status = init::FS_NO_MEMORY;
    return;
  }
  n->root_dir = w.ino;
  n->limit_bytes = limit_bytes;
  n->limit_inodes = req->limit_inodes;
  parent.node->delegated_bytes += limit_bytes;
  parent.node->delegated_inodes += req->limit_inodes;
  // The handle asked for, and the ADMIN one for the creator to keep (one and
  // the same when ADMIN was asked for).
  const bool admin = (req->perms & perms::Store) != 0;
  Capability admin_handle = seal_node(n, true);
  Capability handle = admin ? admin_handle : seal_node(n, false);
  if (!capability_is_valid(handle) || !capability_is_valid(admin_handle)) {
    free_node(n);  // refunds the parent
    req->status = init::FS_NO_MEMORY;
    return;
  }
  if (adopt) {
    for (uint32_t i = 0; i < s_max_inodes; ++i) {
      if (inode_used(i) && s_owner[i] == parent.node && under_dir(i, w.ino)) {
        s_owner[i] = n;
      }
    }
    parent.node->used_bytes -= adopt_bytes;
    parent.node->used_inodes -= adopt_inodes;
    n->used_bytes = adopt_bytes;
    n->used_inodes = adopt_inodes;
  }
  req->out_quota = handle;
  req->out_admin = admin_handle;
  req->status = init::FS_OK;
}

extern "C" void fs_quota_destroy_entry(Capability arg) {
  auto* req = open_request<init::FsDestroyRequest>(arg);
  if (req == nullptr) {
    return;
  }
  if (!s_mounted) {
    req->status = init::FS_NOT_MOUNTED;
    return;
  }
  BusyScope busy;
  if (!busy.taken) {
    req->status = init::FS_BUSY;
    return;
  }
  const QuotaRef q = open_quota(req->quota);
  if (q.node == nullptr) {
    req->status = init::FS_INVALID_QUOTA;
    return;
  }
  if (!q.admin || q.node == s_root) {
    req->status = init::FS_PERMISSION;
    return;
  }
  if (q.node->tree.child_count != 0) {
    req->status = init::FS_BUSY;
    return;
  }
  // Cascade (spec 3.8): the files it owns go, then its directories as they
  // empty out; one still holding other nodes' files, or that another node is
  // rooted at, passes to the parent along with the limits (`free_node`).
  // Only its own children keep a node from going: were another node's root
  // enough, whoever can see a directory of mine could pin my node for good.
  int64_t status = init::FS_OK;
  for (uint32_t i = 0; i < s_max_inodes; ++i) {
    if (inode_used(i) && s_owner[i] == q.node && !inode_is_dir(i)) {
      const int64_t st = unlink_inode(i);
      if (st != init::FS_OK) {
        status = st;
      }
    }
  }
  for (bool again = true; again;) {
    again = false;
    for (uint32_t i = 0; i < s_max_inodes; ++i) {
      if (inode_used(i) && s_owner[i] == q.node && dir_empty(i) &&
          !node_rooted_at(i, q.node)) {
        const int64_t st = unlink_inode(i);
        if (st != init::FS_OK) {
          status = st;
        }
        again = true;
      }
    }
  }
  QuotaDisk* parent = q.node->tree.parent;
  for (uint32_t i = 0; i < s_max_inodes; ++i) {
    if (inode_used(i) && s_owner[i] == q.node) {
      s_owner[i] = parent;
      parent->used_inodes += 1;
    }
  }
  free_node(q.node);  // and the parent gets the limits back
  req->status = status;
}

extern "C" void fs_quota_query_entry(Capability arg) {
  auto* req = open_request<init::FsQueryRequest>(arg);
  if (req == nullptr) {
    return;
  }
  req->limit_bytes = 0;
  req->used_bytes = 0;
  req->delegated_bytes = 0;
  req->limit_inodes = 0;
  req->used_inodes = 0;
  req->delegated_inodes = 0;
  if (!s_mounted) {
    req->status = init::FS_NOT_MOUNTED;
    return;
  }
  const QuotaRef q = open_quota(req->quota);
  if (q.node == nullptr) {
    req->status = init::FS_INVALID_QUOTA;
    return;
  }
  req->limit_bytes = q.node->limit_bytes;
  req->used_bytes = q.node->used_bytes;
  req->delegated_bytes = q.node->delegated_bytes;
  req->limit_inodes = q.node->limit_inodes;
  req->used_inodes = q.node->used_inodes;
  req->delegated_inodes = q.node->delegated_inodes;
  req->status = init::FS_OK;
}

extern "C" void fs_create_entry(Capability arg) {
  auto* req = open_request<init::FsOpenRequest>(arg);
  if (req == nullptr) {
    return;
  }
  req->out_file = nullptr;
  req->out_size = 0;  // a new file is empty
  if (!s_mounted) {
    req->status = init::FS_NOT_MOUNTED;
    return;
  }
  BusyScope busy;
  if (!busy.taken) {
    req->status = init::FS_BUSY;
    return;
  }
  const QuotaRef q = open_quota(req->quota);
  if (q.node == nullptr) {
    req->status = init::FS_INVALID_QUOTA;
    return;
  }
  if ((req->perms & perms::Load) == 0) {
    req->status = init::FS_BAD_REQUEST;
    return;
  }
  if (!q.admin) {
    req->status = init::FS_PERMISSION;
    return;
  }
  Walk w;
  const int64_t st = walk(q.node->root_dir, req->path, &w);
  if (st != init::FS_OK) {
    req->status = st;
    return;
  }
  if (w.leaf[0] == '\0') {
    req->status = init::FS_BAD_REQUEST;  // "" is the root directory itself
    return;
  }
  if (w.found) {
    req->status = init::FS_EXISTS;
    return;
  }
  if (avail_inodes(q.node) == 0) {
    req->status = init::FS_QUOTA;
    return;
  }
  OpenFile* f = alloc_file(q.node);
  if (f == nullptr) {
    req->status = init::FS_NO_MEMORY;
    return;
  }
  const int64_t ino = new_inode(q.node, w.dir, w.leaf, 0);
  if (ino < 0) {
    req->status = ino;
    return;
  }
  f->inode = static_cast<uint32_t>(ino);
  f->writable = (req->perms & perms::Store) != 0 ? 1 : 0;
  f->in_use = 1;
  Capability handle = seal_file(f);
  if (!capability_is_valid(handle)) {
    unlink_inode(static_cast<uint32_t>(ino));  // releases the slot too
    req->status = init::FS_NO_MEMORY;
    return;
  }
  req->out_file = handle;
  req->status = init::FS_OK;
}

extern "C" void fs_mkdir_entry(Capability arg) {
  auto* req = open_request<init::FsPathRequest>(arg);
  if (req == nullptr) {
    return;
  }
  if (!s_mounted) {
    req->status = init::FS_NOT_MOUNTED;
    return;
  }
  BusyScope busy;
  if (!busy.taken) {
    req->status = init::FS_BUSY;
    return;
  }
  const QuotaRef q = open_quota(req->quota);
  if (q.node == nullptr) {
    req->status = init::FS_INVALID_QUOTA;
    return;
  }
  if (!q.admin) {
    req->status = init::FS_PERMISSION;
    return;
  }
  Walk w;
  const int64_t st = walk(q.node->root_dir, req->path, &w);
  if (st != init::FS_OK) {
    req->status = st;
    return;
  }
  if (w.leaf[0] == '\0') {
    req->status = init::FS_BAD_REQUEST;
    return;
  }
  if (w.found) {
    req->status = init::FS_EXISTS;
    return;
  }
  if (avail_inodes(q.node) == 0) {
    req->status = init::FS_QUOTA;
    return;
  }
  const int64_t ino = new_inode(q.node, w.dir, w.leaf, INODE_DIR);
  req->status = ino < 0 ? ino : init::FS_OK;
}

extern "C" void fs_open_entry(Capability arg) {
  auto* req = open_request<init::FsOpenRequest>(arg);
  if (req == nullptr) {
    return;
  }
  req->out_file = nullptr;
  req->out_size = 0;
  if (!s_mounted) {
    req->status = init::FS_NOT_MOUNTED;
    return;
  }
  BusyScope busy;
  if (!busy.taken) {
    req->status = init::FS_BUSY;
    return;
  }
  const QuotaRef q = open_quota(req->quota);
  if (q.node == nullptr) {
    req->status = init::FS_INVALID_QUOTA;
    return;
  }
  if ((req->perms & perms::Load) == 0) {
    req->status = init::FS_BAD_REQUEST;
    return;
  }
  Walk w;
  const int64_t st = walk(q.node->root_dir, req->path, &w);
  if (st != init::FS_OK) {
    req->status = st;
    return;
  }
  if (w.leaf[0] == '\0') {
    req->status = init::FS_IS_DIR;
    return;
  }
  if (!w.found) {
    req->status = init::FS_NOT_FOUND;
    return;
  }
  if (inode_is_dir(w.ino)) {
    req->status = init::FS_IS_DIR;
    return;
  }
  // Under the handle's root, so there to read; the handle's own (or a
  // descendant's) and ADMIN, so there to write -- if writing was asked for.
  const bool owned = is_within(q.node, s_owner[w.ino]);
  const bool wants_write = (req->perms & perms::Store) != 0;
  OpenFile* f = alloc_file(q.node);
  if (f == nullptr) {
    req->status = init::FS_NO_MEMORY;
    return;
  }
  f->inode = w.ino;
  f->writable = (wants_write && q.admin && owned) ? 1 : 0;
  f->in_use = 1;
  Capability handle = seal_file(f);
  if (!capability_is_valid(handle)) {
    release_file(f);
    req->status = init::FS_NO_MEMORY;
    return;
  }
  req->out_file = handle;
  req->out_size = s_inodes[w.ino].size;
  req->status = init::FS_OK;
}

extern "C" void fs_close_entry(Capability arg) {
  auto* req = open_request<init::FsCloseRequest>(arg);
  if (req == nullptr) {
    return;
  }
  if (!s_mounted) {
    req->status = init::FS_NOT_MOUNTED;
    return;
  }
  OpenFile* f = open_file(req->file);
  if (f == nullptr) {
    req->status = init::FS_INVALID_FILE;
    return;
  }
  release_file(f);
  req->status = init::FS_OK;
}

extern "C" void fs_read_entry(Capability arg) {
  auto* req = open_request<init::FsIoRequest>(arg);
  if (req == nullptr) {
    return;
  }
  req->out_count = 0;
  if (!s_mounted) {
    req->status = init::FS_NOT_MOUNTED;
    return;
  }
  BusyScope busy;
  if (!busy.taken) {
    req->status = init::FS_BUSY;
    return;
  }
  OpenFile* f = open_file(req->file);
  if (f == nullptr) {
    req->status = init::FS_INVALID_FILE;
    return;
  }
  const Inode& in = s_inodes[f->inode];
  if (req->length == 0 || req->offset >= in.size) {
    req->status = init::FS_OK;  // nothing to read past the end
    return;
  }
  uint64_t n = in.size - req->offset;
  if (n > req->length) {
    n = req->length;
  }
  if (!buffer_ok(req->buf, perms::Store, n)) {
    req->status = init::FS_BAD_REQUEST;
    return;
  }
  auto* dst = reinterpret_cast<uint8_t*>(req->buf);
  uint64_t done = 0;
  int64_t status = init::FS_OK;
  while (done < n) {
    const uint64_t pos = req->offset + done;
    const uint32_t bi = static_cast<uint32_t>(pos / BLOCK_BYTES);
    const uint64_t within = pos % BLOCK_BYTES;
    uint64_t chunk = BLOCK_BYTES - within;
    if (chunk > n - done) {
      chunk = n - done;
    }
    uint32_t blk = 0;
    status = inode_block_at(in, bi, &blk);
    if (status != init::FS_OK) {
      break;
    }
    status = read_block(blk, s_io);
    if (status != init::FS_OK) {
      break;
    }
    copy_bytes(dst + done, s_io + within, chunk);
    done += chunk;
  }
  req->out_count = done;
  req->status = status;
}

extern "C" void fs_write_entry(Capability arg) {
  auto* req = open_request<init::FsIoRequest>(arg);
  if (req == nullptr) {
    return;
  }
  req->out_count = 0;
  if (!s_mounted) {
    req->status = init::FS_NOT_MOUNTED;
    return;
  }
  BusyScope busy;
  if (!busy.taken) {
    req->status = init::FS_BUSY;
    return;
  }
  OpenFile* f = open_file(req->file);
  if (f == nullptr) {
    req->status = init::FS_INVALID_FILE;
    return;
  }
  if (f->writable == 0) {
    req->status = init::FS_PERMISSION;
    return;
  }
  if (req->length == 0) {
    req->status = init::FS_OK;
    return;
  }
  if (req->offset > init::FS_MAX_FILE_BYTES ||
      req->length > init::FS_MAX_FILE_BYTES - req->offset) {
    req->status = init::FS_TOO_LARGE;
    return;
  }
  if (!buffer_ok(req->buf, perms::Load, req->length)) {
    req->status = init::FS_BAD_REQUEST;
    return;
  }
  Inode& in = s_inodes[f->inode];
  QuotaDisk* owner = s_owner[f->inode];
  const uint64_t end = req->offset + req->length;

  // 1. Grow first, charging the owner (including the indirect block if the
  //    file crosses DIRECT_BLOCKS): FS_QUOTA / FS_DISK_FULL leaves the file
  //    untouched.
  const uint32_t old_nblocks = in.nblocks;
  const uint32_t need = static_cast<uint32_t>((end + BLOCK_BYTES - 1) / BLOCK_BYTES);
  if (need > old_nblocks) {
    const uint64_t old_charged = charged_blocks_for(old_nblocks);
    const uint64_t new_charged = charged_blocks_for(need);
    const uint64_t cost = (new_charged - old_charged) * BLOCK_BYTES;
    if (owner == nullptr || cost > avail_bytes(owner)) {
      req->status = init::FS_QUOTA;
      return;
    }
    const bool need_new_indirect =
        (old_nblocks <= DIRECT_BLOCKS && need > DIRECT_BLOCKS);
    if (!need_new_indirect && need > DIRECT_BLOCKS) {
      const int64_t st_ind = load_indirect(in.indirect);
      if (st_ind != init::FS_OK) {
        req->status = st_ind;
        return;
      }
    } else if (need_new_indirect) {
      zero_bytes(s_indirect, sizeof(s_indirect));
      s_indirect_blk = 0;
    }

    uint64_t cursor = s_data_start;
    uint32_t new_indirect_blk = in.indirect;
    bool ok = true;
    if (need_new_indirect) {
      ok = claim_one_block(&cursor, &new_indirect_blk);
    }
    for (uint32_t bi = old_nblocks; ok && bi < need; ++bi) {
      uint32_t b = 0;
      ok = claim_one_block(&cursor, &b);
      if (ok) {
        if (bi < DIRECT_BLOCKS) {
          in.blocks[bi] = b;
        } else {
          s_indirect[bi - DIRECT_BLOCKS] = b;
        }
      } else {
        // Roll back any data blocks already claimed in this call.
        for (uint32_t r = old_nblocks; r < bi; ++r) {
          const uint32_t rb =
              (r < DIRECT_BLOCKS) ? in.blocks[r] : s_indirect[r - DIRECT_BLOCKS];
          bit_clear(rb);
          if (r < DIRECT_BLOCKS) {
            in.blocks[r] = 0;
          } else {
            s_indirect[r - DIRECT_BLOCKS] = 0;
          }
        }
        if (need_new_indirect && new_indirect_blk != 0) {
          bit_clear(new_indirect_blk);
        }
        req->status = init::FS_DISK_FULL;
        return;
      }
    }

    // Zero-fill newly claimed data blocks so holes read as zeros.
    zero_bytes(s_io, BLOCK_BYTES);
    int64_t st = init::FS_OK;
    for (uint32_t bi = old_nblocks; bi < need && st == init::FS_OK; ++bi) {
      const uint32_t b =
          (bi < DIRECT_BLOCKS) ? in.blocks[bi] : s_indirect[bi - DIRECT_BLOCKS];
      st = write_block(b, s_io);
    }
    if (st == init::FS_OK && need > DIRECT_BLOCKS) {
      st = save_indirect(new_indirect_blk);
    }
    if (st == init::FS_OK) {
      st = write_bitmap();
    }
    if (st != init::FS_OK) {
      for (uint32_t r = old_nblocks; r < need; ++r) {
        const uint32_t rb =
            (r < DIRECT_BLOCKS) ? in.blocks[r] : s_indirect[r - DIRECT_BLOCKS];
        bit_clear(rb);
        if (r < DIRECT_BLOCKS) {
          in.blocks[r] = 0;
        } else {
          s_indirect[r - DIRECT_BLOCKS] = 0;
        }
      }
      if (need_new_indirect && new_indirect_blk != 0) {
        bit_clear(new_indirect_blk);
        s_indirect_blk = 0;
      }
      req->status = st;
      return;
    }
    in.indirect = new_indirect_blk;
    in.nblocks = need;
    owner->used_bytes += cost;
  }

  // 2. The data, one block at a time, read-modify-write for partial blocks.
  const auto* src = reinterpret_cast<const uint8_t*>(req->buf);
  uint64_t done = 0;
  int64_t status = init::FS_OK;
  while (done < req->length) {
    const uint64_t pos = req->offset + done;
    const uint32_t bi = static_cast<uint32_t>(pos / BLOCK_BYTES);
    const uint64_t within = pos % BLOCK_BYTES;
    uint64_t chunk = BLOCK_BYTES - within;
    if (chunk > req->length - done) {
      chunk = req->length - done;
    }
    uint32_t blk = 0;
    status = inode_block_at(in, bi, &blk);
    if (status != init::FS_OK) {
      break;
    }
    if (chunk < BLOCK_BYTES) {
      status = read_block(blk, s_io);
      if (status != init::FS_OK) {
        break;
      }
    }
    copy_bytes(s_io + within, src + done, chunk);
    status = write_block(blk, s_io);
    if (status != init::FS_OK) {
      break;
    }
    done += chunk;
  }

  // 3. The inode: new size (as far as the data got) and any new blocks.
  const uint64_t reached = req->offset + done;
  if (reached > in.size) {
    in.size = reached;
  }
  const int64_t st_inode = write_inode_block(f->inode);
  req->out_count = done;
  req->status = status != init::FS_OK ? status : st_inode;
}

extern "C" void fs_unlink_entry(Capability arg) {
  auto* req = open_request<init::FsPathRequest>(arg);
  if (req == nullptr) {
    return;
  }
  if (!s_mounted) {
    req->status = init::FS_NOT_MOUNTED;
    return;
  }
  BusyScope busy;
  if (!busy.taken) {
    req->status = init::FS_BUSY;
    return;
  }
  const QuotaRef q = open_quota(req->quota);
  if (q.node == nullptr) {
    req->status = init::FS_INVALID_QUOTA;
    return;
  }
  if (!q.admin) {
    req->status = init::FS_PERMISSION;
    return;
  }
  Walk w;
  const int64_t st = walk(q.node->root_dir, req->path, &w);
  if (st != init::FS_OK) {
    req->status = st;
    return;
  }
  if (w.leaf[0] == '\0') {
    req->status = init::FS_BAD_REQUEST;  // the root directory itself
    return;
  }
  if (!w.found) {
    req->status = init::FS_NOT_FOUND;
    return;
  }
  // In view, but another node's: there to be seen, not this handle's to
  // remove.
  if (!is_within(q.node, s_owner[w.ino])) {
    req->status = init::FS_PERMISSION;
    return;
  }
  if (inode_is_dir(w.ino)) {
    if (!dir_empty(w.ino)) {
      req->status = init::FS_NOT_EMPTY;
      return;
    }
    if (node_rooted_at(w.ino, nullptr)) {
      req->status = init::FS_BUSY;
      return;
    }
  }
  req->status = unlink_inode(w.ino);
}

extern "C" void fs_list_entry(Capability arg) {
  auto* req = open_request<init::FsListRequest>(arg);
  if (req == nullptr) {
    return;
  }
  req->out_count = 0;
  req->out_total = 0;
  if (!s_mounted) {
    req->status = init::FS_NOT_MOUNTED;
    return;
  }
  const QuotaRef q = open_quota(req->quota);
  if (q.node == nullptr) {
    req->status = init::FS_INVALID_QUOTA;
    return;
  }
  Walk w;
  const int64_t st = walk(q.node->root_dir, req->path, &w);
  if (st != init::FS_OK) {
    req->status = st;
    return;
  }
  if (!w.found) {
    req->status = init::FS_NOT_FOUND;
    return;
  }
  if (w.leaf[0] != '\0' && !inode_is_dir(w.ino)) {
    req->status = init::FS_NOT_DIR;
    return;
  }
  const uint32_t dir = w.ino;
  uint64_t capacity = req->capacity;
  if (capacity > s_max_inodes) {
    capacity = s_max_inodes;  // never more entries than that
  }
  if (capacity != 0 &&
      !buffer_ok(req->entries, perms::Store,
                 capacity * sizeof(init::FsDirEntry))) {
    req->status = init::FS_BAD_REQUEST;
    return;
  }
  auto* entries = reinterpret_cast<init::FsDirEntry*>(req->entries);
  uint64_t count = 0;
  uint64_t total = 0;
  for (uint32_t i = 0; i < s_max_inodes; ++i) {
    const Inode& in = s_inodes[i];
    if ((in.flags & INODE_USED) == 0 || in.parent != dir) {
      continue;
    }
    total += 1;
    if (count < capacity) {
      init::FsDirEntry& e = entries[count];
      copy_name(e.name, in.name);
      e.size = in.size;
      e.inode = i;
      e.owner = (s_owner[i] == q.node)          ? init::FS_OWNER_SELF
                : is_within(q.node, s_owner[i]) ? init::FS_OWNER_CHILD
                                                : init::FS_OWNER_OTHER;
      e.is_dir = (in.flags & INODE_DIR) != 0 ? 1 : 0;
      e.pad_[0] = 0;
      e.pad_[1] = 0;
      e.pad_[2] = 0;
      count += 1;
    }
  }
  req->out_count = count;
  req->out_total = total;
  req->status = init::FS_OK;
}

extern "C" void compartment_main(Capability arg) {
  Capability* rw = rw_table();
  s_gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  s_uart = rw[SLOT_UART_SENTRY];

  // One-shot handshake: the first call with a writable argument of exactly
  // `FsInterface`'s size is `init` bringing us up. Anything later is a
  // status enquiry.
  if (s_first_call_done) {
    if (!s_mounted) {
      out("[fs]       not mounted\n");
      return;
    }
    out_dec("[fs]       mounted: ", s_root->used_bytes / 1024, " KiB used of ");
    out_dec("", s_root->limit_bytes / 1024, " KiB, ");
    out_dec("", s_root->used_inodes, " inode(s) in use\n");
    return;
  }
  s_first_call_done = true;

  s_self_comp = rw[compartment::SLOT_SELF];
  s_vm_quota = rw[compartment::SLOT_VM_QUOTA];
  Capability gate_type_mint = rw[SLOT_SYS_TYPE_MINT];
  Capability gate_sentry = rw[SLOT_SYS_SENTRY];
  s_gate_alloc = rw[SLOT_SYS_VM_ALLOC];
  s_gate_dealloc = rw[SLOT_SYS_VM_DEALLOC];
  s_gate_seal = rw[SLOT_SYS_SEAL];
  s_gate_unseal = rw[SLOT_SYS_UNSEAL];
  s_blk_read = rw[SLOT_BLK_READ];
  s_blk_write = rw[SLOT_BLK_WRITE];

  if (!sealing::is_sealed_as(OType::Compartment, s_self_comp) ||
      !sealing::is_sealed_as(OType::QuotaVm, s_vm_quota)) {
    out("[fs]       missing seeds; file system disabled\n");
    return;
  }
  if (!capability_is_valid(arg) || sealing::is_sealed(arg) ||
      !capability_has_perms(arg, perms::Load | perms::Store) ||
      capability_get_length(arg) != sizeof(init::FsInterface)) {
    out("[fs]       no FsInterface handshake; file system disabled\n");
    return;
  }
  auto* iface = reinterpret_cast<init::FsInterface*>(arg);
  iface->root_quota = nullptr;
  iface->quota_derive = nullptr;
  iface->quota_destroy = nullptr;
  iface->quota_query = nullptr;
  iface->create = nullptr;
  iface->mkdir = nullptr;
  iface->open = nullptr;
  iface->close = nullptr;
  iface->read = nullptr;
  iface->write = nullptr;
  iface->unlink = nullptr;
  iface->list = nullptr;
  iface->total_bytes = 0;
  iface->used_bytes = 0;
  iface->total_inodes = 0;
  iface->used_inodes = 0;
  iface->formatted = 0;
  iface->status = init::FS_NOT_MOUNTED;

  // 1. Private sealing types: one for quota handles, one for file handles
  //    (spec 2.7). Both records live in our own `.bss`.
  using FnTypeMint = decltype(&sys_type_mint);
  s_quota_key = syscall::call<FnTypeMint>(
      s_gate_invoke, gate_type_mint,
      reinterpret_cast<Capability>(&s_quota_type_record));
  s_file_key = syscall::call<FnTypeMint>(
      s_gate_invoke, gate_type_mint,
      reinterpret_cast<Capability>(&s_file_type_record));
  if (!sealing::is_sealed_as(OType::TypeKey, s_quota_key) ||
      !sealing::is_sealed_as(OType::TypeKey, s_file_key)) {
    out("[fs]       type_mint failed; file system disabled\n");
    return;
  }
  rw[SLOT_QUOTA_TYPE_KEY] = s_quota_key;
  rw[SLOT_FILE_TYPE_KEY] = s_file_key;

  // 2. Entry points, handed back whether or not the mount below succeeds: a
  //    client that reaches them gets FS_NOT_MOUNTED, not nothing. There is no
  //    naming service yet to publish them with (`naming` is loaded from this
  //    very disk); `init` publishes them as "fs.*" once there is.
  auto entry = [&](const void* fn) {
    return mint_entry(s_gate_invoke, gate_sentry, s_self_comp, fn);
  };
  iface->quota_derive = entry(reinterpret_cast<const void*>(&fs_quota_derive_entry));
  iface->quota_destroy = entry(reinterpret_cast<const void*>(&fs_quota_destroy_entry));
  iface->quota_query = entry(reinterpret_cast<const void*>(&fs_quota_query_entry));
  iface->create = entry(reinterpret_cast<const void*>(&fs_create_entry));
  iface->mkdir = entry(reinterpret_cast<const void*>(&fs_mkdir_entry));
  iface->open = entry(reinterpret_cast<const void*>(&fs_open_entry));
  iface->close = entry(reinterpret_cast<const void*>(&fs_close_entry));
  iface->read = entry(reinterpret_cast<const void*>(&fs_read_entry));
  iface->write = entry(reinterpret_cast<const void*>(&fs_write_entry));
  iface->unlink = entry(reinterpret_cast<const void*>(&fs_unlink_entry));
  iface->list = entry(reinterpret_cast<const void*>(&fs_list_entry));

  // 3. The disk.
  if (iface->capacity_sectors == 0 || !capability_is_valid(s_blk_read) ||
      !capability_is_valid(s_blk_write)) {
    out("[fs]       no block device; file system not mounted\n");
    return;
  }
  uint32_t formatted = 0;
  const int64_t st = mount(iface->capacity_sectors, &formatted);
  if (st != init::FS_OK) {
    out_dec("[fs]       mount failed, status -", static_cast<uint64_t>(-st),
            "; file system not mounted\n");
    iface->status = st;
    return;
  }

  // 4. Root node: the whole data area, rooted at `/`, funded from our own VM
  //    quota. Every inode already on the disk belongs to it (file comment,
  //    Ownership).
  s_root = alloc_node(s_vm_quota, nullptr);
  if (s_root == nullptr) {
    out("[fs]       could not allocate the root quota node\n");
    iface->status = init::FS_NO_MEMORY;
    return;
  }
  s_root->limit_bytes = (s_total_blocks - s_data_start) * BLOCK_BYTES;
  s_root->limit_inodes = s_max_inodes;
  for (uint32_t i = 0; i < s_max_inodes; ++i) {
    s_owner[i] = nullptr;
    if (inode_used(i)) {
      s_owner[i] = s_root;
      s_root->used_bytes +=
          charged_blocks_for(s_inodes[i].nblocks) * BLOCK_BYTES;
      s_root->used_inodes += 1;
    }
  }
  Capability root_handle = seal_node(s_root, true);
  if (!capability_is_valid(root_handle)) {
    out("[fs]       could not seal the root quota handle\n");
    free_node(s_root);
    s_root = nullptr;
    iface->status = init::FS_NO_MEMORY;
    return;
  }
  s_mounted = true;

  iface->root_quota = root_handle;
  iface->total_bytes = s_root->limit_bytes;
  iface->used_bytes = s_root->used_bytes;
  iface->total_inodes = s_max_inodes;
  iface->used_inodes = s_root->used_inodes;
  iface->formatted = formatted;
  iface->status = init::FS_OK;

  out_dec(formatted ? "[fs]       Formatted and mounted: " : "[fs]       Mounted: ",
          s_root->limit_bytes / 1024, " KiB of data space, ");
  out_dec("", s_root->used_bytes / 1024, " KiB used, ");
  out_dec("", s_root->used_inodes, " of ");
  out_dec("", s_max_inodes, " inode(s)\n");
}

}  // namespace signetos::user
