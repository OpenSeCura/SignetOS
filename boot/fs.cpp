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
 * fs.cpp - SignetOS file system
 *
 * Files, directories and disk quotas are reached only through handles:
 * sealed pointers to records holding an entry and rights (user/abi.hpp).
 * File, directory and quota handles each have their own OType. Each
 * handle is opened through another, paid for by the caller's memory quota,
 * and closed with everything opened through it; a temporary goes with the
 * handle that made it. Rights only shrink; paths only go down, or through a
 * link, which can only take rights away.
 *
 * On disk: a header, the entry table (one 128-byte entry per disk block),
 * data. A directory or quota has no blocks; its children point at it with
 * `parent`. A link names a file or directory, with rights. Entry 0 is `/`,
 * entry 1 the root quota. A file's blocks past its first DIRECT_BLOCKS, and
 * a name too long to fit in its entry, are trees of blocks that grow another
 * level whenever they fill up (TREES), so neither has a limit but the disk.
 * Paths are read from the caller's buffer a name at a time, so they have
 * none either.
 *
 * Each quota keeps what it pays for in `used`. A charge is written before
 * the change it pays for and a refund after it, so a crash can only leave
 * `used` too high. Mount rebuilds the free-block map and `used`.
 *
 * Started before naming: init gets the entry points from the handshake and
 * publishes them. Every entry point holds `s_lock`.
 */

#include "runtime.hpp"

namespace signetos::user {
namespace {

// blk.* are optional: without a disk, fs reports itself unmounted.
#define FS_MANIFEST(X)                               \
  M_QUOTA_VM(X, VM_QUOTA)                            \
  M_OTYPE(X, SEAL_FILE, ::signetos::OType::FsFile)   \
  M_OTYPE(X, SEAL_DIR, ::signetos::OType::FsDir)     \
  M_OTYPE(X, SEAL_QUOTA, ::signetos::OType::FsQuota) \
  M_SYSCALL(X, SYS_VM_ALLOC, vm_allocate)            \
  M_SYSCALL(X, SYS_VM_DEALLOC, vm_deallocate)        \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)  \
  M_SYSCALL(X, SYS_SENTRY, sentry)                   \
  M_SERVICE(X, UART_SENTRY, "uart")                  \
  M_SERVICE_OPT(X, BLK_READ, "blk.read")             \
  M_SERVICE_OPT(X, BLK_WRITE, "blk.write")
// init adds the size of the in-memory tables (init.cpp, step 4).
SIGNETOS_MANIFEST(FS_MANIFEST, 128 * 1024)

// --- On disk ----------------------------------------------------------------

constexpr uint64_t MAGIC = 0x5349474341504653ULL;  // "SIGCAPFS"
constexpr uint64_t VERSION = 2;
constexpr uint64_t BLOCK = init::FS_BLOCK_BYTES;
constexpr uint64_t SECTORS_PER_BLOCK = BLOCK / init::BLK_SECTOR_BYTES;
constexpr uint32_t DIRECT_BLOCKS = 16;                // a file's first blocks
constexpr uint32_t NAME_HEAD = init::FS_NAME_INLINE;  // name bytes in an entry
// A list block (TREES) holds FANOUT block numbers.
constexpr uint32_t FANOUT_BITS = 10;
constexpr uint32_t FANOUT = 1u << FANOUT_BITS;
static_assert(FANOUT * sizeof(uint32_t) == BLOCK);
// Levels of lists enough for as many blocks as a uint32_t counts.
constexpr uint32_t MAX_LEVELS = (32 + FANOUT_BITS - 1) / FANOUT_BITS;
constexpr uint32_t MAX_COUNT = 0xFFFFFFFFu;  // blocks, or bytes of a name

// Block 0. The entry table follows, then data.
struct DiskHeader {
  uint64_t magic;
  uint64_t version;
  uint64_t total_blocks;
};

// Entry flags. DIR, QUOTA, FROZEN and LINK are also FS_ENTRY_*. REMOVING and
// CHANGED are memory only.
constexpr uint32_t IN_USE = 1;
constexpr uint32_t DIR = init::FS_ENTRY_DIR;
constexpr uint32_t QUOTA = init::FS_ENTRY_QUOTA;
constexpr uint32_t FROZEN = init::FS_ENTRY_FROZEN;
constexpr uint32_t LINK = init::FS_ENTRY_LINK;
constexpr uint32_t REMOVING = 1u << 30;
constexpr uint32_t CHANGED = 1u << 31;  // to be written

constexpr uint32_t NO_ENTRY = 0xFFFFFFFFu;
constexpr uint32_t ROOT_DIR = 0;
constexpr uint32_t ROOT_QUOTA = 1;

// A name of `length` bytes. One of up to NAME_HEAD bytes is all in `head`. A
// longer one is all in the tree `tree`, BLOCK bytes to a block, with its
// first NAME_HEAD bytes in `head` as well: most names compared differ there,
// or in length or hash, without a block being read.
struct Name {
  uint32_t length;          // no NUL; 0 for none (`/`, the root quota, a temporary)
  uint32_t hash;            // of all of it (hash_step)
  uint32_t tree;            // a longer name's blocks, or 0
  char head[NAME_HEAD];
};

// A file, directory, quota or link.
struct Entry {
  uint32_t flags;
  uint32_t parent;          // directory; for a quota, its parent quota
  uint32_t payer;           // quota paying for a file, directory or link
  uint32_t generation;      // bumped on free: kills old handles
  union {
    uint64_t size;          // file: bytes
    uint64_t limit;         // quota
  };
  uint32_t block_count;     // file: blocks
  uint32_t tree;            // file: its blocks past DIRECT_BLOCKS, or 0
  Name name;
  union {
    uint32_t blocks[DIRECT_BLOCKS];  // file: its first blocks
    uint64_t used;                   // quota: what it pays for, its quotas included
    struct {
      uint32_t entry;
      uint32_t generation;
      uint32_t rights;
    } target;                        // link: what it names, and with what rights
  };
};
static_assert(sizeof(Entry) == 128);
constexpr uint32_t ENTRIES_PER_BLOCK = static_cast<uint32_t>(BLOCK / sizeof(Entry));

// --- Handles ----------------------------------------------------------------

// A file, directory or quota handle points at one of these. Each is its own
// allocation, paid for by `memory_quota`.
struct Handle {
  Capability self;          // this allocation
  Capability memory_quota;  // the memory quota it goes back to
  Handle* parent;           // the handle it was opened through; null for a root
  Handle* first_child;      // the handles opened through this one
  Handle* next_sibling;     // the next child of `parent`
  uint32_t entry;
  uint32_t generation;
  uint32_t rights;
  uint32_t is_open;
  uint32_t temporary;       // made the temporary it names (fs.create, no dir)
};

// --- State ------------------------------------------------------------------

Capability s_self_comp = nullptr;
Capability s_vm_quota = nullptr;
Capability s_seal_file = nullptr;    // OType::FsFile authority
Capability s_seal_dir = nullptr;     // OType::FsDir authority
Capability s_seal_quota = nullptr;   // OType::FsQuota authority
Capability s_gate_alloc = nullptr;
Capability s_gate_dealloc = nullptr;
Capability s_gate_invoke = nullptr;
Capability s_uart = nullptr;
Capability s_blk_read = nullptr;
Capability s_blk_write = nullptr;

Entry* s_entries = nullptr;     // the whole entry table
uint32_t s_entry_count = 0;
uint8_t* s_block_map = nullptr;  // one bit per block: in use
uint64_t s_total_blocks = 0;
uint64_t s_data_start = 0;
uint64_t s_free_blocks = 0;
uint64_t s_next_block = 0;      // where to look for a free block next

alignas(16) uint8_t s_block_buf[BLOCK];
alignas(16) uint8_t s_name_buf[BLOCK];  // a block of a long name
// The lists of the tree walked last, one per level (TREES).
alignas(16) uint32_t s_list[MAX_LEVELS][FANOUT];
uint32_t s_list_block[MAX_LEVELS];  // the block held at each level, or 0
bool s_list_changed[MAX_LEVELS];    // changed since it was read or written

bool s_mounted = false;
bool s_first_call_done = false;
bool s_second_call_done = false;

uint64_t s_lock = 0;
Capability s_lock_wait = nullptr;  // sched.lock_wait
Capability s_lock_wake = nullptr;  // sched.lock_wake

// --- Small helpers ----------------------------------------------------------

// Returns `expr` if it is not FS_OK.
#define TRY(expr)                        \
  do {                                   \
    const int64_t st_ = (expr);          \
    if (st_ != init::FS_OK) return st_;  \
  } while (false)

void out(const char* msg) { print(s_gate_invoke, s_uart, msg); }
void out_dec(const char* prefix, uint64_t value, const char* suffix) {
  print_dec(s_gate_invoke, s_uart, prefix, value, suffix);
}

void zero_bytes(void* dst, size_t count) {
  auto* bytes = static_cast<uint8_t*>(dst);
  for (size_t i = 0; i < count; ++i) {
    bytes[i] = 0;
  }
}

void copy_bytes(void* dst, const void* src, size_t count) {
  auto* to = static_cast<uint8_t*>(dst);
  const auto* from = static_cast<const uint8_t*>(src);
  for (size_t i = 0; i < count; ++i) {
    to[i] = from[i];
  }
}

// Bytes from `cap`'s address to the end of its bounds.
uint64_t bytes_left(Capability cap) {
  const uint64_t base = capability_get_base(cap);
  const uint64_t end = base + capability_get_length(cap);
  const uint64_t addr = capability_get_address(cap);
  return (addr < base || addr > end) ? 0 : end - addr;
}

bool buffer_ok(Capability buf, uint64_t perms_needed, uint64_t bytes) {
  return capability_is_valid(buf) && !sealing::is_sealed(buf) &&
         capability_has_perms(buf, perms_needed) && bytes_left(buf) >= bytes;
}

// Holds `s_lock` while in scope.
struct LockScope {
  bool taken;
  LockScope() {
    const int64_t status = lock(s_gate_invoke, s_lock_wait, &s_lock);
    if (status == init::SCHED_OWNER_DEAD) {
      out("[fs]       WARNING: a thread ended holding the fs lock; the tables "
          "may be half-updated\n");
    }
    taken = status == init::SCHED_OK || status == init::SCHED_OWNER_DEAD;
  }
  ~LockScope() {
    if (taken) {
      unlock(s_gate_invoke, s_lock_wake, &s_lock);
    }
  }
};

// Held by every entry point.
struct CallGuard {
  LockScope lock;
  int64_t status() const {
    return !lock.taken    ? init::FS_BUSY
           : !s_mounted   ? init::FS_NOT_MOUNTED
                          : init::FS_OK;
  }
};

// --- Names and paths --------------------------------------------------------

// A name is one or more printable characters, no blank or '/', and not "."
// or "..".
bool name_char(char c) { return c > ' ' && c <= '~' && c != '/'; }

bool is_dot_or_dotdot(const char* name, uint64_t length) {
  return name[0] == '.' && (length == 1 || (length == 2 && name[1] == '.'));
}

// A name's hash (FNV-1a): HASH_SEED, then hash_step for each byte.
constexpr uint32_t HASH_SEED = 2166136261u;
uint32_t hash_step(uint32_t hash, char c) {
  return (hash ^ static_cast<uint8_t>(c)) * 16777619u;
}

// A name in a caller's buffer: `length` bytes at `chars`, as they were when
// checked and hashed. The caller can change them since: whatever compares or
// keeps them reads them again, and what is kept is checked again.
struct Text {
  const char* chars = nullptr;
  uint64_t length = 0;
  uint32_t hash = HASH_SEED;
};

// A caller's path: the `length` bytes at `chars` before its NUL. Read where
// it is, as it is followed, so it can be as long as the caller likes.
struct Path {
  const char* chars = nullptr;
  uint64_t length = 0;
};

int64_t read_path(Capability path_cap, Path* path) {
  if (!buffer_ok(path_cap, perms::Load, 1)) {
    return init::FS_BAD_REQUEST;
  }
  const uint64_t max = bytes_left(path_cap);
  const auto* chars = static_cast<const char*>(path_cap);
  for (uint64_t i = 0; i < max; ++i) {
    if (chars[i] == '\0') {
      *path = Path{chars, i};
      return init::FS_OK;
    }
  }
  return init::FS_BAD_REQUEST;
}

// The name at `*at` in `path`, checked and hashed; `*at` moves past it and
// the '/' after it. FS_BAD_REQUEST for a bad name or a trailing '/'.
int64_t next_name(const Path& path, uint64_t* at, Text* name) {
  Text found{path.chars + *at, 0, HASH_SEED};
  uint64_t end = *at;
  for (; end < path.length; ++end) {
    const char c = path.chars[end];
    if (c == '/') {
      break;
    }
    if (!name_char(c)) {
      return init::FS_BAD_REQUEST;
    }
    found.hash = hash_step(found.hash, c);
  }
  found.length = end - *at;
  if (found.length == 0 || is_dot_or_dotdot(found.chars, found.length)) {
    return init::FS_BAD_REQUEST;
  }
  if (found.length > MAX_COUNT) {
    return init::FS_TOO_LARGE;  // more than an entry can record
  }
  if (end < path.length && ++end == path.length) {
    return init::FS_BAD_REQUEST;  // trailing '/'
  }
  *at = end;
  *name = found;
  return init::FS_OK;
}

// --- The disk ---------------------------------------------------------------

// One block to or from the disk. `blk` gets a buffer bounded to the block,
// read-only for a write.
int64_t blk_io(Capability blk_entry, uint64_t block, void* buf, bool write) {
  if (!capability_is_valid(blk_entry)) {
    return init::FS_IO_ERROR;
  }
  Capability bounded =
      capability_set_bounds(reinterpret_cast<Capability>(buf), BLOCK);
  Capability buffer = write ? capability_and_perms(bounded, perms::Load) : bounded;
  const int64_t status = invoke<int64_t>(s_gate_invoke, blk_entry, buffer,
                                         block * SECTORS_PER_BLOCK,
                                         SECTORS_PER_BLOCK);
  return status == init::BLK_OK ? init::FS_OK : init::FS_IO_ERROR;
}

int64_t read_block(uint64_t block, void* buf) {
  return blk_io(s_blk_read, block, buf, false);
}

int64_t write_block(uint64_t block, const void* buf) {
  return blk_io(s_blk_write, block, const_cast<void*>(buf), true);
}

bool block_in_use(uint64_t block) {
  return ((s_block_map[block / 8] >> (block % 8)) & 1) != 0;
}

void set_block_used(uint64_t block, bool used) {
  const auto bit = static_cast<uint8_t>(1u << (block % 8));
  s_block_map[block / 8] = static_cast<uint8_t>(
      used ? s_block_map[block / 8] | bit : s_block_map[block / 8] & ~bit);
}

// The caller has checked `s_free_blocks`.
uint32_t alloc_block() {
  while (block_in_use(s_next_block)) {
    s_next_block =
        s_next_block + 1 < s_total_blocks ? s_next_block + 1 : s_data_start;
  }
  set_block_used(s_next_block, true);
  s_free_blocks -= 1;
  return static_cast<uint32_t>(s_next_block);
}

void free_block(uint32_t block) {
  if (block >= s_data_start && block < s_total_blocks && block_in_use(block)) {
    set_block_used(block, false);
    s_free_blocks += 1;
  }
}

// --- Trees ------------------------------------------------------------------
//
// A file's blocks past DIRECT_BLOCKS, and a long name's blocks, are a tree: a
// root and a count of blocks. A tree of one block is just that block. A
// bigger one hangs from lists of FANOUT block numbers, as many levels of them
// as the count needs (`levels`): level 0 lists blocks, level k lists lists of
// level k-1, and the root is the one list at the top. Block `index` is in
// slot `slot_at(index, k)` of the list on its way down at level k. A tree only
// grows at its end, gaining a level on top when it is full, so the count says
// which slots mean anything; a slot past it is left over, and never read.

// Levels of lists in a tree of `count` blocks.
uint32_t levels(uint32_t count) {
  uint32_t depth = 0;
  for (uint64_t span = 1; span < count; span <<= FANOUT_BITS) {
    ++depth;
  }
  return depth;
}

// Lists in a tree of `count` blocks.
uint64_t list_count(uint32_t count) {
  uint64_t lists = 0;
  const uint32_t depth = levels(count);
  for (uint32_t level = 1; level <= depth; ++level) {
    const uint64_t span = uint64_t{1} << (FANOUT_BITS * level);
    lists += (count + span - 1) / span;
  }
  return lists;
}

uint32_t slot_at(uint32_t index, uint32_t level) {
  return (index >> (FANOUT_BITS * level)) & (FANOUT - 1);
}

// Whether block `index` is the first under its list at `level`.
bool starts_list(uint32_t index, uint32_t level) {
  const uint64_t span = uint64_t{1} << (FANOUT_BITS * (level + 1));
  return (index & (span - 1)) == 0;
}

// Writes the list held at `level` if it changed.
int64_t flush_list(uint32_t level) {
  if (s_list_changed[level]) {
    TRY(write_block(s_list_block[level], s_list[level]));
    s_list_changed[level] = false;
  }
  return init::FS_OK;
}

int64_t flush_lists() {
  for (uint32_t level = 0; level < MAX_LEVELS; ++level) {
    TRY(flush_list(level));
  }
  return init::FS_OK;
}

// Forgets the lists held, changed or not: once their tree is freed, or a
// change to it failed.
void drop_lists() {
  for (uint32_t level = 0; level < MAX_LEVELS; ++level) {
    s_list_block[level] = 0;
    s_list_changed[level] = false;
  }
}

// Holds list `block` at `level`, reading it unless it is held already.
int64_t load_list(uint32_t level, uint32_t block) {
  if (block == 0) {
    return init::FS_IO_ERROR;
  }
  if (block != s_list_block[level]) {
    TRY(flush_list(level));
    s_list_block[level] = 0;
    TRY(read_block(block, s_list[level]));
    s_list_block[level] = block;
  }
  return init::FS_OK;
}

// Holds `block`, just allocated, at `level` as an empty list.
int64_t start_list(uint32_t level, uint32_t block) {
  TRY(flush_list(level));
  zero_bytes(s_list[level], BLOCK);
  s_list_block[level] = block;
  s_list_changed[level] = true;
  return init::FS_OK;
}

// Block `index` of the tree `root` of `count` blocks; 0 on error.
uint32_t tree_block(uint32_t root, uint32_t count, uint32_t index) {
  uint32_t block = root;
  for (uint32_t level = levels(count); level-- > 0;) {
    if (load_list(level, block) != init::FS_OK) {
      return 0;
    }
    block = s_list[level][slot_at(index, level)];
  }
  return block;
}

// Puts `block` at the end of the tree `*root` of `*count` blocks, allocating
// the lists that takes: the caller has checked there are blocks for them
// (`list_count`). The lists changed are written by `flush_lists`.
int64_t tree_append(uint32_t* root, uint32_t* count, uint32_t block) {
  const uint32_t index = *count;
  if (index == 0) {
    *root = block;
    *count = 1;
    return init::FS_OK;
  }
  uint32_t depth = levels(index);
  if (levels(index + 1) > depth) {  // full: a new root, over the old one
    const uint32_t old_root = *root;
    *root = alloc_block();
    TRY(start_list(depth, *root));
    s_list[depth][0] = old_root;
    depth += 1;
  }
  uint32_t list = *root;
  for (uint32_t level = depth - 1; level > 0; --level) {
    TRY(load_list(level, list));
    uint32_t& slot = s_list[level][slot_at(index, level)];
    if (starts_list(index, level - 1)) {  // the list below is new
      slot = alloc_block();
      s_list_changed[level] = true;
      TRY(start_list(level - 1, slot));
    }
    list = slot;
  }
  TRY(load_list(0, list));
  s_list[0][slot_at(index, 0)] = block;
  s_list_changed[0] = true;
  *count = index + 1;
  return init::FS_OK;
}

// Frees the tree `root` of `count` blocks, lists and all. What hangs from a
// list that cannot be read stays taken until the next mount.
void tree_free(uint32_t root, uint32_t count) {
  const uint32_t depth = levels(count);
  for (uint32_t index = 0; index < count; ++index) {
    uint32_t block = root;
    for (uint32_t level = depth; block != 0 && level-- > 0;) {
      if (starts_list(index, level)) {
        free_block(block);  // a list, reached here first
      }
      block = load_list(level, block) == init::FS_OK
                  ? s_list[level][slot_at(index, level)]
                  : 0;
    }
    free_block(block);
  }
  drop_lists();
}

// --- Names on disk ----------------------------------------------------------

// A name compared is not the same (positive, so TRY passes it on).
constexpr int64_t DIFFERENT = 1;

// Blocks a name of `length` bytes takes, lists included; none if it fits in
// its entry.
uint32_t name_blocks(uint32_t length) {
  return length <= NAME_HEAD
             ? 0
             : static_cast<uint32_t>((uint64_t{length} + BLOCK - 1) / BLOCK);
}

uint64_t name_cost(uint32_t length) {
  const uint32_t blocks = name_blocks(length);
  return blocks + list_count(blocks);
}

// Calls `use(chunk, start, n)` for each block of long name `name` in turn,
// read into `buf`: its `n` bytes, from byte `start` of the name. Stops at an
// error, or at anything `use` returns that is not FS_OK.
template <typename Use>
int64_t each_name_block(const Name& name, uint8_t* buf, Use use) {
  const uint32_t count = name_blocks(name.length);
  for (uint32_t k = 0; k < count; ++k) {
    const uint32_t block = tree_block(name.tree, count, k);
    if (block == 0) {
      return init::FS_IO_ERROR;
    }
    TRY(read_block(block, buf));
    const uint64_t start = uint64_t{k} * BLOCK;
    const uint64_t n = name.length - start < BLOCK ? name.length - start : BLOCK;
    TRY(use(reinterpret_cast<const char*>(buf), start, n));
  }
  return init::FS_OK;
}

uint32_t head_bytes(uint32_t length) {
  return length < NAME_HEAD ? length : NAME_HEAD;
}

// FS_OK if `name` is `text`, DIFFERENT if not, or an I/O error.
int64_t compare_text(const Name& name, const Text& text) {
  if (name.length != text.length || name.hash != text.hash) {
    return DIFFERENT;
  }
  for (uint32_t i = 0; i < head_bytes(name.length); ++i) {
    if (name.head[i] != text.chars[i]) {
      return DIFFERENT;
    }
  }
  return each_name_block(
      name, s_name_buf, [&](const char* chunk, uint64_t start, uint64_t n) {
        for (uint64_t i = 0; i < n; ++i) {
          if (chunk[i] != text.chars[start + i]) {
            return DIFFERENT;
          }
        }
        return init::FS_OK;
      });
}

// FS_OK if names `a` and `b` are the same, DIFFERENT if not, or an I/O error.
int64_t compare_names(const Name& a, const Name& b) {
  if (a.length != b.length || a.hash != b.hash) {
    return DIFFERENT;
  }
  for (uint32_t i = 0; i < head_bytes(a.length); ++i) {
    if (a.head[i] != b.head[i]) {
      return DIFFERENT;
    }
  }
  const uint32_t count = name_blocks(a.length);
  for (uint32_t k = 0; k < count; ++k) {
    const uint32_t block_a = tree_block(a.tree, count, k);
    if (block_a == 0) {
      return init::FS_IO_ERROR;
    }
    TRY(read_block(block_a, s_block_buf));
    const uint32_t block_b = tree_block(b.tree, count, k);
    if (block_b == 0) {
      return init::FS_IO_ERROR;
    }
    TRY(read_block(block_b, s_name_buf));
    const uint64_t start = uint64_t{k} * BLOCK;
    const uint64_t n = a.length - start < BLOCK ? a.length - start : BLOCK;
    for (uint64_t i = 0; i < n; ++i) {
      if (s_block_buf[i] != s_name_buf[i]) {
        return DIFFERENT;
      }
    }
  }
  return init::FS_OK;
}

// Copies name `name`, and a NUL, to `out`.
int64_t copy_name(const Name& name, char* out) {
  copy_bytes(out, name.head, head_bytes(name.length));
  TRY(each_name_block(
      name, s_name_buf, [&](const char* chunk, uint64_t start, uint64_t n) {
        copy_bytes(out + start, chunk, n);
        return init::FS_OK;
      }));
  out[name.length] = '\0';
  return init::FS_OK;
}

// Keeps `text` as `*name`: read once more, checked and hashed as it is
// copied. A long name's blocks are allocated and written here, and the caller
// has paid for them (`name_cost`). On failure `*name` is empty and the blocks
// are given back, but after an I/O error, which leaves them taken until the
// next mount.
int64_t store_name(Name* name, const Text& text) {
  zero_bytes(name, sizeof(Name));
  if (text.length == 0 || text.length > MAX_COUNT) {
    return init::FS_BAD_REQUEST;
  }
  const bool is_long = text.length > NAME_HEAD;
  uint32_t hash = HASH_SEED;
  uint32_t tree = 0;
  uint32_t count = 0;
  int64_t status = init::FS_OK;
  for (uint64_t start = 0; status == init::FS_OK && start < text.length;
       start += BLOCK) {
    const uint64_t n = text.length - start < BLOCK ? text.length - start : BLOCK;
    for (uint64_t i = 0; i < n; ++i) {
      const char c = text.chars[start + i];
      status = name_char(c) ? status : init::FS_BAD_REQUEST;
      hash = hash_step(hash, c);
      s_name_buf[i] = static_cast<uint8_t>(c);
    }
    if (start == 0) {
      copy_bytes(name->head, s_name_buf, head_bytes(static_cast<uint32_t>(n)));
    }
    if (status == init::FS_OK && is_long) {
      zero_bytes(s_name_buf + n, BLOCK - n);
      const uint32_t block = alloc_block();
      status = write_block(block, s_name_buf);
      if (status == init::FS_OK) {
        status = tree_append(&tree, &count, block);
      } else {
        free_block(block);  // in no tree yet
      }
    }
  }
  if (status == init::FS_OK && is_long) {
    status = flush_lists();
  }
  if (status == init::FS_OK && is_dot_or_dotdot(name->head, text.length)) {
    status = init::FS_BAD_REQUEST;
  }
  if (status != init::FS_OK) {
    if (status == init::FS_BAD_REQUEST && count != 0) {
      tree_free(tree, count);
    }
    drop_lists();
    zero_bytes(name, sizeof(Name));
    return status;
  }
  name->length = static_cast<uint32_t>(text.length);
  name->hash = hash;
  name->tree = tree;
  return init::FS_OK;
}

void free_name(const Name& name) {
  if (name.length > NAME_HEAD) {
    tree_free(name.tree, name_blocks(name.length));
  }
}

// --- Entries ----------------------------------------------------------------

bool entry_in_use(uint32_t entry) { return (s_entries[entry].flags & IN_USE) != 0; }

bool has_flag(uint32_t entry, uint32_t flags) {
  return (s_entries[entry].flags & flags) != 0;
}

// Whether `entry` is a temporary: made in no directory, and not moved into one.
bool is_temporary(uint32_t entry) {
  return entry > ROOT_QUOTA && entry_in_use(entry) &&
         s_entries[entry].parent == NO_ENTRY;
}

// Entry `entry`, marked to be written by `write_changes`.
Entry& modify(uint32_t entry) {
  s_entries[entry].flags |= CHANGED;
  return s_entries[entry];
}

// Writes block `table_block` of the entry table, leaving out the memory-only
// flags.
int64_t write_entry_block(uint32_t table_block) {
  auto* copy = reinterpret_cast<Entry*>(s_block_buf);
  for (uint32_t i = 0; i < ENTRIES_PER_BLOCK; ++i) {
    Entry& entry = s_entries[table_block * ENTRIES_PER_BLOCK + i];
    entry.flags &= ~CHANGED;
    copy_bytes(&copy[i], &entry, sizeof(Entry));
    copy[i].flags &= ~REMOVING;
  }
  return write_block(1 + table_block, s_block_buf);
}

// Writes the blocks of the entry table that hold changed entries.
int64_t write_changes() {
  int64_t status = init::FS_OK;
  for (uint32_t table_block = 0; table_block < s_entry_count / ENTRIES_PER_BLOCK;
       ++table_block) {
    bool changed = false;
    for (uint32_t i = table_block * ENTRIES_PER_BLOCK;
         i < (table_block + 1) * ENTRIES_PER_BLOCK; ++i) {
      changed = changed || has_flag(i, CHANGED);
    }
    if (changed && write_entry_block(table_block) != init::FS_OK) {
      status = init::FS_IO_ERROR;
    }
  }
  return status;
}

// Charges `quota` `bytes`, written before the change it pays for.
int64_t charge(uint32_t quota, uint64_t bytes) {
  s_entries[quota].used += bytes;
  return write_entry_block(quota / ENTRIES_PER_BLOCK);
}

// Gives `quota` back `bytes`, written after the change.
int64_t refund(uint32_t quota, uint64_t bytes) {
  TRY(write_changes());
  modify(quota).used -= bytes;
  return write_changes();
}

// Entry `name` of directory or quota `dir`, into `*found` (NO_ENTRY if none).
int64_t find_child(uint32_t dir, const Text& name, uint32_t* found) {
  *found = NO_ENTRY;
  for (uint32_t i = 2; i < s_entry_count; ++i) {
    if (entry_in_use(i) && s_entries[i].parent == dir) {
      const int64_t status = compare_text(s_entries[i].name, name);
      if (status != DIFFERENT) {
        *found = status == init::FS_OK ? i : NO_ENTRY;
        return status;
      }
    }
  }
  return init::FS_OK;
}

// An entry of `dir` named `name`, other than `self`, into `*found`.
int64_t find_namesake(uint32_t dir, const Name& name, uint32_t self,
                      uint32_t* found) {
  *found = NO_ENTRY;
  for (uint32_t i = 2; i < s_entry_count; ++i) {
    if (i != self && entry_in_use(i) && s_entries[i].parent == dir) {
      const int64_t status = compare_names(s_entries[i].name, name);
      if (status != DIFFERENT) {
        *found = status == init::FS_OK ? i : NO_ENTRY;
        return status;
      }
    }
  }
  return init::FS_OK;
}

// Blocks a file of `blocks` blocks takes: those, and its tree's lists.
uint64_t file_cost(uint32_t blocks) {
  return blocks + (blocks > DIRECT_BLOCKS ? list_count(blocks - DIRECT_BLOCKS) : 0);
}

// What an entry costs whoever pays for it: a block for the entry, and its
// name's blocks and a file's; and a quota its limit too.
uint64_t cost_of(const Entry& entry) {
  const uint64_t blocks =
      1 + name_cost(entry.name.length) + file_cost(entry.block_count);
  return BLOCK * blocks + ((entry.flags & QUOTA) != 0 ? entry.limit : 0);
}

// Rebuilds every quota's `used` from the table: a quota costs its parent,
// anything else its payer, `cost_of` it.
void recount_quotas() {
  for (uint32_t i = 1; i < s_entry_count; ++i) {
    if (entry_in_use(i) && has_flag(i, QUOTA)) {
      modify(i).used = 0;
    }
  }
  for (uint32_t i = 2; i < s_entry_count; ++i) {
    const Entry& entry = s_entries[i];
    if (entry_in_use(i)) {
      s_entries[has_flag(i, QUOTA) ? entry.parent : entry.payer].used +=
          cost_of(entry);
    }
  }
}

bool has_room(uint32_t quota, uint64_t bytes) {
  const uint64_t limit = s_entries[quota].limit;
  return bytes <= limit && s_entries[quota].used <= limit - bytes;
}

// Makes entry `index` new, keeping its generation. It has no name yet.
void init_entry(uint32_t index, uint32_t flags, uint32_t parent,
                uint32_t payer) {
  Entry& entry = s_entries[index];
  const uint32_t generation = entry.generation;
  zero_bytes(&entry, sizeof(entry));
  entry.flags = IN_USE | CHANGED | flags;
  entry.parent = parent;
  entry.payer = payer;
  entry.generation = generation;
}

uint32_t new_entry(uint32_t flags, uint32_t parent, uint32_t payer) {
  for (uint32_t i = 2; i < s_entry_count; ++i) {
    if (!entry_in_use(i)) {
      init_entry(i, flags, parent, payer);
      return i;
    }
  }
  return NO_ENTRY;
}

// Empties entry `index`; the new generation kills its handles.
void clear_entry(uint32_t index) {
  const uint32_t generation = s_entries[index].generation + 1;
  zero_bytes(&s_entries[index], sizeof(Entry));
  s_entries[index].generation = generation;
  s_entries[index].flags = CHANGED;
}

// Frees entry `index`: its blocks, its name's, and the entry.
void free_entry(uint32_t index) {
  const Entry& entry = s_entries[index];
  const uint32_t direct =
      entry.block_count < DIRECT_BLOCKS ? entry.block_count : DIRECT_BLOCKS;
  for (uint32_t i = 0; i < direct; ++i) {
    free_block(entry.blocks[i]);
  }
  if (entry.block_count > DIRECT_BLOCKS) {
    tree_free(entry.tree, entry.block_count - DIRECT_BLOCKS);
  }
  free_name(entry.name);
  clear_entry(index);
}

// Gives entry `index`, paid for and out of sight so far (no parent), the name
// `text` in directory or quota `dir`. FS_EXISTS if `dir` has an entry of that
// name already, compared as kept: the caller could have changed its buffer
// since `text` was looked up.
int64_t place_entry(uint32_t index, uint32_t dir, const Text& text) {
  Name& name = s_entries[index].name;
  TRY(store_name(&name, text));
  uint32_t namesake = NO_ENTRY;
  TRY(find_namesake(dir, name, index, &namesake));
  if (namesake != NO_ENTRY) {
    return init::FS_EXISTS;
  }
  s_entries[index].parent = dir;
  return init::FS_OK;
}

// Removes `removed`, a file, directory or link, and everything in it.
int64_t remove_tree(uint32_t removed) {
  // Mark the subtree.
  s_entries[removed].flags |= REMOVING;
  for (bool more = true; more;) {
    more = false;
    for (uint32_t i = 2; i < s_entry_count; ++i) {
      const uint32_t parent = s_entries[i].parent;
      if (entry_in_use(i) && !has_flag(i, REMOVING) && parent != NO_ENTRY &&
          has_flag(parent, REMOVING)) {
        s_entries[i].flags |= REMOVING;
        more = true;
      }
    }
  }
  // Freed, then refunded, one payer at a time.
  for (;;) {
    uint32_t payer = NO_ENTRY;
    for (uint32_t i = 2; i < s_entry_count && payer == NO_ENTRY; ++i) {
      payer = has_flag(i, REMOVING) ? s_entries[i].payer : NO_ENTRY;
    }
    if (payer == NO_ENTRY) {
      return write_changes();
    }
    uint64_t freed = 0;
    for (uint32_t i = 2; i < s_entry_count; ++i) {
      if (has_flag(i, REMOVING) && s_entries[i].payer == payer) {
        freed += cost_of(s_entries[i]);
        free_entry(i);
      }
    }
    TRY(refund(payer, freed));
  }
}

// The disk block holding block `index` of `file`; 0 on error.
uint32_t file_block(const Entry& file, uint32_t index) {
  return index < DIRECT_BLOCKS
             ? file.blocks[index]
             : tree_block(file.tree, file.block_count - DIRECT_BLOCKS,
                          index - DIRECT_BLOCKS);
}

// Grows `file` to `blocks` zeroed blocks, paid for by its payer. On failure
// the file is left as it was; the blocks it took stay taken, and paid for,
// until the next mount.
int64_t grow_file(uint32_t file, uint32_t blocks) {
  Entry& entry = s_entries[file];
  if (blocks <= entry.block_count) {
    return init::FS_OK;
  }
  const uint64_t new_blocks = file_cost(blocks) - file_cost(entry.block_count);
  if (!has_room(entry.payer, new_blocks * BLOCK)) {
    return init::FS_QUOTA;
  }
  if (new_blocks > s_free_blocks) {
    return init::FS_DISK_FULL;
  }
  TRY(charge(entry.payer, new_blocks * BLOCK));
  modify(file);
  const uint32_t old_count = entry.block_count;
  const uint32_t old_tree = entry.tree;
  zero_bytes(s_block_buf, BLOCK);
  int64_t status = init::FS_OK;
  while (status == init::FS_OK && entry.block_count < blocks) {
    const uint32_t block = alloc_block();
    status = write_block(block, s_block_buf);
    if (status == init::FS_OK && entry.block_count < DIRECT_BLOCKS) {
      entry.blocks[entry.block_count++] = block;
    } else if (status == init::FS_OK) {
      uint32_t count = entry.block_count - DIRECT_BLOCKS;
      status = tree_append(&entry.tree, &count, block);
      entry.block_count = DIRECT_BLOCKS + count;
    }
  }
  if (status == init::FS_OK) {
    status = flush_lists();
  }
  if (status != init::FS_OK) {
    // What it was on disk: no list written here is reachable from that.
    drop_lists();
    for (uint32_t i = old_count; i < DIRECT_BLOCKS; ++i) {
      entry.blocks[i] = 0;
    }
    entry.block_count = old_count;
    entry.tree = old_tree;
  }
  return status;
}

// Copies `length` bytes at `offset` between `buf` and `file`, which has the
// blocks.
int64_t copy_data(Entry& file, uint8_t* buf, uint64_t offset, uint64_t length,
                  bool writing) {
  for (uint64_t done = 0; done < length;) {
    const uint64_t offset_in_block = (offset + done) % BLOCK;
    const uint64_t count = BLOCK - offset_in_block < length - done
                               ? BLOCK - offset_in_block
                               : length - done;
    const uint32_t block =
        file_block(file, static_cast<uint32_t>((offset + done) / BLOCK));
    if (block == 0) {
      return init::FS_IO_ERROR;
    }
    if (!writing || count < BLOCK) {
      TRY(read_block(block, s_block_buf));
    }
    if (writing) {
      copy_bytes(s_block_buf + offset_in_block, buf + done, count);
      TRY(write_block(block, s_block_buf));
    } else {
      copy_bytes(buf + done, s_block_buf + offset_in_block, count);
    }
    done += count;
  }
  return init::FS_OK;
}

// What `link` names, or NO_ENTRY if that is gone.
uint32_t link_target(uint32_t link) {
  const uint32_t target = s_entries[link].target.entry;
  return target < s_entry_count && entry_in_use(target) &&
                 !has_flag(target, LINK | QUOTA) &&
                 s_entries[target].generation == s_entries[link].target.generation
             ? target
             : NO_ENTRY;
}

// `entry` (NO_ENTRY if missing) is entry `last` of `parent`. The path "" gives
// the start entry. Links passed through only take rights away from those the
// start was given: `parent_rights` is what is left for `parent`, `rights` for
// `entry`.
struct Lookup {
  int64_t status;
  uint32_t parent = NO_ENTRY;
  uint32_t entry = NO_ENTRY;
  uint32_t name_count = 0;
  Text last{};
  uint32_t parent_rights = ~0u;
  uint32_t rights = ~0u;
};

// Follows `path` down from entry `start`, held with `rights`, through links,
// and through one at the end too if `follow_last_link`. Looking inside a
// directory needs READ on it.
Lookup look_up(uint32_t start, uint32_t rights, const Path& path,
               bool follow_last_link) {
  Lookup found{init::FS_OK, NO_ENTRY, start, 0, Text{}, rights, rights};
  for (uint64_t at = 0; at < path.length;) {
    Text name;
    if (const int64_t status = next_name(path, &at, &name);
        status != init::FS_OK) {
      return Lookup{status};
    }
    const bool last = at == path.length;
    if (found.entry == NO_ENTRY) {
      return Lookup{init::FS_NOT_FOUND};
    }
    if (!has_flag(found.entry, DIR | QUOTA)) {
      return Lookup{init::FS_NOT_DIR};
    }
    if (!last && (found.rights & init::FS_READ) == 0) {
      return Lookup{init::FS_PERMISSION};
    }
    uint32_t child = NO_ENTRY;
    if (const int64_t status = find_child(found.entry, name, &child);
        status != init::FS_OK) {
      return Lookup{status};
    }
    found = Lookup{init::FS_OK, found.entry, child, found.name_count + 1,
                   name, found.rights, found.rights};
    if (child != NO_ENTRY && has_flag(child, LINK) &&
        (!last || follow_last_link)) {
      found.rights &= s_entries[child].target.rights;
      found.entry = link_target(child);
      if (found.entry == NO_ENTRY) {
        return Lookup{init::FS_NOT_FOUND};  // what it named is gone
      }
    }
  }
  return found;
}

// --- Handles ----------------------------------------------------------------

// Kinds of handle; a call takes any mix of them.
constexpr uint32_t KIND_FILE = 1;
constexpr uint32_t KIND_DIR = 2;
constexpr uint32_t KIND_QUOTA = 4;
constexpr uint32_t KIND_ANY = KIND_FILE | KIND_DIR | KIND_QUOTA;

// The open record behind `handle`, a file, directory or quota handle, or
// null. `*kind` says which (KIND_*).
Handle* open_record(Capability handle, uint32_t* kind) {
  Capability seal = nullptr;
  if (sealing::is_sealed_as(OType::FsFile, handle)) {
    *kind = KIND_FILE;
    seal = s_seal_file;
  } else if (sealing::is_sealed_as(OType::FsDir, handle)) {
    *kind = KIND_DIR;
    seal = s_seal_dir;
  } else if (sealing::is_sealed_as(OType::FsQuota, handle)) {
    *kind = KIND_QUOTA;
    seal = s_seal_quota;
  } else {
    return nullptr;
  }
  Handle* record = static_cast<Handle*>(sealing::unseal_with(seal, handle));
  return record != nullptr && record->is_open != 0 ? record : nullptr;
}

// The record behind `handle`, if it is a handle of one of `kinds` and what it
// names still exists, and whether it has the rights in `needed`.
int64_t check_handle(Capability handle, uint32_t kinds, uint32_t needed,
                     Handle** out) {
  uint32_t kind = 0;
  Handle* record = open_record(handle, &kind);
  if (record == nullptr || !entry_in_use(record->entry) ||
      s_entries[record->entry].generation != record->generation) {
    return init::FS_INVALID;
  }
  if ((kinds & kind) == 0) {
    return kinds == KIND_FILE  ? init::FS_IS_DIR    // a file was needed
           : kind == KIND_FILE ? init::FS_NOT_DIR   // a file was given
                               : init::FS_BAD_REQUEST;
  }
  *out = record;
  return (record->rights & needed) == needed ? init::FS_OK : init::FS_PERMISSION;
}

// A new handle on `entry` with `rights`, opened through `parent` (null for a
// root) and paid for by `memory_quota`; or a status. `temporary`: it is the
// handle fs.create made the temporary `entry` with.
Capability make_handle(Handle* parent, uint32_t entry, uint32_t rights,
                       Capability memory_quota, bool temporary = false) {
  if (!sealing::is_sealed_as(OType::QuotaVm, memory_quota)) {
    return init::status_cap(init::FS_BAD_REQUEST);
  }
  // A VM quota hands out whole pages; an allocator quota could hand out just
  // sizeof(Handle).
  using FnAlloc = decltype(&sys_vm_allocate);
  Capability self =
      syscall::call<FnAlloc>(s_gate_invoke, s_gate_alloc, s_self_comp,
                             memory_quota, vm::PAGE_SIZE, 0);
  if (!capability_is_valid(self)) {
    return init::status_cap(init::FS_NO_MEMORY);
  }
  Handle* handle = static_cast<Handle*>(self);
  *handle = Handle{self, memory_quota, parent, nullptr,
                   parent != nullptr ? parent->first_child : nullptr,
                   entry, s_entries[entry].generation, rights, 1,
                   temporary ? 1u : 0u};
  if (parent != nullptr) {
    parent->first_child = handle;
  }
  const Capability seal = has_flag(entry, QUOTA) ? s_seal_quota
                          : has_flag(entry, DIR) ? s_seal_dir
                                                 : s_seal_file;
  return sealing::seal_with(seal, capability_set_bounds(self, sizeof(Handle)));
}

// Takes `handle` out of its parent's list of children.
void detach(Handle* handle) {
  if (handle->parent == nullptr) {
    return;
  }
  Handle** next = &handle->parent->first_child;
  while (*next != handle) {
    next = &(*next)->next_sibling;
  }
  *next = handle->next_sibling;
}

// Closes `top` and every handle opened through it, children first, and gives
// their memory back. Zeroed first: until the sweep revokes them, stale copies
// read as closed. A temporary is removed, and its payer refunded, with the
// handle that made it: every handle on it was opened through that one, so
// nothing can reach it after. FS_OK, or the status of a removal that failed;
// every handle is closed either way.
int64_t close_with_children(Handle* top) {
  using FnDealloc = decltype(&sys_vm_deallocate);
  int64_t status = init::FS_OK;
  for (Handle* handle = top;;) {
    if (handle->first_child != nullptr) {
      handle = handle->first_child;
      continue;
    }
    Handle* const parent = handle->parent;
    const bool is_top = handle == top;
    const uint32_t entry = handle->entry;
    const bool temporary = handle->temporary != 0 && is_temporary(entry) &&
                           s_entries[entry].generation == handle->generation;
    detach(handle);
    const Capability self = handle->self;
    const Capability memory_quota = handle->memory_quota;
    zero_bytes(self, sizeof(Handle));
    syscall::call<FnDealloc>(s_gate_invoke, s_gate_dealloc, s_self_comp,
                             memory_quota, self);
    if (temporary) {
      const int64_t removed = remove_tree(entry);
      status = status == init::FS_OK ? removed : status;
    }
    if (is_top) {
      return status;
    }
    handle = parent;
  }
}

Capability handle_or_status(int64_t status, const Capability* handle) {
  return status == init::FS_OK ? *handle : init::status_cap(status);
}

// --- Mount ------------------------------------------------------------------

// Page-rounded memory from our VM quota.
void* alloc_table(uint64_t bytes) {
  using FnAlloc = decltype(&sys_vm_allocate);
  const size_t size = (bytes + vm::PAGE_SIZE - 1) & ~(vm::PAGE_SIZE - 1);
  Capability memory = syscall::call<FnAlloc>(s_gate_invoke, s_gate_alloc,
                                             s_self_comp, s_vm_quota, size, 0);
  return capability_is_valid(memory) ? memory : nullptr;
}

// Marks `block` used, unless it is out of range or taken.
bool claim_block(uint32_t block) {
  if (block < s_data_start || block >= s_total_blocks || block_in_use(block)) {
    return false;
  }
  set_block_used(block, true);
  s_free_blocks -= 1;
  return true;
}

// Claims the tree `root` of `count` blocks, as read from disk, lists and
// all, each before it is read: false if one is out of range or taken.
bool tree_claim(uint32_t root, uint32_t count) {
  const uint32_t depth = levels(count);
  for (uint32_t index = 0; index < count; ++index) {
    uint32_t block = root;
    for (uint32_t level = depth; level-- > 0;) {
      if ((starts_list(index, level) && !claim_block(block)) ||
          load_list(level, block) != init::FS_OK) {
        return false;
      }
      block = s_list[level][slot_at(index, level)];
    }
    if (!claim_block(block)) {
      return false;
    }
  }
  return true;
}

// Whether `name`, as read from disk, is a good name, with its blocks
// claimed, and its hash and head what its bytes say.
bool name_is_valid(const Name& name) {
  if (name.length == 0 || (name.length <= NAME_HEAD) != (name.tree == 0)) {
    return false;
  }
  uint32_t hash = HASH_SEED;
  bool ok = true;
  auto check = [&](const char* chunk, uint64_t start, uint64_t n) {
    for (uint64_t i = 0; i < n; ++i) {
      ok = ok && name_char(chunk[i]) &&
           (start + i >= NAME_HEAD || chunk[i] == name.head[start + i]);
      hash = hash_step(hash, chunk[i]);
    }
    return init::FS_OK;
  };
  if (name.length <= NAME_HEAD) {
    check(name.head, 0, name.length);
  } else if (!tree_claim(name.tree, name_blocks(name.length)) ||
             each_name_block(name, s_name_buf, check) != init::FS_OK) {
    return false;
  }
  return ok && hash == name.hash && !is_dot_or_dotdot(name.head, name.length);
}

// Whether entry `index`, as read from disk, is consistent: known flags, a
// valid unique name (its blocks claimed), parents up to its root, a payer,
// blocks of its own (claimed), and for a link, something to name.
bool entry_is_valid(uint32_t index) {
  Entry& entry = s_entries[index];
  const uint32_t kind = entry.flags & (DIR | QUOTA | LINK);
  if ((entry.flags & ~(IN_USE | DIR | QUOTA | FROZEN | LINK)) != 0 ||
      (kind & (kind - 1)) != 0 || !name_is_valid(entry.name)) {
    return false;
  }
  const uint32_t parent_kind = kind == QUOTA ? QUOTA : DIR;
  const uint32_t root = parent_kind == QUOTA ? ROOT_QUOTA : ROOT_DIR;
  uint32_t steps = 0;
  for (uint32_t parent = entry.parent; parent != root;
       parent = s_entries[parent].parent) {
    if (parent >= s_entry_count || !entry_in_use(parent) ||
        (s_entries[parent].flags & (DIR | QUOTA)) != parent_kind ||
        ++steps > s_entry_count) {
      return false;
    }
  }
  for (uint32_t other = 2; other < index; ++other) {
    if (entry_in_use(other) && s_entries[other].parent == entry.parent &&
        compare_names(s_entries[other].name, entry.name) != DIFFERENT) {
      return false;  // the same name, or one that cannot be read
    }
  }
  if (kind == QUOTA) {
    return entry.block_count == 0 && entry.tree == 0;
  }
  if (entry.payer >= s_entry_count || !entry_in_use(entry.payer) ||
      !has_flag(entry.payer, QUOTA)) {
    return false;
  }
  if (kind == DIR) {
    return entry.block_count == 0 && entry.tree == 0 && entry.size == 0;
  }
  if (kind == LINK) {
    return entry.block_count == 0 && entry.tree == 0 &&
           entry.size == 0 && (entry.flags & FROZEN) == 0 &&
           (entry.target.rights & ~init::FS_ALL) == 0 &&
           link_target(index) != NO_ENTRY;
  }
  if (entry.size > uint64_t{entry.block_count} * BLOCK ||
      (entry.block_count > DIRECT_BLOCKS) != (entry.tree != 0)) {
    return false;
  }
  const uint32_t direct =
      entry.block_count < DIRECT_BLOCKS ? entry.block_count : DIRECT_BLOCKS;
  for (uint32_t n = 0; n < direct; ++n) {
    if (!claim_block(entry.blocks[n])) {
      return false;
    }
  }
  return entry.block_count <= DIRECT_BLOCKS ||
         tree_claim(entry.tree, entry.block_count - DIRECT_BLOCKS);
}

// Loads the entry table, formatting the disk first if it has no header of
// ours.
int64_t mount(uint64_t sectors, uint32_t* formatted) {
  const uint64_t blocks = sectors / SECTORS_PER_BLOCK;
  TRY(read_block(0, s_block_buf));
  DiskHeader header = *reinterpret_cast<const DiskHeader*>(s_block_buf);
  const bool already_formatted = header.magic == MAGIC &&
                                 header.version == VERSION &&
                                 header.total_blocks <= blocks;
  if (!already_formatted) {
    header = DiskHeader{MAGIC, VERSION, blocks};
  }
  // One entry per disk block, in a table from block 1.
  s_total_blocks = header.total_blocks;
  s_entry_count = static_cast<uint32_t>(
      (s_total_blocks + ENTRIES_PER_BLOCK - 1) / ENTRIES_PER_BLOCK *
      ENTRIES_PER_BLOCK);
  s_data_start = 1 + s_entry_count / ENTRIES_PER_BLOCK;
  if (s_data_start >= s_total_blocks) {
    return init::FS_NOT_MOUNTED;
  }
  s_entries = static_cast<Entry*>(alloc_table(uint64_t{s_entry_count} * sizeof(Entry)));
  s_block_map = static_cast<uint8_t*>(alloc_table((s_total_blocks + 7) / 8));
  if (s_entries == nullptr || s_block_map == nullptr) {
    return init::FS_NO_MEMORY;
  }
  // Read the table, or write a blank one.
  for (uint32_t table_block = 0; table_block < s_entry_count / ENTRIES_PER_BLOCK;
       ++table_block) {
    Entry* first = &s_entries[table_block * ENTRIES_PER_BLOCK];
    TRY(already_formatted ? read_block(1 + table_block, first)
                          : write_block(1 + table_block, first));
  }
  if (!already_formatted) {
    zero_bytes(s_block_buf, BLOCK);
    *reinterpret_cast<DiskHeader*>(s_block_buf) = header;
    TRY(write_block(0, s_block_buf));
    *formatted = 1;
  }
  init_entry(ROOT_DIR, DIR, NO_ENTRY, ROOT_QUOTA);
  init_entry(ROOT_QUOTA, QUOTA, NO_ENTRY, NO_ENTRY);
  s_entries[ROOT_QUOTA].limit = (s_total_blocks - s_data_start) * BLOCK;
  // Drop bad entries (temporaries included) until none are left: dropping one
  // can orphan others.
  uint32_t dropped = 0;
  for (bool again = true; again;) {
    again = false;
    zero_bytes(s_block_map, (s_total_blocks + 7) / 8);
    for (uint64_t block = 0; block < s_data_start; ++block) {
      set_block_used(block, true);
    }
    s_free_blocks = s_total_blocks - s_data_start;
    for (uint32_t i = 2; i < s_entry_count; ++i) {
      if (entry_in_use(i) && !entry_is_valid(i)) {
        clear_entry(i);
        dropped += 1;
        again = true;
      }
    }
  }
  if (dropped != 0) {
    out_dec("[fs]       dropped ", dropped,
            " temporary or damaged entries\n");
  }
  recount_quotas();  // every entry is read anyway; fixes what a crash left
  s_next_block = s_data_start;
  return write_changes();
}

// --- Entry points that return a handle --------------------------------------

int64_t open_handle(Capability from_cap, Capability path_cap, uint32_t rights,
                    Capability memory_quota, Capability* out) {
  CallGuard guard;
  TRY(guard.status());
  Path path;
  TRY(read_path(path_cap, &path));
  Handle* from = nullptr;
  TRY(check_handle(from_cap, KIND_ANY, path.length != 0 ? init::FS_READ : 0, &from));
  const Lookup found = look_up(from->entry, from->rights, path, true);
  TRY(found.status);
  if (found.entry == NO_ENTRY) {
    return init::FS_NOT_FOUND;
  }
  if (found.name_count != 0 && (found.parent_rights & init::FS_READ) == 0) {
    return init::FS_PERMISSION;
  }
  *out = make_handle(from, found.entry, rights & from->rights & found.rights,
                     memory_quota);
  return init::FS_OK;
}

// A null `dir_cap` makes a temporary, opened through `payer_cap`: removed when
// the handle made here is closed, unless it was moved into a directory first,
// and at the next mount if it is still there.
int64_t create_handle(Capability dir_cap, Capability path_cap,
                      Capability payer_cap, uint32_t flags,
                      Capability memory_quota, Capability* out) {
  CallGuard guard;
  TRY(guard.status());
  Path path;
  TRY(read_path(path_cap, &path));
  if ((flags & ~init::FS_CREATE_DIR) != 0) {
    return init::FS_BAD_REQUEST;
  }
  Handle* payer = nullptr;
  TRY(check_handle(payer_cap, KIND_QUOTA, init::FS_ADD, &payer));
  Handle* opened_through = payer;
  Lookup found{init::FS_OK};  // a temporary: no directory, no name
  if (dir_cap != nullptr) {
    TRY(check_handle(dir_cap, KIND_DIR, init::FS_ADD, &opened_through));
    found = look_up(opened_through->entry, opened_through->rights, path, false);
    TRY(found.status);
    if (found.name_count == 0) {
      return init::FS_BAD_REQUEST;
    }
    if (found.entry != NO_ENTRY) {
      return init::FS_EXISTS;
    }
    if (!has_flag(found.parent, DIR)) {
      return init::FS_NOT_DIR;
    }
    if ((found.parent_rights & init::FS_ADD) == 0) {
      return init::FS_PERMISSION;
    }
  }
  const uint64_t name_blocks_needed =
      name_cost(static_cast<uint32_t>(found.last.length));
  const uint64_t cost = BLOCK * (1 + name_blocks_needed);
  if (!has_room(payer->entry, cost)) {
    return init::FS_QUOTA;
  }
  if (name_blocks_needed > s_free_blocks) {
    return init::FS_DISK_FULL;
  }
  // Out of sight, in no directory, until it has its name: what a fault
  // leaves of it then is a temporary, gone at the next mount.
  const uint32_t created = new_entry(
      (flags & init::FS_CREATE_DIR) != 0 ? DIR : 0, NO_ENTRY, payer->entry);
  if (created == NO_ENTRY) {
    return init::FS_DISK_FULL;
  }
  if (const int64_t status = charge(payer->entry, cost); status != init::FS_OK) {
    clear_entry(created);
    return status;
  }
  if (dir_cap != nullptr) {
    if (const int64_t status = place_entry(created, found.parent, found.last);
        status != init::FS_OK) {
      free_entry(created);
      refund(payer->entry, cost);
      return status;
    }
  }
  // Every right on what you make; LINK only if the directory had it.
  const uint32_t linkable =
      opened_through->rights & found.parent_rights & init::FS_LINK;
  *out = make_handle(opened_through, created, init::FS_ALL | linkable,
                     memory_quota, dir_cap == nullptr);
  if (!capability_is_valid(*out)) {
    free_entry(created);  // no handle, no file
    return refund(payer->entry, cost);
  }
  return write_changes();
}

// Quota `name` of `parent`, made with `limit` bytes, or set to `limit` if it
// is there already. Growing takes from `parent`; shrinking stops at what the
// quota has used. Needs CHANGE on `parent`, and ADD as well to make or grow
// one, which is paying with `parent`. The handle has `parent`'s rights.
int64_t make_or_resize_quota(Capability parent_cap, Capability name_cap,
                             uint64_t limit, Capability memory_quota,
                             Capability* out) {
  CallGuard guard;
  TRY(guard.status());
  Path path;
  TRY(read_path(name_cap, &path));
  Handle* parent = nullptr;
  TRY(check_handle(parent_cap, KIND_QUOTA, init::FS_CHANGE, &parent));
  uint64_t at = 0;
  Text name;
  TRY(next_name(path, &at, &name));
  if (at != path.length) {
    return init::FS_BAD_REQUEST;  // a name, not a path
  }
  uint32_t quota = NO_ENTRY;
  TRY(find_child(parent->entry, name, &quota));
  const bool is_new = quota == NO_ENTRY;
  if ((is_new || limit > s_entries[quota].limit) &&
      (parent->rights & init::FS_ADD) == 0) {
    return init::FS_PERMISSION;
  }
  if (limit > s_entries[parent->entry].limit) {
    return init::FS_QUOTA;  // and the cost below cannot overflow
  }
  if (is_new) {
    const uint64_t name_blocks_needed =
        name_cost(static_cast<uint32_t>(name.length));
    const uint64_t cost = limit + BLOCK * (1 + name_blocks_needed);
    if (!has_room(parent->entry, cost)) {
      return init::FS_QUOTA;
    }
    if (name_blocks_needed > s_free_blocks) {
      return init::FS_DISK_FULL;
    }
    quota = new_entry(QUOTA, NO_ENTRY, NO_ENTRY);  // out of sight, as above
    if (quota == NO_ENTRY) {
      return init::FS_DISK_FULL;
    }
    s_entries[quota].limit = limit;
    if (const int64_t status = charge(parent->entry, cost);
        status != init::FS_OK) {
      clear_entry(quota);
      return status;
    }
    if (const int64_t status = place_entry(quota, parent->entry, name);
        status != init::FS_OK) {
      free_entry(quota);
      refund(parent->entry, cost);
      return status;
    }
  } else {
    const uint64_t old_limit = s_entries[quota].limit;
    if (limit > old_limit) {
      if (!has_room(parent->entry, limit - old_limit)) {
        return init::FS_QUOTA;
      }
      TRY(charge(parent->entry, limit - old_limit));
      modify(quota).limit = limit;
    } else if (limit < old_limit) {
      if (limit < s_entries[quota].used) {
        return init::FS_QUOTA;
      }
      modify(quota).limit = limit;
      TRY(refund(parent->entry, old_limit - limit));
    }
  }
  *out = make_handle(parent, quota, parent->rights, memory_quota);
  if (is_new && !capability_is_valid(*out)) {
    const uint64_t cost = cost_of(s_entries[quota]);
    free_entry(quota);
    return refund(parent->entry, cost);
  }
  return write_changes();
}

}  // namespace

// The default handler (runtime.hpp), which unwinds -- past ~LockScope. A lock
// left with the faulting thread would keep every later caller waiting for good,
// so it is let go first. What faults is most likely a caller's buffer, which is
// touched only where nothing is left half-changed: paths are read as they are
// followed (look_up) and a new name as it is kept (store_name), into an entry
// still out of sight or no entry yet, with its blocks paid for; data in
// copy_data; fs.list and fs.stat write to it. A fault in store_name leaves its
// blocks taken, and the entry a temporary, until the next mount.
SIGNETOS_FAULT_HANDLER compartment_error_handler(
    ::signetos::fault::ErrorState* state) {
  const Capability* table = rw_table();
  const bool held = (__atomic_load_n(&s_lock, __ATOMIC_SEQ_CST) &
                     ~init::LOCK_WAITERS) == self_tid();
  if (held) {
    unlock(table[SLOT_SYS_COMP_INVOKE], s_lock_wake, &s_lock);
  }
  const uint64_t action = report_fault_and_unwind(
      "fs", *state, table[SLOT_SYS_COMP_INVOKE], table[SLOT_UART_SENTRY]);
  if (held) {
    print(table[SLOT_SYS_COMP_INVOKE], table[SLOT_UART_SENTRY],
          "[fs]       released the fs lock the faulting call held\n");
  }
  return action;
}

// --- Entry points (user/abi.hpp) --------------------------------------------

// Works on the handle of something since removed too: its memory comes back.
extern "C" int64_t fs_close_entry(Capability handle_cap) {
  CallGuard guard;
  TRY(guard.status());
  uint32_t kind = 0;
  Handle* handle = open_record(handle_cap, &kind);
  if (handle == nullptr) {
    return init::FS_INVALID;
  }
  return close_with_children(handle);
}

extern "C" Capability fs_open_entry(Capability from, Capability path,
                                    uint32_t rights, Capability memory_quota) {
  Capability handle = nullptr;
  return handle_or_status(open_handle(from, path, rights, memory_quota, &handle),
                          &handle);
}

extern "C" Capability fs_create_entry(Capability dir, Capability path,
                                      Capability payer, uint32_t flags,
                                      Capability memory_quota) {
  Capability handle = nullptr;
  return handle_or_status(
      create_handle(dir, path, payer, flags, memory_quota, &handle), &handle);
}

extern "C" Capability fs_quota_entry(Capability parent, Capability name,
                                     uint64_t limit, Capability memory_quota) {
  Capability handle = nullptr;
  return handle_or_status(
      make_or_resize_quota(parent, name, limit, memory_quota, &handle), &handle);
}

extern "C" int64_t fs_read_entry(Capability file_cap, Capability buf,
                                 uint64_t offset, uint64_t length) {
  CallGuard guard;
  TRY(guard.status());
  Handle* handle = nullptr;
  TRY(check_handle(file_cap, KIND_FILE, init::FS_READ, &handle));
  Entry& file = s_entries[handle->entry];
  if (offset >= file.size) {
    return 0;
  }
  if (length > file.size - offset) {
    length = file.size - offset;
  }
  if (!buffer_ok(buf, perms::Store, length)) {
    return init::FS_BAD_REQUEST;
  }
  TRY(copy_data(file, static_cast<uint8_t*>(buf), offset, length, false));
  return static_cast<int64_t>(length);
}

extern "C" int64_t fs_write_entry(Capability file_cap, Capability buf,
                                  uint64_t offset, uint64_t length,
                                  Capability payer_cap) {
  CallGuard guard;
  TRY(guard.status());
  Handle* handle = nullptr;
  TRY(check_handle(file_cap, KIND_FILE, 0, &handle));
  Entry& file = s_entries[handle->entry];
  if (has_flag(handle->entry, FROZEN)) {
    return init::FS_FROZEN;
  }
  if (offset == init::FS_APPEND) {
    offset = file.size;
  }
  // As far as an offset reaches, and a block count counts: the quota or the
  // disk runs out long before.
  if (length > ~uint64_t{0} - offset) {
    return init::FS_TOO_LARGE;
  }
  const uint64_t end = offset + length;
  const uint64_t blocks = end / BLOCK + (end % BLOCK != 0 ? 1 : 0);
  if (blocks > MAX_COUNT) {
    return init::FS_TOO_LARGE;
  }
  // Overwriting needs CHANGE, extending needs ADD.
  const bool overwrites = offset < file.size;
  const bool extends = end > file.size;
  const uint32_t needed =
      (overwrites ? init::FS_CHANGE : 0) | (extends ? init::FS_ADD : 0);
  if ((handle->rights & needed) != needed) {
    return init::FS_PERMISSION;
  }
  // Extending also needs ADD on the quota that pays for the file.
  if (extends) {
    Handle* payer = nullptr;
    TRY(check_handle(payer_cap, KIND_QUOTA, init::FS_ADD, &payer));
    if (payer->entry != file.payer) {
      return init::FS_PERMISSION;
    }
  }
  if (!buffer_ok(buf, perms::Load, length)) {
    return init::FS_BAD_REQUEST;
  }
  TRY(grow_file(handle->entry, static_cast<uint32_t>(blocks)));
  TRY(copy_data(file, static_cast<uint8_t*>(buf), offset, length, true));
  if (extends) {
    modify(handle->entry).size = end;
  }
  TRY(write_changes());
  return static_cast<int64_t>(length);
}

extern "C" int64_t fs_list_entry(Capability from_cap, Capability path_cap,
                                 Capability buf_cap, uint64_t bytes,
                                 uint64_t start) {
  CallGuard guard;
  TRY(guard.status());
  Path path;
  TRY(read_path(path_cap, &path));
  Handle* from = nullptr;
  TRY(check_handle(from_cap, KIND_DIR | KIND_QUOTA, init::FS_READ, &from));
  const Lookup found = look_up(from->entry, from->rights, path, true);
  TRY(found.status);
  if (found.entry == NO_ENTRY) {
    return init::FS_NOT_FOUND;
  }
  if (!has_flag(found.entry, DIR | QUOTA)) {
    return init::FS_NOT_DIR;
  }
  if ((found.rights & init::FS_READ) == 0) {
    return init::FS_PERMISSION;
  }
  if (bytes != 0 && !buffer_ok(buf_cap, perms::Store, bytes)) {
    return init::FS_BAD_REQUEST;
  }
  auto* out = static_cast<char*>(buf_cap);
  uint64_t used = 0;
  uint64_t position = 0;
  int64_t written = 0;
  for (uint32_t i = 2; i < s_entry_count; ++i) {
    if (!entry_in_use(i) || s_entries[i].parent != found.entry ||
        position++ < start) {
      continue;
    }
    const Entry& entry = s_entries[i];
    const init::FsDirEntry item{entry.size,
                                entry.flags & (DIR | QUOTA | FROZEN | LINK),
                                entry.name.length};
    const uint64_t need = init::fs_dir_entry_bytes(entry.name.length);
    if (need > bytes - used) {
      if (written == 0 && bytes >= sizeof(item)) {
        copy_bytes(out, &item, sizeof(item));  // what it needs
      }
      return written == 0 ? init::FS_TOO_LARGE : written;
    }
    // Byte by byte: the caller's buffer need not be aligned.
    char* const record = out + used;
    copy_bytes(record, &item, sizeof(item));
    TRY(copy_name(entry.name, record + sizeof(item)));
    const uint64_t name_end = sizeof(item) + entry.name.length + 1;
    zero_bytes(record + name_end, need - name_end);
    used += need;
    written += 1;
  }
  return written;
}

// `path` under `from` and everything in it. A quota only once it pays for
// nothing.
extern "C" int64_t fs_remove_entry(Capability from_cap, Capability path_cap) {
  CallGuard guard;
  TRY(guard.status());
  Path path;
  TRY(read_path(path_cap, &path));
  Handle* from = nullptr;
  TRY(check_handle(from_cap, KIND_ANY, init::FS_CHANGE, &from));
  const Lookup found = look_up(from->entry, from->rights, path, false);
  TRY(found.status);
  if (found.entry == NO_ENTRY) {
    return init::FS_NOT_FOUND;
  }
  if ((found.parent_rights & init::FS_CHANGE) == 0) {
    return init::FS_PERMISSION;
  }
  const uint32_t removed = found.entry;
  if (removed == ROOT_DIR || removed == ROOT_QUOTA) {
    return init::FS_PERMISSION;
  }
  if (has_flag(removed, QUOTA)) {
    // Its files and the quotas made from it go first.
    if (s_entries[removed].used != 0) {
      return init::FS_IN_USE;
    }
    const uint32_t parent = s_entries[removed].parent;
    const uint64_t cost = cost_of(s_entries[removed]);
    free_entry(removed);
    return refund(parent, cost);
  }
  return remove_tree(removed);
}

// Entry `from_path` of `from` to `path` under `dir`. Needs every right on the
// directory it is in, through `from`, or a move could take it from whoever
// shares that directory, or put it where others have more. A temporary, in no
// directory, is moved through its own handle with `from_path` "". It keeps its
// payer, which pays for a new name that takes blocks: in full before it is
// kept, the old name's blocks refunded after. A link is not moved: that would
// grant what it names somewhere new, which takes LINK on it.
extern "C" int64_t fs_move_entry(Capability from_cap, Capability from_path_cap,
                                 Capability dir_cap, Capability path_cap,
                                 Capability payer_cap) {
  CallGuard guard;
  TRY(guard.status());
  Path from_path;
  TRY(read_path(from_path_cap, &from_path));
  Path path;
  TRY(read_path(path_cap, &path));
  Handle* from = nullptr;
  TRY(check_handle(from_cap, KIND_FILE | KIND_DIR, init::FS_ALL, &from));
  const Lookup source = look_up(from->entry, from->rights, from_path, false);
  TRY(source.status);
  if (source.entry == NO_ENTRY) {
    return init::FS_NOT_FOUND;
  }
  const uint32_t moved = source.entry;
  if (source.name_count == 0 ? !is_temporary(moved) : has_flag(moved, LINK)) {
    return init::FS_BAD_REQUEST;
  }
  if ((source.parent_rights & init::FS_ALL) != init::FS_ALL) {
    return init::FS_PERMISSION;  // a link on the way took a right away
  }
  Handle* dir = nullptr;
  TRY(check_handle(dir_cap, KIND_DIR, init::FS_ADD, &dir));
  const Lookup found = look_up(dir->entry, dir->rights, path, false);
  TRY(found.status);
  if (found.name_count == 0) {
    return init::FS_BAD_REQUEST;
  }
  if (!has_flag(found.parent, DIR)) {
    return init::FS_NOT_DIR;
  }
  if ((found.parent_rights & init::FS_ADD) == 0) {
    return init::FS_PERMISSION;
  }
  for (uint32_t ancestor = found.parent; ancestor != NO_ENTRY;
       ancestor = s_entries[ancestor].parent) {
    if (ancestor == moved) {
      return init::FS_BAD_REQUEST;  // into itself
    }
  }
  const uint32_t payer = s_entries[moved].payer;
  const uint64_t name_blocks_needed =
      name_cost(static_cast<uint32_t>(found.last.length));
  if (name_blocks_needed != 0) {
    Handle* paying = nullptr;
    TRY(check_handle(payer_cap, KIND_QUOTA, init::FS_ADD, &paying));
    if (paying->entry != payer) {
      return init::FS_PERMISSION;
    }
    if (!has_room(payer, BLOCK * name_blocks_needed)) {
      return init::FS_QUOTA;
    }
    if (name_blocks_needed > s_free_blocks) {
      return init::FS_DISK_FULL;
    }
    TRY(charge(payer, BLOCK * name_blocks_needed));
  }
  // The new name, kept before anything moves; and what has it there already,
  // compared as kept: itself (nothing to do), or a file it replaces, which
  // needs CHANGE on the destination; its payer is refunded.
  Name fresh;
  int64_t status = store_name(&fresh, found.last);
  uint32_t there = NO_ENTRY;
  if (status == init::FS_OK) {
    status = find_namesake(found.parent, fresh, NO_ENTRY, &there);
  }
  if (status == init::FS_OK && there != NO_ENTRY && there != moved) {
    if (has_flag(there, DIR) || has_flag(moved, DIR)) {
      status = init::FS_EXISTS;
    } else if ((dir->rights & found.parent_rights & init::FS_CHANGE) == 0) {
      status = init::FS_PERMISSION;
    }
  }
  if (status != init::FS_OK || there == moved) {
    free_name(fresh);
    if (name_blocks_needed != 0) {
      refund(payer, BLOCK * name_blocks_needed);
    }
    return status;
  }
  uint32_t replaced_payer = NO_ENTRY;
  uint64_t replaced_cost = 0;
  if (there != NO_ENTRY) {
    replaced_payer = s_entries[there].payer;
    replaced_cost = cost_of(s_entries[there]);
    free_entry(there);
  }
  Entry& entry = modify(moved);
  const uint64_t old_name_cost = BLOCK * name_cost(entry.name.length);
  free_name(entry.name);
  entry.parent = found.parent;
  copy_bytes(&entry.name, &fresh, sizeof(Name));
  TRY(old_name_cost != 0 ? refund(payer, old_name_cost) : write_changes());
  return replaced_payer != NO_ENTRY ? refund(replaced_payer, replaced_cost)
                                    : init::FS_OK;
}

extern "C" int64_t fs_freeze_entry(Capability file_cap) {
  CallGuard guard;
  TRY(guard.status());
  Handle* file = nullptr;
  TRY(check_handle(file_cap, KIND_FILE, init::FS_CHANGE, &file));
  modify(file->entry).flags |= FROZEN;
  return write_changes();
}

extern "C" int64_t fs_stat_entry(Capability handle_cap, Capability stat_cap) {
  CallGuard guard;
  TRY(guard.status());
  Handle* handle = nullptr;
  TRY(check_handle(handle_cap, KIND_ANY, 0, &handle));
  if (!buffer_ok(stat_cap, perms::Store, sizeof(init::FsStat))) {
    return init::FS_BAD_REQUEST;
  }
  const Entry& entry = s_entries[handle->entry];
  auto* stat = static_cast<init::FsStat*>(stat_cap);
  stat->size = entry.size;
  stat->used = has_flag(handle->entry, QUOTA) ? entry.used : cost_of(entry);
  stat->flags = entry.flags & (DIR | QUOTA | FROZEN);
  stat->rights = handle->rights;
  return init::FS_OK;
}

extern "C" int64_t fs_link_entry(Capability dir_cap, Capability path_cap,
                                 Capability target_cap, uint32_t rights,
                                 Capability payer_cap) {
  CallGuard guard;
  TRY(guard.status());
  Path path;
  TRY(read_path(path_cap, &path));
  Handle* payer = nullptr;
  TRY(check_handle(payer_cap, KIND_QUOTA, init::FS_ADD, &payer));
  Handle* target = nullptr;
  TRY(check_handle(target_cap, KIND_FILE | KIND_DIR, init::FS_LINK, &target));
  if (is_temporary(target->entry)) {
    return init::FS_BAD_REQUEST;  // a temporary
  }
  Handle* dir = nullptr;
  TRY(check_handle(dir_cap, KIND_DIR, init::FS_ADD, &dir));
  const Lookup found = look_up(dir->entry, dir->rights, path, false);
  TRY(found.status);
  if (found.name_count == 0) {
    return init::FS_BAD_REQUEST;
  }
  if (found.entry != NO_ENTRY) {
    return init::FS_EXISTS;
  }
  if (!has_flag(found.parent, DIR)) {
    return init::FS_NOT_DIR;
  }
  if ((found.parent_rights & init::FS_ADD) == 0) {
    return init::FS_PERMISSION;
  }
  const uint64_t name_blocks_needed =
      name_cost(static_cast<uint32_t>(found.last.length));
  const uint64_t cost = BLOCK * (1 + name_blocks_needed);
  if (!has_room(payer->entry, cost)) {
    return init::FS_QUOTA;
  }
  if (name_blocks_needed > s_free_blocks) {
    return init::FS_DISK_FULL;
  }
  const uint32_t link = new_entry(LINK, NO_ENTRY, payer->entry);  // out of sight
  if (link == NO_ENTRY) {
    return init::FS_DISK_FULL;
  }
  Entry& entry = s_entries[link];
  entry.target.entry = target->entry;
  entry.target.generation = target->generation;
  entry.target.rights = rights & target->rights & init::FS_ALL;
  if (const int64_t status = charge(payer->entry, cost); status != init::FS_OK) {
    clear_entry(link);
    return status;
  }
  if (const int64_t status = place_entry(link, found.parent, found.last);
      status != init::FS_OK) {
    free_entry(link);
    refund(payer->entry, cost);
    return status;
  }
  return write_changes();
}

extern "C" int64_t compartment_main(Capability arg, Capability arg1) {
  Capability* rw = rw_table();
  s_gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  s_uart = rw[SLOT_UART_SENTRY];

  // Called by init: first the FsInterface handshake, then with the
  // scheduler's lock entries. Later calls print status.
  if (s_first_call_done && !s_second_call_done) {
    s_second_call_done = true;
    if (!sealing::is_sealed_as(OType::EntryPoint, arg) ||
        !sealing::is_sealed_as(OType::EntryPoint, arg1)) {
      return init::FS_BAD_REQUEST;
    }
    s_lock_wait = arg;
    s_lock_wake = arg1;
    return init::FS_OK;
  }
  if (s_first_call_done) {
    if (!s_mounted) {
      out("[fs]       not mounted\n");
      return init::FS_NOT_MOUNTED;
    }
    LockScope locked;
    out_dec("[fs]       mounted: ", s_entries[ROOT_QUOTA].used / 1024,
            " KiB used of ");
    out_dec("", s_entries[ROOT_QUOTA].limit / 1024, " KiB\n");
    return init::FS_OK;
  }
  s_first_call_done = true;

  s_self_comp = rw[compartment::SLOT_SELF];
  s_vm_quota = rw[SLOT_VM_QUOTA];
  s_seal_file = rw[SLOT_SEAL_FILE];
  s_seal_dir = rw[SLOT_SEAL_DIR];
  s_seal_quota = rw[SLOT_SEAL_QUOTA];
  Capability gate_sentry = rw[SLOT_SYS_SENTRY];
  s_gate_alloc = rw[SLOT_SYS_VM_ALLOC];
  s_gate_dealloc = rw[SLOT_SYS_VM_DEALLOC];
  s_blk_read = rw[SLOT_BLK_READ];
  s_blk_write = rw[SLOT_BLK_WRITE];

  const auto seal_and_unseal = perms::Seal | perms::Unseal;
  if (!sealing::is_sealed_as(OType::Compartment, s_self_comp) ||
      !sealing::is_sealed_as(OType::QuotaVm, s_vm_quota) ||
      !capability_has_perms(s_seal_file, seal_and_unseal) ||
      !capability_has_perms(s_seal_dir, seal_and_unseal) ||
      !capability_has_perms(s_seal_quota, seal_and_unseal)) {
    out("[fs]       missing seeds; file system disabled\n");
    return init::FS_BAD_REQUEST;
  }
  if (!capability_is_valid(arg) || sealing::is_sealed(arg) ||
      !capability_has_perms(arg, perms::Load | perms::Store) ||
      capability_get_length(arg) != sizeof(init::FsInterface)) {
    out("[fs]       no FsInterface handshake; file system disabled\n");
    return init::FS_BAD_REQUEST;
  }
  auto* iface = static_cast<init::FsInterface*>(arg);
  iface->root_dir = nullptr;
  iface->root_quota = nullptr;
  iface->total_bytes = 0;
  iface->used_bytes = 0;
  iface->formatted = 0;
  iface->status = init::FS_NOT_MOUNTED;

  // 1. Entry points, even if the mount fails (callers then get NOT_MOUNTED).
  auto address = [](auto* function) {
    return reinterpret_cast<const void*>(function);
  };
  const void* const entry_points[init::FS_CALLS] = {
      address(&fs_close_entry),  address(&fs_open_entry),
      address(&fs_create_entry), address(&fs_quota_entry),
      address(&fs_read_entry),   address(&fs_write_entry),
      address(&fs_list_entry),   address(&fs_remove_entry),
      address(&fs_move_entry),   address(&fs_freeze_entry),
      address(&fs_stat_entry),   address(&fs_link_entry)};
  for (uint32_t i = 0; i < init::FS_CALLS; ++i) {
    iface->call[i] =
        mint_entry(s_gate_invoke, gate_sentry, s_self_comp, entry_points[i]);
  }

  // 2. The disk.
  if (iface->capacity_sectors == 0 || !capability_is_valid(s_blk_read) ||
      !capability_is_valid(s_blk_write)) {
    out("[fs]       no block device; file system not mounted\n");
    return iface->status;
  }
  uint32_t formatted = 0;
  const int64_t status = mount(iface->capacity_sectors, &formatted);
  if (status != init::FS_OK) {
    out_dec("[fs]       mount failed, status -", static_cast<uint64_t>(-status),
            "; file system not mounted\n");
    iface->status = status;
    return iface->status;
  }

  // 3. `/` and the root quota for init, paid for by `memory_quota`: every
  //    other handle is opened through these two.
  iface->root_dir = make_handle(nullptr, ROOT_DIR, init::FS_ALL | init::FS_LINK,
                                iface->memory_quota);
  iface->root_quota = make_handle(nullptr, ROOT_QUOTA,
                                  init::FS_ALL | init::FS_LINK,
                                  iface->memory_quota);
  if (!capability_is_valid(iface->root_dir) ||
      !capability_is_valid(iface->root_quota)) {
    out("[fs]       no memory for init's handles; file system not mounted\n");
    iface->status = init::FS_NO_MEMORY;
    return iface->status;
  }
  s_mounted = true;
  iface->total_bytes = s_entries[ROOT_QUOTA].limit;
  iface->used_bytes = s_entries[ROOT_QUOTA].used;
  iface->formatted = formatted;
  iface->status = init::FS_OK;

  out_dec(formatted ? "[fs]       Formatted and mounted: " : "[fs]       Mounted: ",
          iface->total_bytes / 1024, " KiB, ");
  out_dec("", iface->used_bytes / 1024, " KiB used\n");
  return iface->status;
}

}  // namespace signetos::user
