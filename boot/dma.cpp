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
 * dma.cpp - SignetOS DMA Compartment
 *
 * Without an IOMMU a device reaches whatever physical address it is given, so
 * whoever writes those addresses can reach all of RAM. This compartment is
 * the only one that does. `init` calls it once, before `blk`, and it is never
 * entered again:
 *   1. it finds the virtio-blk device, resets it, and accepts
 *      VIRTIO_F_VERSION_1 and nothing else: no indirect descriptors, no
 *      packed ring, no queue but queue 0;
 *   2. it writes a fixed descriptor table into the first page of the DMA
 *      arena and points queue 0 at it and at the rings;
 *   3. it hands back, for `blk`, two capabilities that reach neither, and
 *      the disk's size.
 *
 * THE ARENA (DMA_ARENA_BYTES, FLAG_DMA: physically contiguous, and its
 * physical base in its first word when it arrives)
 *   0x0000  descriptor table, 4 x 16 B   only this compartment writes it
 *   0x1000  avail ring                   <- `blk`'s view (`buf`) starts here
 *   0x1100  used ring
 *   0x1ff0  request header, 16 B
 *   0x2000  data, 4 KiB
 *   0x3000  status, 1 B
 * Header, data and status sit back to back, so a request is one run of bytes
 * and two descriptors cover each direction (virtio 1.x lets a request be cut
 * anywhere between its device-readable and device-writable parts):
 *   0  header            device reads    -> 1     a read starts here
 *   1  data + status     device writes
 *   2  header + data     device reads    -> 3     a write starts here
 *   3  status            device writes
 * `blk` starts a request by putting 0 or 2 in the avail ring
 * (DMA_CHAIN_READ, DMA_CHAIN_WRITE). Any other number names half a chain or
 * none, and the device refuses it.
 *
 * WHY THIS IS ENOUGH
 *   With only VERSION_1 negotiated and only queue 0 ready, the device takes
 *   memory addresses from two places: queue 0's address registers and the
 *   descriptor table. Both are written here, once. `blk` cannot reach either:
 *   its view of the arena starts a page in, and its writable view of the
 *   registers is QUEUE_NOTIFY, INTERRUPT_STATUS and INTERRUPT_ACK -- not
 *   status (so no reset, after which queue 0 could be made ready with no
 *   addresses), not features, not queue select or ready, not the addresses.
 *   What `blk` does write -- header, data, ring indices -- holds no memory
 *   address; the most it can make the device do is overwrite `blk`'s own
 *   pages. Its views carry no capability permissions, so nothing tagged
 *   passes through them.
 */

#include "runtime.hpp"

namespace signetos::user {
namespace {

// --- What `dma` asks `init` for (user/manifest.hpp) ---------------------------
// The virtio window and the arena are optional: without them nothing is set
// up, `blk` reports BLK_NO_DEVICE and the file system stays unmounted.
#define DMA_MANIFEST(X)                                  \
  M_MMIO_OPT(X, VIRTIO_MMIO, "virtio")                   \
  M_DMA_OPT(X, DMA_ARENA, init::DMA_ARENA_BYTES)         \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)      \
  M_SERVICE(X, UART_SENTRY, "uart")
SIGNETOS_MANIFEST(DMA_MANIFEST, 64 * 1024)

// --- virtio-mmio (modern, version 2) registers ---------------------------------
constexpr size_t R_MAGIC               = 0x000;
constexpr size_t R_VERSION             = 0x004;
constexpr size_t R_DEVICE_ID           = 0x008;
constexpr size_t R_DEVICE_FEATURES     = 0x010;
constexpr size_t R_DEVICE_FEATURES_SEL = 0x014;
constexpr size_t R_DRIVER_FEATURES     = 0x020;
constexpr size_t R_DRIVER_FEATURES_SEL = 0x024;
constexpr size_t R_QUEUE_SEL           = 0x030;
constexpr size_t R_QUEUE_NUM_MAX       = 0x034;
constexpr size_t R_QUEUE_NUM           = 0x038;
constexpr size_t R_QUEUE_READY         = 0x044;
constexpr size_t R_STATUS              = 0x070;
constexpr size_t R_QUEUE_DESC_LOW      = 0x080;
constexpr size_t R_QUEUE_DESC_HIGH     = 0x084;
constexpr size_t R_QUEUE_DRIVER_LOW    = 0x090;
constexpr size_t R_QUEUE_DRIVER_HIGH   = 0x094;
constexpr size_t R_QUEUE_DEVICE_LOW    = 0x0a0;
constexpr size_t R_QUEUE_DEVICE_HIGH   = 0x0a4;
constexpr size_t R_CONFIG              = 0x100;  // virtio_blk_config: capacity le64
constexpr size_t SLOT_MIN_BYTES        = R_CONFIG + 8;

constexpr uint32_t MAGIC_VIRT     = 0x74726976;  // "virt"
constexpr uint32_t VERSION_MODERN = 2;
constexpr uint32_t DEVICE_ID_BLK  = 2;

constexpr uint32_t STATUS_ACKNOWLEDGE = 1;
constexpr uint32_t STATUS_DRIVER      = 2;
constexpr uint32_t STATUS_DRIVER_OK   = 4;
constexpr uint32_t STATUS_FEATURES_OK = 8;
constexpr uint32_t STATUS_FAILED      = 128;

// Feature bit 32 (VIRTIO_F_VERSION_1) is bit 0 of the high selector word.
constexpr uint32_t FEATURE_HI_VERSION_1 = 1u << 0;

// --- The arena (file comment) -------------------------------------------------
struct VirtqDesc {
  uint64_t addr;
  uint32_t len;
  uint16_t flags;
  uint16_t next;
};
static_assert(sizeof(VirtqDesc) == 16);
constexpr uint16_t DESC_F_NEXT  = 1;
constexpr uint16_t DESC_F_WRITE = 2;  // device writes this buffer

constexpr size_t PAGE   = 4096;
constexpr size_t A_BUF  = PAGE;  // where `blk`'s view starts
constexpr size_t HEADER = A_BUF + init::DMA_BUF_HEADER;
constexpr size_t DATA   = A_BUF + init::DMA_BUF_DATA;
constexpr size_t STATUS = A_BUF + init::DMA_BUF_STATUS;
constexpr uint32_t HEADER_BYTES = 16;
static_assert(HEADER + HEADER_BYTES == DATA && DATA + init::BLK_XFER_BYTES == STATUS,
              "a request must be one run of bytes");
static_assert(STATUS < init::DMA_ARENA_BYTES);
static_assert(init::DMA_CHAIN_READ == 0 && init::DMA_CHAIN_WRITE == 2);

// --- state -----------------------------------------------------------------------
Capability s_gate_invoke = nullptr;
Capability s_uart = nullptr;
bool s_called = false;

inline void fence() { __asm__ volatile("fence rw, rw" ::: "memory"); }

void out(const char* msg) { print(s_gate_invoke, s_uart, msg); }

// The first slot in `window` holding a modern virtio-blk device, as a
// capability to the whole slot, or null.
Capability find_device(Capability window, uint64_t slot_bytes, uint32_t count,
                       uint32_t* out_slot) {
  if (!capability_is_valid(window) || slot_bytes < SLOT_MIN_BYTES) {
    return nullptr;
  }
  const uint64_t base = capability_get_base(window);
  const uint64_t len = capability_get_length(window);
  for (uint32_t slot = 0; slot < count; ++slot) {
    const uint64_t off = static_cast<uint64_t>(slot) * slot_bytes;
    if (off + slot_bytes > len) {
      break;
    }
    Capability c = capability_set_bounds(
        capability_set_address(window, base + off), slot_bytes);
    const auto* r = reinterpret_cast<const volatile uint32_t*>(c);
    if (r[R_MAGIC / 4] == MAGIC_VIRT && r[R_DEVICE_ID / 4] == DEVICE_ID_BLK) {
      if (r[R_VERSION / 4] != VERSION_MODERN) {
        out("[dma]      virtio-blk found with the legacy transport only; run "
            "QEMU with -global virtio-mmio.force-legacy=false\n");
        return nullptr;
      }
      *out_slot = slot;
      return c;
    }
  }
  return nullptr;
}

void set_desc(volatile VirtqDesc* d, uint64_t addr, uint64_t len,
              uint16_t flags, uint16_t next) {
  d->addr = addr;
  d->len = static_cast<uint32_t>(len);
  d->flags = flags;
  d->next = next;
}

// Resets the device and brings it up with VERSION_1 as its only feature and
// queue 0 on the table `pa` is the arena's physical base for (file comment).
// False, with the device left FAILED, if it refuses any step.
bool start_device(volatile uint32_t* r, volatile VirtqDesc* table,
                  uint64_t pa) {
  r[R_STATUS / 4] = 0;  // reset; done when it reads back 0
  while (r[R_STATUS / 4] != 0) {
  }
  r[R_STATUS / 4] = STATUS_ACKNOWLEDGE;
  r[R_STATUS / 4] = STATUS_ACKNOWLEDGE | STATUS_DRIVER;

  r[R_DEVICE_FEATURES_SEL / 4] = 1;
  if ((r[R_DEVICE_FEATURES / 4] & FEATURE_HI_VERSION_1) == 0) {
    r[R_STATUS / 4] = STATUS_FAILED;
    return false;
  }
  r[R_DRIVER_FEATURES_SEL / 4] = 0;
  r[R_DRIVER_FEATURES / 4] = 0;
  r[R_DRIVER_FEATURES_SEL / 4] = 1;
  r[R_DRIVER_FEATURES / 4] = FEATURE_HI_VERSION_1;
  r[R_STATUS / 4] = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK;
  if ((r[R_STATUS / 4] & STATUS_FEATURES_OK) == 0) {
    r[R_STATUS / 4] = STATUS_FAILED;
    return false;
  }

  r[R_QUEUE_SEL / 4] = 0;
  if (r[R_QUEUE_NUM_MAX / 4] < init::DMA_QUEUE_SIZE ||
      r[R_QUEUE_READY / 4] != 0) {
    r[R_STATUS / 4] = STATUS_FAILED;
    return false;
  }

  // The two chains (file comment). The rest of the arena is zero: empty rings.
  set_desc(&table[0], pa + HEADER, HEADER_BYTES, DESC_F_NEXT, 1);
  set_desc(&table[1], pa + DATA, init::BLK_XFER_BYTES + 1, DESC_F_WRITE, 0);
  set_desc(&table[2], pa + HEADER, HEADER_BYTES + init::BLK_XFER_BYTES,
           DESC_F_NEXT, 3);
  set_desc(&table[3], pa + STATUS, 1, DESC_F_WRITE, 0);

  const uint64_t avail = pa + A_BUF + init::DMA_BUF_AVAIL;
  const uint64_t used = pa + A_BUF + init::DMA_BUF_USED;
  r[R_QUEUE_NUM / 4] = init::DMA_QUEUE_SIZE;
  r[R_QUEUE_DESC_LOW / 4] = static_cast<uint32_t>(pa);
  r[R_QUEUE_DESC_HIGH / 4] = static_cast<uint32_t>(pa >> 32);
  r[R_QUEUE_DRIVER_LOW / 4] = static_cast<uint32_t>(avail);
  r[R_QUEUE_DRIVER_HIGH / 4] = static_cast<uint32_t>(avail >> 32);
  r[R_QUEUE_DEVICE_LOW / 4] = static_cast<uint32_t>(used);
  r[R_QUEUE_DEVICE_HIGH / 4] = static_cast<uint32_t>(used >> 32);
  fence();
  r[R_QUEUE_READY / 4] = 1;
  r[R_STATUS / 4] = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK |
                    STATUS_DRIVER_OK;
  return true;
}

}  // namespace

SIGNETOS_DEFAULT_FAULT_HANDLER("dma")

// Once, from `init`, with a writable `DmaInterface` (abi.hpp). Any later call,
// from anyone, gets nothing.
extern "C" int64_t compartment_main(Capability arg) {
  Capability* rw = rw_table();
  s_gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  s_uart = rw[SLOT_UART_SENTRY];
  if (s_called) {
    return init::BLK_BAD_REQUEST;
  }
  s_called = true;
  if (!capability_is_valid(arg) || sealing::is_sealed(arg) ||
      !capability_has_perms(arg, perms::Load | perms::Store) ||
      capability_get_length(arg) != sizeof(init::DmaInterface)) {
    return init::BLK_BAD_REQUEST;
  }
  auto* iface = reinterpret_cast<init::DmaInterface*>(arg);
  iface->buf = nullptr;
  iface->notify = nullptr;
  iface->capacity_sectors = 0;
  iface->slot = 0;
  iface->status = init::BLK_NO_DEVICE;

  Capability arena = rw[SLOT_DMA_ARENA];
  if (!capability_is_valid(arena) ||
      !capability_has_perms(arena, perms::Load | perms::Store) ||
      capability_get_length(arena) < init::DMA_ARENA_BYTES) {
    out("[dma]      no DMA arena; block device disabled\n");
    return iface->status;
  }
  const uint64_t arena_base = capability_get_base(arena);
  auto* bytes = reinterpret_cast<volatile uint8_t*>(
      capability_set_address(arena, arena_base));
  const uint64_t pa = *reinterpret_cast<volatile uint64_t*>(bytes);
  if (pa == 0 || (pa & (PAGE - 1)) != 0) {
    out("[dma]      the DMA arena has no physical base; block device disabled\n");
    return iface->status;
  }
  for (size_t i = 0; i < init::DMA_ARENA_BYTES; ++i) {
    bytes[i] = 0;  // the base goes; the rings start empty
  }

  uint32_t slot = 0;
  Capability dev = find_device(rw[SLOT_VIRTIO_MMIO], iface->virtio_slot_bytes,
                               iface->virtio_count, &slot);
  if (!capability_is_valid(dev)) {
    out("[dma]      no virtio-blk device found; block device disabled\n");
    return iface->status;
  }
  auto* regs = reinterpret_cast<volatile uint32_t*>(dev);
  if (!start_device(regs, reinterpret_cast<volatile VirtqDesc*>(bytes), pa)) {
    out("[dma]      virtio-blk refused initialisation; block device disabled\n");
    return iface->status;
  }

  // `blk`'s two views (file comment, WHY THIS IS ENOUGH).
  const uint64_t dev_base = capability_get_base(dev);
  Capability buf = capability_set_bounds(
      capability_set_address(arena, arena_base + A_BUF),
      init::DMA_ARENA_BYTES - A_BUF);
  Capability notify = capability_set_bounds(
      capability_set_address(dev, dev_base + init::DMA_NOTIFY_BASE),
      init::DMA_NOTIFY_BYTES);
  // Exactly these bounds, or nothing: a rounded-up view could reach the
  // descriptor table or the queue registers.
  if (capability_get_base(buf) != arena_base + A_BUF ||
      capability_get_length(buf) != init::DMA_ARENA_BYTES - A_BUF ||
      capability_get_base(notify) != dev_base + init::DMA_NOTIFY_BASE ||
      capability_get_length(notify) != init::DMA_NOTIFY_BYTES) {
    regs[R_STATUS / 4] = STATUS_FAILED;
    out("[dma]      could not bound the views for blk; block device disabled\n");
    return iface->status;
  }
  iface->buf = capability_and_perms(buf, perms::Load | perms::Store);
  iface->notify = capability_and_perms(notify, perms::Load | perms::Store);
  iface->capacity_sectors = static_cast<uint64_t>(regs[R_CONFIG / 4]) |
                            (static_cast<uint64_t>(regs[R_CONFIG / 4 + 1]) << 32);
  iface->slot = slot;
  iface->status = init::BLK_OK;
  out("[dma]      virtio-blk queue fixed to the DMA arena\n");
  return iface->status;
}

}  // namespace signetos::user
