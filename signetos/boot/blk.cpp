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
 * blk.cpp - SignetOS virtio-blk Driver Compartment
 *
 * Holds two capabilities nobody else has: the virtio-mmio slot window
 * (`BootManifest::virtio_mmio`, QEMU `virt`: eight 4 KiB slots from
 * 0x10001000) and the DMA arena the kernel set aside at boot
 * (`BootManifest::dma_window`, physically contiguous, its physical base
 * handed over in the `BlkInterface` handshake). Drives one virtio-blk device
 * over the modern (version 2) MMIO transport.
 *
 * Three entry points (see `BlkInterface` in abi.hpp), minted once on the
 * first invocation of `compartment_main`, exactly like `uart`:
 *   blk_read_entry(req)    copies `count` sectors from the device into
 *                          `req->buf`.
 *   blk_write_entry(req)   the other way round.
 *   blk_irq_entry(event)   the device's PLIC source fired: acknowledge it and
 *                          wake whichever thread is waiting for its request.
 *                          `trap_mgr` invokes this from interrupt context.
 *
 * WHY A BOUNCE BUFFER
 *   The device only ever sees physical addresses inside the arena: the
 *   virtqueue rings, a request header, a status byte, and one 4 KiB data
 *   buffer. A caller's buffer is copied in or out, so no caller memory is
 *   ever exposed to the device, and the driver never needs to know a
 *   physical address for anything but the arena. That is what makes the
 *   kernel side a one-time boot-time allocation instead of a translation
 *   syscall.
 *
 * ONE REQUEST AT A TIME
 *   A request is a three-descriptor chain (header, data, status) placed in
 *   the available ring, then a notify. Completion is a new entry in the used
 *   ring. While it is in flight the calling thread sleeps in `sched.block`;
 *   `blk_irq_entry` wakes it by tid. The wait loop re-checks the used ring
 *   after every return from `block`, so a wake that arrives early (or a
 *   spurious one) costs a trip round the loop and nothing else.
 *
 *   A wake can also fail to arrive: `sched.wake` is a compartment call made
 *   from interrupt context on the interrupted thread's kernel stack, and the
 *   switcher refuses it when that stack has no room (SPEC_CHANGE_NOTES.md
 *   H23 has the case that hung the system). So the waiter never sleeps
 *   without a bound: it blocks for at most WAIT_TIMEOUT_US at a time and
 *   looks at the used ring again, and a lost wake costs that much and no
 *   more. The interrupt entry checks what `wake` said and counts the
 *   refusals; the waiter reports the first one on the console, since it is
 *   a sign that some caller is running deeper than the system allows for.
 *   Until the
 *   first interrupt has been seen -- or when the caller is not a scheduled
 *   thread, such as `init` mounting the disk -- the loop polls instead, so a
 *   missing interrupt route degrades to polling rather than a hang.
 *
 * BEFORE THERE IS A SCHEDULER
 *   `blk` is in the boot set: `sched` and `trap_mgr` are files on the disk it
 *   serves, so at its handshake there is nothing to look up and no interrupt
 *   route. Every request polls until `init` has loaded the scheduler and
 *   hands over its entries in a second call (`BlkSchedRequest`), and until
 *   `trap_mgr` is up and the device's interrupt is routed here.
 */

#include "runtime.hpp"

namespace signetos::user {
namespace {

// --- What `blk` asks `init` for (user/manifest.hpp) ---------------------------
// The virtio slot window and a DMA arena are optional: on a machine without
// them the driver still comes up and reports BLK_NO_DEVICE, and the file
// system reports itself unmounted. 64 KiB of arena is far more than the rings,
// one request and one 4 KiB bounce buffer need (ARENA_MIN below); the rest is
// room to grow the queue.
#define BLK_MANIFEST(X)                                  \
  M_MMIO_OPT(X, VIRTIO_MMIO, "virtio")                   \
  M_DMA_OPT(X, DMA_WINDOW, 64 * 1024)                    \
  M_SYSCALL(X, SYS_SENTRY, sentry)                       \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)      \
  M_SERVICE(X, UART_SENTRY, "uart")
SIGNETOS_MANIFEST(BLK_MANIFEST, 64 * 1024)
// Runtime slots: the three entry points minted in the handshake.
constexpr size_t SLOT_READ_ENTRY  = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 0;
constexpr size_t SLOT_WRITE_ENTRY = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 1;
constexpr size_t SLOT_IRQ_ENTRY   = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 2;

// --- virtio-mmio (modern) register offsets, in bytes ---------------------------
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
constexpr size_t R_QUEUE_NOTIFY        = 0x050;
constexpr size_t R_INTERRUPT_STATUS    = 0x060;
constexpr size_t R_INTERRUPT_ACK       = 0x064;
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

// --- split virtqueue ------------------------------------------------------------
constexpr uint16_t QUEUE_SIZE = 8;  // power of two; a request uses three
constexpr uint16_t DESC_F_NEXT  = 1;
constexpr uint16_t DESC_F_WRITE = 2;  // device writes this buffer

constexpr uint32_t BLK_T_IN  = 0;  // device -> memory (read)
constexpr uint32_t BLK_T_OUT = 1;  // memory -> device (write)
constexpr uint8_t  BLK_S_OK  = 0;
constexpr uint8_t  STATUS_POISON = 0xff;

struct VirtqDesc {
  uint64_t addr;
  uint32_t len;
  uint16_t flags;
  uint16_t next;
};
struct VirtqAvail {
  uint16_t flags;
  uint16_t idx;
  uint16_t ring[QUEUE_SIZE];
  uint16_t used_event;
};
struct VirtqUsedElem {
  uint32_t id;
  uint32_t len;
};
struct VirtqUsed {
  uint16_t flags;
  uint16_t idx;
  VirtqUsedElem ring[QUEUE_SIZE];
  uint16_t avail_event;
};
struct BlkReqHeader {
  uint32_t type;
  uint32_t reserved;
  uint64_t sector;
};
static_assert(sizeof(VirtqDesc) == 16);
static_assert(sizeof(BlkReqHeader) == 16);

// Layout of the DMA arena. Everything the device touches lives here.
constexpr size_t OFF_DESC   = 0x000;  // 16 * QUEUE_SIZE bytes, 16-aligned
constexpr size_t OFF_AVAIL  = 0x100;  // 6 + 2 * QUEUE_SIZE bytes, 2-aligned
constexpr size_t OFF_USED   = 0x200;  // 6 + 8 * QUEUE_SIZE bytes, 4-aligned
constexpr size_t OFF_HEADER = 0x300;
constexpr size_t OFF_STATUS = 0x310;
constexpr size_t OFF_DATA   = 0x1000;
constexpr size_t ARENA_MIN  = OFF_DATA + init::BLK_MAX_XFER_BYTES;
static_assert(OFF_DESC + sizeof(VirtqDesc) * QUEUE_SIZE <= OFF_AVAIL);
static_assert(OFF_AVAIL + sizeof(VirtqAvail) <= OFF_USED);
static_assert(OFF_USED + sizeof(VirtqUsed) <= OFF_HEADER);

// --- state -----------------------------------------------------------------------
Capability s_gate_invoke = nullptr;
Capability s_uart = nullptr;
Capability s_sched_block = nullptr;
Capability s_sched_wake = nullptr;
Capability s_sched_self = nullptr;

volatile uint32_t* s_regs = nullptr;  // the chosen slot's registers
uint8_t* s_dma = nullptr;             // the arena, as the driver sees it
uint64_t s_dma_phys = 0;              // ... and as the device sees it
uint64_t s_capacity = 0;              // sectors
uint32_t s_slot = 0;
bool s_present = false;
bool s_busy = false;
bool s_first_call_done = false;
uint16_t s_last_used = 0;             // used-ring entries consumed so far

// The thread waiting for the in-flight request (0: nobody, or not a
// scheduled thread), and how many interrupts have ever reached us.
volatile uint64_t s_waiter_tid = 0;
volatile uint32_t s_irq_count = 0;

// Wakes `blk_irq_entry` could not deliver (the call refused, or `wake` said
// no), and how many of them the waiter has already reported.
volatile uint32_t s_wakes_lost = 0;
uint32_t s_wakes_reported = 0;

// The longest the waiter sleeps before it looks at the used ring itself; a
// request completes in well under this, so it only matters when a wake was
// lost.
constexpr uint64_t WAIT_TIMEOUT_US = 10'000;

inline void fence() { __asm__ volatile("fence rw, rw" ::: "memory"); }

inline uint32_t reg_read(size_t off) { return s_regs[off / 4]; }
inline void reg_write(size_t off, uint32_t v) { s_regs[off / 4] = v; }

template <typename T>
Capability bounded(T* p) {
  return capability_set_bounds(reinterpret_cast<Capability>(p), sizeof(T));
}

void out(const char* msg) { print(s_gate_invoke, s_uart, msg); }
void out_dec(const char* p, uint64_t v, const char* s) {
  print_dec(s_gate_invoke, s_uart, p, v, s);
}

inline uint64_t arena_phys(size_t off) { return s_dma_phys + off; }

volatile VirtqDesc* descs() {
  return reinterpret_cast<volatile VirtqDesc*>(s_dma + OFF_DESC);
}
volatile VirtqAvail* avail() {
  return reinterpret_cast<volatile VirtqAvail*>(s_dma + OFF_AVAIL);
}
volatile VirtqUsed* used() {
  return reinterpret_cast<volatile VirtqUsed*>(s_dma + OFF_USED);
}
volatile BlkReqHeader* header() {
  return reinterpret_cast<volatile BlkReqHeader*>(s_dma + OFF_HEADER);
}
volatile uint8_t* status_byte() { return s_dma + OFF_STATUS; }
uint8_t* data() { return s_dma + OFF_DATA; }

// Finds the first slot in `window` holding a modern virtio-blk device.
// Returns false (and leaves `s_regs` null) if there is none.
bool probe(Capability window, uint64_t slot_bytes, uint32_t count) {
  if (!capability_is_valid(window) || slot_bytes < SLOT_MIN_BYTES) {
    return false;
  }
  const uint64_t base = capability_get_base(window);
  const uint64_t len = capability_get_length(window);
  bool saw_legacy = false;
  for (uint32_t slot = 0; slot < count; ++slot) {
    const uint64_t off = static_cast<uint64_t>(slot) * slot_bytes;
    if (off + slot_bytes > len) {
      break;
    }
    Capability c = capability_set_address(window, base + off);
    c = capability_set_bounds(c, slot_bytes);
    if (!capability_is_valid(c)) {
      break;
    }
    auto* regs = reinterpret_cast<volatile uint32_t*>(c);
    if (regs[R_MAGIC / 4] != MAGIC_VIRT) {
      continue;
    }
    if (regs[R_DEVICE_ID / 4] != DEVICE_ID_BLK) {
      continue;  // empty slot (0) or some other device
    }
    if (regs[R_VERSION / 4] != VERSION_MODERN) {
      saw_legacy = true;
      continue;
    }
    s_regs = regs;
    s_slot = slot;
    return true;
  }
  if (saw_legacy) {
    out("[blk]      virtio-blk found with the legacy transport only; run QEMU "
        "with -global virtio-mmio.force-legacy=false\n");
  }
  return false;
}

// virtio 1.x initialisation (spec 3.1.1) with VIRTIO_F_VERSION_1 as the only
// feature, then one split queue in the arena. Returns false if the device
// refuses at any step; the device is then left FAILED.
bool init_device() {
  reg_write(R_STATUS, 0);  // reset
  reg_write(R_STATUS, STATUS_ACKNOWLEDGE);
  reg_write(R_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

  reg_write(R_DEVICE_FEATURES_SEL, 1);
  const uint32_t features_hi = reg_read(R_DEVICE_FEATURES);
  if ((features_hi & FEATURE_HI_VERSION_1) == 0) {
    reg_write(R_STATUS, STATUS_FAILED);
    return false;
  }
  reg_write(R_DRIVER_FEATURES_SEL, 0);
  reg_write(R_DRIVER_FEATURES, 0);
  reg_write(R_DRIVER_FEATURES_SEL, 1);
  reg_write(R_DRIVER_FEATURES, FEATURE_HI_VERSION_1);

  reg_write(R_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
  if ((reg_read(R_STATUS) & STATUS_FEATURES_OK) == 0) {
    reg_write(R_STATUS, STATUS_FAILED);
    return false;
  }

  // Queue 0: rings zeroed (the arena came zeroed, but a re-handshake must
  // not inherit stale indices), then their physical addresses programmed.
  for (size_t i = 0; i < OFF_HEADER; ++i) {
    s_dma[i] = 0;
  }
  s_last_used = 0;
  reg_write(R_QUEUE_SEL, 0);
  const uint32_t num_max = reg_read(R_QUEUE_NUM_MAX);
  if (num_max == 0 || num_max < QUEUE_SIZE || reg_read(R_QUEUE_READY) != 0) {
    reg_write(R_STATUS, STATUS_FAILED);
    return false;
  }
  reg_write(R_QUEUE_NUM, QUEUE_SIZE);
  const uint64_t desc_pa = arena_phys(OFF_DESC);
  const uint64_t avail_pa = arena_phys(OFF_AVAIL);
  const uint64_t used_pa = arena_phys(OFF_USED);
  reg_write(R_QUEUE_DESC_LOW, static_cast<uint32_t>(desc_pa));
  reg_write(R_QUEUE_DESC_HIGH, static_cast<uint32_t>(desc_pa >> 32));
  reg_write(R_QUEUE_DRIVER_LOW, static_cast<uint32_t>(avail_pa));
  reg_write(R_QUEUE_DRIVER_HIGH, static_cast<uint32_t>(avail_pa >> 32));
  reg_write(R_QUEUE_DEVICE_LOW, static_cast<uint32_t>(used_pa));
  reg_write(R_QUEUE_DEVICE_HIGH, static_cast<uint32_t>(used_pa >> 32));
  fence();
  reg_write(R_QUEUE_READY, 1);

  reg_write(R_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK |
                          STATUS_DRIVER_OK);

  const uint64_t cap_lo = reg_read(R_CONFIG + 0);
  const uint64_t cap_hi = reg_read(R_CONFIG + 4);
  s_capacity = cap_lo | (cap_hi << 32);
  return true;
}

// The calling thread's tid, or 0 if it is not running under the scheduler.
uint64_t self_tid() {
  if (!capability_is_valid(s_sched_self)) {
    return 0;
  }
  using FnInvoke = decltype(&sys_compartment_invoke);
  init::SchedSelfRequest req{};
  req.status = init::SCHED_INVALID_THREAD;
  reinterpret_cast<FnInvoke>(s_gate_invoke)(s_sched_self, bounded(&req));
  return req.status == init::SCHED_OK ? req.out_tid : 0;
}

// Sleeps until woken or WAIT_TIMEOUT_US, whichever is first.
void block() {
  using FnInvoke = decltype(&sys_compartment_invoke);
  init::SchedBlockRequest req{};
  req.timeout_us = WAIT_TIMEOUT_US;
  req.status = init::SCHED_BAD_REQUEST;
  reinterpret_cast<FnInvoke>(s_gate_invoke)(s_sched_block, bounded(&req));
}

// Submits one request and waits for it. `type` is BLK_T_IN or BLK_T_OUT; the
// data goes through the arena's data buffer, which the caller has filled
// (OUT) or will drain (IN). Returns BLK_OK or BLK_IO_ERROR.
int64_t transfer(uint32_t type, uint64_t sector, uint32_t bytes) {
  volatile BlkReqHeader* h = header();
  h->type = type;
  h->reserved = 0;
  h->sector = sector;
  *status_byte() = STATUS_POISON;

  volatile VirtqDesc* d = descs();
  d[0].addr = arena_phys(OFF_HEADER);
  d[0].len = sizeof(BlkReqHeader);
  d[0].flags = DESC_F_NEXT;
  d[0].next = 1;
  d[1].addr = arena_phys(OFF_DATA);
  d[1].len = bytes;
  d[1].flags = static_cast<uint16_t>(DESC_F_NEXT |
                                     (type == BLK_T_IN ? DESC_F_WRITE : 0));
  d[1].next = 2;
  d[2].addr = arena_phys(OFF_STATUS);
  d[2].len = 1;
  d[2].flags = DESC_F_WRITE;
  d[2].next = 0;

  // Whom to wake, recorded before the device can possibly complete.
  const uint64_t tid = self_tid();
  s_waiter_tid = tid;

  volatile VirtqAvail* av = avail();
  const uint16_t idx = av->idx;
  av->ring[idx % QUEUE_SIZE] = 0;  // the chain starts at descriptor 0
  fence();
  av->idx = static_cast<uint16_t>(idx + 1);
  fence();
  reg_write(R_QUEUE_NOTIFY, 0);

  // Sleep until the used ring moves. Polling instead if we are not a
  // scheduled thread or no interrupt has ever arrived (no route).
  volatile VirtqUsed* us = used();
  for (;;) {
    fence();
    if (us->idx != s_last_used) {
      break;
    }
    if (tid != 0 && s_irq_count > 0 && capability_is_valid(s_sched_block)) {
      block();
    } else {
      __asm__ volatile("" ::: "memory");
    }
  }
  s_waiter_tid = 0;
  if (s_wakes_lost != s_wakes_reported) {
    if (s_wakes_reported == 0) {
      out("[blk]      WARNING: a completion wake was refused; "
          "the request finished on the wait timeout\n");
    }
    s_wakes_reported = s_wakes_lost;
  }
  const VirtqUsedElem done = {us->ring[s_last_used % QUEUE_SIZE].id,
                              us->ring[s_last_used % QUEUE_SIZE].len};
  s_last_used = static_cast<uint16_t>(s_last_used + 1);
  fence();
  if (done.id != 0 || *status_byte() != BLK_S_OK) {
    return init::BLK_IO_ERROR;
  }
  return init::BLK_OK;
}

// Shared by read and write: validates the request and moves the data through
// the bounce buffer.
void handle(Capability arg, uint32_t type) {
  if (!capability_is_valid(arg) || sealing::is_sealed(arg) ||
      !capability_has_perms(arg, perms::Load | perms::Store) ||
      capability_get_length(arg) < sizeof(init::BlkRequest)) {
    return;
  }
  auto* req = reinterpret_cast<init::BlkRequest*>(arg);
  if (!s_present) {
    req->status = init::BLK_NO_DEVICE;
    return;
  }
  const uint64_t bytes = req->count * init::BLK_SECTOR_BYTES;
  if (req->count == 0 || bytes > init::BLK_MAX_XFER_BYTES) {
    req->status = init::BLK_BAD_REQUEST;
    return;
  }
  if (req->sector >= s_capacity || req->count > s_capacity - req->sector) {
    req->status = init::BLK_OUT_OF_RANGE;
    return;
  }
  Capability buf = req->buf;
  const uint64_t need = (type == BLK_T_IN) ? perms::Store : perms::Load;
  if (!capability_is_valid(buf) || sealing::is_sealed(buf) ||
      !capability_has_perms(buf, need)) {
    req->status = init::BLK_BAD_REQUEST;
    return;
  }
  const uint64_t end = capability_get_base(buf) + capability_get_length(buf);
  const uint64_t addr = capability_get_address(buf);
  if (end < addr || end - addr < bytes) {
    req->status = init::BLK_BAD_REQUEST;
    return;
  }
  if (s_busy) {
    req->status = init::BLK_BUSY;
    return;
  }
  s_busy = true;

  auto* user = reinterpret_cast<uint8_t*>(buf);
  uint8_t* bounce = data();
  if (type == BLK_T_OUT) {
    for (uint64_t i = 0; i < bytes; ++i) {
      bounce[i] = user[i];
    }
  }
  const int64_t status = transfer(type, req->sector, static_cast<uint32_t>(bytes));
  if (type == BLK_T_IN && status == init::BLK_OK) {
    for (uint64_t i = 0; i < bytes; ++i) {
      user[i] = bounce[i];
    }
  }
  s_busy = false;
  req->status = status;
}

}  // namespace

// Interrupt context (see trap_mgr.cpp): acknowledge, wake the waiter, return.
extern "C" void blk_irq_entry(Capability event) {
  (void)event;  // the only source routed here is ours
  if (s_regs == nullptr) {
    return;
  }
  const uint32_t pending = reg_read(R_INTERRUPT_STATUS);
  if (pending != 0) {
    reg_write(R_INTERRUPT_ACK, pending);
  }
  s_irq_count = s_irq_count + 1;
  const uint64_t tid = s_waiter_tid;
  if (tid != 0 && capability_is_valid(s_sched_wake)) {
    using FnInvoke = decltype(&sys_compartment_invoke);
    init::SchedWakeRequest req{};
    req.tid = tid;
    req.status = init::SCHED_INVALID_THREAD;
    reinterpret_cast<FnInvoke>(s_gate_invoke)(s_sched_wake, bounded(&req));
    // A refused call never reached `wake` and left the status as it was.
    if (req.status != init::SCHED_OK) {
      s_wakes_lost = s_wakes_lost + 1;
    }
  }
}

extern "C" void blk_read_entry(Capability arg) { handle(arg, BLK_T_IN); }

extern "C" void blk_write_entry(Capability arg) { handle(arg, BLK_T_OUT); }

namespace {

// A later call from `init` (abi.hpp, `BlkSchedRequest`): the scheduler's
// entries, now that there is a scheduler. Nothing else reaches our sentry,
// so the entries are taken on the strength of their shape alone.
void bind_sched(Capability arg) {
  if (!capability_is_valid(arg) || sealing::is_sealed(arg) ||
      !capability_has_perms(arg, perms::Load | perms::Store) ||
      capability_get_length(arg) != sizeof(init::BlkSchedRequest)) {
    return;
  }
  auto* req = reinterpret_cast<init::BlkSchedRequest*>(arg);
  if (!sealing::is_sealed_as(OType::EntryPoint, req->block) ||
      !sealing::is_sealed_as(OType::EntryPoint, req->wake) ||
      !sealing::is_sealed_as(OType::EntryPoint, req->self)) {
    req->status = init::BLK_BAD_REQUEST;
    return;
  }
  s_sched_block = req->block;
  s_sched_wake = req->wake;
  s_sched_self = req->self;
  req->status = init::BLK_OK;
}

}  // namespace

extern "C" void compartment_main(Capability arg) {
  Capability* rw = rw_table();
  s_gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  s_uart = rw[SLOT_UART_SENTRY];

  // One-shot handshake (file comment): the first call with a writable
  // argument of exactly `BlkInterface`'s size is `init` bringing us up. Any
  // later call can only be `init` handing over the scheduler's entries.
  if (s_first_call_done) {
    bind_sched(arg);
    return;
  }
  s_first_call_done = true;
  if (!capability_is_valid(arg) || sealing::is_sealed(arg) ||
      !capability_has_perms(arg, perms::Load | perms::Store) ||
      capability_get_length(arg) != sizeof(init::BlkInterface)) {
    return;
  }
  auto* iface = reinterpret_cast<init::BlkInterface*>(arg);
  iface->read = nullptr;
  iface->write = nullptr;
  iface->irq = nullptr;
  iface->capacity_sectors = 0;
  iface->slot = 0;
  iface->status = init::BLK_NO_DEVICE;

  Capability window = rw[SLOT_VIRTIO_MMIO];
  Capability dma = rw[SLOT_DMA_WINDOW];
  Capability gate_sentry = rw[SLOT_SYS_SENTRY];
  Capability self = rw[compartment::SLOT_SELF];

  if (!capability_is_valid(dma) ||
      !capability_has_perms(dma, perms::Load | perms::Store) ||
      capability_get_length(dma) < ARENA_MIN || iface->dma_phys == 0 ||
      (iface->dma_phys & (vm::PAGE_SIZE - 1)) != 0) {
    out("[blk]      no usable DMA arena; block device disabled\n");
    return;
  }
  s_dma = reinterpret_cast<uint8_t*>(
      capability_set_address(dma, capability_get_base(dma)));
  s_dma_phys = iface->dma_phys;

  if (!probe(window, iface->virtio_slot_bytes, iface->virtio_count)) {
    out("[blk]      no virtio-blk device found; block device disabled\n");
    return;
  }
  if (!init_device()) {
    out("[blk]      virtio-blk refused initialisation; block device disabled\n");
    s_regs = nullptr;
    return;
  }
  s_present = true;

  // How we sleep while a request is in flight arrives later (`bind_sched`):
  // there is no scheduler yet, it is on the disk we are about to serve.
  // Until then `transfer` polls.

  Capability e_read = mint_entry(s_gate_invoke, gate_sentry, self,
                                 reinterpret_cast<const void*>(&blk_read_entry));
  Capability e_write = mint_entry(s_gate_invoke, gate_sentry, self,
                                  reinterpret_cast<const void*>(&blk_write_entry));
  Capability e_irq = mint_entry(s_gate_invoke, gate_sentry, self,
                                reinterpret_cast<const void*>(&blk_irq_entry));
  rw[SLOT_READ_ENTRY] = e_read;
  rw[SLOT_WRITE_ENTRY] = e_write;
  rw[SLOT_IRQ_ENTRY] = e_irq;
  iface->read = e_read;
  iface->write = e_write;
  iface->irq = e_irq;
  iface->capacity_sectors = s_capacity;
  iface->slot = s_slot;
  iface->status = init::BLK_OK;

  out_dec("[blk]      virtio-blk online in slot ", s_slot, ": ");
  out_dec("", s_capacity * init::BLK_SECTOR_BYTES / 1024, " KiB, 4 KiB per request\n");
}

}  // namespace signetos::user
