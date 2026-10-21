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
 * Drives one virtio-blk device, which `dma` has already set up (dma.cpp):
 * queue 0 runs on a fixed descriptor table only `dma` can write. `blk` holds
 * the rest of the DMA arena -- rings, request header, data, status -- and a
 * window onto three device registers (notify, interrupt status and
 * acknowledge), handed over in the `BlkInterface` handshake. It never sees or
 * writes a physical address, and cannot point the device outside the arena.
 *
 * Three entry points (see `BlkInterface` in abi.hpp), minted once on the
 * first invocation of `compartment_main`, exactly like `uart`:
 *   blk_read_entry(buf, sector, count)   copies `count` sectors from the
 *                                        device into `buf`.
 *   blk_write_entry(buf, sector, count)  the other way round.
 *   blk_irq_entry(source)                the device's PLIC source fired:
 *                                        acknowledge it and wake whichever
 *                                        thread is waiting for its request.
 *                                        `trap_mgr` invokes this from
 *                                        interrupt context.
 *
 * WHY A BOUNCE BUFFER
 *   The device only ever sees the addresses in `dma`'s table, all inside the
 *   arena: one request header, one 4 KiB data buffer and one status byte. A
 *   caller's buffer is copied in or out, so no caller memory is ever exposed
 *   to the device. That is what lets the descriptors be fixed at boot, and
 *   it is also why every request is exactly one 4 KiB page.
 *
 * ONE REQUEST AT A TIME
 *   Every request holds `s_lock`, the scheduler's lock (runtime.hpp, `lock`),
 *   from submission to completion. A caller that is stopped (its scheduler
 *   node taken back) while it holds it is lent time by the next caller until
 *   it releases it (sched.cpp, LOCKS). A caller can also end while it holds
 *   it -- the kernel ends a thread that has no room to take a trap, or whose
 *   every frame is in a destroyed compartment -- possibly with its request
 *   still in flight. The next caller then gets the lock with SCHED_OWNER_DEAD
 *   and recovers before using the device (`recover`): it waits for the device
 *   to finish everything submitted and catches the used ring up. Before there
 *   is a scheduler (`init` alone) the lock is taken without waiting.
 *
 *   A request is one of `dma`'s two fixed chains (read or write) placed in
 *   the available ring, then a notify. Completion is a new entry in the used
 *   ring. While it is in flight the calling thread sleeps in `sched.block`;
 *   `blk_irq_entry` wakes it by tid. The wait loop re-checks the used ring
 *   after every return from `block`, so a wake that arrives early (or a
 *   spurious one) costs a trip round the loop and nothing else.
 *
 *   A wake can also fail to arrive: `sched.wake` is a compartment call made
 *   from interrupt context on the interrupted thread's kernel stack, and the
 *   switcher refuses it when that stack has no room. So the waiter never sleeps
 *   without a bound: it blocks for at most WAIT_TIMEOUT_US at a time and
 *   looks at the used ring again, and a lost wake costs that much and no
 *   more. The interrupt entry checks what `wake` said and counts the
 *   refusals; the waiter reports the first one on the console, since it is
 *   a sign that some caller is running deeper than the system allows for.
 *   Until the
 *   first interrupt has been seen -- or when the caller is not a scheduled
 *   thread, such as `init` mounting the disk, which `block` turns away with
 *   SCHED_INVALID_THREAD -- the loop polls instead, so a missing interrupt
 *   route degrades to polling rather than a hang.
 *
 * BEFORE THERE IS A SCHEDULER
 *   `blk` is in the boot set: `sched` and `trap_mgr` are files on the disk it
 *   serves, so at its handshake there is nothing to look up and no interrupt
 *   route. Every request polls until `init` has loaded the scheduler and
 *   hands over its entries (`block`, `wake`, `lock_wait`, `lock_wake`) in a
 *   second call, and until
 *   `trap_mgr` is up and the device's interrupt is routed here.
 */

#include "runtime.hpp"

namespace signetos::user {
namespace {

// --- What `blk` asks `init` for (user/manifest.hpp) ---------------------------
// No device window and no DMA arena: those are `dma`'s, and what `blk` gets
// of them arrives in the handshake (abi.hpp, BlkInterface). Without a device
// the driver still comes up and reports BLK_NO_DEVICE, and the file system
// reports itself unmounted.
#define BLK_MANIFEST(X)                                  \
  M_SYSCALL(X, SYS_SENTRY, sentry)                       \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)      \
  M_SERVICE(X, UART_SENTRY, "uart")
SIGNETOS_MANIFEST(BLK_MANIFEST, 64 * 1024)
// Runtime slots: the three entry points minted in the handshake.
constexpr size_t SLOT_READ_ENTRY  = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 0;
constexpr size_t SLOT_WRITE_ENTRY = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 1;
constexpr size_t SLOT_IRQ_ENTRY   = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 2;

// --- The device, as `dma` left it (dma.cpp) ------------------------------------
// The registers `blk` may write, as offsets into `s_notify`.
constexpr size_t R_QUEUE_NOTIFY     = init::DMA_NOTIFY_QUEUE;
constexpr size_t R_INTERRUPT_STATUS = init::DMA_NOTIFY_IRQ_STATUS;
constexpr size_t R_INTERRUPT_ACK    = init::DMA_NOTIFY_IRQ_ACK;

// --- split virtqueue ------------------------------------------------------------
constexpr uint16_t QUEUE_SIZE = init::DMA_QUEUE_SIZE;

constexpr uint32_t BLK_T_IN  = 0;  // device -> memory (read)
constexpr uint32_t BLK_T_OUT = 1;  // memory -> device (write)
constexpr uint8_t  BLK_S_OK  = 0;
constexpr uint8_t  STATUS_POISON = 0xff;

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
static_assert(sizeof(BlkReqHeader) == 16);
static_assert(init::DMA_BUF_AVAIL + sizeof(VirtqAvail) <= init::DMA_BUF_USED);
static_assert(init::DMA_BUF_USED + sizeof(VirtqUsed) <= init::DMA_BUF_HEADER);

// What `buf` must cover: up to the status byte.
constexpr size_t BUF_MIN = init::DMA_BUF_STATUS + 1;

// --- state -----------------------------------------------------------------------
Capability s_gate_invoke = nullptr;
Capability s_uart = nullptr;
Capability s_sched_block = nullptr;
Capability s_sched_wake = nullptr;
Capability s_lock_wait = nullptr;
Capability s_lock_wake = nullptr;

volatile uint32_t* s_notify = nullptr;  // QUEUE_NOTIFY .. INTERRUPT_ACK
uint8_t* s_buf = nullptr;               // the arena past its descriptor page
uint64_t s_capacity = 0;                // sectors
uint32_t s_slot = 0;
bool s_present = false;
uint64_t s_lock = 0;                  // ONE REQUEST AT A TIME
bool s_first_call_done = false;
uint16_t s_last_used = 0;             // used-ring entries consumed so far

// The thread waiting for the in-flight request (0: nobody), and how many
// interrupts have ever reached us.
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

inline uint32_t reg_read(size_t off) { return s_notify[off / 4]; }
inline void reg_write(size_t off, uint32_t v) { s_notify[off / 4] = v; }

template <typename T>
Capability bounded(T* p) {
  return capability_set_bounds(reinterpret_cast<Capability>(p), sizeof(T));
}

void out(const char* msg) { print(s_gate_invoke, s_uart, msg); }
void out_dec(const char* p, uint64_t v, const char* s) {
  print_dec(s_gate_invoke, s_uart, p, v, s);
}

volatile VirtqAvail* avail() {
  return reinterpret_cast<volatile VirtqAvail*>(s_buf + init::DMA_BUF_AVAIL);
}
volatile VirtqUsed* used() {
  return reinterpret_cast<volatile VirtqUsed*>(s_buf + init::DMA_BUF_USED);
}
volatile BlkReqHeader* header() {
  return reinterpret_cast<volatile BlkReqHeader*>(s_buf + init::DMA_BUF_HEADER);
}
volatile uint8_t* status_byte() { return s_buf + init::DMA_BUF_STATUS; }
uint8_t* data() { return s_buf + init::DMA_BUF_DATA; }

// Sleeps until woken or WAIT_TIMEOUT_US, whichever is first. False if the
// scheduler does not run the calling thread (`init`, before the dispatcher
// starts), which cannot sleep and polls instead.
bool block() {
  return invoke<int64_t>(s_gate_invoke, s_sched_block, WAIT_TIMEOUT_US) !=
         init::SCHED_INVALID_THREAD;
}

// Submits one request and waits for it. `type` is BLK_T_IN or BLK_T_OUT; the
// data -- always BLK_XFER_BYTES -- goes through the arena's data buffer, which
// the caller has filled (OUT) or will drain (IN). Returns BLK_OK or
// BLK_IO_ERROR.
int64_t transfer(uint32_t type, uint64_t sector) {
  volatile BlkReqHeader* h = header();
  h->type = type;
  h->reserved = 0;
  h->sector = sector;
  *status_byte() = STATUS_POISON;

  // Whom to wake, recorded before the device can possibly complete.
  s_waiter_tid = self_tid();

  volatile VirtqAvail* av = avail();
  const uint16_t idx = av->idx;
  // The descriptors are `dma`'s, fixed: we only say which chain (dma.cpp).
  const uint16_t chain =
      type == BLK_T_IN ? init::DMA_CHAIN_READ : init::DMA_CHAIN_WRITE;
  av->ring[idx % QUEUE_SIZE] = chain;
  fence();
  av->idx = static_cast<uint16_t>(idx + 1);
  fence();
  reg_write(R_QUEUE_NOTIFY, 0);

  // Sleep until the used ring moves. Polling instead if we are not a
  // scheduled thread or no interrupt has ever arrived (no route). A killed
  // thread never sleeps (`block` returns SCHED_KILLED at once), so for one
  // this loop polls. It must still wait for the completion: the device owns
  // the request until then.
  volatile VirtqUsed* us = used();
  bool scheduled = capability_is_valid(s_sched_block);
  for (;;) {
    fence();
    if (us->idx != s_last_used) {
      break;
    }
    if (scheduled && s_irq_count > 0) {
      scheduled = block();
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
  if (done.id != chain || *status_byte() != BLK_S_OK) {
    return init::BLK_IO_ERROR;
  }
  return init::BLK_OK;
}

// The previous holder of `s_lock` ended without releasing it (ONE REQUEST AT
// A TIME), maybe with its request still in flight. The device owns that
// request until it completes, so wait for everything submitted to complete,
// and consume it: the dead caller will never read its result. It may have
// been cut between publishing its request and notifying the device, so
// notify again first; a second notify is harmless.
void recover() {
  volatile VirtqAvail* av = avail();
  volatile VirtqUsed* us = used();
  fence();
  reg_write(R_QUEUE_NOTIFY, 0);
  for (;;) {
    fence();
    if (us->idx == av->idx) {
      break;
    }
  }
  s_last_used = us->idx;
  s_waiter_tid = 0;
  out("[blk]      a caller ended mid-request; recovered the device queue\n");
}

// Shared by read and write: validates the arguments and moves the data through
// the bounce buffer.
int64_t handle(Capability buf, uint64_t sector, uint64_t count, uint32_t type) {
  if (!s_present) {
    return init::BLK_NO_DEVICE;
  }
  const uint64_t bytes = init::BLK_XFER_BYTES;
  if (count * init::BLK_SECTOR_BYTES != bytes) {
    return init::BLK_BAD_REQUEST;  // one page, always (abi.hpp)
  }
  if (sector >= s_capacity || count > s_capacity - sector) {
    return init::BLK_OUT_OF_RANGE;
  }
  const uint64_t need = (type == BLK_T_IN) ? perms::Store : perms::Load;
  if (!capability_is_valid(buf) || sealing::is_sealed(buf) ||
      !capability_has_perms(buf, need)) {
    return init::BLK_BAD_REQUEST;
  }
  const uint64_t end = capability_get_base(buf) + capability_get_length(buf);
  const uint64_t addr = capability_get_address(buf);
  if (end < addr || end - addr < bytes) {
    return init::BLK_BAD_REQUEST;
  }
  const int64_t taken = lock(s_gate_invoke, s_lock_wait, &s_lock);
  if (taken == init::SCHED_OWNER_DEAD) {
    recover();
  } else if (taken != init::SCHED_OK) {
    return init::BLK_BUSY;
  }

  auto* user = reinterpret_cast<uint8_t*>(buf);
  uint8_t* bounce = data();
  if (type == BLK_T_OUT) {
    for (uint64_t i = 0; i < bytes; ++i) {
      bounce[i] = user[i];
    }
  }
  const int64_t status = transfer(type, sector);
  if (type == BLK_T_IN && status == init::BLK_OK) {
    for (uint64_t i = 0; i < bytes; ++i) {
      user[i] = bounce[i];
    }
  }
  unlock(s_gate_invoke, s_lock_wake, &s_lock);
  return status;
}

}  // namespace

SIGNETOS_DEFAULT_FAULT_HANDLER("blk")

// Interrupt context (see trap_mgr.cpp): acknowledge, wake the waiter, return.
extern "C" uint64_t blk_irq_entry(uint64_t source) {
  (void)source;  // the only source routed here is ours
  if (s_notify == nullptr) {
    return 0;
  }
  const uint32_t pending = reg_read(R_INTERRUPT_STATUS);
  if (pending != 0) {
    reg_write(R_INTERRUPT_ACK, pending);
  }
  s_irq_count = s_irq_count + 1;
  const uint64_t tid = s_waiter_tid;
  if (tid != 0 && capability_is_valid(s_sched_wake)) {
    const int64_t st = invoke<int64_t>(s_gate_invoke, s_sched_wake, tid);
    // SCHED_INVALID_THREAD: a waiter the scheduler does not run (`init`),
    // which polls. Anything else that is not SCHED_OK was lost.
    if (st != init::SCHED_OK && st != init::SCHED_INVALID_THREAD) {
      s_wakes_lost = s_wakes_lost + 1;
    }
  }
  return 0;
}

extern "C" int64_t blk_read_entry(Capability buf, uint64_t sector,
                                  uint64_t count) {
  return handle(buf, sector, count, BLK_T_IN);
}

extern "C" int64_t blk_write_entry(Capability buf, uint64_t sector,
                                   uint64_t count) {
  return handle(buf, sector, count, BLK_T_OUT);
}

namespace {

// A later call from `init` (abi.hpp): the scheduler's entries (`block`,
// `wake`, `lock_wait`, `lock_wake`), now that there is a scheduler. Nothing
// else reaches our sentry, so the entries are taken on the strength of their
// shape alone.
int64_t bind_sched(Capability block_ep, Capability wake_ep,
                   Capability lock_wait_ep, Capability lock_wake_ep) {
  if (!sealing::is_sealed_as(OType::EntryPoint, block_ep) ||
      !sealing::is_sealed_as(OType::EntryPoint, wake_ep) ||
      !sealing::is_sealed_as(OType::EntryPoint, lock_wait_ep) ||
      !sealing::is_sealed_as(OType::EntryPoint, lock_wake_ep)) {
    return init::BLK_BAD_REQUEST;
  }
  s_sched_block = block_ep;
  s_sched_wake = wake_ep;
  s_lock_wait = lock_wait_ep;
  s_lock_wake = lock_wake_ep;
  return init::BLK_OK;
}

}  // namespace

extern "C" int64_t compartment_main(Capability arg0, Capability arg1,
                                    Capability arg2, Capability arg3) {
  Capability* rw = rw_table();
  s_gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
  s_uart = rw[SLOT_UART_SENTRY];

  // One-shot handshake (file comment): the first call with a writable
  // argument of `BlkInterface`'s size is `init` bringing us up. Any later
  // call can only be `init` handing over the scheduler's entries.
  if (s_first_call_done) {
    return bind_sched(arg0, arg1, arg2, arg3);
  }
  s_first_call_done = true;
  if (!capability_is_valid(arg0) || sealing::is_sealed(arg0) ||
      !capability_has_perms(arg0, perms::Load | perms::Store) ||
      capability_get_length(arg0) != sizeof(init::BlkInterface)) {
    return init::BLK_BAD_REQUEST;
  }
  auto* iface = reinterpret_cast<init::BlkInterface*>(arg0);
  iface->read = nullptr;
  iface->write = nullptr;
  iface->irq = nullptr;
  iface->status = init::BLK_NO_DEVICE;

  Capability gate_sentry = rw[SLOT_SYS_SENTRY];
  Capability self = rw[compartment::SLOT_SELF];

  // What `dma` set up (abi.hpp, DmaInterface), passed on by `init`.
  Capability buf = iface->buf;
  Capability notify = iface->notify;
  if (!capability_is_valid(buf) ||
      !capability_has_perms(buf, perms::Load | perms::Store) ||
      capability_get_length(buf) < BUF_MIN || !capability_is_valid(notify) ||
      !capability_has_perms(notify, perms::Load | perms::Store) ||
      capability_get_length(notify) < init::DMA_NOTIFY_BYTES ||
      iface->capacity_sectors == 0) {
    out("[blk]      no device from `dma`; block device disabled\n");
    return iface->status;
  }
  s_buf = reinterpret_cast<uint8_t*>(
      capability_set_address(buf, capability_get_base(buf)));
  s_notify = reinterpret_cast<volatile uint32_t*>(
      capability_set_address(notify, capability_get_base(notify)));
  s_capacity = iface->capacity_sectors;
  s_slot = iface->slot;
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
  iface->status = init::BLK_OK;

  out_dec("[blk]      virtio-blk online in slot ", s_slot, ": ");
  out_dec("", s_capacity * init::BLK_SECTOR_BYTES / 1024, " KiB, 4 KiB per request\n");
  return iface->status;
}

}  // namespace signetos::user
