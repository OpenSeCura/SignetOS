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
 * uart.cpp - SignetOS User-Space UART 16550 Console Compartment
 *
 * Holds the exclusive 4 KiB UART MMIO capability (`0x10000000`) delegated by
 * `init`. Output is polled; input is interrupt driven.
 *
 * Three entry points (see `UartInterface` in abi.hpp):
 *   compartment_main(str)   output: prints a NUL-terminated string. This is
 *                           the sentry published as "uart".
 *   uart_irq_entry(event)   the UART's PLIC source fired: drain the receive
 *                           FIFO into the ring buffer and, if a reader asked
 *                           to be told, tell it. `trap_mgr` invokes this from
 *                           interrupt context.
 *   uart_read_entry(req)    input: hands the reader what the ring buffer
 *                           holds, without blocking, and remembers whom to
 *                           tell when more arrives.
 *
 * `read` and `irq` are minted once, on the very first invocation of
 * `compartment_main`, if the argument is a writable `UartInterface` rather
 * than a string. `init` makes that call before anybody else exists and before
 * it prints anything, seeds `read` to the shell alone and routes the UART's
 * PLIC source to `irq` through `trap_mgr`. After that first call the
 * handshake is closed for good, so holding the print sentry never turns into
 * the right to read the keyboard. The same call switches the UART's
 * "received data available" interrupt on; until `trap_mgr` enables the source
 * at the PLIC that is a wire nobody listens to.
 *
 * THE RING BUFFER
 *   One producer (`irq`, interrupt context) and one consumer (`read`, thread
 *   context) on one hart: the producer can run between any two instructions
 *   of the consumer, never the other way round. Each side owns one index and
 *   only reads the other's, so no lock is needed.
 *
 * THE WAKE
 *   `read` records the reader's `wake` entry point *before* it looks at the
 *   buffer and drops it again if it found something. So a byte that lands
 *   between the look and the reader going to sleep still produces a wake,
 *   and the scheduler turns a wake that arrives before the reader has gone
 *   to sleep into an immediate return from `sched.block` (sched.cpp). No
 *   interleaving loses a keystroke.
 */

#include "runtime.hpp"

namespace signetos::user {
namespace {

// 16550 registers (byte offsets) and the bits used here.
constexpr size_t REG_RBR_THR = 0;    // receive buffer (read) / transmit (write)
constexpr size_t REG_IER = 1;        // interrupt enable
constexpr size_t REG_LSR = 5;        // line status
constexpr uint8_t IER_RX_DATA = 0x01;     // "received data available"
constexpr uint8_t LSR_DATA_READY = 0x01;
constexpr uint8_t LSR_THR_EMPTY = 0x20;

// Received bytes the reader has not collected yet. Power-of-two size; the
// indices run free and are reduced modulo the size on access, so
// `head - tail` is the fill level even across wrap-around.
constexpr uint32_t RING_SIZE = 256;
uint8_t s_ring[RING_SIZE];
volatile uint32_t s_head = 0;   // written by `irq` only
volatile uint32_t s_tail = 0;   // written by `read` only

// Entry point to invoke when input arrives, or null if nobody is waiting.
Capability volatile s_waiter = nullptr;

// Set by the first invocation of `compartment_main`, whatever it was.
bool s_first_call_done = false;

// --- What `uart` asks `init` for (user/manifest.hpp) --------------------------
// The device window, the switcher, and `sentry` to mint `read` and `irq` in
// the handshake above. `init` loads the console itself, before anything else
// exists; it is the only compartment the loader does not load.
#define UART_MANIFEST(X)                                 \
  M_MMIO(X, UART_MMIO, "uart")                           \
  M_SYSCALL(X, SYS_SENTRY, sentry)                       \
  M_SYSCALL(X, SYS_COMP_INVOKE, compartment_invoke)
SIGNETOS_MANIFEST(UART_MANIFEST, 64 * 1024)
// Runtime slots: the two entry points minted in the handshake.
constexpr size_t SLOT_READ_ENTRY = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 0;
constexpr size_t SLOT_IRQ_ENTRY  = compartment::RW_SLOT_SEED_BASE + MANIFEST_COUNT + 1;

volatile uint8_t* uart_regs() {
  Capability cap = rw_table()[SLOT_UART_MMIO];
  return capability_is_valid(cap) ? reinterpret_cast<volatile uint8_t*>(cap)
                                  : nullptr;
}

}  // namespace

// Interrupt context (see trap_mgr.cpp): short, no blocking, no switching.
extern "C" void uart_irq_entry(Capability event) {
  (void)event;  // the only source routed here is ours
  volatile uint8_t* uart = uart_regs();
  if (uart == nullptr) {
    return;
  }
  bool received = false;
  while ((uart[REG_LSR] & LSR_DATA_READY) != 0) {
    const uint8_t byte = uart[REG_RBR_THR];  // the read is what drops the line
    const uint32_t head = s_head;
    if (head - s_tail < RING_SIZE) {
      s_ring[head % RING_SIZE] = byte;
      s_head = head + 1;
    }
    // else: full -- a reader that far behind loses the byte.
    received = true;
  }
  Capability waiter = s_waiter;
  if (received && capability_is_valid(waiter)) {
    s_waiter = nullptr;  // one wake per request
    using FnInvoke = decltype(&sys_compartment_invoke);
    Capability gate = rw_table()[SLOT_SYS_COMP_INVOKE];
    reinterpret_cast<FnInvoke>(gate)(waiter, nullptr);
  }
}

extern "C" void uart_read_entry(Capability arg) {
  if (!capability_is_valid(arg) || sealing::is_sealed(arg) ||
      !capability_has_perms(arg, perms::Load | perms::Store) ||
      capability_get_length(arg) < sizeof(init::UartReadRequest)) {
    return;
  }
  auto* req = reinterpret_cast<init::UartReadRequest*>(arg);
  req->count = 0;

  Capability buf_cap = req->buf;
  if (!capability_is_valid(buf_cap) || sealing::is_sealed(buf_cap) ||
      !capability_has_perms(buf_cap, perms::Store)) {
    return;
  }
  // Room from the capability's address to the end of its bounds.
  const uint64_t end = capability_get_base(buf_cap) + capability_get_length(buf_cap);
  const uint64_t addr = capability_get_address(buf_cap);
  const size_t room = (end > addr) ? static_cast<size_t>(end - addr) : 0;

  // Arm first, look second (file comment, THE WAKE).
  s_waiter = sealing::is_sealed_as(OType::EntryPoint, req->wake) ? req->wake
                                                                  : nullptr;

  auto* buf = reinterpret_cast<uint8_t*>(buf_cap);
  uint32_t tail = s_tail;
  while (req->count < room && tail != s_head) {
    buf[req->count] = s_ring[tail % RING_SIZE];
    req->count += 1;
    tail += 1;
  }
  s_tail = tail;

  if (req->count > 0) {
    s_waiter = nullptr;  // the caller has something to do; it will be back
  }
}

extern "C" void compartment_main(Capability arg) {
  Capability* rw = rw_table();
  volatile uint8_t* uart = uart_regs();
  if (uart == nullptr || !capability_is_valid(arg)) {
    return;
  }

  // One-shot console-input handshake (file comment). Strings arrive Load-only
  // through `print()`, so a writable argument of exactly this size on the
  // first call can only be `init`'s `UartInterface`.
  if (!s_first_call_done) {
    s_first_call_done = true;
    if (!sealing::is_sealed(arg) &&
        capability_has_perms(arg, perms::Load | perms::Store) &&
        capability_get_length(arg) == sizeof(init::UartInterface)) {
      Capability gate_invoke = rw[SLOT_SYS_COMP_INVOKE];
      Capability gate_sentry = rw[SLOT_SYS_SENTRY];
      Capability self = rw[compartment::SLOT_SELF];
      Capability read = mint_entry(gate_invoke, gate_sentry, self,
                                   reinterpret_cast<const void*>(&uart_read_entry));
      Capability irq = mint_entry(gate_invoke, gate_sentry, self,
                                  reinterpret_cast<const void*>(&uart_irq_entry));
      rw[SLOT_READ_ENTRY] = read;
      rw[SLOT_IRQ_ENTRY] = irq;
      auto* iface = reinterpret_cast<init::UartInterface*>(arg);
      iface->read = read;
      iface->irq = irq;
      // From here on the UART raises its line whenever a byte is waiting.
      uart[REG_IER] = IER_RX_DATA;
      return;
    }
  }

  const char* str = reinterpret_cast<const char*>(arg);
  const size_t max_len = capability_get_length(arg);

  for (size_t i = 0; i < max_len && str[i] != '\0'; ++i) {
    const char ch = str[i];
    if (ch == '\n') {
      while ((uart[REG_LSR] & LSR_THR_EMPTY) == 0) {}
      uart[REG_RBR_THR] = '\r';
    }
    while ((uart[REG_LSR] & LSR_THR_EMPTY) == 0) {}
    uart[REG_RBR_THR] = static_cast<uint8_t>(ch);
  }
}

}  // namespace signetos::user
