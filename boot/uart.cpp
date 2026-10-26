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
 * `init`. Output is polled; input sleeps on the UART's interrupt.
 *
 * Three entry points (see `UartInterface` in abi.hpp):
 *   compartment_main(str)      output: prints a NUL-terminated string. This is
 *                              the sentry published as "uart".
 *   uart_irq_entry(irq_wait)   `init` hands over the scheduler entry that waits
 *                              for the UART's PLIC source (sched.cpp, DEVICE
 *                              INTERRUPTS), once.
 *   uart_read_entry(buf)       input: hands the reader what the UART holds,
 *                              first sleeping until there is something.
 *
 * `read` and `irq` are minted once, on the very first invocation of
 * `compartment_main`, if the argument is a writable `UartInterface` rather
 * than a string. `init` makes that call before anybody else exists and before
 * it prints anything, seeds `read` to the shell alone and keeps `irq` to
 * itself. After that first call the handshake is closed for good, so holding
 * the print sentry never turns into the right to read the keyboard. The same
 * call switches the UART's "received data available" interrupt on; until the
 * scheduler routes the source at the PLIC that is a wire nobody listens to.
 *
 * THE WAIT
 *   `read` takes what the UART holds and returns it; with nothing there, it
 *   sleeps in `irq_wait` until the UART interrupts, and looks again. Reading
 *   the bytes is what drops the UART's line, so `irq_wait`, which completes
 *   the interrupt at the PLIC before it sleeps, never completes one the UART
 *   is still raising: a key pressed between the look and the sleep
 *   interrupts again at once. Bytes that arrive while nobody reads wait in
 *   the UART.
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

// `sched.irq_wait` for the UART's source, once `init` has routed it; until
// then `read` returns what there is without waiting.
Capability s_irq_wait = nullptr;

// Set by the first invocation of `compartment_main`, whatever it was.
bool s_first_call_done = false;

// --- What `uart` asks `init` for (user/manifest.hpp) --------------------------
// The device window, the switcher, and `sentry` to mint `read` and `irq` in
// the handshake above. `init` loads the console first, before anything else
// exists.
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

// Sends `str`, up to its NUL or `max_len` bytes, turning "\n" into "\r\n".
// Returns how many bytes of `str` it sent.
size_t transmit(volatile uint8_t* uart, const char* str, size_t max_len) {
  size_t i = 0;
  for (; i < max_len && str[i] != '\0'; ++i) {
    const char ch = str[i];
    if (ch == '\n') {
      while ((uart[REG_LSR] & LSR_THR_EMPTY) == 0) {}
      uart[REG_RBR_THR] = '\r';
    }
    while ((uart[REG_LSR] & LSR_THR_EMPTY) == 0) {}
    uart[REG_RBR_THR] = static_cast<uint8_t>(ch);
  }
  return i;
}

}  // namespace

// The console's fault handler (fault.hpp) prints the report every other
// compartment prints through it (SIGNETOS_DEFAULT_FAULT_HANDLER,
// runtime.hpp), but straight to the device: the console cannot call itself.
SIGNETOS_FAULT_HANDLER compartment_error_handler(fault::ErrorState* state) {
  LineBuffer line;
  describe_fault(line, "uart", *state);
  volatile uint8_t* uart = uart_regs();
  if (uart != nullptr) {
    transmit(uart, line.buf, sizeof(line.buf));
  }
  return fault::UNWIND;
}

// From `init`, once: the UART's `irq_wait` (THE WAIT).
extern "C" uint64_t uart_irq_entry(Capability irq_wait) {
  if (!capability_is_valid(s_irq_wait) &&
      sealing::is_sealed_as(OType::EntryPoint, irq_wait)) {
    s_irq_wait = irq_wait;
  }
  return 0;
}

extern "C" uint64_t uart_read_entry(Capability buf_cap) {
  volatile uint8_t* uart = uart_regs();
  if (uart == nullptr || !capability_is_valid(buf_cap) ||
      sealing::is_sealed(buf_cap) ||
      !capability_has_perms(buf_cap, perms::Store)) {
    return 0;
  }
  // Room from the capability's address to the end of its bounds.
  const uint64_t end = capability_get_base(buf_cap) + capability_get_length(buf_cap);
  const uint64_t addr = capability_get_address(buf_cap);
  const size_t room = (end > addr) ? static_cast<size_t>(end - addr) : 0;

  auto* buf = reinterpret_cast<uint8_t*>(buf_cap);
  uint64_t count = 0;
  while (room > 0) {
    while (count < room && (uart[REG_LSR] & LSR_DATA_READY) != 0) {
      buf[count++] = uart[REG_RBR_THR];  // the read is what drops the line
    }
    // Something for the reader, or no sleeping until there is: no route
    // yet, a caller the scheduler does not run, or a killed one.
    if (count > 0 || !capability_is_valid(s_irq_wait) ||
        invoke<int64_t>(rw_table()[SLOT_SYS_COMP_INVOKE], s_irq_wait, 0ULL) !=
            init::SCHED_OK) {
      break;
    }
  }
  return count;
}

extern "C" uint64_t compartment_main(Capability arg) {
  Capability* rw = rw_table();
  volatile uint8_t* uart = uart_regs();
  if (uart == nullptr || !capability_is_valid(arg)) {
    return 0;
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
      return 0;
    }
  }

  return transmit(uart, reinterpret_cast<const char*>(arg),
                  capability_get_length(arg));
}

}  // namespace signetos::user
