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
 * uart.cpp - SignetOS Capability-Bounded UART 16550 Console & Diagnostic Utilities
 */

#include <signetos/uart.hpp>
#include <signetos/lock.hpp>
#include <signetos/platform.hpp>
#include <signetos/sealing.hpp>

namespace signetos::uart {

static volatile uint8_t* __capability s_uart_mmio = nullptr;
static volatile uint32_t* __capability s_test_dev_mmio = nullptr;

namespace {

// Serialises the printing calls across harts (lock.hpp). Held for one call
// at a time, never across a return to the caller.
SpinLock s_lock;

// Set by `halting()`; read without the lock. Once set, prints go straight to
// the device: see `halting` in uart.hpp.
bool s_halting = false;

// Takes the console lock for the enclosing scope, unless the kernel is
// halting, in which case it takes nothing and the print proceeds at once.
class Hold {
 public:
  Hold() : took_(!__atomic_load_n(&s_halting, __ATOMIC_RELAXED)) {
    if (took_) {
      s_lock.acquire();
    }
  }
  ~Hold() {
    if (took_) {
      s_lock.release();
    }
  }
  Hold(const Hold&) = delete;
  Hold& operator=(const Hold&) = delete;

 private:
  bool took_;
};

// The device writes. No locking here: every public call below wraps the
// `put_*` it needs in one `Hold`.

void put(char ch) {
    if (!s_uart_mmio) {
        return;
    }
    if (ch == '\n') {
        while ((s_uart_mmio[5] & 0x20) == 0) {}
        s_uart_mmio[0] = '\r';
    }
    while ((s_uart_mmio[5] & 0x20) == 0) {}
    s_uart_mmio[0] = static_cast<uint8_t>(ch);
}

void put_str(const char* str) {
    if (!str) {
        return;
    }
    while (*str) {
        put(*str++);
    }
}

void put_hex64(uint64_t val) {
    for (int i = 60; i >= 0; i -= 4) {
        const uint8_t nibble = (val >> i) & 0xFULL;
        if (nibble < 10) {
            put('0' + nibble);
        } else {
            put('a' + (nibble - 10));
        }
    }
}

void put_dec(uint64_t val) {
    if (val == 0) {
        put('0');
        return;
    }
    char buf[24];
    int idx = 0;
    while (val > 0) {
        buf[idx++] = '0' + (val % 10);
        val /= 10;
    }
    while (idx > 0) {
        put(buf[--idx]);
    }
}

// Name of a hardware object type (the CT field), for print_cap.
const char* otype_name(uint64_t ct) {
    switch (static_cast<OType>(ct)) {
        case OType::Unsealed:       return "Unsealed";
        case OType::Sentry:         return "Sentry";
        case OType::QuotaVm:        return "QuotaVm";
        case OType::QuotaThreadMem: return "QuotaThreadMem";
        case OType::QuotaHeap:      return "QuotaHeap";
        case OType::QuotaSched:     return "QuotaSched";
        case OType::QuotaDisk:      return "QuotaDisk";
        case OType::Compartment:    return "Compartment";
        case OType::Thread:         return "Thread";
        case OType::Revoker:        return "Revoker";
        case OType::TypeKey:        return "TypeKey";
        case OType::SealedObject:   return "SealedObject";
        case OType::EntryPoint:     return "EntryPoint";
        case OType::Trap:           return "Trap";
    }
    return "unknown";
}

}  // namespace

void init(Capability root_data_cap) {
    if (!capability_is_valid(root_data_cap)) {
        return;
    }

    // Derive strictly bounded capability for the console UART discovered from
    // the DTB.
    Capability uart_cap =
        capability_set_address(root_data_cap, platform::uart_base());
    uart_cap = capability_set_bounds(uart_cap, platform::uart_size());
    uart_cap = capability_and_perms(uart_cap, perms::DataRw);
    s_uart_mmio = reinterpret_cast<volatile uint8_t* __capability>(uart_cap);

    // Derive strictly bounded capability for the finisher / poweroff device
    // discovered from the DTB.
    Capability test_cap =
        capability_set_address(root_data_cap, platform::test_device_base());
    test_cap = capability_set_bounds(test_cap, platform::test_device_size());
    test_cap = capability_and_perms(test_cap, perms::DataRw);
    s_test_dev_mmio = reinterpret_cast<volatile uint32_t* __capability>(test_cap);
}

void putchar(char ch) {
    Hold hold;
    put(ch);
}

void print(const char* str) {
    Hold hold;
    put_str(str);
}

void print_hex64(uint64_t val) {
    Hold hold;
    put_hex64(val);
}

void print_dec(uint64_t val) {
    Hold hold;
    put_dec(val);
}

void print_cap(const char* label, Capability cap) {
    Hold hold;
    put_str(label);
    put_str(": [tag=");
    put(capability_is_valid(cap) ? '1' : '0');
    const uint64_t p = capability_get_perms(cap);
    put_str(" perms=0x");
    put_hex64(p);
    // One letter per permission, '-' where it is missing:
    //   r Load, w Store, x Execute, c load/store capabilities, m LoadMutable,
    //   a AccessSystemRegs, s Seal, u Unseal
    put_str(" (");
    put((p & perms::Load) ? 'r' : '-');
    put((p & perms::Store) ? 'w' : '-');
    put((p & perms::Execute) ? 'x' : '-');
    put((p & perms::LoadCapability) ? 'c' : '-');
    put((p & perms::LoadMutable) ? 'm' : '-');
    put((p & perms::AccessSystemRegs) ? 'a' : '-');
    put((p & perms::Seal) ? 's' : '-');
    put((p & perms::Unseal) ? 'u' : '-');
    put_str(")");
    put_str(" base=0x");
    put_hex64(capability_get_base(cap));
    put_str(" len=0x");
    put_hex64(capability_get_length(cap));
    put_str(" addr=0x");
    put_hex64(capability_get_address(cap));
    if (sealing::is_sealed(cap)) {
        const uint64_t ct = sealing::type_of(cap);
        put_str(" sealed otype=");
        put_dec(ct);
        put_str(" (");
        put_str(otype_name(ct));
        put_str(")");
    } else {
        put_str(" unsealed");
    }
    put_str("]\n");
}

void halting() {
    __atomic_store_n(&s_halting, true, __ATOMIC_RELAXED);
}

[[noreturn]] void panic(const char* msg) {
  halting();
  print("[PANIC] ");
  print(msg);
  print("\n");
  qemu_poweroff(1);
}

[[noreturn]] void qemu_poweroff(int exit_code) {
    halting();
    print("\n[SignetOS] Requesting QEMU poweroff (exit_code=");
    print_dec(static_cast<uint64_t>(exit_code));
    print(")...\n");

    if (s_test_dev_mmio) {
        if (exit_code == 0) {
            s_test_dev_mmio[0] = 0x5555;
        } else {
            s_test_dev_mmio[0] = (static_cast<uint32_t>(exit_code) << 16) | 0x3333;
        }
    }

    while (true) {
        __asm__ volatile ("wfi");
    }
}

} // namespace signetos::uart
