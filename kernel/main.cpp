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
 * main.cpp - SignetOS Microkernel Main Entry Point (Freestanding C++20)
 *
 * Brings up the kernel subsystems and launches the `init` compartment.
 */

#include <signetos/hw/clint.hpp>
#include <signetos/compartment.hpp>
#include <signetos/frame.hpp>
#include <signetos/debug/report.hpp>
#include <signetos/init.hpp>
#include <signetos/hw/platform.hpp>
#include <signetos/quota.hpp>
#include <signetos/revoke.hpp>
#include <signetos/sealing.hpp>
#include <signetos/sentry.hpp>
#include <signetos/smp.hpp>
#include <signetos/irq.hpp>
#include <signetos/thread.hpp>
#include <signetos/trap.hpp>
#include <signetos/types.hpp>
#include <signetos/hw/uart.hpp>
#include <signetos/vm.hpp>

using namespace signetos;

extern "C" void kernel_main(Capability root_data_cap, uint64_t hartid,
                            Capability dtb_cap) {
  // Discover board hardware (RAM, harts, timebase, CLINT, UART, finisher) from
  // the DTB while physical addressing is still on, then build the boot
  // mappings and switch the MMU on.
  platform::discover(root_data_cap, dtb_cap);
  clint::init(root_data_cap);
  frame::discover(root_data_cap, dtb_cap);
  vm::init(root_data_cap);

  // Initialize UART Console
  uart::init(root_data_cap);

  // Establish the sealing authority root. Every subsystem below assumes its
  // `sealing::authority_for(OType)` is valid, so this is fatal.
  if (!sealing::init_type_root(root_data_cap)) {
    debug::panic(
        "no sealing authority: needs a zyseal -march and "
        "a QEMU run with -cpu rv64,Zyseal=on");
  }

  if (!vm::is_initialized()) {
    debug::panic("vm: boot mappings could not be built");
  }

  // Physical frame allocator, bitmap reached through the direct map.
  frame::init();
  if (!frame::is_initialized()) {
    debug::panic("frame allocator did not initialise");
  }

  // Initialize kernel subsystems
  quota::init();
  // The root VM quota is all the address space alloc_pages hands out
  // (vm.hpp, LAYOUT).
  const Capability system_quota =
      quota::create_root(vm::BITMAP_BASE - vm::DYNAMIC_BASE);

  revoke::init();
  sentry::init(root_data_cap);
  syscall::init();
  compartment::init();
  thread::init();
  thread::init_hart(hartid);
  irq::init();
  irq::init_hart();
  smp::bring_up_secondary_harts(root_data_cap, hartid);

  // The thread memory root, carved out of the VM root. How much of the
  // address space to set aside for threads is policy; 1 GiB for now.
  constexpr uint64_t THREAD_MEMORY_BYTES = 1024ULL * 1024 * 1024;
  const Capability thread_quota =
      thread::create_root_quota(system_quota, THREAD_MEMORY_BYTES);

#ifdef SIGNETOS_QUOTA_SELFTEST
  debug::quota_self_test(system_quota);
#endif

  (void)hartid;

  // Scrub the stack-local root capability before entering user compartments.
  root_data_cap = nullptr;

  const init::Status status = init::launch(system_quota, thread_quota);

  uart::qemu_poweroff(status == init::Status::Ok ? 0 : 1);
}
