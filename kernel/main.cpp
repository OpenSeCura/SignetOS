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

#include <signetos/compartment.hpp>
#include <signetos/frame.hpp>
#include <signetos/init.hpp>
#include <signetos/logo.hpp>
#include <signetos/platform.hpp>
#include <signetos/quota.hpp>
#include <signetos/revoke.hpp>
#include <signetos/sbi.hpp>
#include <signetos/sealing.hpp>
#include <signetos/sentry.hpp>
#include <signetos/thread.hpp>
#include <signetos/trap.hpp>
#include <signetos/types.hpp>
#include <signetos/uart.hpp>
#include <signetos/vm.hpp>

using namespace signetos;

extern "C" void kernel_main(Capability root_data_cap, uint64_t hartid,
                            Capability dtb_cap) {
  // Discover board hardware (RAM, harts, timebase, CLINT, UART, finisher) from
  // the DTB while physical addressing is still on, then build the boot
  // mappings and switch the MMU on.
  platform::discover(root_data_cap, dtb_cap);
  sbi::init(root_data_cap);
  frame::discover(root_data_cap, dtb_cap);
  vm::init(root_data_cap);

  // Initialize UART Console
  uart::init(root_data_cap);

  logo::play(uart::print, platform::timebase_hz() / 1000ULL, true);

  // Establish the sealing authority root. Every subsystem below assumes its
  // `sealing::authority_for(OType)` is valid, so this is fatal.
  if (!sealing::init_type_root(root_data_cap)) {
    uart::panic(
        "no sealing authority: needs a zyseal -march and "
        "a QEMU run with -cpu rv64,Zyseal=on");
  }

  if (!vm::is_initialized()) {
    uart::panic("vm: boot mappings could not be built");
  }

  // Physical frame allocator, bitmap reached through the direct map.
  frame::init();
  if (!frame::is_initialized()) {
    uart::panic("frame allocator did not initialise");
  }

  // Initialize kernel subsystems
  quota::init();
  const Capability system_quota = quota::create_root(frame::pool_bytes());

  revoke::init();
  sentry::init(root_data_cap);
  syscall::init();
  compartment::init();
  thread::init();
  thread::init_hart(hartid);
  trap::init();
  trap::init_hart();
  thread::bring_up_secondary_harts(root_data_cap, hartid);

  // The thread memory root, paid for out of the VM root so that between them
  // they never promise more memory than physically exists. How much to set
  // aside for threads is policy; 16 MiB for now.
  constexpr uint64_t THREAD_MEMORY_BYTES = 16ULL * 1024 * 1024;
  const Capability thread_quota =
      thread::create_root_quota(system_quota, THREAD_MEMORY_BYTES);

  (void)hartid;

  // Scrub the stack-local root capability before entering user compartments.
  root_data_cap = nullptr;

  const init::Status status = init::launch(system_quota, thread_quota);

  uart::qemu_poweroff(status == init::Status::Ok ? 0 : 1);
}
