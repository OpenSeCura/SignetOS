# Building QEMU

[https://github.com/CTSRD-CHERI/cheribuild](https://github.com/CTSRD-CHERI/cheribuild) 

NOTES:  
It pulls cheribuild and everything from the regular cheribuild repo: [https://github.com/CTSRD-CHERI/cheribuild\#debianubuntu](https://github.com/CTSRD-CHERI/cheribuild#debianubuntu) make sure to install the dependencies before you start to make things go more smoothly.

I ran cheribuild with the following command: 

```
./cheribuild.py run-minimal-cheri-linux-riscv64-purecap -d
```

But you probably don’t need the linux and can maybe replace with qemu only. 

# Building and Running Bare-Metal Applications in QEMU

## 1\. Setup Environment Variables

# First, define paths to your specific compiler and QEMU instance. Update these paths if your toolchain is installed in a different location.

```
export COMPILER="~/cheri/output/cheri-std093-sdk/bin/clang"
export QEMU="~/cheri/build/cheri-std093-qemu-build/qemu-system-riscv64xcheri"
```

## 2\. Compile and Link the Executable

# Since you are building a bare-metal application, you cannot rely on the host operating system's standard libraries or default startup logic. You must provide your own linker script and pass specific flags to structure the executable for bare-metal execution.

```
$COMPILER -O2 -g \
  --target=riscv64 -march=rv64gxcheri -mabi=l64pc128d -mcmodel=medany \
  -ffreestanding -fno-pic -fno-pie -nostdlib -nostartfiles \
  -fno-exceptions -fno-rtti -fno-threadsafe-statics \
  -T your_linker_script.ld \
  your_object_files.o ... \
  -o your_output_binary.elf
```

### Important Compile & Link Flags:

* # **Architecture Flags** (\--target, \-march, \-mabi): Configures the target to compile for RISC-V 64-bit with CHERI capability extensions.

* # **\-mcmodel=medany**: Generates code using the "medium-any" code model, which is the standard approach for RISC-V kernels allowing code execution at any address layout.

* # **\-ffreestanding \-nostdlib \-nostartfiles**: Tells the compiler **not** to bundle the standard C/C++ library or default OS entry-point code. Your codebase must provide its own entry point (e.g., typically \_start inside a custom boot.S).

* # **\-fno-exceptions \-fno-rtti**: Disables exceptions and runtime type information since these mechanisms rely on standard libraries and OS runtime support.

* # **\-fno-pic \-fno-pie**: Disables Position Independent Code/Executables, streamlining linking for flat, static address spaces.

* # **\-T your\_linker\_script.ld**: Relies on a customizable Linker Script that dictates exactly how the binary sections (.text, .data, .bss) should be loaded into physical memory.

#### Example RISC-V Linker Script
The linker flag flag requires a script to tell the compiler where to put everything in memory. Below is a minimal linker script.

```ld
OUTPUT_ARCH( "riscv" )
ENTRY( _start )

MEMORY
{
  /* QEMU's RISC-V 'virt' machine's physical RAM always starts at 0x80000000 */
  /* We configure 128MB length (0x8000000) explicitly here */
  RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 0x8000000
}

SECTIONS
{
  .text : {
    /* Put the _start symbol entry routines right at the top */
    *(.text.init)
    /* Followed by the rest of the executable code */
    *(.text)
  } > RAM

  .rodata : ALIGN(16) {
    *(.rodata)
  } > RAM

  .data : ALIGN(16) {
    *(.data)
  } > RAM

  /* The BSS section contains uninitialized global variables.
     Bare-metal startup code usually relies on __bss_start and __bss_end
     to manually zero out this memory space upon boot. */
  .bss : ALIGN(16) {
    __bss_start = .;
    *(.bss)
    . = ALIGN(16);
    __bss_end = .;
  } > RAM

  . = ALIGN(16);
  PROVIDE( _end = . );
}
```

## 3\. Run with QEMU

# Once your executable (.elf) is successfully built, use QEMU to act as the hardware and run it.

```
$QEMU -machine virt -bios none -m 128M -nographic -kernel your_output_binary.elf
```

### QEMU Execution Flags:

* # **\-machine virt**: Uses QEMU's generic RISC-V virtual machine framework. This provides a baseline set of emulated peripherals (like a UART for console output) without tying it to a specific physical dev board.

* # **\-bios none**: Disables default boot firmware (like OpenSBI or firmware that jumps to supervisor mode). This tells QEMU to load your binary and immediately hand off control to it in Machine Mode (M-Mode).

* # **\-m 128M**: Determines how much physical RAM to provision to the virtual machine (adjust size as needed).

* # **\-nographic**: Disables all QEMU graphical windows. It redirects the emulated system's serial port (UART) directly into your current terminal output, which is ideal for bare-metal printf logging.

* # **\-kernel ...**: Specifies the .elf binary image to inject into the virtual memory spacing and boot from.

# 

