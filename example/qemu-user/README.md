# qemu user hello world

> tested on ubuntu 22.04

Assuming you have a simple C program and want to compile it for ARM architecture (for instance), and run it using QEMU User mode, the steps will be as follows.

Let's say you have a simple "Hello, World!" C program, named `hello.c`.

```c
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
```

1. First, you need a cross-compiler to compile your C program for the ARM architecture. If you're using a Debian-based system, you can get it using apt:

```bash
sudo apt-get install gcc-arm-linux-gnueabi
```

2. Now, you can compile your C program with the cross-compiler:

```bash
arm-linux-gnueabi-gcc -static -o hello hello.c
```

The `-static` flag tells the compiler to include all the necessary libraries within the binary itself, which will make it easier to run on a different system.

3. Now, you have an ARM binary named `hello` that you can run with QEMU User mode. First, you need to install QEMU User mode. Again, if you're using a Debian-based system, you can use apt:

```bash
sudo apt-get install qemu-user
```

4. With QEMU User mode installed, you can now run your ARM binary on your x86_64 system:

```bash
qemu-arm ./hello
```

If everything has been set up correctly, it should print "Hello, World!" to your terminal.

Remember, you need to adjust this instruction to match the architecture of your binary and the specifics of your system.

## use cmake for cross build app to arm(32 bit) and run with qemu

To cross-compile a C application for ARM using CMake and run it using QEMU, you'll first need an ARM cross-compiler and QEMU installed on your system. If you're using Ubuntu, you can install them with:

```bash
sudo apt-get install gcc-arm-linux-gnueabi qemu-user
```

Then, you'll need a CMake toolchain file to specify the cross-compiler and target system. Create a file named `arm-toolchain.cmake` with the following content:

```cmake
# this one is important
SET(CMAKE_SYSTEM_NAME Linux)
#this one not so much
SET(CMAKE_SYSTEM_VERSION 1)

# specify the cross compiler
SET(CMAKE_C_COMPILER   arm-linux-gnueabi-gcc)
SET(CMAKE_CXX_COMPILER arm-linux-gnueabi-g++)

# where is the target environment 
SET(CMAKE_FIND_ROOT_PATH  /usr/arm-linux-gnueabi)

# search for programs in the build host directories
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# for libraries and headers in the target directories
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
```

Next, in the directory of your `CMakeLists.txt`, create a `build` directory and configure the build with the toolchain file:

```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=../arm-toolchain.cmake ..
```

Then, build the application with `make`:

```bash
make
```

You should now have an ARM binary that you can run with QEMU:

```bash
qemu-arm your_binary
```

This is a basic example and may need to be adjusted based on your specific application and system. The toolchain file, in particular, might need modifications to point to the correct locations for your cross-compiler and target system libraries.

Remember that not all programs can be successfully cross-compiled. The program in question must be capable of running on the target architecture, and all its dependencies must also be available for that architecture.

On error:

```console
$ qemu-arm HelloWorld
qemu-arm: Could not open '/lib/ld-linux.so.3': No such file or directory
```

The error you're seeing (`qemu-arm: Could not open '/lib/ld-linux.so.3': No such file or directory`) typically happens when you're trying to run a dynamically linked ARM binary on a host system that does not have the necessary ARM libraries.

One way to overcome this is to compile your application statically. To do this, you can modify the CMakeLists.txt file to use static linking by setting the `-static` flag:

```cmake
cmake_minimum_required(VERSION 3.10)
project(HelloWorld C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

add_executable(HelloWorld hello.c)

# set the -static flag for static linking
set_target_properties(HelloWorld PROPERTIES LINK_FLAGS "-static")
```

After you modify the `CMakeLists.txt`, you can try compiling and running the application again:

```bash
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=../arm-toolchain.cmake ..
make
qemu-arm HelloWorld
```

With `-static` flag, the binary will include all the necessary libraries within the binary itself, which makes it more portable and it should run correctly under `qemu-arm`.