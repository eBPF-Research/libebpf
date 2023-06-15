# Allow user to specify the architecture
if(NOT DEFINED ARCH)
  set(ARCH ${CMAKE_SYSTEM_PROCESSOR})
endif()

message(STATUS "Building for architecture: ${ARCH}")

# Detect the architecture
if(ARCH MATCHES "arm")
  message(STATUS "arm architecture detected")
  set(ARCH_SOURCES
    # src/arch/arm/bpf_jit_32.c
    src/ebpf_jit_arm32.c
  )
  set(ARCH_HEADERS
    src/
  )
elseif(ARCH MATCHES "aarch64")
  message(STATUS "arm64 architecture detected")
  set(ARCH_SOURCES
    src/arch/arm64/bpf_jit_comp.c
    src/arch/arm64/insn.c
    src/ebpf_jit_arm64.c
  )
  set(ARCH_HEADERS
    src/arch/arm64/
  )
elseif(ARCH MATCHES "riscv")
  message(STATUS "riscv architecture detected")
  set(ARCH_SOURCES
    src/arch/riscv/bpf_jit_comp64.c
    src/arch/riscv/bpf_jit_core.c
  )
  set(ARCH_HEADERS
    src/arch/riscv/
  )
elseif(ARCH MATCHES "x86_64" OR ARCH MATCHES "i686" OR ARCH MATCHES "i386")
  message(STATUS "x86 architecture detected")
  set(ARCH_SOURCES
    src/arch/x86/bpf_jit_comp.c
    src/ebpf_jit_x86_64.c
  )
  set(ARCH_HEADERS
    src/arch/x86/
  )
else()
  message(FATAL_ERROR "Unsupported architecture")
endif()

set(sources
  ${ARCH_SOURCES}
  src/ebpf_jit.c
  src/ebpf_vm.c
  src/linux_bpf_core.c
)

set(exe_sources
    example/main.c
    ${sources}
)

set(headers
    include/
    src/
    ${ARCH_HEADERS}
    ${headerfiles}
)
message(STATUS ${headers})

set(test_sources
  src/tmp_test.cpp
)
