file(GLOB srcfiles
    "${PROJECT_SOURCE_DIR}/src/*.c")
file(GLOB headerfiles
		"${PROJECT_SOURCE_DIR}/src/*.h")

# Detect the architecture
if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
  message(STATUS "arm architecture detected")
  set(ARCH_SOURCES
    src/arch/arm/bpf_jit_32.c
  )
  set(ARCH_HEADERS
    src/arch/arm/
  )
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
  message(STATUS "arm64 architecture detected")
  set(ARCH_SOURCES
    src/arch/arm64/bpf_jit_comp.c
    src/arch/arm64/insn.c
  )
  set(ARCH_HEADERS
    src/arch/arm64/
  )
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "riscv")
  message(STATUS "riscv architecture detected")
  set(ARCH_SOURCES
    src/arch/riscv/bpf_jit_comp64.c
    src/arch/riscv/bpf_jit_core.c
  )
  set(ARCH_HEADERS
    src/arch/riscv/
  )
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "i686" OR CMAKE_SYSTEM_PROCESSOR MATCHES "i386")
  message(STATUS "x86 architecture detected")
  set(ARCH_SOURCES
    src/arch/x86/bpf_jit_comp.c
  )
  set(ARCH_HEADERS
    src/arch/x86/
  )
else()
  message(FATAL_ERROR "Unsupported architecture")
endif()

set(sources
  ${ARCH_SOURCES}
  ${srcfiles}
)

set(exe_sources
    example/main.c
		${sources}
)

set(headers
    include/
    ${ARCH_HEADERS}
    ${headerfiles}
)
message(STATUS ${headers})

set(test_sources
  src/tmp_test.cpp
)
