cmake_minimum_required(VERSION 3.15)

#
# Project details
#
project(
  "libebpf"
  VERSION 0.1.0
  LANGUAGES C CXX
)
set(LIBEBPF_SOURCE_LIST
  src/libebpf.c
  src/libebpf_vm.c
  src/libebpf_vm_verify.c
  src/libebpf_execution.c
  src/libebpf_map_hash.c
  src/libebpf_map_array.c
  src/libebpf_map_ringbuf.c
  src/libebpf_execution_helpers.c
  src/libebpf_ffi_functions.c
  src/utils/hashmap.c
)
set(LIBEBPF_JIT_ENABLED FALSE)

# set(CMAKE_SYSTEM_PROCESSOR "aarch64")

if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
  list(APPEND LIBEBPF_SOURCE_LIST src/jit/x86_64/ubpf_jit_x86_64.c)
  set(LIBEBPF_JIT_ENABLED TRUE)
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
  list(APPEND LIBEBPF_SOURCE_LIST src/jit/arm64/ubpf_jit_arm64.c)
  set(LIBEBPF_JIT_ENABLED TRUE)
else()
  message(WARNING "JIT is not supported on ${CMAKE_SYSTEM_PROCESSOR}")
endif()

if(${LIBEBPF_JIT_ENABLED})
  message(STATUS "Enabling JIT on ${CMAKE_SYSTEM_PROCESSOR}")
  add_compile_definitions(LIBEBPF_ENABLE_JIT=1)
  list(APPEND LIBEBPF_SOURCE_LIST
    src/jit/helper_adaptor.c)
endif()

add_library(
  libebpf_objects
  OBJECT
  ${LIBEBPF_SOURCE_LIST}
)
target_compile_definitions(libebpf_objects PRIVATE -D_GNU_SOURCE)
target_include_directories(
  libebpf_objects
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set_target_properties(libebpf_objects PROPERTIES C_STANDARD 11 C_EXTENSIONS TRUE)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libebpf.o
  DEPENDS $<TARGET_OBJECTS:libebpf_objects> ${CMAKE_CURRENT_SOURCE_DIR}/src/libebpf.ld
  COMMAND ${CMAKE_C_COMPILER} -r -T ${CMAKE_CURRENT_SOURCE_DIR}/src/libebpf.ld -o ${CMAKE_CURRENT_BINARY_DIR}/libebpf.o $<TARGET_OBJECTS:libebpf_objects>
  COMMAND_EXPAND_LISTS
)

add_library(libebpf STATIC ${CMAKE_CURRENT_BINARY_DIR}/libebpf.o)

set_target_properties(libebpf PROPERTIES PREFIX "" LINKER_LANGUAGE C)
target_include_directories(
  libebpf
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_subdirectory(vm-test)
add_subdirectory(execution-test)
