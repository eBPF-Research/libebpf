cmake_minimum_required(VERSION 3.15)

#
# Project details
#
project(
  "libebpf"
  VERSION 0.1.0
  LANGUAGES C CXX
)

add_library(
  libebpf
  STATIC
  src/libebpf.c
  src/libebpf_vm.c
  src/libebpf_vm_verify.c
  src/libebpf_execution.c
  src/libebpf_map_hash.c
  src/libebpf_map_array.c
  src/libebpf_map_ringbuf.c
  src/utils/hashmap.c
)

target_include_directories(
  libebpf
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set_target_properties(libebpf PROPERTIES C_STANDARD 11 C_EXTENSIONS TRUE PREFIX "")

add_subdirectory(vm-test)
add_subdirectory(execution-test)
