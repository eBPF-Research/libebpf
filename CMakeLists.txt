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
  libebpf_objects
  OBJECT
  src/libebpf.c
  src/libebpf_vm.c
  src/libebpf_vm_verify.c
  src/libebpf_execution.c
  src/libebpf_map_hash.c
  src/libebpf_map_array.c
  src/libebpf_map_ringbuf.c
  src/libebpf_execution_helpers.c
  src/utils/hashmap.c
)
target_compile_definitions(libebpf_objects PRIVATE -D_GNU_SOURCE)
target_include_directories(
  libebpf_objects
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set_target_properties(libebpf_objects PROPERTIES C_STANDARD 11 C_EXTENSIONS TRUE)

set(SPACE " ")


add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libebpf.o
  DEPENDS  $<TARGET_OBJECTS:libebpf_objects> ${CMAKE_CURRENT_SOURCE_DIR}/src/libebpf.ld
  COMMAND ${CMAKE_C_COMPILER} -r -T ${CMAKE_CURRENT_SOURCE_DIR}/src/libebpf.ld -o ${CMAKE_CURRENT_BINARY_DIR}/libebpf.o $<TARGET_OBJECTS:libebpf_objects>
  COMMAND_EXPAND_LISTS
)

add_library(libebpf STATIC ${CMAKE_CURRENT_BINARY_DIR}/libebpf.o)

set_target_properties(libebpf PROPERTIES PREFIX "" LINKER_LANGUAGE C)


add_subdirectory(vm-test)
add_subdirectory(execution-test)
