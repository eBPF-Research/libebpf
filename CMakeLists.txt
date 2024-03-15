cmake_minimum_required(VERSION 3.15)

#
# Project details
#
project(
  "libebpf"
  VERSION 0.1.0
  LANGUAGES C
)

add_library(
  libebpf
  STATIC
  src/libebpf.c
  src/libebpf_vm.c
  src/libebpf_verify.c
)

target_include_directories(
  libebpf
  INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src
)

set_target_properties(libebpf PROPERTIES C_STANDARD 11)

add_subdirectory(test)
