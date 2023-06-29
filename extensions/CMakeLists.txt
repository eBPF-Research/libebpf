cmake_minimum_required(VERSION 3.15)

#
# Project details
#

project(
  vm-exten
  LANGUAGES C
)

verbose_message("extensions for vm")

set(SRC_FILE
  src/relo.c
)

if(${CMAKE_PROJECT_NAME}_BUILD_EXECUTABLE)
  add_executable(vm-exten ${SRC_FILE})
  set(${CMAKE_PROJECT_NAME}_EXTEN_LIB ${CMAKE_PROJECT_NAME}_LIB)
else()
  add_library(${CMAKE_PROJECT_NAME} ${SRC_FILE})
  set(${CMAKE_PROJECT_NAME}_EXTEN_LIB ${CMAKE_PROJECT_NAME})
endif()

include(ExternalProject)
ExternalProject_Add(libbpf
  PREFIX libbpf
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make
    BUILD_STATIC_ONLY=1
    OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
    DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
    INCLUDEDIR=
    LIBDIR=
    UAPIDIR=
    install
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

# Set BpfObject input parameters -- note this is usually not necessary unless
# you're in a highly vendored environment (like libbpf-bootstrap)
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)

target_include_directories(${PROJECT_NAME} PUBLIC ${LIBBPF_INCLUDE_DIRS})
add_custom_target(copy_headers
  COMMENT "Copying headers"
)

set(HEADER_FILES relo_core.h hashmap.h nlattr.h libbpf_internal.h)
set(HEADER_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/include/linux)
set(DEST_DIR ${LIBBPF_INCLUDE_DIRS}/linux)
add_custom_command(
  TARGET copy_headers
  COMMAND ${CMAKE_COMMAND} -E copy_directory
  ${HEADER_DIRS}
  ${DEST_DIR}
  COMMENT "Copying directory ${HEADER_DIRS} to ${DEST_DIR}"
)
foreach(file ${HEADER_FILES})
  add_custom_command(
    TARGET copy_headers
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    ${CMAKE_CURRENT_SOURCE_DIR}/libbpf/src/${file}
    ${LIBBPF_INCLUDE_DIRS}/bpf/${file}
    COMMENT "Copying ${file}"
  )
endforeach()

add_dependencies(copy_headers libbpf-build)
add_dependencies(${PROJECT_NAME} copy_headers)
target_link_libraries(${PROJECT_NAME} PUBLIC ${LIBBPF_LIBRARIES} -lelf -lz -lpthread)

# set the -static flag for static linking
set_target_properties(vm-exten PROPERTIES LINK_FLAGS "-static")

target_link_libraries(
  vm-exten
  PUBLIC
    ${${CMAKE_PROJECT_NAME}_EXTEN_LIB}
)

verbose_message("Finished adding unit tests for ${CMAKE_PROJECT_NAME}.")
