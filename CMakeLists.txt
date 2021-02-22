cmake_minimum_required(VERSION 3.4)

project(LibEbpf VERSION 0.1 LANGUAGES C CXX)

set(APP_TARGET LibEbpf)
# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

add_definitions(-DWin32)

SET(CMAKE_C_FLAGS "-g")

file(GLOB libsrc
		"${PROJECT_SOURCE_DIR}/ebpf-src/*.h"
        "${PROJECT_SOURCE_DIR}/ebpf-src/*.c")

add_library(ebpf STATIC ${libsrc})

include_directories(
    "${PROJECT_SOURCE_DIR}/"
    "${PROJECT_SOURCE_DIR}/ebpf-src"
)

add_definitions(-DLINUX_TEST)

add_executable(linux_ebpf
    "${PROJECT_SOURCE_DIR}/examples/linux/main.c"
)

target_link_libraries(linux_ebpf ebpf)

set_target_properties(linux_ebpf PROPERTIES 
    RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin
    OUTPUT_NAME "ebpf.elf"
    )

add_custom_target(linux 
    COMMAND make
    COMMAND ../bin/ebpf.elf
    )