add_subdirectory(catch2)

add_executable(
    ebpf_state_test
    ./test_map.cpp
    ./test_with_ebpf.cpp
    ./test_ffi.cpp
)

add_dependencies(ebpf_state_test
    Catch2
    libebpf
)
target_link_libraries(ebpf_state_test
    PRIVATE
    libebpf
    Catch2::Catch2WithMain
)

target_include_directories(ebpf_state_test PRIVATE ${Catch2_INCLUDE} ${CMAKE_CURRENT_SOURCE_DIR}/../src)

set_target_properties(ebpf_state_test PROPERTIES CXX_STANDARD 20 LINKER_LANGUAGE CXX) 
target_compile_options(ebpf_state_test PRIVATE -fsanitize=address -fsanitize=undefined -D_LIBEBPF_UNIT_TEST)
target_link_options(ebpf_state_test PRIVATE -fsanitize=address -fsanitize=undefined)
