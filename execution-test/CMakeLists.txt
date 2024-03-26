add_subdirectory(catch2)

add_executable(
    ebpf_execution_context_test
    ./test_map.cpp
    ./test_with_ebpf.cpp
    ./test_ffi.cpp
)

add_dependencies(ebpf_execution_context_test
    Catch2
    libebpf
)
target_link_libraries(ebpf_execution_context_test
    PRIVATE
    libebpf
    Catch2::Catch2WithMain
)

target_include_directories(ebpf_execution_context_test PRIVATE ${Catch2_INCLUDE} ${CMAKE_CURRENT_SOURCE_DIR}/../src)

set_target_properties(ebpf_execution_context_test PROPERTIES CXX_STANDARD 20 LINKER_LANGUAGE CXX) 
target_compile_options(ebpf_execution_context_test PRIVATE -fsanitize=address -fsanitize=undefined -D_LIBEBPF_UNIT_TEST)
target_link_options(ebpf_execution_context_test PRIVATE -fsanitize=address -fsanitize=undefined)
