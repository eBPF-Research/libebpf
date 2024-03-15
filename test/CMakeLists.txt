add_executable(libebpf_test_runner ./test_runner/test_runner.c)
add_dependencies(libebpf_test_runner libebpf)
target_link_libraries(libebpf_test_runner PRIVATE libebpf m)
