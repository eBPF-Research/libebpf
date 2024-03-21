mkdir -p build
cmake -S . -B ./build
cmake --build build --target libebpf_test_runner
