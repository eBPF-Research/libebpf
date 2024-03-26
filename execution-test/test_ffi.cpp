#include "libebpf_ffi.h"
#include <catch2/catch_test_macros.hpp>
#include <libebpf_ffi.bpf.h>
#include <libebpf_vm.h>
#include <libebpf_execution.h>
#include <memory>
extern "C" {
#include <libebpf_internal.h>
}

static int32_t int32_plus(int32_t a, int32_t b) {
    return a + b;
}
static uint32_t uint32_plus(uint32_t a, uint32_t b) {
    return a + b;
}
static uint64_t uint64_plus(uint64_t a, uint64_t b) {
    return a + b;
}
TEST_CASE("Test FFI calls, without eBPF program") {
    std::unique_ptr<ebpf_execution_context_t, decltype(&ebpf_execution_context__destroy)> ctx(ebpf_execution_context__create(),
                                                                                              ebpf_execution_context__destroy);
    REQUIRE(ctx != nullptr);
    ebpf_execution_context__thread_global_context = ctx.get();
    std::unique_ptr<ebpf_vm_t, decltype(&ebpf_vm_destroy)> vm(ebpf_vm_create(), ebpf_vm_destroy);
    REQUIRE(vm != nullptr);
    ebpf_execution_context__setup_internal_helpers(vm.get());
    int uint32_plus_id;
    {
        enum libebpf_ffi_type args[6] = { ARG_UINT32, ARG_UINT32, ARG_VOID, ARG_VOID, ARG_VOID, ARG_VOID };
        uint32_plus_id = ebpf_execution_context__register_ffi_function(ctx.get(), (void *)&uint32_plus, "uint32_plus", args, ARG_UINT32);
        REQUIRE(uint32_plus_id >= 0);
    }
    int uint64_plus_id;
    {
        enum libebpf_ffi_type args[6] = { ARG_UINT64, ARG_UINT64, ARG_VOID, ARG_VOID, ARG_VOID, ARG_VOID };
        uint64_plus_id = ebpf_execution_context__register_ffi_function(ctx.get(), (void *)&uint64_plus, "uint64_plus", args, ARG_UINT64);
        REQUIRE(uint64_plus_id >= 0);
    }
    int int32_plus_id;
    {
        enum libebpf_ffi_type args[6] = { ARG_INT32, ARG_INT32, ARG_VOID, ARG_VOID, ARG_VOID, ARG_VOID };
        int32_plus_id = ebpf_execution_context__register_ffi_function(ctx.get(), (void *)&int32_plus, "int32_plus", args, ARG_INT32);
        REQUIRE(int32_plus_id >= 0);
    }
    auto libebpf_ffi_lookup_by_name = [&](const char *name) -> int {
        return ebpf_vm_call_helper(vm.get(), LIBEBPF_FFI_HELPER_INDEX__LOOKUP_BY_NAME, (uintptr_t)name, 0, 0, 0, 0);
    };
    auto libebpf_ffi_call = [&](int func_id, libebpf_ffi_call_argument_list *args) -> int64_t {
        return ebpf_vm_call_helper(vm.get(), LIBEBPF_FFI_HELPER_INDEX__CALL, (uint32_t)func_id, (uintptr_t)args, 0, 0, 0);
    };
    REQUIRE(libebpf_ffi_lookup_by_name("int32_plus") == int32_plus_id);
    REQUIRE(libebpf_ffi_lookup_by_name("uint32_plus") == uint32_plus_id);
    REQUIRE(libebpf_ffi_lookup_by_name("uint64_plus") == uint64_plus_id);
    {
        // Test int32 plus
        int64_t result = LIBEBPF_FFI_CALL_BY_ID_ARG2(int32_plus_id, 111, -222);
        REQUIRE(result == 111 - 222);
        result = LIBEBPF_FFI_CALL_BY_NAME_ARG2(int32_plus, 111, -222);
        REQUIRE(result == 111 - 222);
    }
    {
        // Test uint32 plus
        // If it overflows..
        int64_t result = LIBEBPF_FFI_CALL_BY_ID_ARG2(uint32_plus_id, UINT32_MAX - 1, 10);
        REQUIRE(result == 8);
        result = LIBEBPF_FFI_CALL_BY_NAME_ARG2(uint32_plus, UINT32_MAX - 1, 10);
        REQUIRE(result == 8);
    }
    {
        // Test uint64 plus
        // If it overflows..
        int64_t result = LIBEBPF_FFI_CALL_BY_ID_ARG2(uint32_plus_id, (int64_t)(UINT64_MAX - 233), 10000);
        REQUIRE(result == 9766);
        result = LIBEBPF_FFI_CALL_BY_NAME_ARG2(uint32_plus, (int64_t)(UINT64_MAX - 233), 10000);
        REQUIRE(result == 9766);
    }
}
