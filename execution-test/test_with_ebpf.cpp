#include "catch2/catch_message.hpp"
#include "libebpf.h"
#include "libebpf_insn.h"
#include "libebpf_map.h"
#include "libebpf_vm.h"
#include <catch2/catch_test_macros.hpp>
#include <iterator>
#include <libebpf_execution.h>
#include <memory>

TEST_CASE("Test map operations with ebpf programs") {
    std::unique_ptr<ebpf_state_t, decltype(&ebpf_state__destroy)> ctx(ebpf_state__create(), ebpf_state__destroy);
    REQUIRE(ctx != nullptr);
    std::unique_ptr<ebpf_vm_t, decltype(&ebpf_vm_destroy)> vm(ebpf_vm_create(), ebpf_vm_destroy);
    REQUIRE(vm != nullptr);
    struct ebpf_map_attr attr {
        .type = EBPF_MAP_TYPE_HASH, .key_size = 8, .value_size = 8, .max_ents = 10, .flags = 0,
    };
    int hash_map_id = ebpf_state__map_create(ctx.get(), "hash_map", &attr);
    uint64_t key = 1, value = 233;
    REQUIRE(ebpf_state__map_elem_update(ctx.get(), hash_map_id, &key, &value, 0) == 0);
    key = 2;
    value = 456;
    REQUIRE(ebpf_state__map_elem_update(ctx.get(), hash_map_id, &key, &value, 0) == 0);
    ebpf_state__setup_internal_helpers(vm.get());

    REQUIRE(hash_map_id >= 0);
    struct libebpf_insn insns[] = { // r7 = map_by_fd(hash_map_id)
                                    BPF_RAW_INSN_IMM64(0x1, 7, hash_map_id, 0),
                                    // r1 = r7
                                    BPF_RAW_INSN(BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_MOV_MOVSX, 1, 7, 0, 0),
                                    // *(r10 - 8) = 1
                                    BPF_RAW_INSN(BPF_CLASS_ST | BPF_LS_MODE_MEM | BPF_LS_SIZE_DW, 10, 0, -8, 1),
                                    // r2 = r10
                                    BPF_RAW_INSN(BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_MOV_MOVSX, 2, 10, 0, 0),
                                    // r2 -= 8
                                    BPF_RAW_INSN(BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_SUB, 2, 0, 0, 8),
                                    // r0 = call bpf_map_lookup_elem
                                    BPF_RAW_INSN(BPF_CLASS_JMP | BPF_JMP_CALL | BPF_SOURCE_IMM, 0, 0, 0, 1),
                                    // r8 = *r0
                                    BPF_RAW_INSN(BPF_CLASS_LDX | BPF_LS_SIZE_DW | BPF_LS_MODE_MEM, 8, 0, 0, 0),
                                    // r1 = r7
                                    BPF_RAW_INSN(BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_MOV_MOVSX, 1, 7, 0, 0),
                                    // *(r10 - 8) = 2
                                    BPF_RAW_INSN(BPF_CLASS_ST | BPF_LS_MODE_MEM | BPF_LS_SIZE_DW, 10, 0, -8, 2),
                                    // r2 = r10
                                    BPF_RAW_INSN(BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_MOV_MOVSX, 2, 10, 0, 0),
                                    // r2 -= 8
                                    BPF_RAW_INSN(BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_SUB, 2, 0, 0, 8),
                                    // r0 = bpf_map_lookup_elem
                                    BPF_RAW_INSN(BPF_CLASS_JMP | BPF_JMP_CALL | BPF_SOURCE_IMM, 0, 0, 0, 1),
                                    // r1 = r7
                                    BPF_RAW_INSN(BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_MOV_MOVSX, 1, 7, 0, 0),
                                    // r6 = *r0
                                    BPF_RAW_INSN(BPF_CLASS_LDX | BPF_LS_SIZE_DW | BPF_LS_MODE_MEM, 6, 0, 0, 0),
                                    // r5 += r6
                                    BPF_RAW_INSN(BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_ADD, 8, 6, 0, 0),
                                    // *(r10 - 16) = 3 <KEY>
                                    BPF_RAW_INSN(BPF_CLASS_ST | BPF_LS_MODE_MEM | BPF_LS_SIZE_DW, 10, 0, -16, 3),
                                    // *(r10 - 8) = r8 <VALUE>
                                    BPF_RAW_INSN(BPF_CLASS_STX | BPF_LS_MODE_MEM | BPF_LS_SIZE_DW, 10, 8, -8, 0),
                                    // r2 = r10
                                    BPF_RAW_INSN(BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_MOV_MOVSX, 2, 10, 0, 0),
                                    // r2 -= 16
                                    BPF_RAW_INSN(BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_SUB, 2, 0, 0, 16),
                                    // r3 = r10
                                    BPF_RAW_INSN(BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_MOV_MOVSX, 3, 10, 0, 0),
                                    // r3 -= 8
                                    BPF_RAW_INSN(BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_SUB, 3, 0, 0, 8),
                                    // r4 = 0
                                    BPF_RAW_INSN(BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_MOV_MOVSX, 4, 0, 0, 0),
                                    // call bpf_map_update_elem
                                    // r0 = bpf_map_update_elem
                                    BPF_RAW_INSN(BPF_CLASS_JMP | BPF_JMP_CALL | BPF_SOURCE_IMM, 0, 0, 0, 2),
                                    // exit
                                    BPF_RAW_INSN(BPF_CLASS_JMP | BPF_JMP_EXIT | BPF_SOURCE_IMM, 0, 0, 0, 0)
    };
    ebpf_state__thread_global_state = ctx.get();
    REQUIRE(ebpf_vm_load_instructions(vm.get(), insns, std::size(insns)) == 0);

    SECTION("Run using intepreter") {
        uint64_t ret;
        REQUIRE(ebpf_vm_run(vm.get(), nullptr, 0, &ret) == 0);
    }
    SECTION("Run using JIT compiler") {
        auto func = ebpf_vm_compile(vm.get());
        REQUIRE(func);
        func(nullptr, 0);
    }
    key = 3;
    REQUIRE(ebpf_state__map_elem_lookup(ctx.get(), hash_map_id, &key, &value) == 0);
    REQUIRE(value == 233 + 456);
}

TEST_CASE("Test execution with JIT") {
    std::unique_ptr<ebpf_vm_t, decltype(&ebpf_vm_destroy)> vm(ebpf_vm_create(), ebpf_vm_destroy);
    struct libebpf_insn insns[] = { // r1 += r2
                                    BPF_RAW_INSN(BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_ADD, 1, 2, 0, 0),
                                    // r0 = r1
                                    BPF_RAW_INSN(BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_MOV_MOVSX, 0, 1, 0, 0)
    };
    REQUIRE(ebpf_vm_load_instructions(vm.get(), insns, std::size(insns)) == 0);
    auto func = ebpf_vm_compile(vm.get());
    INFO(ebpf_error_string());
    REQUIRE(func);
    REQUIRE(func((void *)100, (size_t)5000) == 5000 + 100);
}
