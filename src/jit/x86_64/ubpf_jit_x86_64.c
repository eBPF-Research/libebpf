// Copyright (c) 2015 Big Switch Networks, Inc
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "libebpf_internal.h"
#include "libebpf_vm.h"
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include "ubpf_jit_x86_64.h"
#include <libebpf_insn.h>
#if !defined(_countof)
#define _countof(array) (sizeof(array) / sizeof(array[0]))
#endif

static void muldivmod(struct jit_state *state, uint8_t opcode, int src, int dst, int32_t imm);

#define REGISTER_MAP_SIZE 11

/*
 * There are two common x86-64 calling conventions, as discussed at
 * https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions
 *
 * Please Note: R12 is special and we are *not* using it. As a result, it is omitted
 * from the list of non-volatile registers for both platforms (even though it is, in
 * fact, non-volatile).
 *
 * BPF R0-R4 are "volatile"
 * BPF R5-R10 are "non-volatile"
 * In general, we attempt to map BPF volatile registers to x64 volatile and BPF non-
 * volatile to x64 non-volatile.
 */
#define RCX_ALT R9
static int platform_nonvolatile_registers[] = { RBP, RBX, R13, R14, R15 };
static int platform_parameter_registers[] = { RDI, RSI, RDX, RCX, R8, R9 };
static int register_map[REGISTER_MAP_SIZE] = {
    RAX, RDI, RSI, RDX, R9, R8, RBX, R13, R14, R15, RBP,
};

/* Return the x86 register for the given eBPF register */
static int map_register(int r) {
    assert(r < _BPF_REG_MAX);
    return register_map[r % _BPF_REG_MAX];
}

static inline void emit_local_call(struct jit_state *state, uint32_t target_pc) {
    /*
     * Pushing 4 * 8 = 32 bytes will maintain the invariant
     * that the stack is 16-byte aligned.
     */
    emit_push(state, map_register(BPF_REG_6));
    emit_push(state, map_register(BPF_REG_7));
    emit_push(state, map_register(BPF_REG_8));
    emit_push(state, map_register(BPF_REG_9));

    emit1(state, 0xe8); // e8 is the opcode for a CALL
    emit_jump_target_address(state, target_pc);

    emit_pop(state, map_register(BPF_REG_9));
    emit_pop(state, map_register(BPF_REG_8));
    emit_pop(state, map_register(BPF_REG_7));
    emit_pop(state, map_register(BPF_REG_6));
}
extern uint64_t ebpf_ubpf_jit_dispatcher_adaptor(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, unsigned int index,
                                                 ebpf_vm_t *vm);
static uint32_t emit_dispatched_external_helper_address(struct jit_state *state, struct ebpf_vm *vm) {
    uint32_t external_helper_address_target = state->offset;
    emit8(state, (uint64_t)ebpf_ubpf_jit_dispatcher_adaptor);
    return external_helper_address_target;
}

static uint32_t emit_retpoline(struct jit_state *state) {
    /*
     * Using retpolines to mitigate spectre/meltdown. Adapting the approach
     * from
     * https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/retpoline-branch-target-injection-mitigation.html
     */

    /* label0: */
    /* call label1 */
    uint32_t retpoline_target = state->offset;
    emit1(state, 0xe8);
    uint32_t label1_call_offset = state->offset;
    emit4(state, 0x00);

    /* capture_ret_spec: */
    /* pause */
    uint32_t capture_ret_spec = state->offset;
    emit1(state, 0xf3);
    emit1(state, 0x90);
    /* jmp  capture_ret_spec */
    emit1(state, 0xe9);
    emit_jump_target_offset(state, state->offset, capture_ret_spec);
    emit4(state, 0x00);

    /* label1: */
    /* mov rax, (rsp) */
    uint32_t label1 = state->offset;
    emit1(state, 0x48);
    emit1(state, 0x89);
    emit1(state, 0x04);
    emit1(state, 0x24);

    /* ret */
    emit1(state, 0xc3);

    emit_jump_target_offset(state, label1_call_offset, label1);

    return retpoline_target;
}

/* For testing, this changes the mapping between x86 and eBPF registers */
// void ubpf_set_register_offset(int x) {
//     int i;
//     if (x < REGISTER_MAP_SIZE) {
//         int tmp[REGISTER_MAP_SIZE];
//         memcpy(tmp, register_map, sizeof(register_map));
//         for (i = 0; i < REGISTER_MAP_SIZE; i++) {
//             register_map[i] = tmp[(i + x) % REGISTER_MAP_SIZE];
//         }
//     } else {
//         /* Shuffle array */
//         unsigned int seed = x;
//         for (i = 0; i < REGISTER_MAP_SIZE - 1; i++) {
//             int j = i + (rand_r(&seed) % (REGISTER_MAP_SIZE - i));
//             int tmp = register_map[j];
//             register_map[j] = register_map[i];
//             register_map[i] = tmp;
//         }
//     }
// }

static int translate(struct ebpf_vm *vm, struct jit_state *state) {
    int i;

    /* Save platform non-volatile registers */
    for (i = 0; i < _countof(platform_nonvolatile_registers); i++) {
        emit_push(state, platform_nonvolatile_registers[i]);
    }

    /* Move first platform parameter register into register 1 */
    if (map_register(1) != platform_parameter_registers[0]) {
        emit_mov(state, platform_parameter_registers[0], map_register(BPF_REG_1));
    }

    /*
     * Assuming that the stack is 16-byte aligned right before
     * the call insn that brought us to this code, when
     * we start executing the jit'd code, we need to regain a 16-byte
     * alignment. The UBPF_STACK_SIZE is guaranteed to be
     * divisible by 16. However, if we pushed an even number of
     * registers on the stack when we are saving state (see above),
     * then we have to add an additional 8 bytes to get back
     * to a 16-byte alignment.
     */
    if (!(_countof(platform_nonvolatile_registers) % 2)) {
        emit_alu64_imm32(state, 0x81, 5, RSP, 0x8);
    }

    /*
     * Set BPF R10 (the way to access the frame in eBPF) to match RSP.
     */
    emit_mov(state, RSP, map_register(BPF_REG_10));

    /* Allocate stack space */
    emit_alu64_imm32(state, 0x81, 5, RSP, EBPF_STACK_SIZE);

    /*
     * Use a call to set up a place where we can land after eBPF program's
     * final EXIT call. This makes it appear to the ebpf programs
     * as if they are called like a function. It is their responsibility
     * to deal with the non-16-byte aligned stack pointer that goes along
     * with this pretense.
     */
    emit1(state, 0xe8);
    emit4(state, 5);
    /*
     * We jump over this instruction in the first place; return here
     * after the eBPF program is finished executing.
     */
    emit_jmp(state, TARGET_PC_EXIT);

    for (i = 0; i < vm->insn_cnt; i++) {
        struct libebpf_insn *inst = &vm->insns[i];
        state->pc_locs[i] = state->offset;

        int dst = map_register(inst->dst_reg);
        int src = map_register(inst->src_reg);
        uint32_t target_pc = i + inst->offset + 1;

        if (i == 0 || vm->begin_of_local_function[i]) {
            /* When we are the subject of a call, we have to properly align our
             * stack pointer.
             */
            emit_alu64_imm32(state, 0x81, 5, RSP, 8);
        }

        switch (inst->code) {
        case BPF_CLASS_ALU | BPF_SOURCE_IMM | BPF_ALU_ADD:
            emit_alu32_imm32(state, 0x81, 0, dst, inst->imm);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_REG | BPF_ALU_ADD:
            emit_alu32(state, 0x01, src, dst);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_IMM | BPF_ALU_SUB:
            emit_alu32_imm32(state, 0x81, 5, dst, inst->imm);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_REG | BPF_ALU_SUB:
            emit_alu32(state, 0x29, src, dst);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_IMM | BPF_ALU_MUL:
        case BPF_CLASS_ALU | BPF_SOURCE_REG | BPF_ALU_MUL:
        case BPF_CLASS_ALU | BPF_SOURCE_IMM | BPF_ALU_DIV_SDIV:
        case BPF_CLASS_ALU | BPF_SOURCE_REG | BPF_ALU_DIV_SDIV:
        case BPF_CLASS_ALU | BPF_SOURCE_IMM | BPF_ALU_MOD_SMOD:
        case BPF_CLASS_ALU | BPF_SOURCE_REG | BPF_ALU_MOD_SMOD:
            muldivmod(state, inst->code, src, dst, inst->imm);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_IMM | BPF_ALU_OR:
            emit_alu32_imm32(state, 0x81, 1, dst, inst->imm);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_REG | BPF_ALU_OR:
            emit_alu32(state, 0x09, src, dst);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_IMM | BPF_ALU_AND:
            emit_alu32_imm32(state, 0x81, 4, dst, inst->imm);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_REG | BPF_ALU_AND:
            emit_alu32(state, 0x21, src, dst);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_IMM | BPF_ALU_LSH:
            emit_alu32_imm8(state, 0xc1, 4, dst, inst->imm);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_REG | BPF_ALU_LSH:
            emit_mov(state, src, RCX);
            emit_alu32(state, 0xd3, 4, dst);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_IMM | BPF_ALU_RSH:
            emit_alu32_imm8(state, 0xc1, 5, dst, inst->imm);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_REG | BPF_ALU_RSH:
            emit_mov(state, src, RCX);
            emit_alu32(state, 0xd3, 5, dst);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_IMM | BPF_ALU_NEG:
        case BPF_CLASS_ALU | BPF_SOURCE_REG | BPF_ALU_NEG:
            emit_alu32(state, 0xf7, 3, dst);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_IMM | BPF_ALU_XOR:
            emit_alu32_imm32(state, 0x81, 6, dst, inst->imm);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_REG | BPF_ALU_XOR:
            emit_alu32(state, 0x31, src, dst);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_IMM | BPF_ALU_MOV_MOVSX:
            emit_alu32_imm32(state, 0xc7, 0, dst, inst->imm);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_REG | BPF_ALU_MOV_MOVSX:
            emit_mov(state, src, dst);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_IMM | BPF_ALU_ARSH:
            emit_alu32_imm8(state, 0xc1, 7, dst, inst->imm);
            break;
        case BPF_CLASS_ALU | BPF_SOURCE_REG | BPF_ALU_ARSH:
            emit_mov(state, src, RCX);
            emit_alu32(state, 0xd3, 7, dst);
            break;

        case BPF_CLASS_ALU | BPF_END_TO_LE | BPF_ALU_END:
            /* No-op */
            break;
        case BPF_CLASS_ALU | BPF_END_TO_BE | BPF_ALU_END:
            if (inst->imm == 16) {
                /* rol */
                emit1(state, 0x66); /* 16-bit override */
                emit_alu32_imm8(state, 0xc1, 0, dst, 8);
                /* and */
                emit_alu32_imm32(state, 0x81, 4, dst, 0xffff);
            } else if (inst->imm == 32 || inst->imm == 64) {
                /* bswap */
                emit_basic_rex(state, inst->imm == 64, 0, dst);
                emit1(state, 0x0f);
                emit1(state, 0xc8 | (dst & 7));
            }
            break;

        case BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_ADD:
            emit_alu64_imm32(state, 0x81, 0, dst, inst->imm);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_ADD:
            emit_alu64(state, 0x01, src, dst);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_SUB:
            emit_alu64_imm32(state, 0x81, 5, dst, inst->imm);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_SUB:
            emit_alu64(state, 0x29, src, dst);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_MUL:
        case BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_MUL:
        case BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_DIV_SDIV:
        case BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_DIV_SDIV:
        case BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_MOD_SMOD:
        case BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_MOD_SMOD:
            muldivmod(state, inst->code, src, dst, inst->imm);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_OR:
            emit_alu64_imm32(state, 0x81, 1, dst, inst->imm);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_OR:
            emit_alu64(state, 0x09, src, dst);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_AND:
            emit_alu64_imm32(state, 0x81, 4, dst, inst->imm);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_AND:
            emit_alu64(state, 0x21, src, dst);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_LSH:
            emit_alu64_imm8(state, 0xc1, 4, dst, inst->imm);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_LSH:
            emit_mov(state, src, RCX);
            emit_alu64(state, 0xd3, 4, dst);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_RSH:
            emit_alu64_imm8(state, 0xc1, 5, dst, inst->imm);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_RSH:
            emit_mov(state, src, RCX);
            emit_alu64(state, 0xd3, 5, dst);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_NEG:
        case BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_NEG:
            emit_alu64(state, 0xf7, 3, dst);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_XOR:
            emit_alu64_imm32(state, 0x81, 6, dst, inst->imm);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_XOR:
            emit_alu64(state, 0x31, src, dst);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_MOV_MOVSX:
            emit_load_imm(state, dst, inst->imm);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_MOV_MOVSX:
            emit_mov(state, src, dst);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_IMM | BPF_ALU_ARSH:
            emit_alu64_imm8(state, 0xc1, 7, dst, inst->imm);
            break;
        case BPF_CLASS_ALU64 | BPF_SOURCE_REG | BPF_ALU_ARSH:
            emit_mov(state, src, RCX);
            emit_alu64(state, 0xd3, 7, dst);
            break;

        /* TODO use 8 bit immediate when possible */
        case BPF_CLASS_JMP | BPF_SOURCE_IMM | BPF_JMP_JA:
        case BPF_CLASS_JMP | BPF_SOURCE_REG | BPF_JMP_JA:
            emit_jmp(state, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_IMM | BPF_JMP_JEQ:
            emit_cmp_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x84, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_REG | BPF_JMP_JEQ:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x84, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_IMM | BPF_JMP_JGT:
            emit_cmp_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x87, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_REG | BPF_JMP_JGT:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x87, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_IMM | BPF_JMP_JGE:
            emit_cmp_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x83, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_REG | BPF_JMP_JGE:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x83, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_IMM | BPF_JMP_JLT:
            emit_cmp_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x82, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_REG | BPF_JMP_JLT:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x82, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_IMM | BPF_JMP_JLE:
            emit_cmp_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x86, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_REG | BPF_JMP_JLE:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x86, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_IMM | BPF_JMP_JSET:
            emit_alu64_imm32(state, 0xf7, 0, dst, inst->imm);
            emit_jcc(state, 0x85, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_REG | BPF_JMP_JSET:
            emit_alu64(state, 0x85, src, dst);
            emit_jcc(state, 0x85, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_IMM | BPF_JMP_JNE:
            emit_cmp_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x85, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_REG | BPF_JMP_JNE:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x85, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_IMM | BPF_JMP_JSGT:
            emit_cmp_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x8f, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_REG | BPF_JMP_JSGT:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x8f, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_IMM | BPF_JMP_JSGE:
            emit_cmp_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x8d, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_REG | BPF_JMP_JSGE:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x8d, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_IMM | BPF_JMP_JSLT:
            emit_cmp_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x8c, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_REG | BPF_JMP_JSLT:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x8c, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_IMM | BPF_JMP_JSLE:
            emit_cmp_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x8e, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_REG | BPF_JMP_JSLE:
            emit_cmp(state, src, dst);
            emit_jcc(state, 0x8e, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_IMM | BPF_JMP_JEQ:
            emit_cmp32_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x84, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_REG | BPF_JMP_JEQ:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x84, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_IMM | BPF_JMP_JGT:
            emit_cmp32_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x87, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_REG | BPF_JMP_JGT:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x87, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_IMM | BPF_JMP_JGE:
            emit_cmp32_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x83, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_REG | BPF_JMP_JGE:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x83, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_IMM | BPF_JMP_JLT:
            emit_cmp32_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x82, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_REG | BPF_JMP_JLT:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x82, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_IMM | BPF_JMP_JLE:
            emit_cmp32_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x86, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_REG | BPF_JMP_JLE:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x86, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_IMM | BPF_JMP_JSET:
            emit_alu32_imm32(state, 0xf7, 0, dst, inst->imm);
            emit_jcc(state, 0x85, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_REG | BPF_JMP_JSET:
            emit_alu32(state, 0x85, src, dst);
            emit_jcc(state, 0x85, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_IMM | BPF_JMP_JNE:
            emit_cmp32_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x85, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_REG | BPF_JMP_JNE:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x85, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_IMM | BPF_JMP_JSGT:
            emit_cmp32_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x8f, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_REG | BPF_JMP_JSGT:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x8f, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_IMM | BPF_JMP_JSGE:
            emit_cmp32_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x8d, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_REG | BPF_JMP_JSGE:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x8d, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_IMM | BPF_JMP_JSLT:
            emit_cmp32_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x8c, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_REG | BPF_JMP_JSLT:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x8c, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_IMM | BPF_JMP_JSLE:
            emit_cmp32_imm32(state, dst, inst->imm);
            emit_jcc(state, 0x8e, target_pc);
            break;
        case BPF_CLASS_JMP32 | BPF_SOURCE_REG | BPF_JMP_JSLE:
            emit_cmp32(state, src, dst);
            emit_jcc(state, 0x8e, target_pc);
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_IMM | BPF_JMP_CALL:
        case BPF_CLASS_JMP | BPF_SOURCE_REG | BPF_JMP_CALL:
        case BPF_CLASS_JMP32 | BPF_SOURCE_IMM | BPF_JMP_CALL:
        case BPF_CLASS_JMP32 | BPF_SOURCE_REG | BPF_JMP_CALL:
            /* We reserve RCX for shifts */
            if (inst->src_reg == 0) {
                emit_mov(state, RCX_ALT, RCX);
                emit_dispatched_external_helper_call(state, vm, inst->imm);
                // if (inst->imm == vm->unwind_stack_extension_index) {
                //     emit_cmp_imm32(state, map_register(BPF_REG_0), 0);
                //     emit_jcc(state, 0x84, TARGET_PC_EXIT);
                // }
            } else if (inst->src_reg == 1) {
                target_pc = i + inst->imm + 1;
                emit_local_call(state, target_pc);
            }
            break;
        case BPF_CLASS_JMP | BPF_SOURCE_IMM | BPF_JMP_EXIT:
        case BPF_CLASS_JMP | BPF_SOURCE_REG | BPF_JMP_EXIT:
            /* On entry to every local function we add an additional 8 bytes.
             * Undo that here!
             */
            emit_alu64_imm32(state, 0x81, 0, RSP, 8);
            emit_ret(state);
            break;

        case BPF_CLASS_LDX | BPF_LS_SIZE_W | BPF_LS_MODE_MEM:
            emit_load(state, S32, src, dst, inst->offset);
            break;
        case BPF_CLASS_LDX | BPF_LS_SIZE_H | BPF_LS_MODE_MEM:
            emit_load(state, S16, src, dst, inst->offset);
            break;
        case BPF_CLASS_LDX | BPF_LS_SIZE_B | BPF_LS_MODE_MEM:
            emit_load(state, S8, src, dst, inst->offset);
            break;
        case BPF_CLASS_LDX | BPF_LS_SIZE_DW | BPF_LS_MODE_MEM:
            emit_load(state, S64, src, dst, inst->offset);
            break;

        case BPF_CLASS_ST | BPF_LS_SIZE_W | BPF_LS_MODE_MEM:
            emit_store_imm32(state, S32, dst, inst->offset, inst->imm);
            break;
        case BPF_CLASS_ST | BPF_LS_SIZE_H | BPF_LS_MODE_MEM:
            emit_store_imm32(state, S16, dst, inst->offset, inst->imm);
            break;
        case BPF_CLASS_ST | BPF_LS_SIZE_B | BPF_LS_MODE_MEM:
            emit_store_imm32(state, S8, dst, inst->offset, inst->imm);
            break;
        case BPF_CLASS_ST | BPF_LS_SIZE_DW | BPF_LS_MODE_MEM:
            emit_store_imm32(state, S64, dst, inst->offset, inst->imm);
            break;

        case BPF_CLASS_STX | BPF_LS_SIZE_W | BPF_LS_MODE_MEM:
            emit_store(state, S32, src, dst, inst->offset);
            break;
        case BPF_CLASS_STX | BPF_LS_SIZE_H | BPF_LS_MODE_MEM:
            emit_store(state, S16, src, dst, inst->offset);
            break;
        case BPF_CLASS_STX | BPF_LS_SIZE_B | BPF_LS_MODE_MEM:
            emit_store(state, S8, src, dst, inst->offset);
            break;
        case BPF_CLASS_STX | BPF_LS_SIZE_DW | BPF_LS_MODE_MEM:
            emit_store(state, S64, src, dst, inst->offset);
            break;

        case BPF_CLASS_LD | BPF_LS_SIZE_DW | BPF_LS_MODE_IMM: {
            struct libebpf_insn *inst2 = &vm->insns[++i];
            uint64_t imm = (uint32_t)inst->imm | ((uint64_t)inst2->imm << 32);
            emit_load_imm(state, dst, imm);
            break;
        }

        default:
            ebpf_set_error_string("Unknown instruction at PC %d: opcode %02x", i, inst->code);
            return -1;
        }
    }

    /* Epilogue */
    state->exit_loc = state->offset;

    /* Move register 0 into rax */
    if (map_register(BPF_REG_0) != RAX) {
        emit_mov(state, map_register(BPF_REG_0), RAX);
    }

    /* Deallocate stack space by restoring RSP from BPF R10. */
    emit_mov(state, map_register(BPF_REG_10), RSP);

    if (!(_countof(platform_nonvolatile_registers) % 2)) {
        emit_alu64_imm32(state, 0x81, 0, RSP, 0x8);
    }

    /* Restore platform non-volatile registers */
    for (i = 0; i < _countof(platform_nonvolatile_registers); i++) {
        emit_pop(state, platform_nonvolatile_registers[_countof(platform_nonvolatile_registers) - i - 1]);
    }

    emit1(state, 0xc3); /* ret */

    state->retpoline_loc = emit_retpoline(state);
    state->dispatcher_loc = emit_dispatched_external_helper_address(state, vm);

    return 0;
}

static void muldivmod(struct jit_state *state, uint8_t opcode, int src, int dst, int32_t imm) {
    bool mul = (opcode & BPF_ALU_CODE_MASK) == BPF_ALU_MUL;
    bool div = (opcode & BPF_ALU_CODE_MASK) == BPF_ALU_DIV_SDIV;
    bool mod = (opcode & BPF_ALU_CODE_MASK) == BPF_ALU_MOD_SMOD;
    bool is64 = (opcode & BPF_ALU_CLASS_MASK) == BPF_CLASS_ALU64;
    bool reg = (opcode & BPF_ALU_SOURCE_MASK) == BPF_SOURCE_REG;

    // Short circuit for imm == 0.
    if (!reg && imm == 0) {
        if (div || mul) {
            // For division and multiplication, set result to zero.
            emit_alu32(state, 0x31, dst, dst);
        } else {
            // For modulo, set result to dividend.
            emit_mov(state, dst, dst);
        }
        return;
    }

    if (dst != RAX) {
        emit_push(state, RAX);
    }

    if (dst != RDX) {
        emit_push(state, RDX);
    }

    // Load the divisor into RCX.
    if (imm) {
        emit_load_imm(state, RCX, imm);
    } else {
        emit_mov(state, src, RCX);
    }

    // Load the dividend into RAX.
    emit_mov(state, dst, RAX);

    // BPF has two different semantics for division and modulus. For division
    // if the divisor is zero, the result is zero.  For modulus, if the divisor
    // is zero, the result is the dividend. To handle this we set the divisor
    // to 1 if it is zero and then set the result to zero if the divisor was
    // zero (for division) or set the result to the dividend if the divisor was
    // zero (for modulo).

    if (div || mod) {
        // Check if divisor is zero.
        if (is64) {
            emit_alu64(state, 0x85, RCX, RCX);
        } else {
            emit_alu32(state, 0x85, RCX, RCX);
        }

        // Save the dividend for the modulo case.
        if (mod) {
            emit_push(state, RAX); // Save dividend.
        }

        // Save the result of the test.
        emit1(state, 0x9c); /* pushfq */

        // Set the divisor to 1 if it is zero.
        emit_load_imm(state, RDX, 1);
        emit1(state, 0x48);
        emit1(state, 0x0f);
        emit1(state, 0x44);
        emit1(state, 0xca); /* cmove rcx,rdx */

        /* xor %edx,%edx */
        emit_alu32(state, 0x31, RDX, RDX);
    }

    if (is64) {
        emit_rex(state, 1, 0, 0, 0);
    }

    // Multiply or divide.
    emit_alu32(state, 0xf7, mul ? 4 : 6, RCX);

    // Division operation stores the remainder in RDX and the quotient in RAX.
    if (div || mod) {
        // Restore the result of the test.
        emit1(state, 0x9d); /* popfq */

        // If zero flag is set, then the divisor was zero.

        if (div) {
            // Set the dividend to zero if the divisor was zero.
            emit_load_imm(state, RCX, 0);

            // Store 0 in RAX if the divisor was zero.
            // Use conditional move to avoid a branch.
            emit1(state, 0x48);
            emit1(state, 0x0f);
            emit1(state, 0x44);
            emit1(state, 0xc1); /* cmove rax,rcx */
        } else {
            // Restore dividend to RCX.
            emit_pop(state, RCX);

            // Store the dividend in RAX if the divisor was zero.
            // Use conditional move to avoid a branch.
            emit1(state, 0x48);
            emit1(state, 0x0f);
            emit1(state, 0x44);
            emit1(state, 0xd1); /* cmove rdx,rcx */
        }
    }

    if (dst != RDX) {
        if (mod) {
            emit_mov(state, RDX, dst);
        }
        emit_pop(state, RDX);
    }
    if (dst != RAX) {
        if (div || mul) {
            emit_mov(state, RAX, dst);
        }
        emit_pop(state, RAX);
    }
}

static bool resolve_patchable_relatives(struct jit_state *state) {
    int i;
    for (i = 0; i < state->num_jumps; i++) {
        struct patchable_relative jump = state->jumps[i];

        int target_loc;
        if (jump.target_offset != 0) {
            target_loc = jump.target_offset;
        } else if (jump.target_pc == TARGET_PC_EXIT) {
            target_loc = state->exit_loc;
        } else if (jump.target_pc == TARGET_PC_RETPOLINE) {
            target_loc = state->retpoline_loc;
        } else {
            target_loc = state->pc_locs[jump.target_pc];
        }

        /* Assumes jump offset is at end of instruction */
        uint32_t rel = target_loc - (jump.offset_loc + sizeof(uint32_t));

        uint8_t *offset_ptr = &state->buf[jump.offset_loc];
        memcpy(offset_ptr, &rel, sizeof(uint32_t));
    }
    for (i = 0; i < state->num_loads; i++) {
        struct patchable_relative load = state->loads[i];

        int target_loc;
        if (load.target_pc == TARGET_PC_EXTERNAL_DISPATCHER) {
            target_loc = state->dispatcher_loc;
        } else {
            target_loc = -1;
            return false;
        }

        /* Assumes jump offset is at end of instruction */
        uint32_t rel = target_loc - (load.offset_loc + sizeof(uint32_t));

        uint8_t *offset_ptr = &state->buf[load.offset_loc];
        memcpy(offset_ptr, &rel, sizeof(uint32_t));
    }
    return true;
}

int ebpf_translate(struct ebpf_vm *vm, uint8_t **buffer, size_t *size) {
    struct jit_state state;
    int result = -1;
    state.offset = 0;
    *size = state.size = LIBEBPF_MAX_INSTRUCTION_COUNT * 8;
    state.buf = _libebpf_global_malloc(LIBEBPF_MAX_INSTRUCTION_COUNT * 8);
    state.pc_locs = _libebpf_global_malloc((LIBEBPF_MAX_INSTRUCTION_COUNT + 1) * sizeof(state.pc_locs[0]));
    state.jumps = _libebpf_global_malloc(LIBEBPF_MAX_INSTRUCTION_COUNT * sizeof(state.jumps[0]));
    state.loads = _libebpf_global_malloc(LIBEBPF_MAX_INSTRUCTION_COUNT * sizeof(state.loads[0]));
    state.num_jumps = 0;
    state.num_loads = 0;
    if (!state.pc_locs || !state.jumps) {
        ebpf_set_error_string("Out of memory");
        goto err;
    }

    if (translate(vm, &state) < 0) {
        goto err;
    }

    if (state.num_jumps == LIBEBPF_MAX_INSTRUCTION_COUNT) {
        ebpf_set_error_string("Excessive number of jump targets");
        goto err;
    }

    if (state.offset == state.size) {
        ebpf_set_error_string("Target buffer too small");
        goto err;
    }

    if (!resolve_patchable_relatives(&state)) {
        ebpf_set_error_string("Could not patch the relative addresses in the JIT'd code.");
        goto err;
    }

    result = 0;
    *size = state.offset;
    *buffer = state.buf;
    goto out;
err:
    _libebpf_global_free(state.buf);
out:
    _libebpf_global_free(state.pc_locs);
    _libebpf_global_free(state.jumps);
    _libebpf_global_free(state.loads);
    return result;
}
