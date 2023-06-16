/*
 * Copyright 2015 Big Switch Networks, Inc
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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <endian.h>
#include "ebpf_inst.h"
#include "ebpf_vm.h"
#include <unistd.h>
#include "linux_bpf.h"

#define MAX_EXT_FUNCS 64

static bool
validate(const struct ebpf_vm* vm, const struct bpf_insn* insts, uint32_t num_insts, char** errmsg);
static bool
bounds_check(
    const struct ebpf_vm* vm,
    void* addr,
    int size,
    const char* type,
    uint16_t cur_pc,
    void* mem,
    size_t mem_len,
    void* stack);

bool
ebpf_toggle_bounds_check(struct ebpf_vm* vm, bool enable)
{
    bool old = vm->bounds_check_enabled;
    vm->bounds_check_enabled = enable;
    return old;
}

void
ebpf_set_error_print(struct ebpf_vm* vm, int (*error_printf)(FILE* stream, const char* format, ...))
{
    if (error_printf)
        vm->error_printf = error_printf;
    else
        vm->error_printf = fprintf;
}

struct ebpf_vm*
ebpf_create(void)
{
    struct ebpf_vm* vm = calloc(1, sizeof(*vm));
    if (vm == NULL) {
        return NULL;
    }

    /* linux aux alloc */
    struct bpf_prog_aux *aux;
    aux = calloc(1, sizeof(*aux));
	if (aux == NULL) {
		free(vm);
		return NULL;
	}
	vm->aux = aux;
	vm->aux->prog = vm;
    /* end linux bpf_prog_aux */

    vm->ext_funcs = calloc(MAX_EXT_FUNCS, sizeof(*vm->ext_funcs));
    if (vm->ext_funcs == NULL) {
        ebpf_destroy(vm);
        return NULL;
    }

    vm->ext_func_names = calloc(MAX_EXT_FUNCS, sizeof(*vm->ext_func_names));
    if (vm->ext_func_names == NULL) {
        ebpf_destroy(vm);
        return NULL;
    }

    vm->bounds_check_enabled = true;
    vm->error_printf = fprintf;

#if defined(__x86_64__) || defined(_M_X64)
    printf("ebpf_create: x86_64\n");
    vm->translate = ebpf_translate_x86_64;
#elif defined(__aarch64__) || defined(_M_ARM64)
    printf("ebpf_create: arm64\n");
    vm->translate = ebpf_translate_arm64;
#elif defined(__arm__) || defined(_M_ARM)
    printf("ebpf_create: arm32\n");
    vm->translate = ebpf_translate_arm32;
#else
    printf("ebpf_create: null\n");
    vm->translate = ebpf_translate_null;
#endif
    vm->unwind_stack_extension_index = -1;
    return vm;
}

void
ebpf_destroy(struct ebpf_vm* vm)
{
    ebpf_unload_code(vm);
    free(vm->ext_funcs);
    free(vm->ext_func_names);
    free(vm);
}

int
ebpf_register(struct ebpf_vm* vm, unsigned int idx, const char* name, void* fn)
{
    if (idx >= MAX_EXT_FUNCS) {
        return -1;
    }

    vm->ext_funcs[idx] = (ext_func)fn;
    vm->ext_func_names[idx] = name;
    printf("ebpf_register: %s idx: %d func: %ld\n", name, idx, (long)fn);
    return 0;
}

int
ebpf_set_unwind_function_index(struct ebpf_vm* vm, unsigned int idx)
{
    if (vm->unwind_stack_extension_index != -1) {
        return -1;
    }

    vm->unwind_stack_extension_index = idx;
    return 0;
}

unsigned int
ebpf_lookup_registered_function(struct ebpf_vm* vm, const char* name)
{
    int i;
    for (i = 0; i < MAX_EXT_FUNCS; i++) {
        const char* other = vm->ext_func_names[i];
        if (other && !strcmp(other, name)) {
            return i;
        }
    }
    return -1;
}

int
ebpf_load(struct ebpf_vm* vm, const void* code, uint32_t code_len, char** errmsg)
{
    const struct bpf_insn* source_inst = code;
    *errmsg = NULL;

    if (vm->insnsi) {
        *errmsg = ebpf_error(
            "code has already been loaded into this VM. Use ebpf_unload_code() if you need to reuse this VM");
        return -1;
    }

    if (code_len % 8 != 0) {
        *errmsg = ebpf_error("code_len must be a multiple of 8");
        return -1;
    }

    if (!validate(vm, code, code_len / 8, errmsg)) {
        return -1;
    }

    vm->insnsi = malloc(code_len);
    if (vm->insnsi == NULL) {
        *errmsg = ebpf_error("out of memory");
        return -1;
    }

    vm->num_insts = code_len / sizeof(vm->insnsi[0]);
	vm->orig_prog = NULL;
    // Store instructions in the vm.
    for (uint32_t i = 0; i < vm->num_insts; i++) {
        ebpf_store_instruction(vm, i, source_inst[i]);
    }

    return 0;
}

void
ebpf_unload_code(struct ebpf_vm* vm)
{
    if (vm->jitted_function) {
        munmap(vm->jitted_function, vm->jitted_size);
        vm->jitted_function = NULL;
        vm->jitted_size = 0;
    }
    if (vm->insnsi) {
        free(vm->insnsi);
        vm->insnsi = NULL;
        vm->num_insts = 0;
    }
}

#define IS_ALIGNED(x, a) (((uintptr_t)(x) & ((a)-1)) == 0)

inline static uint64_t
ebpf_mem_load(uint64_t address, size_t size)
{
    if (!IS_ALIGNED(address, size)) {
        // Fill the result with 0 to avoid leaking uninitialized memory.
        uint64_t value = 0;
        memcpy(&value, (void*)address, size);
        return value;
    }

    switch (size) {
    case 1:
        return *(uint8_t*)address;
    case 2:
        return *(uint16_t*)address;
    case 4:
        return *(uint32_t*)address;
    case 8:
        return *(uint64_t*)address;
    default:
        abort();
    }
}

inline static void
ebpf_mem_store(uint64_t address, uint64_t value, size_t size)
{
    if (!IS_ALIGNED(address, size)) {
        memcpy((void*)address, &value, size);
        return;
    }

    switch (size) {
    case 1:
        *(uint8_t*)address = value;
        break;
    case 2:
        *(uint16_t*)address = value;
        break;
    case 4:
        *(uint32_t*)address = value;
        break;
    case 8:
        *(uint64_t*)address = value;
        break;
    default:
        abort();
    }
}

int
ebpf_exec(const struct ebpf_vm* vm, void* mem, size_t mem_len, uint64_t* bpf_return_value)
{
    uint16_t pc = 0;
    const struct bpf_insn* insts = vm->insnsi;
    uint64_t* reg;
    uint64_t _reg[16];
    uint64_t stack[(EBPF_STACK_SIZE + 7) / 8];

    if (!insts) {
        /* Code must be loaded before we can execute */
        return -1;
    }

#ifdef DEBUG
    if (vm->regs)
        reg = vm->regs;
    else
        reg = _reg;
#else
    reg = _reg;
#endif

    reg[1] = (uintptr_t)mem;
    reg[2] = (uint64_t)mem_len;
    reg[10] = (uintptr_t)stack + sizeof(stack);

    while (1) {
        const uint16_t cur_pc = pc;
        struct bpf_insn inst = ebpf_fetch_instruction(vm, pc++);

        printf("op: %d %d\n", EBPF_OP_CALL, inst.code);

        switch (inst.code) {
        case EBPF_OP_ADD_IMM:
            reg[inst.dst_reg] += inst.imm;
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_ADD_REG:
            reg[inst.dst_reg] += reg[inst.src_reg];
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_SUB_IMM:
            reg[inst.dst_reg] -= inst.imm;
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_SUB_REG:
            reg[inst.dst_reg] -= reg[inst.src_reg];
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_MUL_IMM:
            reg[inst.dst_reg] *= inst.imm;
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_MUL_REG:
            reg[inst.dst_reg] *= reg[inst.src_reg];
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_DIV_IMM:
            reg[inst.dst_reg] = (u32)(inst.imm) ? (u32)(reg[inst.dst_reg]) / (u32)(inst.imm) : 0;
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_DIV_REG:
            reg[inst.dst_reg] = reg[inst.src_reg] ? (u32)(reg[inst.dst_reg]) / (u32)(reg[inst.src_reg]) : 0;
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_OR_IMM:
            reg[inst.dst_reg] |= inst.imm;
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_OR_REG:
            reg[inst.dst_reg] |= reg[inst.src_reg];
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_AND_IMM:
            reg[inst.dst_reg] &= inst.imm;
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_AND_REG:
            reg[inst.dst_reg] &= reg[inst.src_reg];
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_LSH_IMM:
            reg[inst.dst_reg] <<= inst.imm;
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_LSH_REG:
            reg[inst.dst_reg] <<= reg[inst.src_reg];
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_RSH_IMM:
            reg[inst.dst_reg] = (u32)(reg[inst.dst_reg]) >> inst.imm;
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_RSH_REG:
            reg[inst.dst_reg] = (u32)(reg[inst.dst_reg]) >> reg[inst.src_reg];
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_NEG:
            reg[inst.dst_reg] = -(int64_t)reg[inst.dst_reg];
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_IMM:
            reg[inst.dst_reg] = (u32)(inst.imm) ? (u32)(reg[inst.dst_reg]) % (u32)(inst.imm) : (u32)(reg[inst.dst_reg]);
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_MOD_REG:
            reg[inst.dst_reg] = (u32)(reg[inst.src_reg]) ? (u32)(reg[inst.dst_reg]) % (u32)(reg[inst.src_reg]) : (u32)(reg[inst.dst_reg]);
            break;
        case EBPF_OP_XOR_IMM:
            reg[inst.dst_reg] ^= inst.imm;
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_XOR_REG:
            reg[inst.dst_reg] ^= reg[inst.src_reg];
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_MOV_IMM:
            reg[inst.dst_reg] = inst.imm;
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_MOV_REG:
            reg[inst.dst_reg] = reg[inst.src_reg];
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_ARSH_IMM:
            reg[inst.dst_reg] = (int32_t)reg[inst.dst_reg] >> inst.imm;
            reg[inst.dst_reg] &= UINT32_MAX;
            break;
        case EBPF_OP_ARSH_REG:
            reg[inst.dst_reg] = (int32_t)reg[inst.dst_reg] >> (u32)(reg[inst.src_reg]);
            reg[inst.dst_reg] &= UINT32_MAX;
            break;

        case EBPF_OP_LE:
            if (inst.imm == 16) {
                reg[inst.dst_reg] = htole16(reg[inst.dst_reg]);
            } else if (inst.imm == 32) {
                reg[inst.dst_reg] = htole32(reg[inst.dst_reg]);
            } else if (inst.imm == 64) {
                reg[inst.dst_reg] = htole64(reg[inst.dst_reg]);
            }
            break;
        case EBPF_OP_BE:
            if (inst.imm == 16) {
                reg[inst.dst_reg] = htobe16(reg[inst.dst_reg]);
            } else if (inst.imm == 32) {
                reg[inst.dst_reg] = htobe32(reg[inst.dst_reg]);
            } else if (inst.imm == 64) {
                reg[inst.dst_reg] = htobe64(reg[inst.dst_reg]);
            }
            break;

        case EBPF_OP_ADD64_IMM:
            reg[inst.dst_reg] += inst.imm;
            break;
        case EBPF_OP_ADD64_REG:
            reg[inst.dst_reg] += reg[inst.src_reg];
            break;
        case EBPF_OP_SUB64_IMM:
            reg[inst.dst_reg] -= inst.imm;
            break;
        case EBPF_OP_SUB64_REG:
            reg[inst.dst_reg] -= reg[inst.src_reg];
            break;
        case EBPF_OP_MUL64_IMM:
            reg[inst.dst_reg] *= inst.imm;
            break;
        case EBPF_OP_MUL64_REG:
            reg[inst.dst_reg] *= reg[inst.src_reg];
            break;
        case EBPF_OP_DIV64_IMM:
            reg[inst.dst_reg] = inst.imm ? reg[inst.dst_reg] / inst.imm : 0;
            break;
        case EBPF_OP_DIV64_REG:
            reg[inst.dst_reg] = reg[inst.src_reg] ? reg[inst.dst_reg] / reg[inst.src_reg] : 0;
            break;
        case EBPF_OP_OR64_IMM:
            reg[inst.dst_reg] |= inst.imm;
            break;
        case EBPF_OP_OR64_REG:
            reg[inst.dst_reg] |= reg[inst.src_reg];
            break;
        case EBPF_OP_AND64_IMM:
            reg[inst.dst_reg] &= inst.imm;
            break;
        case EBPF_OP_AND64_REG:
            reg[inst.dst_reg] &= reg[inst.src_reg];
            break;
        case EBPF_OP_LSH64_IMM:
            reg[inst.dst_reg] <<= inst.imm;
            break;
        case EBPF_OP_LSH64_REG:
            reg[inst.dst_reg] <<= reg[inst.src_reg];
            break;
        case EBPF_OP_RSH64_IMM:
            reg[inst.dst_reg] >>= inst.imm;
            break;
        case EBPF_OP_RSH64_REG:
            reg[inst.dst_reg] >>= reg[inst.src_reg];
            break;
        case EBPF_OP_NEG64:
            reg[inst.dst_reg] = -reg[inst.dst_reg];
            break;
        case EBPF_OP_MOD64_IMM:
            reg[inst.dst_reg] = inst.imm ? reg[inst.dst_reg] % inst.imm : reg[inst.dst_reg];
            break;
        case EBPF_OP_MOD64_REG:
            reg[inst.dst_reg] = reg[inst.src_reg] ? reg[inst.dst_reg] % reg[inst.src_reg] : reg[inst.dst_reg];
            break;
        case EBPF_OP_XOR64_IMM:
            reg[inst.dst_reg] ^= inst.imm;
            break;
        case EBPF_OP_XOR64_REG:
            reg[inst.dst_reg] ^= reg[inst.src_reg];
            break;
        case EBPF_OP_MOV64_IMM:
            reg[inst.dst_reg] = inst.imm;
            break;
        case EBPF_OP_MOV64_REG:
            reg[inst.dst_reg] = reg[inst.src_reg];
            break;
        case EBPF_OP_ARSH64_IMM:
            reg[inst.dst_reg] = (int64_t)reg[inst.dst_reg] >> inst.imm;
            break;
        case EBPF_OP_ARSH64_REG:
            reg[inst.dst_reg] = (int64_t)reg[inst.dst_reg] >> reg[inst.src_reg];
            break;

            /*
             * HACK runtime bounds check
             *
             * Needed since we don't have a verifier yet.
             */
#define BOUNDS_CHECK_LOAD(size)                                                                                 \
    do {                                                                                                        \
        if (!bounds_check(vm, (char*)reg[inst.src_reg] + inst.off, size, "load", cur_pc, mem, mem_len, stack)) { \
            return -1;                                                                                          \
        }                                                                                                       \
    } while (0)
#define BOUNDS_CHECK_STORE(size)                                                                                 \
    do {                                                                                                         \
        if (!bounds_check(vm, (char*)reg[inst.dst_reg] + inst.off, size, "store", cur_pc, mem, mem_len, stack)) { \
            return -1;                                                                                           \
        }                                                                                                        \
    } while (0)

        case EBPF_OP_LDXW:
            BOUNDS_CHECK_LOAD(4);
            reg[inst.dst_reg] = ebpf_mem_load(reg[inst.src_reg] + inst.off, 4);
            break;
        case EBPF_OP_LDXH:
            BOUNDS_CHECK_LOAD(2);
            reg[inst.dst_reg] = ebpf_mem_load(reg[inst.src_reg] + inst.off, 2);
            break;
        case EBPF_OP_LDXB:
            BOUNDS_CHECK_LOAD(1);
            reg[inst.dst_reg] = ebpf_mem_load(reg[inst.src_reg] + inst.off, 1);
            break;
        case EBPF_OP_LDXDW:
            BOUNDS_CHECK_LOAD(8);
            reg[inst.dst_reg] = ebpf_mem_load(reg[inst.src_reg] + inst.off, 8);
            break;

        case EBPF_OP_STW:
            BOUNDS_CHECK_STORE(4);
            ebpf_mem_store(reg[inst.dst_reg] + inst.off, inst.imm, 4);
            break;
        case EBPF_OP_STH:
            BOUNDS_CHECK_STORE(2);
            ebpf_mem_store(reg[inst.dst_reg] + inst.off, inst.imm, 2);
            break;
        case EBPF_OP_STB:
            BOUNDS_CHECK_STORE(1);
            ebpf_mem_store(reg[inst.dst_reg] + inst.off, inst.imm, 1);
            break;
        case EBPF_OP_STDW:
            BOUNDS_CHECK_STORE(8);
            ebpf_mem_store(reg[inst.dst_reg] + inst.off, inst.imm, 8);
            break;

        case EBPF_OP_STXW:
            BOUNDS_CHECK_STORE(4);
            ebpf_mem_store(reg[inst.dst_reg] + inst.off, reg[inst.src_reg], 4);
            break;
        case EBPF_OP_STXH:
            BOUNDS_CHECK_STORE(2);
            ebpf_mem_store(reg[inst.dst_reg] + inst.off, reg[inst.src_reg], 2);
            break;
        case EBPF_OP_STXB:
            BOUNDS_CHECK_STORE(1);
            ebpf_mem_store(reg[inst.dst_reg] + inst.off, reg[inst.src_reg], 1);
            break;
        case EBPF_OP_STXDW:
            BOUNDS_CHECK_STORE(8);
            ebpf_mem_store(reg[inst.dst_reg] + inst.off, reg[inst.src_reg], 8);
            break;

        case EBPF_OP_LDDW:
            reg[inst.dst_reg] = (u32)(inst.imm) | ((uint64_t)ebpf_fetch_instruction(vm, pc++).imm << 32);
            break;

        case EBPF_OP_JA:
            pc += inst.off;
            break;
        case EBPF_OP_JEQ_IMM:
            if (reg[inst.dst_reg] == inst.imm) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JEQ_REG:
            if (reg[inst.dst_reg] == reg[inst.src_reg]) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JEQ32_IMM:
            if ((u32)(reg[inst.dst_reg]) == (u32)(inst.imm)) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JEQ32_REG:
            if ((u32)(reg[inst.dst_reg]) == reg[inst.src_reg]) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JGT_IMM:
            if (reg[inst.dst_reg] > (u32)(inst.imm)) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JGT_REG:
            if (reg[inst.dst_reg] > reg[inst.src_reg]) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JGT32_IMM:
            if ((u32)(reg[inst.dst_reg]) > (u32)(inst.imm)) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JGT32_REG:
            if ((u32)(reg[inst.dst_reg]) > (u32)(reg[inst.src_reg])) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JGE_IMM:
            if (reg[inst.dst_reg] >= (u32)(inst.imm)) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JGE_REG:
            if (reg[inst.dst_reg] >= reg[inst.src_reg]) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JGE32_IMM:
            if ((u32)(reg[inst.dst_reg]) >= (u32)(inst.imm)) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JGE32_REG:
            if ((u32)(reg[inst.dst_reg]) >= (u32)(reg[inst.src_reg])) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JLT_IMM:
            if (reg[inst.dst_reg] < (u32)(inst.imm)) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JLT_REG:
            if (reg[inst.dst_reg] < reg[inst.src_reg]) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JLT32_IMM:
            if ((u32)(reg[inst.dst_reg]) < (u32)(inst.imm)) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JLT32_REG:
            if ((u32)(reg[inst.dst_reg]) < (u32)(reg[inst.src_reg])) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JLE_IMM:
            if (reg[inst.dst_reg] <= (u32)(inst.imm)) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JLE_REG:
            if (reg[inst.dst_reg] <= reg[inst.src_reg]) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JLE32_IMM:
            if ((u32)(reg[inst.dst_reg]) <= (u32)(inst.imm)) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JLE32_REG:
            if ((u32)(reg[inst.dst_reg]) <= (u32)(reg[inst.src_reg])) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSET_IMM:
            if (reg[inst.dst_reg] & inst.imm) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSET_REG:
            if (reg[inst.dst_reg] & reg[inst.src_reg]) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSET32_IMM:
            if ((u32)(reg[inst.dst_reg]) & (u32)(inst.imm)) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSET32_REG:
            if ((u32)(reg[inst.dst_reg]) & (u32)(reg[inst.src_reg])) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JNE_IMM:
            if (reg[inst.dst_reg] != inst.imm) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JNE_REG:
            if (reg[inst.dst_reg] != reg[inst.src_reg]) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JNE32_IMM:
            if ((u32)(reg[inst.dst_reg]) != (u32)(inst.imm)) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JNE32_REG:
            if ((u32)(reg[inst.dst_reg]) != (u32)(reg[inst.src_reg])) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSGT_IMM:
            if ((int64_t)reg[inst.dst_reg] > inst.imm) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSGT_REG:
            if ((int64_t)reg[inst.dst_reg] > (int64_t)reg[inst.src_reg]) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSGT32_IMM:
            if ((int32_t)(reg[inst.dst_reg]) > (int32_t)(inst.imm)) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSGT32_REG:
            if ((int32_t)(reg[inst.dst_reg]) > (int32_t)(reg[inst.src_reg])) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSGE_IMM:
            if ((int64_t)reg[inst.dst_reg] >= inst.imm) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSGE_REG:
            if ((int64_t)reg[inst.dst_reg] >= (int64_t)reg[inst.src_reg]) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSGE32_IMM:
            if ((int32_t)(reg[inst.dst_reg]) >= (int32_t)(inst.imm)) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSGE32_REG:
            if ((int32_t)(reg[inst.dst_reg]) >= (int32_t)(reg[inst.src_reg])) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSLT_IMM:
            if ((int64_t)reg[inst.dst_reg] < inst.imm) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSLT_REG:
            if ((int64_t)reg[inst.dst_reg] < (int64_t)reg[inst.src_reg]) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSLT32_IMM:
            if ((int32_t)(reg[inst.dst_reg]) < (int32_t)(inst.imm)) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSLT32_REG:
            if ((int32_t)(reg[inst.dst_reg]) < (int32_t)(reg[inst.src_reg])) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSLE_IMM:
            if ((int64_t)reg[inst.dst_reg] <= inst.imm) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSLE_REG:
            if ((int64_t)reg[inst.dst_reg] <= (int64_t)reg[inst.src_reg]) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSLE32_IMM:
            if ((int32_t)(reg[inst.dst_reg]) <= (int32_t)(inst.imm)) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_JSLE32_REG:
            if ((int32_t)(reg[inst.dst_reg]) <= (int32_t)(reg[inst.src_reg])) {
                pc += inst.off;
            }
            break;
        case EBPF_OP_EXIT:
            *bpf_return_value = reg[0];
            return 0;
        case EBPF_OP_CALL:
            printf("call: %ld", vm->ext_funcs[inst.imm]);
            reg[0] = vm->ext_funcs[inst.imm](reg[1], reg[2], reg[3], reg[4], reg[5]);
            // Unwind the stack if unwind extension returns success.
            if (inst.imm == vm->unwind_stack_extension_index && reg[0] == 0) {
                *bpf_return_value = reg[0];
                return 0;
            }
            break;
        }
    }
}

static bool
validate(const struct ebpf_vm* vm, const struct bpf_insn* insts, uint32_t num_insts, char** errmsg)
{
    if (num_insts >= EBPF_MAX_INSTS) {
        *errmsg = ebpf_error("too many instructions (max %u)", EBPF_MAX_INSTS);
        return false;
    }

    int i;
    for (i = 0; i < num_insts; i++) {
        struct bpf_insn inst = insts[i];
        bool store = false;

        printf("op: %d %d imm: %d\n", EBPF_OP_CALL, inst.code, inst.imm);

        switch (inst.code) {
        case EBPF_OP_ADD_IMM:
        case EBPF_OP_ADD_REG:
        case EBPF_OP_SUB_IMM:
        case EBPF_OP_SUB_REG:
        case EBPF_OP_MUL_IMM:
        case EBPF_OP_MUL_REG:
        case EBPF_OP_DIV_REG:
        case EBPF_OP_OR_IMM:
        case EBPF_OP_OR_REG:
        case EBPF_OP_AND_IMM:
        case EBPF_OP_AND_REG:
        case EBPF_OP_LSH_IMM:
        case EBPF_OP_LSH_REG:
        case EBPF_OP_RSH_IMM:
        case EBPF_OP_RSH_REG:
        case EBPF_OP_NEG:
        case EBPF_OP_MOD_REG:
        case EBPF_OP_XOR_IMM:
        case EBPF_OP_XOR_REG:
        case EBPF_OP_MOV_IMM:
        case EBPF_OP_MOV_REG:
        case EBPF_OP_ARSH_IMM:
        case EBPF_OP_ARSH_REG:
            break;

        case EBPF_OP_LE:
        case EBPF_OP_BE:
            if (inst.imm != 16 && inst.imm != 32 && inst.imm != 64) {
                *errmsg = ebpf_error("invalid endian immediate at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_ADD64_IMM:
        case EBPF_OP_ADD64_REG:
        case EBPF_OP_SUB64_IMM:
        case EBPF_OP_SUB64_REG:
        case EBPF_OP_MUL64_IMM:
        case EBPF_OP_MUL64_REG:
        case EBPF_OP_DIV64_REG:
        case EBPF_OP_OR64_IMM:
        case EBPF_OP_OR64_REG:
        case EBPF_OP_AND64_IMM:
        case EBPF_OP_AND64_REG:
        case EBPF_OP_LSH64_IMM:
        case EBPF_OP_LSH64_REG:
        case EBPF_OP_RSH64_IMM:
        case EBPF_OP_RSH64_REG:
        case EBPF_OP_NEG64:
        case EBPF_OP_MOD64_REG:
        case EBPF_OP_XOR64_IMM:
        case EBPF_OP_XOR64_REG:
        case EBPF_OP_MOV64_IMM:
        case EBPF_OP_MOV64_REG:
        case EBPF_OP_ARSH64_IMM:
        case EBPF_OP_ARSH64_REG:
            break;

        case EBPF_OP_LDXW:
        case EBPF_OP_LDXH:
        case EBPF_OP_LDXB:
        case EBPF_OP_LDXDW:
            break;

        case EBPF_OP_STW:
        case EBPF_OP_STH:
        case EBPF_OP_STB:
        case EBPF_OP_STDW:
        case EBPF_OP_STXW:
        case EBPF_OP_STXH:
        case EBPF_OP_STXB:
        case EBPF_OP_STXDW:
            store = true;
            break;

        case EBPF_OP_LDDW:
            if (inst.src_reg != 0) {
                *errmsg = ebpf_error("invalid source register for LDDW at PC %d", i);
                return false;
            }
            if (i + 1 >= num_insts || insts[i + 1].code != 0) {
                *errmsg = ebpf_error("incomplete lddw at PC %d", i);
                return false;
            }
            i++; /* Skip next instruction */
            break;

        case EBPF_OP_JA:
        case EBPF_OP_JEQ_REG:
        case EBPF_OP_JEQ_IMM:
        case EBPF_OP_JGT_REG:
        case EBPF_OP_JGT_IMM:
        case EBPF_OP_JGE_REG:
        case EBPF_OP_JGE_IMM:
        case EBPF_OP_JLT_REG:
        case EBPF_OP_JLT_IMM:
        case EBPF_OP_JLE_REG:
        case EBPF_OP_JLE_IMM:
        case EBPF_OP_JSET_REG:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JNE_REG:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGT_REG:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JSGE_REG:
        case EBPF_OP_JSLT_IMM:
        case EBPF_OP_JSLT_REG:
        case EBPF_OP_JSLE_IMM:
        case EBPF_OP_JSLE_REG:
        case EBPF_OP_JEQ32_IMM:
        case EBPF_OP_JEQ32_REG:
        case EBPF_OP_JGT32_IMM:
        case EBPF_OP_JGT32_REG:
        case EBPF_OP_JGE32_IMM:
        case EBPF_OP_JGE32_REG:
        case EBPF_OP_JSET32_REG:
        case EBPF_OP_JSET32_IMM:
        case EBPF_OP_JNE32_IMM:
        case EBPF_OP_JNE32_REG:
        case EBPF_OP_JSGT32_IMM:
        case EBPF_OP_JSGT32_REG:
        case EBPF_OP_JSGE32_IMM:
        case EBPF_OP_JSGE32_REG:
        case EBPF_OP_JLT32_IMM:
        case EBPF_OP_JLT32_REG:
        case EBPF_OP_JLE32_IMM:
        case EBPF_OP_JLE32_REG:
        case EBPF_OP_JSLT32_IMM:
        case EBPF_OP_JSLT32_REG:
        case EBPF_OP_JSLE32_IMM:
        case EBPF_OP_JSLE32_REG:
            if (inst.off == -1) {
                *errmsg = ebpf_error("infinite loop at PC %d", i);
                return false;
            }
            int new_pc = i + 1 + inst.off;
            if (new_pc < 0 || new_pc >= num_insts) {
                *errmsg = ebpf_error("jump out of bounds at PC %d", i);
                return false;
            } else if (insts[new_pc].code == 0) {
                *errmsg = ebpf_error("jump to middle of lddw at PC %d", i);
                return false;
            }
            break;

        case EBPF_OP_CALL:
            if (inst.imm < 0 || inst.imm >= MAX_EXT_FUNCS) {
                *errmsg = ebpf_error("invalid call immediate at PC %d", i);
                return false;
            }
            // printf("func: %ld\n", vm->ext_funcs[inst.imm]);
            if (!vm->ext_funcs[inst.imm]) {
                *errmsg = ebpf_error("call to nonexistent function %u at PC %d", inst.imm, i);
                return false;
            }
            break;

        case EBPF_OP_EXIT:
            break;

        case EBPF_OP_DIV_IMM:
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_DIV64_IMM:
        case EBPF_OP_MOD64_IMM:
            break;

        default:
            *errmsg = ebpf_error("unknown opcode 0x%02x at PC %d", inst.code, i);
            return false;
        }

        if (inst.src_reg > 10) {
            *errmsg = ebpf_error("invalid source register at PC %d", i);
            return false;
        }

        if (inst.dst_reg > 9 && !(store && inst.dst_reg == 10)) {
            *errmsg = ebpf_error("invalid destination register at PC %d", i);
            return false;
        }
    }

    return true;
}

static bool
bounds_check(
    const struct ebpf_vm* vm,
    void* addr,
    int size,
    const char* type,
    uint16_t cur_pc,
    void* mem,
    size_t mem_len,
    void* stack)
{
    if (!vm->bounds_check_enabled)
        return true;
    if (mem && (addr >= mem && ((char*)addr + size) <= ((char*)mem + mem_len))) {
        /* Context access */
        return true;
    } else if (addr >= stack && ((char*)addr + size) <= ((char*)stack + EBPF_STACK_SIZE)) {
        /* Stack access */
        return true;
    } else {
        vm->error_printf(
            stderr,
            "ebpf error: out of bounds memory %s at PC %u, addr %p, size %d\nmem %p/%zd stack %p/%d\n",
            type,
            cur_pc,
            addr,
            size,
            mem,
            mem_len,
            stack,
            EBPF_STACK_SIZE);
        return false;
    }
}

char*
ebpf_error(const char* fmt, ...)
{
    char* msg;
    va_list ap;
    va_start(ap, fmt);
    if (vasprintf(&msg, fmt, ap) < 0) {
        msg = NULL;
    }
    va_end(ap);
    return msg;
}

#ifdef DEBUG
void
ebpf_set_registers(struct ebpf_vm* vm, uint64_t* regs)
{
    vm->regs = regs;
}

uint64_t*
ebpf_get_registers(const struct ebpf_vm* vm)
{
    return vm->regs;
}
#else
void
ebpf_set_registers(struct ebpf_vm* vm, uint64_t* regs)
{
    (void)vm;
    (void)regs;
    fprintf(stderr, "ebpf warning: registers are not exposed in release mode. Please recompile in debug mode\n");
}

uint64_t*
ebpf_get_registers(const struct ebpf_vm* vm)
{
    (void)vm;
    fprintf(stderr, "ebpf warning: registers are not exposed in release mode. Please recompile in debug mode\n");
    return NULL;
}

#endif

typedef struct _ebpf_encoded_inst
{
    union
    {
        uint64_t value;
        struct bpf_insn inst;
    };
} ebpf_encoded_inst;

struct bpf_insn
ebpf_fetch_instruction(const struct ebpf_vm* vm, uint16_t pc)
{
    // XOR instruction with base address of vm.
    // This makes ROP attack more difficult.
    ebpf_encoded_inst encode_inst;
    encode_inst.inst = vm->insnsi[pc];
    encode_inst.value ^= (uint64_t)vm->insnsi;
    encode_inst.value ^= vm->pointer_secret;
    return encode_inst.inst;
}

void
ebpf_store_instruction(const struct ebpf_vm* vm, uint16_t pc, struct bpf_insn inst)
{
    // XOR instruction with base address of vm.
    // This makes ROP attack more difficult.
    ebpf_encoded_inst encode_inst;
    encode_inst.inst = inst;
    encode_inst.value ^= (uint64_t)vm->insnsi;
    encode_inst.value ^= vm->pointer_secret;
    vm->insnsi[pc] = encode_inst.inst;
}

int
ebpf_set_pointer_secret(struct ebpf_vm* vm, uint64_t secret)
{
    if (vm->insnsi) {
        return -1;
    }
    vm->pointer_secret = secret;
    return 0;
}
