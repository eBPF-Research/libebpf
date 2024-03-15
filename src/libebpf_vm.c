#include "libebpf_insn.h"
#include <asm-generic/errno-base.h>
#include <libebpf.h>
#include <libebpf_internal.h>
#include <stdint.h>
#include "ends_conversion.h"
#include "clause_helpers.h"
#include <stdbool.h>
int ebpf_vm_run(ebpf_vm_t *vm, void *mem, size_t mem_len, uint64_t *return_value) {
    if (!vm->insns) {
        ebpf_set_error_string("Instructions not loaded yet!");
        return -EBADF;
    }
    uint16_t pc = 0;
    const struct libebpf_insn *insns = vm->insns;
    uint64_t reg[11];
    uint16_t stack[MAX_LOCAL_FUNCTION_LEVEL * EBPF_STACK_SIZE];
    if (!insns) {
        ebpf_set_error_string("Instructions not loaded yet");
        return -EINVAL;
    }

    reg[1] = (uintptr_t)mem;
    reg[2] = mem_len;
    reg[10] = (uintptr_t)stack + sizeof(stack);

    while (1) {
        const struct libebpf_insn *insn = insns + pc;
        pc++;
        switch (insn->code) {
        case BPF_CLASS_ALU | BPF_SOURCE_K | BPF_ALU_ADD:
        case BPF_CLASS_ALU | BPF_SOURCE_X | BPF_ALU_ADD:
        case BPF_CLASS_ALU64 | BPF_SOURCE_K | BPF_ALU_ADD:
        case BPF_CLASS_ALU64 | BPF_SOURCE_X | BPF_ALU_ADD: {
            uint64_t src = insn->code_alu.src == 0 ? insn->imm : reg[insn->src_reg];
            uint64_t dst = reg[insn->dst_reg];
            if (insn->code & BPF_CLASS_ALU) {
                reg[insn->dst_reg] = (uint32_t)dst + (uint32_t)src;
            } else {
                reg[insn->dst_reg] = dst + src;
            }
            break;
        }
            SIMPLE_ALU_OP_DEF(BPF_ALU_SUB, -);
            SIMPLE_ALU_OP_DEF(BPF_ALU_MUL, *);
            SIMPLE_ALU_OP_DEF(BPF_ALU_OR, |);
            SIMPLE_ALU_OP_DEF(BPF_ALU_AND, &);
            SIMPLE_ALU_OP_DEF(BPF_ALU_XOR, ^);

        case BPF_CLASS_ALU | BPF_SOURCE_K | BPF_ALU_DIV_SDIV:
        case BPF_CLASS_ALU | BPF_SOURCE_X | BPF_ALU_DIV_SDIV:
        case BPF_CLASS_ALU64 | BPF_SOURCE_K | BPF_ALU_DIV_SDIV:
        case BPF_CLASS_ALU64 | BPF_SOURCE_X | BPF_ALU_DIV_SDIV: {
            uint64_t src = insn->code_alu.src == 0 ? insn->imm : reg[insn->src_reg];
            uint64_t dst = reg[insn->dst_reg];
            if (insn->offset == 0) {
                if (insn->code & BPF_CLASS_ALU) {
                    reg[insn->dst_reg] = src != 0 ? (uint32_t)dst / (uint32_t)src : 0;
                } else {
                    reg[insn->dst_reg] = src != 0 ? dst / src : 0;
                }
            } else if (insn->offset == 1) {
                // sdiv
                if (insn->code & BPF_CLASS_ALU) {
                    reg[insn->dst_reg] = src != 0 ? (int32_t)dst / (int32_t)src : 0;
                } else {
                    reg[insn->dst_reg] = src != 0 ? (int64_t)dst / (int64_t)src : 0;
                }
            }
            break;
        }

        case BPF_CLASS_ALU | BPF_SOURCE_K | BPF_ALU_LSH:
        case BPF_CLASS_ALU | BPF_SOURCE_X | BPF_ALU_LSH:
        case BPF_CLASS_ALU64 | BPF_SOURCE_K | BPF_ALU_LSH:
        case BPF_CLASS_ALU64 | BPF_SOURCE_X | BPF_ALU_LSH: {
            uint64_t src = insn->code_alu.src == 0 ? insn->imm : reg[insn->src_reg];
            uint64_t dst = reg[insn->dst_reg];
            if (insn->code & BPF_CLASS_ALU) {
                reg[insn->dst_reg] = ((uint32_t)dst) << (src & 0x1f);
            } else {
                reg[insn->dst_reg] = dst << (src & 0x3f);
            }
            break;
        }
        case BPF_CLASS_ALU | BPF_SOURCE_K | BPF_ALU_RSH:
        case BPF_CLASS_ALU | BPF_SOURCE_X | BPF_ALU_RSH:
        case BPF_CLASS_ALU64 | BPF_SOURCE_K | BPF_ALU_RSH:
        case BPF_CLASS_ALU64 | BPF_SOURCE_X | BPF_ALU_RSH: {
            uint64_t src = insn->code_alu.src == 0 ? insn->imm : reg[insn->src_reg];
            uint64_t dst = reg[insn->dst_reg];
            if (insn->code & BPF_CLASS_ALU) {
                reg[insn->dst_reg] = ((uint32_t)dst) >> (src & 0x1f);
            } else {
                reg[insn->dst_reg] = dst >> (src & 0x3f);
            }
            break;
        }
        case BPF_CLASS_ALU | BPF_SOURCE_K | BPF_ALU_NEG:
        case BPF_CLASS_ALU | BPF_SOURCE_X | BPF_ALU_NEG:
        case BPF_CLASS_ALU64 | BPF_SOURCE_K | BPF_ALU_NEG:
        case BPF_CLASS_ALU64 | BPF_SOURCE_X | BPF_ALU_NEG: {
            uint64_t dst = reg[insn->dst_reg];
            if (insn->code & BPF_CLASS_ALU) {
                reg[insn->dst_reg] = (uint32_t)(-(int32_t)dst);
            } else {
                reg[insn->dst_reg] = (uint64_t)(-(int64_t)dst);
            }
            break;
        }
        case BPF_CLASS_ALU | BPF_SOURCE_K | BPF_ALU_MOD_SMOD:
        case BPF_CLASS_ALU | BPF_SOURCE_X | BPF_ALU_MOD_SMOD:
        case BPF_CLASS_ALU64 | BPF_SOURCE_K | BPF_ALU_MOD_SMOD:
        case BPF_CLASS_ALU64 | BPF_SOURCE_X | BPF_ALU_MOD_SMOD: {
            uint64_t src = insn->code_alu.src == 0 ? insn->imm : reg[insn->src_reg];
            uint64_t dst = reg[insn->dst_reg];
            if (insn->offset == 0) {
                if (insn->code & BPF_CLASS_ALU) {
                    reg[insn->dst_reg] = src != 0 ? (uint32_t)dst % (uint32_t)src : 0;
                } else {
                    reg[insn->dst_reg] = src != 0 ? dst % src : 0;
                }
            } else if (insn->offset == 1) {
                // smod
                if (insn->code & BPF_CLASS_ALU) {
                    reg[insn->dst_reg] = src != 0 ? (int32_t)dst % (int32_t)src : 0;
                } else {
                    reg[insn->dst_reg] = src != 0 ? (int64_t)dst % (int64_t)src : 0;
                }
            }
            break;
        }

        case BPF_CLASS_ALU | BPF_SOURCE_K | BPF_ALU_MOV_MOVSX:
        case BPF_CLASS_ALU | BPF_SOURCE_X | BPF_ALU_MOV_MOVSX:
        case BPF_CLASS_ALU64 | BPF_SOURCE_K | BPF_ALU_MOV_MOVSX:
        case BPF_CLASS_ALU64 | BPF_SOURCE_X | BPF_ALU_MOV_MOVSX: {
            uint64_t dst = reg[insn->dst_reg];
            uint64_t src = insn->code_alu.src == 0 ? insn->imm : reg[insn->src_reg];
            if (insn->offset == 0) {
                if (insn->code & BPF_CLASS_ALU) {
                    reg[insn->dst_reg] = (uint32_t)src;
                } else {
                    reg[insn->dst_reg] = src;
                }
            } else if (insn->offset == 8) {
                // dst = (s8) src
                if (insn->code & BPF_CLASS_ALU) {
                    reg[insn->dst_reg] = (uint32_t)(int8_t)src;
                } else {
                    reg[insn->dst_reg] = (uint64_t)(int8_t)src;
                }
            } else if (insn->offset == 16) {
                // dst = (s16) src
                if (insn->code & BPF_CLASS_ALU) {
                    reg[insn->dst_reg] = (uint32_t)(int16_t)src;
                } else {
                    reg[insn->dst_reg] = (uint64_t)(int16_t)src;
                }
            } else if (insn->offset == 32) {
                // dst = (s32) src
                if (insn->code & BPF_CLASS_ALU) {
                    reg[insn->dst_reg] = (uint32_t)(int32_t)src;
                } else {
                    reg[insn->dst_reg] = (uint64_t)(int32_t)src;
                }
            }
            break;
        }

        case BPF_CLASS_ALU | BPF_SOURCE_K | BPF_ALU_ARSH:
        case BPF_CLASS_ALU | BPF_SOURCE_X | BPF_ALU_ARSH:
        case BPF_CLASS_ALU64 | BPF_SOURCE_K | BPF_ALU_ARSH:
        case BPF_CLASS_ALU64 | BPF_SOURCE_X | BPF_ALU_ARSH: {
            uint64_t src = insn->code_alu.src == 0 ? insn->imm : reg[insn->src_reg];
            uint64_t dst = reg[insn->dst_reg];
            if (insn->code & BPF_CLASS_ALU) {
                reg[insn->dst_reg] = ((int32_t)dst) >> (src & 0x1f);
            } else {
                reg[insn->dst_reg] = ((int64_t)dst) >> (src & 0x3f);
            }
            break;
        }
        case BPF_CLASS_ALU | BPF_END_TO_LE | BPF_ALU_END: {
            if (insn->imm == 16)
                reg[insn->dst_reg] = htole16(reg[insn->dst_reg]);
            else if (insn->imm == 32)
                reg[insn->dst_reg] = htole32(reg[insn->dst_reg]);
            else if (insn->imm == 64)
                reg[insn->dst_reg] = htole64(reg[insn->dst_reg]);

            break;
        }
        case BPF_CLASS_ALU | BPF_END_TO_BE | BPF_ALU_END: {
            if (insn->imm == 16)
                reg[insn->dst_reg] = htobe16(reg[insn->dst_reg]);
            else if (insn->imm == 32)
                reg[insn->dst_reg] = htobe32(reg[insn->dst_reg]);
            else if (insn->imm == 64)
                reg[insn->dst_reg] = htobe64(reg[insn->dst_reg]);

            break;
        }
        case BPF_CLASS_ALU64 | BPF_ALU_END: {
            if (insn->imm == 16)
                reg[insn->dst_reg] = bswap16(reg[insn->dst_reg]);
            else if (insn->imm == 32)
                reg[insn->dst_reg] = bswap32(reg[insn->dst_reg]);
            else if (insn->imm == 64)
                reg[insn->dst_reg] = bswap64(reg[insn->dst_reg]);

            break;
        }
        case BPF_CLASS_JMP | BPF_SOURCE_K | BPF_JMP_JA:
        case BPF_CLASS_JMP | BPF_SOURCE_X | BPF_JMP_JA: {
            pc += insn->offset;
            break;
        }
        case BPF_CLASS_JMP32 | BPF_SOURCE_K | BPF_JMP_JA:
        case BPF_CLASS_JMP32 | BPF_SOURCE_X | BPF_JMP_JA: {
            pc += insn->imm;
            break;
        }
        case BPF_CLASS_JMP | BPF_SOURCE_K | BPF_JMP_JEQ:
        case BPF_CLASS_JMP | BPF_SOURCE_X | BPF_JMP_JEQ:
        case BPF_CLASS_JMP32 | BPF_SOURCE_K | BPF_JMP_JEQ:
        case BPF_CLASS_JMP32 | BPF_SOURCE_X | BPF_JMP_JEQ: {
            uint64_t src = insn->code_alu.src == 0 ? insn->imm : reg[insn->src_reg];
            uint64_t dst = reg[insn->dst_reg];
            if (insn->code & BPF_CLASS_JMP) {
                if (dst == src)
                    pc += insn->offset;
            } else {
                if ((uint32_t)dst == (uint32_t)src)
                    pc += insn->offset;
            }
        }
            SIMPLE_JMP_OP_CLAUSE(BPF_JMP_JGT, >);
            SIMPLE_JMP_OP_CLAUSE(BPF_JMP_JGE, >=);
            SIMPLE_JMP_OP_CLAUSE(BPF_JMP_JSET, &);
            SIMPLE_JMP_OP_CLAUSE(BPF_JMP_JNE, !=);
            SIMPLE_JMP_OP_CLAUSE_SIGNED(BPF_JMP_JSGT, >);
            SIMPLE_JMP_OP_CLAUSE_SIGNED(BPF_JMP_JSGE, >=);
            SIMPLE_JMP_OP_CLAUSE(BPF_JMP_JLT, <);
            SIMPLE_JMP_OP_CLAUSE(BPF_JMP_JLE, <=);
            SIMPLE_JMP_OP_CLAUSE_SIGNED(BPF_JMP_JSLT, <);
            SIMPLE_JMP_OP_CLAUSE_SIGNED(BPF_JMP_JSLE, <=);

        case BPF_CLASS_JMP | BPF_SOURCE_K | BPF_JMP_CALL:
        case BPF_CLASS_JMP | BPF_SOURCE_X | BPF_JMP_CALL:
        case BPF_CLASS_JMP32 | BPF_SOURCE_K | BPF_JMP_CALL:
        case BPF_CLASS_JMP32 | BPF_SOURCE_X | BPF_JMP_CALL: {
            if (insn->src_reg == 0) {
                reg[0] = vm->helpers[insn->imm].fn(reg[1], reg[2], reg[3], reg[4], reg[5]);
            } else if (insn->src_reg == 1) {
            } else if (insn->src_reg == 2) {
            }
            break;
        }
        case BPF_CLASS_JMP | BPF_SOURCE_K | BPF_JMP_EXIT:
        case BPF_CLASS_JMP | BPF_SOURCE_X | BPF_JMP_EXIT: {
            return reg[0];
        }

            SIMPLE_STX_CLAUSE(BPF_LS_SIZE_B, uint8_t);
            SIMPLE_STX_CLAUSE(BPF_LS_SIZE_H, uint16_t);
            SIMPLE_STX_CLAUSE(BPF_LS_SIZE_W, uint32_t);
            SIMPLE_STX_CLAUSE(BPF_LS_SIZE_DW, uint64_t);

            SIMPLE_ST_CLAUSE(BPF_LS_SIZE_B, uint8_t);
            SIMPLE_ST_CLAUSE(BPF_LS_SIZE_H, uint16_t);
            SIMPLE_ST_CLAUSE(BPF_LS_SIZE_W, uint32_t);
            SIMPLE_ST_CLAUSE(BPF_LS_SIZE_DW, uint64_t);

            SIMPLE_LDX_CLAUSE(BPF_LS_SIZE_B, uint8_t);
            SIMPLE_LDX_CLAUSE(BPF_LS_SIZE_H, uint16_t);
            SIMPLE_LDX_CLAUSE(BPF_LS_SIZE_W, uint32_t);
            SIMPLE_LDX_CLAUSE(BPF_LS_SIZE_DW, uint64_t);

            SIMPLE_LDX_SIGNED_CLAUSE(BPF_LS_SIZE_B, int8_t);
            SIMPLE_LDX_SIGNED_CLAUSE(BPF_LS_SIZE_H, int16_t);
            SIMPLE_LDX_SIGNED_CLAUSE(BPF_LS_SIZE_W, int32_t);
            SIMPLE_LDX_SIGNED_CLAUSE(BPF_LS_SIZE_DW, int64_t);

        case BPF_CLASS_STX | BPF_LS_SIZE_W | BPF_LS_MODE_ATOMIC: {
            // 32-bit atomic operations
            uint32_t old_value;
            bool value_set = false;
            if (insn->imm & 0x00) {
                // Atomic add
                // *(u32*)(dst+offset) += src;
                old_value = __atomic_fetch_add((uint32_t *)(uintptr_t)(reg[insn->dst_reg] + insn->offset), reg[insn->src_reg], __ATOMIC_SEQ_CST);
                value_set = true;
            } else if (insn->imm & 0x40) {
                // Atomic or
                // *(u32*)(dst+offset) |= src;
                old_value = __atomic_fetch_or((uint32_t *)(uintptr_t)(reg[insn->dst_reg] + insn->offset), reg[insn->src_reg], __ATOMIC_SEQ_CST);
                value_set = true;
            } else if (insn->imm & 0x50) {
                // Atomic and
                // *(u32*)(dst+offset) &= src;
                old_value = __atomic_fetch_and((uint32_t *)(uintptr_t)(reg[insn->dst_reg] + insn->offset), reg[insn->src_reg], __ATOMIC_SEQ_CST);
                value_set = true;
            } else if (insn->imm & 0xa0) {
                // Atomic xor
                // *(u32*)(dst+offset) ^= src;
                old_value = __atomic_fetch_xor((uint32_t *)(uintptr_t)(reg[insn->dst_reg] + insn->offset), reg[insn->src_reg], __ATOMIC_SEQ_CST);
                value_set = true;
            }
            if (value_set)
                reg[insn->src_reg] = old_value;
            if (insn->imm == BPF_ATOMIC_XCHG) {
                __atomic_exchange((uint32_t *)(uintptr_t)(reg[insn->dst_reg] + insn->offset), (uint32_t *)&reg[insn->src_reg],
                                  (uint32_t *)&reg[insn->src_reg], __ATOMIC_SEQ_CST);
            } else if (insn->imm == BPF_ATOMIC_CMPXCHG) {
                if (!__atomic_compare_exchange_n((uint32_t *)(uintptr_t)(reg[insn->dst_reg] + insn->offset), (uint32_t *)&reg[0],
                                                 (uint32_t)reg[insn->src_reg], false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
                    reg[0] = *(uint32_t *)(uintptr_t)(reg[insn->dst_reg] + insn->offset);
                } else {
                    reg[0] >>= 32;
                    reg[0] <<= 32;
                }
            }
            break;
        }
        case BPF_CLASS_STX | BPF_LS_SIZE_DW | BPF_LS_MODE_ATOMIC: {
            // 64-bit atomic operations
            uint64_t old_value;
            bool value_set = false;
            if (insn->imm & 0x00) {
                // Atomic add
                // *(u32*)(dst+offset) += src;
                old_value = __atomic_fetch_add((uint64_t *)(uintptr_t)(reg[insn->dst_reg] + insn->offset), reg[insn->src_reg], __ATOMIC_SEQ_CST);
                value_set = true;
            } else if (insn->imm & 0x40) {
                // Atomic or
                // *(u32*)(dst+offset) |= src;
                old_value = __atomic_fetch_or((uint64_t *)(uintptr_t)(reg[insn->dst_reg] + insn->offset), reg[insn->src_reg], __ATOMIC_SEQ_CST);
                value_set = true;
            } else if (insn->imm & 0x50) {
                // Atomic and
                // *(u32*)(dst+offset) &= src;
                old_value = __atomic_fetch_and((uint64_t *)(uintptr_t)(reg[insn->dst_reg] + insn->offset), reg[insn->src_reg], __ATOMIC_SEQ_CST);
                value_set = true;
            } else if (insn->imm & 0xa0) {
                // Atomic xor
                // *(u32*)(dst+offset) ^= src;
                old_value = __atomic_fetch_xor((uint64_t *)(uintptr_t)(reg[insn->dst_reg] + insn->offset), reg[insn->src_reg], __ATOMIC_SEQ_CST);
                value_set = true;
            }
            if (value_set)
                reg[insn->src_reg] = old_value;
            if (insn->imm == BPF_ATOMIC_XCHG) {
                __atomic_exchange((uint64_t *)(uintptr_t)(reg[insn->dst_reg] + insn->offset), (uint64_t *)&reg[insn->src_reg],
                                  (uint64_t *)&reg[insn->src_reg], __ATOMIC_SEQ_CST);
            } else if (insn->imm == BPF_ATOMIC_CMPXCHG) {
                if (!__atomic_compare_exchange_n((uint64_t *)(uintptr_t)(reg[insn->dst_reg] + insn->offset), &reg[0], reg[insn->src_reg], false,
                                                 __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
                    reg[0] = *(uint64_t *)(uintptr_t)(reg[insn->dst_reg] + insn->offset);
                }
            }
            break;
        }
        case BPF_CLASS_LD | BPF_LS_SIZE_DW | BPF_LS_MODE_IMM: {
            // 64bit imm operations
            uint32_t next_imm = insns[pc + 1].imm;
            pc++;
            if (insn->src_reg == 0) {
                reg[insn->dst_reg] = (((uint64_t)next_imm << 32) | insn->imm);
            } else if (insn->src_reg == 1) {
                reg[insn->dst_reg] = vm->map_by_fd(insn->imm);
            } else if (insn->src_reg == 2) {
                reg[insn->dst_reg] = (uintptr_t)(vm->map_val(vm->map_by_fd(insn->imm)) + next_imm);
            } else if (insn->src_reg == 3) {
                reg[insn->dst_reg] = (uintptr_t)vm->var_addr(insn->imm);
            } else if (insn->src_reg == 4) {
                reg[insn->dst_reg] = (uintptr_t)vm->code_addr(insn->imm);
            } else if (insn->src_reg == 5) {
                reg[insn->dst_reg] = (uintptr_t)vm->map_by_idx(insn->imm);
            } else if (insn->src_reg == 6) {
                reg[insn->dst_reg] = (uintptr_t)(vm->map_val(vm->map_by_idx(insn->imm)) + next_imm);
            }

            break;
        }
        }
    }
}
