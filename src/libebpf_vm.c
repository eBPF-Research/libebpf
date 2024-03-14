#include "libebpf_insn.h"
#include <asm-generic/errno-base.h>
#include <libebpf.h>
#include <libebpf_internal.h>
#include <stdint.h>
#include "ends_conversion.h"
#include "clause_helpers.h"
int ebpf_vm_run(ebpf_vm_t *vm, void *mem, size_t mem_len, uint64_t *return_value) {
    if (!vm->insns) {
        ebpf_set_error_string("Instructions not loaded yet!");
        return -EBADF;
    }
    uint16_t pc = 0;
    const struct libebpf_insn *insns = vm->insns;
    uint16_t reg[11];
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
        }
    }
}
