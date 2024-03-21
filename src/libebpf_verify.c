#include "libebpf.h"
#include "libebpf_internal.h"
#include "libebpf_insn.h"
#include "misc.h"
#include <stdbool.h>
#include <string.h>

// int ebpf_verify_memory_access(ebpf)

int ebpf_vm_verify(ebpf_vm_t *vm, const struct libebpf_insn *code, size_t code_len) {
    if (code_len > 65536) {
        ebpf_set_error_string("too many instructions (max 65536)");
        return -E2BIG;
    }
    int err = 0;
    bool *bad_jmp_pos = _libebpf_global_malloc(sizeof(bool) * 65536);
    memset(bad_jmp_pos, 0, sizeof(bool) * 65536);
    // Scan for lddw helpers
    for (int i = 0; i < code_len; i++) {
        if (code[i].code == (BPF_LS_SIZE_DW | BPF_CLASS_LD | BPF_LS_MODE_IMM)) {
            if (i + 1 < code_len)
                bad_jmp_pos[i + 1] = true;
        }
    }
    uint16_t pc = 0;
    while (pc < code_len) {
        const struct libebpf_insn *insn = code + pc;

        if (bit_test_mask(insn->code, BPF_CLASS_MASK, BPF_CLASS_ALU) || bit_test_mask(insn->code, BPF_CLASS_MASK, BPF_CLASS_ALU64)) {
            if (insn->dst_reg == 10) {
                ebpf_set_error_string("Write to stack register is forbidden. pc %d", pc);
                return -EPERM;
            }

            // Check register access for ALU instructions
            if (insn->dst_reg > 10) {
                ebpf_set_error_string("Invalid dst register %d at pc %d", (int)insn->dst_reg, (int)pc);
                err = -EPERM;
                goto out;
            }
            if (bit_test_mask(insn->code, BPF_ALU_SOURCE_MASK, BPF_SOURCE_X) && insn->src_reg > 10) {
                ebpf_set_error_string("Invalid src register %d at pc %d", (int)insn->src_reg, (int)pc);
                err = -EPERM;
                goto out;
            }
            // Check offset for ALU instructions
            // These instructions doesn't need offset
            if (

                    bit_test_mask(insn->code, BPF_ALU_CODE_MASK, BPF_ALU_ADD) || bit_test_mask(insn->code, BPF_ALU_CODE_MASK, BPF_ALU_SUB) ||
                    bit_test_mask(insn->code, BPF_ALU_CODE_MASK, BPF_ALU_MUL) || bit_test_mask(insn->code, BPF_ALU_CODE_MASK, BPF_ALU_OR) ||
                    bit_test_mask(insn->code, BPF_ALU_CODE_MASK, BPF_ALU_AND) || bit_test_mask(insn->code, BPF_ALU_CODE_MASK, BPF_ALU_LSH) ||
                    bit_test_mask(insn->code, BPF_ALU_CODE_MASK, BPF_ALU_NEG) || bit_test_mask(insn->code, BPF_ALU_CODE_MASK, BPF_ALU_XOR) ||
                    bit_test_mask(insn->code, BPF_ALU_CODE_MASK, BPF_ALU_ARSH) || bit_test_mask(insn->code, BPF_ALU_CODE_MASK, BPF_ALU_END)) {
                if (insn->offset != 0) {
                    ebpf_set_error_string("Invalid offset (must be 0) at pc %d", (int)pc);
                }
            }
            // Check offset for div/sdiv mod/smod
            if (bit_test_mask(insn->code, BPF_ALU_CODE_MASK, BPF_ALU_DIV_SDIV) || bit_test_mask(insn->code, BPF_ALU_CODE_MASK, BPF_ALU_MOD_SMOD)) {
                if (insn->offset != 0 && insn->offset != 1) {
                    ebpf_set_error_string("Invalid offset (must be 0 or 1) at pc %d", (int)pc);
                    err = -EPERM;
                    goto out;
                }
            }
            // Check offset for mov/movsx
            if (bit_test_mask(insn->code, BPF_ALU_CODE_MASK, BPF_ALU_MOV_MOVSX)) {
                if (insn->offset != 0 && insn->offset != 8 && insn->offset != 16 && insn->offset != 32) {
                    ebpf_set_error_string("Invalid offset (must be 0, 8, 16, 32) at pc %d", (int)pc);
                    err = -EPERM;
                    goto out;
                }
            }
            // Check imm for endian conversion
            if (bit_test_mask(insn->code, BPF_ALU_CODE_MASK, BPF_ALU_END) || insn->code == (BPF_ALU_END | BPF_END_TO_LE)) {
                if (insn->imm != 16 && insn->imm != 32 && insn->imm != 64) {
                    ebpf_set_error_string("Invalid imm, must be 16, 32, 64 at pc %d", (int)pc);
                    err = -EPERM;
                    goto out;
                }
            }
        }
        // Check for jmp instructions
        else if (bit_test_mask(insn->code, BPF_CLASS_MASK, BPF_CLASS_JMP) || bit_test_mask(insn->code, BPF_CLASS_MASK, BPF_CLASS_JMP32)) {
            // JA, using offset
            if (bit_test_mask(insn->code, BPF_CLASS_MASK | BPF_JMP_CODE_MASK, (BPF_CLASS_JMP | BPF_JMP_JA))) {
                if (pc + insn->offset + 1 >= code_len) {
                    ebpf_set_error_string("JA at %d jumps out of the program", (int)pc);
                    err = -EPERM;
                    goto out;
                }
                if (insn->offset <= -1) {
                    ebpf_set_error_string("Infinite loop at pc %d", pc);
                    err = -EPERM;
                    goto out;
                }
                if (bad_jmp_pos[pc + insn->offset + 1]) {
                    ebpf_set_error_string("Jumping to the intermediate of a LDDW at pc %d", (int)pc);
                    err = -EPERM;
                    goto out;
                }
            } else
                // JA, using imm
                if (bit_test_mask(insn->code, BPF_CLASS_MASK | BPF_JMP_CODE_MASK, (BPF_CLASS_JMP32 | BPF_JMP_JA))) {
                    if (pc + insn->imm >= code_len) {
                        ebpf_set_error_string("JA at %d jumps out of the program", (int)pc);
                        err = -EPERM;
                        goto out;
                    }
                    if (insn->imm <= -1) {
                        ebpf_set_error_string("Infinite loop at pc %d", pc);
                        err = -EPERM;
                        goto out;
                    }
                    if (bad_jmp_pos[pc + insn->imm + 1]) {
                        ebpf_set_error_string("Jumping to the intermediate of a LDDW at pc %d", (int)pc);
                        err = -EPERM;
                        goto out;
                    }
                } else
                    // CALL, check src reg and other stuff
                    if (bit_test_mask(insn->code, BPF_JMP_CODE_MASK, BPF_JMP_CALL)) {
                        if (insn->src_reg == 0) {
                            if (insn->imm < 0 || insn->imm >= MAX_EXTERNAL_HELPER || vm->helpers[insn->imm].fn == NULL) {
                                ebpf_set_error_string("Invalid helper id %d pc %d", insn->imm, (int)pc);
                                err = -EPERM;
                                goto out;
                            }
                        } else if (insn->src_reg == 1) {
                            if (pc + insn->imm + 1 >= code_len) {
                                ebpf_set_error_string("CALL at %d jumps out of the program", (int)pc);
                                err = -EPERM;
                                goto out;
                            }
                        } else {
                            ebpf_set_error_string("Unsupported BPF_CALL subtype %d", insn->src_reg);
                            err = -EPERM;
                            goto out;
                        }
                    } else
                        // EXIT, check src reg
                        if (bit_test_mask(insn->code, BPF_JMP_CODE_MASK, BPF_JMP_EXIT)) {
                            if (insn->src_reg != 0) {
                                ebpf_set_error_string("Expected src reg to be 0 at pc %d", pc);
                                err = -EPERM;
                                goto out;
                            }
                            if (!bit_test_mask(insn->code, BPF_CLASS_MASK, BPF_CLASS_JMP)) {
                                if (insn->src_reg != 0) {
                                    ebpf_set_error_string("BPF_JMP_EXIT can only be with BPF_CLASS_JMP at pc %d", pc);
                                    err = -EPERM;
                                    goto out;
                                }
                            }
                        }
                        // Other normal jmp instructions, check offset, dst_reg, and src
                        else {
                            if (insn->dst_reg < 0 || insn->dst_reg >= 10) {
                                ebpf_set_error_string("Invalid dst register %d at pc %d", (int)insn->dst_reg, (int)pc);
                                err = -EPERM;
                                goto out;
                            }
                            if (bit_test_mask(insn->code, BPF_JMP_SOURCE_MASK, BPF_SOURCE_X)) {
                                if (insn->src_reg < 0 || insn->src_reg >= 10) {
                                    ebpf_set_error_string("Invalid src register %d at pc %d", (int)insn->src_reg, (int)pc);
                                    err = -EPERM;
                                    goto out;
                                }
                            }
                            if (insn->offset == -1) {
                                ebpf_set_error_string("Infinite loop at pc %d", pc);
                                err = -EPERM;
                                goto out;
                            }
                            if (bad_jmp_pos[pc + insn->offset + 1]) {
                                ebpf_set_error_string("Jumping to the intermediate of a LDDW at pc %d", (int)pc);
                                err = -EPERM;
                                goto out;
                            }
                        }
        }
        // STX/LDX and signed LDX instructions, check src and dst reg
        else if (bit_test_mask(insn->code, BPF_LS_MODE_MASK | BPF_CLASS_MASK, (BPF_LS_MODE_MEM | BPF_CLASS_STX)) ||
                 bit_test_mask(insn->code, BPF_LS_MODE_MASK | BPF_CLASS_MASK, (BPF_LS_MODE_MEM | BPF_CLASS_LDX)) ||
                 bit_test_mask(insn->code, BPF_LS_MODE_MASK | BPF_CLASS_MASK, (BPF_LS_MODE_MEMSX | BPF_CLASS_LDX))) {
            if (insn->dst_reg > 10) {
                ebpf_set_error_string("Invalid dst register %d at pc %d", (int)insn->dst_reg, (int)pc);
                err = -EPERM;
                goto out;
            }
            if (insn->src_reg > 10) {
                ebpf_set_error_string("Invalid src register %d at pc %d", (int)insn->src_reg, (int)pc);
                err = -EPERM;
                goto out;
            }
            if (bit_test_mask(insn->code, BPF_CLASS_MASK, BPF_CLASS_LDX)) {
                if (insn->dst_reg == 10) {
                    ebpf_set_error_string("Write to stack register is forbidden. pc %d", pc);
                    return -EPERM;
                }
            }
        }
        // ST instructions, check dst register
        else if (bit_test_mask(insn->code, BPF_LS_MODE_MASK | BPF_CLASS_MASK, (BPF_LS_MODE_MEM | BPF_CLASS_ST))) {
            if (insn->dst_reg > 10) {
                ebpf_set_error_string("Invalid dst register %d at pc %d", (int)insn->dst_reg, (int)pc);
                err = -EPERM;
                goto out;
            }
        }
        // Atomic instructions
        else if (bit_test_mask(insn->code, BPF_LS_MODE_MASK | BPF_CLASS_MASK, (BPF_CLASS_STX | BPF_LS_MODE_ATOMIC))) {
            if (insn->imm == BPF_ATOMIC_ADD || insn->imm == (BPF_ATOMIC_ADD | BPF_ATOMIC_FETCH) ||

                insn->imm == BPF_ATOMIC_OR || insn->imm == (BPF_ATOMIC_OR | BPF_ATOMIC_FETCH) ||

                insn->imm == BPF_ATOMIC_AND || insn->imm == (BPF_ATOMIC_AND | BPF_ATOMIC_FETCH) ||

                insn->imm == BPF_ATOMIC_XOR || insn->imm == (BPF_ATOMIC_XOR | BPF_ATOMIC_FETCH) ||

                insn->imm == BPF_ATOMIC_XCHG || insn->imm == BPF_ATOMIC_CMPXCHG) {
                if (insn->dst_reg > 10) {
                    ebpf_set_error_string("Invalid dst register %d at pc %d", (int)insn->dst_reg, (int)pc);
                    err = -EPERM;
                    goto out;
                }
                if (insn->src_reg > 10) {
                    ebpf_set_error_string("Invalid src register %d at pc %d", (int)insn->src_reg, (int)pc);
                    err = -EPERM;
                    goto out;
                }
            } else {
                ebpf_set_error_string("Invalid atomic operation %x at pc %d", insn->imm, pc);
            }
        }
        // ld64 helpers
        else if (insn->code == (BPF_LS_MODE_IMM | BPF_LS_SIZE_DW | BPF_CLASS_LD)) {
            if (insn->dst_reg == 10) {
                ebpf_set_error_string("Write to stack register is forbidden. pc %d", pc);
                return -EPERM;
            }
            if (pc == code_len - 1) {
                ebpf_set_error_string("Expected one more instructions at pc %d, since it's a 16 bytes instruction", pc);
                err = -EPERM;
                goto out;
            }
            if (code[pc + 1].code != 0 || code[pc + 1].dst_reg != 0 || code[pc + 1].src_reg != 0 || code[pc + 1].offset != 0) {
                ebpf_set_error_string("Incomplete lddw at pc %d", pc);
                err = -EPERM;
                goto out;
            }

            bad_jmp_pos[pc] = true;
            if (insn->dst_reg > 10) {
                ebpf_set_error_string("Invalid dst register %d at pc %d", (int)insn->dst_reg, (int)pc);
                err = -EPERM;
                goto out;
            }
            if (insn->src_reg == 1) {
                // dst = map_by_fd(imm)
                if (!vm->map_by_fd) {
                    ebpf_set_error_string("Requires map_by_fd to be set at pc %d for lddw helpers imm %d", pc, insn->src_reg);
                    err = -EPERM;
                    goto out;
                }
            } else if (insn->src_reg == 2) {
                // dst = map_val(map_by_fd(imm)) + next_imm
                if (!vm->map_by_fd || !vm->map_val) {
                    ebpf_set_error_string("Requires map_by_fd and map_val to be set at pc %d for lddw helpers imm %d", pc, insn->src_reg);
                    err = -EPERM;
                    goto out;
                }
            } else if (insn->src_reg == 3) {
                // dst = var_addr(imm)
                if (!vm->var_addr) {
                    ebpf_set_error_string("Requires var_addr to be set at pc %d for lddw helpers imm %d", pc, insn->src_reg);
                    err = -EPERM;
                    goto out;
                }
            } else if (insn->src_reg == 4) {
                // dst = code_addr(imm)
                if (!vm->code_addr) {
                    ebpf_set_error_string("Requires code_addr to be set at pc %d for lddw helpers imm %d", pc, insn->src_reg);
                    err = -EPERM;
                    goto out;
                }
            } else if (insn->src_reg == 5) {
                // dst = map_by_idx(imm)
                if (!vm->map_by_idx) {
                    ebpf_set_error_string("Requires map_by_idx to be set at pc %d for lddw helpers imm %d", pc, insn->src_reg);
                    err = -EPERM;
                    goto out;
                }
            } else if (insn->src_reg == 6) {
                // dst = map_val(map_by_idx(imm)) + next_imm
                if (!vm->map_by_idx || !vm->map_val) {
                    ebpf_set_error_string("Requires map_by_idx and map_val to be set at pc %d for lddw helpers imm %d", pc, insn->src_reg);
                    err = -EPERM;
                    goto out;
                }
            } else if (insn->src_reg != 0) {
                ebpf_set_error_string("Unsupported lddw helper %d at pc %d", insn->src_reg, pc);
                err = -EPERM;
                goto out;
            }
            pc++;
        } else {
            ebpf_set_error_string("Unsupported opcode 0x%x at pc %d", insn->code, pc);
            return -EINVAL;
        }
        pc++;
    }
out:
    _libebpf_global_free(bad_jmp_pos);
    return err;
}
