#include "libebpf.h"
#include "libebpf_internal.h"
#include "libebpf_insn.h"
#include <asm-generic/errno-base.h>
int ebpf_vm_verify(ebpf_vm_t *vm, const struct libebpf_insn *code, size_t code_len) {
    uint16_t pc = 0;
    while (pc < code_len) {
        const struct libebpf_insn *insn = code + pc;

        if ((insn->code & BPF_CLASS_ALU) || (insn->code & BPF_CLASS_ALU64)) {
            // Check register access for ALU instructions
            if (insn->dst_reg > 10) {
                ebpf_set_error_string("Invalid dst register %d at pc %d", (int)insn->dst_reg, (int)pc);
                return -EPERM;
            }
            if ((insn->code & BPF_SOURCE_X) && insn->src_reg > 10) {
                ebpf_set_error_string("Invalid src register %d at pc %d", (int)insn->src_reg, (int)pc);
                return -EPERM;
            }
            // Check offset for ALU instructions
            // These instructions doesn't need offset
            if (insn->code & BPF_ALU_ADD || insn->code & BPF_ALU_SUB || insn->code & BPF_ALU_MUL || insn->code & BPF_ALU_OR ||
                insn->code & BPF_ALU_AND || insn->code & BPF_ALU_LSH || insn->code & BPF_ALU_RSH || insn->code & BPF_ALU_NEG ||
                insn->code & BPF_ALU_XOR || insn->code & BPF_ALU_ARSH || insn->code & BPF_ALU_END) {
                if (insn->offset != 0) {
                    ebpf_set_error_string("Invalid offset (must be 0) at pc %d", (int)pc);
                    return -EPERM;
                }
            }
            // Check offset for div/sdiv mod/smod
            if (insn->code & BPF_ALU_DIV_SDIV || insn->code & BPF_ALU_MOD_SMOD) {
                if (insn->offset != 0 && insn->offset != 1) {
                    ebpf_set_error_string("Invalid offset (must be 0 or 1) at pc %d", (int)pc);
                    return -EPERM;
                }
            }
            // Check offset for mov/movsx
            if (insn->code & BPF_ALU_MOV_MOVSX) {
                if (insn->offset != 0 && insn->offset != 8 && insn->offset != 16 && insn->offset != 32) {
                    ebpf_set_error_string("Invalid offset (must be 0, 8, 16, 32) at pc %d", (int)pc);
                    return -EPERM;
                }
            }
            // Check imm for endian conversion
            if (insn->code & BPF_ALU_END || insn->code == (BPF_ALU_END | BPF_END_TO_LE)) {
                if (insn->imm != 16 && insn->imm != 32 && insn->imm != 64) {
                    ebpf_set_error_string("Invalid imm, must be 16, 32, 64 at pc %d", (int)pc);
                    return -EPERM;
                }
            }
        }
        // Check for jmp instructions
        if (insn->code & BPF_CLASS_JMP || insn->code & BPF_CLASS_JMP32) {
            // JA, using offset
            if (insn->code & (BPF_CLASS_JMP | BPF_JMP_JA)) {
                if (pc + insn->offset >= code_len) {
                    ebpf_set_error_string("JA at %d jumps out of the program", (int)pc);
                    return -EPERM;
                }
            } else
                // JA, using imm
                if (insn->code & (BPF_CLASS_JMP32 | BPF_JMP_JA)) {
                    if (pc + insn->imm >= code_len) {
                        ebpf_set_error_string("JA at %d jumps out of the program", (int)pc);
                        return -EPERM;
                    }
                } else
                    // CALL, check src reg and other stuff
                    if (insn->code & BPF_JMP_CALL) {
                        if (insn->src_reg == 0) {
                            if (insn->imm < 0 || insn->imm >= MAX_EXTERNAL_HELPER || vm->helpers[insn->imm].fn == NULL) {
                                ebpf_set_error_string("Invalid helper id %d pc %d", insn->imm, (int)pc);
                                return -EPERM;
                            }
                        } else if (insn->src_reg) {
                            if (pc + insn->imm >= code_len) {
                                ebpf_set_error_string("CALL at %d jumps out of the program", (int)pc);
                                return -EPERM;
                            }
                        } else {
                            ebpf_set_error_string("Unsupported BPF_CALL subtype %d", insn->src_reg);
                            return -EPERM;
                        }
                    } else
                        // EXIT, check src reg
                        if (insn->code & BPF_JMP_EXIT) {
                            if (insn->src_reg != 0) {
                                ebpf_set_error_string("Expected src reg to be 0 at pc %d", pc);
                                return -EPERM;
                            }
                        }
                        // Other normal jmo instructions, check offset, dst_reg, and src
                        else {
                            if (insn->dst_reg < 0 || insn->dst_reg >= 10) {
                                ebpf_set_error_string("Invalid dst register %d at pc %d", (int)insn->dst_reg, (int)pc);
                                return -EPERM;
                            }
                            if (insn->code & BPF_SOURCE_X) {
                                if (insn->src_reg < 0 || insn->src_reg >= 10) {
                                    ebpf_set_error_string("Invalid src register %d at pc %d", (int)insn->src_reg, (int)pc);
                                    return -EPERM;
                                }
                            }
                        }
        }
        // STX/LDX and signed LDX instructions, check src and dst reg
        if (insn->code & (BPF_LS_MODE_MEM | BPF_CLASS_STX) || insn->code & (BPF_LS_MODE_MEM | BPF_CLASS_LDX) ||
            insn->code & (BPF_LS_MODE_MEMSX | BPF_CLASS_LDX)) {
            if (insn->dst_reg > 10) {
                ebpf_set_error_string("Invalid dst register %d at pc %d", (int)insn->dst_reg, (int)pc);
                return -EPERM;
            }
            if (insn->src_reg > 10) {
                ebpf_set_error_string("Invalid src register %d at pc %d", (int)insn->src_reg, (int)pc);
                return -EPERM;
            }
        }
        // ST instructions, check dst register
        if (insn->code & (BPF_LS_MODE_MEM | BPF_CLASS_STX)) {
            if (insn->dst_reg > 10) {
                ebpf_set_error_string("Invalid dst register %d at pc %d", (int)insn->dst_reg, (int)pc);
                return -EPERM;
            }
        }
        // Atomic instructions
        if (insn->code & (BPF_CLASS_STX | BPF_LS_MODE_ATOMIC)) {
            if ((insn->imm & BPF_ATOMIC_ADD) || (insn->imm & BPF_ATOMIC_OR) || (insn->imm & BPF_ATOMIC_AND) || (insn->imm & BPF_ATOMIC_XOR) ||
                insn->imm == BPF_ATOMIC_XCHG || insn->imm == BPF_ATOMIC_CMPXCHG) {
                if (insn->dst_reg > 10) {
                    ebpf_set_error_string("Invalid dst register %d at pc %d", (int)insn->dst_reg, (int)pc);
                    return -EPERM;
                }
                if (insn->src_reg > 10) {
                    ebpf_set_error_string("Invalid src register %d at pc %d", (int)insn->src_reg, (int)pc);
                    return -EPERM;
                }
            } else {
                ebpf_set_error_string("Invalid atomic operation %x at pc %d", insn->imm, pc);
            }
        }
        // ld64 helpers
        if (insn->code == (BPF_LS_MODE_IMM | BPF_LS_SIZE_DW | BPF_CLASS_LD)) {
            if (pc == code_len - 1) {
                ebpf_set_error_string("Expected one more instructions at pc %d, since it's a 16 bytes instruction", pc);
                return -EPERM;
            }
            if (insn->dst_reg > 10) {
                ebpf_set_error_string("Invalid dst register %d at pc %d", (int)insn->dst_reg, (int)pc);
                return -EPERM;
            }
            if (insn->src_reg == 1) {
                // dst = map_by_fd(imm)
                if (!vm->map_by_fd) {
                    ebpf_set_error_string("Requires map_by_fd to be set at pc %d for lddw helpers imm %d", pc, insn->src_reg);
                    return -EPERM;
                }
            } else if (insn->src_reg == 2) {
                // dst = map_val(map_by_fd(imm)) + next_imm
                if (!vm->map_by_fd || !vm->map_val) {
                    ebpf_set_error_string("Requires map_by_fd and map_val to be set at pc %d for lddw helpers imm %d", pc, insn->src_reg);
                    return -EPERM;
                }
            } else if (insn->src_reg == 3) {
                // dst = var_addr(imm)
                if (!vm->var_addr) {
                    ebpf_set_error_string("Requires var_addr to be set at pc %d for lddw helpers imm %d", pc, insn->src_reg);
                    return -EPERM;
                }
            } else if (insn->src_reg == 4) {
                // dst = code_addr(imm)
                if (!vm->code_addr) {
                    ebpf_set_error_string("Requires code_addr to be set at pc %d for lddw helpers imm %d", pc, insn->src_reg);
                    return -EPERM;
                }
            } else if (insn->src_reg == 5) {
                // dst = map_by_idx(imm)
                if (!vm->map_by_idx) {
                    ebpf_set_error_string("Requires map_by_idx to be set at pc %d for lddw helpers imm %d", pc, insn->src_reg);
                    return -EPERM;
                }
            } else if (insn->src_reg == 6) {
                // dst = map_val(map_by_idx(imm)) + next_imm
                if (!vm->map_by_idx || !vm->map_val) {
                    ebpf_set_error_string("Requires map_by_idx and map_val to be set at pc %d for lddw helpers imm %d", pc, insn->src_reg);
                    return -EPERM;
                }
            } else {
                ebpf_set_error_string("Unsupported ldds helper %d at pc %d", insn->src_reg, pc);
                return -EPERM;
            }
        }
        pc++;
    }

    return 0;
}
