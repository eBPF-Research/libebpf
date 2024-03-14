#include "libebpf_internal.h"
#include "libebpf_insn.h"
#include <asm-generic/errno-base.h>
int ebpf_vm_verify(ebpf_vm_t *vm, const struct libebpf_insn *code, size_t code_len) {
    uint16_t pc = 0;
    while (1) {
        const struct libebpf_insn *insn = code + pc;
        uint16_t curr_pc = pc++;
        if ((insn->code & BPF_CLASS_ALU) || (insn->code & BPF_CLASS_ALU64)) {
            if (insn->dst_reg > 10) {
                ebpf_set_error_string("Invalid dst register %d at pc %d", (int)insn->dst_reg, (int)curr_pc);
                return -EPERM;
            }
            if ((insn->code & BPF_SOURCE_X) && insn->src_reg > 10) {
                ebpf_set_error_string("Invalid src register %d at pc %d", (int)insn->src_reg, (int)curr_pc);
                return -EPERM;
            }
        }
        if (insn->code & BPF_ALU_ADD || insn->code & BPF_ALU_SUB || insn->code & BPF_ALU_MUL || insn->code & BPF_ALU_OR || insn->code & BPF_ALU_AND ||
            insn->code & BPF_ALU_LSH || insn->code & BPF_ALU_RSH || insn->code & BPF_ALU_NEG || insn->code & BPF_ALU_XOR ||
            insn->code & BPF_ALU_ARSH || insn->code & BPF_ALU_END) {
            if (insn->offset != 0) {
                ebpf_set_error_string("Invalid offset (must be 0) at pc %d", (int)curr_pc);
                return -EPERM;
            }
        }
        if (insn->code & BPF_ALU_DIV_SDIV || insn->code & BPF_ALU_MOD_SMOD) {
            if (insn->offset != 0 && insn->offset != 1) {
                ebpf_set_error_string("Invalid offset (must be 0 or 1) at pc %d", (int)curr_pc);
                return -EPERM;
            }
        }

        if (insn->code & BPF_ALU_MOV_MOVSX) {
            if (insn->offset != 0 && insn->offset != 8 && insn->offset != 16 && insn->offset != 32) {
                ebpf_set_error_string("Invalid offset (must be 0, 8, 16, 32) at pc %d", (int)curr_pc);
                return -EPERM;
            }
        }
        if (insn->code & (BPF_ALU_END | BPF_CLASS_ALU) || insn->code == (BPF_ALU_END | BPF_END_TO_LE | BPF_CLASS_ALU64)) {
            if (insn->imm != 16 && insn->imm != 32 && insn->imm != 64) {
                ebpf_set_error_string("Invalid imm, must be 16, 32, 64 at pc %d", (int)curr_pc);
                return -EPERM;
            }
        }
        
    }

    return 0;
}
