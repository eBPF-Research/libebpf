#ifndef _CLAUSE_HELPERS_H
#define _CLAUSE_HELPERS_H
#define BOUNDS_CHECK_LOAD(size)                                                                                                                      \
    do {                                                                                                                                             \
        if (!ebpf_runtime_bound_check(vm, (char *)(uintptr_t)reg[insn->src_reg] + insn->offset, size, "load", pc - 1, mem, mem_len, stack)) {        \
            return -EINVAL;                                                                                                                          \
        }                                                                                                                                            \
    } while (0)
#define BOUNDS_CHECK_STORE(size)                                                                                                                     \
    do {                                                                                                                                             \
        if (!ebpf_runtime_bound_check(vm, (char *)(uintptr_t)reg[insn->dst_reg] + insn->offset, size, "store", pc - 1, mem, mem_len, stack)) {       \
            return -EINVAL;                                                                                                                          \
        }                                                                                                                                            \
    } while (0)

#define SIMPLE_ALU_OP_DEF(op, c_op)                                                                                                                  \
    case BPF_CLASS_ALU | BPF_SOURCE_K | op:                                                                                                          \
    case BPF_CLASS_ALU | BPF_SOURCE_X | op:                                                                                                          \
    case BPF_CLASS_ALU64 | BPF_SOURCE_K | op:                                                                                                        \
    case BPF_CLASS_ALU64 | BPF_SOURCE_X | op: {                                                                                                      \
        uint64_t src = insn->code_alu.src == 0 ? insn->imm : reg[insn->src_reg];                                                                     \
        uint64_t dst = reg[insn->dst_reg];                                                                                                           \
        if (bit_test_mask(insn->code, BPF_CLASS_MASK, BPF_CLASS_ALU)) {                                                                              \
            reg[insn->dst_reg] = (uint32_t)dst c_op(uint32_t) src;                                                                                   \
        } else {                                                                                                                                     \
            reg[insn->dst_reg] = dst c_op src;                                                                                                       \
        }                                                                                                                                            \
        break;                                                                                                                                       \
    }

#define SIMPLE_JMP_OP_CLAUSE(op, c_op)                                                                                                               \
    case BPF_CLASS_JMP | BPF_SOURCE_K | op:                                                                                                          \
    case BPF_CLASS_JMP | BPF_SOURCE_X | op:                                                                                                          \
    case BPF_CLASS_JMP32 | BPF_SOURCE_K | op:                                                                                                        \
    case BPF_CLASS_JMP32 | BPF_SOURCE_X | op: {                                                                                                      \
        uint64_t src = insn->code_alu.src == 0 ? insn->imm : reg[insn->src_reg];                                                                     \
        uint64_t dst = reg[insn->dst_reg];                                                                                                           \
        if (bit_test_mask(insn->code, BPF_CLASS_MASK, BPF_CLASS_JMP)) {                                                                              \
            if (dst c_op src)                                                                                                                        \
                pc += insn->offset;                                                                                                                  \
        } else {                                                                                                                                     \
            if (((uint32_t)dst)c_op((uint32_t)src))                                                                                                  \
                pc += insn->offset;                                                                                                                  \
        }                                                                                                                                            \
        break;                                                                                                                                       \
    }
#define SIMPLE_JMP_OP_CLAUSE_SIGNED(op, c_op)                                                                                                        \
    case BPF_CLASS_JMP | BPF_SOURCE_K | op:                                                                                                          \
    case BPF_CLASS_JMP | BPF_SOURCE_X | op:                                                                                                          \
    case BPF_CLASS_JMP32 | BPF_SOURCE_K | op:                                                                                                        \
    case BPF_CLASS_JMP32 | BPF_SOURCE_X | op: {                                                                                                      \
        uint64_t src = insn->code_alu.src == 0 ? insn->imm : reg[insn->src_reg];                                                                     \
        uint64_t dst = reg[insn->dst_reg];                                                                                                           \
        if (bit_test_mask(insn->code, BPF_CLASS_MASK, BPF_CLASS_JMP)) {                                                                              \
            if (((int64_t)dst)c_op((int64_t)src))                                                                                                    \
                pc += insn->offset;                                                                                                                  \
        } else {                                                                                                                                     \
            if (((int32_t)dst)c_op((int32_t)src))                                                                                                    \
                pc += insn->offset;                                                                                                                  \
        }                                                                                                                                            \
        break;                                                                                                                                       \
    }

#define SIMPLE_STX_CLAUSE(bpf_size, st_ty, size_num)                                                                                                 \
    case BPF_CLASS_STX | bpf_size | BPF_LS_MODE_MEM: {                                                                                               \
        BOUNDS_CHECK_STORE(size_num);                                                                                                                \
        *(st_ty *)(uintptr_t)(reg[insn->dst_reg] + insn->offset) = reg[insn->src_reg];                                                               \
        break;                                                                                                                                       \
    }

#define SIMPLE_ST_CLAUSE(bpf_size, st_ty, size_num)                                                                                                  \
    case BPF_CLASS_ST | bpf_size | BPF_LS_MODE_MEM: {                                                                                                \
        BOUNDS_CHECK_STORE(size_num);                                                                                                                \
        *(st_ty *)(uintptr_t)(reg[insn->dst_reg] + insn->offset) = insn->imm;                                                                        \
        break;                                                                                                                                       \
    }

#define SIMPLE_LDX_CLAUSE(bpf_size, ld_type, size_num)                                                                                               \
    BOUNDS_CHECK_LOAD(size_num);                                                                                                                     \
    case BPF_CLASS_LDX | bpf_size | BPF_LS_MODE_MEM: {                                                                                               \
        reg[insn->dst_reg] = *(ld_type *)(uintptr_t)(reg[insn->src_reg] + insn->offset);                                                             \
        break;                                                                                                                                       \
    }

#define SIMPLE_LDX_SIGNED_CLAUSE(bpf_size, ld_type, size_num)                                                                                        \
    BOUNDS_CHECK_LOAD(size_num);                                                                                                                     \
    case BPF_CLASS_LDX | bpf_size | BPF_LS_MODE_MEMSX: {                                                                                             \
        reg[insn->dst_reg] = (int64_t) * (ld_type *)(uintptr_t)(reg[insn->src_reg] + insn->offset);                                                  \
        break;                                                                                                                                       \
    }

#endif
