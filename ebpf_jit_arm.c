#include "ebpf_jit_arm32.h"
#include "ebpf_vm.h"
#include <string.h>
#include <stdlib.h>
#define STACK_OFFSET(k)	(-4 - (k) * 4)
enum Registers
{
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    SP,
    R14,
    PC,
    RZ = 13
};
// Registers are these in ARM32
enum BPFRegsInstack{
	/* Stack layout - these are offsets from (top of stack - 4) */
	BPF_R2_HI,
	BPF_R2_LO,
	BPF_R3_HI,
	BPF_R3_LO,
	BPF_R4_HI,
	BPF_R4_LO,
	BPF_R5_HI,
	BPF_R5_LO,
	BPF_R7_HI,
	BPF_R7_LO,
	BPF_R8_HI,
	BPF_R8_LO,
	BPF_R9_HI,
	BPF_R9_LO,
	BPF_FP_HI,
	BPF_FP_LO,
	BPF_TC_HI,
	BPF_TC_LO,
	BPF_AX_HI,
	BPF_AX_LO,
	/* Stack space for BPF_REG_2, BPF_REG_3, BPF_REG_4,
	 * BPF_REG_5, BPF_REG_7, BPF_REG_8, BPF_REG_9,
	 * BPF_REG_FP and Tail call counts.
	 */
	BPF_JIT_SCRATCH_REGS,
};

enum BPFRegisters{
	BPF_REG_0 = 0,
	BPF_REG_1,
	BPF_REG_2,
	BPF_REG_3,
	BPF_REG_4,
	BPF_REG_5,
	BPF_REG_6,
	BPF_REG_7,
	BPF_REG_8,
	BPF_REG_9,
	BPF_REG_10,
	__MAX_BPF_REG,
};



#define TMP_REG_1	(__MAX_BPF_REG + 1)	/* TEMP Register 1 */
#define TMP_REG_2	(__MAX_BPF_REG + 2)	/* TEMP Register 2 */
#define TCALL_CNT	(__MAX_BPF_REG + 3)	/* Tail Call Count */



static int8_t register_map[15][2] = {
    [BPF_REG_0]={R1,R0}, // result
    [BPF_REG_1]={R3,R2},
    // Using Base Registers
    [BPF_REG_2] = {STACK_OFFSET(BPF_R2_HI), STACK_OFFSET(BPF_R2_LO)},
	[BPF_REG_3] = {STACK_OFFSET(BPF_R3_HI), STACK_OFFSET(BPF_R3_LO)},
	[BPF_REG_4] = {STACK_OFFSET(BPF_R4_HI), STACK_OFFSET(BPF_R4_LO)},
	[BPF_REG_5] = {STACK_OFFSET(BPF_R5_HI), STACK_OFFSET(BPF_R5_LO)},
	/* callee saved registers that in-kernel function will preserve */
	[BPF_REG_6] = {R5, R4},
	/* Stored on stack scratch space */
	[BPF_REG_7] = {STACK_OFFSET(BPF_R7_HI), STACK_OFFSET(BPF_R7_LO)},
	[BPF_REG_8] = {STACK_OFFSET(BPF_R8_HI), STACK_OFFSET(BPF_R8_LO)},
	[BPF_REG_9] = {STACK_OFFSET(BPF_R9_HI), STACK_OFFSET(BPF_R9_LO)},
    [BPF_REG_10] = {STACK_OFFSET(BPF_FP_HI), STACK_OFFSET(BPF_FP_LO)},
    // EQUAL to BPF_REG_FP
    [TMP_REG_1] = {R7, R6},
	[TMP_REG_2] = {R9, R8},
    // Temp Registers
	/* Tail call count. Stored on stack scratch space. */
	[TCALL_CNT] = {STACK_OFFSET(BPF_TC_HI), STACK_OFFSET(BPF_TC_LO)},
	/* temporary register for blinding constants.
	 * Stored on stack scratch space.
	 */
	[__MAX_BPF_REG] = {STACK_OFFSET(BPF_AX_HI), STACK_OFFSET(BPF_AX_LO)},
};
// To ARM32(4 availble R and 9 in stacks) from EBPF(11 Registers in 64)
static bool is_stacked(int8_t reg)
{
    return reg<0;
}
// TODO: Use is_stacked while using regs 
static void
emit_function_prologue(struct jit_state* state, size_t ebpf_stack_size)
{
    // uint32_t register_space = _countof(callee_saved_registers) * 8 + 2 * 8;
    uint32_t register_space = 8 * 8 + 2 * 8;
    // Warning: Hard-coded 8
    // Callee: BPF_REG_6 to BPF_REG_9
    state->stack_size = (ebpf_stack_size + register_space + 15) & ~15U;
    emit_addsub_immediate(state, true, AS_SUB, SP, SP, state->stack_size);

    /* Set up frame */
    emit_loadstorepair_immediate(state, LSP_STPX, R29, R30, SP, 0);
    emit_addsub_immediate(state, true, AS_ADD, R29, SP, 0);

    /* Save callee saved registers */
    unsigned i;
    for (i = 0; i < _countof(callee_saved_registers); i += 2) {
        emit_loadstorepair_immediate(
            state, LSP_STPX, callee_saved_registers[i], callee_saved_registers[i + 1], SP, (i + 2) * 8);
    }

    /* Setup eBPF frame pointer. */
    emit_addsub_immediate(state, true, AS_ADD, map_register(10), SP, state->stack_size);
}

static int
translate(struct ebpf_vm* vm, struct jit_state* state, char** errmsg)
{
    int i;

    emit_function_prologue(state, EBPF_STACK_SIZE);

    for (i = 0; i < vm->num_insts; i++) {
        struct ebpf_inst inst = ebpf_fetch_instruction(vm, i);
        state->pc_locs[i] = state->offset;

        enum Registers dst = map_register(inst.dst);
        enum Registers src = map_register(inst.src);
        uint8_t opcode = inst.opcode;
        uint32_t target_pc = i + inst.offset + 1;

        int sixty_four = is_alu64_op(&inst);

        if (is_imm_op(&inst) && !is_simple_imm(&inst)) {
            emit_movewide_immediate(state, sixty_four, temp_register, (int64_t)inst.imm);
            src = temp_register;
            opcode = to_reg_op(opcode);
        }

        switch (opcode) {
        case EBPF_OP_ADD_IMM:
        case EBPF_OP_ADD64_IMM:
        case EBPF_OP_SUB_IMM:
        case EBPF_OP_SUB64_IMM:
            emit_addsub_immediate(state, sixty_four, to_addsub_opcode(opcode), dst, dst, inst.imm);
            break;
        case EBPF_OP_ADD_REG:
        case EBPF_OP_ADD64_REG:
        case EBPF_OP_SUB_REG:
        case EBPF_OP_SUB64_REG:
            emit_addsub_register(state, sixty_four, to_addsub_opcode(opcode), dst, dst, src);
            break;
        case EBPF_OP_LSH_REG:
        case EBPF_OP_RSH_REG:
        case EBPF_OP_ARSH_REG:
        case EBPF_OP_LSH64_REG:
        case EBPF_OP_RSH64_REG:
        case EBPF_OP_ARSH64_REG:
            /* TODO: CHECK imm is small enough.  */
            emit_dataprocessing_twosource(state, sixty_four, to_dp2_opcode(opcode), dst, dst, src);
            break;
        case EBPF_OP_MUL_REG:
        case EBPF_OP_MUL64_REG:
            emit_dataprocessing_threesource(state, sixty_four, DP3_MADD, dst, dst, src, RZ);
            break;
        case EBPF_OP_DIV_REG:
        case EBPF_OP_MOD_REG:
        case EBPF_OP_DIV64_REG:
        case EBPF_OP_MOD64_REG:
            divmod(state, opcode, dst, dst, src);
            break;
        case EBPF_OP_OR_REG:
        case EBPF_OP_AND_REG:
        case EBPF_OP_XOR_REG:
        case EBPF_OP_OR64_REG:
        case EBPF_OP_AND64_REG:
        case EBPF_OP_XOR64_REG:
            emit_logical_register(state, sixty_four, to_logical_opcode(opcode), dst, dst, src);
            break;
        case EBPF_OP_NEG:
        case EBPF_OP_NEG64:
            emit_addsub_register(state, sixty_four, AS_SUB, dst, RZ, src);
            break;
        case EBPF_OP_MOV_IMM:
        case EBPF_OP_MOV64_IMM:
            emit_movewide_immediate(state, sixty_four, dst, (int64_t)inst.imm);
            break;
        case EBPF_OP_MOV_REG:
        case EBPF_OP_MOV64_REG:
            emit_logical_register(state, sixty_four, LOG_ORR, dst, RZ, src);
            break;
        case EBPF_OP_LE:
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            /* No-op */
#else
            emit_dataprocessing_onesource(state, sixty_four, to_dp1_opcode(opcode, inst.imm), dst, dst);
#endif
            if (inst.imm == 16) {
                /* UXTH dst, dst. */
                emit_instruction(state, 0x53003c00 | (dst << 5) | dst);
            }
            break;
        case EBPF_OP_BE:
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            emit_dataprocessing_onesource(state, sixty_four, to_dp1_opcode(opcode, inst.imm), dst, dst);
#else
            /* No-op. */
#endif
            if (inst.imm == 16) {
                /* UXTH dst, dst. */
                emit_instruction(state, 0x53003c00 | (dst << 5) | dst);
            }
            break;

        /* TODO use 8 bit immediate when possible */
        case EBPF_OP_JA:
            emit_unconditionalbranch_immediate(state, UBR_B, target_pc);
            break;
        case EBPF_OP_JEQ_IMM:
        case EBPF_OP_JGT_IMM:
        case EBPF_OP_JGE_IMM:
        case EBPF_OP_JLT_IMM:
        case EBPF_OP_JLE_IMM:
        case EBPF_OP_JNE_IMM:
        case EBPF_OP_JSGT_IMM:
        case EBPF_OP_JSGE_IMM:
        case EBPF_OP_JSLT_IMM:
        case EBPF_OP_JSLE_IMM:
        case EBPF_OP_JEQ32_IMM:
        case EBPF_OP_JGT32_IMM:
        case EBPF_OP_JGE32_IMM:
        case EBPF_OP_JLT32_IMM:
        case EBPF_OP_JLE32_IMM:
        case EBPF_OP_JNE32_IMM:
        case EBPF_OP_JSGT32_IMM:
        case EBPF_OP_JSGE32_IMM:
        case EBPF_OP_JSLT32_IMM:
        case EBPF_OP_JSLE32_IMM:
            emit_addsub_immediate(state, sixty_four, AS_SUBS, RZ, dst, inst.imm);
            emit_conditionalbranch_immediate(state, to_condition(opcode), target_pc);
            break;
        case EBPF_OP_JEQ_REG:
        case EBPF_OP_JGT_REG:
        case EBPF_OP_JGE_REG:
        case EBPF_OP_JLT_REG:
        case EBPF_OP_JLE_REG:
        case EBPF_OP_JNE_REG:
        case EBPF_OP_JSGT_REG:
        case EBPF_OP_JSGE_REG:
        case EBPF_OP_JSLT_REG:
        case EBPF_OP_JSLE_REG:
        case EBPF_OP_JEQ32_REG:
        case EBPF_OP_JGT32_REG:
        case EBPF_OP_JGE32_REG:
        case EBPF_OP_JLT32_REG:
        case EBPF_OP_JLE32_REG:
        case EBPF_OP_JNE32_REG:
        case EBPF_OP_JSGT32_REG:
        case EBPF_OP_JSGE32_REG:
        case EBPF_OP_JSLT32_REG:
        case EBPF_OP_JSLE32_REG:
            emit_addsub_register(state, sixty_four, AS_SUBS, RZ, dst, src);
            emit_conditionalbranch_immediate(state, to_condition(opcode), target_pc);
            break;
        case EBPF_OP_JSET_REG:
        case EBPF_OP_JSET32_REG:
            emit_logical_register(state, sixty_four, LOG_ANDS, RZ, dst, src);
            emit_conditionalbranch_immediate(state, to_condition(opcode), target_pc);
            break;
        case EBPF_OP_CALL:
            emit_call(state, (uintptr_t)vm->ext_funcs[inst.imm]);
            if (inst.imm == vm->unwind_stack_extension_index) {
                emit_addsub_immediate(state, true, AS_SUBS, RZ, map_register(0), 0);
                emit_conditionalbranch_immediate(state, COND_EQ, TARGET_PC_EXIT);
            }
            break;
        case EBPF_OP_EXIT:
            if (i != vm->num_insts - 1) {
                emit_unconditionalbranch_immediate(state, UBR_B, TARGET_PC_EXIT);
            }
            break;

        case EBPF_OP_STXW:
        case EBPF_OP_STXH:
        case EBPF_OP_STXB:
        case EBPF_OP_STXDW: {
            enum Registers tmp = dst;
            dst = src;
            src = tmp;
        }
            /* fallthrough: */
        case EBPF_OP_LDXW:
        case EBPF_OP_LDXH:
        case EBPF_OP_LDXB:
        case EBPF_OP_LDXDW:
            if (inst.offset >= -256 && inst.offset < 256) {
                emit_loadstore_immediate(state, to_loadstore_opcode(opcode), dst, src, inst.offset);
            } else {
                emit_movewide_immediate(state, true, offset_register, inst.offset);
                emit_loadstore_register(state, to_loadstore_opcode(opcode), dst, src, offset_register);
            }
            break;

        case EBPF_OP_LDDW: {
            struct ebpf_inst inst2 = ebpf_fetch_instruction(vm, ++i);
            uint64_t imm = (uint32_t)inst.imm | ((uint64_t)inst2.imm << 32);
            emit_movewide_immediate(state, true, dst, imm);
            break;
        }

        case EBPF_OP_MUL_IMM:
        case EBPF_OP_MUL64_IMM:
        case EBPF_OP_DIV_IMM:
        case EBPF_OP_MOD_IMM:
        case EBPF_OP_DIV64_IMM:
        case EBPF_OP_MOD64_IMM:
        case EBPF_OP_STW:
        case EBPF_OP_STH:
        case EBPF_OP_STB:
        case EBPF_OP_STDW:
        case EBPF_OP_JSET_IMM:
        case EBPF_OP_JSET32_IMM:
        case EBPF_OP_OR_IMM:
        case EBPF_OP_AND_IMM:
        case EBPF_OP_XOR_IMM:
        case EBPF_OP_OR64_IMM:
        case EBPF_OP_AND64_IMM:
        case EBPF_OP_XOR64_IMM:
        case EBPF_OP_LSH_IMM:
        case EBPF_OP_RSH_IMM:
        case EBPF_OP_ARSH_IMM:
        case EBPF_OP_LSH64_IMM:
        case EBPF_OP_RSH64_IMM:
        case EBPF_OP_ARSH64_IMM:
            *errmsg = ebpf_error("Unexpected instruction at PC %d: opcode %02x, immediate %08x", i, opcode, inst.imm);
            return -1;
        default:
            *errmsg = ebpf_error("Unknown instruction at PC %d: opcode %02x", i, opcode);
            return -1;
        }
    }

    emit_function_epilogue(state);

    return 0;
}

int ebpf_translate_arm32(struct ebpf_vm *vm, uint8_t *buffer, size_t *size,
			 char **errmsg)
{
	struct jit_state state;
	int result = -1;

	state.offset = 0;
	state.size = *size;
	state.buf = buffer;
	state.pc_locs = calloc(EBPF_MAX_INSTS + 1, sizeof(state.pc_locs[0]));
	state.jumps = calloc(EBPF_MAX_INSTS, sizeof(state.jumps[0]));
	state.num_jumps = 0;

	if (translate(vm, &state, errmsg) < 0) {
		goto out;
	}

	if (state.num_jumps == EBPF_MAX_INSTS) {
		*errmsg = ebpf_error("Excessive number of jump targets");
		goto out;
	}

	if (state.offset == state.size) {
		*errmsg = ebpf_error("Target buffer too small");
		goto out;
	}

	resolve_jumps(&state);
	result = 0;

	*size = state.offset;

out:
	free(state.pc_locs);
	free(state.jumps);
	return result;
}