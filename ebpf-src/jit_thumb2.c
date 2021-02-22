#include "jit_thumb2.h"
#include "jit.h"
#include "ebpf_inst.h"
#include <stdint.h>
#include <stdbool.h>
// #include "hotpatch/include/utils.h"

typedef void (*f_void)(void);
typedef uint64_t (*f_ebpf)(void*);
static uint8_t jit_buffer[2048];
static uint8_t offset_mem[2048];

static void first_jit_func();
static void gen_code_for_ebpf1();
/*
http://shell-storm.org/online/Online-Assembler-and-Disassembler
*/

void jit_run_test() {
    // first_jit_func();
    gen_code_for_ebpf1();
}

#ifdef SYS_CORTEX_M4


#endif

static int build_inst(jit_state *state, ebpf_inst *inst, int pc);

/*
ARM Thumb2 instruction
*/
//


// ebpf Memory Instuctions 
#define ARM_LDR_I  0x6800 // A7-246
#define ARM_LDRB_I 0x7800 // A7-252
static void _emit_ldr_i(jit_state *state, const s8 Rt, const s8 Rn, s16 off);
static void _emit_mov_reg(jit_state *state, s8 src, s8 dst);
static void emit_a32_mov_reg(jit_state *state, s8 src, s8 dst);
static void _emit_str_i(jit_state *state, const s8 Rt, const s8 Rn, s16 off);
static void _emit_strd_i(jit_state *state, const s8 Rt[], const s8 Rn, s16 off);
static void _emit_ldrd_i(jit_state *state, const s8 Rt[], const s8 Rn, s16 off);
static inline void emit_mov_imm(jit_state *state, const u8 rd, u32 val);
/*
ARM register
*/
enum {
  ARM_R0 =	0,
  ARM_R1 =	1,
  ARM_R2 =	2,
  ARM_R3 =	3,
  ARM_R4 =	4,
  ARM_R5 =	5,
  ARM_R6 =	6,
  ARM_R7 =	7,
  ARM_R8 =	8,
  ARM_R9 =	9,
  ARM_R10 =	10,
  ARM_FP =	11,	/* Frame Pointer */
  ARM_IP =	12,	/* Intra-procedure scratch register */
  ARM_SP =	13,	/* Stack pointer: as load/store base reg */
  ARM_LR =	14,	/* Link Register */
  ARM_PC =	15,	/* Program counter */
};

enum {
	/* Stack layout - these are offsets from (top of stack - 4) */
	BPF_R2_HI = 0,
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

#define STACK_OFFSET(k)	(-4 - (k) * 4)
#define SCRATCH_SIZE	(BPF_JIT_SCRATCH_REGS * 4)

#define TMP_REG_1	(MAX_BPF_JIT_REG + 0)	/* TEMP Register 1 */
#define TMP_REG_2	(MAX_BPF_JIT_REG + 1)	/* TEMP Register 2 */
#define TCALL_CNT	(MAX_BPF_JIT_REG + 2)	/* Tail Call Count */

// push {r4 - r9, r11}
#ifdef CONFIG_FRAME_POINTER
#define EBPF_SCRATCH_TO_ARM_FP(x) ((x) - 4 * 7 - 4)
#else
#define EBPF_SCRATCH_TO_ARM_FP(x) (x)
#endif

/*
 * Map eBPF registers to ARM 32bit registers or stack scratch space.
 * 
 *
 */
static const int8_t bpf2a32[][2] = {
	/* return value from in-kernel function, and exit value from eBPF */
	[BPF_REG_0] = {ARM_R1, ARM_R0},
	/* arguments from eBPF program to in-kernel function */
	[BPF_REG_1] = {ARM_R3, ARM_R2},
	/* Stored on stack scratch space */
	[BPF_REG_2] = {STACK_OFFSET(BPF_R2_HI), STACK_OFFSET(BPF_R2_LO)},
	[BPF_REG_3] = {STACK_OFFSET(BPF_R3_HI), STACK_OFFSET(BPF_R3_LO)},
	[BPF_REG_4] = {STACK_OFFSET(BPF_R4_HI), STACK_OFFSET(BPF_R4_LO)},
	[BPF_REG_5] = {STACK_OFFSET(BPF_R5_HI), STACK_OFFSET(BPF_R5_LO)},
	/* callee saved registers that in-kernel function will preserve */
	[BPF_REG_6] = {ARM_R5, ARM_R4},
	/* Stored on stack scratch space */
	[BPF_REG_7] = {STACK_OFFSET(BPF_R7_HI), STACK_OFFSET(BPF_R7_LO)},
	[BPF_REG_8] = {STACK_OFFSET(BPF_R8_HI), STACK_OFFSET(BPF_R8_LO)},
	[BPF_REG_9] = {STACK_OFFSET(BPF_R9_HI), STACK_OFFSET(BPF_R9_LO)},
	/* Read only Frame Pointer to access Stack */
	[BPF_REG_FP] = {STACK_OFFSET(BPF_FP_HI), STACK_OFFSET(BPF_FP_LO)},
	/* Temporary Register for internal BPF JIT, can be used
	 * for constant blindings and others.
	 */
	[TMP_REG_1] = {ARM_R7, ARM_R6},
	[TMP_REG_2] = {ARM_R9, ARM_R8},
	/* Tail call count. Stored on stack scratch space. */
	[TCALL_CNT] = {STACK_OFFSET(BPF_TC_HI), STACK_OFFSET(BPF_TC_LO)},
	/* temporary register for blinding constants.
	 * Stored on stack scratch space.
	 */
	[BPF_REG_AX] = {STACK_OFFSET(BPF_AX_HI), STACK_OFFSET(BPF_AX_LO)},
};

#define	dst_lo	dst[1]
#define dst_hi	dst[0]
#define src_lo	src[1]
#define src_hi	src[0]

// enum {
//     imm_overflow = 0,
//     imm5 = 5,
//     imm8 = 8,
//     imm12 = 12,
// };

/* Is the translated BPF register on stack? */
static bool is_stacked(int8_t reg) {
	return reg < 0;
}

/* If a BPF register is on the stack (stk is true), load it to the
 * supplied temporary register and return the temporary register
 * for subsequent operations, otherwise just use the CPU register.
 */
static int8_t arm_bpf_get_reg32(jit_state *state, s8 reg, s8 tmp) {
	if (is_stacked(reg)) {
		//emit(ARM_LDR_I(tmp, ARM_FP, EBPF_SCRATCH_TO_ARM_FP(reg)), ctx);
        // rt rn off
        s16 off = EBPF_SCRATCH_TO_ARM_FP(reg);
        _emit_ldr_i(state, tmp, ARM_FP, off);
        // u16 inst = ARM_LDR_I | (off << 6) | (ARM_FP) | (tmp);
        // emit2(state, inst);
		reg = tmp;
	}
	return reg;
}

static void arm_bpf_put_reg32(jit_state *state, s8 reg, s8 src) {
	if (is_stacked(reg)) {
		// emit(ARM_STR_I(src, ARM_FP, EBPF_SCRATCH_TO_ARM_FP(reg)), ctx);
        s16 off = EBPF_SCRATCH_TO_ARM_FP(reg);
        _emit_str_i(state, ARM_FP, src, off);
	} else if (reg != src) {
        _emit_mov_reg(state, src, reg);
    }
}

static const s8 *arm_bpf_get_reg64(jit_state *state, const s8 *reg, const s8 *tmp) {
    if (is_stacked(reg[1])) {
         s16 off = EBPF_SCRATCH_TO_ARM_FP(reg[1]);
        _emit_ldrd_i(state, tmp, ARM_FP, off);
        reg = tmp;
    }
    return reg;
}

static void arm_bpf_put_reg64(jit_state *state, const s8 *reg, const s8 *src) {
	if (is_stacked(reg[1])) {
        s16 off = EBPF_SCRATCH_TO_ARM_FP(reg[1]);
        _emit_strd_i(state, src, ARM_FP, off);
	} else {
		if (reg[1] != src[1]) {
            emit_a32_mov_reg(state, src[1], reg[1]);
        }
            
        if (reg[0] != src[0]) {
            emit_a32_mov_reg(state, src[0], reg[0]);
        }
    }
}

static bool is_ldst_imm(s16 off, const u8 size) {
	s16 off_max = 0;
    // 0b11111
    // imm5 or imm12
	switch (size) {
    // 12
	case EBPF_SIZE_B:
	case EBPF_SIZE_W:
		off_max = 0xfff;
		break;
	case EBPF_SIZE_H:
		off_max = 0xff;
		break;
	case EBPF_SIZE_DW:
		/* Need to make sure off+4 does not overflow. */
		off_max = 0xfff - 4;
		break;
	}
	return -off_max <= off && off <= off_max;
}

/*
Thumb2 decode
*/
void jit_dump_inst(jit_state *state) {
    DEBUG_LOG("\nDecode:\n");
    for (int i = 0; i < state->idx; i++) {
        DEBUG_LOG("%02x", state->jit_code[i]);
    }
    DEBUG_LOG("\n");
}

/*
Thumb2 encode
*/

/*
  LDXW -> LDR
  A7-246
  verified _emit_ldr_i(state, 0, 1, 0xffe);
  Rn - Src
  Rt - Dst
*/
static void _emit_ldr_i(jit_state *state, const s8 Rt, const s8 Rn, s16 off) {
    // s16 imm5 = 0b11111, imm8 = 0xff, imm12 = 0xfff;
    // if (off <= imm5 && off >= 0 && Rt < 8 && Rn < 8) {
    //     s16 inst = 0x6800 | ((off & 0b11111) << 6) | (Rn << 3) | (Rt);
    //     my_printf("imm5 _emit_ldr_i: %x Rt=%d Rn=%d\n", inst, Rt, Rn);
    //     // real_off = off * 4
    //     emit2(state, inst);
    // } else if (off <= imm8 && off >= 0 && Rt < 8 && Rn < 8) { // 
    //     s32 inst = 0xf8500000 | (Rn << 16) | (Rt << 12) | (0b1110 << 8) | (off & 0xff);
    //     // my_printf("imm8 _emit_ldr_i: %x\n", inst);
    //     emit4(state, inst);
    // } 
    if (off == 0) { // imm12
        s32 inst = 0xf8d00000 | (Rn << 16) | (Rt << 12) | (off & 0xfff);
        emit4(state, inst);
    } else {
        u8 P = off != 0, U = off > 0, W = 0;
        u8 imm8 = off > 0 ? off : -off;
        s32 inst = 0xf8500000 | (Rn << 16) | (Rt << 12) | (0b1 << 11) | (P << 10) | (U << 9) | (W << 8) | (imm8);
        emit4(state, inst);
    }
}

static void _emit_ldrb_i(jit_state *state, const s8 Rt, const s8 Rn, s16 off) {
    s16 imm5 = 0b11111, imm8 = 0xff, imm12 = 0xfff;
    if (off <= imm5 && off >= -imm5) {
        s16 inst = 0x7800 | (off << 6) | (Rn << 3) | (Rt);
        emit2(state, inst);
    } else if (off <= imm8 && off >= -imm8) {
        s32 inst = 0xf8100000 | (Rn << 16) | (Rt << 12) | (0b1110 << 8) | off;
        emit4(state, inst);
    } else if (off <= imm12 && off >= -imm12) {
        s32 inst = 0xf8900000 | (Rn << 16) | (Rt << 12) | off;
        emit4(state, inst);
    }
}

static void _emit_ldrh_i(jit_state *state, const s8 Rt, const s8 Rn, s16 off) {
    s16 imm5 = 0b11111, imm8 = 0xff, imm12 = 0xfff;
    if (off <= imm5 && off >= -imm5) {
        s16 inst = 0x8800 | ((off & imm5) << 6) | (Rn << 3) | (Rt);
        emit2(state, inst);
    } else if (off <= imm8 && off >= -imm8) {
        s32 inst = 0xf8300000 | (Rn << 16) | (Rt << 12) | (0b1110 << 8) | (off & imm8);
        emit4(state, inst);
    } else if (off <= imm12 && off >= -imm12) {
        s32 inst = 0xf8b00000 | (Rn << 16) | (Rt << 12) | (off & imm12);
        emit4(state, inst);
    }
}

static void _emit_ldrd_i(jit_state *state, const s8 Rt[], const s8 Rn, s16 off) {
    // u8 imm8 = off > 0 ? off : -off;
    // u8 P = off != 0, U = off > 0, W = 0;
    // u8 flag = (P << 4) | (U << 3) | 0b100 | (W << 1) | 0b1;
    // // my_printf("flag: %x\n", flag);
    // // P = 1, U = 1, W = 0
    // s32 inst = 0xe8000000 | (flag << 20) | (Rn << 16) | (Rt[0] << 12) | (Rt[1] << 8) | (imm8);
    // my_printf("_emit_ldrd_i inst: %d %d\n", inst, off);
    if (off < -1020 || off > 1020) {
        ERR_IMM(off);
        return;
    }
    off /= 4;
    emit4(state, _thumb32_LDRD_IMM_T1(Rt, Rn, off, WBACK_NO));
}

#ifdef JIT_TEST_FUNC
static void test_ldr(jit_state *state) {
    _emit_ldr_i(state, 0, 1, 0xe);
    _emit_ldr_i(state, 0, 1, 0xfe);
    _emit_ldr_i(state, 0, 1, 0xffe);
    _emit_ldrb_i(state, 0, 1, 0xe);
    _emit_ldrb_i(state, 0, 1, 0xfe);
    _emit_ldrb_i(state, 0, 1, 0xffe);
    _emit_ldrh_i(state, 0, 1, 0xe);
    _emit_ldrh_i(state, 0, 1, 0xfe);
    _emit_ldrh_i(state, 0, 1, 0xffe);
    s8 rt[2] = {0, 1};
    _emit_ldrd_i(state, rt, 7, 2); // e9d7 0102
}
#endif

/*

*/
static void _emit_str_i(jit_state *state, const s8 RnSrc, const s8 Rt,  s16 off) {
    u8 P = off != 0;
    u8 U = off > 0, W = 0;
    u8 imm8 = off > 0 ? off : -off;
    u8 flag = 0b1000 | (P << 2) | (U << 1) | (W);
    u32 inst = (THUMB2_STR_IMM)  | (RnSrc << 16) | (Rt << 12) | (flag << 8) | (imm8);
    emit4(state, inst);
    // my_printf("_emit_strd_i: %x rn=%d rt=%d flag: %d off: %d\n", inst, RnSrc, Rt, flag, imm8);
}

static void _emit_strd_i(jit_state *state, const s8 RnSrc[], const s8 RtDst,  s16 off) {
    // * 4
    off /= 4;
    emit4(state, _thumb32_STRD_IMM_T1(RnSrc, RtDst, off));
    // my_printf("_emit_strd_i: %x\n", inst);
}

/*
ALU
*/
static void inline _emit_add_reg(jit_state *state, const s8 dst, const s8 src, const bool is64, const bool hi) {
    if (is64) {
        if (hi) { // ADC should not update flag
            uint32_t inst = (0xeb400000) | (src << 16) | (dst << 8) | (dst);
            emit4(state, inst);
        } else { // set flag ADDS
            uint32_t inst = (0xeb100000) | (src << 16) | (dst << 8) | (dst);
            emit4(state, inst);
        }
    } else { // ADD
        uint16_t inst = (0x4400) | (src << 3) | (dst);
        emit2(state, inst);
    }
}

static void _emit_add_imm(jit_state *state, const s8 dst, const s8 src, s32 val) {
    if (val > 0 && val < 255) {
        if (dst == src) {
            emit2(state, _thumb16_ADD_IMM_T2(dst, val));
        }
    }
}

static void _emit_sub_imm(jit_state *state, const s8 dst, const s8 src, s32 val) {
    if (val < 0 || val > 4095) {
        DEBUG_LOG("Invalide imm value. Line:%d Val:%d\n", __LINE__, val);
        return;
    }
    if (dst < 8 && dst >= 0 && src < 8 && src >= 0) {
        if (dst == src && val <= 0xff) {
            emit2(state, _thumb16_SUB_IMM_T2(dst, val));
            return;
        }
        if (val <= 0x7) {
            emit2(state, _thumb16_SUB_IMM_T1(dst, src, val));
            return;
        }
    }

    // subw_imm
    emit4(state, _thumb32_SUBW_IMM_T4(dst, src, val, FLAG_NOS));
}

static void inline _emit_sub_reg(jit_state *state, const s8 dst, const s8 src, const bool is64, const bool hi) {
    if (is64 && !hi) { // subs.w
        uint32_t inst = (0xebb00000) | (src << 16) | (dst << 8) | (dst);
        emit4(state, inst);
    } else if (is64 && hi) { // suc
        uint32_t inst = (0xeb600000) | (src << 16) | (dst << 8) | (dst);
        emit4(state, inst);
    } else { // subs or sub.w
        // uint32_t inst = (0xeba00000) | (src << 16) | (dst << 8) | (dst);
        // emit4(state, inst);
        uint16_t inst = (0x1a00) | (src << 6) | (dst << 3) | (dst);
        emit2(state, inst);
    }
}

static void inline _emit_cmp_reg(jit_state *state, const s8 Rn, const s8 Rm) {
    // DEBUG_LOG("_emit_cmp_reg: Rn=%d Rm=%d %x\n", Rn, Rm, _thumb16_CMP_REG_T2(Rn, Rm));
    if (Rn < 0x8 && Rm < 0x8) {
        emit2(state, _thumb16_CMP_REG_T1(Rn, Rm));
    } else {
        emit2(state, _thumb16_CMP_REG_T2(Rn, Rm));
    }
}

static void inline _emit_b_cond(jit_state *state, s32 off, u8 cond) {
    // DEBUG_LOG("_emit_b_cond off=%d  inst:%x\n", off, _thumb16_B_T1(off, cond));
    if (off > -256 && off < 254) {
        emit2(state, _thumb16_B_T1(off, cond));
    } else if (off > -1048576 && off < 1048574) {
        emit4(state, _thumb32_BW_T3(off, cond));
    }
}

static void inline _emit_b(jit_state *state, s32 off) {
    if (off > -2048 && off < 2046) {
        emit2(state, _thumb16_B_T2(off));
    } else if (off > -16777216 && off < 16777214) {
        emit4(state, _thumb32_BW_T4(off));
    }
}

static void emit_alu32_reg(jit_state *state, const s8 dst, const s8 src, 
            const bool is64, const bool hi, const u8 op) {
    const s8 *tmp = bpf2a32[TMP_REG_1];
    s8 rn, rd;
    rn = arm_bpf_get_reg32(state, src, tmp[1]);
    rd = arm_bpf_get_reg32(state, dst, tmp[0]);
    // emit_alu_r(rd, rn, is64, hi, op, ctx);
    // my_printf("emit_alu32_reg: %d src: %d dst: %d\n", op, rn, rd);
    switch (op)
    {
    case EBPF_ALU_ADD:
        _emit_add_reg(state, rd, rn, is64, hi);
        break;
    case EBPF_ALU_SUB:
        _emit_sub_reg(state, rd, rn, is64, hi);
        break;
    case EBPF_ALU_OR: // ORR
        emit2(state, (THUMB2_ORR_REG) | (rn << 3) | (rd));
        break;
    case EBPF_ALU_AND: // AND
        emit2(state, (0x4000) | (rn << 3) | (rd));
        break;
    case EBPF_ALU_XOR: // EOR
        emit2(state, (0x4040) | (rn << 3) | (rd));
        break;
    case EBPF_ALU_MUL: // MUL
        emit2(state, (0x4340) | (rn << 3) | (rd));
        break;
    case EBPF_ALU_LSH: // LSL
        emit2(state, (0x4080) | (rn << 3) | (rd));
        break;
    case EBPF_ALU_RSH: // LSR
        emit2(state, (0x40c0) | (rn << 3) | (rd));
        break;
    case EBPF_ALU_ARSH:
        emit2(state, (0x4100) | (rn << 3) | (rd));
        break;
    }
	arm_bpf_put_reg32(state, dst, rd);
}

/* ALU operation (64 bit) */
void emit_alu64_reg(jit_state *state, bool is64, const s8 dst[], const s8 src[], const u8 op) {
    const s8 *tmp = bpf2a32[TMP_REG_1];
	const s8 *tmp2 = bpf2a32[TMP_REG_2];
	const s8 *rd = arm_bpf_get_reg64(state, dst, tmp);
    // my_printf("emit_alu64_reg: %d\n", op);
    if (is64) {
        // emit_alu32_reg();
        const s8 *rs = arm_bpf_get_reg64(state, src, tmp2);
        /* ALU operation */
        emit_alu32_reg(state, rd[1], rs[1], true, false, op);
        emit_alu32_reg(state, rd[0], rs[0], true, true, op);
    } else {
        s8 rs = arm_bpf_get_reg32(state, src_lo, tmp2[1]);
        emit_alu32_reg(state, rd[1], rs, true, false, op);
    }
    arm_bpf_put_reg64(state, dst, rd);
}

static void emit_alu32_imm(jit_state *state, const s8 dst, const u16 val, const u8 op) {
    const s8 *tmp = bpf2a32[TMP_REG_1];
    s8 rd = arm_bpf_get_reg32(state, dst, tmp[0]);

    /* Do shift operation */
    switch (op) {
    case EBPF_ALU_LSH:
        emit2(state, (0x0000) | (val << 6) | (rd << 3) | (rd));
        break;
    case EBPF_ALU_RSH:
        emit2(state, (0x0800) | (val << 6) | (rd << 3) | (rd));
        break;
    case EBPF_ALU_ARSH:
        emit2(state, (0x1000) | (val << 6) | (rd << 3) | (rd));
        break;
    case EBPF_ALU_NEG: // RSG
        emit2(state, (0x4240) | (rd << 3) | (rd));
        break;
    }

    arm_bpf_put_reg32(state, dst, rd);
}

static void emit_u32_div_mod(jit_state *state, const s8 dst[], const s8 src[], const u16 code, const u16 imm) {
    const s8 *tmp = bpf2a32[TMP_REG_1];
    const s8 *tmp2 = bpf2a32[TMP_REG_2];
    s8 rd_lo, rt;
    rd_lo = arm_bpf_get_reg32(state, dst_lo, tmp2[1]);
    switch (BPF_SRC(code)) {
    case EBPF_SRC_REG:
        rt = arm_bpf_get_reg32(state, src_lo, tmp2[0]);
        break;
    case EBPF_SRC_IMM:
        rt = tmp2[0];
        emit_mov_imm(state, rt, imm);
        break;
    default:
        rt = src_lo;
        break;
    }
    // emit_udivmod(rd_lo, rd_lo, rt, ctx, BPF_OP(code));
    if (BPF_OP(code) == EBPF_ALU_DIV) {
        u32 inst = (0xfbb0f0f0) | (rd_lo << 16) | (rd_lo << 8) | (rt);
        emit4(state, inst);
    } else { // MOD
        u32 inst = (0xfbb0f0f0) | (rd_lo << 16) | (ARM_IP << 8) | (rt);
        emit4(state, inst);
        inst = (0xfb000010) | (rd_lo << 16) | (ARM_IP << 12) | (rd_lo << 8) | (rt);
        emit4(state, inst);
    }

    arm_bpf_put_reg32(state, dst_lo, rd_lo);
}

// dst: rd rt 
// src: rm rn
static void _emit_cmp_cond(jit_state *state, s8 rd, s8 rt, s8 rm, s8 rn, u8 op, bool is_jmp64) {
    switch (op)
    {
    case EBPF_JSET:
        if (is_jmp64) {
            // emit(ARM_AND_R(ARM_IP, rt, rn), ctx);
            emit4(state, _thumb32_ADDW_REG_T3(ARM_IP, rt, rn, 0, SRTYPE_LSL, FLAG_NOS));
            // emit(ARM_AND_R(ARM_LR, rd, rm), ctx);
            emit4(state, _thumb32_ADDW_REG_T3(ARM_LR, rd, rm, 0, SRTYPE_LSL, FLAG_NOS));
            // emit(ARM_ORRS_R(ARM_IP, ARM_LR, ARM_IP), ctx);
            emit4(state, _thumb32_ORRW_REG_T2(ARM_IP, ARM_LR, ARM_IP, 0, SRTYPE_LSL, FLAG_S));
        } else {
            emit4(state, _thumb32_ADDW_REG_T3(ARM_IP, rt, rn, 0, SRTYPE_LSL, FLAG_S));
        }
        break;
    
    case EBPF_JEQ: // ==
    case EBPF_JNE: // != 
    case EBPF_JGT: // >
    case EBPF_JGE: // >=
    case EBPF_JLE: // <=
    case EBPF_JLT: // <
        if (is_jmp64) {
			// emit(ARM_CMP_R(rd, rm), ctx);
            _emit_cmp_reg(state, rd, rm);
            // DEBUG_LOG("_emit_cmp_reg: %d %d\n", rd, rm);
			/* Only compare low halve if high halve are equal. */
			// _emit(ARM_COND_EQ, ARM_CMP_R(rt, rn), ctx);
             _emit_cmp_reg(state, rt, rn);
		} else {
			// emit(ARM_CMP_R(rt, rn), ctx);
             _emit_cmp_reg(state, rt, rn);
        }
        break;

    // b - a, COND_LT
    case EBPF_JSLE: // <= a:(rd, rt) b:(rm, rn)
    case EBPF_JSGT: // >
        // DEBUG_LOG("EBPF_JSLEEBPF_JSLE== %d %d\n", rt, rn);
        _emit_cmp_reg(state, rn, rt); // low cmp: rn - rt
        if (is_jmp64) { // subtract with carray b - a, rm - rd
            emit4(state, _thumb32_SBCW_T2(ARM_IP, rm, rd, 0, SRTYPE_LSL, FLAG_S));
        }
        break;

    // a - b, COND_GE
    case EBPF_JSLT: // <
    case EBPF_JSGE: // >=, N == V (N=negative, V=overflow)
        // DEBUG_LOG("EBPF_JSLT== %d %d\n", rt, rn);
        _emit_cmp_reg(state, rt, rn);
        if (is_jmp64) {
            emit4(state, _thumb32_SBCW_T2(ARM_IP, rd, rm, 0, SRTYPE_LSL, FLAG_S));
        }
        break;

    default:
        break;
    }
}

static void _emit_jump(jit_state *state, s32 jmp_off, s8 op) {
    switch (op)
    {
    case EBPF_JNE: // != 
    case EBPF_JSET: // &
        // emit4()
        _emit_b_cond(state, jmp_off, COND_NE);
        break;

    case EBPF_JEQ:
        // DEBUG_LOG("_emit_b_cond: %d %d\n", jmp_off, COND_EQ);
        _emit_b_cond(state, jmp_off, COND_EQ);
        break;

    case EBPF_JGT:
        _emit_b_cond(state, jmp_off, COND_HI);
        break;
    case EBPF_JGE:
		// _emit(ARM_COND_CS, ARM_B(jmp_offset), ctx);
        _emit_b_cond(state, jmp_off, COND_CS);
        break;
    case EBPF_JSGT:
        // _emit(ARM_COND_LT, ARM_B(jmp_offset), ctx);
        _emit_b_cond(state, jmp_off, COND_LT);
        break;
    case EBPF_JSGE:
        // _emit(ARM_COND_GE, ARM_B(jmp_offset), ctx);
        _emit_b_cond(state, jmp_off, COND_GE);
        break;
    case EBPF_JLE:
        // _emit(ARM_COND_LS, ARM_B(jmp_offset), ctx);
        _emit_b_cond(state, jmp_off, COND_LS);
        break;
    case EBPF_JLT:
        // _emit(ARM_COND_CC, ARM_B(jmp_offset), ctx);
        _emit_b_cond(state, jmp_off, COND_CC);
        break;
    case EBPF_JSLT:
        // _emit(ARM_COND_LT, ARM_B(jmp_offset), ctx);
        _emit_b_cond(state, jmp_off, COND_LT);
        break;
    case EBPF_JSLE:
        // _emit(ARM_COND_GE, ARM_B(jmp_offset), ctx);
        _emit_b_cond(state, jmp_off, COND_GE);
        break;

    default:
        break;
    }
}

void _emit_lsh64_reg(jit_state *state, const s8 dst[], const s8 src[]) {
    const s8 *tmp = bpf2a32[TMP_REG_1];
    const s8 *tmp2 = bpf2a32[TMP_REG_2];
    const s8 *rd;
    s8 rt;
   
    /* Setup Operands */
    rt = arm_bpf_get_reg32(state, src_lo, tmp2[1]);
    // DEBUG_LOG("arm_bpf_get_reg32 src: %d tmp: %d\n", src_lo, tmp2[1]);
    rd = arm_bpf_get_reg64(state, dst, tmp);
    // DEBUG_LOG("emit_alu64_reg dst=%d rd=%d\n", dst[0], rd[0]);
    // return;
    /*
    emit(ARM_RSB_I(ARM_IP, rt, 32), ctx);
	emit(ARM_SUBS_I(tmp2[0], rt, 32), ctx);
	emit(ARM_MOV_SR(ARM_LR, rd[1], SRTYPE_LSR, rt), ctx);
	emit(ARM_ORR_SR(ARM_LR, ARM_LR, rd[0], SRTYPE_ASL, ARM_IP), ctx);
	emit(ARM_ORR_SR(ARM_LR, ARM_LR, rd[0], SRTYPE_LSR, tmp2[0]), ctx);
	emit(ARM_MOV_SR(ARM_IP, rd[0], SRTYPE_LSR, rt), ctx);
    ARM_IP = rt - 32
    ARM_LR = rd[0] << rt
    ARM_LR = ARM_LR or (rd[1] >> ARM_IP)
    tmp2[0] = 32 - rt
    ARM_IP = ARM_LR or (rd[1] << tmp2[0])
    ARM_LR = rd[1] << rt
    -----> we can only use two extra register
    ARM_IP = rt - 32
    tmp2[0] = rd[0] << rt
    ARM_IP = tmp2[0] or (rd[1] >> ARM_IP)

    tmp2[0] = 32 - rt
    ARM_IP = ARM_IP or (rd[1] << tmp2[0])
    tmp2[0] = rd[1] << rt
    */

    /* Do LSH operation */
    // sub.w ARM_IP = rt - 32
    u8 i = (32 >> 11) & 0b1;
    u16 imm3 = (32 >> 8) & 0b111;
    u16 imm8 = 32 & 0xff;
    u32 inst = (0xf1a00000) | (i << 26) | (rt << 16) | (imm3 << 12) | (ARM_IP << 8) | imm8;
    emit4(state, inst);

    // tmp2[0] = rd[0] << rt, LSL
    inst = (THUMB2_LSLW_REG) | (rd[0] << 16) | (tmp2[0] << 8) | (rt);
    emit4(state, inst);
    // my_printf("THUMB2_LSLSW_REG: %x %d %d %d\n", inst, rd[0], tmp2[0], rt);
    
    // ARM_ORR_SR -> two inst
    // ARM_IP = tmp2[0] or (rd[1] << (rt - 32)) shift <= 0 ommit
    // 1. ARM_IP = rd[1] << ARM_IP 2. tmp2[0] = tmp2[0] or ARM_IP
    inst = (THUMB2_LSLW_REG) | (rd[1] << 16) | (ARM_IP << 8) | (ARM_IP);
    emit4(state, inst);
    inst = (THUMB2_ORRW_REG) | (tmp2[0] << 16) | (ARM_IP << 8) | (ARM_IP); 
    emit4(state, inst);
    // return;
    
    // tmp2[0] = 32 - rt
    inst = (0xf1c00000) | (i << 26) | (rt << 16) | (imm3 << 12) | (tmp2[0] << 8) | imm8;
    emit4(state, inst);
   
    // ARM_IP = ARM_IP or (rd[1] >> (32 - rt))  shift <= 0 ommit
    // 1. tmp2[0] = rd[1] >> tmp2[0] 2. ARM_IP = tmp2[0] or ARM_IP
    inst = (THUMB2_LSLW_REG) | (rd[1] << 16) | (tmp2[0] << 8) | (tmp2[0]);
    emit4(state, inst);
    inst = (THUMB2_ORRW_REG) | (tmp2[0] << 16) | (ARM_IP << 8) | (ARM_IP); 
    emit4(state, inst);

    // tmp2[0] = rd[1] << rt
    inst = (THUMB2_LSLW_REG) | (rd[1] << 16) | (tmp2[0] << 8) | (rt);
    emit4(state, inst);

	arm_bpf_put_reg32(state, dst_lo, tmp2[0]);
	arm_bpf_put_reg32(state, dst_hi, ARM_IP);
}

void _emit_lsh64_imm(jit_state *state, const s8 dst[], const u16 val) {
    const s8 *tmp = bpf2a32[TMP_REG_1];
	const s8 *tmp2 = bpf2a32[TMP_REG_2];
	const s8 *rd;

    // DEBUG_LOG("_emit_lsh64_imm: imm=%d %d\n", val, tmp2[0]);

	/* Setup operands */
	rd = arm_bpf_get_reg64(state, dst, tmp);

	/* Do LSH operation */
    if (val < 32) {
        // emit(ARM_MOV_SI(tmp2[0], rd[0], SRTYPE_ASL, val), ctx);
        // LSLS.W tmp2[0] = rd[0] << val
        u16 imm3 = (val & 0b11100) >> 2;
        u16 imm2 = (val & 0b11);
        u32 inst = (0xea5f0000) | (imm3 << 12) | (tmp2[0] << 8) | (imm2 << 4) | (rd[0]);  
        emit4(state, inst);
        // emit(ARM_ORR_SI(rd[0], tmp2[0], rd[1], SRTYPE_LSR, 32 - val), ctx);
        // ORRS.W rd[0] = tmp2[0] or (rd[1] >> (32 -val))
        imm3 = ((32 - val) & 0b11100) >> 2;
        imm2 = ((32 - val) & 0b11);
        inst = (0xea500010) | (tmp2[0] << 16) | (imm3 << 12) | (rd[0] << 8) | (imm2 << 6) | (rd[1]);
        emit4(state, inst);
        // emit(ARM_MOV_SI(rd[1], rd[1], SRTYPE_ASL, val), ctx);
        // lsls imm 
        emit2(state, (0x0000) | (val << 6) | (rd[1]<< 3) | (rd[1]));
    } else {
        if (val == 32) { // 0
            // emit(ARM_MOV_R(rd[0], rd[1]), ctx); 
            // rd[1] -> rd[0]
            _emit_mov_reg(state, rd[1], rd[0]);

        } else {
            // emit(ARM_MOV_SI(rd[0], rd[1], SRTYPE_ASL, val - 32), ctx);
            // rd[0] = rd[1] << (val - 32)
            emit2(state, (0x0000) | ((val - 32) << 6) | (rd[1] << 3) | (rd[0]));
        }
        // emit(ARM_EOR_R(rd[1], rd[1], rd[1]), ctx);
        // rd[1] = rd[1]^rd[1] = 0
        emit2(state, (0x4040) | (rd[1] << 3) | (rd[1]));
    }
    arm_bpf_put_reg64(state, dst, rd);
}

static inline void emit_a32_rsh_r64(jit_state *state, const s8 dst[], const s8 src[]) {
    const s8 *tmp = bpf2a32[TMP_REG_1];
    const s8 *tmp2 = bpf2a32[TMP_REG_2];
    const s8 *rd;
    s8 rt;

    /* Setup Operands */
    rt = arm_bpf_get_reg32(state, src_lo, tmp2[1]);
    rd = arm_bpf_get_reg64(state, dst, tmp);

    /* Do RSH operation */
    // emit(ARM_RSB_I(ARM_IP, rt, 32), ctx);
    emit4(state, _thumb32_RSBW_IMM_T2(ARM_IP, rt, 32, FLAG_S));
    // emit(ARM_SUBS_I(tmp2[0], rt, 32), ctx);
    emit4(state, _thumb32_SUBW_IMM_T4(tmp2[0], rt, 32, FLAG_S));
    // emit(ARM_MOV_SR(ARM_LR, rd[1], SRTYPE_LSR, rt), ctx);
    emit4(state, _thumb32_LSRW_REG_T2(ARM_LR, rd[1], rt, FLAG_S));
    // emit(ARM_ORR_SR(ARM_LR, ARM_LR, rd[0], SRTYPE_ASL, ARM_IP), ctx);
    emit4(state, _thumb32_LSLW_REG_T2(rd[0], rd[0], ARM_IP, FLAG_S));
    emit4(state, _thumb32_ORRW_REG_T2(ARM_LR, ARM_LR, rd[0], 0, SRTYPE_LSL, FLAG_S));
    // emit(ARM_ORR_SR(ARM_LR, ARM_LR, rd[0], SRTYPE_LSR, tmp2[0]), ctx);
    emit4(state, _thumb32_LSRW_REG_T2(rd[0], rd[0], tmp2[0], FLAG_S));
    emit4(state, _thumb32_ORRW_REG_T2(ARM_LR, ARM_LR, rd[0], 0, SRTYPE_LSL, FLAG_S));
    // emit(ARM_MOV_SR(ARM_IP, rd[0], SRTYPE_LSR, rt), ctx);
    emit4(state, _thumb32_LSRW_REG_T2(ARM_IP, rd[0], rt, FLAG_S));

    arm_bpf_put_reg32(state, dst_lo, ARM_LR);
    arm_bpf_put_reg32(state, dst_hi, ARM_IP);
}

static inline void emit_a32_rsh_i64(jit_state *state, const s8 dst[], const u16 val) {
    const s8 *tmp = bpf2a32[TMP_REG_1];
    const s8 *tmp2 = bpf2a32[TMP_REG_2];
    const s8 *rd;

    /* Setup operands */
    rd = arm_bpf_get_reg64(state, dst, tmp);

    /* Do LSR operation */
    if (val == 0) {
        /* An immediate value of 0 encodes a shift amount of 32
            * for LSR. To shift by 0, don't do anything.
            */
    } else if (val < 32) {
        // emit(ARM_MOV_SI(tmp2[1], rd[1], SRTYPE_LSR, val), ctx);
        emit4(state, _thumb32_LSRW_IMM_T2(tmp2[1], rd[1], val, FLAG_NOS));

        // emit(ARM_ORR_SI(rd[1], tmp2[1], rd[0], SRTYPE_ASL, 32 - val), ctx);
        emit4(state, _thumb32_ORRW_REG_T2(rd[1], tmp2[1], rd[0], 32 - val, SRTYPE_LSL, FLAG_NOS));

        // emit(ARM_MOV_SI(rd[0], rd[0], SRTYPE_LSR, val), ctx);
        emit4(state, _thumb32_LSRW_IMM_T2(rd[0], rd[0], val, FLAG_NOS));
    } else if (val == 32) {
        // emit(ARM_MOV_R(rd[1], rd[0]), ctx);
		// emit(ARM_MOV_I(rd[0], 0), ctx);
        _emit_mov_reg(state, rd[0], rd[1]);
        emit_mov_imm(state, rd[0], 0);
    } else {
        // emit(ARM_MOV_SI(rd[1], rd[0], SRTYPE_LSR, val - 32), ctx);
        emit4(state, _thumb32_LSRW_IMM_T2(rd[1], rd[0], val - 32, FLAG_NOS));

        // emit(ARM_MOV_I(rd[0], 0), ctx);
        emit_mov_imm(state, rd[0], 0);
    }

    // DEBUG_LOG("arm_bpf_put_reg64 r64_imm: %d %d\n", dst_lo, rd[0]);
    arm_bpf_put_reg64(state, dst, rd);
}


static inline void emit_a32_arsh_r64(jit_state *state, const s8 dst[], const s8 src[]) {
    const s8 *tmp = bpf2a32[TMP_REG_1];
    const s8 *tmp2 = bpf2a32[TMP_REG_2];
    const s8 *rd;
    s8 rt;

    /* Setup Operands */
    rt = arm_bpf_get_reg32(state, src_lo, tmp2[1]);
    rd = arm_bpf_get_reg64(state, dst, tmp);

    /* Do the ARSH operation */
    // emit(ARM_RSB_I(ARM_IP, rt, 32), ctx);
    emit4(state, _thumb32_RSBW_IMM_T2(ARM_IP, rt, 32, FLAG_S));
	// emit(ARM_SUBS_I(tmp2[0], rt, 32), ctx);
    emit4(state, _thumb32_SUBW_IMM_T4(tmp2[0], rt, 32, FLAG_S));
	// emit(ARM_MOV_SR(ARM_LR, rd[1], SRTYPE_LSR, rt), ctx);
    emit4(state, _thumb32_LSRW_REG_T2(ARM_LR, rd[1], rt, FLAG_S));

	// emit(ARM_ORR_SR(ARM_LR, ARM_LR, rd[0], SRTYPE_ASL, ARM_IP), ctx);
    emit4(state, _thumb32_LSLW_REG_T2(rd[0], rd[0], tmp2[0], FLAG_NOS));
    emit4(state, _thumb32_ORRW_REG_T2(ARM_LR, ARM_LR, rd[0], 0, SRTYPE_LSL, FLAG_S));

	// _emit(ARM_COND_PL, ARM_ORR_SR(ARM_LR, ARM_LR, rd[0], SRTYPE_ASR, tmp2[0]), ctx);
    emit4(state, _thumb32_ASRW_REG_T2(rd[0], rd[0], tmp2[0], FLAG_NOS));
    emit2(state, _thumb16_IT_T1(COND_PL, IT_MASK_NONE));
    emit4(state, _thumb32_ORRW_REG_T2(ARM_LR, ARM_LR, rd[0], 0, SRTYPE_LSL, FLAG_S));

    // emit(ARM_MOV_SR(ARM_IP, rd[0], SRTYPE_ASR, rt), ctx);
    emit4(state, _thumb32_ASRW_REG_T2(ARM_IP, rd[0], rt, FLAG_S));

    arm_bpf_put_reg32(state, dst_lo, ARM_LR);
    arm_bpf_put_reg32(state, dst_hi, ARM_IP);
}

/* dst = dst >> val (signed) */
static inline void emit_a32_arsh_i64(jit_state *state, const s8 dst[], const u32 val) {
    const s8 *tmp = bpf2a32[TMP_REG_1];
    const s8 *tmp2 = bpf2a32[TMP_REG_2];
    const s8 *rd;

    /* Setup operands */
    rd = arm_bpf_get_reg64(state, dst, tmp);

    /* Do ARSH operation */
    if (val == 0) {
        /* An immediate value of 0 encodes a shift amount of 32
            * for ASR. To shift by 0, don't do anything.
            */
    } else if (val < 32) {
        // emit(ARM_MOV_SI(tmp2[1], rd[1], SRTYPE_LSR, val), ctx);
        emit4(state, _thumb32_LSRW_IMM_T2(tmp2[1], rd[1], val, FLAG_S));
        // emit(ARM_ORR_SI(rd[1], tmp2[1], rd[0], SRTYPE_ASL, 32 - val), ctx);
        emit4(state, _thumb32_ORRW_REG_T2(rd[1], tmp2[1], rd[0], 32 - val, SRTYPE_LSL, FLAG_S));
        // emit(ARM_MOV_SI(rd[0], rd[0], SRTYPE_ASR, val), ctx);
        emit4(state, _thumb32_ASRW_IMM_T2(rd[0], rd[0], val, FLAG_S));
    } else if (val == 32) {
        // emit(ARM_MOV_R(rd[1], rd[0]), ctx);
        _emit_mov_reg(state, rd[0], rd[1]);
        // emit(ARM_MOV_SI(rd[0], rd[0], SRTYPE_ASR, 31), ctx);
        emit4(state, _thumb32_ASRW_IMM_T2(rd[0], rd[0], 31, FLAG_S));
    } else {
        // emit(ARM_MOV_SI(rd[1], rd[0], SRTYPE_ASR, val - 32), ctx);
        emit4(state, _thumb32_ASRW_IMM_T2(rd[1], rd[0], val - 32, FLAG_S));
        // emit(ARM_MOV_SI(rd[0], rd[0], SRTYPE_ASR, 31), ctx);
        emit4(state, _thumb32_ASRW_IMM_T2(rd[0], rd[0], 31, FLAG_S));
    }

    arm_bpf_put_reg64(state, dst, rd);
}

/* dst = ~dst (64 bit) */
static inline void emit_a32_neg64(jit_state *state, const s8 dst[]){
    const s8 *tmp = bpf2a32[TMP_REG_1];
    const s8 *rd;

    /* Setup Operand */
    rd = arm_bpf_get_reg64(state, dst, tmp);

    /* Do Negate Operation */
    // emit(ARM_RSBS_I(rd[1], rd[1], 0), ctx);
    emit4(state, _thumb32_RSBW_IMM_T2(rd[1], rd[1], 0, FLAG_S));

    // emit(ARM_RSC_I(rd[0], rd[0], 0), ctx);
    emit4(state, _thumb32_RSBW_IMM_T2(rd[0], rd[0], 0, FLAG_S));

    arm_bpf_put_reg64(state, dst, rd);
}

static inline void emit_a32_mul_r64(jit_state *state, const s8 dst[], const s8 src[]) {
	const s8 *tmp = bpf2a32[TMP_REG_1];
	const s8 *tmp2 = bpf2a32[TMP_REG_2];
	const s8 *rd, *rt;

	/* Setup operands for multiplication */
	rd = arm_bpf_get_reg64(state, dst, tmp);
	rt = arm_bpf_get_reg64(state, src, tmp2);

	/* Do Multiplication */
	// emit(ARM_MUL(ARM_IP, rd[1], rt[0]), ctx);
    emit4(state, _thumb32_MUL_T2(ARM_IP, rd[1], rt[0]));
	// emit(ARM_MUL(ARM_LR, rd[0], rt[1]), ctx);
    emit4(state, _thumb32_MUL_T2(ARM_LR, rd[0], rt[1]));
	// emit(ARM_ADD_R(ARM_LR, ARM_IP, ARM_LR), ctx);
    emit2(state, _thumb16_ADD_REG_T2(ARM_LR, ARM_IP));

	// emit(ARM_UMULL(ARM_IP, rd[0], rd[1], rt[1]), ctx);
    emit4(state, _thumb32_UMULL_T2(ARM_IP, rd[0], rd[1], rt[1]));

	// emit(ARM_ADD_R(rd[0], ARM_LR, rd[0]), ctx);
     emit2(state, _thumb16_ADD_REG_T2(rd[0], ARM_LR));

	arm_bpf_put_reg32(state, dst_lo, ARM_IP);
	arm_bpf_put_reg32(state, dst_hi, rd[0]);
}

#ifdef JIT_TEST_FUNC
void test_alu(jit_state *state) {
    // _emit_add_reg(state, 0, 1, false, false);
    // _emit_add_reg(state, 0, 1, true, false);
    // _emit_add_reg(state, 0, 1, true, true);
    // _emit_sub_reg(state, 0, 1, false, false);
    // _emit_sub_reg(state, 0, 1, true, false);
    // _emit_sub_reg(state, 0, 1, true, true);
    // // _emit_sub_reg()
    // s8 src = 1, dst = 2, rd = 3;
    // emit2(state, (0x4180) | (src << 3) | (dst));
    // emit2(state, (0x4000) | (src << 3) | (dst));
    // emit2(state, (0x4040) | (src << 3) | (dst));
    // emit2(state, (0x4340) | (src << 3) | (dst));
    // emit2(state, (0x4080) | (src << 3) | (dst));
    // emit2(state, (0x40c0) | (src << 3) | (dst));
    // emit2(state, (0x4100) | (src << 3) | (dst));
    // uint16_t val = 12;
    // emit2(state, (0x0000) | (val << 6) | (rd << 3) | (rd));
    // emit2(state, (0x0800) | (val << 6) | (rd << 3) | (rd));
    // emit2(state, (0x1000) | (val << 6) | (rd << 3) | (rd));
    // emit2(state, (0x4240) | (rd << 3) | (rd));

    // s8 rd_lo = 3, rt = 4;
    // u32 inst = (0xfbb0f0f0) | (rd_lo << 16) | (rd_lo << 8) | (rt);
    // emit4(state, inst);
    // inst = (0xfbb0f0f0) | (rd_lo << 16) | (ARM_IP << 8) | (rt);
    // emit4(state, inst);
    // inst = (0xfb000010) | (rd_lo << 16) | (ARM_IP << 12) | (rd_lo << 8) | (rt);
    // emit4(state, inst);

    s8 dd[] = {1, 3};
    _emit_lsh64_imm(state, dd, 0x20);
}
#endif

/* dst = *(size*)(src + off) */
void emit_ldx_reg(jit_state *state, const s8 dst[], const s8 src, s16 off, const u8 sz) 
{
    const s8 *tmp = bpf2a32[TMP_REG_1];
    const s8 *rd = is_stacked(dst_lo) ? tmp : dst; //Rt
    s8 rm = src; // Rn

    // 
    if (!is_ldst_imm(off, sz)) {

    } else if (rd[1] == rm) {
        emit_a32_mov_reg(state, rm, tmp[0]);
        rm = tmp[0];
    }
    //const u16 ARM_LDR_I = 0x6800; // 0b011010
    // my_printf("emit_ldx size: %d\n", sz);
    u16 inst = 0;
    switch (sz) {
        case EBPF_SIZE_B:
            _emit_ldrb_i(state, rd[1], rm, off);
            break;
        case EBPF_SIZE_H:
            _emit_ldrh_i(state, rd[1], rm, off);
            break;
        case EBPF_SIZE_W: // A7-246
            _emit_ldr_i(state, rd[1], rm, off);
            // inst = ARM_LDR_I | (off << 6) | (rd[1] << 3) | (rm);
            // my_printf("LDXW %x\n")
            // emit2(state, inst);
            break;
        case EBPF_SIZE_DW:
            // DEBUG_LOG("EBPF_SIZE_DW: %d\n", off);
            _emit_ldrd_i(state, rd, rm, off);
            break;
    }

}

static void emit_str_reg(jit_state *state, const s8 dst, const s8 src[], s16 off, const u8 sz) {

}

static void emit_mov_imm(jit_state *state, const u8 rd, u32 val)
{
    u16 imm8 = 0xff, imm13 = 0xff, imm16 = 0xffff;
	//int imm12 = imm8m(val);

    // DEBUG_LOG("emit_mov_imm now: dst=%d imm:%x\n", rd, val);
	if (val <= imm8 && val >= 0 && rd < 8) {
        // movs
        uint16_t inst = 0x2000 | (rd << 8) | (val);
        emit2(state, inst);
    } else {
        // movw 0xfffff82f
        uint16_t v1 = val & 0xffff;
        uint16_t i4 = (v1 & 0xf000) >> 12;
        uint16_t i = (v1 & 0x0800) >> 11;
        uint16_t i3 = (v1 & 0x0700) >> 8;
        uint16_t i8 = v1 & 0x00ff;
        // 40f2 0003
        uint32_t inst = 0xf2400000 | (i << 26) | (i4 << 16) | (i3 << 12) | (rd << 8) | i8;
        emit4(state, inst);
        if (val > 0xffff) { // movt
            v1 = val >> 16;
            i4 = (v1 & 0xf000) >> 12;
            i = (v1 & 0x0800) >> 11;
            i3 = (v1 & 0x0700) >> 8;
            i8 = v1 & 0x00ff;
            inst = 0xf2c00000 | (i << 26) | (i4 << 16) | (i3 << 12) | (rd << 8) | i8;
            // inst = 
            emit4(state, inst);
        }
    }
	// 	emit(ARM_MOV_I(rd, imm12), ctx);
	// else
	// 	emit_mov_i_no8m(rd, val, ctx);
}

static void _emit_mov_reg(jit_state *state, s8 src, s8 dst) {
    /*
    mov r0-r7
    mov.w can use for pc, sp
    */
    // 0x46
    // 01000110 0000 000 A7.7.77
    // MOV      Rm   Rd
   // uint16_t inst =  0x4600 | (src << 3) | (dst);
    // my_printf("emit_mov_reg: 0x%x\n", inst);
    if (dst != ARM_SP && src != ARM_SP) {
        emit2(state, _thumb16_MOV_REG_T1(dst, src));
        return;
    }
   
    emit4(state, _thumb32_MOVW_REG_T3(dst, src, FLAG_NOS));
}

static void emit_a32_mov_reg(jit_state *state, s8 src, s8 dst) {
    const s8 *tmp = bpf2a32[TMP_REG_1];
	s8 rt = arm_bpf_get_reg32(state, src, tmp[0]);
	arm_bpf_put_reg32(state, dst, rt);
    // my_printf("emit_mov_reg src:%d dst:%d\n", src, dst);
}

static void emit_mov_reg64(jit_state *state, const bool is64, const s8 dst[], const s8 src[]) {
    if (!is64) {
        emit_a32_mov_reg(state, src_lo, dst_lo);
    } else if (is_stacked(src_lo) && is_stacked(dst_lo)) {
        const u8 *tmp = bpf2a32[TMP_REG_1];
        // emit(ARM_LDRD_I(tmp[1], ARM_FP, EBPF_SCRATCH_TO_ARM_FP(src_lo)), ctx);
        _emit_ldrd_i(state, tmp, ARM_FP, EBPF_SCRATCH_TO_ARM_FP(src_lo));
        // emit(ARM_STRD_I(tmp[1], ARM_FP, EBPF_SCRATCH_TO_ARM_FP(dst_lo)), ctx);
        _emit_strd_i(state, tmp, ARM_FP, EBPF_SCRATCH_TO_ARM_FP(dst_lo));
    } else if (is_stacked(src_lo)) {
        // emit(ARM_LDRD_I(dst[1], ARM_FP, EBPF_SCRATCH_TO_ARM_FP(src_lo)), ctx);
        _emit_ldrd_i(state, dst, ARM_FP, EBPF_SCRATCH_TO_ARM_FP(src_lo));
    }  else if (is_stacked(dst_lo)) {
        // emit(ARM_STRD_I(src[1], ARM_FP, EBPF_SCRATCH_TO_ARM_FP(dst_lo)), ctx);
        // DEBUG_LOG("dst_lo: %x\n", dst_lo);
        _emit_strd_i(state, src, ARM_FP, EBPF_SCRATCH_TO_ARM_FP(dst_lo));
    } else {
        // my_printf("emit_mov_reg64: %d %d\n", dst[0], src[0]);
        _emit_mov_reg(state, src[1], dst[1]);
        _emit_mov_reg(state, src[0], dst[0]);
    }
}

static void emit_push_r64(jit_state *state, s8 reg) {
    if (reg == ARM_LR || reg < 8 && reg >= 0) {
        emit2(state, _thumb16_PUSH_T1(reg));
    } else {
        emit4(state, reg);
    }
}

static void emit_mov_i64(jit_state *state, const s8 dst[], u64 val)
{
    const s8 *tmp = bpf2a32[TMP_REG_1];
    const s8 *rd = is_stacked(dst_lo) ? tmp : dst;
   
    emit_mov_imm(state, rd[1], (u32)val);
    emit_mov_imm(state, rd[0], val >> 32);
    // DEBUG_LOG("emit_mov_i64: %d %d %d %d \n", dst_lo, dst_hi, rd[0], rd[1]);
    arm_bpf_put_reg64(state, dst, rd);
}

static void emit_mov_se_imm64(jit_state *state, const bool is64, const s8 dst[], const u32 val) {
    if (is64) {
        u64 val64 = val;
        if (is64 && (val & (1<<31))) // < 0
            val64 |= 0xffffffff00000000ULL;
        emit_mov_i64(state, dst, val64);
        //my_printf("emit_mov_se_imm64asd\n");
    } else {
        emit_mov_imm(state, dst[1], val);
    }
}

static void test_mov(jit_state *state) {
    s8 dst[] = {0, 3};
    emit_mov_se_imm64(state, false, dst, 0x100);
    emit_mov_se_imm64(state, false, dst, 0xfffff82f);
    emit_a32_mov_reg(state, 0, 1);
}


static inline int bpf2a32_offset(jit_state *state, int bpf_to, int bpf_from) {
    int to, from;

    if (!state->needGen) {
        return 0;
    }

    to = state->offsets[bpf_to];
    from = state->offsets[bpf_from];

    // gaps
    return to - from - 1;
}

static void gen_return(jit_state *state) {
    // emit_mov_reg(state, false, )
    _emit_mov_reg(state, ARM_IP, 0);
    _emit_mov_reg(state, ARM_LR, 1);
}

static int build_inst(jit_state *state, ebpf_inst *inst, int pc) {
    const int8_t *dst = bpf2a32[inst->dst];
    const int8_t *src = bpf2a32[inst->src];
    const int8_t *tmp = bpf2a32[TMP_REG_1];
    const int8_t *tmp2 = bpf2a32[TMP_REG_2];
    const s16 off = inst->offset;
    const s32 imm = inst->imm;
    uint32_t target_pc = pc + inst->offset + 1;
    const int8_t *rd, *rs;
    int8_t rd_lo, rt, rm, rn;
    s32 jmp_offset;
    const u8 code = inst->opcode;
    const bool is64 = (BPF_CLASS(code) == EBPF_CLS_ALU64);
    // my_printf("switch code:%x\n", BPF_OP(code));
    // DEBUG_LOG("inst: pc=%d dst=%d src=%d imm=%d\n", pc, inst->dst, inst->src, imm);
    switch (code) {
/* ALU operations */
    
    /* dst = src */ // Done
    case EBPF_OP_MOV_IMM:
    case EBPF_OP_MOV_REG:
    case EBPF_OP_MOV64_IMM:
    case EBPF_OP_MOV64_REG:
        switch (BPF_SRC(code))
        {
        case EBPF_SRC_REG:
            if (imm == 1) {
                /* Special mov32 for zext */
                emit_mov_imm(state, dst_hi, 0);
                break;
            }
            // my_printf("emit_mov_reg64: dst=%d src=%d\n", inst->dst, inst->src);
            emit_mov_reg64(state, is64, dst, src);
            break;
        
        case EBPF_SRC_IMM:
            /* Sign-extend immediate value to destination reg */
            // DEBUG_LOG("emit_mov_se_imm64: dst:%d %d\n", dst_lo, imm);
            emit_mov_se_imm64(state, is64, dst, imm);
            break;
        }
        break;

    // done
    /* dst = dst + src/imm */
    /* dst = dst - src/imm */
    /* dst = dst | src/imm */
    /* dst = dst & src/imm */
    /* dst = dst ^ src/imm */
    /* dst = dst * src/imm */
    /* dst = dst << src */
    /* dst = dst >> src */
    case EBPF_OP_ADD_IMM:
    case EBPF_OP_ADD_REG:
    case EBPF_OP_SUB_IMM:
    case EBPF_OP_SUB_REG:
    case EBPF_OP_OR_IMM:
    case EBPF_OP_OR_REG:
    case EBPF_OP_AND_IMM:
    case EBPF_OP_AND_REG:
    case EBPF_OP_XOR_IMM:
    case EBPF_OP_XOR_REG:
    case EBPF_OP_MUL_IMM:
    case EBPF_OP_MUL_REG:
    case EBPF_OP_LSH_REG:
    case EBPF_OP_RSH_REG:
    case EBPF_OP_ARSH_REG:
    case EBPF_OP_ADD64_IMM:
    case EBPF_OP_ADD64_REG:
    case EBPF_OP_SUB64_IMM:
    case EBPF_OP_SUB64_REG:
    case EBPF_OP_OR64_IMM:
    case EBPF_OP_OR64_REG:
    case EBPF_OP_AND64_IMM:
    case EBPF_OP_AND64_REG:
    case EBPF_OP_XOR64_IMM:
    case EBPF_OP_XOR64_REG:
        // my_printf("alu %d %d\n", i);
        switch (BPF_SRC(code))
        {
        case EBPF_SRC_IMM:
            /* Move immediate value to the temporary register
            * and then do the ALU operation on the temporary
            * register as this will sign-extend the immediate
            * value into temporary reg and then it would be
            * safe to do the operation on it.
            */
            DEBUG_LOG("emit_mov_se_imm64: %x\n", imm);
            emit_mov_se_imm64(state, is64, tmp2, imm);
            emit_alu64_reg(state, is64, dst, tmp2, BPF_OP(code));
            break;
        case EBPF_SRC_REG:
            emit_alu64_reg(state, is64, dst, src, BPF_OP(code));
            break;
        }
        break;
    /* dst = dst / src(imm) */
    /* dst = dst % src(imm) */
    case EBPF_OP_DIV_IMM:
    case EBPF_OP_DIV_REG:
    case EBPF_OP_MOD_IMM:
    case EBPF_OP_MOD_REG:
    // treat as u32
    case EBPF_OP_DIV64_IMM:
    case EBPF_OP_DIV64_REG:
    case EBPF_OP_MOD64_IMM:
    case EBPF_OP_MOD64_REG:
        emit_u32_div_mod(state, dst, src, code, imm);
        break;

    // done
    /* dst = dst << imm */
    /* dst = dst >> imm */
    /* dst = dst >> imm (signed) */
    case EBPF_OP_LSH_IMM:
    case EBPF_OP_RSH_IMM:
    case EBPF_OP_ARSH_IMM:
        if (imm > 31) {
            state->err_line = __LINE__;
            return -1;
        }
        if (imm) {
            emit_alu32_imm(state, dst_lo, imm, BPF_OP(code));
        }
        break;

    case EBPF_OP_LSH64_REG:
        _emit_lsh64_reg(state, dst, src);
        break;
    case EBPF_OP_LSH64_IMM:
        _emit_lsh64_imm(state, dst, imm);
        break;
    case EBPF_OP_RSH64_REG:
        emit_a32_rsh_r64(state, dst, src);
        break;
    case EBPF_OP_RSH64_IMM:
        // DEBUG_LOG("emit_a32_rsh_i64: %d\n", imm);
        emit_a32_rsh_i64(state, dst, imm);
        break;
    case EBPF_OP_ARSH64_REG:
        emit_a32_arsh_r64(state, dst, src);
        break;
    case EBPF_OP_ARSH64_IMM:
        emit_a32_arsh_i64(state, dst, imm);
        break;

    case EBPF_OP_NEG:
        emit_alu32_imm(state, dst_lo, 0, BPF_OP(code));
        break;
    /* dst = ~dst (64 bit) */
    case EBPF_OP_NEG64:
        emit_a32_neg64(state, dst);
        break;
	/* dst = dst * src/imm */
	case EBPF_OP_MUL64_IMM:
	case EBPF_OP_MUL64_REG: {
        switch (BPF_SRC(code)) {
        case EBPF_SRC_IMM:
            emit_mov_se_imm64(state, is64, tmp2, imm);
            emit_a32_mul_r64(state, dst, tmp2);
            break;
        
         case EBPF_SRC_REG:
            emit_a32_mul_r64(state, dst, src);
            break;
        }
        break;
    }
       

    /* dst = htole(dst) */
	/* dst = htobe(dst) */
	case EBPF_OP_LE:
	case EBPF_OP_BE:
        goto todo;
        break;

    /* dst = imm64 */
    case EBPF_OP_LDDW: { // cur-inst.imm + next-inst.imm
        u64 val = (u32)imm | (u64) inst[1].imm << 32;
        emit_mov_i64(state, dst, val);
        return 1;
    }

    /* LDX: dst = *(size *)(src + off) */
    case EBPF_OP_LDXW:
    case EBPF_OP_LDXH:
    case EBPF_OP_LDXB:
    case EBPF_OP_LDXDW:
        rn = arm_bpf_get_reg32(state, src_lo, tmp2[1]);
        // DEBUG_LOG("EBPF_OP_LDXDW %d -> %d dst:%d\n", src_lo, rn, dst_lo);
        emit_ldx_reg(state, dst, rn, inst->offset, BPF_SIZE(code));
        break;
    /* ST: *(size *)(dst + off) = imm */
    case EBPF_OP_STW:
    case EBPF_OP_STH:
    case EBPF_OP_STB:
    case EBPF_OP_STDW: {
        switch (BPF_SIZE(code))
        {
        case EBPF_SIZE_DW:
            /* Sign-extend immediate value into temp reg */
            emit_mov_se_imm64(state, true, tmp2, imm);
            break;
        case EBPF_SIZE_W:
        case EBPF_SIZE_H:
        case EBPF_SIZE_B:
            emit_mov_imm(state, tmp2[1], imm);
            break;
        }
        emit_str_reg(state, dst_lo, tmp2, off, BPF_SIZE(code));
        break;
    }
    /* ST: *(size *)(dst + off) = imm */
    case EBPF_OP_STXW:
    case EBPF_OP_STXH:
    case EBPF_OP_STXB:
    case EBPF_OP_STXDW:
        rs = arm_bpf_get_reg64(state, src, tmp2);
        emit_str_reg(state, dst_lo, rs, off, BPF_SIZE(code));
        break;

    // done
    // jump instructions
    /* PC += off if dst == src */
    /* PC += off if dst > src */
    /* PC += off if dst >= src */
    /* PC += off if dst < src */
    /* PC += off if dst <= src */
    /* PC += off if dst != src */
    /* PC += off if dst > src (signed) */
    /* PC += off if dst >= src (signed) */
    /* PC += off if dst < src (signed) */
    /* PC += off if dst <= src (signed) */
    /* PC += off if dst & src */
    /* PC += off if dst == imm */
    /* PC += off if dst > imm */
    /* PC += off if dst >= imm */
    /* PC += off if dst < imm */
    /* PC += off if dst <= imm */
    /* PC += off if dst != imm */
    /* PC += off if dst > imm (signed) */
    /* PC += off if dst >= imm (signed) */
    /* PC += off if dst < imm (signed) */
    /* PC += off if dst <= imm (signed) */
    /* PC += off if dst & imm */
    case EBPF_OP_JEQ_IMM:
    case EBPF_OP_JEQ_REG:
    case EBPF_OP_JGT_IMM:
    case EBPF_OP_JGT_REG:
    case EBPF_OP_JGE_IMM:
    case EBPF_OP_JGE_REG:
    case EBPF_OP_JSET_IMM:
    case EBPF_OP_JSET_REG:
    case EBPF_OP_JNE_IMM:
    case EBPF_OP_JNE_REG:
    case EBPF_OP_JSGT_IMM:
    case EBPF_OP_JSGT_REG:
    case EBPF_OP_JSGE_IMM:
    case EBPF_OP_JSGE_REG:
    case EBPF_OP_JLT_IMM:
    case EBPF_OP_JLT_REG:
    case EBPF_OP_JLE_IMM:
    case EBPF_OP_JLE_REG:
    case EBPF_OP_JSLT_IMM:
    case EBPF_OP_JSLT_REG:
    case EBPF_OP_JSLE_IMM:
    case EBPF_OP_JSLE_REG: {
        if (BPF_SRC(code) == EBPF_SRC_REG) {
            rm = arm_bpf_get_reg32(state, src_hi, tmp2[0]);
            rn = arm_bpf_get_reg32(state, src_lo, tmp2[1]);
        } else { // IMM
            if (off == 0)
                break;
            rm = tmp2[0];
            rn = tmp2[1];
            /* Sign-extend immediate value */
            // DEBUG_LOG("IMM emit_mov_se_imm64: %d\n", imm);
            emit_mov_se_imm64(state, true, tmp2, imm);
        }
        rd = arm_bpf_get_reg64(state, dst, tmp);
        // CMP
        // DEBUG_LOG("rn=%d rm=%d rd[0]=%d rd[1]=%d\n", rn, rm, rd[0], rd[1]);
        _emit_cmp_cond(state, rd[0], rd[1], rm, rn, BPF_OP(code), BPF_CLASS(code) == EBPF_CLS_JMP);
        jmp_offset = bpf2a32_offset(state, pc + off, pc);
        // DEBUG_LOG("off set addr: %d off:%d jmp:%d\n", pc, off, jmp_offset);
        _emit_jump(state, jmp_offset, BPF_OP(code));
        // gen_return(state);
        // return -1;
        break;
    }
    case EBPF_OP_JA:
        if (off == 0)
            break;
        jmp_offset = bpf2a32_offset(state, pc + off, pc);
        _emit_b(state, jmp_offset);
        break;

    // tail call

    // function call
    case EBPF_OP_CALL: {
        const s8 *r0 = bpf2a32[BPF_REG_0];
        const s8 *r1 = bpf2a32[BPF_REG_1];
        const s8 *r2 = bpf2a32[BPF_REG_2];
        const s8 *r3 = bpf2a32[BPF_REG_3];
        const s8 *r4 = bpf2a32[BPF_REG_4];
        const s8 *r5 = bpf2a32[BPF_REG_5];
        const u32 func = (u32)state->__bpf_call_base + (u32)imm;

        emit_mov_reg64(state, true, r0, r1);
        emit_mov_reg64(state, true, r1, r2);
        emit_push_r64(state, r5);
        emit_push_r64(state, r4);
        emit_push_r64(state, r3);

        // emit_a32_mov_i(tmp[1], func, ctx);
        emit_mov_imm(state, tmp[1], func);
        // emit_blx_r(tmp[1], ctx);
        emit2(state, _thumb16_BLX_REG_T1(tmp[1]));
        // _emit_b(state, )
        
        // emit(ARM_ADD_I(ARM_SP, ARM_SP, imm8m(24)), ctx); // callee clean
        _emit_add_imm(state, ARM_SP, ARM_SP, 24);
        break;
    }
    
    case EBPF_OP_EXIT:
        // emit2(state, 0x4770);
        DEBUG_LOG("EBPF_OP_EXIT: %d\n", pc);
        return JIT_FINISH;

    case 0: // NOP
        break;

    default:
        DEBUG_LOG("Unsupport op: %x pc: %d\n", code, pc);
        // state->err_line = __LINE__;
        // return -1;
        break;
notyet:
        DEBUG_LOG("Do not implement current op: %x pc: %d\n", code, pc);
        state->err_line = __LINE__;
        return -1;

todo:
        DEBUG_LOG("TODO op: %x pc: %d\n", code, pc);
        return -1;
    }
    return 0;
}

/*
 * eBPF prog stack layout:
 *
 *                         high
 * original ARM_SP =>     +-----+
 *                        |     | callee saved registers
 *                        +-----+ <= (BPF_FP + SCRATCH_SIZE)
 *                        | ... | eBPF JIT scratch space
 * eBPF fp register =>    +-----+
 *   (BPF_FP)             | ... | eBPF prog stack
 *                        +-----+
 *                        |RSVD | JIT scratchpad
 * current ARM_SP =>      +-----+ <= (BPF_FP - STACK_SIZE + SCRATCH_SIZE)
 *                        |     |
 *                        | ... | Function call stack
 *                        |     |
 *                        +-----+
 *                          low
 *
 * The callee saved registers depends on whether frame pointers are enabled.
 * With frame pointers (to be compliant with the ABI):
 *
 *                              high
 * original ARM_SP =>     +--------------+ \
 *                        |      pc      | |
 * current ARM_FP =>      +--------------+ } callee saved registers
 *                        |r4-r9,fp,ip,lr| |
 *                        +--------------+ /
 *                              low
 *
 * Without frame pointers:
 *
 *                              high
 * original ARM_SP =>     +--------------+
 *                        |  r4-r9,fp,lr | callee saved registers
 * current ARM_FP =>      +--------------+
 *                              low
 *
 * When popping registers off the stack at the end of a BPF function, we
 * reference them via the current ARM_FP register.
 */
// init eBPF stack and args
static void build_prologue(jit_state *state) {
    const s8 *bpf_r1 = bpf2a32[BPF_REG_1];
	const s8 *bpf_fp = bpf2a32[BPF_REG_FP];
    // 1. set stack SP to r10, USE SP
    // emit(ARM_PUSH(CALLEE_PUSH_MASK), ctx);
    // emit(ARM_MOV_R(ARM_FP, ARM_SP), ctx);
    // push {r4-r9, lr} , r4-r9, lr in used. aligned -> 8 reg
    emit4(state, _thumb32_PUSHW_T2(CALLEE_PUSH_MASK));
    _emit_mov_reg(state, ARM_SP, ARM_FP);
    // stack for registers
    // emit(state, ARM_SUB_I(bpf_r1_lo, ARM_SP, SCRATCH_SIZE));
    emit_mov_imm(state, bpf_r1[0], 0);
    _emit_sub_imm(state, bpf_r1[1], ARM_SP, SCRATCH_SIZE);

    // 2. create stack space
    // emit(state, ARM_SUB_I(ARM_SP, ARM_SP, EBPF_STACK_SIZE));
    _emit_sub_imm(state, ARM_SP, ARM_SP, EBPF_STACK_SIZE);

    
    /* Set up BPF prog stack base register */
	// emit_a32_mov_r64(state, true, bpf_fp, bpf_r1);
    emit_mov_reg64(state, true, bpf_fp, bpf_r1);
    // 3. mov arm_r0 to BPF_R1
    _emit_mov_reg(state, ARM_R0, bpf_r1[1]);
    emit_mov_imm(state, bpf_r1[0], 0);
}

static void build_body(jit_state *state) {
    ebpf_inst *insts = state->insts;
    int inst_num = state->inst_num;
    for (int i = 0; i < inst_num; i++) {
        ebpf_inst inst = insts[i];
        int ret = build_inst(state, &inst, i);
        if (!state->needGen) {
            state->offsets[i] = state->idx;
            // DEBUG_LOG("set offset: i=%d v=%d\n", i, state->idx);
        }
        if (ret == JIT_FINISH) {
            break;
        }
        if (ret > 0) {
            i++;
            continue;
        }
        if (ret < 0) {
            return;
        }
    }
}

/* restore callee saved registers. */
static void build_epilogue(jit_state *state) {
    /* Restore callee saved registers. */
	// emit(ARM_MOV_R(ARM_SP, ARM_FP), ctx);
    _emit_mov_reg(state, ARM_FP, ARM_SP);
	// emit(ARM_POP(CALLEE_POP_MASK), ctx);
    emit4(state, _thumb32_POPW_T2(CALLEE_POP_MASK));
}

static void test_branch(jit_state *state) {
    emit_mov_imm(state, 0, 3);
    emit_mov_imm(state, 1, 0);
    emit4(state, _thumb32_ORRW_REG_T2(0, 0, 1, 0, SRTYPE_LSL, FLAG_S));
    _emit_b_cond(state, 1, COND_NE);
    emit_mov_imm(state, 0, 2);
}

void jit_compile(jit_state *state) {
    // test_ldr(state);
    // test_alu(state);
    // return state;
    // PrePass: clac offset
	state->idx = 0;
    state->needGen = false;
    build_body(state);
    // for (int i = 0; i < state->inst_num; i++) {
    //     DEBUG_LOG("build offset: i=%d %d\n", i, state->offsets[i]);
    // }
    // GenPass: generate jit code
    state->idx = 0;
    state->needGen = true;
    build_prologue(state);

    // test_branch(state);
    build_body(state);

    build_epilogue(state);
    // return state;
}

static void ebpf_ret(uint64_t ret) {
    uint32_t op = ret >> 32;
    uint32_t lr = (uint32_t) (ret & 0x00000000FFFFFFFF);
    // DEBUG_LOG("ebpf_ret: op=%x lr=%x\n", op, lr);
}

uint64_t ebpf_run_jit(jit_state *state, void *ctx) {
#ifdef SYS_CORTEX_M4
    typedef uint64_t (*jit_func)(void *);
    jit_func func = (jit_func) ((uint32_t) state->jit_code | 0x1);
    __asm__("DSB");
    __asm__("ISB");
    uint64_t ret2 = func(ctx);
    ebpf_ret(ret2);
    return ret2;
#endif
    // my_jit_func2(ctx);
    // for (int i = 0; i < 4; i++) {
    //     my_printf("0x%x ", (uint8_t) state->jit_code[i]);
    // }
    // my_printf("\n%s %p\n", state->jit_code, ctx);
}


jit_state g_state;

jit_state* init_jit_state(uint8_t *code, int code_len) {
    jit_state *state = &g_state;
    memset(&g_state, 0, sizeof(g_state));
    memset(offset_mem, 0, sizeof(offset_mem));
    ebpf_inst *insts = (ebpf_inst *) code;
    int inst_num = code_len / sizeof(ebpf_inst);
    // DEBUG_LOG("gen_code_for_ebpf1: %d inst size: %d\n", inst_num, sizeof(ebpf_inst));
    state->insts = insts;
    state->inst_num = inst_num;
    state->idx = 0;
    state->jit_code = (uint8_t *) ((uint32_t) jit_buffer & (~0x3));
    state->size = 2000;
    state->err_line = 0;
    state->offsets = offset_mem;
    return state;
}

void run_jit_func(uint8_t *code, int len, void *ctx) {
    // jit_state *state = init_jit_state();
    // emit_mov_reg(state, ARM_SP, ARM_R0);
    // s8 s2[] = {};
    // _emit_strd_i(state, )
    // emit2(state, 0x4770);
    jit_state *state = init_jit_state(code, len);
    jit_compile(state);
    jit_dump_inst(state);

    ebpf_run_jit(state, ctx);
}

/*
Extra test
zephyr_cve_2020_10028.ebpf pass
zephyr_cve_2020_17445.ebpf failed
zephyr_cve_2020_10062.ebpf pass
zephyr_cve_2020_10024.ebpf failed
zephyr_cve_2020_17443.ebpf pass
zephyr_cve_2018_16524.ebpf pass
zephyr_cve_2018_16603.ebpf pass
zephyr_cve_2020_10021.ebpf pass
zephyr_cve_2020_10063.ebpf pass <---- check
*/
char code_t1[] = ""
"\x61\x12\x08\x00\x00\x00\x00\x00\x61\x11\x04\x00\x00\x00\x00\x00\x07\x01\x00\x00\x05\x00\x00\x00\x67"
"\x01\x00\x00\x20\x00\x00\x00\x77\x01\x00\x00\x20\x00\x00\x00\x69\x11\x00\x00\x00\x00\x00\x00\xbf\x24"
"\x00\x00\x00\x00\x00\x00\x0f\x14\x00\x00\x00\x00\x00\x00\x67\x04\x00\x00\x20\x00\x00\x00\x77\x04\x00"
"\x00\x20\x00\x00\x00\x18\x00\x00\x00\xea\xff\xff\xff\x00\x00\x00\x00\x01\x00\x00\x00\x18\x03\x00\x00"
"\xea\xff\xff\xff\x00\x00\x00\x00\x01\x00\x00\x00\x25\x04\x01\x00\xfe\xff\x00\x00\xb7\x03\x00\x00\x00"
"\x00\x00\x00\x2d\x21\x01\x00\x00\x00\x00\x00\xbf\x30\x00\x00\x00\x00\x00\x00\x95\x00\x00\x00\x00\x00"
"\x00\x00"
"";

uint64_t my_test_func2(uint64_t a1, uint64_t a2) {
    return a1 << a2;
} 

static void gen_code_for_ebpf1() {
    // test_all_inst();
    u32 ctx1 = 1;
    run_jit_func(code_t1, sizeof(code_t1), &ctx1);
}
