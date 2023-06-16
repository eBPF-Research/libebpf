// SPDX-License-Identifier: GPL-2.0-only
/*
 * Just-In-Time compiler for eBPF filters on 32bit ARM
 *
 * Copyright (c) 2017 Shubham Bansal <illusionist.neo@gmail.com>
 * Copyright (c) 2011 Mircea Gherzan <mgherzan@gmail.com>
 * 
 * Supports (__LINUX_ARM_ARCH__ >= 6
 *  || ctx->cpu_architecture >= CPU_ARCH_ARMv5TE)
 */
#include "libebpf/libebpf.h"
#include "linux_bpf.h"
#include "linux-errno.h"
#include "ebpf_jit_arm32.h"
#include "ebpf_vm.h"

#include <string.h>
#include <stdlib.h>

/* ARM 32bit Registers */
#define ARM_R0	0
#define ARM_R1	1
#define ARM_R2	2
#define ARM_R3	3
#define ARM_R4	4
#define ARM_R5	5
#define ARM_R6	6
#define ARM_R7	7
#define ARM_R8	8
#define ARM_R9	9
#define ARM_R10	10
#define ARM_FP	11	/* Frame Pointer */
#define ARM_IP	12	/* Intra-procedure scratch register */
#define ARM_SP	13	/* Stack pointer: as load/store base reg */
#define ARM_LR	14	/* Link Register */
#define ARM_PC	15	/* Program counter */

#define ARM_COND_EQ		0x0	/* == */
#define ARM_COND_NE		0x1	/* != */
#define ARM_COND_CS		0x2	/* unsigned >= */
#define ARM_COND_HS		ARM_COND_CS
#define ARM_COND_CC		0x3	/* unsigned < */
#define ARM_COND_LO		ARM_COND_CC
#define ARM_COND_MI		0x4	/* < 0 */
#define ARM_COND_PL		0x5	/* >= 0 */
#define ARM_COND_VS		0x6	/* Signed Overflow */
#define ARM_COND_VC		0x7	/* No Signed Overflow */
#define ARM_COND_HI		0x8	/* unsigned > */
#define ARM_COND_LS		0x9	/* unsigned <= */
#define ARM_COND_GE		0xa	/* Signed >= */
#define ARM_COND_LT		0xb	/* Signed < */
#define ARM_COND_GT		0xc	/* Signed > */
#define ARM_COND_LE		0xd	/* Signed <= */
#define ARM_COND_AL		0xe	/* None */

/* register shift types */
#define SRTYPE_LSL		0
#define SRTYPE_LSR		1
#define SRTYPE_ASR		2
#define SRTYPE_ROR		3
#define SRTYPE_ASL		(SRTYPE_LSL)

#define ARM_INST_ADD_R		0x00800000
#define ARM_INST_ADDS_R		0x00900000
#define ARM_INST_ADC_R		0x00a00000
#define ARM_INST_ADC_I		0x02a00000
#define ARM_INST_ADD_I		0x02800000
#define ARM_INST_ADDS_I		0x02900000

#define ARM_INST_AND_R		0x00000000
#define ARM_INST_ANDS_R		0x00100000
#define ARM_INST_AND_I		0x02000000

#define ARM_INST_BIC_R		0x01c00000
#define ARM_INST_BIC_I		0x03c00000

#define ARM_INST_B		0x0a000000
#define ARM_INST_BX		0x012FFF10
#define ARM_INST_BLX_R		0x012fff30

#define ARM_INST_CMP_R		0x01500000
#define ARM_INST_CMP_I		0x03500000

#define ARM_INST_EOR_R		0x00200000
#define ARM_INST_EOR_I		0x02200000

#define ARM_INST_LDST__U	0x00800000
#define ARM_INST_LDST__IMM12	0x00000fff
#define ARM_INST_LDRB_I		0x05500000
#define ARM_INST_LDRB_R		0x07d00000
#define ARM_INST_LDRD_I		0x014000d0
#define ARM_INST_LDRH_I		0x015000b0
#define ARM_INST_LDRH_R		0x019000b0
#define ARM_INST_LDR_I		0x05100000
#define ARM_INST_LDR_R		0x07900000

#define ARM_INST_LDM		0x08900000
#define ARM_INST_LDM_IA		0x08b00000

#define ARM_INST_LSL_I		0x01a00000
#define ARM_INST_LSL_R		0x01a00010

#define ARM_INST_LSR_I		0x01a00020
#define ARM_INST_LSR_R		0x01a00030

#define ARM_INST_ASR_I		0x01a00040
#define ARM_INST_ASR_R		0x01a00050

#define ARM_INST_MOV_R		0x01a00000
#define ARM_INST_MOVS_R		0x01b00000
#define ARM_INST_MOV_I		0x03a00000
#define ARM_INST_MOVW		0x03000000
#define ARM_INST_MOVT		0x03400000

#define ARM_INST_MUL		0x00000090

#define ARM_INST_POP		0x08bd0000
#define ARM_INST_PUSH		0x092d0000

#define ARM_INST_ORR_R		0x01800000
#define ARM_INST_ORRS_R		0x01900000
#define ARM_INST_ORR_I		0x03800000

#define ARM_INST_REV		0x06bf0f30
#define ARM_INST_REV16		0x06bf0fb0

#define ARM_INST_RSB_I		0x02600000
#define ARM_INST_RSBS_I		0x02700000
#define ARM_INST_RSC_I		0x02e00000

#define ARM_INST_SUB_R		0x00400000
#define ARM_INST_SUBS_R		0x00500000
#define ARM_INST_RSB_R		0x00600000
#define ARM_INST_SUB_I		0x02400000
#define ARM_INST_SUBS_I		0x02500000
#define ARM_INST_SBC_I		0x02c00000
#define ARM_INST_SBC_R		0x00c00000
#define ARM_INST_SBCS_R		0x00d00000

#define ARM_INST_STR_I		0x05000000
#define ARM_INST_STRB_I		0x05400000
#define ARM_INST_STRD_I		0x014000f0
#define ARM_INST_STRH_I		0x014000b0

#define ARM_INST_TST_R		0x01100000
#define ARM_INST_TST_I		0x03100000

#define ARM_INST_UDIV		0x0730f010

#define ARM_INST_UMULL		0x00800090

#define ARM_INST_MLS		0x00600090

#define ARM_INST_UXTH		0x06ff0070

/*
 * Use a suitable undefined instruction to use for ARM/Thumb2 faulting.
 * We need to be careful not to conflict with those used by other modules
 * (BUG, kprobes, etc) and the register_undef_hook() system.
 *
 * The ARM architecture reference manual guarantees that the following
 * instruction space will produce an undefined instruction exception on
 * all CPUs:
 *
 * ARM:   xxxx 0111 1111 xxxx xxxx xxxx 1111 xxxx	ARMv7-AR, section A5.4
 * Thumb: 1101 1110 xxxx xxxx				ARMv7-M, section A5.2.6
 */
#define ARM_INST_UDF		0xe7fddef1

/* register */
#define _AL3_R(op, rd, rn, rm)	((op ## _R) | (rd) << 12 | (rn) << 16 | (rm))
/* immediate */
#define _AL3_I(op, rd, rn, imm)	((op ## _I) | (rd) << 12 | (rn) << 16 | (imm))
/* register with register-shift */
#define _AL3_SR(inst)	(inst | (1 << 4))

#define ARM_ADD_R(rd, rn, rm)	_AL3_R(ARM_INST_ADD, rd, rn, rm)
#define ARM_ADDS_R(rd, rn, rm)	_AL3_R(ARM_INST_ADDS, rd, rn, rm)
#define ARM_ADD_I(rd, rn, imm)	_AL3_I(ARM_INST_ADD, rd, rn, imm)
#define ARM_ADDS_I(rd, rn, imm)	_AL3_I(ARM_INST_ADDS, rd, rn, imm)
#define ARM_ADC_R(rd, rn, rm)	_AL3_R(ARM_INST_ADC, rd, rn, rm)
#define ARM_ADC_I(rd, rn, imm)	_AL3_I(ARM_INST_ADC, rd, rn, imm)

#define ARM_AND_R(rd, rn, rm)	_AL3_R(ARM_INST_AND, rd, rn, rm)
#define ARM_ANDS_R(rd, rn, rm)	_AL3_R(ARM_INST_ANDS, rd, rn, rm)
#define ARM_AND_I(rd, rn, imm)	_AL3_I(ARM_INST_AND, rd, rn, imm)

#define ARM_BIC_R(rd, rn, rm)	_AL3_R(ARM_INST_BIC, rd, rn, rm)
#define ARM_BIC_I(rd, rn, imm)	_AL3_I(ARM_INST_BIC, rd, rn, imm)

#define ARM_B(imm24)		(ARM_INST_B | ((imm24) & 0xffffff))
#define ARM_BX(rm)		(ARM_INST_BX | (rm))
#define ARM_BLX_R(rm)		(ARM_INST_BLX_R | (rm))

#define ARM_CMP_R(rn, rm)	_AL3_R(ARM_INST_CMP, 0, rn, rm)
#define ARM_CMP_I(rn, imm)	_AL3_I(ARM_INST_CMP, 0, rn, imm)

#define ARM_EOR_R(rd, rn, rm)	_AL3_R(ARM_INST_EOR, rd, rn, rm)
#define ARM_EOR_I(rd, rn, imm)	_AL3_I(ARM_INST_EOR, rd, rn, imm)

#define ARM_LDR_R(rt, rn, rm)	(ARM_INST_LDR_R | ARM_INST_LDST__U \
				 | (rt) << 12 | (rn) << 16 \
				 | (rm))
#define ARM_LDR_R_SI(rt, rn, rm, type, imm) \
				(ARM_INST_LDR_R | ARM_INST_LDST__U \
				 | (rt) << 12 | (rn) << 16 \
				 | (imm) << 7 | (type) << 5 | (rm))
#define ARM_LDRB_R(rt, rn, rm)	(ARM_INST_LDRB_R | ARM_INST_LDST__U \
				 | (rt) << 12 | (rn) << 16 \
				 | (rm))
#define ARM_LDRH_R(rt, rn, rm)	(ARM_INST_LDRH_R | ARM_INST_LDST__U \
				 | (rt) << 12 | (rn) << 16 \
				 | (rm))

#define ARM_LDM(rn, regs)	(ARM_INST_LDM | (rn) << 16 | (regs))
#define ARM_LDM_IA(rn, regs)	(ARM_INST_LDM_IA | (rn) << 16 | (regs))

#define ARM_LSL_R(rd, rn, rm)	(_AL3_R(ARM_INST_LSL, rd, 0, rn) | (rm) << 8)
#define ARM_LSL_I(rd, rn, imm)	(_AL3_I(ARM_INST_LSL, rd, 0, rn) | (imm) << 7)

#define ARM_LSR_R(rd, rn, rm)	(_AL3_R(ARM_INST_LSR, rd, 0, rn) | (rm) << 8)
#define ARM_LSR_I(rd, rn, imm)	(_AL3_I(ARM_INST_LSR, rd, 0, rn) | (imm) << 7)
#define ARM_ASR_R(rd, rn, rm)   (_AL3_R(ARM_INST_ASR, rd, 0, rn) | (rm) << 8)
#define ARM_ASR_I(rd, rn, imm)  (_AL3_I(ARM_INST_ASR, rd, 0, rn) | (imm) << 7)

#define ARM_MOV_R(rd, rm)	_AL3_R(ARM_INST_MOV, rd, 0, rm)
#define ARM_MOVS_R(rd, rm)	_AL3_R(ARM_INST_MOVS, rd, 0, rm)
#define ARM_MOV_I(rd, imm)	_AL3_I(ARM_INST_MOV, rd, 0, imm)
#define ARM_MOV_SR(rd, rm, type, rs)	\
	(_AL3_SR(ARM_MOV_R(rd, rm)) | (type) << 5 | (rs) << 8)
#define ARM_MOV_SI(rd, rm, type, imm6)	\
	(ARM_MOV_R(rd, rm) | (type) << 5 | (imm6) << 7)

#define ARM_MOVW(rd, imm)	\
	(ARM_INST_MOVW | ((imm) >> 12) << 16 | (rd) << 12 | ((imm) & 0x0fff))

#define ARM_MOVT(rd, imm)	\
	(ARM_INST_MOVT | ((imm) >> 12) << 16 | (rd) << 12 | ((imm) & 0x0fff))

#define ARM_MUL(rd, rm, rn)	(ARM_INST_MUL | (rd) << 16 | (rm) << 8 | (rn))

#define ARM_POP(regs)		(ARM_INST_POP | (regs))
#define ARM_PUSH(regs)		(ARM_INST_PUSH | (regs))

#define ARM_ORR_R(rd, rn, rm)	_AL3_R(ARM_INST_ORR, rd, rn, rm)
#define ARM_ORR_I(rd, rn, imm)	_AL3_I(ARM_INST_ORR, rd, rn, imm)
#define ARM_ORR_SR(rd, rn, rm, type, rs)	\
	(_AL3_SR(ARM_ORR_R(rd, rn, rm)) | (type) << 5 | (rs) << 8)
#define ARM_ORRS_R(rd, rn, rm)	_AL3_R(ARM_INST_ORRS, rd, rn, rm)
#define ARM_ORRS_SR(rd, rn, rm, type, rs)	\
	(_AL3_SR(ARM_ORRS_R(rd, rn, rm)) | (type) << 5 | (rs) << 8)
#define ARM_ORR_SI(rd, rn, rm, type, imm6)	\
	(ARM_ORR_R(rd, rn, rm) | (type) << 5 | (imm6) << 7)
#define ARM_ORRS_SI(rd, rn, rm, type, imm6)	\
	(ARM_ORRS_R(rd, rn, rm) | (type) << 5 | (imm6) << 7)

#define ARM_REV(rd, rm)		(ARM_INST_REV | (rd) << 12 | (rm))
#define ARM_REV16(rd, rm)	(ARM_INST_REV16 | (rd) << 12 | (rm))

#define ARM_RSB_I(rd, rn, imm)	_AL3_I(ARM_INST_RSB, rd, rn, imm)
#define ARM_RSBS_I(rd, rn, imm)	_AL3_I(ARM_INST_RSBS, rd, rn, imm)
#define ARM_RSC_I(rd, rn, imm)	_AL3_I(ARM_INST_RSC, rd, rn, imm)

#define ARM_SUB_R(rd, rn, rm)	_AL3_R(ARM_INST_SUB, rd, rn, rm)
#define ARM_SUBS_R(rd, rn, rm)	_AL3_R(ARM_INST_SUBS, rd, rn, rm)
#define ARM_RSB_R(rd, rn, rm)	_AL3_R(ARM_INST_RSB, rd, rn, rm)
#define ARM_SBC_R(rd, rn, rm)	_AL3_R(ARM_INST_SBC, rd, rn, rm)
#define ARM_SBCS_R(rd, rn, rm)	_AL3_R(ARM_INST_SBCS, rd, rn, rm)
#define ARM_SUB_I(rd, rn, imm)	_AL3_I(ARM_INST_SUB, rd, rn, imm)
#define ARM_SUBS_I(rd, rn, imm)	_AL3_I(ARM_INST_SUBS, rd, rn, imm)
#define ARM_SBC_I(rd, rn, imm)	_AL3_I(ARM_INST_SBC, rd, rn, imm)

#define ARM_TST_R(rn, rm)	_AL3_R(ARM_INST_TST, 0, rn, rm)
#define ARM_TST_I(rn, imm)	_AL3_I(ARM_INST_TST, 0, rn, imm)

#define ARM_UDIV(rd, rn, rm)	(ARM_INST_UDIV | (rd) << 16 | (rn) | (rm) << 8)

#define ARM_UMULL(rd_lo, rd_hi, rn, rm)	(ARM_INST_UMULL | (rd_hi) << 16 \
					 | (rd_lo) << 12 | (rm) << 8 | rn)

#define ARM_MLS(rd, rn, rm, ra)	(ARM_INST_MLS | (rd) << 16 | (rn) | (rm) << 8 \
				 | (ra) << 12)
#define ARM_UXTH(rd, rm)	(ARM_INST_UXTH | (rd) << 12 | (rm))

struct jump
{
    uint32_t offset_loc;
    uint32_t target_pc;
};

struct jit_state
{
    uint8_t* buf;
    uint32_t offset;
    uint32_t size;
    uint32_t* pc_locs;
    uint32_t exit_loc;
    uint32_t unwind_loc;
    struct jump* jumps;
    int num_jumps;
    uint32_t stack_size;
};

#define ___asm_opcode_identity32(x) ((x) & 0xFFFFFFFF)

#define ___opcode_identity32(x) ___asm_opcode_identity32(x)
#define __opcode_to_mem_arm(x) ___opcode_identity32(x)
#define __opcode_to_mem_thumb32(x) ___opcode_swahw32(x)
#define ___asm_opcode_to_mem_thumb32(x) ___asm_opcode_swahw32(x)

/* Operations specific to Thumb opcodes */

/* Instruction size checks: */
#define __opcode_is_thumb16(x) (					\
	   ((x) & 0xFFFF0000) == 0					\
	&& !(((x) & 0xF800) == 0xE800 || ((x) & 0xF000) == 0xF000)	\
)

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
#define CALLEE_MASK	(1 << ARM_R4 | 1 << ARM_R5 | 1 << ARM_R6 | \
			 1 << ARM_R7 | 1 << ARM_R8 | 1 << ARM_R9 | \
			 1 << ARM_FP)
#define CALLEE_PUSH_MASK (CALLEE_MASK | 1 << ARM_LR)
#define CALLEE_POP_MASK  (CALLEE_MASK | 1 << ARM_PC)

enum {
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

/*
 * Negative "register" values indicate the register is stored on the stack
 * and are the offset from the top of the eBPF JIT scratch space.
 */
#define STACK_OFFSET(k)	(-4 - (k) * 4)
#define SCRATCH_SIZE	(BPF_JIT_SCRATCH_REGS * 4)

#ifdef CONFIG_FRAME_POINTER
#define EBPF_SCRATCH_TO_ARM_FP(x) ((x) - 4 * hweight16(CALLEE_PUSH_MASK) - 4)
#else
#define EBPF_SCRATCH_TO_ARM_FP(x) (x)
#endif

#define TMP_REG_1	(MAX_BPF_JIT_REG + 0)	/* TEMP Register 1 */
#define TMP_REG_2	(MAX_BPF_JIT_REG + 1)	/* TEMP Register 2 */
#define TCALL_CNT	(MAX_BPF_JIT_REG + 2)	/* Tail Call Count */

#define FLAG_IMM_OVERFLOW	(1 << 0)

/*
 * Map eBPF registers to ARM 32bit registers or stack scratch space.
 *
 * 1. First argument is passed using the arm 32bit registers and rest of the
 * arguments are passed on stack scratch space.
 * 2. First callee-saved argument is mapped to arm 32 bit registers and rest
 * arguments are mapped to scratch space on stack.
 * 3. We need two 64 bit temp registers to do complex operations on eBPF
 * registers.
 *
 * As the eBPF registers are all 64 bit registers and arm has only 32 bit
 * registers, we have to map each eBPF registers with two arm 32 bit regs or
 * scratch memory space and we have to build eBPF 64 bit register from those.
 *
 */
static const s8 bpf2a32[][2] = {
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

/*
 * JIT Context:
 *
 * prog			:	bpf_prog
 * idx			:	index of current last JITed instruction.
 * prologue_bytes	:	bytes used in prologue.
 * epilogue_offset	:	offset of epilogue starting.
 * offsets		:	array of eBPF instruction offsets in
 *				JITed code.
 * target		:	final JITed code.
 * epilogue_bytes	:	no of bytes used in epilogue.
 * imm_count		:	no of immediate counts used for global
 *				variables.
 * imms			:	array of global variable addresses.
 */

struct jit_ctx {
	const struct ebpf_vm *prog;
	unsigned int idx;
	unsigned int prologue_bytes;
	unsigned int epilogue_offset;
	// no meaning
	u32 flags;
	u32 *offsets;
	u32 *target;
	// buf in 
	u32 stack_size;
	// stack_size in jit_state
};

/*
 * Wrappers which handle both OABI and EABI and assures Thumb2 interworking
 * (where the assembly routines like __aeabi_uidiv could cause problems).
 */
static u32 jit_udiv32(u32 dividend, u32 divisor)
{
	return dividend / divisor;
}

static u32 jit_mod32(u32 dividend, u32 divisor)
{
	return dividend % divisor;
}

static inline void _emit(int cond, u32 inst, struct jit_ctx *ctx)
{
	// TODO: Core Function
	inst |= (cond << 28);
	inst = __opcode_to_mem_arm(inst);

	if (ctx->target != NULL)
		ctx->target[ctx->idx] = inst;

	ctx->idx++;
}

/*
 * Emit an instruction that will be executed unconditionally.
 */
static inline void emit(u32 inst, struct jit_ctx *ctx)
{
	_emit(ARM_COND_AL, inst, ctx);
}

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline u32 rol32(u32 word, unsigned int shift)
{
	return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

/**
 * ror32 - rotate a 32-bit value right
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline u32 ror32(u32 word, unsigned int shift)
{
	return (word >> (shift & 31)) | (word << ((-shift) & 31));
}

/*
 * This is rather horrid, but necessary to convert an integer constant
 * to an immediate operand for the opcodes, and be able to detect at
 * build time whether the constant can't be converted (iow, usable in
 * static_assert()).
 */
#define imm12val(v, s) (rol32(v, (s)) | (s) << 7)
#define const_imm8m(x)					\
	({ int r;					\
	   u32 v = (x);					\
	   if (!(v & ~0x000000ff))			\
		r = imm12val(v, 0);			\
	   else if (!(v & ~0xc000003f))			\
		r = imm12val(v, 2);			\
	   else if (!(v & ~0xf000000f))			\
		r = imm12val(v, 4);			\
	   else if (!(v & ~0xfc000003))			\
		r = imm12val(v, 6);			\
	   else if (!(v & ~0xff000000))			\
		r = imm12val(v, 8);			\
	   else if (!(v & ~0x3fc00000))			\
		r = imm12val(v, 10);			\
	   else if (!(v & ~0x0ff00000))			\
		r = imm12val(v, 12);			\
	   else if (!(v & ~0x03fc0000))			\
		r = imm12val(v, 14);			\
	   else if (!(v & ~0x00ff0000))			\
		r = imm12val(v, 16);			\
	   else if (!(v & ~0x003fc000))			\
		r = imm12val(v, 18);			\
	   else if (!(v & ~0x000ff000))			\
		r = imm12val(v, 20);			\
	   else if (!(v & ~0x0003fc00))			\
		r = imm12val(v, 22);			\
	   else if (!(v & ~0x0000ff00))			\
		r = imm12val(v, 24);			\
	   else if (!(v & ~0x00003fc0))			\
		r = imm12val(v, 26);			\
	   else if (!(v & ~0x00000ff0))			\
		r = imm12val(v, 28);			\
	   else if (!(v & ~0x000003fc))			\
		r = imm12val(v, 30);			\
	   else						\
		r = -1;					\
	   r; })

/*
 * Checks if immediate value can be converted to imm12(12 bits) value.
 */
static int imm8m(u32 x)
{
	u32 rot;

	for (rot = 0; rot < 16; rot++)
		if ((x & ~ror32(0xff, 2 * rot)) == 0)
			return rol32(x, 2 * rot) | (rot << 8);
	return -1;
}

#define imm8m(x) (__builtin_constant_p(x) ? const_imm8m(x) : imm8m(x))

static u32 arm_bpf_ldst_imm12(u32 op, u8 rt, u8 rn, s16 imm12)
{
	op |= rt << 12 | rn << 16;
	if (imm12 >= 0)
		op |= ARM_INST_LDST__U;
	else
		imm12 = -imm12;
	return op | (imm12 & ARM_INST_LDST__IMM12);
}

static u32 arm_bpf_ldst_imm8(u32 op, u8 rt, u8 rn, s16 imm8)
{
	op |= rt << 12 | rn << 16;
	if (imm8 >= 0)
		op |= ARM_INST_LDST__U;
	else
		imm8 = -imm8;
	return op | (imm8 & 0xf0) << 4 | (imm8 & 0x0f);
}

#define ARM_LDR_I(rt, rn, off)	arm_bpf_ldst_imm12(ARM_INST_LDR_I, rt, rn, off)
#define ARM_LDRB_I(rt, rn, off)	arm_bpf_ldst_imm12(ARM_INST_LDRB_I, rt, rn, off)
#define ARM_LDRD_I(rt, rn, off)	arm_bpf_ldst_imm8(ARM_INST_LDRD_I, rt, rn, off)
#define ARM_LDRH_I(rt, rn, off)	arm_bpf_ldst_imm8(ARM_INST_LDRH_I, rt, rn, off)

#define ARM_STR_I(rt, rn, off)	arm_bpf_ldst_imm12(ARM_INST_STR_I, rt, rn, off)
#define ARM_STRB_I(rt, rn, off)	arm_bpf_ldst_imm12(ARM_INST_STRB_I, rt, rn, off)
#define ARM_STRD_I(rt, rn, off)	arm_bpf_ldst_imm8(ARM_INST_STRD_I, rt, rn, off)
#define ARM_STRH_I(rt, rn, off)	arm_bpf_ldst_imm8(ARM_INST_STRH_I, rt, rn, off)

/*
 * Initializes the JIT space with undefined instructions.
 */
static void jit_fill_hole(void *area, unsigned int size)
{
	u32 *ptr;
	/* We are guaranteed to have aligned memory. */
	for (ptr = area; size >= sizeof(u32); size -= sizeof(u32))
		*ptr++ = __opcode_to_mem_arm(ARM_INST_UDF);
}

/* EABI requires the stack to be aligned to 64-bit boundaries */
#define STACK_ALIGNMENT	8
/* total stack size used in JITed code */
#define _STACK_SIZE	(EBPF_STACK_SIZE + SCRATCH_SIZE)
/* total stack size used in JITed code */
#define STACK_SIZE	ALIGN(_STACK_SIZE, STACK_ALIGNMENT)


static inline int bpf2a32_offset(int bpf_to, int bpf_from,
				 const struct jit_ctx *ctx) {
	int to, from;

	if (ctx->target == NULL)
		return 0;
	to = ctx->offsets[bpf_to];
	from = ctx->offsets[bpf_from];

	return to - from - 1;
}

/*
 * Move an immediate that's not an imm8m to a core register.
 */
static inline void emit_mov_i_no8m(const u8 rd, u32 val, struct jit_ctx *ctx)
{

	emit(ARM_MOVW(rd, val & 0xffff), ctx);
	if (val > 0xffff)
		emit(ARM_MOVT(rd, val >> 16), ctx);

}

static inline void emit_mov_i(const u8 rd, u32 val, struct jit_ctx *ctx)
{
	int imm12 = imm8m(val);

	if (imm12 >= 0)
		emit(ARM_MOV_I(rd, imm12), ctx);
	else
		emit_mov_i_no8m(rd, val, ctx);
}

static void emit_bx_r(u8 tgt_reg, struct jit_ctx *ctx)
{
	// if (elf_hwcap & HWCAP_THUMB)
	// 	emit(ARM_BX(tgt_reg), ctx);
	// else
	emit(ARM_MOV_R(ARM_PC, tgt_reg), ctx);
}

static inline void emit_blx_r(u8 tgt_reg, struct jit_ctx *ctx)
{
	emit(ARM_BLX_R(tgt_reg), ctx);
}

static inline int epilogue_offset(const struct jit_ctx *ctx)
{
	int to, from;
	/* No need for 1st dummy run */
	if (ctx->target == NULL)
		return 0;
	to = ctx->epilogue_offset;
	from = ctx->idx;

	return to - from - 2;
}

static inline void emit_udivmod(u8 rd, u8 rm, u8 rn, struct jit_ctx *ctx, u8 op)
{
	const s8 *tmp = bpf2a32[TMP_REG_1];

	/*
	 * For BPF_ALU | BPF_DIV | BPF_K instructions
	 * As ARM_R1 and ARM_R0 contains 1st argument of bpf
	 * function, we need to save it on caller side to save
	 * it from getting destroyed within callee.
	 * After the return from the callee, we restore ARM_R0
	 * ARM_R1.
	 */
	if (rn != ARM_R1) {
		emit(ARM_MOV_R(tmp[0], ARM_R1), ctx);
		emit(ARM_MOV_R(ARM_R1, rn), ctx);
	}
	if (rm != ARM_R0) {
		emit(ARM_MOV_R(tmp[1], ARM_R0), ctx);
		emit(ARM_MOV_R(ARM_R0, rm), ctx);
	}

	/* Call appropriate function */
	emit_mov_i(ARM_IP, op == BPF_DIV ?
		   (u32)jit_udiv32 : (u32)jit_mod32, ctx);
	emit_blx_r(ARM_IP, ctx);

	/* Save return value */
	if (rd != ARM_R0)
		emit(ARM_MOV_R(rd, ARM_R0), ctx);

	/* Restore ARM_R0 and ARM_R1 */
	if (rn != ARM_R1)
		emit(ARM_MOV_R(ARM_R1, tmp[0]), ctx);
	if (rm != ARM_R0)
		emit(ARM_MOV_R(ARM_R0, tmp[1]), ctx);
}

/* Is the translated BPF register on stack? */
static bool is_stacked(s8 reg)
{
	return reg < 0;
}

/* If a BPF register is on the stack (stk is true), load it to the
 * supplied temporary register and return the temporary register
 * for subsequent operations, otherwise just use the CPU register.
 */
static s8 arm_bpf_get_reg32(s8 reg, s8 tmp, struct jit_ctx *ctx)
{
	if (is_stacked(reg)) {
		emit(ARM_LDR_I(tmp, ARM_FP, EBPF_SCRATCH_TO_ARM_FP(reg)), ctx);
		reg = tmp;
	}
	return reg;
}

static const s8 *arm_bpf_get_reg64(const s8 *reg, const s8 *tmp,
				   struct jit_ctx *ctx)
{
	if (is_stacked(reg[1])) {
			emit(ARM_LDRD_I(tmp[1], ARM_FP,
					EBPF_SCRATCH_TO_ARM_FP(reg[1])), ctx);
		reg = tmp;
	}
	return reg;
}

/* If a BPF register is on the stack (stk is true), save the register
 * back to the stack.  If the source register is not the same, then
 * move it into the correct register.
 */
static void arm_bpf_put_reg32(s8 reg, s8 src, struct jit_ctx *ctx)
{
	if (is_stacked(reg))
		emit(ARM_STR_I(src, ARM_FP, EBPF_SCRATCH_TO_ARM_FP(reg)), ctx);
	else if (reg != src)
		emit(ARM_MOV_R(reg, src), ctx);
}

static void arm_bpf_put_reg64(const s8 *reg, const s8 *src,
			      struct jit_ctx *ctx)
{
	if (is_stacked(reg[1])) {
			emit(ARM_STRD_I(src[1], ARM_FP,
				       EBPF_SCRATCH_TO_ARM_FP(reg[1])), ctx);
	} else {
		if (reg[1] != src[1])
			emit(ARM_MOV_R(reg[1], src[1]), ctx);
		if (reg[0] != src[0])
			emit(ARM_MOV_R(reg[0], src[0]), ctx);
	}
}

static inline void emit_a32_mov_i(const s8 dst, const u32 val,
				  struct jit_ctx *ctx)
{
	const s8 *tmp = bpf2a32[TMP_REG_1];

	if (is_stacked(dst)) {
		emit_mov_i(tmp[1], val, ctx);
		arm_bpf_put_reg32(dst, tmp[1], ctx);
	} else {
		emit_mov_i(dst, val, ctx);
	}
}

static void emit_a32_mov_i64(const s8 dst[], u64 val, struct jit_ctx *ctx)
{
	const s8 *tmp = bpf2a32[TMP_REG_1];
	const s8 *rd = is_stacked(dst_lo) ? tmp : dst;

	emit_mov_i(rd[1], (u32)val, ctx);
	emit_mov_i(rd[0], val >> 32, ctx);

	arm_bpf_put_reg64(dst, rd, ctx);
}

/* Sign extended move */
static inline void emit_a32_mov_se_i64(const bool is64, const s8 dst[],
				       const u32 val, struct jit_ctx *ctx) {
	u64 val64 = val;

	if (is64 && (val & (1<<31)))
		val64 |= 0xffffffff00000000ULL;
	emit_a32_mov_i64(dst, val64, ctx);
}

static inline void emit_a32_add_r(const u8 dst, const u8 src,
			      const bool is64, const bool hi,
			      struct jit_ctx *ctx) {
	/* 64 bit :
	 *	adds dst_lo, dst_lo, src_lo
	 *	adc dst_hi, dst_hi, src_hi
	 * 32 bit :
	 *	add dst_lo, dst_lo, src_lo
	 */
	if (!hi && is64)
		emit(ARM_ADDS_R(dst, dst, src), ctx);
	else if (hi && is64)
		emit(ARM_ADC_R(dst, dst, src), ctx);
	else
		emit(ARM_ADD_R(dst, dst, src), ctx);
}

static inline void emit_a32_sub_r(const u8 dst, const u8 src,
				  const bool is64, const bool hi,
				  struct jit_ctx *ctx) {
	/* 64 bit :
	 *	subs dst_lo, dst_lo, src_lo
	 *	sbc dst_hi, dst_hi, src_hi
	 * 32 bit :
	 *	sub dst_lo, dst_lo, src_lo
	 */
	if (!hi && is64)
		emit(ARM_SUBS_R(dst, dst, src), ctx);
	else if (hi && is64)
		emit(ARM_SBC_R(dst, dst, src), ctx);
	else
		emit(ARM_SUB_R(dst, dst, src), ctx);
}

static inline void emit_alu_r(const u8 dst, const u8 src, const bool is64,
			      const bool hi, const u8 op, struct jit_ctx *ctx){
	switch (BPF_OP(op)) {
	/* dst = dst + src */
	case BPF_ADD:
		emit_a32_add_r(dst, src, is64, hi, ctx);
		break;
	/* dst = dst - src */
	case BPF_SUB:
		emit_a32_sub_r(dst, src, is64, hi, ctx);
		break;
	/* dst = dst | src */
	case BPF_OR:
		emit(ARM_ORR_R(dst, dst, src), ctx);
		break;
	/* dst = dst & src */
	case BPF_AND:
		emit(ARM_AND_R(dst, dst, src), ctx);
		break;
	/* dst = dst ^ src */
	case BPF_XOR:
		emit(ARM_EOR_R(dst, dst, src), ctx);
		break;
	/* dst = dst * src */
	case BPF_MUL:
		emit(ARM_MUL(dst, dst, src), ctx);
		break;
	/* dst = dst << src */
	case BPF_LSH:
		emit(ARM_LSL_R(dst, dst, src), ctx);
		break;
	/* dst = dst >> src */
	case BPF_RSH:
		emit(ARM_LSR_R(dst, dst, src), ctx);
		break;
	/* dst = dst >> src (signed)*/
	case BPF_ARSH:
		emit(ARM_MOV_SR(dst, dst, SRTYPE_ASR, src), ctx);
		break;
	}
}

/* ALU operation (32 bit)
 * dst = dst (op) src
 */
static inline void emit_a32_alu_r(const s8 dst, const s8 src,
				  struct jit_ctx *ctx, const bool is64,
				  const bool hi, const u8 op) {
	const s8 *tmp = bpf2a32[TMP_REG_1];
	s8 rn, rd;

	rn = arm_bpf_get_reg32(src, tmp[1], ctx);
	rd = arm_bpf_get_reg32(dst, tmp[0], ctx);
	/* ALU operation */
	emit_alu_r(rd, rn, is64, hi, op, ctx);
	arm_bpf_put_reg32(dst, rd, ctx);
}

/* ALU operation (64 bit) */
static inline void emit_a32_alu_r64(const bool is64, const s8 dst[],
				  const s8 src[], struct jit_ctx *ctx,
				  const u8 op) {
	const s8 *tmp = bpf2a32[TMP_REG_1];
	const s8 *tmp2 = bpf2a32[TMP_REG_2];
	const s8 *rd;

	rd = arm_bpf_get_reg64(dst, tmp, ctx);
	if (is64) {
		const s8 *rs;

		rs = arm_bpf_get_reg64(src, tmp2, ctx);

		/* ALU operation */
		emit_alu_r(rd[1], rs[1], true, false, op, ctx);
		emit_alu_r(rd[0], rs[0], true, true, op, ctx);
	} else {
		s8 rs;

		rs = arm_bpf_get_reg32(src_lo, tmp2[1], ctx);

		/* ALU operation */
		emit_alu_r(rd[1], rs, true, false, op, ctx);
		if (!ctx->prog->aux->verifier_zext)
			emit_a32_mov_i(rd[0], 0, ctx);
	}

	arm_bpf_put_reg64(dst, rd, ctx);
}

/* dst = src (4 bytes)*/
static inline void emit_a32_mov_r(const s8 dst, const s8 src,
				  struct jit_ctx *ctx) {
	const s8 *tmp = bpf2a32[TMP_REG_1];
	s8 rt;

	rt = arm_bpf_get_reg32(src, tmp[0], ctx);
	arm_bpf_put_reg32(dst, rt, ctx);
}

/* dst = src */
static inline void emit_a32_mov_r64(const bool is64, const s8 dst[],
				  const s8 src[],
				  struct jit_ctx *ctx) {
	if (!is64) {
		emit_a32_mov_r(dst_lo, src_lo, ctx);
		if (!ctx->prog->aux->verifier_zext)
			/* Zero out high 4 bytes */
			emit_a32_mov_i(dst_hi, 0, ctx);
	} 
	else if (is_stacked(src_lo) && is_stacked(dst_lo)) {
		const u8 *tmp = bpf2a32[TMP_REG_1];

		emit(ARM_LDRD_I(tmp[1], ARM_FP, EBPF_SCRATCH_TO_ARM_FP(src_lo)), ctx);
		emit(ARM_STRD_I(tmp[1], ARM_FP, EBPF_SCRATCH_TO_ARM_FP(dst_lo)), ctx);
	} else if (is_stacked(src_lo)) {
		emit(ARM_LDRD_I(dst[1], ARM_FP, EBPF_SCRATCH_TO_ARM_FP(src_lo)), ctx);
	} else if (is_stacked(dst_lo)) {
		emit(ARM_STRD_I(src[1], ARM_FP, EBPF_SCRATCH_TO_ARM_FP(dst_lo)), ctx);
	} else {
		emit(ARM_MOV_R(dst[0], src[0]), ctx);
		emit(ARM_MOV_R(dst[1], src[1]), ctx);
	}
}

/* Shift operations */
static inline void emit_a32_alu_i(const s8 dst, const u32 val,
				struct jit_ctx *ctx, const u8 op) {
	const s8 *tmp = bpf2a32[TMP_REG_1];
	s8 rd;

	rd = arm_bpf_get_reg32(dst, tmp[0], ctx);

	/* Do shift operation */
	switch (op) {
	case BPF_LSH:
		emit(ARM_LSL_I(rd, rd, val), ctx);
		break;
	case BPF_RSH:
		emit(ARM_LSR_I(rd, rd, val), ctx);
		break;
	case BPF_ARSH:
		emit(ARM_ASR_I(rd, rd, val), ctx);
		break;
	case BPF_NEG:
		emit(ARM_RSB_I(rd, rd, val), ctx);
		break;
	}

	arm_bpf_put_reg32(dst, rd, ctx);
}

/* dst = ~dst (64 bit) */
static inline void emit_a32_neg64(const s8 dst[],
				struct jit_ctx *ctx){
	const s8 *tmp = bpf2a32[TMP_REG_1];
	const s8 *rd;

	/* Setup Operand */
	rd = arm_bpf_get_reg64(dst, tmp, ctx);

	/* Do Negate Operation */
	emit(ARM_RSBS_I(rd[1], rd[1], 0), ctx);
	emit(ARM_RSC_I(rd[0], rd[0], 0), ctx);

	arm_bpf_put_reg64(dst, rd, ctx);
}

/* dst = dst << src */
static inline void emit_a32_lsh_r64(const s8 dst[], const s8 src[],
				    struct jit_ctx *ctx) {
	const s8 *tmp = bpf2a32[TMP_REG_1];
	const s8 *tmp2 = bpf2a32[TMP_REG_2];
	const s8 *rd;
	s8 rt;

	/* Setup Operands */
	rt = arm_bpf_get_reg32(src_lo, tmp2[1], ctx);
	rd = arm_bpf_get_reg64(dst, tmp, ctx);

	/* Do LSH operation */
	emit(ARM_SUB_I(ARM_IP, rt, 32), ctx);
	emit(ARM_RSB_I(tmp2[0], rt, 32), ctx);
	emit(ARM_MOV_SR(ARM_LR, rd[0], SRTYPE_ASL, rt), ctx);
	emit(ARM_ORR_SR(ARM_LR, ARM_LR, rd[1], SRTYPE_ASL, ARM_IP), ctx);
	emit(ARM_ORR_SR(ARM_IP, ARM_LR, rd[1], SRTYPE_LSR, tmp2[0]), ctx);
	emit(ARM_MOV_SR(ARM_LR, rd[1], SRTYPE_ASL, rt), ctx);

	arm_bpf_put_reg32(dst_lo, ARM_LR, ctx);
	arm_bpf_put_reg32(dst_hi, ARM_IP, ctx);
}

/* dst = dst >> src (signed)*/
static inline void emit_a32_arsh_r64(const s8 dst[], const s8 src[],
				     struct jit_ctx *ctx) {
	const s8 *tmp = bpf2a32[TMP_REG_1];
	const s8 *tmp2 = bpf2a32[TMP_REG_2];
	const s8 *rd;
	s8 rt;

	/* Setup Operands */
	rt = arm_bpf_get_reg32(src_lo, tmp2[1], ctx);
	rd = arm_bpf_get_reg64(dst, tmp, ctx);

	/* Do the ARSH operation */
	emit(ARM_RSB_I(ARM_IP, rt, 32), ctx);
	emit(ARM_SUBS_I(tmp2[0], rt, 32), ctx);
	emit(ARM_MOV_SR(ARM_LR, rd[1], SRTYPE_LSR, rt), ctx);
	emit(ARM_ORR_SR(ARM_LR, ARM_LR, rd[0], SRTYPE_ASL, ARM_IP), ctx);
	_emit(ARM_COND_PL,
	      ARM_ORR_SR(ARM_LR, ARM_LR, rd[0], SRTYPE_ASR, tmp2[0]), ctx);
	emit(ARM_MOV_SR(ARM_IP, rd[0], SRTYPE_ASR, rt), ctx);

	arm_bpf_put_reg32(dst_lo, ARM_LR, ctx);
	arm_bpf_put_reg32(dst_hi, ARM_IP, ctx);
}

/* dst = dst >> src */
static inline void emit_a32_rsh_r64(const s8 dst[], const s8 src[],
				    struct jit_ctx *ctx) {
	const s8 *tmp = bpf2a32[TMP_REG_1];
	const s8 *tmp2 = bpf2a32[TMP_REG_2];
	const s8 *rd;
	s8 rt;

	/* Setup Operands */
	rt = arm_bpf_get_reg32(src_lo, tmp2[1], ctx);
	rd = arm_bpf_get_reg64(dst, tmp, ctx);

	/* Do RSH operation */
	emit(ARM_RSB_I(ARM_IP, rt, 32), ctx);
	emit(ARM_SUBS_I(tmp2[0], rt, 32), ctx);
	emit(ARM_MOV_SR(ARM_LR, rd[1], SRTYPE_LSR, rt), ctx);
	emit(ARM_ORR_SR(ARM_LR, ARM_LR, rd[0], SRTYPE_ASL, ARM_IP), ctx);
	emit(ARM_ORR_SR(ARM_LR, ARM_LR, rd[0], SRTYPE_LSR, tmp2[0]), ctx);
	emit(ARM_MOV_SR(ARM_IP, rd[0], SRTYPE_LSR, rt), ctx);

	arm_bpf_put_reg32(dst_lo, ARM_LR, ctx);
	arm_bpf_put_reg32(dst_hi, ARM_IP, ctx);
}

/* dst = dst << val */
static inline void emit_a32_lsh_i64(const s8 dst[],
				    const u32 val, struct jit_ctx *ctx){
	const s8 *tmp = bpf2a32[TMP_REG_1];
	const s8 *tmp2 = bpf2a32[TMP_REG_2];
	const s8 *rd;

	/* Setup operands */
	rd = arm_bpf_get_reg64(dst, tmp, ctx);

	/* Do LSH operation */
	if (val < 32) {
		emit(ARM_MOV_SI(tmp2[0], rd[0], SRTYPE_ASL, val), ctx);
		emit(ARM_ORR_SI(rd[0], tmp2[0], rd[1], SRTYPE_LSR, 32 - val), ctx);
		emit(ARM_MOV_SI(rd[1], rd[1], SRTYPE_ASL, val), ctx);
	} else {
		if (val == 32)
			emit(ARM_MOV_R(rd[0], rd[1]), ctx);
		else
			emit(ARM_MOV_SI(rd[0], rd[1], SRTYPE_ASL, val - 32), ctx);
		emit(ARM_EOR_R(rd[1], rd[1], rd[1]), ctx);
	}

	arm_bpf_put_reg64(dst, rd, ctx);
}

/* dst = dst >> val */
static inline void emit_a32_rsh_i64(const s8 dst[],
				    const u32 val, struct jit_ctx *ctx) {
	const s8 *tmp = bpf2a32[TMP_REG_1];
	const s8 *tmp2 = bpf2a32[TMP_REG_2];
	const s8 *rd;

	/* Setup operands */
	rd = arm_bpf_get_reg64(dst, tmp, ctx);

	/* Do LSR operation */
	if (val == 0) {
		/* An immediate value of 0 encodes a shift amount of 32
		 * for LSR. To shift by 0, don't do anything.
		 */
	} else if (val < 32) {
		emit(ARM_MOV_SI(tmp2[1], rd[1], SRTYPE_LSR, val), ctx);
		emit(ARM_ORR_SI(rd[1], tmp2[1], rd[0], SRTYPE_ASL, 32 - val), ctx);
		emit(ARM_MOV_SI(rd[0], rd[0], SRTYPE_LSR, val), ctx);
	} else if (val == 32) {
		emit(ARM_MOV_R(rd[1], rd[0]), ctx);
		emit(ARM_MOV_I(rd[0], 0), ctx);
	} else {
		emit(ARM_MOV_SI(rd[1], rd[0], SRTYPE_LSR, val - 32), ctx);
		emit(ARM_MOV_I(rd[0], 0), ctx);
	}

	arm_bpf_put_reg64(dst, rd, ctx);
}

/* dst = dst >> val (signed) */
static inline void emit_a32_arsh_i64(const s8 dst[],
				     const u32 val, struct jit_ctx *ctx){
	const s8 *tmp = bpf2a32[TMP_REG_1];
	const s8 *tmp2 = bpf2a32[TMP_REG_2];
	const s8 *rd;

	/* Setup operands */
	rd = arm_bpf_get_reg64(dst, tmp, ctx);

	/* Do ARSH operation */
	if (val == 0) {
		/* An immediate value of 0 encodes a shift amount of 32
		 * for ASR. To shift by 0, don't do anything.
		 */
	} else if (val < 32) {
		emit(ARM_MOV_SI(tmp2[1], rd[1], SRTYPE_LSR, val), ctx);
		emit(ARM_ORR_SI(rd[1], tmp2[1], rd[0], SRTYPE_ASL, 32 - val), ctx);
		emit(ARM_MOV_SI(rd[0], rd[0], SRTYPE_ASR, val), ctx);
	} else if (val == 32) {
		emit(ARM_MOV_R(rd[1], rd[0]), ctx);
		emit(ARM_MOV_SI(rd[0], rd[0], SRTYPE_ASR, 31), ctx);
	} else {
		emit(ARM_MOV_SI(rd[1], rd[0], SRTYPE_ASR, val - 32), ctx);
		emit(ARM_MOV_SI(rd[0], rd[0], SRTYPE_ASR, 31), ctx);
	}

	arm_bpf_put_reg64(dst, rd, ctx);
}

static inline void emit_a32_mul_r64(const s8 dst[], const s8 src[],
				    struct jit_ctx *ctx) {
	const s8 *tmp = bpf2a32[TMP_REG_1];
	const s8 *tmp2 = bpf2a32[TMP_REG_2];
	const s8 *rd, *rt;

	/* Setup operands for multiplication */
	rd = arm_bpf_get_reg64(dst, tmp, ctx);
	rt = arm_bpf_get_reg64(src, tmp2, ctx);

	/* Do Multiplication */
	emit(ARM_MUL(ARM_IP, rd[1], rt[0]), ctx);
	emit(ARM_MUL(ARM_LR, rd[0], rt[1]), ctx);
	emit(ARM_ADD_R(ARM_LR, ARM_IP, ARM_LR), ctx);

	emit(ARM_UMULL(ARM_IP, rd[0], rd[1], rt[1]), ctx);
	emit(ARM_ADD_R(rd[0], ARM_LR, rd[0]), ctx);

	arm_bpf_put_reg32(dst_lo, ARM_IP, ctx);
	arm_bpf_put_reg32(dst_hi, rd[0], ctx);
}

static bool is_ldst_imm(s16 off, const u8 size)
{
	s16 off_max = 0;

	switch (size) {
	case BPF_B:
	case BPF_W:
		off_max = 0xfff;
		break;
	case BPF_H:
		off_max = 0xff;
		break;
	case BPF_DW:
		/* Need to make sure off+4 does not overflow. */
		off_max = 0xfff - 4;
		break;
	}
	return -off_max <= off && off <= off_max;
}

/* *(size *)(dst + off) = src */
static inline void emit_str_r(const s8 dst, const s8 src[],
			      s16 off, struct jit_ctx *ctx, const u8 sz){
	const s8 *tmp = bpf2a32[TMP_REG_1];
	s8 rd;

	rd = arm_bpf_get_reg32(dst, tmp[1], ctx);

	if (!is_ldst_imm(off, sz)) {
		emit_a32_mov_i(tmp[0], off, ctx);
		emit(ARM_ADD_R(tmp[0], tmp[0], rd), ctx);
		rd = tmp[0];
		off = 0;
	}
	switch (sz) {
	case BPF_B:
		/* Store a Byte */
		emit(ARM_STRB_I(src_lo, rd, off), ctx);
		break;
	case BPF_H:
		/* Store a HalfWord */
		emit(ARM_STRH_I(src_lo, rd, off), ctx);
		break;
	case BPF_W:
		/* Store a Word */
		emit(ARM_STR_I(src_lo, rd, off), ctx);
		break;
	case BPF_DW:
		/* Store a Double Word */
		emit(ARM_STR_I(src_lo, rd, off), ctx);
		emit(ARM_STR_I(src_hi, rd, off + 4), ctx);
		break;
	}
}

/* dst = *(size*)(src + off) */
static inline void emit_ldx_r(const s8 dst[], const s8 src,
			      s16 off, struct jit_ctx *ctx, const u8 sz){
	const s8 *tmp = bpf2a32[TMP_REG_1];
	const s8 *rd = is_stacked(dst_lo) ? tmp : dst;
	s8 rm = src;

	if (!is_ldst_imm(off, sz)) {
		emit_a32_mov_i(tmp[0], off, ctx);
		emit(ARM_ADD_R(tmp[0], tmp[0], src), ctx);
		rm = tmp[0];
		off = 0;
	} else if (rd[1] == rm) {
		emit(ARM_MOV_R(tmp[0], rm), ctx);
		rm = tmp[0];
	}
	switch (sz) {
	case BPF_B:
		/* Load a Byte */
		emit(ARM_LDRB_I(rd[1], rm, off), ctx);
		if (!ctx->prog->aux->verifier_zext)
			emit_a32_mov_i(rd[0], 0, ctx);
		break;
	case BPF_H:
		/* Load a HalfWord */
		emit(ARM_LDRH_I(rd[1], rm, off), ctx);
		if (!ctx->prog->aux->verifier_zext)
			emit_a32_mov_i(rd[0], 0, ctx);
		break;
	case BPF_W:
		/* Load a Word */
		emit(ARM_LDR_I(rd[1], rm, off), ctx);
		if (!ctx->prog->aux->verifier_zext)
			emit_a32_mov_i(rd[0], 0, ctx);
		break;
	case BPF_DW:
		/* Load a Double Word */
		emit(ARM_LDR_I(rd[1], rm, off), ctx);
		emit(ARM_LDR_I(rd[0], rm, off + 4), ctx);
		break;
	}
	arm_bpf_put_reg64(dst, rd, ctx);
}

/* Arithmatic Operation */
static inline void emit_ar_r(const u8 rd, const u8 rt, const u8 rm,
			     const u8 rn, struct jit_ctx *ctx, u8 op,
			     bool is_jmp64) {
	switch (op) {
	case BPF_JSET:
		if (is_jmp64) {
			emit(ARM_AND_R(ARM_IP, rt, rn), ctx);
			emit(ARM_AND_R(ARM_LR, rd, rm), ctx);
			emit(ARM_ORRS_R(ARM_IP, ARM_LR, ARM_IP), ctx);
		} else {
			emit(ARM_ANDS_R(ARM_IP, rt, rn), ctx);
		}
		break;
	case BPF_JEQ:
	case BPF_JNE:
	case BPF_JGT:
	case BPF_JGE:
	case BPF_JLE:
	case BPF_JLT:
		if (is_jmp64) {
			emit(ARM_CMP_R(rd, rm), ctx);
			/* Only compare low halve if high halve are equal. */
			_emit(ARM_COND_EQ, ARM_CMP_R(rt, rn), ctx);
		} else {
			emit(ARM_CMP_R(rt, rn), ctx);
		}
		break;
	case BPF_JSLE:
	case BPF_JSGT:
		emit(ARM_CMP_R(rn, rt), ctx);
		if (is_jmp64)
			emit(ARM_SBCS_R(ARM_IP, rm, rd), ctx);
		break;
	case BPF_JSLT:
	case BPF_JSGE:
		emit(ARM_CMP_R(rt, rn), ctx);
		if (is_jmp64)
			emit(ARM_SBCS_R(ARM_IP, rd, rm), ctx);
		break;
	}
}

/* 0xabcd => 0xcdab */
static inline void emit_rev16(const u8 rd, const u8 rn, struct jit_ctx *ctx)
{
	emit(ARM_REV16(rd, rn), ctx);
}

/* 0xabcdefgh => 0xghefcdab */
static inline void emit_rev32(const u8 rd, const u8 rn, struct jit_ctx *ctx)
{

	emit(ARM_REV(rd, rn), ctx);

}

// push the scratch stack register on top of the stack
static inline void emit_push_r64(const s8 src[], struct jit_ctx *ctx)
{
	const s8 *tmp2 = bpf2a32[TMP_REG_2];
	const s8 *rt;
	u16 reg_set = 0;

	rt = arm_bpf_get_reg64(src, tmp2, ctx);

	reg_set = (1 << rt[1]) | (1 << rt[0]);
	emit(ARM_PUSH(reg_set), ctx);
}


// TODO: 以上内容的ctx的作用均是提供一个emit空间，给谁都可以
// bpf_insn = ebpf_inst
// jited_len = jitted_size

static void build_prologue(struct jit_ctx *ctx)
{
	const s8 arm_r0 = bpf2a32[BPF_REG_0][1];
	const s8 *bpf_r1 = bpf2a32[BPF_REG_1];
	const s8 *bpf_fp = bpf2a32[BPF_REG_FP];
	const s8 *tcc = bpf2a32[TCALL_CNT];

	/* Save callee saved registers. */
#ifdef CONFIG_FRAME_POINTER
	u16 reg_set = CALLEE_PUSH_MASK | 1 << ARM_IP | 1 << ARM_PC;
	emit(ARM_MOV_R(ARM_IP, ARM_SP), ctx);
	emit(ARM_PUSH(reg_set), ctx);
	emit(ARM_SUB_I(ARM_FP, ARM_IP, 4), ctx);
#else
	emit(ARM_PUSH(CALLEE_PUSH_MASK), ctx);
	emit(ARM_MOV_R(ARM_FP, ARM_SP), ctx);
#endif
	/* mov r3, #0 */
	/* sub r2, sp, #SCRATCH_SIZE */
	emit(ARM_MOV_I(bpf_r1[0], 0), ctx);
	emit(ARM_SUB_I(bpf_r1[1], ARM_SP, SCRATCH_SIZE), ctx);

	ctx->stack_size = imm8m(STACK_SIZE);

	/* Set up function call stack */
	emit(ARM_SUB_I(ARM_SP, ARM_SP, ctx->stack_size), ctx);

	/* Set up BPF prog stack base register */
	emit_a32_mov_r64(true, bpf_fp, bpf_r1, ctx);

	/* Initialize Tail Count */
	emit(ARM_MOV_I(bpf_r1[1], 0), ctx);
	emit_a32_mov_r64(true, tcc, bpf_r1, ctx);

	/* Move BPF_CTX to BPF_R1 */
	emit(ARM_MOV_R(bpf_r1[1], arm_r0), ctx);

	/* end of prologue */
}

/* restore callee saved registers. */
static void build_epilogue(struct jit_ctx *ctx)
{
#ifdef CONFIG_FRAME_POINTER
	/* When using frame pointers, some additional registers need to
	 * be loaded. */
	u16 reg_set = CALLEE_POP_MASK | 1 << ARM_SP;
	emit(ARM_SUB_I(ARM_SP, ARM_FP, hweight16(reg_set) * 4), ctx);
	emit(ARM_LDM(ARM_SP, reg_set), ctx);
#else
	/* Restore callee saved registers. */
	emit(ARM_MOV_R(ARM_SP, ARM_FP), ctx);
	emit(ARM_POP(CALLEE_POP_MASK), ctx);
#endif
}

// TODO: 以上两函数均只是使用emit结构，可以直接使用jit_state结构替换

/*
 * Convert an eBPF instruction to native instruction, i.e
 * JITs an eBPF instruction.
 * Returns :
 *	0  - Successfully JITed an 8-byte eBPF instruction
 *	>0 - Successfully JITed a 16-byte eBPF instruction
 *	<0 - Failed to JIT.
 */
static int build_insn(const struct bpf_insn *insn, struct jit_ctx *ctx)
{
	const u8 code = insn->code;
	const s8 *dst = bpf2a32[insn->dst_reg];
	const s8 *src = bpf2a32[insn->src_reg];
	const s8 *tmp = bpf2a32[TMP_REG_1];
	const s8 *tmp2 = bpf2a32[TMP_REG_2];
	const s16 off = insn->off;
	const s32 imm = insn->imm;
	const int i = insn - ctx->prog->insnsi;
	const bool is64 = BPF_CLASS(code) == BPF_ALU64;
	const s8 *rd, *rs;
	s8 rd_lo, rt, rm, rn;
	s32 jmp_offset;

#define check_imm(bits, imm) do {				\
	if ((imm) >= (1 << ((bits) - 1)) ||			\
	    (imm) < -(1 << ((bits) - 1))) {			\
		printf("[%2d] imm=%d(0x%x) out of range\n",	\
			i, imm, imm);				\
		return -EINVAL;					\
	}							\
} while (0)
#define check_imm24(imm) check_imm(24, imm)

	switch (code) {
	/* ALU operations */

	/* dst = src */
	case BPF_ALU | BPF_MOV | BPF_K:
	case BPF_ALU | BPF_MOV | BPF_X:
	case BPF_ALU64 | BPF_MOV | BPF_K:
	case BPF_ALU64 | BPF_MOV | BPF_X:
		switch (BPF_SRC(code)) {
		case BPF_X:
			if (imm == 1) {
				/* Special mov32 for zext */
				emit_a32_mov_i(dst_hi, 0, ctx);
				break;
			}
			emit_a32_mov_r64(is64, dst, src, ctx);
			break;
		case BPF_K:
			/* Sign-extend immediate value to destination reg */
			emit_a32_mov_se_i64(is64, dst, imm, ctx);
			break;
		}
		break;
	/* dst = dst + src/imm */
	/* dst = dst - src/imm */
	/* dst = dst | src/imm */
	/* dst = dst & src/imm */
	/* dst = dst ^ src/imm */
	/* dst = dst * src/imm */
	/* dst = dst << src */
	/* dst = dst >> src */
	case BPF_ALU | BPF_ADD | BPF_K:
	case BPF_ALU | BPF_ADD | BPF_X:
	case BPF_ALU | BPF_SUB | BPF_K:
	case BPF_ALU | BPF_SUB | BPF_X:
	case BPF_ALU | BPF_OR | BPF_K:
	case BPF_ALU | BPF_OR | BPF_X:
	case BPF_ALU | BPF_AND | BPF_K:
	case BPF_ALU | BPF_AND | BPF_X:
	case BPF_ALU | BPF_XOR | BPF_K:
	case BPF_ALU | BPF_XOR | BPF_X:
	case BPF_ALU | BPF_MUL | BPF_K:
	case BPF_ALU | BPF_MUL | BPF_X:
	case BPF_ALU | BPF_LSH | BPF_X:
	case BPF_ALU | BPF_RSH | BPF_X:
	case BPF_ALU | BPF_ARSH | BPF_X:
	case BPF_ALU64 | BPF_ADD | BPF_K:
	case BPF_ALU64 | BPF_ADD | BPF_X:
	case BPF_ALU64 | BPF_SUB | BPF_K:
	case BPF_ALU64 | BPF_SUB | BPF_X:
	case BPF_ALU64 | BPF_OR | BPF_K:
	case BPF_ALU64 | BPF_OR | BPF_X:
	case BPF_ALU64 | BPF_AND | BPF_K:
	case BPF_ALU64 | BPF_AND | BPF_X:
	case BPF_ALU64 | BPF_XOR | BPF_K:
	case BPF_ALU64 | BPF_XOR | BPF_X:
		switch (BPF_SRC(code)) {
		case BPF_X:
			emit_a32_alu_r64(is64, dst, src, ctx, BPF_OP(code));
			break;
		case BPF_K:
			/* Move immediate value to the temporary register
			 * and then do the ALU operation on the temporary
			 * register as this will sign-extend the immediate
			 * value into temporary reg and then it would be
			 * safe to do the operation on it.
			 */
			emit_a32_mov_se_i64(is64, tmp2, imm, ctx);
			emit_a32_alu_r64(is64, dst, tmp2, ctx, BPF_OP(code));
			break;
		}
		break;
	/* dst = dst / src(imm) */
	/* dst = dst % src(imm) */
	case BPF_ALU | BPF_DIV | BPF_K:
	case BPF_ALU | BPF_DIV | BPF_X:
	case BPF_ALU | BPF_MOD | BPF_K:
	case BPF_ALU | BPF_MOD | BPF_X:
		rd_lo = arm_bpf_get_reg32(dst_lo, tmp2[1], ctx);
		switch (BPF_SRC(code)) {
		case BPF_X:
			rt = arm_bpf_get_reg32(src_lo, tmp2[0], ctx);
			break;
		case BPF_K:
			rt = tmp2[0];
			emit_a32_mov_i(rt, imm, ctx);
			break;
		default:
			rt = src_lo;
			break;
		}
		emit_udivmod(rd_lo, rd_lo, rt, ctx, BPF_OP(code));
		arm_bpf_put_reg32(dst_lo, rd_lo, ctx);
		if (!ctx->prog->aux->verifier_zext)
			emit_a32_mov_i(dst_hi, 0, ctx);
		break;
	case BPF_ALU64 | BPF_DIV | BPF_K:
	case BPF_ALU64 | BPF_DIV | BPF_X:
	case BPF_ALU64 | BPF_MOD | BPF_K:
	case BPF_ALU64 | BPF_MOD | BPF_X:
		goto notyet;
	/* dst = dst << imm */
	/* dst = dst >> imm */
	/* dst = dst >> imm (signed) */
	case BPF_ALU | BPF_LSH | BPF_K:
	case BPF_ALU | BPF_RSH | BPF_K:
	case BPF_ALU | BPF_ARSH | BPF_K:
		if ( (imm > 31))
			return -EINVAL;
		if (imm)
			emit_a32_alu_i(dst_lo, imm, ctx, BPF_OP(code));
		if (!ctx->prog->aux->verifier_zext)
			emit_a32_mov_i(dst_hi, 0, ctx);
		break;
	/* dst = dst << imm */
	case BPF_ALU64 | BPF_LSH | BPF_K:
		if ( (imm > 63))
			return -EINVAL;
		emit_a32_lsh_i64(dst, imm, ctx);
		break;
	/* dst = dst >> imm */
	case BPF_ALU64 | BPF_RSH | BPF_K:
		if ( (imm > 63))
			return -EINVAL;
		emit_a32_rsh_i64(dst, imm, ctx);
		break;
	/* dst = dst << src */
	case BPF_ALU64 | BPF_LSH | BPF_X:
		emit_a32_lsh_r64(dst, src, ctx);
		break;
	/* dst = dst >> src */
	case BPF_ALU64 | BPF_RSH | BPF_X:
		emit_a32_rsh_r64(dst, src, ctx);
		break;
	/* dst = dst >> src (signed) */
	case BPF_ALU64 | BPF_ARSH | BPF_X:
		emit_a32_arsh_r64(dst, src, ctx);
		break;
	/* dst = dst >> imm (signed) */
	case BPF_ALU64 | BPF_ARSH | BPF_K:
		if ( (imm > 63))
			return -EINVAL;
		emit_a32_arsh_i64(dst, imm, ctx);
		break;
	/* dst = ~dst */
	case BPF_ALU | BPF_NEG:
		emit_a32_alu_i(dst_lo, 0, ctx, BPF_OP(code));
		if (!ctx->prog->aux->verifier_zext)
			emit_a32_mov_i(dst_hi, 0, ctx);
		break;
	/* dst = ~dst (64 bit) */
	case BPF_ALU64 | BPF_NEG:
		emit_a32_neg64(dst, ctx);
		break;
	/* dst = dst * src/imm */
	case BPF_ALU64 | BPF_MUL | BPF_X:
	case BPF_ALU64 | BPF_MUL | BPF_K:
		switch (BPF_SRC(code)) {
		case BPF_X:
			emit_a32_mul_r64(dst, src, ctx);
			break;
		case BPF_K:
			/* Move immediate value to the temporary register
			 * and then do the multiplication on it as this
			 * will sign-extend the immediate value into temp
			 * reg then it would be safe to do the operation
			 * on it.
			 */
			emit_a32_mov_se_i64(is64, tmp2, imm, ctx);
			emit_a32_mul_r64(dst, tmp2, ctx);
			break;
		}
		break;
	/* dst = htole(dst) */
	/* dst = htobe(dst) */
	case BPF_ALU | BPF_END | BPF_FROM_LE:
	case BPF_ALU | BPF_END | BPF_FROM_BE:
		rd = arm_bpf_get_reg64(dst, tmp, ctx);
		if (BPF_SRC(code) == BPF_FROM_LE)
			goto emit_bswap_uxt;
		switch (imm) {
		case 16:
			emit_rev16(rd[1], rd[1], ctx);
			goto emit_bswap_uxt;
		case 32:
			emit_rev32(rd[1], rd[1], ctx);
			goto emit_bswap_uxt;
		case 64:
			emit_rev32(ARM_LR, rd[1], ctx);
			emit_rev32(rd[1], rd[0], ctx);
			emit(ARM_MOV_R(rd[0], ARM_LR), ctx);
			break;
		}
		goto exit;
emit_bswap_uxt:
		switch (imm) {
		case 16:
			/* zero-extend 16 bits into 64 bits */
#if __LINUX_ARM_ARCH__ < 6
			emit_a32_mov_i(tmp2[1], 0xffff, ctx);
			emit(ARM_AND_R(rd[1], rd[1], tmp2[1]), ctx);
#else /* ARMv6+ */
			emit(ARM_UXTH(rd[1], rd[1]), ctx);
#endif
			if (!ctx->prog->aux->verifier_zext)
				emit(ARM_EOR_R(rd[0], rd[0], rd[0]), ctx);
			break;
		case 32:
			/* zero-extend 32 bits into 64 bits */
			if (!ctx->prog->aux->verifier_zext)
				emit(ARM_EOR_R(rd[0], rd[0], rd[0]), ctx);
			break;
		case 64:
			/* nop */
			break;
		}
exit:
		arm_bpf_put_reg64(dst, rd, ctx);
		break;
	/* dst = imm64 */
	case BPF_LD | BPF_IMM | BPF_DW:
	{
		u64 val = (u32)imm | (u64)insn[1].imm << 32;

		emit_a32_mov_i64(dst, val, ctx);

		return 1;
	}
	/* LDX: dst = *(size *)(src + off) */
	case BPF_LDX | BPF_MEM | BPF_W:
	case BPF_LDX | BPF_MEM | BPF_H:
	case BPF_LDX | BPF_MEM | BPF_B:
	case BPF_LDX | BPF_MEM | BPF_DW:
		rn = arm_bpf_get_reg32(src_lo, tmp2[1], ctx);
		emit_ldx_r(dst, rn, off, ctx, BPF_SIZE(code));
		break;
	/* ST: *(size *)(dst + off) = imm */
	case BPF_ST | BPF_MEM | BPF_W:
	case BPF_ST | BPF_MEM | BPF_H:
	case BPF_ST | BPF_MEM | BPF_B:
	case BPF_ST | BPF_MEM | BPF_DW:
		switch (BPF_SIZE(code)) {
		case BPF_DW:
			/* Sign-extend immediate value into temp reg */
			emit_a32_mov_se_i64(true, tmp2, imm, ctx);
			break;
		case BPF_W:
		case BPF_H:
		case BPF_B:
			emit_a32_mov_i(tmp2[1], imm, ctx);
			break;
		}
		emit_str_r(dst_lo, tmp2, off, ctx, BPF_SIZE(code));
		break;
	/* STX XADD: lock *(u32 *)(dst + off) += src */
	case BPF_STX | BPF_XADD | BPF_W:
	/* STX XADD: lock *(u64 *)(dst + off) += src */
	case BPF_STX | BPF_XADD | BPF_DW:
		goto notyet;
	/* STX: *(size *)(dst + off) = src */
	case BPF_STX | BPF_MEM | BPF_W:
	case BPF_STX | BPF_MEM | BPF_H:
	case BPF_STX | BPF_MEM | BPF_B:
	case BPF_STX | BPF_MEM | BPF_DW:
		rs = arm_bpf_get_reg64(src, tmp2, ctx);
		emit_str_r(dst_lo, rs, off, ctx, BPF_SIZE(code));
		break;
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
	case BPF_JMP | BPF_JEQ | BPF_X:
	case BPF_JMP | BPF_JGT | BPF_X:
	case BPF_JMP | BPF_JGE | BPF_X:
	case BPF_JMP | BPF_JNE | BPF_X:
	case BPF_JMP | BPF_JSGT | BPF_X:
	case BPF_JMP | BPF_JSGE | BPF_X:
	case BPF_JMP | BPF_JSET | BPF_X:
	case BPF_JMP | BPF_JLE | BPF_X:
	case BPF_JMP | BPF_JLT | BPF_X:
	case BPF_JMP | BPF_JSLT | BPF_X:
	case BPF_JMP | BPF_JSLE | BPF_X:
	case BPF_JMP32 | BPF_JEQ | BPF_X:
	case BPF_JMP32 | BPF_JGT | BPF_X:
	case BPF_JMP32 | BPF_JGE | BPF_X:
	case BPF_JMP32 | BPF_JNE | BPF_X:
	case BPF_JMP32 | BPF_JSGT | BPF_X:
	case BPF_JMP32 | BPF_JSGE | BPF_X:
	case BPF_JMP32 | BPF_JSET | BPF_X:
	case BPF_JMP32 | BPF_JLE | BPF_X:
	case BPF_JMP32 | BPF_JLT | BPF_X:
	case BPF_JMP32 | BPF_JSLT | BPF_X:
	case BPF_JMP32 | BPF_JSLE | BPF_X:
		/* Setup source registers */
		rm = arm_bpf_get_reg32(src_hi, tmp2[0], ctx);
		rn = arm_bpf_get_reg32(src_lo, tmp2[1], ctx);
		goto go_jmp;
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
	case BPF_JMP | BPF_JEQ | BPF_K:
	case BPF_JMP | BPF_JGT | BPF_K:
	case BPF_JMP | BPF_JGE | BPF_K:
	case BPF_JMP | BPF_JNE | BPF_K:
	case BPF_JMP | BPF_JSGT | BPF_K:
	case BPF_JMP | BPF_JSGE | BPF_K:
	case BPF_JMP | BPF_JSET | BPF_K:
	case BPF_JMP | BPF_JLT | BPF_K:
	case BPF_JMP | BPF_JLE | BPF_K:
	case BPF_JMP | BPF_JSLT | BPF_K:
	case BPF_JMP | BPF_JSLE | BPF_K:
	case BPF_JMP32 | BPF_JEQ | BPF_K:
	case BPF_JMP32 | BPF_JGT | BPF_K:
	case BPF_JMP32 | BPF_JGE | BPF_K:
	case BPF_JMP32 | BPF_JNE | BPF_K:
	case BPF_JMP32 | BPF_JSGT | BPF_K:
	case BPF_JMP32 | BPF_JSGE | BPF_K:
	case BPF_JMP32 | BPF_JSET | BPF_K:
	case BPF_JMP32 | BPF_JLT | BPF_K:
	case BPF_JMP32 | BPF_JLE | BPF_K:
	case BPF_JMP32 | BPF_JSLT | BPF_K:
	case BPF_JMP32 | BPF_JSLE | BPF_K:
		if (off == 0)
			break;
		rm = tmp2[0];
		rn = tmp2[1];
		/* Sign-extend immediate value */
		emit_a32_mov_se_i64(true, tmp2, imm, ctx);
go_jmp:
		/* Setup destination register */
		rd = arm_bpf_get_reg64(dst, tmp, ctx);

		/* Check for the condition */
		emit_ar_r(rd[0], rd[1], rm, rn, ctx, BPF_OP(code),
			  BPF_CLASS(code) == BPF_JMP);

		/* Setup JUMP instruction */
		jmp_offset = bpf2a32_offset(i+off, i, ctx);
		switch (BPF_OP(code)) {
		case BPF_JNE:
		case BPF_JSET:
			_emit(ARM_COND_NE, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JEQ:
			_emit(ARM_COND_EQ, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JGT:
			_emit(ARM_COND_HI, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JGE:
			_emit(ARM_COND_CS, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JSGT:
			_emit(ARM_COND_LT, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JSGE:
			_emit(ARM_COND_GE, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JLE:
			_emit(ARM_COND_LS, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JLT:
			_emit(ARM_COND_CC, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JSLT:
			_emit(ARM_COND_LT, ARM_B(jmp_offset), ctx);
			break;
		case BPF_JSLE:
			_emit(ARM_COND_GE, ARM_B(jmp_offset), ctx);
			break;
		}
		break;
	/* JMP OFF */
	case BPF_JMP | BPF_JA:
	{
		if (off == 0)
			break;
		jmp_offset = bpf2a32_offset(i+off, i, ctx);
		check_imm24(jmp_offset);
		emit(ARM_B(jmp_offset), ctx);
		break;
	}
	/* function call */
	case BPF_JMP | BPF_CALL:
	{
		const s8 *r0 = bpf2a32[BPF_REG_0];
		const s8 *r1 = bpf2a32[BPF_REG_1];
		const s8 *r2 = bpf2a32[BPF_REG_2];
		const s8 *r3 = bpf2a32[BPF_REG_3];
		const s8 *r4 = bpf2a32[BPF_REG_4];
		const s8 *r5 = bpf2a32[BPF_REG_5];
		const u32 func = (u32)__bpf_call_base + (u32)imm;

		emit_a32_mov_r64(true, r0, r1, ctx);
		emit_a32_mov_r64(true, r1, r2, ctx);
		emit_push_r64(r5, ctx);
		emit_push_r64(r4, ctx);
		emit_push_r64(r3, ctx);

		emit_a32_mov_i(tmp[1], func, ctx);
		emit_blx_r(tmp[1], ctx);

		emit(ARM_ADD_I(ARM_SP, ARM_SP, imm8m(24)), ctx); // callee clean
		break;
	}
	/* function return */
	case BPF_JMP | BPF_EXIT:
		/* Optimization: when last instruction is EXIT
		 * simply fallthrough to epilogue.
		 */
		if (i == ctx->prog->num_insts - 1)
			break;
		jmp_offset = epilogue_offset(ctx);
		check_imm24(jmp_offset);
		emit(ARM_B(jmp_offset), ctx);
		break;
		/* tail call */
	case BPF_JMP | BPF_TAIL_CALL:
		printf("tail call not supported\n");
		return -EFAULT;
notyet:
		printf("*** NOT YET: opcode %02x ***\n", code);
		return -EFAULT;
	default:
		printf("unknown opcode %02x\n", code);
		return -EINVAL;
	}

	if (ctx->flags & FLAG_IMM_OVERFLOW)
		/*
		 * this instruction generated an overflow when
		 * trying to access the literal pool, so
		 * delegate this filter to the kernel interpreter.
		 */
		return -1;
	return 0;
}

static int build_body(struct jit_ctx *ctx)
{
	const struct ebpf_vm *prog = ctx->prog;
	unsigned int i;

	for (i = 0; i < prog->num_insts; i++) {
		const struct bpf_insn *insn = &(prog->insnsi[i]);
		int ret;

		ret = build_insn(insn, ctx);

		/* It's used with loading the 64 bit immediate value. */
		if (ret > 0) {
			i++;
			if (ctx->target == NULL)
				ctx->offsets[i] = ctx->idx;
			continue;
		}

		if (ctx->target == NULL)
			ctx->offsets[i] = ctx->idx;

		/* If unsuccesfull, return with error code */
		if (ret)
			return ret;
	}
	return 0;
}

static int validate_code(struct jit_ctx *ctx)
{
	int i;

	for (i = 0; i < ctx->idx; i++) {
		if (ctx->target[i] == __opcode_to_mem_arm(ARM_INST_UDF))
			return -1;
	}

	return 0;
}

void bpf_jit_compile(struct ebpf_vm *prog)
{
	/* Nothing to do here. We support Internal BPF. */
}

bool bpf_jit_needs_zext(void)
{
	return true;
}

struct ebpf_vm *linux_bpf_int_jit_compile(struct ebpf_vm *prog)
{
	struct ebpf_vm *tmp, *orig_prog = prog;
	struct bpf_binary_header *header;
	struct jit_ctx ctx;
	unsigned int tmp_idx;
	unsigned int image_size;
	u8 *image_ptr;

	memset(&ctx, 0, sizeof(ctx));
	ctx.prog = prog;
	// pa: prog is altered by ebpf_vm
	// In kernel: #define CPU_ARCH_UNKNOWN	0
	// ctx.cpu_architecture = 0;
	// pa: no longer needed

	/* Not able to allocate memory for offsets[] , then
	 * we must fall back to the interpreter
	 */
	// ctx.target = (u32* )buffer;
	ctx.offsets = calloc(prog->num_insts, sizeof(int));
	// pa: TODO: what's length is needed?
	// if (ctx.offsets == NULL) {
	// 	prog = orig_prog;
	// 	goto out;
	// }

	/* 1) fake pass to find in the length of the JITed code,
	 * to compute ctx->offsets and other context variables
	 * needed to compute final JITed code.
	 * Also, calculate random starting pointer/start of JITed code
	 * which is prefixed by random number of fault instructions.
	 *
	 * If the first pass fails then there is no chance of it
	 * being successful in the second pass, so just fall back
	 * to the interpreter.
	 */
	// if (build_body(&ctx)) {
	// 	prog = orig_prog;
	// 	goto out_off;
	// }

	tmp_idx = ctx.idx;
	build_prologue(&ctx);
	ctx.prologue_bytes = (ctx.idx - tmp_idx) * 4;

	ctx.epilogue_offset = ctx.idx;

	/* there's nothing about the epilogue on ARMv7 */
	build_epilogue(&ctx);
	/* Now we can get the actual image size of the JITed arm code.
	 * Currently, we are not considering the THUMB-2 instructions
	 * for jit, although it can decrease the size of the image.
	 *
	 * As each arm instruction is of length 32bit, we are translating
	 * number of JITed intructions into the size required to store these
	 * JITed code.
	 */
	image_size = sizeof(u32) * ctx.idx;

	/* Now we know the size of the structure to make */
	header = bpf_jit_binary_alloc(image_size, &image_ptr,
				      sizeof(u32), jit_fill_hole);
	/* Not able to allocate memory for the structure then
	 * we must fall back to the interpretation
	 */
	if (header == NULL) {
		prog = orig_prog;
		goto out_imms;
	}

	/* 2.) Actual pass to generate final JIT code */
	ctx.target = (u32 *) image_ptr;
	ctx.idx = 0;

	build_prologue(&ctx);

	/* If building the body of the JITed code fails somehow,
	 * we fall back to the interpretation.
	 */
	if (build_body(&ctx) < 0) {
		image_ptr = NULL;
		bpf_jit_free_exec(header);
		prog = orig_prog;
		goto out_imms;
	}
	build_epilogue(&ctx);

	/* 3.) Extra pass to validate JITed Code */
	if (validate_code(&ctx)) {
		image_ptr = NULL;
		bpf_jit_free_exec(header);
		prog = orig_prog;
		goto out_imms;
	}
	// flush_icache_range((u32)header, (u32)(ctx.target + ctx.idx));

	/* there are 2 passes here */
	bpf_jit_dump(prog->num_insts, image_size, 2, ctx.target);

	// bpf_jit_binary_lock_ro(header);
	prog->bpf_func = (void *)ctx.target;
	prog->jited = 1;
	prog->jited_len = image_size;

out_imms:
out_off:
	 free(ctx.offsets);
out:
	return prog;
}

int
ebpf_translate_arm32(struct ebpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg)
{
    int result = -1;
	struct ebpf_vm * new_vm;
	
	new_vm = linux_bpf_int_jit_compile(vm);
    return result;
}

// int ebpf_translate_arm32(struct ebpf_vm *vm, uint8_t *buffer, size_t *size,char **errmsg)
// {
// 	struct jit_state state;
// 	int result = -1;

// 	state.offset = 0;
// 	state.size = *size;
// 	state.buf = buffer;
// 	state.pc_locs = calloc(EBPF_MAX_INSTS + 1, sizeof(state.pc_locs[0]));
// 	state.jumps = calloc(EBPF_MAX_INSTS, sizeof(state.jumps[0]));
// 	state.num_jumps = 0;

// 	if (translate(vm, &state, errmsg) < 0) {
// 		goto out;
// 	}

// 	if (state.num_jumps == EBPF_MAX_INSTS) {
// 		*errmsg = ebpf_error("Excessive number of jump targets");
// 		goto out;
// 	}

// 	if (state.offset == state.size) {
// 		*errmsg = ebpf_error("Target buffer too small");
// 		goto out;
// 	}

// 	resolve_jumps(&state);
// 	result = 0;

// 	*size = state.offset;

// out:
// 	free(state.pc_locs);
// 	free(state.jumps);
// 	return result;
// }

// static int
// translate(struct ebpf_vm* vm, struct jit_state* state, char** errmsg)
// {
//     int i;

//     emit_function_prologue(state, EBPF_STACK_SIZE);

//     for (i = 0; i < vm->num_insts; i++) {
//         struct ebpf_inst inst = ebpf_fetch_instruction(vm, i);
//         state->pc_locs[i] = state->offset;

//         enum Registers dst = map_register(inst.dst);
//         enum Registers src = map_register(inst.src);
//         uint8_t opcode = inst.opcode;
//         uint32_t target_pc = i + inst.offset + 1;

//         int sixty_four = is_alu64_op(&inst);

//         if (is_imm_op(&inst) && !is_simple_imm(&inst)) {
//             emit_movewide_immediate(state, sixty_four, temp_register, (int64_t)inst.imm);
//             src = temp_register;
//             opcode = to_reg_op(opcode);
//         }

//         switch (opcode) {
//         case EBPF_OP_ADD_IMM:
//         case EBPF_OP_ADD64_IMM:
//         case EBPF_OP_SUB_IMM:
//         case EBPF_OP_SUB64_IMM:
//             emit_addsub_immediate(state, sixty_four, to_addsub_opcode(opcode), dst, dst, inst.imm);
//             break;
//         case EBPF_OP_ADD_REG:
//         case EBPF_OP_ADD64_REG:
//         case EBPF_OP_SUB_REG:
//         case EBPF_OP_SUB64_REG:
//             emit_addsub_register(state, sixty_four, to_addsub_opcode(opcode), dst, dst, src);
//             break;
//         case EBPF_OP_LSH_REG:
//         case EBPF_OP_RSH_REG:
//         case EBPF_OP_ARSH_REG:
//         case EBPF_OP_LSH64_REG:
//         case EBPF_OP_RSH64_REG:
//         case EBPF_OP_ARSH64_REG:
//             /* TODO: CHECK imm is small enough.  */
//             emit_dataprocessing_twosource(state, sixty_four, to_dp2_opcode(opcode), dst, dst, src);
//             break;
//         case EBPF_OP_MUL_REG:
//         case EBPF_OP_MUL64_REG:
//             emit_dataprocessing_threesource(state, sixty_four, DP3_MADD, dst, dst, src, RZ);
//             break;
//         case EBPF_OP_DIV_REG:
//         case EBPF_OP_MOD_REG:
//         case EBPF_OP_DIV64_REG:
//         case EBPF_OP_MOD64_REG:
//             divmod(state, opcode, dst, dst, src);
//             break;
//         case EBPF_OP_OR_REG:
//         case EBPF_OP_AND_REG:
//         case EBPF_OP_XOR_REG:
//         case EBPF_OP_OR64_REG:
//         case EBPF_OP_AND64_REG:
//         case EBPF_OP_XOR64_REG:
//             emit_logical_register(state, sixty_four, to_logical_opcode(opcode), dst, dst, src);
//             break;
//         case EBPF_OP_NEG:
//         case EBPF_OP_NEG64:
//             emit_addsub_register(state, sixty_four, AS_SUB, dst, RZ, src);
//             break;
//         case EBPF_OP_MOV_IMM:
//         case EBPF_OP_MOV64_IMM:
//             emit_movewide_immediate(state, sixty_four, dst, (int64_t)inst.imm);
//             break;
//         case EBPF_OP_MOV_REG:
//         case EBPF_OP_MOV64_REG:
//             emit_logical_register(state, sixty_four, LOG_ORR, dst, RZ, src);
//             break;
//         case EBPF_OP_LE:
// #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
//             /* No-op */
// #else
//             emit_dataprocessing_onesource(state, sixty_four, to_dp1_opcode(opcode, inst.imm), dst, dst);
// #endif
//             if (inst.imm == 16) {
//                 /* UXTH dst, dst. */
//                 emit_instruction(state, 0x53003c00 | (dst << 5) | dst);
//             }
//             break;
//         case EBPF_OP_BE:
// #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
//             emit_dataprocessing_onesource(state, sixty_four, to_dp1_opcode(opcode, inst.imm), dst, dst);
// #else
//             /* No-op. */
// #endif
//             if (inst.imm == 16) {
//                 /* UXTH dst, dst. */
//                 emit_instruction(state, 0x53003c00 | (dst << 5) | dst);
//             }
//             break;

//         /* TODO use 8 bit immediate when possible */
//         case EBPF_OP_JA:
//             emit_unconditionalbranch_immediate(state, UBR_B, target_pc);
//             break;
//         case EBPF_OP_JEQ_IMM:
//         case EBPF_OP_JGT_IMM:
//         case EBPF_OP_JGE_IMM:
//         case EBPF_OP_JLT_IMM:
//         case EBPF_OP_JLE_IMM:
//         case EBPF_OP_JNE_IMM:
//         case EBPF_OP_JSGT_IMM:
//         case EBPF_OP_JSGE_IMM:
//         case EBPF_OP_JSLT_IMM:
//         case EBPF_OP_JSLE_IMM:
//         case EBPF_OP_JEQ32_IMM:
//         case EBPF_OP_JGT32_IMM:
//         case EBPF_OP_JGE32_IMM:
//         case EBPF_OP_JLT32_IMM:
//         case EBPF_OP_JLE32_IMM:
//         case EBPF_OP_JNE32_IMM:
//         case EBPF_OP_JSGT32_IMM:
//         case EBPF_OP_JSGE32_IMM:
//         case EBPF_OP_JSLT32_IMM:
//         case EBPF_OP_JSLE32_IMM:
//             emit_addsub_immediate(state, sixty_four, AS_SUBS, RZ, dst, inst.imm);
//             emit_conditionalbranch_immediate(state, to_condition(opcode), target_pc);
//             break;
//         case EBPF_OP_JEQ_REG:
//         case EBPF_OP_JGT_REG:
//         case EBPF_OP_JGE_REG:
//         case EBPF_OP_JLT_REG:
//         case EBPF_OP_JLE_REG:
//         case EBPF_OP_JNE_REG:
//         case EBPF_OP_JSGT_REG:
//         case EBPF_OP_JSGE_REG:
//         case EBPF_OP_JSLT_REG:
//         case EBPF_OP_JSLE_REG:
//         case EBPF_OP_JEQ32_REG:
//         case EBPF_OP_JGT32_REG:
//         case EBPF_OP_JGE32_REG:
//         case EBPF_OP_JLT32_REG:
//         case EBPF_OP_JLE32_REG:
//         case EBPF_OP_JNE32_REG:
//         case EBPF_OP_JSGT32_REG:
//         case EBPF_OP_JSGE32_REG:
//         case EBPF_OP_JSLT32_REG:
//         case EBPF_OP_JSLE32_REG:
//             emit_addsub_register(state, sixty_four, AS_SUBS, RZ, dst, src);
//             emit_conditionalbranch_immediate(state, to_condition(opcode), target_pc);
//             break;
//         case EBPF_OP_JSET_REG:
//         case EBPF_OP_JSET32_REG:
//             emit_logical_register(state, sixty_four, LOG_ANDS, RZ, dst, src);
//             emit_conditionalbranch_immediate(state, to_condition(opcode), target_pc);
//             break;
//         case EBPF_OP_CALL:
//             emit_call(state, (uintptr_t)vm->ext_funcs[inst.imm]);
//             if (inst.imm == vm->unwind_stack_extension_index) {
//                 emit_addsub_immediate(state, true, AS_SUBS, RZ, map_register(0), 0);
//                 emit_conditionalbranch_immediate(state, COND_EQ, TARGET_PC_EXIT);
//             }
//             break;
//         case EBPF_OP_EXIT:
//             if (i != vm->num_insts - 1) {
//                 emit_unconditionalbranch_immediate(state, UBR_B, TARGET_PC_EXIT);
//             }
//             break;

//         case EBPF_OP_STXW:
//         case EBPF_OP_STXH:
//         case EBPF_OP_STXB:
//         case EBPF_OP_STXDW: {
//             enum Registers tmp = dst;
//             dst = src;
//             src = tmp;
//         }
//             /* fallthrough: */
//         case EBPF_OP_LDXW:
//         case EBPF_OP_LDXH:
//         case EBPF_OP_LDXB:
//         case EBPF_OP_LDXDW:
//             if (inst.offset >= -256 && inst.offset < 256) {
//                 emit_loadstore_immediate(state, to_loadstore_opcode(opcode), dst, src, inst.offset);
//             } else {
//                 emit_movewide_immediate(state, true, offset_register, inst.offset);
//                 emit_loadstore_register(state, to_loadstore_opcode(opcode), dst, src, offset_register);
//             }
//             break;

//         case EBPF_OP_LDDW: {
//             struct ebpf_inst inst2 = ebpf_fetch_instruction(vm, ++i);
//             uint64_t imm = (uint32_t)inst.imm | ((uint64_t)inst2.imm << 32);
//             emit_movewide_immediate(state, true, dst, imm);
//             break;
//         }

//         case EBPF_OP_MUL_IMM:
//         case EBPF_OP_MUL64_IMM:
//         case EBPF_OP_DIV_IMM:
//         case EBPF_OP_MOD_IMM:
//         case EBPF_OP_DIV64_IMM:
//         case EBPF_OP_MOD64_IMM:
//         case EBPF_OP_STW:
//         case EBPF_OP_STH:
//         case EBPF_OP_STB:
//         case EBPF_OP_STDW:
//         case EBPF_OP_JSET_IMM:
//         case EBPF_OP_JSET32_IMM:
//         case EBPF_OP_OR_IMM:
//         case EBPF_OP_AND_IMM:
//         case EBPF_OP_XOR_IMM:
//         case EBPF_OP_OR64_IMM:
//         case EBPF_OP_AND64_IMM:
//         case EBPF_OP_XOR64_IMM:
//         case EBPF_OP_LSH_IMM:
//         case EBPF_OP_RSH_IMM:
//         case EBPF_OP_ARSH_IMM:
//         case EBPF_OP_LSH64_IMM:
//         case EBPF_OP_RSH64_IMM:
//         case EBPF_OP_ARSH64_IMM:
//             *errmsg = ebpf_error("Unexpected instruction at PC %d: opcode %02x, immediate %08x", i, opcode, inst.imm);
//             return -1;
//         default:
//             *errmsg = ebpf_error("Unknown instruction at PC %d: opcode %02x", i, opcode);
//             return -1;
//         }
//     }

//     emit_function_epilogue(state);

//     return 0;
// }