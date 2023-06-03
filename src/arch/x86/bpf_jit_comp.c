// SPDX-License-Identifier: GPL-2.0-only
/*
 * bpf_jit_comp.c: BPF JIT compiler
 *
 * Copyright (C) 2011-2013 Eric Dumazet (eric.dumazet@gmail.com)
 * Internal BPF Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 */
#include "type-fixes.h"
#include "linux-errno.h"
#include "linux-bpf.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef __ASSEMBLY__

#ifdef __i386__
/* this struct defines the way the registers are stored on the
   stack during a system call. */

struct pt_regs {
	long ebx;
	long ecx;
	long edx;
	long esi;
	long edi;
	long ebp;
	long eax;
	int  xds;
	int  xes;
	int  xfs;
	int  xgs;
	long orig_eax;
	long eip;
	int  xcs;
	long eflags;
	long esp;
	int  xss;
};


#else /* __i386__ */


struct pt_regs {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
	unsigned long orig_rax;
/* Return frame for iretq */
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
/* top of stack page */
};

struct exception_table_entry {
	int insn, fixup, data;
};

#endif /* !__i386__ */

#endif /* !__ASSEMBLY__ */

static u8 *emit_code(u8 *ptr, u32 bytes, unsigned int len)
{
	if (len == 1)
		*ptr = bytes;
	else if (len == 2)
		*(u16 *)ptr = bytes;
	else {
		*(u32 *)ptr = bytes;
		barrier();
	}
	return ptr + len;
}

#define EMIT(bytes, len) \
	do { prog = emit_code(prog, bytes, len); cnt += len; } while (0)

#define EMIT1(b1)		EMIT(b1, 1)
#define EMIT2(b1, b2)		EMIT((b1) + ((b2) << 8), 2)
#define EMIT3(b1, b2, b3)	EMIT((b1) + ((b2) << 8) + ((b3) << 16), 3)
#define EMIT4(b1, b2, b3, b4)   EMIT((b1) + ((b2) << 8) + ((b3) << 16) + ((b4) << 24), 4)

#define EMIT1_off32(b1, off) \
	do { EMIT1(b1); EMIT(off, 4); } while (0)
#define EMIT2_off32(b1, b2, off) \
	do { EMIT2(b1, b2); EMIT(off, 4); } while (0)
#define EMIT3_off32(b1, b2, b3, off) \
	do { EMIT3(b1, b2, b3); EMIT(off, 4); } while (0)
#define EMIT4_off32(b1, b2, b3, b4, off) \
	do { EMIT4(b1, b2, b3, b4); EMIT(off, 4); } while (0)

static bool is_imm8(int value)
{
	return value <= 127 && value >= -128;
}

static bool is_simm32(s64 value)
{
	return value == (s64)(s32)value;
}

static bool is_uimm32(u64 value)
{
	return value == (u64)(u32)value;
}

/* mov dst, src */
#define EMIT_mov(DST, SRC)								 \
	do {										 \
		if (DST != SRC)								 \
			EMIT3(add_2mod(0x48, DST, SRC), 0x89, add_2reg(0xC0, DST, SRC)); \
	} while (0)

static int bpf_size_to_x86_bytes(int bpf_size)
{
	if (bpf_size == BPF_W)
		return 4;
	else if (bpf_size == BPF_H)
		return 2;
	else if (bpf_size == BPF_B)
		return 1;
	else if (bpf_size == BPF_DW)
		return 4; /* imm32 */
	else
		return 0;
}

/*
 * List of x86 cond jumps opcodes (. + s8)
 * Add 0x10 (and an extra 0x0f) to generate far jumps (. + s32)
 */
#define X86_JB  0x72
#define X86_JAE 0x73
#define X86_JE  0x74
#define X86_JNE 0x75
#define X86_JBE 0x76
#define X86_JA  0x77
#define X86_JL  0x7C
#define X86_JGE 0x7D
#define X86_JLE 0x7E
#define X86_JG  0x7F

/* Pick a register outside of BPF range for JIT internal work */
#define AUX_REG (MAX_BPF_JIT_REG + 1)
#define X86_REG_R9 (MAX_BPF_JIT_REG + 2)

/*
 * The following table maps BPF registers to x86-64 registers.
 *
 * x86-64 register R12 is unused, since if used as base address
 * register in load/store instructions, it always needs an
 * extra byte of encoding and is callee saved.
 *
 * x86-64 register R9 is not used by BPF programs, but can be used by BPF
 * trampoline. x86-64 register R10 is used for blinding (if enabled).
 */
static const int reg2hex[] = {
	[BPF_REG_0] = 0,  /* RAX */
	[BPF_REG_1] = 7,  /* RDI */
	[BPF_REG_2] = 6,  /* RSI */
	[BPF_REG_3] = 2,  /* RDX */
	[BPF_REG_4] = 1,  /* RCX */
	[BPF_REG_5] = 0,  /* R8  */
	[BPF_REG_6] = 3,  /* RBX callee saved */
	[BPF_REG_7] = 5,  /* R13 callee saved */
	[BPF_REG_8] = 6,  /* R14 callee saved */
	[BPF_REG_9] = 7,  /* R15 callee saved */
	[BPF_REG_FP] = 5, /* RBP readonly */
	[BPF_REG_AX] = 2, /* R10 temp register */
	[AUX_REG] = 3,    /* R11 temp register */
	[X86_REG_R9] = 1, /* R9 register, 6th function argument */
};

static const int reg2pt_regs[] = {
	[BPF_REG_0] = offsetof(struct pt_regs, rax),
	[BPF_REG_1] = offsetof(struct pt_regs, rdi),
	[BPF_REG_2] = offsetof(struct pt_regs, rsi),
	[BPF_REG_3] = offsetof(struct pt_regs, rdx),
	[BPF_REG_4] = offsetof(struct pt_regs, rcx),
	[BPF_REG_5] = offsetof(struct pt_regs, r8),
	[BPF_REG_6] = offsetof(struct pt_regs, rbx),
	[BPF_REG_7] = offsetof(struct pt_regs, r13),
	[BPF_REG_8] = offsetof(struct pt_regs, r14),
	[BPF_REG_9] = offsetof(struct pt_regs, r15),
};

/*
 * is_ereg() == true if BPF register 'reg' maps to x86-64 r8..r15
 * which need extra byte of encoding.
 * rax,rcx,...,rbp have simpler encoding
 */
static bool is_ereg(u32 reg)
{
	return (1 << reg) & (BIT(BPF_REG_5) |
			     BIT(AUX_REG) |
			     BIT(BPF_REG_7) |
			     BIT(BPF_REG_8) |
			     BIT(BPF_REG_9) |
			     BIT(X86_REG_R9) |
			     BIT(BPF_REG_AX));
}

/*
 * is_ereg_8l() == true if BPF register 'reg' is mapped to access x86-64
 * lower 8-bit registers dil,sil,bpl,spl,r8b..r15b, which need extra byte
 * of encoding. al,cl,dl,bl have simpler encoding.
 */
static bool is_ereg_8l(u32 reg)
{
	return is_ereg(reg) ||
	    (1 << reg) & (BIT(BPF_REG_1) |
			  BIT(BPF_REG_2) |
			  BIT(BPF_REG_FP));
}

static bool is_axreg(u32 reg)
{
	return reg == BPF_REG_0;
}

/* Add modifiers if 'reg' maps to x86-64 registers R8..R15 */
static u8 add_1mod(u8 byte, u32 reg)
{
	if (is_ereg(reg))
		byte |= 1;
	return byte;
}

static u8 add_2mod(u8 byte, u32 r1, u32 r2)
{
	if (is_ereg(r1))
		byte |= 1;
	if (is_ereg(r2))
		byte |= 4;
	return byte;
}

/* Encode 'dst_reg' register into x86-64 opcode 'byte' */
static u8 add_1reg(u8 byte, u32 dst_reg)
{
	return byte + reg2hex[dst_reg];
}

/* Encode 'dst_reg' and 'src_reg' registers into x86-64 opcode 'byte' */
static u8 add_2reg(u8 byte, u32 dst_reg, u32 src_reg)
{
	return byte + reg2hex[dst_reg] + (reg2hex[src_reg] << 3);
}

static void jit_fill_hole(void *area, unsigned int size)
{
	/* Fill whole space with INT3 instructions */
	memset(area, 0xcc, size);
}

struct jit_context {
	int cleanup_addr; /* Epilogue code offset */
};

/* Maximum number of bytes emitted while JITing one eBPF insn */
#define BPF_MAX_INSN_SIZE	128
#define BPF_INSN_SAFETY		64

/* Number of bytes emit_patch() needs to generate instructions */
#define X86_PATCH_SIZE		5

#define PROLOGUE_SIZE		25

/*
 * Emit x86-64 prologue code for BPF program and check its size.
 * bpf_tail_call helper will skip it while jumping into another program
 */
static void emit_prologue(u8 **pprog, u32 stack_depth, bool ebpf_from_cbpf)
{
	u8 *prog = *pprog;
	int cnt = X86_PATCH_SIZE;

	/* BPF trampoline can be made to work without these nops,
	 * but let's waste 5 bytes for now and optimize later
	 */
	// memcpy(prog, ideal_nops[NOP_ATOMIC5], cnt);
	// prog += cnt;
	EMIT1(0x55);             /* push rbp */
	EMIT3(0x48, 0x89, 0xE5); /* mov rbp, rsp */
	/* sub rsp, rounded_stack_depth */
	EMIT3_off32(0x48, 0x81, 0xEC, round_up(stack_depth, 8));
	EMIT1(0x53);             /* push rbx */
	EMIT2(0x41, 0x55);       /* push r13 */
	EMIT2(0x41, 0x56);       /* push r14 */
	EMIT2(0x41, 0x57);       /* push r15 */
	if (!ebpf_from_cbpf) {
		/* zero init tail_call_cnt */
		EMIT2(0x6a, 0x00);
		BUILD_BUG_ON(cnt != PROLOGUE_SIZE);
	}
	*pprog = prog;
}

static int emit_patch(u8 **pprog, void *func, void *ip, u8 opcode)
{
	u8 *prog = *pprog;
	int cnt = 0;
	s64 offset;

	offset = func - (ip + X86_PATCH_SIZE);
	if (!is_simm32(offset)) {
		pr_err("Target call %p is out of range\n", func);
		return -ERANGE;
	}
	EMIT1_off32(opcode, offset);
	*pprog = prog;
	return 0;
}

static int emit_call(u8 **pprog, void *func, void *ip)
{
	return emit_patch(pprog, func, ip, 0xE8);
}

static int emit_jump(u8 **pprog, void *func, void *ip)
{
	return emit_patch(pprog, func, ip, 0xE9);
}

static void emit_mov_imm32(u8 **pprog, bool sign_propagate,
			   u32 dst_reg, const u32 imm32)
{
	u8 *prog = *pprog;
	u8 b1, b2, b3;
	int cnt = 0;

	/*
	 * Optimization: if imm32 is positive, use 'mov %eax, imm32'
	 * (which zero-extends imm32) to save 2 bytes.
	 */
	if (sign_propagate && (s32)imm32 < 0) {
		/* 'mov %rax, imm32' sign extends imm32 */
		b1 = add_1mod(0x48, dst_reg);
		b2 = 0xC7;
		b3 = 0xC0;
		EMIT3_off32(b1, b2, add_1reg(b3, dst_reg), imm32);
		goto done;
	}

	/*
	 * Optimization: if imm32 is zero, use 'xor %eax, %eax'
	 * to save 3 bytes.
	 */
	if (imm32 == 0) {
		if (is_ereg(dst_reg))
			EMIT1(add_2mod(0x40, dst_reg, dst_reg));
		b2 = 0x31; /* xor */
		b3 = 0xC0;
		EMIT2(b2, add_2reg(b3, dst_reg, dst_reg));
		goto done;
	}

	/* mov %eax, imm32 */
	if (is_ereg(dst_reg))
		EMIT1(add_1mod(0x40, dst_reg));
	EMIT1_off32(add_1reg(0xB8, dst_reg), imm32);
done:
	*pprog = prog;
}

static void emit_mov_imm64(u8 **pprog, u32 dst_reg,
			   const u32 imm32_hi, const u32 imm32_lo)
{
	u8 *prog = *pprog;
	int cnt = 0;

	if (is_uimm32(((u64)imm32_hi << 32) | (u32)imm32_lo)) {
		/*
		 * For emitting plain u32, where sign bit must not be
		 * propagated LLVM tends to load imm64 over mov32
		 * directly, so save couple of bytes by just doing
		 * 'mov %eax, imm32' instead.
		 */
		emit_mov_imm32(&prog, false, dst_reg, imm32_lo);
	} else {
		/* movabsq %rax, imm64 */
		EMIT2(add_1mod(0x48, dst_reg), add_1reg(0xB8, dst_reg));
		EMIT(imm32_lo, 4);
		EMIT(imm32_hi, 4);
	}

	*pprog = prog;
}

static void emit_mov_reg(u8 **pprog, bool is64, u32 dst_reg, u32 src_reg)
{
	u8 *prog = *pprog;
	int cnt = 0;

	if (is64) {
		/* mov dst, src */
		EMIT_mov(dst_reg, src_reg);
	} else {
		/* mov32 dst, src */
		if (is_ereg(dst_reg) || is_ereg(src_reg))
			EMIT1(add_2mod(0x40, dst_reg, src_reg));
		EMIT2(0x89, add_2reg(0xC0, dst_reg, src_reg));
	}

	*pprog = prog;
}

/* LDX: dst_reg = *(u8*)(src_reg + off) */
static void emit_ldx(u8 **pprog, u32 size, u32 dst_reg, u32 src_reg, int off)
{
	u8 *prog = *pprog;
	int cnt = 0;

	switch (size) {
	case BPF_B:
		/* Emit 'movzx rax, byte ptr [rax + off]' */
		EMIT3(add_2mod(0x48, src_reg, dst_reg), 0x0F, 0xB6);
		break;
	case BPF_H:
		/* Emit 'movzx rax, word ptr [rax + off]' */
		EMIT3(add_2mod(0x48, src_reg, dst_reg), 0x0F, 0xB7);
		break;
	case BPF_W:
		/* Emit 'mov eax, dword ptr [rax+0x14]' */
		if (is_ereg(dst_reg) || is_ereg(src_reg))
			EMIT2(add_2mod(0x40, src_reg, dst_reg), 0x8B);
		else
			EMIT1(0x8B);
		break;
	case BPF_DW:
		/* Emit 'mov rax, qword ptr [rax+0x14]' */
		EMIT2(add_2mod(0x48, src_reg, dst_reg), 0x8B);
		break;
	}
	/*
	 * If insn->off == 0 we can save one extra byte, but
	 * special case of x86 R13 which always needs an offset
	 * is not worth the hassle
	 */
	if (is_imm8(off))
		EMIT2(add_2reg(0x40, src_reg, dst_reg), off);
	else
		EMIT1_off32(add_2reg(0x80, src_reg, dst_reg), off);
	*pprog = prog;
}

/* STX: *(u8*)(dst_reg + off) = src_reg */
static void emit_stx(u8 **pprog, u32 size, u32 dst_reg, u32 src_reg, int off)
{
	u8 *prog = *pprog;
	int cnt = 0;

	switch (size) {
	case BPF_B:
		/* Emit 'mov byte ptr [rax + off], al' */
		if (is_ereg(dst_reg) || is_ereg_8l(src_reg))
			/* Add extra byte for eregs or SIL,DIL,BPL in src_reg */
			EMIT2(add_2mod(0x40, dst_reg, src_reg), 0x88);
		else
			EMIT1(0x88);
		break;
	case BPF_H:
		if (is_ereg(dst_reg) || is_ereg(src_reg))
			EMIT3(0x66, add_2mod(0x40, dst_reg, src_reg), 0x89);
		else
			EMIT2(0x66, 0x89);
		break;
	case BPF_W:
		if (is_ereg(dst_reg) || is_ereg(src_reg))
			EMIT2(add_2mod(0x40, dst_reg, src_reg), 0x89);
		else
			EMIT1(0x89);
		break;
	case BPF_DW:
		EMIT2(add_2mod(0x48, dst_reg, src_reg), 0x89);
		break;
	}
	if (is_imm8(off))
		EMIT2(add_2reg(0x40, dst_reg, src_reg), off);
	else
		EMIT1_off32(add_2reg(0x80, dst_reg, src_reg), off);
	*pprog = prog;
}

static int do_jit(struct bpf_prog *bpf_prog, int *addrs, u8 *image,
		  int oldproglen, struct jit_context *ctx)
{
	struct bpf_insn *insn = bpf_prog->insnsi;
	int insn_cnt = bpf_prog->len;
	bool seen_exit = false;
	u8 temp[BPF_MAX_INSN_SIZE + BPF_INSN_SAFETY];
	int i, cnt = 0, excnt = 0;
	int proglen = 0;
	u8 *prog = temp;

	emit_prologue(&prog, 512, // bpf_prog->aux->stack_depth,
		      bpf_prog_was_classic(bpf_prog));
	addrs[0] = prog - temp;

	for (i = 1; i <= insn_cnt; i++, insn++) {
		const s32 imm32 = insn->imm;
		u32 dst_reg = insn->dst_reg;
		u32 src_reg = insn->src_reg;
		u8 b2 = 0, b3 = 0;
		s64 jmp_offset;
		u8 jmp_cond;
		int ilen;
		u8 *func;

		switch (insn->code) {
			/* ALU */
		case BPF_ALU | BPF_ADD | BPF_X:
		case BPF_ALU | BPF_SUB | BPF_X:
		case BPF_ALU | BPF_AND | BPF_X:
		case BPF_ALU | BPF_OR | BPF_X:
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU64 | BPF_ADD | BPF_X:
		case BPF_ALU64 | BPF_SUB | BPF_X:
		case BPF_ALU64 | BPF_AND | BPF_X:
		case BPF_ALU64 | BPF_OR | BPF_X:
		case BPF_ALU64 | BPF_XOR | BPF_X:
			switch (BPF_OP(insn->code)) {
			case BPF_ADD: b2 = 0x01; break;
			case BPF_SUB: b2 = 0x29; break;
			case BPF_AND: b2 = 0x21; break;
			case BPF_OR: b2 = 0x09; break;
			case BPF_XOR: b2 = 0x31; break;
			}
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_2mod(0x48, dst_reg, src_reg));
			else if (is_ereg(dst_reg) || is_ereg(src_reg))
				EMIT1(add_2mod(0x40, dst_reg, src_reg));
			EMIT2(b2, add_2reg(0xC0, dst_reg, src_reg));
			break;

		case BPF_ALU64 | BPF_MOV | BPF_X:
		case BPF_ALU | BPF_MOV | BPF_X:
			emit_mov_reg(&prog,
				     BPF_CLASS(insn->code) == BPF_ALU64,
				     dst_reg, src_reg);
			break;

			/* neg dst */
		case BPF_ALU | BPF_NEG:
		case BPF_ALU64 | BPF_NEG:
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, dst_reg));
			else if (is_ereg(dst_reg))
				EMIT1(add_1mod(0x40, dst_reg));
			EMIT2(0xF7, add_1reg(0xD8, dst_reg));
			break;

		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU64 | BPF_ADD | BPF_K:
		case BPF_ALU64 | BPF_SUB | BPF_K:
		case BPF_ALU64 | BPF_AND | BPF_K:
		case BPF_ALU64 | BPF_OR | BPF_K:
		case BPF_ALU64 | BPF_XOR | BPF_K:
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, dst_reg));
			else if (is_ereg(dst_reg))
				EMIT1(add_1mod(0x40, dst_reg));

			/*
			 * b3 holds 'normal' opcode, b2 short form only valid
			 * in case dst is eax/rax.
			 */
			switch (BPF_OP(insn->code)) {
			case BPF_ADD:
				b3 = 0xC0;
				b2 = 0x05;
				break;
			case BPF_SUB:
				b3 = 0xE8;
				b2 = 0x2D;
				break;
			case BPF_AND:
				b3 = 0xE0;
				b2 = 0x25;
				break;
			case BPF_OR:
				b3 = 0xC8;
				b2 = 0x0D;
				break;
			case BPF_XOR:
				b3 = 0xF0;
				b2 = 0x35;
				break;
			}

			if (is_imm8(imm32))
				EMIT3(0x83, add_1reg(b3, dst_reg), imm32);
			else if (is_axreg(dst_reg))
				EMIT1_off32(b2, imm32);
			else
				EMIT2_off32(0x81, add_1reg(b3, dst_reg), imm32);
			break;

		case BPF_ALU64 | BPF_MOV | BPF_K:
		case BPF_ALU | BPF_MOV | BPF_K:
			emit_mov_imm32(&prog, BPF_CLASS(insn->code) == BPF_ALU64,
				       dst_reg, imm32);
			break;

		case BPF_LD | BPF_IMM | BPF_DW:
			emit_mov_imm64(&prog, dst_reg, insn[1].imm, insn[0].imm);
			insn++;
			i++;
			break;

			/* dst %= src, dst /= src, dst %= imm32, dst /= imm32 */
		case BPF_ALU | BPF_MOD | BPF_X:
		case BPF_ALU | BPF_DIV | BPF_X:
		case BPF_ALU | BPF_MOD | BPF_K:
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU64 | BPF_MOD | BPF_X:
		case BPF_ALU64 | BPF_DIV | BPF_X:
		case BPF_ALU64 | BPF_MOD | BPF_K:
		case BPF_ALU64 | BPF_DIV | BPF_K:
			EMIT1(0x50); /* push rax */
			EMIT1(0x52); /* push rdx */

			if (BPF_SRC(insn->code) == BPF_X)
				/* mov r11, src_reg */
				EMIT_mov(AUX_REG, src_reg);
			else
				/* mov r11, imm32 */
				EMIT3_off32(0x49, 0xC7, 0xC3, imm32);

			/* mov rax, dst_reg */
			EMIT_mov(BPF_REG_0, dst_reg);

			/*
			 * xor edx, edx
			 * equivalent to 'xor rdx, rdx', but one byte less
			 */
			EMIT2(0x31, 0xd2);

			if (BPF_CLASS(insn->code) == BPF_ALU64)
				/* div r11 */
				EMIT3(0x49, 0xF7, 0xF3);
			else
				/* div r11d */
				EMIT3(0x41, 0xF7, 0xF3);

			if (BPF_OP(insn->code) == BPF_MOD)
				/* mov r11, rdx */
				EMIT3(0x49, 0x89, 0xD3);
			else
				/* mov r11, rax */
				EMIT3(0x49, 0x89, 0xC3);

			EMIT1(0x5A); /* pop rdx */
			EMIT1(0x58); /* pop rax */

			/* mov dst_reg, r11 */
			EMIT_mov(dst_reg, AUX_REG);
			break;

		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU | BPF_MUL | BPF_X:
		case BPF_ALU64 | BPF_MUL | BPF_K:
		case BPF_ALU64 | BPF_MUL | BPF_X:
		{
			bool is64 = BPF_CLASS(insn->code) == BPF_ALU64;

			if (dst_reg != BPF_REG_0)
				EMIT1(0x50); /* push rax */
			if (dst_reg != BPF_REG_3)
				EMIT1(0x52); /* push rdx */

			/* mov r11, dst_reg */
			EMIT_mov(AUX_REG, dst_reg);

			if (BPF_SRC(insn->code) == BPF_X)
				emit_mov_reg(&prog, is64, BPF_REG_0, src_reg);
			else
				emit_mov_imm32(&prog, is64, BPF_REG_0, imm32);

			if (is64)
				EMIT1(add_1mod(0x48, AUX_REG));
			else if (is_ereg(AUX_REG))
				EMIT1(add_1mod(0x40, AUX_REG));
			/* mul(q) r11 */
			EMIT2(0xF7, add_1reg(0xE0, AUX_REG));

			if (dst_reg != BPF_REG_3)
				EMIT1(0x5A); /* pop rdx */
			if (dst_reg != BPF_REG_0) {
				/* mov dst_reg, rax */
				EMIT_mov(dst_reg, BPF_REG_0);
				EMIT1(0x58); /* pop rax */
			}
			break;
		}
			/* Shifts */
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU | BPF_ARSH | BPF_K:
		case BPF_ALU64 | BPF_LSH | BPF_K:
		case BPF_ALU64 | BPF_RSH | BPF_K:
		case BPF_ALU64 | BPF_ARSH | BPF_K:
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, dst_reg));
			else if (is_ereg(dst_reg))
				EMIT1(add_1mod(0x40, dst_reg));

			switch (BPF_OP(insn->code)) {
			case BPF_LSH: b3 = 0xE0; break;
			case BPF_RSH: b3 = 0xE8; break;
			case BPF_ARSH: b3 = 0xF8; break;
			}

			if (imm32 == 1)
				EMIT2(0xD1, add_1reg(b3, dst_reg));
			else
				EMIT3(0xC1, add_1reg(b3, dst_reg), imm32);
			break;

		case BPF_ALU | BPF_LSH | BPF_X:
		case BPF_ALU | BPF_RSH | BPF_X:
		case BPF_ALU | BPF_ARSH | BPF_X:
		case BPF_ALU64 | BPF_LSH | BPF_X:
		case BPF_ALU64 | BPF_RSH | BPF_X:
		case BPF_ALU64 | BPF_ARSH | BPF_X:

			/* Check for bad case when dst_reg == rcx */
			if (dst_reg == BPF_REG_4) {
				/* mov r11, dst_reg */
				EMIT_mov(AUX_REG, dst_reg);
				dst_reg = AUX_REG;
			}

			if (src_reg != BPF_REG_4) { /* common case */
				EMIT1(0x51); /* push rcx */

				/* mov rcx, src_reg */
				EMIT_mov(BPF_REG_4, src_reg);
			}

			/* shl %rax, %cl | shr %rax, %cl | sar %rax, %cl */
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, dst_reg));
			else if (is_ereg(dst_reg))
				EMIT1(add_1mod(0x40, dst_reg));

			switch (BPF_OP(insn->code)) {
			case BPF_LSH: b3 = 0xE0; break;
			case BPF_RSH: b3 = 0xE8; break;
			case BPF_ARSH: b3 = 0xF8; break;
			}
			EMIT2(0xD3, add_1reg(b3, dst_reg));

			if (src_reg != BPF_REG_4)
				EMIT1(0x59); /* pop rcx */

			if (insn->dst_reg == BPF_REG_4)
				/* mov dst_reg, r11 */
				EMIT_mov(insn->dst_reg, AUX_REG);
			break;

		case BPF_ALU | BPF_END | BPF_FROM_BE:
			switch (imm32) {
			case 16:
				/* Emit 'ror %ax, 8' to swap lower 2 bytes */
				EMIT1(0x66);
				if (is_ereg(dst_reg))
					EMIT1(0x41);
				EMIT3(0xC1, add_1reg(0xC8, dst_reg), 8);

				/* Emit 'movzwl eax, ax' */
				if (is_ereg(dst_reg))
					EMIT3(0x45, 0x0F, 0xB7);
				else
					EMIT2(0x0F, 0xB7);
				EMIT1(add_2reg(0xC0, dst_reg, dst_reg));
				break;
			case 32:
				/* Emit 'bswap eax' to swap lower 4 bytes */
				if (is_ereg(dst_reg))
					EMIT2(0x41, 0x0F);
				else
					EMIT1(0x0F);
				EMIT1(add_1reg(0xC8, dst_reg));
				break;
			case 64:
				/* Emit 'bswap rax' to swap 8 bytes */
				EMIT3(add_1mod(0x48, dst_reg), 0x0F,
				      add_1reg(0xC8, dst_reg));
				break;
			}
			break;

		case BPF_ALU | BPF_END | BPF_FROM_LE:
			switch (imm32) {
			case 16:
				/*
				 * Emit 'movzwl eax, ax' to zero extend 16-bit
				 * into 64 bit
				 */
				if (is_ereg(dst_reg))
					EMIT3(0x45, 0x0F, 0xB7);
				else
					EMIT2(0x0F, 0xB7);
				EMIT1(add_2reg(0xC0, dst_reg, dst_reg));
				break;
			case 32:
				/* Emit 'mov eax, eax' to clear upper 32-bits */
				if (is_ereg(dst_reg))
					EMIT1(0x45);
				EMIT2(0x89, add_2reg(0xC0, dst_reg, dst_reg));
				break;
			case 64:
				/* nop */
				break;
			}
			break;

			/* ST: *(u8*)(dst_reg + off) = imm */
		case BPF_ST | BPF_MEM | BPF_B:
			if (is_ereg(dst_reg))
				EMIT2(0x41, 0xC6);
			else
				EMIT1(0xC6);
			goto st;
		case BPF_ST | BPF_MEM | BPF_H:
			if (is_ereg(dst_reg))
				EMIT3(0x66, 0x41, 0xC7);
			else
				EMIT2(0x66, 0xC7);
			goto st;
		case BPF_ST | BPF_MEM | BPF_W:
			if (is_ereg(dst_reg))
				EMIT2(0x41, 0xC7);
			else
				EMIT1(0xC7);
			goto st;
		case BPF_ST | BPF_MEM | BPF_DW:
			EMIT2(add_1mod(0x48, dst_reg), 0xC7);

st:			if (is_imm8(insn->off))
				EMIT2(add_1reg(0x40, dst_reg), insn->off);
			else
				EMIT1_off32(add_1reg(0x80, dst_reg), insn->off);

			EMIT(imm32, bpf_size_to_x86_bytes(BPF_SIZE(insn->code)));
			break;

			/* STX: *(u8*)(dst_reg + off) = src_reg */
		case BPF_STX | BPF_MEM | BPF_B:
		case BPF_STX | BPF_MEM | BPF_H:
		case BPF_STX | BPF_MEM | BPF_W:
		case BPF_STX | BPF_MEM | BPF_DW:
			emit_stx(&prog, BPF_SIZE(insn->code), dst_reg, src_reg, insn->off);
			break;

			/* LDX: dst_reg = *(u8*)(src_reg + off) */
		case BPF_LDX | BPF_MEM | BPF_B:
		case BPF_LDX | BPF_PROBE_MEM | BPF_B:
		case BPF_LDX | BPF_MEM | BPF_H:
		case BPF_LDX | BPF_PROBE_MEM | BPF_H:
		case BPF_LDX | BPF_MEM | BPF_W:
		case BPF_LDX | BPF_PROBE_MEM | BPF_W:
		case BPF_LDX | BPF_MEM | BPF_DW:
		case BPF_LDX | BPF_PROBE_MEM | BPF_DW:
			emit_ldx(&prog, BPF_SIZE(insn->code), dst_reg, src_reg, insn->off);
			if (BPF_MODE(insn->code) == BPF_PROBE_MEM) {
				printf("BPF_MODE(insn->code) == BPF_PROBE_MEM unsupported.");
				// struct exception_table_entry *ex;
				// u8 *_insn = image + proglen;
				// s64 delta;

				// if (!bpf_prog->aux->extable)
				// 	break;

				// if (excnt >= bpf_prog->aux->num_exentries) {
				// 	pr_err("ex gen bug\n");
				// 	return -EFAULT;
				// }
				// ex = &bpf_prog->aux->extable[excnt++];

				// delta = _insn - (u8 *)&ex->insn;
				// if (!is_simm32(delta)) {
				// 	pr_err("extable->insn doesn't fit into 32-bit\n");
				// 	return -EFAULT;
				// }
				// ex->insn = delta;

				// delta = (u8 *)ex_handler_bpf - (u8 *)&ex->handler;
				// if (!is_simm32(delta)) {
				// 	pr_err("extable->handler doesn't fit into 32-bit\n");
				// 	return -EFAULT;
				// }
				// ex->handler = delta;

				// if (dst_reg > BPF_REG_9) {
				// 	pr_err("verifier error\n");
				// 	return -EFAULT;
				// }
				// /*
				//  * Compute size of x86 insn and its target dest x86 register.
				//  * ex_handler_bpf() will use lower 8 bits to adjust
				//  * pt_regs->ip to jump over this x86 instruction
				//  * and upper bits to figure out which pt_regs to zero out.
				//  * End result: x86 insn "mov rbx, qword ptr [rax+0x14]"
				//  * of 4 bytes will be ignored and rbx will be zero inited.
				//  */
				// ex->fixup = (prog - temp) | (reg2pt_regs[dst_reg] << 8);
			}
			break;

			/* STX XADD: lock *(u32*)(dst_reg + off) += src_reg */
		case BPF_STX | BPF_XADD | BPF_W:
			/* Emit 'lock add dword ptr [rax + off], eax' */
			if (is_ereg(dst_reg) || is_ereg(src_reg))
				EMIT3(0xF0, add_2mod(0x40, dst_reg, src_reg), 0x01);
			else
				EMIT2(0xF0, 0x01);
			goto xadd;
		case BPF_STX | BPF_XADD | BPF_DW:
			EMIT3(0xF0, add_2mod(0x48, dst_reg, src_reg), 0x01);
xadd:			if (is_imm8(insn->off))
				EMIT2(add_2reg(0x40, dst_reg, src_reg), insn->off);
			else
				EMIT1_off32(add_2reg(0x80, dst_reg, src_reg),
					    insn->off);
			break;

			/* call */
		case BPF_JMP | BPF_CALL:
			func = (u8 *) __bpf_call_base + imm32;
			if (!imm32 || emit_call(&prog, func, image + addrs[i - 1]))
				return -EINVAL;
			break;

		case BPF_JMP | BPF_TAIL_CALL:
			printf("BPF_TAIL_CALL unsupported.");
			// if (imm32)
			// 	emit_bpf_tail_call_direct(&bpf_prog->aux->poke_tab[imm32 - 1],
			// 				  &prog, addrs[i], image);
			// else
			// 	emit_bpf_tail_call_indirect(&prog);
			break;

			/* cond jump */
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JNE | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JLT | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_X:
		case BPF_JMP | BPF_JLE | BPF_X:
		case BPF_JMP | BPF_JSGT | BPF_X:
		case BPF_JMP | BPF_JSLT | BPF_X:
		case BPF_JMP | BPF_JSGE | BPF_X:
		case BPF_JMP | BPF_JSLE | BPF_X:
		case BPF_JMP32 | BPF_JEQ | BPF_X:
		case BPF_JMP32 | BPF_JNE | BPF_X:
		case BPF_JMP32 | BPF_JGT | BPF_X:
		case BPF_JMP32 | BPF_JLT | BPF_X:
		case BPF_JMP32 | BPF_JGE | BPF_X:
		case BPF_JMP32 | BPF_JLE | BPF_X:
		case BPF_JMP32 | BPF_JSGT | BPF_X:
		case BPF_JMP32 | BPF_JSLT | BPF_X:
		case BPF_JMP32 | BPF_JSGE | BPF_X:
		case BPF_JMP32 | BPF_JSLE | BPF_X:
			/* cmp dst_reg, src_reg */
			if (BPF_CLASS(insn->code) == BPF_JMP)
				EMIT1(add_2mod(0x48, dst_reg, src_reg));
			else if (is_ereg(dst_reg) || is_ereg(src_reg))
				EMIT1(add_2mod(0x40, dst_reg, src_reg));
			EMIT2(0x39, add_2reg(0xC0, dst_reg, src_reg));
			goto emit_cond_jmp;

		case BPF_JMP | BPF_JSET | BPF_X:
		case BPF_JMP32 | BPF_JSET | BPF_X:
			/* test dst_reg, src_reg */
			if (BPF_CLASS(insn->code) == BPF_JMP)
				EMIT1(add_2mod(0x48, dst_reg, src_reg));
			else if (is_ereg(dst_reg) || is_ereg(src_reg))
				EMIT1(add_2mod(0x40, dst_reg, src_reg));
			EMIT2(0x85, add_2reg(0xC0, dst_reg, src_reg));
			goto emit_cond_jmp;

		case BPF_JMP | BPF_JSET | BPF_K:
		case BPF_JMP32 | BPF_JSET | BPF_K:
			/* test dst_reg, imm32 */
			if (BPF_CLASS(insn->code) == BPF_JMP)
				EMIT1(add_1mod(0x48, dst_reg));
			else if (is_ereg(dst_reg))
				EMIT1(add_1mod(0x40, dst_reg));
			EMIT2_off32(0xF7, add_1reg(0xC0, dst_reg), imm32);
			goto emit_cond_jmp;

		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JNE | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JLT | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JLE | BPF_K:
		case BPF_JMP | BPF_JSGT | BPF_K:
		case BPF_JMP | BPF_JSLT | BPF_K:
		case BPF_JMP | BPF_JSGE | BPF_K:
		case BPF_JMP | BPF_JSLE | BPF_K:
		case BPF_JMP32 | BPF_JEQ | BPF_K:
		case BPF_JMP32 | BPF_JNE | BPF_K:
		case BPF_JMP32 | BPF_JGT | BPF_K:
		case BPF_JMP32 | BPF_JLT | BPF_K:
		case BPF_JMP32 | BPF_JGE | BPF_K:
		case BPF_JMP32 | BPF_JLE | BPF_K:
		case BPF_JMP32 | BPF_JSGT | BPF_K:
		case BPF_JMP32 | BPF_JSLT | BPF_K:
		case BPF_JMP32 | BPF_JSGE | BPF_K:
		case BPF_JMP32 | BPF_JSLE | BPF_K:
			/* test dst_reg, dst_reg to save one extra byte */
			if (imm32 == 0) {
				if (BPF_CLASS(insn->code) == BPF_JMP)
					EMIT1(add_2mod(0x48, dst_reg, dst_reg));
				else if (is_ereg(dst_reg))
					EMIT1(add_2mod(0x40, dst_reg, dst_reg));
				EMIT2(0x85, add_2reg(0xC0, dst_reg, dst_reg));
				goto emit_cond_jmp;
			}

			/* cmp dst_reg, imm8/32 */
			if (BPF_CLASS(insn->code) == BPF_JMP)
				EMIT1(add_1mod(0x48, dst_reg));
			else if (is_ereg(dst_reg))
				EMIT1(add_1mod(0x40, dst_reg));

			if (is_imm8(imm32))
				EMIT3(0x83, add_1reg(0xF8, dst_reg), imm32);
			else
				EMIT2_off32(0x81, add_1reg(0xF8, dst_reg), imm32);

emit_cond_jmp:		/* Convert BPF opcode to x86 */
			switch (BPF_OP(insn->code)) {
			case BPF_JEQ:
				jmp_cond = X86_JE;
				break;
			case BPF_JSET:
			case BPF_JNE:
				jmp_cond = X86_JNE;
				break;
			case BPF_JGT:
				/* GT is unsigned '>', JA in x86 */
				jmp_cond = X86_JA;
				break;
			case BPF_JLT:
				/* LT is unsigned '<', JB in x86 */
				jmp_cond = X86_JB;
				break;
			case BPF_JGE:
				/* GE is unsigned '>=', JAE in x86 */
				jmp_cond = X86_JAE;
				break;
			case BPF_JLE:
				/* LE is unsigned '<=', JBE in x86 */
				jmp_cond = X86_JBE;
				break;
			case BPF_JSGT:
				/* Signed '>', GT in x86 */
				jmp_cond = X86_JG;
				break;
			case BPF_JSLT:
				/* Signed '<', LT in x86 */
				jmp_cond = X86_JL;
				break;
			case BPF_JSGE:
				/* Signed '>=', GE in x86 */
				jmp_cond = X86_JGE;
				break;
			case BPF_JSLE:
				/* Signed '<=', LE in x86 */
				jmp_cond = X86_JLE;
				break;
			default: /* to silence GCC warning */
				return -EFAULT;
			}
			jmp_offset = addrs[i + insn->off] - addrs[i];
			if (is_imm8(jmp_offset)) {
				EMIT2(jmp_cond, jmp_offset);
			} else if (is_simm32(jmp_offset)) {
				EMIT2_off32(0x0F, jmp_cond + 0x10, jmp_offset);
			} else {
				pr_err("cond_jmp gen bug %llx\n", jmp_offset);
				return -EFAULT;
			}

			break;

		case BPF_JMP | BPF_JA:
			if (insn->off == -1)
				/* -1 jmp instructions will always jump
				 * backwards two bytes. Explicitly handling
				 * this case avoids wasting too many passes
				 * when there are long sequences of replaced
				 * dead code.
				 */
				jmp_offset = -2;
			else
				jmp_offset = addrs[i + insn->off] - addrs[i];

			if (!jmp_offset)
				/* Optimize out nop jumps */
				break;
emit_jmp:
			if (is_imm8(jmp_offset)) {
				EMIT2(0xEB, jmp_offset);
			} else if (is_simm32(jmp_offset)) {
				EMIT1_off32(0xE9, jmp_offset);
			} else {
				pr_err("jmp gen bug %llx\n", jmp_offset);
				return -EFAULT;
			}
			break;

		case BPF_JMP | BPF_EXIT:
			if (seen_exit) {
				jmp_offset = ctx->cleanup_addr - addrs[i];
				goto emit_jmp;
			}
			seen_exit = true;
			/* Update cleanup_addr */
			ctx->cleanup_addr = proglen;
			if (!bpf_prog_was_classic(bpf_prog))
				EMIT1(0x5B); /* get rid of tail_call_cnt */
			EMIT2(0x41, 0x5F);   /* pop r15 */
			EMIT2(0x41, 0x5E);   /* pop r14 */
			EMIT2(0x41, 0x5D);   /* pop r13 */
			EMIT1(0x5B);         /* pop rbx */
			EMIT1(0xC9);         /* leave */
			EMIT1(0xC3);         /* ret */
			break;

		default:
			/*
			 * By design x86-64 JIT should support all BPF instructions.
			 * This error will be seen if new instruction was added
			 * to the interpreter, but not to the JIT, or if there is
			 * junk in bpf_prog.
			 */
			pr_err("bpf_jit: unknown opcode %02x\n", insn->code);
			return -EINVAL;
		}

		ilen = prog - temp;
		if (ilen > BPF_MAX_INSN_SIZE) {
			pr_err("bpf_jit: fatal insn size error\n");
			return -EFAULT;
		}

		if (image) {
			if (unlikely(proglen + ilen > oldproglen)) {
				pr_err("bpf_jit: fatal error\n");
				return -EFAULT;
			}
			memcpy(image + proglen, temp, ilen);
		}
		proglen += ilen;
		addrs[i] = proglen;
		prog = temp;
	}

	if (image && excnt != bpf_prog->aux->num_exentries) {
		printf("extable is not populated\n");
		return -EFAULT;
	}
	return proglen;
}

static void save_regs(const struct btf_func_model *m, u8 **prog, int nr_args,
		      int stack_size)
{
	int i;
	/* Store function arguments to stack.
	 * For a function that accepts two pointers the sequence will be:
	 * mov QWORD PTR [rbp-0x10],rdi
	 * mov QWORD PTR [rbp-0x8],rsi
	 */
	for (i = 0; i < min(nr_args, 6); i++)
		emit_stx(prog, bytes_to_bpf_size(m->arg_size[i]),
			 BPF_REG_FP,
			 i == 5 ? X86_REG_R9 : BPF_REG_1 + i,
			 -(stack_size - i * 8));
}

static void restore_regs(const struct btf_func_model *m, u8 **prog, int nr_args,
			 int stack_size)
{
	int i;

	/* Restore function arguments from stack.
	 * For a function that accepts two pointers the sequence will be:
	 * EMIT4(0x48, 0x8B, 0x7D, 0xF0); mov rdi,QWORD PTR [rbp-0x10]
	 * EMIT4(0x48, 0x8B, 0x75, 0xF8); mov rsi,QWORD PTR [rbp-0x8]
	 */
	for (i = 0; i < min(nr_args, 6); i++)
		emit_ldx(prog, bytes_to_bpf_size(m->arg_size[i]),
			 i == 5 ? X86_REG_R9 : BPF_REG_1 + i,
			 BPF_REG_FP,
			 -(stack_size - i * 8));
}

static int invoke_bpf_prog(const struct btf_func_model *m, u8 **pprog,
			   struct bpf_prog *p, int stack_size, bool mod_ret)
{
	u8 *prog = *pprog;
	int cnt = 0;

	if (emit_call(&prog, __bpf_prog_enter, prog))
		return -EINVAL;
	/* remember prog start time returned by __bpf_prog_enter */
	emit_mov_reg(&prog, true, BPF_REG_6, BPF_REG_0);

	/* arg1: lea rdi, [rbp - stack_size] */
	EMIT4(0x48, 0x8D, 0x7D, -stack_size);
	/* arg2: progs[i]->insnsi for interpreter */
	if (!p->jited)
		emit_mov_imm64(&prog, BPF_REG_2,
			       (long) p->insnsi >> 32,
			       (u32) (long) p->insnsi);
	/* call JITed bpf program or interpreter */
	if (emit_call(&prog, p->bpf_func, prog))
		return -EINVAL;

	/* BPF_TRAMP_MODIFY_RETURN trampolines can modify the return
	 * of the previous call which is then passed on the stack to
	 * the next BPF program.
	 */
	if (mod_ret)
		emit_stx(&prog, BPF_DW, BPF_REG_FP, BPF_REG_0, -8);

	/* arg1: mov rdi, progs[i] */
	emit_mov_imm64(&prog, BPF_REG_1, (long) p >> 32,
		       (u32) (long) p);
	/* arg2: mov rsi, rbx <- start time in nsec */
	emit_mov_reg(&prog, true, BPF_REG_2, BPF_REG_6);
	if (emit_call(&prog, __bpf_prog_exit, prog))
		return -EINVAL;

	*pprog = prog;
	return 0;
}

static void emit_nops(u8 **pprog, unsigned int len)
{
	unsigned int i, noplen;
	u8 *prog = *pprog;
	int cnt = 0;

	while (len > 0) {
		noplen = len;

		// if (noplen > ASM_NOP_MAX)
		// 	noplen = ASM_NOP_MAX;
		
		for (i = 0; i < noplen; i++)
			__asm__ __volatile__("nop");
		len -= noplen;
	}

	*pprog = prog;
}

static void emit_align(u8 **pprog, u32 align)
{
	u8 *target, *prog = *pprog;

	target = PTR_ALIGN(prog, align);
	if (target != prog)
		emit_nops(&prog, target - prog);

	*pprog = prog;
}

static int emit_cond_near_jump(u8 **pprog, void *func, void *ip, u8 jmp_cond)
{
	u8 *prog = *pprog;
	int cnt = 0;
	s64 offset;

	offset = func - (ip + 2 + 4);
	if (!is_simm32(offset)) {
		pr_err("Target %p is out of range\n", func);
		return -EINVAL;
	}
	EMIT2_off32(0x0F, jmp_cond + 0x10, offset);
	*pprog = prog;
	return 0;
}

static int invoke_bpf(const struct btf_func_model *m, u8 **pprog,
		      struct bpf_tramp_progs *tp, int stack_size)
{
	int i;
	u8 *prog = *pprog;

	for (i = 0; i < tp->nr_progs; i++) {
		if (invoke_bpf_prog(m, &prog, tp->progs[i], stack_size, false))
			return -EINVAL;
	}
	*pprog = prog;
	return 0;
}

static int invoke_bpf_mod_ret(const struct btf_func_model *m, u8 **pprog,
			      struct bpf_tramp_progs *tp, int stack_size,
			      u8 **branches)
{
	u8 *prog = *pprog;
	int i, cnt = 0;

	/* The first fmod_ret program will receive a garbage return value.
	 * Set this to 0 to avoid confusing the program.
	 */
	emit_mov_imm32(&prog, false, BPF_REG_0, 0);
	emit_stx(&prog, BPF_DW, BPF_REG_FP, BPF_REG_0, -8);
	for (i = 0; i < tp->nr_progs; i++) {
		if (invoke_bpf_prog(m, &prog, tp->progs[i], stack_size, true))
			return -EINVAL;

		/* mod_ret prog stored return value into [rbp - 8]. Emit:
		 * if (*(u64 *)(rbp - 8) !=  0)
		 *	goto do_fexit;
		 */
		/* cmp QWORD PTR [rbp - 0x8], 0x0 */
		EMIT4(0x48, 0x83, 0x7d, 0xf8); EMIT1(0x00);

		/* Save the location of the branch and Generate 6 nops
		 * (4 bytes for an offset and 2 bytes for the jump) These nops
		 * are replaced with a conditional jump once do_fexit (i.e. the
		 * start of the fexit invocation) is finalized.
		 */
		branches[i] = prog;
		emit_nops(&prog, 4 + 2);
	}

	*pprog = prog;
	return 0;
}

static int emit_fallback_jump(u8 **pprog)
{
	u8 *prog = *pprog;
	int err = 0;

#ifdef CONFIG_RETPOLINE
	/* Note that this assumes the the compiler uses external
	 * thunks for indirect calls. Both clang and GCC use the same
	 * naming convention for external thunks.
	 */
	err = emit_jump(&prog, __x86_indirect_thunk_rdx, prog);
#else
	int cnt = 0;

	EMIT2(0xFF, 0xE2);	/* jmp rdx */
#endif
	*pprog = prog;
	return err;
}

static int emit_bpf_dispatcher(u8 **pprog, int a, int b, s64 *progs)
{
	u8 *jg_reloc, *prog = *pprog;
	int pivot, err, jg_bytes = 1, cnt = 0;
	s64 jg_offset;

	if (a == b) {
		/* Leaf node of recursion, i.e. not a range of indices
		 * anymore.
		 */
		EMIT1(add_1mod(0x48, BPF_REG_3));	/* cmp rdx,func */
		if (!is_simm32(progs[a]))
			return -1;
		EMIT2_off32(0x81, add_1reg(0xF8, BPF_REG_3),
			    progs[a]);
		err = emit_cond_near_jump(&prog,	/* je func */
					  (void *)progs[a], prog,
					  X86_JE);
		if (err)
			return err;

		err = emit_fallback_jump(&prog);	/* jmp thunk/indirect */
		if (err)
			return err;

		*pprog = prog;
		return 0;
	}

	/* Not a leaf node, so we pivot, and recursively descend into
	 * the lower and upper ranges.
	 */
	pivot = (b - a) / 2;
	EMIT1(add_1mod(0x48, BPF_REG_3));		/* cmp rdx,func */
	if (!is_simm32(progs[a + pivot]))
		return -1;
	EMIT2_off32(0x81, add_1reg(0xF8, BPF_REG_3), progs[a + pivot]);

	if (pivot > 2) {				/* jg upper_part */
		/* Require near jump. */
		jg_bytes = 4;
		EMIT2_off32(0x0F, X86_JG + 0x10, 0);
	} else {
		EMIT2(X86_JG, 0);
	}
	jg_reloc = prog;

	err = emit_bpf_dispatcher(&prog, a, a + pivot,	/* emit lower_part */
				  progs);
	if (err)
		return err;

	/* From Intel 64 and IA-32 Architectures Optimization
	 * Reference Manual, 3.4.1.4 Code Alignment, Assembly/Compiler
	 * Coding Rule 11: All branch targets should be 16-byte
	 * aligned.
	 */
	emit_align(&prog, 16);
	jg_offset = prog - jg_reloc;
	emit_code(jg_reloc - jg_bytes, jg_offset, jg_bytes);

	err = emit_bpf_dispatcher(&prog, a + pivot + 1,	/* emit upper_part */
				  b, progs);
	if (err)
		return err;

	*pprog = prog;
	return 0;
}

static int cmp_ips(const void *a, const void *b)
{
	const s64 *ipa = a;
	const s64 *ipb = b;

	if (*ipa > *ipb)
		return 1;
	if (*ipa < *ipb)
		return -1;
	return 0;
}

int arch_prepare_bpf_dispatcher(void *image, s64 *funcs, int num_funcs)
{
	u8 *prog = image;

	sort(funcs, num_funcs, sizeof(funcs[0]), cmp_ips, NULL);
	return emit_bpf_dispatcher(&prog, 0, num_funcs - 1, funcs);
}

struct x64_jit_data {
	struct bpf_binary_header *header;
	int *addrs;
	u8 *image;
	int proglen;
	struct jit_context ctx;
};

struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
{
	struct bpf_binary_header *header = NULL;
	struct bpf_prog *tmp, *orig_prog = prog;
	struct x64_jit_data *jit_data;
	int proglen, oldproglen = 0;
	struct jit_context ctx = {};
	bool tmp_blinded = false;
	bool extra_pass = false;
	u8 *image = NULL;
	int *addrs;
	int pass;
	int i;

	const size_t jit_data_size = 1024;

	if (!prog->jit_requested)
		return orig_prog;

	jit_data = prog->aux->jit_data;
	if (!jit_data) {
		jit_data = calloc(jit_data_size, sizeof(*jit_data));
		if (!jit_data) {
			prog = orig_prog;
			goto out;
		}
		prog->aux->jit_data = jit_data;
	}
	addrs = jit_data->addrs;
	if (addrs) {
		ctx = jit_data->ctx;
		oldproglen = jit_data->proglen;
		image = jit_data->image;
		header = jit_data->header;
		extra_pass = true;
		goto skip_init_addrs;
	}
	addrs = calloc(prog->len + 1, sizeof(*addrs));
	if (!addrs) {
		prog = orig_prog;
		goto out_addrs;
	}

	/*
	 * Before first pass, make a rough estimation of addrs[]
	 * each BPF instruction is translated to less than 64 bytes
	 */
	for (proglen = 0, i = 0; i <= prog->len; i++) {
		proglen += 64;
		addrs[i] = proglen;
	}
	ctx.cleanup_addr = proglen;
skip_init_addrs:

	/*
	 * JITed image shrinks with every pass and the loop iterates
	 * until the image stops shrinking. Very large BPF programs
	 * may converge on the last pass. In such case do one more
	 * pass to emit the final image.
	 */
	for (pass = 0; pass < 20 || image; pass++) {
		proglen = do_jit(prog, addrs, image, oldproglen, &ctx);
		if (proglen <= 0) {
out_image:
			image = NULL;
			if (header)
				bpf_jit_binary_free(header);
			prog = orig_prog;
			goto out_addrs;
		}
		if (image) {
			if (proglen != oldproglen) {
				pr_err("bpf_jit: proglen=%d != oldproglen=%d\n",
				       proglen, oldproglen);
				goto out_image;
			}
			break;
		}
		if (proglen == oldproglen) {
			/*
			 * The number of entries in extable is the number of BPF_LDX
			 * insns that access kernel memory via "pointer to BTF type".
			 * The verifier changed their opcode from LDX|MEM|size
			 * to LDX|PROBE_MEM|size to make JITing easier.
			 */
			u32 align = __alignof__(struct exception_table_entry);
			u32 extable_size = prog->aux->num_exentries *
				sizeof(struct exception_table_entry);

			/* allocate module memory for x86 insns and extable */
			header = bpf_jit_binary_alloc(roundup(proglen, align) + extable_size,
						      &image, align, jit_fill_hole);
			if (!header) {
				prog = orig_prog;
				goto out_addrs;
			}
			prog->aux->extable = (void *) image + roundup(proglen, align);
		}
		oldproglen = proglen;
		cond_resched();
	}

	// bpf_jit_dump(prog->len, proglen, pass + 1, image);

	if (image) {
		if (!prog->is_func || extra_pass) {
			bpf_tail_call_direct_fixup(prog);
			bpf_jit_binary_lock_ro(header);
		} else {
			jit_data->addrs = addrs;
			jit_data->ctx = ctx;
			jit_data->proglen = proglen;
			jit_data->image = image;
			jit_data->header = header;
		}
		prog->bpf_func = (void *)image;
		prog->jited = 1;
		prog->jited_len = proglen;
	} else {
		prog = orig_prog;
	}

	if (!image || !prog->is_func || extra_pass) {
		if (image)
			bpf_prog_fill_jited_linfo(prog, addrs + 1);
out_addrs:
		kfree(addrs);
		kfree(jit_data);
		prog->aux->jit_data = NULL;
	}
out:
	if (tmp_blinded)
		bpf_jit_prog_release_other(prog, prog == orig_prog ?
					   tmp : orig_prog);
	return prog;
}
