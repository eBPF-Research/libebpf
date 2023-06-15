#ifndef LIBEBPF_LINUX_JIT_H_
#define LIBEBPF_LINUX_JIT_H_

#include <stdint.h>
#include "type-fixes.h"

struct bpf_insn {
	u8	code;		/* opcode */
	u8	dst_reg:4;	/* dest register */
	u8	src_reg:4;	/* source register */
	s16	off;		/* signed offset */
	s32	imm;		/* signed immediate constant */
};

struct bpf_prog;

struct bpf_prog *bpf_prog_load(const void* code, uint32_t code_len);

struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog);

unsigned int bpf_prog_run_jit(const struct bpf_prog *prog, const void *ctx);

void bpf_prog_free(struct bpf_prog *prog);

#endif
