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

struct ebpf_vm;

struct ebpf_vm *linux_bpf_prog_load(const void* code, uint32_t code_len);

struct ebpf_vm *linux_bpf_int_jit_compile(struct ebpf_vm *prog);

void linux_bpf_prog_free(struct ebpf_vm *prog);

#endif
