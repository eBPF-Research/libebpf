#ifndef LIBEBPF_LINUX_JIT_H_
#define LIBEBPF_LINUX_JIT_H_

#include <stdint.h>
#include "type-fixes.h"

struct ebpf_vm;

struct ebpf_vm *linux_bpf_int_jit_compile(struct ebpf_vm *prog);

void linux_bpf_prog_free(struct ebpf_vm *prog);

#endif
