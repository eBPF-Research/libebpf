#ifndef LIBEBPF_LINUX_JIT_H_
#define LIBEBPF_LINUX_JIT_H_

struct bpf_prog;

struct bpf_prog *bpf_prog_get(const void* code, unsigned int code_len);

struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog);

unsigned int bpf_prog_run_jit(const struct bpf_prog *prog, const void *ctx);

#endif
