#include <string.h>
#include "minimal.h"
#include "libebpf/libebpf.h"
#include "libebpf/linux-jit-bpf.h"

#define JIT_TEST_KERNEL 1

#define CHECK_EXIT(ret)                                                        \
	if (ret != 0) {                                                        \
		fprintf(stderr, "Failed to load code: %s\n", errmsg);          \
	}

#define TEST_BPF_CODE bpf_mul_64_bit

char *errmsg;
struct mem {
	int a;
	int b;
};

int main()
{
	struct mem m = { 1, 2 };
	uint64_t res = 0;
#if JIT_TEST_UBPF
	// using ubpf jit for x86_64 and arm64
	struct ebpf_vm *vm = ebpf_create();
	// remove 0, in the end
	CHECK_EXIT(
		ebpf_load(vm, TEST_BPF_CODE, sizeof(TEST_BPF_CODE), &errmsg));
	ebpf_jit_fn fn = ebpf_compile(vm, &errmsg);
	int mem_len = 1024 * 1024;
	char* mem = malloc(mem_len);
	    if (fn == NULL) {
	        fprintf(stderr, "Failed to compile: %s\n", errmsg);
	        free(errmsg);
	        free(mem);
	        return 1;
	    }
	res = fn(mem, mem_len);
	printf("%d + %d = %ld\n", m.a, m.b, res);
#elif JIT_TEST_KERNEL
	union bpf_attr attr;
	attr.insn_cnt = sizeof(TEST_BPF_CODE) / sizeof(struct bpf_insn);
	attr.insns = (uint64_t)TEST_BPF_CODE;
	strcpy(attr.prog_name, "add_one");
	attr.prog_type = BPF_PROG_TYPE_UNSPEC;
	attr.log_buf = (uint64_t)errmsg;
	attr.license = (uint64_t)"GPL";
	struct bpf_prog* prog = bpf_prog_load(&attr);
	if (!prog) {
		printf("Failed to load bpf program\n");
		return 1;
	}
	printf("start to compile bpf program\n");
	prog = bpf_int_jit_compile(prog);
	if (!prog) {
		printf("Failed to compile bpf program\n");
		return 1;
	}
	printf("start to run bpf program\n");
	res = bpf_prog_run_jit(prog, NULL);
	printf("res = %ld\n", res);
	bpf_prog_free(prog);
#else
	// using ubpf vm for other arch
	struct ebpf_vm *vm = ebpf_create();
	// remove 0, in the end
	CHECK_EXIT(
		ebpf_load(vm, TEST_BPF_CODE, sizeof(TEST_BPF_CODE), &errmsg));
	CHECK_EXIT(ebpf_exec(vm, &m, sizeof(m), &res));
	printf("%d + %d = %ld\n", m.a, m.b, res);
#endif
	return 0;
}