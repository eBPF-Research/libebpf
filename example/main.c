#include <string.h>
#include "minimal.h"
#include "libebpf/libebpf.h"
#include <stdlib.h>

#define JIT_TEST_UBPF 1

#define CHECK_EXIT(ret)                                                        \
	if (ret != 0) {                                                        \
		fprintf(stderr, "Failed to load code: %s\n", errmsg);          \
	}

#define TEST_BPF_CODE ebpf_code
#define TEST_BPF_SIZE sizeof(ebpf_code) - 1

char *errmsg;
struct mem {
	int a;
	int b;
};

const char *ffi_func = "ffi_call";

typedef uint64_t (*ffi_call)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4,
			     uint64_t r5);

uint64_t test_func(uint64_t func_addr, uint64_t arg0, uint64_t arg1,
		   uint64_t arg2, uint64_t arg3)
{
	char *str = (char *)arg0;
	// func_addr(arg0, arg1, arg2, arg3);
	printf("helper-1: \n");
	return 0;
}

int main()
{
	struct mem m = { 1, 2 };
	uint64_t res = 0;
#if JIT_TEST_UBPF
	printf("Use JIT Mode\n");
	// using ubpf jit for x86_64 and arm64
	struct ebpf_vm *vm = ebpf_create();

	// ffi_call my_test_func = test_func;
	ebpf_register(vm, 2, ffi_func, test_func);

	ebpf_toggle_bounds_check(vm, false);

	// remove 0, in the end
	CHECK_EXIT(ebpf_load(vm, TEST_BPF_CODE, TEST_BPF_SIZE,
			     &errmsg));

	// EBPF_OP_CALL
	printf("code len: %d\n", TEST_BPF_SIZE);

	int mem_len = 1024 * 1024;
	char *mem = malloc(mem_len);

	ebpf_jit_fn fn = ebpf_compile(vm, &errmsg);
	if (fn == NULL) {
		fprintf(stderr, "Failed to compile: %s\n", errmsg);
		free(mem);
		return 1;
	}
	res = fn(mem, mem_len);

	printf("%d + %d = %ld\n", m.a, m.b, res);
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