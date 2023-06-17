#include <string.h>
#include "bpf_progs.h"
#include "bpf_host_ffi.h"
#include <stdlib.h>

#define JIT_TEST_UBPF 1

#define CHECK_EXIT(ret)                                                        \
	if (ret != 0) {                                                        \
		fprintf(stderr, "Failed to load code: %s\n", errmsg);          \
	}

#define TEST_BPF_CODE bpf_function_call_add
#define TEST_BPF_SIZE sizeof(bpf_function_call_add) - 1

char *errmsg;
struct mem {
	int a;
	int b;
};

uint64_t print_func(char *str)
{
	printf("helper-1: %s\n", str);
	return 0;
}

int add_func(int a, int b) {
	return a + b;
}

int main()
{
	struct mem m = { 1, 2 };
	uint64_t res = 0;
#if JIT_TEST_UBPF
	printf("Use JIT Mode\n");
	// using ubpf jit for x86_64 and arm64
	struct ebpf_context *context = ebpf_create_context();
	struct ebpf_ffi_func_info func1 = { 
		FFI_FN(print_func),
		FFI_TYPE_ULONG,
		{ FFI_TYPE_POINTER },
		1
	 };
	ebpf_register_ffi(context, 2, func1);
	struct ebpf_ffi_func_info func2 = { 
		FFI_FN(add_func),
		FFI_TYPE_INT,
		{ FFI_TYPE_INT, FFI_TYPE_INT },
		2
	 };
	ebpf_register_ffi(context, 3, func2);

	ebpf_toggle_bounds_check(context->vm, false);

	// remove 0, in the end
	CHECK_EXIT(ebpf_load(context->vm, TEST_BPF_CODE, TEST_BPF_SIZE,
			     &errmsg));

	// EBPF_OP_CALL
	printf("code len: %d\n", TEST_BPF_SIZE);

	int mem_len = 1024 * 1024;
	char *mem = malloc(mem_len);

	ebpf_jit_fn fn = ebpf_compile(context->vm, &errmsg);
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