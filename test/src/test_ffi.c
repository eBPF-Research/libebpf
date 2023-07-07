#include <string.h>
#include "bpf_progs.h"
#include "bpf_host_ffi.h"
#include <stdlib.h>
#include "test_defs.h"

#define TEST_BPF_CODE bpf_ffi_code
#define TEST_BPF_SIZE sizeof(bpf_ffi_code) - 1

typedef unsigned int (*kernel_fn)(const void *ctx,
					    const struct bpf_insn *insn);

char *errmsg;
struct mem {
	uint64_t val;
};

int main()
{
	struct mem m = { __LINE__ };
	uint64_t res = 0;
	// using ubpf jit for x86_64 and arm64
	struct ebpf_vm *vm = ebpf_create();

	register_ffi_handler(vm);

	ebpf_toggle_bounds_check(vm, false);

	// remove 0, in the end
	CHECK_EXIT(
		ebpf_load(vm, TEST_BPF_CODE, TEST_BPF_SIZE, &errmsg));

	// EBPF_OP_CALL
	printf("code len: %d\n", TEST_BPF_SIZE);

	int mem_len = 1024 * 1024;
	char *mem = malloc(mem_len);
	CHECK_EXIT(ebpf_exec(vm, &m, sizeof(m), &res));
	printf("res = %lld\n", res);
	return 0;
}