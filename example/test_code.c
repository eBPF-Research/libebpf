#include "test_code.h"
#include "libebpf/libebpf.h"

#define CHECK_EXIT(ret) \
	if (ret != 0) { \
		fprintf(stderr, "Failed to load code: %s\n", errmsg); \
	}

char *errmsg;

struct mem {
	int a;
	int b;
};


void run_test_code() {
	struct mem m = {1, 2};
	struct ebpf_vm* vm = ebpf_create();
	// remove 0, in the end
	CHECK_EXIT(ebpf_load(vm, example_test_o, sizeof(example_test_o), &errmsg));
	uint64_t res = 0;
#if JIT_TEST
	// ebpf_jit_fn fn = ebpf_compile(vm, &errmsg);
	// int mem_len = 1024 * 1024;
	// char* mem = malloc(mem_len);
    //     if (fn == NULL) {
    //         fprintf(stderr, "Failed to compile: %s\n", errmsg);
    //         free(errmsg);
    //         free(mem);
    //         return 1;
    //     }
    // res = fn(mem, mem_len);
#else
	CHECK_EXIT(ebpf_exec(vm, &m, sizeof(m), &res));
#endif
	printf("%d + %d = %ld\n", m.a, m.b, res);
}

int main() {
	run_test_code();
	return 0;
}