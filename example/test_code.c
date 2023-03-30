#include "test_code.h"
#include "libebpf.h"

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
	CHECK_EXIT(ebpf_load(vm, ebpf_code, sizeof(ebpf_code) - 1, &errmsg));
	uint64_t res = 0;
	CHECK_EXIT(ebpf_exec(vm, &m, sizeof(m), &res));
	printf("%d + %d = %ld\n", m.a, m.b, res);
}

int main() {
	run_test_code();
	return 0;
}