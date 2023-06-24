#include "ffi.bpf.h"


struct data {
	uint64_t val;
};

// call function-1
// int add_func(uint64_t context, int a, int b);

// call function-2
// uint64_t print_func(uint64_t context, char *str);

#define FUNC_ADD 1
#define FUNC_PRINT 2

static inline int add_func(int a, int b) {
	FFI_CALL_2(FUNC_ADD, a, b);
}

static inline uint64_t print_func(char *str) {
	FFI_CALL_1(FUNC_PRINT, str);
}

int bpf_main(struct data *d)
{
	// not support global value
	char str[] = "hello";
	// print_func("hello") not support
	uint64_t n = print_func(str);
	int x = (int)n + d->val;
	return add_func(x, 1);
}
