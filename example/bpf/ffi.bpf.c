#include "ffi.bpf.h"

static inline int add_func(uint64_t context, int a, int b);
static inline uint64_t print_func(uint64_t context, char *str);

int _start(struct data *d, int sz)
{
	// not support global value
	char str[] = "hello";
	// print_func("hello") not support
	uint64_t n = print_func(d->context, str);
	int x = (int)n;
	return add_func(d->context, x, 1);
}
