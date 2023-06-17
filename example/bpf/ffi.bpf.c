
typedef unsigned long long uint64_t;
typedef long long int64_t;
typedef int int32_t;
// global context not support
// uint64_t context;

struct data {
	uint64_t context;
};

union arg_val {
	uint64_t uint64;
	int64_t int64;
	int32_t int32;
	double double_val;
	void *ptr;
};

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

static const uint64_t (*__ebpf_call_ffi_dispatcher)(uint64_t context,
						    uint64_t id, uint64_t r1,
						    uint64_t r2,
						    uint64_t r3) = (void *)0x1;

static inline uint64_t print_func(uint64_t context, char *str)
{
	union arg_val ret;
	ret.uint64 =
		__ebpf_call_ffi_dispatcher(context, 2, (uint64_t)str, 0, 0);
	return ret.uint64;
}

static inline int add_func(uint64_t context, int a, int b)
{
	union arg_val ret;
	ret.uint64 = __ebpf_call_ffi_dispatcher(context, 3, a, b, 0);
	return ret.int32;
}
