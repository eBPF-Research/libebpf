
typedef unsigned long long uint64_t;
typedef long long int64_t;
typedef int int32_t;
uint64_t global_context;

union arg_val {
	uint64_t uint64;
	int64_t int64;
	int32_t int32;
	double double_val;
	void *ptr;
};

int _start(uint64_t context)
{
	global_context = context;
	return 0;
}

uint64_t (*__ebpf_call_ffi_dispatcher)(uint64_t context, uint64_t id,
					   uint64_t r1, uint64_t r2,
<<<<<<< HEAD
					   uint64_t r3, uint64_t r4,
					   uint64_t r5) = (void *)0x1;
=======
					   uint64_t r3) = (void *)0x1;
>>>>>>> 182e297 (add ffi implement)

uint64_t print_func(char *str)
{
	union arg_val ret;
<<<<<<< HEAD
	ret.uint64 = __ebpf_call_ffi_dispatcher(global_context, 0, (uint64_t)str, 0, 0, 0, 0);
=======
	ret.uint64 = __ebpf_call_ffi_dispatcher(global_context, 0, (uint64_t)str, 0, 0);
>>>>>>> 182e297 (add ffi implement)
	return ret.uint64;
}

int add_func(int a, int b) {
<<<<<<< HEAD
	// __ebpf_call_ffi_dispatcher(global_context, 3, a, b, 0, 0, 0);
	union arg_val ret;
	ret.uint64 = __ebpf_call_ffi_dispatcher(global_context, 3, a, b, 0, 0, 0);
=======
	union arg_val ret;
	ret.uint64 = __ebpf_call_ffi_dispatcher(global_context, 3, a, b, 0);
>>>>>>> 182e297 (add ffi implement)
	return ret.int32;
}
