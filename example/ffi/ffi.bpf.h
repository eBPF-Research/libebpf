#ifndef FFI_HELPER_H
#define FFI_HELPER_H

typedef unsigned long long uint64_t;
typedef long long int64_t;
typedef int int32_t;
// global context not support
// uint64_t context;

union arg_val {
	uint64_t uint64;
	int64_t int64;
	int32_t int32;
	double double_val;
	void *ptr;
};

struct arg_list {
	uint64_t args[6];
};

// static const uint64_t (*bpf_ffi_call_helper)(uint64_t context,
// 						    uint64_t id, uint64_t r1,
// 						    uint64_t r2,
// 						    uint64_t r3) = (void *)0x1;


static const uint64_t (*ffi_call)(uint64_t id, uint64_t arg_list) = (void *)0x1;



// #define FFI_CALL_N(FUNC_MARCO, ...) \
// 	struct arg_list argn; \
// 	FUNC_MARCO(argn, __VA_ARGS__); \
// 	bpf_ffi_call_helper(func, &argn)

#define FFI_CALL_1(func, arg1) \
	struct arg_list argn; \
	argn.args[0] = arg1; \
	ffi_call(func, &argn) 

#define FFI_CALL_2(func, arg1, arg2) \
	struct arg_list argn; \
	argn.args[0] = arg1; \
	argn.args[1] = arg2; \
	ffi_call(func, &argn) 

// static inline uint64_t print_func(uint64_t context, char *str)
// {
// 	union arg_val ret;
// 	ret.uint64 =
// 		bpf_ffi_call_helper(context, 2, (uint64_t)str, 0, 0);
// 	return ret.uint64;
// }

// static inline int add_func(uint64_t context, int a, int b)
// {
// 	union arg_val ret;
// 	ret.uint64 = bpf_ffi_call_helper(context, 3, a, b, 0);
// 	return ret.int32;
// }

#endif
