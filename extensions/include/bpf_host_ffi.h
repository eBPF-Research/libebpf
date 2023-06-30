#ifndef BPF_FFI_DEFS_H
#define BPF_FFI_DEFS_H

#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include "libebpf/libebpf.h"

#define MAX_ARGS 5

struct ebpf_context;

/* Useful for eliminating compiler warnings.  */
#define FFI_FN(f) ((void (*)(void))f)

enum ffi_types {
	FFI_TYPE_VOID,
	FFI_TYPE_INT,
	FFI_TYPE_UINT,
	FFI_TYPE_LONG,
	FFI_TYPE_ULONG,
	FFI_TYPE_FLOAT,
	FFI_TYPE_DOUBLE,
	FFI_TYPE_POINTER,
	FFI_TYPE_STRUCT,
	FFI_TYPE_STRING,
	FFI_TYPE_BOOL,
	FFI_TYPE_INT8,
	FFI_TYPE_UINT8,
	FFI_TYPE_INT16,
	FFI_TYPE_UINT16,
	FFI_TYPE_INT32,
	FFI_TYPE_UINT32,
	FFI_TYPE_INT64,
	FFI_TYPE_UINT64,
	FFI_TYPE_INT128,
	FFI_TYPE_UINT128,
	FFI_TYPE_ENUM,
	FFI_TYPE_ARRAY,
	FFI_TYPE_UNION,
	FFI_TYPE_FUNCTION,
};

typedef uint64_t (*ffi_func)(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4,
			     uint64_t r5);

struct ebpf_ffi_func_info {
	ffi_func func;
	enum ffi_types ret_type;
	enum ffi_types arg_types[MAX_ARGS];
	int num_args;
};

union arg_val {
	uint64_t uint64;
	int64_t int64;
	double double_val;
	void *ptr;
};

static inline union arg_val to_arg_val(enum ffi_types type, uint64_t val);

static inline uint64_t from_arg_val(enum ffi_types type, union arg_val val);

void ebpf_register_ffi(struct ebpf_context *context, uint64_t id,
			      struct ebpf_ffi_func_info func_info);

// not used directly
uint64_t __ebpf_call_ffi_dispatcher(struct ebpf_context *context,
					   uint64_t id, uint64_t r1,
					   uint64_t r2, uint64_t r3,
					   uint64_t r4, uint64_t r5);

#endif
