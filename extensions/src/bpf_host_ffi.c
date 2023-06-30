#include "extension.h"
#include "bpf_host_ffi.h"
#include "libebpf/libebpf.h"

#define MAX_FFI_FUNCS 128

/** ebpf_context structure.
 *  Contains the eBPF virtual machine (vm) and the Foreign Function Interface
 * (FFI) functions array.
 */
struct ebpf_context {
	struct ebpf_vm *vm;
	struct ebpf_ffi_func_info ffi_funcs[MAX_FFI_FUNCS];
};

struct ebpf_context *ebpf_create_context(void)
{
	struct ebpf_context *context =
		(struct ebpf_context *)malloc(sizeof(struct ebpf_context));
	struct ebpf_vm *vm = ebpf_create();
	context->vm = vm;
	ebpf_register(context->vm, 1, "__ebpf_call_ffi_dispatcher",
		      __ebpf_call_ffi_dispatcher);
	return context;
}

void ebpf_free_context(struct ebpf_context *context) {
    ebpf_destroy(context->vm);
    free(context);
}

void ebpf_register_ffi(struct ebpf_context *context, uint64_t id,
			      struct ebpf_ffi_func_info func_info)
{
	context->ffi_funcs[id] = func_info;
}

uint64_t __ebpf_call_ffi_dispatcher(struct ebpf_context *context,
					   uint64_t id, uint64_t r1,
					   uint64_t r2, uint64_t r3,
					   uint64_t r4, uint64_t r5)
{
	assert(id < MAX_FFI_FUNCS);
	struct ebpf_ffi_func_info *func_info = &context->ffi_funcs[id];
	assert(func_info->func != NULL);

	// Prepare arguments
	uint64_t raw_args[5] = { r1, r2, r3, r4, r5 };
	union arg_val args[5];
	for (int i = 0; i < func_info->num_args; i++) {
		args[i] = to_arg_val(func_info->arg_types[i], raw_args[i]);
	}

	// Call the function
	union arg_val ret;
	switch (func_info->num_args) {
	case 0:
		ret.uint64 = func_info->func(0, 0, 0, 0, 0);
		break;
	case 1:
		ret.uint64 = func_info->func(args[0].uint64, 0, 0, 0, 0);
		break;
	case 2:
		ret.uint64 = func_info->func(args[0].uint64, args[1].uint64, 0,
					     0, 0);
		break;
	case 3:
		ret.uint64 = func_info->func(args[0].uint64, args[1].uint64,
					     args[2].uint64, 0, 0);
		break;
	case 4:
		ret.uint64 = func_info->func(args[0].uint64, args[1].uint64,
					     args[2].uint64, args[3].uint64, 0);
		break;
	case 5:
		ret.uint64 = func_info->func(args[0].uint64, args[1].uint64,
					     args[2].uint64, args[3].uint64,
					     args[4].uint64);
		break;
	default:
		// Handle other cases
		break;
	}

	// Convert the return value to the correct type
	return from_arg_val(func_info->ret_type, ret);
}


union arg_val to_arg_val(enum ffi_types type, uint64_t val)
{
	union arg_val arg;
	switch (type) {
	case FFI_TYPE_INT:
	case FFI_TYPE_UINT:
		arg.uint64 = val;
		break;
	case FFI_TYPE_DOUBLE:
		arg.double_val = *(double *)&val;
		break;
	case FFI_TYPE_POINTER:
		arg.ptr = (void *)val;
		break;
	default:
		// Handle other types
		break;
	}
	return arg;
}

uint64_t from_arg_val(enum ffi_types type, union arg_val val)
{
	switch (type) {
	case FFI_TYPE_INT:
	case FFI_TYPE_UINT:
		return val.uint64;
	case FFI_TYPE_DOUBLE:
		return *(uint64_t *)&val.double_val;
	case FFI_TYPE_POINTER:
		return (uint64_t)val.ptr;
	default:
		// Handle other types
		break;
	}
	return 0;
}
