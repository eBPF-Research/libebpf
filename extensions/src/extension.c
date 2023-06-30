#include "extension.h"
#include "bpf_host_ffi.h"
#include "libebpf/libebpf.h"
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <bpf/bpf.h>

int ebpf_object_relocate_btf(const char *btf_path, const char *obj_path,
			     struct bpf_object *obj);

#define MAX_FFI_FUNCS 128

/** ebpf_context structure.
 *  Contains the eBPF virtual machine (vm) and the Foreign Function Interface
 * (FFI) functions array.
 */
struct ebpf_context {
	const char *obj_path;
	struct bpf_object *obj;

	bool jitted;
	// used in jit
	ebpf_jit_fn fn;
	struct bpf_insn *insns;
	size_t insn_cnt;
	struct ebpf_vm *vm;
	struct ebpf_ffi_func_info ffi_funcs[MAX_FFI_FUNCS];

	char *errmsg;
};

struct ebpf_context *ebpf_create_context(void)
{
	struct ebpf_context *context =
		(struct ebpf_context *)calloc(1, sizeof(struct ebpf_context));
	struct ebpf_vm *vm = ebpf_create();
	context->vm = vm;
	ebpf_register(context->vm, 1, "__ebpf_call_ffi_dispatcher",
		      __ebpf_call_ffi_dispatcher);
	return context;
}

void ebpf_free_context(struct ebpf_context *context)
{
	ebpf_destroy(context->vm);
	free(context);
}

int ebpf_open_object(struct ebpf_context *context, const char *obj_path,
		     const struct ebpf_open_context_opts *opts)
{
	struct ebpf_open_context_opts inner_opt = { 0 };
	int res;

	if (opts) {
		memcpy(&inner_opt, opts, sizeof(struct ebpf_open_context_opts));
	}
	context->obj = bpf_object__open(obj_path);
	if (!context->obj) {
		printf("failed to open object file: %s\n", obj_path);
		return -1;
	}
	context->obj_path = obj_path;
	if (inner_opt.btf_path) {
		res = ebpf_relocate_btf(context, inner_opt.btf_path);
		if (res < 0) {
			return res;
		}
	}
	return 0;
}

int ebpf_relocate_btf(struct ebpf_context *context, const char *btf_path)
{
	if (!context->obj) {
		printf("object file not opened\n");
		return -1;
	}
	return ebpf_object_relocate_btf(btf_path, context->obj_path,
					context->obj);
}

int ebpf_load_userspace(struct ebpf_context *context, const char *program_name,
			bool jit)
{
	struct bpf_program *prog = NULL;
	int res = -1;

	if (!context->obj) {
		printf("object file not opened\n");
		return -1;
	}
	if (program_name) {
		prog = bpf_object__find_program_by_name(context->obj, program_name);
	} else {
		// use the first prog in the object
		prog = bpf_object__next_program(context->obj, NULL);
	}
	if (!prog) {
		printf("cannot find program %s", program_name? program_name: "(NULL)");
		return -1;
	}
	context->insns = bpf_program__insns(prog);
	context->insn_cnt = bpf_program__insn_cnt(prog);
	printf("load insn cnt: %d\n", context->insn_cnt);
	res = ebpf_load(context->vm, context->insns, context->insn_cnt * sizeof(struct bpf_insn),
			&context->errmsg);
	if (res < 0) {
		fprintf(stderr, "Failed to load insn: %s\n", context->errmsg);
		return res;
	}
	if (jit) {
		// run with jit mode
		context->jitted = true;
		ebpf_jit_fn fn = ebpf_compile(context->vm, &context->errmsg);
		if (fn == NULL) {
			fprintf(stderr, "Failed to compile: %s\n",
				context->errmsg);
			return -1;
		}
	} else {
		// ignore for vm
		context->jitted = false;
	}
	return 0;
}

uint64_t ebpf_exec_userspace(struct ebpf_context *context,
			     void *memory, size_t memory_size)
{
	uint64_t return_val = 0;
	int res = -1;

	if (context->jitted) {
		return context->fn(memory, memory_size);
	}
	res = ebpf_exec(context->vm, memory, memory_size, &return_val);
	if (res < 0) {
		printf("ebpf_exec return error: %d", res);
	}
	return return_val;
}

void ebpf_register_ffi(struct ebpf_context *context, uint64_t id,
		       struct ebpf_ffi_func_info func_info)
{
	context->ffi_funcs[id] = func_info;
}

uint64_t __ebpf_call_ffi_dispatcher(struct ebpf_context *context, uint64_t id,
				    uint64_t r1, uint64_t r2, uint64_t r3,
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
