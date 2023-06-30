#include "extension.h"
#include "bpf_host_ffi.h"
#include <bpf/libbpf.h>
#include <bpf/btf.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

struct data {
	int a;
#ifdef USE_NEW_VERSION
	int b;
#endif
	int c;
	int d;
};

void dump_type(void *ctx, const char *fmt, va_list args) {
	vprintf(fmt, args);
}

void test_find_func_proto(const char *btf_path, const char* name) {
	struct btf* host_btf = btf__parse(btf_path, NULL);
	if (!host_btf) {
		printf("failed to parse btf file: %s\n", btf_path);
		return;
	}
	int id = btf__find_by_name(host_btf, name);
	if (id < 0) {
		printf("failed to find %s\n", name);
		return;
	}
	const struct btf_type* t = btf__type_by_id(host_btf, id);
	if (!t) {
		printf("failed to find type %s\n", name);
		return;
	}
	int type_id = btf__resolve_type(host_btf, t->type);
	printf("found %s [id] %d %d\n", name, id, type_id);
	struct btf_dump *dumper;

	dumper = btf_dump__new(host_btf, dump_type, NULL, NULL);
	if (!dumper) {
		printf("failed to create dumper\n");
		return;
	}
	if (!btf_is_func(t)) {
		printf("not a func\n");
	}
	btf_dump__emit_type_decl(dumper, type_id, NULL);
	printf("\n");

	// find offset
	
}

// avoid const emit
int add_func(int a, int b)
{
	return a + b;
}

uint64_t print_func(char *str)
{
	printf("helper-1: %s\n", str);
	return strlen(str);
}

int test_register_ffi(struct ebpf_context* ctx) {
	// struct ebpf_ffi_func_info func2 = { FFI_FN(add_func),
	// 				    FFI_TYPE_INT,
	// 				    { FFI_TYPE_INT, FFI_TYPE_INT },
	// 				    2 };
	// ebpf_register_ffi(ctx, 3, func2);
	// struct ebpf_ffi_func_info func1 = {
	// 	FFI_FN(print_func), FFI_TYPE_ULONG, { FFI_TYPE_POINTER }, 1
	// };
	// ebpf_register_ffi(ctx, 2, func1);
	struct ebpf_vm *vm = *(struct ebpf_vm **)ctx;
	ebpf_register(vm, 2, "print_func", print_func);
	ebpf_register(vm, 3, "add_func", add_func);
}

int main(int argc, char **argv)
{
	int res = 1;
	struct ebpf_context *ctx;
	const char *prog_name = NULL;
	const char *obj_path = NULL;
	const char *btf_path = NULL;
	uint64_t return_val;

	// use a struct as memory
	struct data memory = { 1, 2, 3 };

	if (argc < 2) {
		printf("Usage: %s <obj_path> [<btf_path>]\n", argv[0]);
		return 1;
	}
	obj_path = argv[1];
	if (argc >= 3) {
		btf_path = argv[2];
	}
	libbpf_set_print(libbpf_print_fn);

	ctx = ebpf_create_context();
	test_register_ffi(ctx);
	if (btf_path) {
		// load the btf for relocation
		res = ebpf_load_relocate_btf(ctx, btf_path);
		if (res < 0) {
			printf("ebpf_relocate_btf failed: %s", btf_path);
			return res;
		}
		test_find_func_proto(btf_path, "add_func");
	}
	// open the object file
	res = ebpf_open_object(ctx, obj_path);
	if (res < 0) {
		printf("ebpf_open_object failed: %s", obj_path);
		return res;
	}
	// use the first program and relocate based on btf if btf has been
	// loaded
	res = ebpf_load_userspace(ctx, NULL, false);
	if (res < 0) {
		printf("ebpf_load_userspace failed\n");
		return res;
	}
	return_val = ebpf_exec_userspace(ctx, &memory, sizeof(memory));
	printf("res = %lld\n", return_val);
	ebpf_free_context(ctx);
	return res;
}
