#include "extension.h"
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
}

int main(int argc, char **argv)
{
	int res = 1;
	const char *obj_path = argv[1];
	const char *btf_path = argv[2];
	struct ebpf_context *ctx;
	const char *prog_name = NULL;
	uint64_t return_val;

	// use a struct as memory
	struct data memory = { 1, 2, 3 };

	if (argc < 3) {
		printf("Usage: %s <obj_path>\n", argv[0]);
		return 1;
	}
	libbpf_set_print(libbpf_print_fn);

	ctx = ebpf_create_context();
	// load the btf for relocation
	res = ebpf_load_relocate_btf(ctx, btf_path);
	if (res < 0) {
		printf("ebpf_relocate_btf failed: %s", btf_path);
		return res;
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
		printf("ebpf_relocate_btf failed: %s", btf_path);
		return res;
	}
	return_val = ebpf_exec_userspace(ctx, &memory, sizeof(memory));
	printf("res = %lld\n", return_val);
	ebpf_free_context(ctx);
	test_find_func_proto(btf_path, "main");
	return res;
}
