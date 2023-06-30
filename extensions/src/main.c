#include "extension.h"
#include <bpf/libbpf.h>

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
	return res;
}
