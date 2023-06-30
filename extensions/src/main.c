#include "extension.h"
#include <bpf/libbpf.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	int res = 1;
	if (argc < 3) {
		printf("Usage: %s <obj_path>\n", argv[0]);
		return 1;
	}
	libbpf_set_print(libbpf_print_fn);
	const char *obj_path = argv[1];
	const char* btf_path = argv[2];
	struct btfgen_info* info = btfgen_new_info(btf_path);
	if (!info) {
		printf("failed to create btfgen_info\n");
		return 1;
	}
	res = btfgen_record_obj(info, obj_path);
out:
	btfgen_free_info(info);
	return res;
}
