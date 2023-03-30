#include <stdio.h>
#include <string.h>
#include "ebpf.h"

#define LINUX_TEST // Test in Linux
// #define WIN_TEST // windows

#ifdef LINUX_TEST
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <math.h>
#include "ebpf.h"

void ebpf_set_register_offset(int x);
static void *readfile(const char *path, size_t maxlen, size_t *len);
static void register_functions(struct ebpf_vm *vm);

int main(int argc, char **argv)
{
	const char *mem_filename = NULL;
	bool jit = false;


	if (argc < 2) {
		fprintf(stdout, "Usage: main bin [mem]\n");
		return 0;
	}

	const char *code_filename = argv[1];
	size_t code_len;
	void *code = readfile(code_filename, 1024 * 1024, &code_len);
	if (code == NULL) {
		return 1;
	}
	if (argc >= 3) {
		mem_filename = argv[2];
	}

	size_t mem_len = 0;
	void *mem = NULL;
	if (mem_filename != NULL) {
		mem = readfile(mem_filename, 1024 * 1024, &mem_len);
		if (mem == NULL) {
			return 1;
		}
	}

	struct ebpf_vm *vm = ebpf_create();
	if (!vm) {
		fprintf(stderr, "Failed to create VM\n");
		return 1;
	}

	register_functions(vm);

	int rv = ebpf_vm_load(vm, code, code_len);
	free(code);

	if (rv < 0) {
		fprintf(stderr, "Failed to load code\n");
		ebpf_vm_destroy(vm);
		return 1;
	}

	uint64_t ret = ebpf_vm_exec(vm, mem, mem_len);;

	printf("0x%"PRIx64"\n", ret);

	ebpf_vm_destroy(vm);

	return 0;
}

static void *readfile(const char *path, size_t maxlen, size_t *len)
{
	FILE *file;
	file = fopen(path, "r");

	if (file == NULL) {
		fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
		return NULL;
	}

	void *data = calloc(maxlen, 1);
	size_t offset = 0;
	size_t rv;
	while ((rv = fread(data + offset, 1, maxlen - offset, file)) > 0) {
		offset += rv;
	}

	if (ferror(file)) {
		fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
		fclose(file);
		free(data);
		return NULL;
	}

	if (!feof(file)) {
		fprintf(stderr, "Failed to read %s because it is too large (max %u bytes)\n",
			path, (unsigned)maxlen);
		fclose(file);
		free(data);
		return NULL;
	}

	fclose(file);
	if (len) {
		*len = offset;
	}
	return data;
}

static uint64_t
gather_bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e)
{
	return ((uint64_t)a << 32) |
		((uint32_t)b << 24) |
		((uint32_t)c << 16) |
		((uint16_t)d << 8) |
		e;
}

static void
trash_registers(void)
{
	/* Overwrite all caller-save registers */
	asm(
		"mov $0xf0, %rax;"
		"mov $0xf1, %rcx;"
		"mov $0xf2, %rdx;"
		"mov $0xf3, %rsi;"
		"mov $0xf4, %rdi;"
		"mov $0xf5, %r8;"
		"mov $0xf6, %r9;"
		"mov $0xf7, %r10;"
		"mov $0xf8, %r11;"
	);
}

static uint32_t
sqrti(uint32_t x)
{
	return x / 2;
}

static void print_str(char *str) {
	printf("%s\n", str);
}

static void
register_functions(struct ebpf_vm *vm)
{
	ebpf_register(vm, 1, "sqrti", sqrti);
	ebpf_register(vm, 2, "print_str", print_str);
	// ebpf_register(vm, 0, "gather_bytes", gather_bytes);
	// ebpf_register(vm, 1, "memfrob", memfrob);
	// ebpf_register(vm, 2, "trash_registers", trash_registers);
	// ebpf_register(vm, 3, "sqrti", sqrti);
	// ebpf_register(vm, 4, "strcmp_ext", strcmp);
}

#endif // UNIT_TEST
