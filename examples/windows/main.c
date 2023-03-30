#include <stdio.h>
#include <string.h>
#include "ebpf.h"

void load_data(char *filename, void *code, int *code_len)
{
	FILE* fp;
	int length;

	fopen_s(&fp, filename, "r");

	if (fp == NULL) return;

	fseek(fp, 0L, SEEK_END);
	length = ftell(fp);
	//fseek(fp, 0L, SEEK_SET);
	rewind(fp);

	//char buf[2048];
	//int ret = fread(buf, 1, length, fp);
	int ret = fread(code, 1, length, fp);
	if (ret != length) { fputs("Reading error", stderr); }
	fclose(fp);
	*code_len = length;
	//memcpy(code, buf, length);
}

struct skb_buffer {
	unsigned protocol;
	unsigned len;
	char data[10];
};

void test_ebpf_map() {
#include "ebpf_map.h"
	test_hashmap_pass1();
}


int main(int argc, const char* argv[]) {
	test_ebpf_map();
	if (argc < 2) {
		fprintf(stdout, "Error. Usage: main bin\n");
		return -1;
	}
	struct ebpf_inst code[MAX_INSTS] = { 0 };
	int code_len = 0;
	load_data(argv[1], code, &code_len);
	printf("read code size: %d\n", code_len);
	char mem[200] = { 0 };
	int mem_len = 0;
	if (argc >= 3) {
		char* mem_file = argv[2];
		load_data(mem_file, mem, &mem_len);
	}

	struct ebpf_vm *vm = ebpf_create();
	ebpf_vm_load(vm, code, code_len);
	u64 ret = 0;
	if (mem_len == 0) {
		ret = ebpf_vm_exec(vm, NULL, 0);
	}
	else {
		struct skb_buffer buf = { 12, 22, "xxxx" };
		u64 prt = &buf;
		ret = ebpf_vm_exec(vm, &buf, sizeof(struct skb_buffer));
		if (ret == -1) {
			printf("error -1\n");
		}
	}

	printf("Execute result: %llu", ret);
	return 0;
}
