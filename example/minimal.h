
#ifndef EBPF_CODE_H_
#define EBPF_CODE_H_

// original code from libebpf repo
const unsigned char bpf_add_mem_64_bit_minimal[] = ""
"\x61\x12\x00\x00\x00\x00\x00\x00"
"\x61\x10\x04\x00\x00\x00\x00\x00"
"\x0f\x20\x00\x00\x00\x00\x00\x00"
"\x95\x00\x00\x00\x00\x00\x00\x00"
"";

/*
int add_test(struct data *d, int sz) {
 	return d->a + d->b;
}
in 64 bit:
*/
const unsigned char bpf_add_mem_64_bit[] = {
  0x7b, 0x1a, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x63, 0x2a, 0xf4, 0xff, 0x00, 0x00, 0x00, 0x00, 
  0x79, 0xa1, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00, 
  0x61, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x11, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x0f, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/*
int mul_test() {
	int a = 1;
	int b = 2;
	int c = a * b; 
 	return c;
}
in 64 bit: using clang -target bpf -c mul.bpf.c -o mul.bpf.o to compile
*/
const unsigned char bpf_mul_64_bit[] = {
    0xb7, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x63, 0x1a, 0xfc, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xb7, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x63, 0x1a, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x61, 0xa1, 0xfc, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x61, 0xa2, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x2f, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x63, 0x1a, 0xf4, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x61, 0xa0, 0xf4, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*
a * b / 2 for 32 bit
clang -O2 -target bpf -m32 -c example/bpf/mul.bpf.c -o prog.o
*/
const unsigned char bpf_mul_32_bit[] = {
  0xb7, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


#endif
