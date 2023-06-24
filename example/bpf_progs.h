
#ifndef EBPF_TEST_CODE_H_
#define EBPF_TEST_CODE_H_

// original code from libebpf repo
const unsigned char bpf_add_mem_64_bit_minimal[] = ""
"\x61\x12\x00\x00\x00\x00\x00\x00"
"\x61\x10\x04\x00\x00\x00\x00\x00"
"\x0f\x20\x00\x00\x00\x00\x00\x00"
"\x95\x00\x00\x00\x00\x00\x00\x00"
"";

/// ebpf code generate by compile framework
// static int (*add)(int a, int b) = (void *)0x3;
// int print_and_add1(struct data *d, int sz) {
//  	return add(1, 3);
// }
const unsigned char bpf_function_call_add[] = ""
"\xb7\x01\x00\x00\x01\x00\x00\x00\xb7\x02\x00\x00\x03\x00\x00\x00\x85\x00\x00\x00\x03\x00\x00\x00\x95"
"\x00\x00\x00\x00\x00\x00\x00";

// static void (*print_bpf)(char *str) = (void *)0x2;
// int print_and_add1(struct data *d, int sz) {
// 	char a[] = "hello";
// 	print_bpf(a);
//  	return 0;
// }
const unsigned char bpf_function_call_print[] = ""
"\xb7\x01\x00\x00\x6f\x00\x00\x00\x6b\x1a\xfc\xff\x00\x00\x00\x00\xb7\x01\x00\x00\x68\x65\x6c\x6c\x63"
"\x1a\xf8\xff\x00\x00\x00\x00\xbf\xa1\x00\x00\x00\x00\x00\x00\x07\x01\x00\x00\xf8\xff\xff\xff\x85\x00"
"\x00\x00\x02\x00\x00\x00\xb7\x00\x00\x00\x00\x00\x00\x00\x95\x00\x00\x00\x00\x00\x00\x00";

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
const unsigned char bpf_mul_optimized[] = {
  0xb7, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


const unsigned char bpf_ffi_code[] = ""
"\xbf\x16\x00\x00\x00\x00\x00\x00\xb7\x01\x00\x00\x6f\x00\x00\x00\x6b\x1a\xfc\xff\x00\x00\x00\x00\xb7"
"\x01\x00\x00\x68\x65\x6c\x6c\x63\x1a\xf8\xff\x00\x00\x00\x00\x79\x61\x00\x00\x00\x00\x00\x00\xbf\xa3"
"\x00\x00\x00\x00\x00\x00\x07\x03\x00\x00\xf8\xff\xff\xff\xb7\x02\x00\x00\x02\x00\x00\x00\xb7\x04\x00"
"\x00\x00\x00\x00\x00\xb7\x05\x00\x00\x00\x00\x00\x00\x85\x00\x00\x00\x01\x00\x00\x00\x67\x00\x00\x00"
"\x20\x00\x00\x00\xc7\x00\x00\x00\x20\x00\x00\x00\x79\x61\x00\x00\x00\x00\x00\x00\xb7\x02\x00\x00\x03"
"\x00\x00\x00\xbf\x03\x00\x00\x00\x00\x00\x00\xb7\x04\x00\x00\x01\x00\x00\x00\xb7\x05\x00\x00\x00\x00"
"\x00\x00\x85\x00\x00\x00\x01\x00\x00\x00\x95\x00\x00\x00\x00\x00\x00\x00";

#endif
