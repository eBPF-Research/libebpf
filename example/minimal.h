
#ifndef EBPF_CODE_H_
#define EBPF_CODE_H_

const unsigned char ebpf_code[] = ""
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
const unsigned char bpf_code_64_bit[] = {
  0x7b, 0x1a, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x63, 0x2a, 0xf4, 0xff, 0x00, 0x00, 0x00, 0x00, 
  0x79, 0xa1, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00, 
  0x61, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x11, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x0f, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

#endif
