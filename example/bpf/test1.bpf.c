// const void (*print_bpf)(char *str) = (void *)0x5; // buggy
//     // call 0x2 or *(u64 *)(r1 + 0), why?
// int print_and_add1(struct data *d, int sz) {
// 	print_bpf("hello bpf\n");
//  	return 0;
// }

// // correct
// int print_and_add2(struct data *d, int sz) {
//     // call 0x5
// 	((void (*)(char *str))((void*)0x5))("hello bpf\n");
//  	return 0;
// }
struct data {
        int a;
        int d;
};

// works:
static void (*print_bpf)(char *str) = (void *)0x2;

int print_and_add1(struct data *d, int sz) {
	char a[] = "hello";
	print_bpf(a);
 	return 0;
}
