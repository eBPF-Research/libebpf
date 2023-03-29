struct data {
	int a;
};

int t;

// buggy
static void (*print_bpf)(char *str, int d) = (void *)0x5; 
void (*print_bpf2)(char *str, int d) = (void *)0x6; 
// works:
// static void (*print_bpf)(char *str) = (void *)0x2;

int print_and_add1(struct data *d, int sz) {
	char a[] = "hello";
	print_bpf(a, t);
	print_bpf2(a, t + 1);
	return 0;
}
