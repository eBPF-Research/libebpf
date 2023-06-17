const int i = 0;
static int j = 1;
int k = 1;
void (*print_bpf)(char *str) = (void *)0x5;

int print_and_add1(struct data *d, int sz) {
    // call 0x2 or *(u64 *)(r1 + 0), why?
	print_bpf("hello bpf\n");
    int n = sz;
    k = 2;
    while (k < sz) {
        n = n + k;
        k++;
    }
    print_bpf("complete\n");
 	return i + j + n;
}

int print_and_add2(struct data *d, int sz) {
    print_bpf = (void *)0x6;
    // call 0x5
	((void (*)(char *str))((void*)0x5))("hello bpf\n");
    int n = print_and_add1(d, sz);
 	return i + k + n;
}

