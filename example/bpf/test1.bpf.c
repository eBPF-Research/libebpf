struct data {
	int a;
	int b;
};

void (*print_bpf)(char *str) = (void *)1;

int add_test(struct data *d, int sz) {
	print_bpf("hello bpf\n");
 	return d->a + d->b;
}
