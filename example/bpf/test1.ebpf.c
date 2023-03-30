struct data {
	int a;
	int b;
};


int add_test(struct data *d, int sz) {
	return d->a + d->b;
}