

// #define USE_NEW_VERSION

struct data {
	int a;
	#ifdef USE_NEW_VERSION
	int b;
	#endif
	int c;
	int d;
};

int add_test(struct data *d) {
	return d->a + d->c;
}