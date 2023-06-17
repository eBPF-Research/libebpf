const int i = 0;
static int j = 1;
int k = 1;

int add1(struct data *d, int sz) {
 	return i + j;
}

int add2(struct data *d, int sz) {
 	return i + k;
}

int add3(struct data *d, int sz) {
 	return j + k;
}
