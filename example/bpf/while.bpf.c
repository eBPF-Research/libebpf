int print_and_add1(int sz) {
    int n = sz;
    int k = 2;
    while (k < sz) {
        n = n + k;
        // possible infinite loop is skipped
        // k++;
    }
 	return n;
}