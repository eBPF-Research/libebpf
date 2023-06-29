#define USE_NEW_VERSION

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

struct data {
        int a;
        #ifdef USE_NEW_VERSION
        int b;
        #endif
        int c;
        int d;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif


int add_test(struct data *d) {
    return d->a + d->c;
}

