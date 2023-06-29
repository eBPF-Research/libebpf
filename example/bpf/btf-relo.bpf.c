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

#define SEC(name) \
	_Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wignored-attributes\"")	    \
	__attribute__((section(name), used))				    \
	_Pragma("GCC diagnostic pop")					    \

SEC("prog")
int add_test(struct data *d) {
    return d->a + d->c;
}

// need prog->sec_idx == obj->efile.text_shndx && obj->nr_programs > 1;
// text is not regconized as a program
SEC("prog1")
int main(){
    return 0;
}