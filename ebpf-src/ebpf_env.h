#ifndef UBPF_ENV_H_
#define UBPF_ENV_H_
#include "ebpf_types.h"

enum InsertPoint {
    MBED_TLS_KEY_CHECK = 0,
    
};

struct ebpf_prog;

typedef struct ebpf_env {
    struct ebpf_prog *prog_list;
    struct ebpf_prog *tail;
    int cur_size;
} ebpf_env;

extern ebpf_env current_env;

typedef struct ebpf_prog {
    // char tag[8]; 
    int prog_id;
    struct ebpf_prog *next;
    struct ebpf_vm *vm;
} ebpf_prog;
/*

*/
void init_ebpf_env();
ebpf_prog* ebpf_add_prog(const void *code, u32 code_len);
int ebpf_remove_prog(ebpf_prog *prog);
void destory_ebpf_env();


/*
Extension functions for eBPF
*/
int ebpf_strlen(char *str);

#endif