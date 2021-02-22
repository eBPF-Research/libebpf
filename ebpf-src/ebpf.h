#ifndef EBPF_H_
#define EBPF_H_
//#include <stdint.h>
//#include <stddef.h>
//#include <stdbool.h>

// #include "ebpf_env.h"
#include "ebpf_vm.h"
#include "jit.h"

struct ebpf_vm;
ebpf_vm *init_ebpf_vm(const uint8_t *code, uint32_t code_len);

#endif