#ifndef UBPF_MBEDTLS_CHECKS_H_
#define UBPF_MBEDTLS_CHECKS_H_
#include "src/ebpf_types.h"

int ebpf_check_args();

int setup_mbedtls_ebpf_progs();
void remove_mbedtls_ebpf_progs();

typedef struct prog_9989_args {
    unsigned char **p;
    unsigned char *end;
} prog_9989_args;

typedef struct prog_9989_args_valid
{
    long long p;
    long long end;
    int len;
} prog_9989_args_valid;


int run_prog_9989(prog_9989_args * args);

#endif
