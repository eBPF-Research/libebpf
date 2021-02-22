#pragma once
#include <stddef.h>

// customer memory manager
void* ebpf_malloc(size_t n);
void* ebpf_realloc(void *rmem, size_t orisize, size_t newsize);
void* ebpf_calloc(size_t nelem, size_t elmsize);
void ebpf_free(void* rmem);

// heap memory manager