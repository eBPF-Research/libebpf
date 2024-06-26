#ifndef _LIBEBPF_H
#define _LIBEBPF_H

#include <stddef.h>
#include "libebpf_vm.h"
#include "libebpf_execution.h"
#include "libebpf_map.h"
#include "libebpf_map_ringbuf.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Function prototype for allocating a piece of executable memory and copy the given buffer onto it
 *
 */
typedef void *(*ebpf_allocate_execuable_memory_and_copy)(void *buffer, size_t bufsize);

/**
 * @brief Function prototype for releasing a piece of executable memory
 *
 */
typedef int (*ebpf_release_executable_memory)(void *mem, size_t len);

/**
 * @brief Function prototype for the global custom memory allocator
 *
 */
typedef void *(*ebpf_malloc)(size_t size);

/**
 * @brief Function prototype for the global custom memory de-allocator
 *
 */

typedef void (*ebpf_free)(void *mem);

/**
 * @brief Function prototype for global custom re-alloc
 *
 */
typedef void *(*ebpf_realloc)(void *, size_t);

/**
 * @brief Set the global memory allocator. If not set, default to malloc & free & realloc in stdlib.h
 *
 * @param malloc The malloc function
 * @param free The free function
 * @param realloc The realloc function
 */
void ebpf_set_global_memory_allocator(ebpf_malloc malloc, ebpf_free free, ebpf_realloc realloc);

/**
 * @brief Set functions which will be used for JIT
 *
 * @param allocate Function to allocate a piece of executable memory and copy buffer to it
 * @param release Function to release a piece of executable memory
 */
void ebpf_set_executable_memory_allocator(ebpf_allocate_execuable_memory_and_copy *allocate, ebpf_release_executable_memory *release);

/**
 * @brief Get the global error string
 *
 * @return const char* The error string
 */
const char *ebpf_error_string();

#ifdef __cplusplus
}
#endif

#endif
