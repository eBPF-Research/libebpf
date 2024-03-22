#ifndef _LIBEBPF_H
#define _LIBEBPF_H

#include <stddef.h>
#include "libebpf_vm.h"
#include "libebpf_execution.h"

#ifdef __cplusplus
extern "C" {
#endif

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
 * @brief Set the global memory allocator. If not set, default to malloc & free in stdlib.h
 *
 * @param malloc The malloc function
 * @param free The free function
 */
void ebpf_set_global_memory_allocator(ebpf_malloc malloc, ebpf_free free);

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
