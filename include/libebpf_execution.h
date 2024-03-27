#ifndef _LIBEBPF_EXECUTION_H
#define _LIBEBPF_EXECUTION_H

#include "libebpf_vm.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque type for an ebpf_state.
 * ebpf_state provides interfaces to create & operate on maps, defining FFI interfaces, and provides helpers for ebpf_vm to do these operations.
 */
struct ebpf_state;

typedef struct ebpf_state ebpf_state_t;

/**
 * @brief Global context for the current thread. You must set it before run your ebpf program, if you want to use features provided by
 * ebpf_state
 *
 */
extern __thread ebpf_state_t *ebpf_state__thread_global_state;

/**
 * @brief Create an ebpf_state
 *
 * @return ebpf_state_t* A pointer to the context if succeeded. NULL if failed. Call ebpf_error_string to get error details.
 */
ebpf_state_t *ebpf_state__create();

/**
 * @brief Destroy the ebpf_state
 *
 * @param ctx Pointer to the context
 */
void ebpf_state__destroy(ebpf_state_t *ctx);

/**
 * @brief Setup helpers provided by ebpf_state for the given ebpf_vm
 *
 * @param vm The vm instance
 */
void ebpf_state__setup_internal_helpers(ebpf_vm_t *vm);
#ifdef __cplusplus
}
#endif

#endif
