#ifndef _LIBEBPF_EXECUTION_H
#define _LIBEBPF_EXECUTION_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque type for an execution context.
 * Execution context provides interfaces to create & operate on maps, defining FFI interfaces, and run ebpf programs using ebpf_vm. eBPF programs
 * executed through an execution context could use helpers related to maps and FFI.
 */
struct ebpf_execution_context;

typedef struct ebpf_execution_context ebpf_execution_context_t;

/**
 * @brief Create an execution context
 *
 * @return ebpf_execution_context_t* A pointer to the context if succeeded. NULL if failed. Call ebpf_error_string to get error details.
 */
ebpf_execution_context_t *ebpf_execution_context__create();

/**
 * @brief Destroy the execution context
 *
 * @param ctx Pointer to the context
 */
void ebpf_execution_context__destroy(ebpf_execution_context_t *ctx);


#ifdef __cplusplus
}
#endif

#endif
