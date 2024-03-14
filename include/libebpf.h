#ifndef _LIBEBPF_H
#define _LIBEBPF_H

#include <stdint.h>
#include <stddef.h>
#include "libebpf_insn.h"
#ifdef __cplusplus
extern "C" {
#endif

#define MAX_EXTERNAL_HELPER ((size_t)4096)
#define MAX_EXTERNAL_HELPER_NAME_LENGTH ((size_t)100)
#define EBPF_STACK_SIZE ((size_t)512)
#define MAX_LOCAL_FUNCTION_LEVEL 20

/**
 * @brief Opaque type for a libebpf virtual machine
 *
 */
struct ebpf_vm;

typedef struct ebpf_vm ebpf_vm_t;

/**
 * @brief Function prototype for a jitted ebpf program
 *
 */
typedef int (*ebpf_jit_fn)(void *mem, size_t mem_len, uint64_t *return_value);

/**
 * @brief Function prototype for external helper
 *
 */
typedef uint64_t (*ebpf_external_helper_fn)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/**
 * @brief Helper prototype for the map_by_fd function.
 * See https://docs.kernel.org/bpf/standardization/instruction-set.html#id20 for details
 *
 */
typedef uint64_t (*ebpf_map_by_fd_callback)(int fd);

/**
 * @brief Helper prototype for the map_val function.
 * See https://docs.kernel.org/bpf/standardization/instruction-set.html#id20 for details
 *
 */
typedef char *(*ebpf_map_val_callback)(uint64_t map_ptr);

/**
 * @brief Helper prototype for the var_addr function.
 * See https://docs.kernel.org/bpf/standardization/instruction-set.html#id20 for details
 *
 */
typedef char *(*ebpf_var_addr_callback)(int var_id);

/**
 * @brief Helper prototype for the code_addr function.
 * See https://docs.kernel.org/bpf/standardization/instruction-set.html#id20 for details
 *
 */
typedef char *(*ebpf_code_addr_callback)(int);

/**
 * @brief Helper prototype for the map_by_idx function.
 * See https://docs.kernel.org/bpf/standardization/instruction-set.html#id20 for details
 *
 */
typedef uint64_t (*ebpf_map_by_idx_callback)(int);

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

/**
 * @brief Create a libebpf virtual machine
 *
 * @return ebpf_vm_t* A pointer to the vm if succeeded, otherwise NULL. Use ebpf_error_string to retrive the error details.
 */
ebpf_vm_t *ebpf_vm_create();

/**
 * @brief Destroy the given vm instance.
 *
 */
void ebpf_vm_destroy(ebpf_vm_t *);

/**
 * @brief Register an external helper.
 *
 * @param vm The virtual machine instance
 * @param index Index of the helper
 * @param name Name of the helper
 * @param fn The function instance
 * @return int 0 if succeeded, otherwise if failed. Call ebpf_error_string to get the error details.
 */
int ebpf_vm_register_external_helper(ebpf_vm_t *vm, size_t index, const char *name, ebpf_external_helper_fn fn);

/**
 * @brief Set ld64 helpers
 * See https://docs.kernel.org/bpf/standardization/instruction-set.html#id20 for details
 * @param vm The virtual machine instance
 * @param map_by_fd
 * @param map_by_idx
 * @param map_val
 * @param code_addr
 * @param var_addr
 */
void ebpf_vm_set_ld64_helpers(ebpf_vm_t *vm, ebpf_map_by_fd_callback map_by_fd, ebpf_map_by_idx_callback map_by_idx, ebpf_map_val_callback map_val,
                              ebpf_code_addr_callback code_addr, ebpf_var_addr_callback var_addr);

/**
 * @brief Load instructions for the given vm instance
 *
 * @param vm The vm instance
 * @param code Code buffer
 * @param code_len Count of instructions
 * @return int 0 if succeeded, other if failed. Use ebpf_error_string to get the error details.
 */
int ebpf_vm_load_instructions(ebpf_vm_t *vm, const struct libebpf_insn *code, size_t code_len);

/**
 * @brief Unload instructions for the given vm instance. Will also remove the compiled function.
 *
 * @param vm The vm instance
 */
void ebpf_vm_unload_instructions(ebpf_vm_t *vm);

/**
 * @brief Execute the loaded instructions through the intepreter, with the given memory
 *
 * @param vm The vm instance
 * @param mem Memory buffer to the ebpf program, will be in %r1
 * @param mem_len Memory buffer size to the ebpf program, will be in %r2
 * @param return_value Buffer to store the return value
 * @return int 0 if the program exits normally, otherwise if failed. Call ebpf_error_string to get the error details.
 */
int ebpf_vm_run(ebpf_vm_t *vm, void *mem, size_t mem_len, uint64_t *return_value);

/**
 * @brief Compile the loaded instructions to a native function. If it's already compiled, just return the compiled function.
 *
 * @param vm The vm instance
 * @return ebpf_jit_fn A pointer to the compiled function. NULL if failed. Use ebpf_error_string to get the error details.
 */
ebpf_jit_fn ebpf_vm_compile(ebpf_vm_t *vm);

#ifdef __cplusplus
}
#endif

#endif
