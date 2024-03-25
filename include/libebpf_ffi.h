#ifndef _LIBEBPF_FFI_H
#define _LIBEBPF_FFI_H
#include "libebpf_execution.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Represent types that will be used in FFI definition
 *
 */
enum libebpf_ffi_type {
    ARG_VOID = 0,
    ARG_INT8,
    ARG_INT16,
    ARG_INT32,
    ARG_INT64,
    ARG_UINT8,
    ARG_UINT16,
    ARG_UINT32,
    ARG_UINT64,
    ARG_FLOAT32,
    ARG_FLOAT64,
    ARG_PTR
};

#define LIBEBPF_FFI_MAX_ARGUMENT_COUNT 6

/**
 * @brief Represent a ffi functio entry
 *
 */
struct libebpf_ffi_function {
    /**
     * @brief The function address
     *
     */
    void *(*ptr)(void *, void *, void *, void *, void *, void *);
    /**
     * @brief Name of the function. Note that libebpf will save a copy of this piece of memory
     *
     */
    char *name;
    /**
     * @brief Argument types of the function
     *
     */
    enum libebpf_ffi_type arg_types[LIBEBPF_FFI_MAX_ARGUMENT_COUNT];
    /**
     * @brief Return type of the function
     *
     */
    enum libebpf_ffi_type return_value_type;
};

/**
 * @brief Register a FFI function. It could be called through a series of bpf helpers. Call to FFI function would be type safe, libebpf will convert
 * arguments to the given argument types
 *
 * @param ctx Context
 * @param func Pointer to the function
 * @param name Name of the function
 * @param arg_types Types of the given FFI function
 * @param return_value_type Return type of the given FFI function
 * @return Negative value if failed. Otherwise the function ID
 */
int ebpf_execution_context__register_ffi_function(ebpf_execution_context_t *ctx, void *func, const char *name, enum libebpf_ffi_type arg_types[6],
                                                  enum libebpf_ffi_type return_value_type);
#ifdef __cplusplus
}
#endif
#endif
