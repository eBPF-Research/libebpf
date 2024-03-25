#ifndef _LIBEBPF_FFI_H
#define _LIBEBPF_FFI_H
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
    AGR_INT8,
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
/**
 * @brief Represent a ffi functio entry
 *
 */
struct libebpf_ffi_function {
    /**
     * @brief The function address
     *
     */
    void *ptr;
    /**
     * @brief Name of the function. Note that libebpf will save a copy of this piece of memory
     *
     */
    char *name;
    /**
     * @brief Argument types of the function
     *
     */
    enum libebpf_ffi_type arg_types[6];
    /**
     * @brief Return type of the function
     *
     */
    enum libebpf_ffi_type return_value_type;
};

#ifdef __cplusplus
}
#endif
#endif
