#ifndef _LIBEBPF_FFI_BPF_H
#define _LIBEBPF_FFI_BPF_H

#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define LIBEBPF_FFI_HELPER_INDEX__LOOKUP_BY_NAME 95
#define LIBEBPF_FFI_HELPER_INDEX__CALL 96

union libebpf_ffi_argument {
    int8_t int8;
    int16_t int16;
    int32_t int32;
    int64_t int64;
    uint8_t uint8;
    uint16_t uint16;
    uint32_t uint32;
    uint64_t uint64;
    double float64;
    float float32;
    // This is the register size of current platform. All arguments would be passed in this size to the FFI function
    void *ptr;
};

struct libebpf_ffi_call_argument_list {
    /**
     * @brief Only accept int64 arguments in the eBPF side
     */
    int64_t args[6];
};
/**
 * @brief Disable these helper definition when running unit tests, so we can provide our own libebpf_ffi_call and libebpf_ffi_lookup_by_name
 * 
 */
#ifndef _LIBEBPF_UNIT_TEST
/**
 * @brief Helper definitions
 * 
 */
static int (*libebpf_ffi_lookup_by_name)(const char *name) = (int (*)(const char *))(uintptr_t)LIBEBPF_FFI_HELPER_INDEX__LOOKUP_BY_NAME;
static int64_t (*libebpf_ffi_call)(int func_id, struct libebpf_ffi_call_argument_list *args) =
        (int64_t(*)(int, struct libebpf_ffi_call_argument_list *))LIBEBPF_FFI_HELPER_INDEX__CALL;
#endif
#define LIBEBPF_FFI_CALL_BY_ID_ARG6(id, arg1, arg2, arg3, arg4, arg5, arg6)                                                                          \
    ({                                                                                                                                               \
        struct libebpf_ffi_call_argument_list args = { .args = { arg1, arg2, arg3, arg4, arg5, arg6 } };                                             \
        libebpf_ffi_call(id, &args);                                                                                                                  \
    })

#define LIBEBPF_FFI_CALL_BY_ID_ARG5(id, arg1, arg2, arg3, arg4, arg5) LIBEBPF_FFI_CALL_BY_ID_ARG6(id, arg1, arg2, arg3, arg4, arg5, 0)
#define LIBEBPF_FFI_CALL_BY_ID_ARG4(id, arg1, arg2, arg3, arg4) LIBEBPF_FFI_CALL_BY_ID_ARG5(id, arg1, arg2, arg3, arg4, 0)
#define LIBEBPF_FFI_CALL_BY_ID_ARG3(id, arg1, arg2, arg3) LIBEBPF_FFI_CALL_BY_ID_ARG4(id, arg1, arg2, arg3, 0)
#define LIBEBPF_FFI_CALL_BY_ID_ARG2(id, arg1, arg2) LIBEBPF_FFI_CALL_BY_ID_ARG3(id, arg1, arg2, 0)
#define LIBEBPF_FFI_CALL_BY_ID_ARG1(id, arg1) LIBEBPF_FFI_CALL_BY_ID_ARG2(id, arg1, 0)
#define LIBEBPF_FFI_CALL_BY_ID_ARG0(id) LIBEBPF_FFI_CALL_BY_ID_ARG1(id, 0)

#define LIBEBPF_FFI_CALL_BY_NAME_ARG6(name, arg1, arg2, arg3, arg4, arg5, arg6)                                                                      \
    ({                                                                                                                                               \
        char localname[] = #name;                                                                                                                    \
        int id = libebpf_ffi_lookup_by_name(localname);                                                                                              \
        LIBEBPF_FFI_CALL_BY_ID_ARG6(id, arg1, arg2, arg3, arg4, arg5, arg6);                                                                         \
    })

#define LIBEBPF_FFI_CALL_BY_NAME_ARG5(name, arg1, arg2, arg3, arg4, arg5) LIBEBPF_FFI_CALL_BY_NAME_ARG6(name, arg1, arg2, arg3, arg4, arg5, 0)
#define LIBEBPF_FFI_CALL_BY_NAME_ARG4(name, arg1, arg2, arg3, arg4) LIBEBPF_FFI_CALL_BY_NAME_ARG5(name, arg1, arg2, arg3, arg4, 0)
#define LIBEBPF_FFI_CALL_BY_NAME_ARG3(name, arg1, arg2, arg3) LIBEBPF_FFI_CALL_BY_NAME_ARG4(name, arg1, arg2, arg3, 0)
#define LIBEBPF_FFI_CALL_BY_NAME_ARG2(name, arg1, arg2) LIBEBPF_FFI_CALL_BY_NAME_ARG3(name, arg1, arg2, 0)
#define LIBEBPF_FFI_CALL_BY_NAME_ARG1(name, arg1) LIBEBPF_FFI_CALL_BY_NAME_ARG2(name, arg1, 0)
#define LIBEBPF_FFI_CALL_BY_NAME_ARG0(name) LIBEBPF_FFI_CALL_BY_NAME_ARG1(name, 0)

#ifdef __cplusplus
}
#endif

#endif
