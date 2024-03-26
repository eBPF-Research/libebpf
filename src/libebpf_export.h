#ifndef _LIBEBPF_EXPORT_H
#define _LIBEBPF_EXPORT_H
#include <libebpf_ffi.h>
#ifdef __cplusplus
extern "C" {
#endif

#define _STRINGIFY(x) #x
#define SYM_TOSTRING(x) _STRINGIFY(x)

#define LIBEBPF_EXPORT_FUNCTION_ARG6(sym, return_type, arg1, arg2, arg3, arg4, arg5, arg6)                                                           \
    static const char _libebpf_sym_strtab__##sym[] __attribute__((section("_libebpf_sym_strings"), aligned(1))) = SYM_TOSTRING(sym);                 \
    static const struct libebpf_ffi_function _libebpf_functab__##sym                                                                                 \
            __attribute__((section("_libebpf_functab+" #sym), used)) = { .ptr = (void *)(uintptr_t) & sym,                                           \
                                                                         .name = (char *)_libebpf_sym_strtab__##sym,                                 \
                                                                         .arg_types = { arg1, arg2, arg3, arg4, arg5, arg6 },                        \
                                                                         .return_value_type = return_type }

#define LIBEBPF_EXPORT_FUNCTION_ARG5(sym, return_type, arg1, arg2, arg3, arg4, arg5)                                                                 \
    LIBEBPF_EXPORT_FUNCTION_ARG6(sym, return_type, arg1, arg2, arg3, arg4, arg5, ARG_VOID)
#define LIBEBPF_EXPORT_FUNCTION_ARG4(sym, return_type, arg1, arg2, arg3, arg4)                                                                       \
    LIBEBPF_EXPORT_FUNCTION_ARG5(sym, return_type, arg1, arg2, arg3, arg4, ARG_VOID)
#define LIBEBPF_EXPORT_FUNCTION_ARG3(sym, return_type, arg1, arg2, arg3) LIBEBPF_EXPORT_FUNCTION_ARG4(sym, return_type, arg1, arg2, arg3, ARG_VOID)
#define LIBEBPF_EXPORT_FUNCTION_ARG2(sym, return_type, arg1, arg2) LIBEBPF_EXPORT_FUNCTION_ARG3(sym, return_type, arg1, arg2, ARG_VOID)
#define LIBEBPF_EXPORT_FUNCTION_ARG1(sym, return_type, arg1) LIBEBPF_EXPORT_FUNCTION_ARG2(sym, return_type, arg1, ARG_VOID)

extern const struct libebpf_ffi_function _start_libebpf_exported_function[];
extern const struct libebpf_ffi_function _end_libebpf_exported_function[];

#ifdef __cplusplus
}
#endif

#endif
