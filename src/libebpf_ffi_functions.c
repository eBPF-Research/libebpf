#include "libebpf_ffi.h"
#include <libebpf_export.h>
#include <string.h>
LIBEBPF_EXPORT_FUNCTION_ARG2(strcmp, ARG_INT32, ARG_PTR, ARG_PTR);
LIBEBPF_EXPORT_FUNCTION_ARG2(strcpy, ARG_VOID, ARG_PTR, ARG_PTR);
LIBEBPF_EXPORT_FUNCTION_ARG2(strchr, ARG_PTR, ARG_PTR, ARG_INT32);
