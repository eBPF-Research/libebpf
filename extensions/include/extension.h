#ifndef _LIBEBPF_EXTENSION_H_
#define _LIBEBPF_EXTENSION_H_

#include "bpf_host_ffi.h"

struct ebpf_context *ebpf_create_context(void);
void ebpf_free_context(struct ebpf_context *context);

#endif // _LIBEBPF_EXTENSION_H_
