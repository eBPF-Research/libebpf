#include "libebpf_vm.h"
#include <assert.h>
#include <stdint.h>
#include <libebpf_internal.h>
uint64_t ebpf_ubpf_jit_dispatcher_adaptor(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, unsigned int index,
                                          ebpf_vm_t *vm) {
    assert(index < MAX_EXTERNAL_HELPER);
    struct ebpf_external_helper_definition *helper_def = &vm->helpers[index];
    assert(helper_def->fn);
    return helper_def->fn(arg1, arg2, arg3, arg4, arg5);
}
