#include "libebpf_execution_internal.h"
#include "utils/spinlock.h"
#include <string.h>
#include <libebpf_execution.h>
#include "libebpf_internal.h"
ebpf_execution_context_t *ebpf_execution_context_create() {
    ebpf_execution_context_t *ctx = _libebpf_global_malloc(sizeof(ebpf_execution_context_t));
    memset(ctx, 0, sizeof(*ctx));
    if (!ctx) {
        ebpf_set_error_string("malloc returned NULL");
        return NULL;
    }
    ebpf_spinlock_init(&ctx->map_alloc_lock);
    return ctx;
}

void ebpf_execution_context_destroy(ebpf_execution_context_t *ctx) {
    _libebpf_global_free(ctx);
}
