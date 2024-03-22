#include "libebpf_execution.h"
#include "libebpf_execution_internal.h"
#include "libebpf_internal.h"
#include <string.h>
#include <errno.h>
#include <libebpf_map.h>
#include "utils/spinlock.h"
#include "libebpf_map_internal.h"
static struct ebpf_map_ops map_ops[(int)__MAX_BPF_MAP_TYPE] = {

};

int ebpf_execution_context__map_create(ebpf_execution_context_t *ctx, const char *map_name, struct ebpf_map_attr *attr) {
    ebpf_spinlock_lock(&ctx->map_alloc_lock);
    int result = -1;
    int idx;
    if (attr->type < 0 || attr->type >= sizeof(map_ops) / sizeof(map_ops[0]) || !map_ops[attr->type].used) {
        ebpf_set_error_string("Invalid or unsupported map type %d", attr->type);
        result = -EINVAL;
        goto cleanup;
    }
    for (int i = 0; i < LIBEBPF_MAX_MAP_COUNT; i++) {
        if (!ctx->maps[i]) {
            idx = i;
        }
    }
    if (result == -1) {
        ebpf_set_error_string("No map slots available");
        result = -ENOMEM;
        goto cleanup;
    }
    ctx->maps[idx] = _libebpf_global_malloc(sizeof(struct ebpf_map));
    if (!ctx->maps[idx]) {
        ebpf_set_error_string("Unable to allocate space for the map");
        result = -ENOMEM;
        goto cleanup;
    }
    struct ebpf_map_ops *ops = &map_ops[attr->type];
    struct ebpf_map *map = ctx->maps[idx];
    map->attr = *attr;
    map->ops = ops;
    strncpy(map->name, map_name, sizeof(map->name));
    // Failed to do initialization
    if ((result = ops->alloc_map(&map->map_private_data, attr)) < 0) {
        _libebpf_global_free(ctx->maps[idx]);
        goto cleanup;
    }
    // Succeeded
    result = idx;
cleanup:
    ebpf_spinlock_unlock(&ctx->map_alloc_lock);
    return result;
}
