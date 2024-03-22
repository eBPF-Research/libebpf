#include "libebpf_execution_internal.h"
#include "utils/spinlock.h"
#include <string.h>
#include <libebpf_execution.h>
#include "libebpf_internal.h"
#include <errno.h>
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
    if ((result = ops->alloc_map(map, attr)) < 0) {
        _libebpf_global_free(ctx->maps[idx]);
        ebpf_set_error_string("Unable to call ops->alloc_map: %s", _libebpf_global_error_string);
        goto cleanup;
    }
    // Succeeded
    result = idx;
cleanup:
    ebpf_spinlock_unlock(&ctx->map_alloc_lock);
    return result;
}

int ebpf_execution_context__map_destroy(ebpf_execution_context_t *ctx, int map_id) {
    ebpf_spinlock_lock(&ctx->map_alloc_lock);
    int result = 0;
    if (!ctx->maps[map_id]) {
        ebpf_set_error_string("Invalid map_id %d", map_id);
        result = -EINVAL;
        goto cleanup;
    }
    ctx->maps[map_id]->ops->map_free(ctx->maps[map_id]);
    _libebpf_global_free(ctx->maps[map_id]);
cleanup:
    ebpf_spinlock_unlock(&ctx->map_alloc_lock);
    return result;
}

int ebpf_execution_context__map_elem_lookup(ebpf_execution_context_t *ctx, int map_id, const void *key, void *value) {
    struct ebpf_map *map = ctx->maps[map_id];
    if (!map) {
        ebpf_set_error_string("Invalid map_id: %d", map_id);
        return -EINVAL;
    }
    return map->ops->elem_lookup(map, key, value);
}

int ebpf_execution_context__map_elem_update(ebpf_execution_context_t *ctx, int map_id, const void *key, const void *value, uint64_t flags) {
    struct ebpf_map *map = ctx->maps[map_id];
    if (!map) {
        ebpf_set_error_string("Invalid map_id: %d", map_id);
        return -EINVAL;
    }
    return map->ops->elem_update(map, key, value, flags);
}
int ebpf_execution_context__map_elem_delete(ebpf_execution_context_t *ctx, int map_id, const void *key) {
    struct ebpf_map *map = ctx->maps[map_id];
    if (!map) {
        ebpf_set_error_string("Invalid map_id: %d", map_id);
        return -EINVAL;
    }
    return map->ops->elem_delete(map, key);
}

int ebpf_execution_context__map_get_next_key(ebpf_execution_context_t *ctx, int map_id, const void *key, void *next_key) {
    struct ebpf_map *map = ctx->maps[map_id];
    if (!map) {
        ebpf_set_error_string("Invalid map_id: %d", map_id);
        return -EINVAL;
    }
    return map->ops->map_get_next_key(map, key, next_key);
}
