#include "libebpf_execution_internal.h"
#include "libebpf_map.h"
#include "utils/spinlock.h"
#include <string.h>
#include <libebpf_execution.h>
#include "libebpf_internal.h"
#include <errno.h>

__thread ebpf_execution_context_t *ebpf_execution_context__thread_global_context;

ebpf_execution_context_t *ebpf_execution_context__create() {
    ebpf_execution_context_t *ctx = _libebpf_global_malloc(sizeof(ebpf_execution_context_t));
    memset(ctx, 0, sizeof(*ctx));
    if (!ctx) {
        ebpf_set_error_string("malloc returned NULL");
        return NULL;
    }
    ebpf_spinlock_init(&ctx->map_alloc_lock);
    ctx->map_ops[EBPF_MAP_TYPE_ARRAY] = ARRAY_MAP_OPS;
    ctx->map_ops[EBPF_MAP_TYPE_HASH] = HASH_MAP_OPS;
    ctx->map_ops[EBPF_MAP_TYPE_RINGBUF] = RINGBUF_MAP_OPS;
    return ctx;
}

void ebpf_execution_context__destroy(ebpf_execution_context_t *ctx) {
    // Destroy maps
    for (int i = 0; i < sizeof(ctx->maps) / sizeof(ctx->maps[0]); i++) {
        if (ctx->maps[i]) {
            ctx->map_ops[ctx->maps[i]->attr.type].map_free(ctx->maps[i]);
            _libebpf_global_free(ctx->maps[i]);
        }
    }
    _libebpf_global_free(ctx);
}

int ebpf_execution_context__map_create(ebpf_execution_context_t *ctx, const char *map_name, struct ebpf_map_attr *attr) {
    ebpf_spinlock_lock(&ctx->map_alloc_lock);
    int result = -1;
    int idx = -1;
    if (attr->type < 0 || attr->type >= sizeof(ctx->map_ops) / sizeof(ctx->map_ops[0]) || !ctx->map_ops[attr->type].used) {
        ebpf_set_error_string("Invalid or unsupported map type %d", attr->type);
        result = -EINVAL;
        goto cleanup;
    }
    for (int i = 0; i < LIBEBPF_MAX_MAP_COUNT; i++) {
        if (!ctx->maps[i]) {
            idx = i;
            break;
        }
    }
    if (idx == -1) {
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
    struct ebpf_map_ops *ops = &ctx->map_ops[attr->type];
    struct ebpf_map *map = ctx->maps[idx];
    map->attr = *attr;
    map->ops = ops;
    strncpy(map->name, map_name, sizeof(map->name));
    map->self_id = idx;
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
    if (!ctx->maps[map_id] || map_id < 0 || map_id >= LIBEBPF_MAX_MAP_COUNT) {
        ebpf_set_error_string("Invalid map_id %d", map_id);
        result = -EINVAL;
        goto cleanup;
    }
    ctx->maps[map_id]->ops->map_free(ctx->maps[map_id]);
    _libebpf_global_free(ctx->maps[map_id]);
    ctx->maps[map_id] = NULL;
cleanup:
    ebpf_spinlock_unlock(&ctx->map_alloc_lock);
    return result;
}

int ebpf_execution_context__map_elem_lookup(ebpf_execution_context_t *ctx, int map_id, const void *key, void *value) {
    if (map_id < 0 || map_id >= LIBEBPF_MAX_MAP_COUNT || !ctx->maps[map_id]) {
        ebpf_set_error_string("Invalid map_id: %d", map_id);
        return -EINVAL;
    }
    struct ebpf_map *map = ctx->maps[map_id];
    return map->ops->elem_lookup(map, key, value);
}

int ebpf_execution_context__map_elem_update(ebpf_execution_context_t *ctx, int map_id, const void *key, const void *value, uint64_t flags) {
    if (map_id < 0 || map_id >= LIBEBPF_MAX_MAP_COUNT || !ctx->maps[map_id]) {
        ebpf_set_error_string("Invalid map_id: %d", map_id);
        return -EINVAL;
    }
    struct ebpf_map *map = ctx->maps[map_id];
    return map->ops->elem_update(map, key, value, flags);
}
int ebpf_execution_context__map_elem_delete(ebpf_execution_context_t *ctx, int map_id, const void *key) {
    if (map_id < 0 || map_id >= LIBEBPF_MAX_MAP_COUNT || !ctx->maps[map_id]) {
        ebpf_set_error_string("Invalid map_id: %d", map_id);
        return -EINVAL;
    }
    struct ebpf_map *map = ctx->maps[map_id];
    return map->ops->elem_delete(map, key);
}

int ebpf_execution_context__map_get_next_key(ebpf_execution_context_t *ctx, int map_id, const void *key, void *next_key) {
    if (map_id < 0 || map_id >= LIBEBPF_MAX_MAP_COUNT || !ctx->maps[map_id]) {
        ebpf_set_error_string("Invalid map_id: %d", map_id);
        return -EINVAL;
    }
    struct ebpf_map *map = ctx->maps[map_id];
    return map->ops->map_get_next_key(map, key, next_key);
}

struct ringbuf_map_private_data *ebpf_execution_context__get_ringbuf_map_private_data(ebpf_execution_context_t *ctx, int map_id) {
    if (map_id < 0 || map_id >= LIBEBPF_MAX_MAP_COUNT || !ctx->maps[map_id]) {
        ebpf_set_error_string("Invalid map_id: %d", map_id);
        return NULL;
    }
    struct ebpf_map *map = ctx->maps[map_id];
    if (map->attr.type != EBPF_MAP_TYPE_RINGBUF) {
        ebpf_set_error_string("Map id %d is not a ringbuf map", map_id);
        return NULL;
    }
    return map->map_private_data;
}
