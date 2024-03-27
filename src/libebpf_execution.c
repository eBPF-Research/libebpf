#include "libebpf_execution_internal.h"
#include "libebpf_export.h"
#include "libebpf_ffi.h"
#include "libebpf_map.h"
#include "utils/hashmap.h"
#include "utils/spinlock.h"
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <libebpf_execution.h>
#include "libebpf_internal.h"
#include <errno.h>

__thread ebpf_state_t *ebpf_state__thread_global_state;

static uint64_t libebpf_ffi_name_entry_hash(const void *ptr, uint64_t s1, uint64_t s2) {
    const struct libebpf_ffi_name_entry *ent = ptr;
    int len = strlen(ent->name);
    return hashmap_sip(ent->name, len, s1, s2);
}

static int libebpf_ffi_name_entry_compare(const void *e1, const void *e2, void *ctx) {
    const struct libebpf_ffi_name_entry *a = e1;
    const struct libebpf_ffi_name_entry *b = e2;
    return strcmp(a->name, b->name);
}
static void libebpf_ffi_name_entry_free(void *v) {
    struct libebpf_ffi_name_entry *a = v;
    _libebpf_global_free((void *)a->name);
}
ebpf_state_t *ebpf_state__create() {
    ebpf_state_t *ctx = _libebpf_global_malloc(sizeof(ebpf_state_t));
    memset(ctx, 0, sizeof(*ctx));
    if (!ctx) {
        ebpf_set_error_string("malloc returned NULL");
        return NULL;
    }
    ebpf_spinlock_init(&ctx->map_alloc_lock);
    ebpf_spinlock_init(&ctx->ffi_alloc_lock);
    ctx->map_ops[EBPF_MAP_TYPE_ARRAY] = ARRAY_MAP_OPS;
    ctx->map_ops[EBPF_MAP_TYPE_HASH] = HASH_MAP_OPS;
    ctx->map_ops[EBPF_MAP_TYPE_RINGBUF] = RINGBUF_MAP_OPS;

    ctx->maps = _libebpf_global_malloc(sizeof(struct ebpf_map *) * LIBEBPF_MAX_MAP_COUNT);
    if (!ctx->maps) {
        ebpf_set_error_string("Unable to allocate memory for maps");
        _libebpf_global_free(ctx);
        return NULL;
    }
    memset(ctx->maps, 0, sizeof(struct ebpf_map *) * LIBEBPF_MAX_MAP_COUNT);
    ctx->ffi_funcs = _libebpf_global_malloc(sizeof(struct libebpf_ffi_function) * LIBEBPF_MAX_FFI_COUNT);
    if (!ctx->ffi_funcs) {
        ebpf_set_error_string("Unable to allocate space for ffi_funcs");
        _libebpf_global_free(ctx->maps);
        _libebpf_global_free(ctx);
        return NULL;
    }
    memset(ctx->ffi_funcs, 0, sizeof(struct libebpf_ffi_function) * LIBEBPF_MAX_FFI_COUNT);
    ctx->ffi_func_name_hashmap =
            hashmap_new_with_allocator(_libebpf_global_malloc, _libebpf_global_realloc, _libebpf_global_free, sizeof(struct libebpf_ffi_name_entry),
                                       10, 0, 0, libebpf_ffi_name_entry_hash, libebpf_ffi_name_entry_compare, libebpf_ffi_name_entry_free, NULL);
    if (!ctx->ffi_func_name_hashmap) {
        ebpf_set_error_string("Unable to create ffi name lookup hashmap");
        _libebpf_global_free(ctx->maps);
        _libebpf_global_free(ctx->ffi_funcs);
        _libebpf_global_free(ctx);
        return NULL;
    }
    for (const struct libebpf_ffi_function *fn = &_start_libebpf_exported_function[0]; fn < &_end_libebpf_exported_function[0]; fn++) {
        int err = ebpf_state__register_ffi(ctx, fn->ptr, fn->name, fn->arg_types, fn->return_value_type);
        if (err < 0) {
            ebpf_set_error_string("Unable to register internal FFI function %s: %s", fn->name, _libebpf_global_error_string);
            _libebpf_global_free(ctx->maps);
            _libebpf_global_free(ctx->ffi_funcs);
            _libebpf_global_free(ctx);
            return NULL;
        }
    }
    return ctx;
}

void ebpf_state__destroy(ebpf_state_t *ctx) {
    // Destroy maps
    for (int i = 0; i < LIBEBPF_MAX_MAP_COUNT; i++) {
        if (ctx->maps[i]) {
            ctx->map_ops[ctx->maps[i]->attr.type].map_free(ctx->maps[i]);
            _libebpf_global_free(ctx->maps[i]);
        }
    }
    _libebpf_global_free(ctx->maps);
    // We don't need to clean them. They will be freed when the hashmap was destroyed.
    // for (int i = 0; i < LIBEBPF_MAX_FFI_COUNT; i++) {
    //     if (ctx->ffi_funcs[i].ptr) {
    //         _libebpf_global_free((void *)ctx->ffi_funcs[i].name);
    //     }
    // }
    _libebpf_global_free(ctx->ffi_funcs);

    hashmap_free(ctx->ffi_func_name_hashmap);
    _libebpf_global_free(ctx);
}

int ebpf_state__map_create(ebpf_state_t *ctx, const char *map_name, struct ebpf_map_attr *attr) {
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

int ebpf_state__register_ffi(ebpf_state_t *ctx, void *func, const char *name,
                                                  const enum libebpf_ffi_type arg_types[6], enum libebpf_ffi_type return_value_type) {
    ebpf_spinlock_lock(&ctx->ffi_alloc_lock);
    int ret = -1;

    if (func == NULL) {
        ebpf_set_error_string("FFI function could not be null pointer");
        ret = -EINVAL;
        goto cleanup;
    }

    for (int i = 0; i < LIBEBPF_MAX_FFI_COUNT; i++) {
        if (!ctx->ffi_funcs[i].ptr) {
            ret = i;
            break;
        }
    }
    if (ret == -1) {
        ebpf_set_error_string("No available slot");
        ret = -ENOSPC;
        goto cleanup;
    }
    struct libebpf_ffi_function *fn = &ctx->ffi_funcs[ret];
    fn->ptr = func;
    memcpy(fn->arg_types, arg_types, sizeof(enum libebpf_ffi_type) * 6);
    fn->return_value_type = return_value_type;
    // Save a copy of the name string
    // The string will also be used for hashmap
    fn->name = _libebpf_global_malloc(strlen(name) + 1);
    if (!fn->name) {
        ebpf_set_error_string("Unable to allocate memory for function name");
        ret = -ENOMEM;
        goto cleanup;
    }
    strcpy(fn->name, name);
    struct libebpf_ffi_name_entry entry = { .name = fn->name, .id = ret };
    // Check if that element exists
    if (hashmap_get(ctx->ffi_func_name_hashmap, &entry, NULL) != NULL) {
        ebpf_set_error_string("There is a FFI function named %s exist", name);
        _libebpf_global_free(fn->name);
        ret = -EEXIST;
        goto cleanup;
    }
    if (hashmap_set(ctx->ffi_func_name_hashmap, &entry) == NULL && hashmap_oom(ctx->ffi_func_name_hashmap)) {
        ebpf_set_error_string("Unable to insert name into hashmap");
        ret = -ENOMEM;
        _libebpf_global_free(fn->name);
        goto cleanup;
    }

cleanup:
    ebpf_spinlock_unlock(&ctx->ffi_alloc_lock);
    return ret;
}

int ebpf_state__map_destroy(ebpf_state_t *ctx, int map_id) {
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

int ebpf_state__map_elem_lookup(ebpf_state_t *ctx, int map_id, const void *key, void *value) {
    if (map_id < 0 || map_id >= LIBEBPF_MAX_MAP_COUNT || !ctx->maps[map_id]) {
        ebpf_set_error_string("Invalid map_id: %d", map_id);
        return -EINVAL;
    }
    struct ebpf_map *map = ctx->maps[map_id];
    return map->ops->elem_lookup(map, key, value);
}

int ebpf_state__map_elem_update(ebpf_state_t *ctx, int map_id, const void *key, const void *value, uint64_t flags) {
    if (map_id < 0 || map_id >= LIBEBPF_MAX_MAP_COUNT || !ctx->maps[map_id]) {
        ebpf_set_error_string("Invalid map_id: %d", map_id);
        return -EINVAL;
    }
    struct ebpf_map *map = ctx->maps[map_id];
    return map->ops->elem_update(map, key, value, flags);
}
int ebpf_state__map_elem_delete(ebpf_state_t *ctx, int map_id, const void *key) {
    if (map_id < 0 || map_id >= LIBEBPF_MAX_MAP_COUNT || !ctx->maps[map_id]) {
        ebpf_set_error_string("Invalid map_id: %d", map_id);
        return -EINVAL;
    }
    struct ebpf_map *map = ctx->maps[map_id];
    return map->ops->elem_delete(map, key);
}

int ebpf_state__map_get_next_key(ebpf_state_t *ctx, int map_id, const void *key, void *next_key) {
    if (map_id < 0 || map_id >= LIBEBPF_MAX_MAP_COUNT || !ctx->maps[map_id]) {
        ebpf_set_error_string("Invalid map_id: %d", map_id);
        return -EINVAL;
    }
    struct ebpf_map *map = ctx->maps[map_id];
    return map->ops->map_get_next_key(map, key, next_key);
}

struct ringbuf_map_private_data *ebpf_state__get_ringbuf_map_private_data(ebpf_state_t *ctx, int map_id) {
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
