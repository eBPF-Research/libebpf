#include "libebpf_execution_internal.h"
#include "libebpf_internal.h"
#include "libebpf_map.h"
#include <errno.h>
#include <inttypes.h>
static int array_map__alloc(struct ebpf_map *map, struct ebpf_map_attr *attr) {
    if (attr->key_size != 4) {
        ebpf_set_error_string("Key size of array map must be 4");
        return -EINVAL;
    }
    if (attr->value_size <= 0 || attr->max_ents <= 0) {
        ebpf_set_error_string("Zero value_size or max_ents");
        return -EINVAL;
    }
    void *buf = _libebpf_global_malloc((size_t)attr->value_size * attr->max_ents);
    if (!buf) {
        ebpf_set_error_string("Unable to allocate buffer");
        return -ENOMEM;
    }
    map->map_private_data = buf;
    return 0;
}

static void array_map__free(struct ebpf_map *map) {
    _libebpf_global_free(map->map_private_data);
}

static int array_map__elem_lookup(struct ebpf_map *map, const void *key, void *value) {
    uint32_t idx = *(uint32_t *)key;
    if (idx >= map->attr.max_ents) {
        ebpf_set_error_string("Invalid index %" PRIu32, idx);
        return -EINVAL;
    }
    memcpy(value, map->map_private_data + idx * map->attr.value_size, map->attr.value_size);
    return 0;
}
static int array_map__elem_update(struct ebpf_map *map, const void *key, const void *value, uint64_t flags) {
    uint32_t idx = *(uint32_t *)key;
    if (idx >= map->attr.max_ents) {
        ebpf_set_error_string("Invalid index %" PRIu32, idx);
        return -EINVAL;
    }
    memcpy(map->map_private_data + idx * map->attr.value_size, value, map->attr.value_size);
    return 0;
}
static int array_map__elem_delete(struct ebpf_map *map, const void *key) {
    ebpf_set_error_string("You can't delete elements from an array map");
    return -ENOTSUP;
}
static int array_map__map_get_next_key(struct ebpf_map *map, const void *key, void *next_key) {
    uint32_t *out_key = (uint32_t *)next_key;
    if (key == NULL) {
        *out_key = 0;
        return 0;
    }
    uint32_t idx = *(uint32_t *)key;
    if (idx >= map->attr.max_ents - 1) {
        ebpf_set_error_string("Already last index");
        return -ENOENT;
    }
    *out_key = idx + 1;
    return 0;
}

struct ebpf_map_ops ARRAY_MAP_OPS = { .used = true,
                                      .alloc_map = array_map__alloc,
                                      .map_free = array_map__free,
                                      .elem_update = array_map__elem_update,
                                      .elem_lookup = array_map__elem_lookup,
                                      .elem_delete = array_map__elem_delete,
                                      .map_get_next_key = array_map__map_get_next_key

};
