

#include "libebpf_execution_internal.h"
#include "libebpf_internal.h"
#include "libebpf_map.h"
#include "utils/hashmap.h"
#include "utils/spinlock.h"
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

struct ebpf_hashmap_freelist_entry {
    void *mem;
    struct ebpf_hashmap_freelist_entry *next;
};

struct ebpf_hashmap_private_data {
    struct hashmap *hashmap;
    ebpf_spinlock_t data_lock;
    struct ebpf_hashmap_freelist_entry *freelist;
    // A freelist to record all values that would be freed. It would be cleaned up when the map was destroyed.
    ebpf_spinlock_t freelist_lock;
};

struct ebpf_hashmap_entry {
    char *key;
    char *value;
    struct ebpf_map_attr *attr;
    struct ebpf_hashmap_private_data *priv_data;
};
static uint64_t entry_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const struct ebpf_hashmap_entry *entry = item;
    return hashmap_sip(entry->key, entry->attr->key_size, seed0, seed1);
}
static int entry_compare(const void *a, const void *b, void *udata) {
    const struct ebpf_hashmap_entry *ua = a;
    const struct ebpf_hashmap_entry *ub = b;
    return memcmp(ua->key, ub->key, ((struct ebpf_map_attr *)udata)->key_size);
}
static void hash_map__insert_into_freelist(struct ebpf_hashmap_private_data *priv_data, void *mem);
static void entry_free(void *item) {
    struct ebpf_hashmap_entry *entry = item;
    _libebpf_global_free(entry->key);
    // When deleting an entry, put its value onto freelist, instead of immediately freeing it. bpf helper bpf_map_lookup_elem returns a pointer value.
    // If one thread retrives a pointer, and if another thread deleted the entry before the first thread trying to operate on the value, the memory
    // access might be invalid.
    hash_map__insert_into_freelist(entry->priv_data, entry->value);
}

static void hash_map__cleanup_freelist(struct ebpf_hashmap_private_data *priv_data) {
    ebpf_spinlock_lock(&priv_data->freelist_lock);
    ebpf_spinlock_lock(&priv_data->data_lock);
    struct ebpf_hashmap_freelist_entry *curr = priv_data->freelist;
    while (curr != NULL) {
        _libebpf_global_free(curr->mem);
        struct ebpf_hashmap_freelist_entry *next = curr->next;
        _libebpf_global_free(curr);
        curr = next;
    }
    priv_data->freelist = NULL;
    ebpf_spinlock_unlock(&priv_data->freelist_lock);
    ebpf_spinlock_unlock(&priv_data->data_lock);
}
static void hash_map__insert_into_freelist(struct ebpf_hashmap_private_data *priv_data, void *mem) {
    ebpf_spinlock_lock(&priv_data->freelist_lock);
    struct ebpf_hashmap_freelist_entry *curr = _libebpf_global_malloc(sizeof(struct ebpf_hashmap_freelist_entry));
    curr->mem = mem;
    curr->next = priv_data->freelist;
    priv_data->freelist = curr;
    ebpf_spinlock_unlock(&priv_data->freelist_lock);
}
static int hash_map__alloc(struct ebpf_map *map, struct ebpf_map_attr *attr) {
    struct ebpf_hashmap_private_data *data = _libebpf_global_malloc(sizeof(struct ebpf_hashmap_private_data));
    ebpf_spinlock_init(&data->data_lock);
    ebpf_spinlock_init(&data->freelist_lock);
    if (!data) {
        ebpf_set_error_string("Unable to allocate memory for struct ebpf_hashmap_private_data");
        return -ENOMEM;
    }
    ebpf_spinlock_init(&data->data_lock);
    data->hashmap = hashmap_new_with_allocator(_libebpf_global_malloc, _libebpf_global_realloc, _libebpf_global_free,
                                               sizeof(struct ebpf_hashmap_entry), 10, 0, 0, entry_hash, entry_compare, entry_free, attr);
    if (!data->hashmap) {
        _libebpf_global_free(data);
        ebpf_set_error_string("Unable to create hashmap");
        return -EINVAL;
    }
    data->freelist = NULL;
    map->map_private_data = data;
    return 0;
}

static void hash_map__free(struct ebpf_map *map) {
    struct ebpf_hashmap_private_data *data = map->map_private_data;
    hashmap_free(data->hashmap);
    hash_map__cleanup_freelist(data);
    _libebpf_global_free(data);
}

static int hash_map__elem_lookup(struct ebpf_map *map, const void *key, void *value) {
    struct ebpf_hashmap_entry entry = { .key = (char *)key, .value = NULL, .attr = &map->attr, .priv_data = map->map_private_data };
    struct ebpf_hashmap_private_data *priv_data = map->map_private_data;
    ebpf_spinlock_lock(&priv_data->data_lock);
    struct ebpf_hashmap_entry *out = (struct ebpf_hashmap_entry *)hashmap_get(priv_data->hashmap, &entry, NULL);
    int err = 0;
    if (!out) {
        ebpf_set_error_string("Element not found");
        err = -ENOENT;
        goto cleanup;
    }
    memcpy(value, out->value, map->attr.value_size);
cleanup:
    ebpf_spinlock_unlock(&priv_data->data_lock);
    return err;
}
static void *hash_map__elem_lookup_from_helper(struct ebpf_map *map, const void *key) {
    struct ebpf_hashmap_entry entry = { .key = (char *)key, .value = NULL, .attr = &map->attr, .priv_data = map->map_private_data };
    struct ebpf_hashmap_private_data *priv_data = map->map_private_data;
    ebpf_spinlock_lock(&priv_data->data_lock);
    struct ebpf_hashmap_entry *out = (struct ebpf_hashmap_entry *)hashmap_get(priv_data->hashmap, &entry, NULL);
    int err = 0;
    if (!out) {
        ebpf_set_error_string("Element not found");
        err = -ENOENT;
        goto cleanup;
    }

cleanup:
    ebpf_spinlock_unlock(&priv_data->data_lock);
    if (err)
        return NULL;
    return out->value;
}
static int hash_map__elem_update(struct ebpf_map *map, const void *key, const void *value, uint64_t flags) {
    struct ebpf_hashmap_entry entry;
    entry.key = _libebpf_global_malloc(map->attr.key_size);
    if (!entry.key) {
        ebpf_set_error_string("Unable to allocate key buffer");
        return -ENOMEM;
    }
    entry.value = _libebpf_global_malloc(map->attr.value_size);
    if (!entry.value) {
        ebpf_set_error_string("Unable to allocate value buffer");
        _libebpf_global_free(entry.key);
        return -ENOMEM;
    }
    entry.attr = &map->attr;
    entry.priv_data = map->map_private_data;
    memcpy(entry.key, key, map->attr.key_size);
    memcpy(entry.value, value, map->attr.value_size);
    struct ebpf_hashmap_private_data *priv_data = map->map_private_data;
    ebpf_spinlock_lock(&priv_data->data_lock);
    void *replaced_elem = (void *)hashmap_set(priv_data->hashmap, &entry);
    if (replaced_elem) {
        entry_free(replaced_elem);
    } else if (hashmap_oom(priv_data->hashmap)) {
        ebpf_set_error_string("Unable to insert element: oom");
        entry_free(replaced_elem);
        return -ENOMEM;
    }
    ebpf_spinlock_unlock(&priv_data->data_lock);
    return 0;
}
static int hash_map__elem_delete(struct ebpf_map *map, const void *key) {
    struct ebpf_hashmap_entry entry = { .key = (char *)key, .value = NULL, .attr = &map->attr, .priv_data = map->map_private_data };
    struct ebpf_hashmap_private_data *priv_data = map->map_private_data;
    ebpf_spinlock_lock(&priv_data->data_lock);
    struct ebpf_hashmap_entry *out = (struct ebpf_hashmap_entry *)hashmap_delete(priv_data->hashmap, &entry);
    ebpf_spinlock_unlock(&priv_data->data_lock);
    if (!out) {
        ebpf_set_error_string("Element not found");
        return -ENOENT;
    }
    entry_free(out);
    return 0;
}
static int hash_map__map_get_next_key(struct ebpf_map *map, const void *key, void *next_key) {
    struct ebpf_hashmap_private_data *priv_data = map->map_private_data;
    ebpf_spinlock_lock(&priv_data->data_lock);
    int err = 0;
    size_t curr_idx = 0;
    if (key != NULL) {
        struct ebpf_hashmap_entry entry = { .key = (char *)key, .value = NULL, .attr = &map->attr, .priv_data = map->map_private_data };
        // If entry was found, then curr_idx will be set
        hashmap_get(priv_data->hashmap, &entry, &curr_idx);
        curr_idx++;
    }
    struct ebpf_hashmap_entry *out;
    if (hashmap_iter(priv_data->hashmap, &curr_idx, (void **)&out)) {
        memcpy(next_key, out->key, map->attr.key_size);
        err = 0;
    } else {
        err = -ENOENT;
    }
cleanup:
    ebpf_spinlock_unlock(&priv_data->data_lock);
    return err;
}

struct ebpf_map_ops HASH_MAP_OPS = { .used = true,
                                     .alloc_map = hash_map__alloc,
                                     .map_free = hash_map__free,
                                     .elem_update = hash_map__elem_update,
                                     .elem_lookup = hash_map__elem_lookup,
                                     .elem_lookup_from_helper = hash_map__elem_lookup_from_helper,
                                     .elem_delete = hash_map__elem_delete,
                                     .map_get_next_key = hash_map__map_get_next_key };
