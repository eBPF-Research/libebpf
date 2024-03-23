#ifndef _LIBEBPF_MAP_H
#define _LIBEBPF_MAP_H
#include "libebpf_execution.h"
#include <stdint.h>
#include "libebpf_map_ringbuf.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Map types that we support
 * All maps are ensured to be thread safe. Locks are spin lock.
 * EBPF_MAP_TYPE_HASH - Hashmap for storing fixed-size (key, value) pairs
 * BPF_MAP_TYPE_ARRAY - Array for storing indexed values
 * BPF_MAP_TYPE_RINGBUF - Ringbuf map, with which eBPF programs could send data to ebpf_execution_context. Users could call a specified function to
 * retrive data.
 */
enum ebpf_map_type {
    EBPF_MAP_TYPE_UNSPEC = 0,
    EBPF_MAP_TYPE_HASH = 1,
    EBPF_MAP_TYPE_ARRAY = 2,
    EBPF_MAP_TYPE_RINGBUF = 27,
    __MAX_EBPF_MAP_TYPE = 33
};

/**
 * @brief Attribute of a map
 *
 */
struct ebpf_map_attr {
    /**
     * @brief Type of the map
     *
     */
    enum ebpf_map_type type;
    /**
     * @brief Size of the key
     *
     */
    uint32_t key_size;
    /**
     * @brief Size of the value
     *
     */
    uint32_t value_size;
    /**
     * @brief Max entries
     *
     */
    uint32_t max_ents;
    /**
     * @brief Map-specified flags
     *
     */
    uint64_t flags;
};

/**
 * @brief Create a map in the specified execution context
 *
 * @param ctx The context
 * @param attr Attributes of the map
 * @param map_name Name of the map
 * @return int A non-negative map id if succeeded, otherwise a negative number. See ebpf_error_string for error details.
 */
int ebpf_execution_context__map_create(ebpf_execution_context_t *ctx, const char *map_name, struct ebpf_map_attr *attr);

/**
 * @brief Destroy a specified map
 *
 * @param ctx Context
 * @param map_id ID of the map
 * @return int 0 if succeeded. Otherwise failed.
 */
int ebpf_execution_context__map_destroy(ebpf_execution_context_t *ctx, int map_id);

/**
 * @brief Lookup a key in a certain map
 *
 * @param ctx Context
 * @param map_id ID of the map
 * @param key Buffer to the key. Must be in size of at least key_size
 * @param value Buffer to the value. Must be in size of at least value_size
 * @return int 0 if succeeded, and value buffer will be updated. Otherwise failed.
 */
int ebpf_execution_context__map_elem_lookup(ebpf_execution_context_t *ctx, int map_id, const void *key, void *value);

/**
 * @brief Update a (key, value) pair in a certain map
 *
 * @param ctx Context
 * @param map_id ID of the map
 * @param key Buffer to the key
 * @param value Buffer to the value
 * @param flags Map-specified flags
 * @return int 0 if succeeded, otherwise failed.
 */
int ebpf_execution_context__map_elem_update(ebpf_execution_context_t *ctx, int map_id, const void *key, const void *value, uint64_t flags);

/**
 * @brief Delete an element from the map
 *
 * @param ctx Context
 * @param map_id ID of the map
 * @param key Buffer to the key
 * @return int 0 if succeeded, otherwise failed
 */
int ebpf_execution_context__map_elem_delete(ebpf_execution_context_t *ctx, int map_id, const void *key);

/**
 * @brief Get the next key after the given key
 *
 * @param ctx Context
 * @param map_id ID of the map
 * @param key Buffer to the given key. If set to NULL, will get the first key
 * @param next_key Buffer to store the nexy key
 * @return int -ENOENT if key is the last key. Other negative values mean an error. Positive if succeeded
 */
int ebpf_execution_context__map_get_next_key(ebpf_execution_context_t *ctx, int map_id, const void *key, void *next_key);

/**
 * @brief Get the opaque pointer to the private data of a ringbuf map. Useful if you want to call ringbuf_map_* functions
 *
 * @param ctx Context
 * @param map_id ID of the map
 * @return struct ringbuf_map_private_data* the pointer if succeeded, otherwise NULL
 */
struct ringbuf_map_private_data *ebpf_execution_context__get_ringbuf_map_private_data(ebpf_execution_context_t *ctx, int map_id);

#ifdef __cplusplus
}
#endif
#endif
