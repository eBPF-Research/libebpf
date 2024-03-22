#ifndef _LIBEBPF_MAP_H
#define _LIBEBPF_MAP_H
#include "libebpf_execution.h"
#include <stdint.h>
/**
 * @brief Map types that we support
 * All maps are ensured to be thread safe. Locks are spin lock.
 * EBPF_MAP_TYPE_HASH - Hashmap for storing fixed-size (key, value) pairs
 * BPF_MAP_TYPE_ARRAY - Array for storing indexed values
 * BPF_MAP_TYPE_RINGBUF - Ringbuf map, with which eBPF programs could send data to ebpf_execution_context. Users could call a specified function to
 * retrive data.
 */
enum ebpf_map_type { EBPF_MAP_TYPE_UNSPEC = 0, EBPF_MAP_TYPE_HASH = 1, BPF_MAP_TYPE_ARRAY = 2, BPF_MAP_TYPE_RINGBUF = 27, __MAX_BPF_MAP_TYPE = 33 };

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

#endif
