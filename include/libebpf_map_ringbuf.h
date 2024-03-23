#ifndef _LIBEBPF_MAP_RINGBUF_H
#define _LIBEBPF_MAP_RINGBUF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Opaque data type for the ringbuf map private data
 *
 */
struct ringbuf_map_private_data;
/**
 * @brief Check if there are available data in a ringbuf map
 *
 * @param map_data Private data of the ringbuf map
 * @return true Data is available
 * @return false Data is not available
 */
bool ringbuf_map_has_data(struct ringbuf_map_private_data *map_data);

/**
 * @brief Reserve size bytes
 *
 * @param map_data Private data of the ringbuf map
 * @param size Size to reserve
 * @return void* NULL if space is not enough, otherwise the data pointer
 */
void *ringbuf_map_reserve(struct ringbuf_map_private_data *map_data, size_t size);

/**
 * @brief Submit the reserved data
 *
 * @param map_data Private data of the ringbuf map
 * @param sample Data pointer
 * @param discard Whether to discard this data piece
 */
void ringbuf_map_submit(struct ringbuf_map_private_data *map_data, const void *sample, bool discard);

/**
 * @brief Fetch data from the specified ringbuf map
 *
 * @param data Private data of the
 * @param context Context for the callback
 * @param callback A callback function to handle received data. If it returned a non-zero number, the process will be terminated.
 * @return int Number of messages that was processed
 */
int ringbuf_map_fetch_data(struct ringbuf_map_private_data *data, void *context, int (*callback)(void *context, void *data, int size));

#ifdef __cplusplus
}
#endif
#endif
