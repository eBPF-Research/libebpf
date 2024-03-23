#include "libebpf_execution_internal.h"
#include "libebpf_internal.h"
#include "libebpf_map.h"
#include "utils/spinlock.h"
#include <stdint.h>
#include <stddef.h>
#include <errno.h>

#define ARG_PAGE_SIZE 16

#define READ_ONCE_UL(x) (*(volatile unsigned long *)&x)
#define WRITE_ONCE_UL(x, v) (*(volatile unsigned long *)&x) = (v)
#define READ_ONCE_I(x) (*(volatile int *)&x)
#define WRITE_ONCE_I(x, v) (*(volatile int *)&x) = (v)

#define smp_store_release_ul(p, v)                                                                                                                   \
    do {                                                                                                                                             \
        smp_mb();                                                                                                                                    \
        WRITE_ONCE_UL(*p, v);                                                                                                                        \
    } while (0)

#define smp_load_acquire_ul(p)                                                                                                                       \
    ({                                                                                                                                               \
        unsigned long ___p = READ_ONCE_UL(*p);                                                                                                       \
        smp_mb();                                                                                                                                    \
        ___p;                                                                                                                                        \
    })

#define smp_load_acquire_i(p)                                                                                                                        \
    ({                                                                                                                                               \
        int ___p = READ_ONCE_I(*p);                                                                                                                  \
        smp_mb();                                                                                                                                    \
        ___p;                                                                                                                                        \
    })

#define smp_mb() __sync_synchronize()

enum {
    EBPF_RINGBUF_BUSY_BIT = 2147483648,
    EBPF_RINGBUF_DISCARD_BIT = 1073741824,
    EBPF_RINGBUF_HDR_SZ = 8,
};

struct ringbuf_hdr {
    uint32_t len;
    int32_t fd;
};

struct ringbuf_map_private_data {
    ebpf_spinlock_t reserve_lock;
    void *raw_buffer;
    unsigned long *consumer_pos;
    unsigned long *producer_pos;
    void *data;
    struct ebpf_map_attr *attr;
};

static int popcount(uint32_t x) {
    int ret = 0;
    while (x) {
        ret += (x & 1);
        x >>= 1;
    }
    return ret;
}

static int ringbuf_map__alloc(struct ebpf_map *map, struct ebpf_map_attr *attr) {
    if (popcount(attr->max_ents) != 1) {
        ebpf_set_error_string("max_ents must be a power of 2");
        return -EINVAL;
    }
    struct ringbuf_map_private_data *data = _libebpf_global_malloc(sizeof(struct ringbuf_map_private_data));
    if (!data) {
        ebpf_set_error_string("Unable to allocate memory for data");
        return -ENOMEM;
    }
    data->raw_buffer = _libebpf_global_malloc(2 * ARG_PAGE_SIZE + 2 * attr->max_ents);
    if (!data->raw_buffer) {
        ebpf_set_error_string("Unable to allocate memort for data buffer");
        _libebpf_global_free(data);
        return -ENOMEM;
    }
    data->consumer_pos = data->raw_buffer;
    data->producer_pos = data->raw_buffer + ARG_PAGE_SIZE;
    data->data = data->raw_buffer + 2 * ARG_PAGE_SIZE;
    data->attr = &map->attr;
    map->map_private_data = data;
    return 0;
}

static void ringbuf_map__free(struct ebpf_map *map) {
    struct ringbuf_map_private_data *data = map->map_private_data;
    _libebpf_global_free(data->raw_buffer);
    _libebpf_global_free(data);
}

static int ringbuf_map__elem_lookup(struct ebpf_map *map, const void *key, void *value) {
    ebpf_set_error_string("Ringbuf map doesn't support lookup");
    return -ENOTSUP;
}
static int ringbuf_map__elem_update(struct ebpf_map *map, const void *key, const void *value, uint64_t flags) {
    ebpf_set_error_string("Ringbuf map doesn't support update");
    return -ENOTSUP;
}
static int ringbuf_map__elem_delete(struct ebpf_map *map, const void *key) {
    ebpf_set_error_string("Ringbuf map doesn't support delete");
    return -ENOTSUP;
}
static int ringbuf_map__map_get_next_key(struct ebpf_map *map, const void *key, void *next_key) {
    ebpf_set_error_string("Ringbuf map doesn't support get next key");
    return -ENOTSUP;
}

bool ringbuf_map_has_data(struct ringbuf_map_private_data *data) {
    unsigned long cons_pos = smp_load_acquire_ul(data->consumer_pos);
    unsigned long prod_pos = smp_load_acquire_ul(data->producer_pos);
    if (cons_pos < prod_pos) {
        int *len_ptr = (int *)(data->data + (cons_pos & (data->attr->max_ents - 1)));
        int len = smp_load_acquire_i(len_ptr);
        if ((len & EBPF_RINGBUF_BUSY_BIT) == 0)
            return true;
    }
    return false;
}

void *ringbuf_map_reserve(struct ringbuf_map_private_data *data, size_t size) {
    if (size & (EBPF_RINGBUF_BUSY_BIT | EBPF_RINGBUF_DISCARD_BIT)) {
        ebpf_set_error_string("size is too large. bit %lx and %lx can't be set", (unsigned long)EBPF_RINGBUF_BUSY_BIT,
                              (unsigned long)EBPF_RINGBUF_DISCARD_BIT);
        return NULL;
    }

    ebpf_spinlock_lock(&data->reserve_lock);
    int err = 0;
    void *result = NULL;
    unsigned long cons_pos = smp_load_acquire_ul(data->consumer_pos);
    unsigned long prod_pos = smp_load_acquire_ul(data->producer_pos);
    unsigned long avail_size = data->attr->max_ents - (prod_pos - cons_pos);
    size_t required_size = (size + EBPF_RINGBUF_HDR_SZ + 7) / 8 * 8;
    if (required_size > data->attr->max_ents || avail_size < required_size) {
        ebpf_set_error_string("Buffer is too small for your required size");
        err = E2BIG;
        goto cleanup;
    }
    struct ringbuf_hdr *header = data->data + (prod_pos & (data->attr->max_ents - 1));
    header->len = size | EBPF_RINGBUF_BUSY_BIT;
    header->fd = 233;
    smp_store_release_ul(data->producer_pos, prod_pos + required_size);
    result = data->data + ((prod_pos + EBPF_RINGBUF_HDR_SZ) & (data->attr->max_ents - 1));
cleanup:
    ebpf_spinlock_unlock(&data->reserve_lock);
    if (err != 0)
        return NULL;
    return result;
}

void ringbuf_map_submit(struct ringbuf_map_private_data *data, const void *sample, bool discard) {
    uintptr_t hdr_offset = data->attr->max_ents + (sample - data->data) - EBPF_RINGBUF_HDR_SZ;
    struct ringbuf_hdr *hdr = data->data + (hdr_offset & (data->attr->max_ents - 1));
    unsigned long new_len = hdr->len & ~EBPF_RINGBUF_BUSY_BIT;
    if (discard) {
        new_len |= EBPF_RINGBUF_DISCARD_BIT;
    }
    __atomic_exchange_n(&hdr->len, new_len, __ATOMIC_SEQ_CST);
}
static inline int roundup_len(uint32_t len) {
    len <<= 2;
    len >>= 2;
    len += EBPF_RINGBUF_HDR_SZ;
    return (len + 7) / 8 * 8;
}

int ringbuf_map_fetch_data(struct ringbuf_map_private_data *data, void *context, int (*callback)(void *context, void *data, int size)) {
    int err;
    int64_t cnt = 0;

    bool got_new_data = false;

    unsigned long cons_pos = smp_load_acquire_ul(data->consumer_pos);
    do {
        got_new_data = false;
        unsigned long prod_pos = smp_load_acquire_ul(data->producer_pos);
        while (cons_pos < prod_pos) {
            int *len_ptr = data->data + (cons_pos & (data->attr->max_ents - 1));
            int len = smp_load_acquire_i(len_ptr);

            if (len & EBPF_RINGBUF_BUSY_BIT)
                goto done;

            got_new_data = true;
            cons_pos += roundup_len(len);

            if ((len & EBPF_RINGBUF_DISCARD_BIT) == 0) {
                void *sample = (void *)len_ptr + EBPF_RINGBUF_HDR_SZ;
                err = callback(context, sample, len);
                if (err < 0) {
                    smp_store_release_ul(data->consumer_pos, cons_pos);
                    return err;
                }
                cnt++;
            }

            smp_store_release_ul(data->consumer_pos, cons_pos);
        }
    } while (got_new_data);
done:
    return cnt;
}

struct ebpf_map_ops RINGBUF_MAP_OPS = { .used = true,
                                        .alloc_map = ringbuf_map__alloc,
                                        .map_free = ringbuf_map__free,
                                        .elem_update = ringbuf_map__elem_update,
                                        .elem_lookup = ringbuf_map__elem_lookup,
                                        .elem_delete = ringbuf_map__elem_delete,
                                        .map_get_next_key = ringbuf_map__map_get_next_key

};
