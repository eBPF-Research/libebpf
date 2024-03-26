#include "libebpf_execution.h"
#include "libebpf_internal.h"
#include "libebpf_map.h"
#include "libebpf_map_ringbuf.h"
#include "libebpf_vm.h"
#include "libebpf_execution_internal.h"
#include <stdint.h>
#include <errno.h>
#define MAP_FD(ptr) (int)(ptr >> 32)

static uint64_t bpf_map_lookup_elem(uint64_t map, uint64_t key, uint64_t _1, uint64_t _2, uint64_t _3) {
    ebpf_execution_context_t *ctx = ebpf_execution_context__thread_global_context;
    int fd = MAP_FD(map);
    if (fd >= 0 && fd <= LIBEBPF_MAX_MAP_COUNT && ctx->maps[fd]) {
        return (uintptr_t)ctx->maps[fd]->ops->elem_lookup_from_helper(ctx->maps[fd], (const void *)(uintptr_t)key);
    } else {
        ebpf_set_error_string("Invalid map fd %d", fd);
        return 0;
    }
}

static uint64_t bpf_map_update_elem(uint64_t map, uint64_t key, uint64_t value, uint64_t flags, uint64_t _1) {
    ebpf_execution_context_t *ctx = ebpf_execution_context__thread_global_context;
    int fd = MAP_FD(map);
    if (fd >= 0 && fd <= LIBEBPF_MAX_MAP_COUNT && ctx->maps[fd]) {
        return (uintptr_t)ctx->maps[fd]->ops->elem_update(ctx->maps[fd], (const void *)(uintptr_t)key, (const void *)(uintptr_t)value, 0);
    } else {
        ebpf_set_error_string("Invalid map fd %d", fd);
        return -EINVAL;
    }
}
static uint64_t bpf_map_delete_elem(uint64_t map, uint64_t key, uint64_t _1, uint64_t _2, uint64_t _3) {
    ebpf_execution_context_t *ctx = ebpf_execution_context__thread_global_context;
    int fd = MAP_FD(map);
    if (fd >= 0 && fd <= LIBEBPF_MAX_MAP_COUNT && ctx->maps[fd]) {
        return (uintptr_t)ctx->maps[fd]->ops->elem_delete(ctx->maps[fd], (const void *)(uintptr_t)key);
    } else {
        ebpf_set_error_string("Invalid map fd %d", fd);
        return -EINVAL;
    }
}
static uint64_t bpf_ringbuf_reserve(uint64_t map, uint64_t size, uint64_t flags, uint64_t _1, uint64_t _2) {
    ebpf_execution_context_t *ctx = ebpf_execution_context__thread_global_context;
    int fd = MAP_FD(map);
    if (fd >= 0 && fd <= LIBEBPF_MAX_MAP_COUNT && ctx->maps[fd]) {
        struct ebpf_map *map = ctx->maps[fd];
        if (map->attr.type == EBPF_MAP_TYPE_RINGBUF) {
            struct ringbuf_map_private_data *data = map->map_private_data;
            return (uint64_t)(uintptr_t)ringbuf_map_reserve(data, size);
        } else {
            ebpf_set_error_string("bpf_ringbuf_reserve must be called on ringbuf map");
            return -ENOTSUP;
        }
    } else {
        ebpf_set_error_string("Invalid map fd %d", fd);
        return 0;
    }
}
static uint64_t bpf_ringbuf_submit(uint64_t buf, uint64_t flags, uint64_t _1, uint64_t _2, uint64_t _3) {
    int32_t *ptr = (int32_t *)(uintptr_t)buf;
    int fd = ptr[-1];
    ebpf_execution_context_t *ctx = ebpf_execution_context__thread_global_context;

    if (fd >= 0 && fd <= LIBEBPF_MAX_MAP_COUNT && ctx->maps[fd]) {
        struct ebpf_map *map = ctx->maps[fd];
        if (map->attr.type == EBPF_MAP_TYPE_RINGBUF) {
            struct ringbuf_map_private_data *data = map->map_private_data;
            ringbuf_map_submit(data, ptr, false);
        }
    }

    return 0;
}
static uint64_t bpf_ringbuf_discard(uint64_t buf, uint64_t flags, uint64_t _1, uint64_t _2, uint64_t _3) {
    int32_t *ptr = (int32_t *)(uintptr_t)buf;
    int fd = ptr[-1];
    ebpf_execution_context_t *ctx = ebpf_execution_context__thread_global_context;

    if (fd >= 0 && fd <= LIBEBPF_MAX_MAP_COUNT && ctx->maps[fd]) {
        struct ebpf_map *map = ctx->maps[fd];
        if (map->attr.type == EBPF_MAP_TYPE_RINGBUF) {
            struct ringbuf_map_private_data *data = map->map_private_data;
            ringbuf_map_submit(data, ptr, true);
        }
    }

    return 0;
}

static uint64_t map_by_fd(int fd) {
    ebpf_execution_context_t *ctx = ebpf_execution_context__thread_global_context;
    if (fd >= 0 && fd <= LIBEBPF_MAX_MAP_COUNT && ctx->maps[fd]) {
        return ((uint64_t)fd) << 32;
    } else {
        ebpf_set_error_string("Invalid map fd %d", fd);
        return (uint64_t)-1;
    }
}
static char *map_val(uint64_t map_ptr) {
    int fd = MAP_FD(map_ptr);
    ebpf_execution_context_t *ctx = ebpf_execution_context__thread_global_context;
    if (fd >= 0 && fd <= LIBEBPF_MAX_MAP_COUNT && ctx->maps[fd]) {
        if (ctx->maps[fd]->attr.type == EBPF_MAP_TYPE_ARRAY) {
            struct ebpf_map *map = ctx->maps[fd];
            int idx = 0;
            return ctx->map_ops[map->attr.type].elem_lookup_from_helper(map, &idx);
        } else {
            ebpf_set_error_string("Only array map supports map_val");
            return NULL;
        }
    } else {
        ebpf_set_error_string("Invalid map fd %d", fd);
        return NULL;
    }
}
void ebpf_execution_context__setup_internal_helpers(ebpf_vm_t *vm) {
    ebpf_vm_set_ld64_helpers(vm, map_by_fd, NULL, map_val, NULL, NULL);
    ebpf_vm_register_external_helper(vm, 1, "bpf_map_lookup_elem", bpf_map_lookup_elem);
    ebpf_vm_register_external_helper(vm, 2, "bpf_map_update_elem", bpf_map_update_elem);
    ebpf_vm_register_external_helper(vm, 3, "bpf_map_delete_elem", bpf_map_delete_elem);
    ebpf_vm_register_external_helper(vm, 131, "bpf_ringbuf_reserve", bpf_ringbuf_reserve);
    ebpf_vm_register_external_helper(vm, 132, "bpf_ringbuf_submit", bpf_ringbuf_submit);
    ebpf_vm_register_external_helper(vm, 133, "bpf_ringbuf_discard", bpf_ringbuf_discard);
}
