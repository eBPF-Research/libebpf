#include "libebpf_execution.h"
#include "libebpf_ffi.h"
#include "libebpf_internal.h"
#include "libebpf_map.h"
#include "libebpf_map_ringbuf.h"
#include "libebpf_vm.h"
#include "libebpf_execution_internal.h"
#include "utils/hashmap.h"
#include <libebpf_ffi.bpf.h>
#include <stdint.h>
#include <errno.h>

#define MAP_FD(ptr) (int)(ptr >> 32)

static uint64_t bpf_map_lookup_elem(uint64_t map, uint64_t key, uint64_t _1, uint64_t _2, uint64_t _3) {
    ebpf_state_t *ctx = ebpf_state__thread_global_state;
    int fd = MAP_FD(map);
    if (fd >= 0 && fd <= LIBEBPF_MAX_MAP_COUNT && ctx->maps[fd]) {
        return (uintptr_t)ctx->maps[fd]->ops->elem_lookup_from_helper(ctx->maps[fd], (const void *)(uintptr_t)key);
    } else {
        ebpf_set_error_string("Invalid map fd %d", fd);
        return 0;
    }
}

static uint64_t bpf_map_update_elem(uint64_t map, uint64_t key, uint64_t value, uint64_t flags, uint64_t _1) {
    ebpf_state_t *ctx = ebpf_state__thread_global_state;
    int fd = MAP_FD(map);
    if (fd >= 0 && fd <= LIBEBPF_MAX_MAP_COUNT && ctx->maps[fd]) {
        return (uintptr_t)ctx->maps[fd]->ops->elem_update(ctx->maps[fd], (const void *)(uintptr_t)key, (const void *)(uintptr_t)value, 0);
    } else {
        ebpf_set_error_string("Invalid map fd %d", fd);
        return -EINVAL;
    }
}
static uint64_t bpf_map_delete_elem(uint64_t map, uint64_t key, uint64_t _1, uint64_t _2, uint64_t _3) {
    ebpf_state_t *ctx = ebpf_state__thread_global_state;
    int fd = MAP_FD(map);
    if (fd >= 0 && fd <= LIBEBPF_MAX_MAP_COUNT && ctx->maps[fd]) {
        return (uintptr_t)ctx->maps[fd]->ops->elem_delete(ctx->maps[fd], (const void *)(uintptr_t)key);
    } else {
        ebpf_set_error_string("Invalid map fd %d", fd);
        return -EINVAL;
    }
}
static uint64_t bpf_ringbuf_reserve(uint64_t map, uint64_t size, uint64_t flags, uint64_t _1, uint64_t _2) {
    ebpf_state_t *ctx = ebpf_state__thread_global_state;
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
    ebpf_state_t *ctx = ebpf_state__thread_global_state;

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
    ebpf_state_t *ctx = ebpf_state__thread_global_state;

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
    ebpf_state_t *ctx = ebpf_state__thread_global_state;
    if (fd >= 0 && fd <= LIBEBPF_MAX_MAP_COUNT && ctx->maps[fd]) {
        return ((uint64_t)fd) << 32;
    } else {
        ebpf_set_error_string("Invalid map fd %d", fd);
        return (uint64_t)-1;
    }
}
static char *map_val(uint64_t map_ptr) {
    int fd = MAP_FD(map_ptr);
    ebpf_state_t *ctx = ebpf_state__thread_global_state;
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

static uint64_t helper_libebpf_ffi_lookup_by_name(uint64_t name, uint64_t _1, uint64_t _2, uint64_t _3, uint64_t _4) {
    ebpf_state_t *ctx = ebpf_state__thread_global_state;
    struct libebpf_ffi_name_entry entry = { .name = (const char *)name, .id = -1 };
    const struct libebpf_ffi_name_entry *ent = hashmap_get(ctx->ffi_func_name_hashmap, &entry, NULL);
    if (ent == NULL) {
        ebpf_set_error_string("Name %s not found in name hashmap", (const char *)name);
        return (int64_t)-1;
    }
    return ent->id;
}
/**
 * @brief Fill a libebpf_ffi_argument from the argument received from ebpf program, adapted to the required type (usually truncated)
 *
 * @param type
 * @param v
 * @return union
 */
static union libebpf_ffi_argument load_argument_from_int64(enum libebpf_ffi_type type, int64_t v) {
    union libebpf_ffi_argument val = { .uint64 = 0 };
    switch (type) {
    case ARG_INT8:
        val.int8 = v;
        break;
    case ARG_INT16:
        val.int16 = v;
        break;
    case ARG_INT32:
        val.int32 = v;
        break;
    case ARG_INT64:
        val.int64 = v;
        break;
    case ARG_UINT8:
        val.uint8 = v;
        break;
    case ARG_UINT16:
        val.uint16 = v;
        break;
    case ARG_UINT32:
        val.uint32 = v;
        break;
    case ARG_UINT64:
        val.uint64 = v;
        break;
    case ARG_FLOAT32:
        val.float32 = *(float *)(uintptr_t)(&v);
        break;
    case ARG_FLOAT64:
        val.float64 = *(double *)(uintptr_t)(&v);
        break;
    case ARG_PTR:
        val.ptr = (void *)(uintptr_t)v;
        break;
    case ARG_VOID:
        break;
    }
    return val;
}
/**
 * @brief Convert an argument received from native function to int64. eBPF side only accept int64 arguments and return values
 *
 * @param type
 * @param arg
 * @return int64_t
 */
static int64_t store_argument_to_int64(enum libebpf_ffi_type type, union libebpf_ffi_argument val) {
    switch (type) {
    case ARG_INT8:
        return val.int8;
    case ARG_INT16:
        return val.int16;
    case ARG_INT32:
        return val.int32;
    case ARG_INT64:
        return val.int64;
    case ARG_UINT8:
        return val.uint8;
    case ARG_UINT16:
        return val.uint16;
    case ARG_UINT32:
        return val.uint32;
    case ARG_UINT64:
        return val.uint64;
    case ARG_FLOAT32:
        return *(uint32_t *)(uintptr_t)(&val.float32);
    case ARG_FLOAT64:
        return *(uint64_t *)(uintptr_t)(&val.float64);
    case ARG_PTR:
        return (uintptr_t)val.ptr;
    case ARG_VOID:
        return 0;
    }
}

static uint64_t helper_libebpf_ffi_call(uint64_t func_id, uint64_t args, uint64_t _1, uint64_t _2, uint64_t _3) {
    int id = func_id;
    ebpf_state_t *ctx = ebpf_state__thread_global_state;

    if (id < 0 || id > LIBEBPF_MAX_FFI_COUNT || !ctx->ffi_funcs[id].ptr) {
        ebpf_set_error_string("Invalid ffi function id: %d", id);
        return (int64_t)-1;
    }
    struct libebpf_ffi_call_argument_list *args_from_ebpf = (void *)(uintptr_t)args;
    struct libebpf_ffi_function *ent = &ctx->ffi_funcs[id];
    union libebpf_ffi_argument args_to_ffi_func[LIBEBPF_FFI_MAX_ARGUMENT_COUNT];
    for (int i = 0; i < LIBEBPF_FFI_MAX_ARGUMENT_COUNT; i++)
        args_to_ffi_func[i] = load_argument_from_int64(ent->arg_types[i], args_from_ebpf->args[i]);
    union libebpf_ffi_argument result;
    result.ptr = ent->ptr(args_to_ffi_func[0].ptr, args_to_ffi_func[1].ptr, args_to_ffi_func[2].ptr, args_to_ffi_func[3].ptr,
                           args_to_ffi_func[4].ptr, args_to_ffi_func[5].ptr);
    return store_argument_to_int64(ent->return_value_type, result);
}

void ebpf_state__setup_internal_helpers(ebpf_vm_t *vm) {
    ebpf_vm_set_ld64_helpers(vm, map_by_fd, NULL, map_val, NULL, NULL);
    ebpf_vm_register_external_helper(vm, 1, "bpf_map_lookup_elem", bpf_map_lookup_elem);
    ebpf_vm_register_external_helper(vm, 2, "bpf_map_update_elem", bpf_map_update_elem);
    ebpf_vm_register_external_helper(vm, 3, "bpf_map_delete_elem", bpf_map_delete_elem);
    ebpf_vm_register_external_helper(vm, 131, "bpf_ringbuf_reserve", bpf_ringbuf_reserve);
    ebpf_vm_register_external_helper(vm, 132, "bpf_ringbuf_submit", bpf_ringbuf_submit);
    ebpf_vm_register_external_helper(vm, 133, "bpf_ringbuf_discard", bpf_ringbuf_discard);
    ebpf_vm_register_external_helper(vm, LIBEBPF_FFI_HELPER_INDEX__LOOKUP_BY_NAME, "libebpf_ffi_lookup_by_name", helper_libebpf_ffi_lookup_by_name);
    ebpf_vm_register_external_helper(vm, LIBEBPF_FFI_HELPER_INDEX__CALL, "liebpf_ffi_call", helper_libebpf_ffi_call);
}
