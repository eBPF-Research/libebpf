#define _GNU_SOURCE
#include <libebpf.h>
#include <stdlib.h>
#include <libebpf_internal.h>

static ebpf_malloc global_malloc = &malloc;
static ebpf_free global_free = &free;

static char global_error_string[1024] = "";

void ebpf_set_global_memory_allocator(ebpf_malloc malloc, ebpf_free free) {
    global_malloc = malloc;
    global_free = free;
}

const char *ebpf_error_string() {
    return global_error_string;
}
