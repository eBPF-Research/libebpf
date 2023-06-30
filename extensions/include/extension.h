#ifndef _LIBEBPF_EXTENSION_H_
#define _LIBEBPF_EXTENSION_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct ebpf_context *ebpf_create_context(void);
void ebpf_free_context(struct ebpf_context *context);

struct ebpf_open_context_opts {
    const char *btf_path;
};

// open the object elf file and load it into the context
int ebpf_open_object(struct ebpf_context *context, const char *obj_path, const struct ebpf_open_context_opts* opts);

// relocate the programs with a 
int ebpf_relocate_btf(struct ebpf_context *context, const char *btf_path);

// load the programs to userspace vm or compile the jit program
// if program_name is NULL, will load the first program in the object
int ebpf_load_userspace(struct ebpf_context *context, const char *program_name, bool jit);

// exec userspace bpf vm
uint64_t ebpf_exec_userspace(struct ebpf_context *context, void* memory, size_t memory_size);

#endif // _LIBEBPF_EXTENSION_H_
