/*
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2022 Linaro Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ebpf_INST_H
#define ebpf_INST_H

#include <libebpf/libebpf.h>
#include "ebpf_inst.h"
#include "linux_jit_bpf.h"

struct ebpf_inst;
typedef uint64_t (*ext_func)(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

struct ebpf_vm
{
    /* ubpf_defs*/
    struct ebpf_inst* insts;
    uint16_t num_insts;
    ebpf_jit_fn jitted;
    size_t jitted_size;
    ext_func* ext_funcs;
    const char** ext_func_names;
    bool bounds_check_enabled;
    int (*error_printf)(FILE* stream, const char* format, ...);
    int (*translate)(struct ebpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg);
    int unwind_stack_extension_index;
    uint64_t pointer_secret;
#ifdef DEBUG
    uint64_t* regs;
#endif
    /* linux defs: TODO: merge them together*/
	u16			pages;		/* Number of allocated pages */
	u16			jited:1,	/* Is our filter JIT'ed? */
				jit_requested:1,/* archs need to JIT the prog */
				gpl_compatible:1, /* Is filter GPL compatible? */
				cb_access:1,	/* Is control block accessed? */
				dst_needed:1,	/* Do we need dst entry? */
				blinded:1,	/* Was blinded */
				is_func:1,	/* program is a bpf function */
				kprobe_override:1, /* Do we override a kprobe? */
				has_callchain_buf:1, /* callchain buffer allocated? */
				enforce_expected_attach_type:1; /* Enforce expected_attach_type checking at attach time */
	u32			len;		/* Number of filter blocks */
	u32			jited_len;	/* Size of jited insns in bytes */
	struct bpf_prog_aux	*aux;		/* Auxiliary fields */
	struct sock_fprog_kern	*orig_prog;	/* Original BPF program */
	unsigned int		(*bpf_func)(const void *ctx,
					    const struct bpf_insn *insn);
	/* Instructions for interpreter */
	struct bpf_insn		insnsi[];
};

/* The various JIT targets.  */
int
ebpf_translate_arm64(struct ebpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg);
int
ebpf_translate_x86_64(struct ebpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg);
int
ebpf_translate_null(struct ebpf_vm* vm, uint8_t* buffer, size_t* size, char** errmsg);

char*
ebpf_error(const char* fmt, ...);
unsigned int
ebpf_lookup_registered_function(struct ebpf_vm* vm, const char* name);

/**
 * @brief Fetch the instruction at the given index.
 *
 * @param[in] vm The VM to fetch the instruction from.
 * @param[in] pc The index of the instruction to fetch.
 * @return The instruction.
 */
struct ebpf_inst
ebpf_fetch_instruction(const struct ebpf_vm* vm, uint16_t pc);

/**
 * @brief Store the given instruction at the given index.
 *
 * @param[in] vm The VM to store the instruction in.
 * @param[in] pc The index of the instruction to store.
 * @param[in] inst The instruction to store.
 */
void
ebpf_store_instruction(const struct ebpf_vm* vm, uint16_t pc, struct ebpf_inst inst);

#endif
