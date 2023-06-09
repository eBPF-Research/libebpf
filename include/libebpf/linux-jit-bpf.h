#ifndef LIBEBPF_LINUX_JIT_H_
#define LIBEBPF_LINUX_JIT_H_

#include <stdint.h>

struct bpf_prog;

#define BPF_OBJ_NAME_LEN 16U

/// a minimal set of definitions from linux/bpf.h for bpf_attr syscall arguments
/// include:
/// - prog load
/// - prog attach
/// - map create, delete, insert, etc.
union bpf_attr {
	struct { /* anonymous struct used by BPF_MAP_CREATE command */
		uint32_t	map_type;	/* one of enum bpf_map_type */
		uint32_t	key_size;	/* size of key in bytes */
		uint32_t	value_size;	/* size of value in bytes */
		uint32_t	max_entries;	/* max number of entries in a map */
		uint32_t	map_flags;	/* BPF_MAP_CREATE related
					 * flags defined above.
					 */
		uint32_t	inner_map_fd;	/* fd pointing to the inner map */
		uint32_t	numa_node;	/* numa node (effective only if
					 * BPF_F_NUMA_NODE is set).
					 */
		char	map_name[BPF_OBJ_NAME_LEN];
		uint32_t	map_ifindex;	/* ifindex of netdev to create on */
		uint32_t	btf_fd;		/* fd pointing to a BTF type data */
		uint32_t	btf_key_type_id;	/* BTF type_id of the key */
		uint32_t	btf_value_type_id;	/* BTF type_id of the value */
		uint32_t	btf_vmlinux_value_type_id;/* BTF type_id of a kernel-
						   * struct stored as the
						   * map value
						   */
		/* Any per-map-type extra fields
		 *
		 * BPF_MAP_TYPE_BLOOM_FILTER - the lowest 4 bits indicate the
		 * number of hash functions (if 0, the bloom filter will default
		 * to using 5 hash functions).
		 */
		uint64_t	map_extra;
	};

	struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
		uint32_t		map_fd;
		__aligned_u64	key;
		union {
			__aligned_u64 value;
			__aligned_u64 next_key;
		};
		uint64_t		flags;
	};

	struct { /* anonymous struct used by BPF_PROG_LOAD command */
		uint32_t		prog_type;	/* one of enum bpf_prog_type */
		uint32_t		insn_cnt;
		__aligned_u64	insns[0];
		__aligned_u64	license;
		uint32_t		log_level;	/* verbosity level of verifier */
		uint32_t		log_size;	/* size of user buffer */
		__aligned_u64	log_buf;	/* user supplied buffer */
		uint32_t		kern_version;	/* not used */
		uint32_t		prog_flags;
		char		prog_name[BPF_OBJ_NAME_LEN];
		uint32_t		prog_ifindex;	/* ifindex of netdev to prep for */
		/* For some prog types expected attach type must be known at
		 * load time to verify attach type specific parts of prog
		 * (context accesses, allowed helpers, etc).
		 */
		uint32_t		expected_attach_type;
		uint32_t		prog_btf_fd;	/* fd pointing to BTF type data */
		uint32_t		func_info_rec_size;	/* userspace bpf_func_info size */
		__aligned_u64	func_info;	/* func info */
		uint32_t		func_info_cnt;	/* number of bpf_func_info records */
		uint32_t		line_info_rec_size;	/* userspace bpf_line_info size */
		__aligned_u64	line_info;	/* line info */
		uint32_t		line_info_cnt;	/* number of bpf_line_info records */
		uint32_t		attach_btf_id;	/* in-kernel BTF type id to attach to */
		union {
			/* valid prog_fd to attach to bpf prog */
			uint32_t		attach_prog_fd;
			/* or valid module BTF object fd or 0 to attach to vmlinux */
			uint32_t		attach_btf_obj_fd;
		};
		uint32_t		core_relo_cnt;	/* number of bpf_core_relo */
		__aligned_u64	fd_array;	/* array of FDs */
		__aligned_u64	core_relos;
		uint32_t		core_relo_rec_size; /* sizeof(struct bpf_core_relo) */
	};

	struct { /* anonymous struct used by BPF_PROG_ATTACH/DETACH commands */
		uint32_t		target_fd;	/* container object to attach to */
		uint32_t		attach_bpf_fd;	/* eBPF program to attach */
		uint32_t		attach_type;
		uint32_t		attach_flags;
		uint32_t		replace_bpf_fd;	/* previously attached eBPF
						 * program to replace if
						 * BPF_F_REPLACE is used
						 */
	};
} __attribute__((aligned(8)));

static int bpf_prog_load(union bpf_attr *attr, const void* uattr);

struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog);

unsigned int bpf_prog_run_jit(const struct bpf_prog *prog, const void *ctx);

void bpf_prog_free(struct bpf_prog *prog);

#endif
