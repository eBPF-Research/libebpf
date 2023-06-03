/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 */
#ifndef _LINUX_BPF_H
#define _LINUX_BPF_H 1

#include "linux-errno.h"
#include "type-fixes.h"


struct sk_buff;
struct sock;
struct seccomp_data;
struct bpf_prog_aux;
struct xdp_rxq_info;
struct xdp_buff;
struct sock_reuseport;
struct ctl_table;
struct ctl_table_header;

/* ArgX, context and stack frame pointer register positions. Note,
 * Arg1, Arg2, Arg3, etc are used as argument mappings of function
 * calls in BPF_CALL instruction.
 */
#define BPF_REG_ARG1	BPF_REG_1
#define BPF_REG_ARG2	BPF_REG_2
#define BPF_REG_ARG3	BPF_REG_3
#define BPF_REG_ARG4	BPF_REG_4
#define BPF_REG_ARG5	BPF_REG_5
#define BPF_REG_CTX	BPF_REG_6
#define BPF_REG_FP	BPF_REG_10

/* Additional register mappings for converted user programs. */
#define BPF_REG_A	BPF_REG_0
#define BPF_REG_X	BPF_REG_7
#define BPF_REG_TMP	BPF_REG_2	/* scratch reg */
#define BPF_REG_D	BPF_REG_8	/* data, callee-saved */
#define BPF_REG_H	BPF_REG_9	/* hlen, callee-saved */

/* Kernel hidden auxiliary/helper register. */
#define BPF_REG_AX		MAX_BPF_REG
#define MAX_BPF_EXT_REG		(MAX_BPF_REG + 1)
#define MAX_BPF_JIT_REG		MAX_BPF_EXT_REG

/* unused opcode to mark special call to bpf_tail_call() helper */
#define BPF_TAIL_CALL	0xf0

/* unused opcode to mark special load instruction. Same as BPF_ABS */
#define BPF_PROBE_MEM	0x20

/* unused opcode to mark call to interpreter with arguments */
#define BPF_CALL_ARGS	0xe0

/* As per nm, we expose JITed images as text (code) section for
 * kallsyms. That way, tools like perf can find it to match
 * addresses.
 */
#define BPF_SYM_ELF_TYPE	't'

/* BPF program can access up to 512 bytes of stack space. */
#define MAX_BPF_STACK	512

/*
 * Current version of the filter code architecture.
 */
#define BPF_MAJOR_VERSION 1
#define BPF_MINOR_VERSION 1

/*
 *	Try and keep these values and structures similar to BSD, especially
 *	the BPF code definitions which need to match so you can share filters
 */
 
struct sock_filter {	/* Filter block */
	__u16	code;   /* Actual filter code */
	__u8	jt;	/* Jump true */
	__u8	jf;	/* Jump false */
	__u32	k;      /* Generic multiuse field */
};

struct sock_fprog {	/* Required for SO_ATTACH_FILTER. */
	unsigned short		len;	/* Number of filter blocks */
	struct sock_filter *filter;
};

/* ret - BPF_K and BPF_X also apply */
#define BPF_RVAL(code)  ((code) & 0x18)
#define         BPF_A           0x10

/* misc */
#define BPF_MISCOP(code) ((code) & 0xf8)
#define         BPF_TAX         0x00
#define         BPF_TXA         0x80

/*
 * Macros for filter block array initializers.
 */
#ifndef BPF_STMT
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#endif
#ifndef BPF_JUMP
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#endif

/*
 * Number of scratch memory words for: BPF_ST and BPF_STX
 */
#define BPF_MEMWORDS 16

/* RATIONALE. Negative offsets are invalid in BPF.
   We use them to reference ancillary data.
   Unlike introduction new instructions, it does not break
   existing compilers/optimizers.
 */
#define SKF_AD_OFF    (-0x1000)
#define SKF_AD_PROTOCOL 0
#define SKF_AD_PKTTYPE 	4
#define SKF_AD_IFINDEX 	8
#define SKF_AD_NLATTR	12
#define SKF_AD_NLATTR_NEST	16
#define SKF_AD_MARK 	20
#define SKF_AD_QUEUE	24
#define SKF_AD_HATYPE	28
#define SKF_AD_RXHASH	32
#define SKF_AD_CPU	36
#define SKF_AD_ALU_XOR_X	40
#define SKF_AD_VLAN_TAG	44
#define SKF_AD_VLAN_TAG_PRESENT 48
#define SKF_AD_PAY_OFFSET	52
#define SKF_AD_RANDOM	56
#define SKF_AD_VLAN_TPID	60
#define SKF_AD_MAX	64

#define SKF_NET_OFF	(-0x100000)
#define SKF_LL_OFF	(-0x200000)

#define BPF_NET_OFF	SKF_NET_OFF
#define BPF_LL_OFF	SKF_LL_OFF

/* Instruction classes */
#define BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC        0x07

/* ld/ldx fields */
#define BPF_SIZE(code)  ((code) & 0x18)
#define		BPF_W		0x00 /* 32-bit */
#define		BPF_H		0x08 /* 16-bit */
#define		BPF_B		0x10 /*  8-bit */
/* eBPF		BPF_DW		0x18    64-bit */
#define BPF_MODE(code)  ((code) & 0xe0)
#define		BPF_IMM		0x00
#define		BPF_ABS		0x20
#define		BPF_IND		0x40
#define		BPF_MEM		0x60
#define		BPF_LEN		0x80
#define		BPF_MSH		0xa0

/* alu/jmp fields */
#define BPF_OP(code)    ((code) & 0xf0)
#define		BPF_ADD		0x00
#define		BPF_SUB		0x10
#define		BPF_MUL		0x20
#define		BPF_DIV		0x30
#define		BPF_OR		0x40
#define		BPF_AND		0x50
#define		BPF_LSH		0x60
#define		BPF_RSH		0x70
#define		BPF_NEG		0x80
#define		BPF_MOD		0x90
#define		BPF_XOR		0xa0

#define		BPF_JA		0x00
#define		BPF_JEQ		0x10
#define		BPF_JGT		0x20
#define		BPF_JGE		0x30
#define		BPF_JSET        0x40
#define BPF_SRC(code)   ((code) & 0x08)
#define		BPF_K		0x00
#define		BPF_X		0x08

#ifndef BPF_MAXINSNS
#define BPF_MAXINSNS 4096
#endif

/* Extended instruction set based on top of classic BPF */

/* instruction classes */
#define BPF_JMP32	0x06	/* jmp mode in word width */
#define BPF_ALU64	0x07	/* alu mode in double word width */

/* ld/ldx fields */
#define BPF_DW		0x18	/* double word (64-bit) */
#define BPF_XADD	0xc0	/* exclusive add */

/* alu/jmp fields */
#define BPF_MOV		0xb0	/* mov reg to reg */
#define BPF_ARSH	0xc0	/* sign extending arithmetic shift right */

/* change endianness of a register */
#define BPF_END		0xd0	/* flags for endianness conversion: */
#define BPF_TO_LE	0x00	/* convert to little-endian */
#define BPF_TO_BE	0x08	/* convert to big-endian */
#define BPF_FROM_LE	BPF_TO_LE
#define BPF_FROM_BE	BPF_TO_BE

/* jmp encodings */
#define BPF_JNE		0x50	/* jump != */
#define BPF_JLT		0xa0	/* LT is unsigned, '<' */
#define BPF_JLE		0xb0	/* LE is unsigned, '<=' */
#define BPF_JSGT	0x60	/* SGT is signed '>', GT in x86 */
#define BPF_JSGE	0x70	/* SGE is signed '>=', GE in x86 */
#define BPF_JSLT	0xc0	/* SLT is signed, '<' */
#define BPF_JSLE	0xd0	/* SLE is signed, '<=' */
#define BPF_CALL	0x80	/* function call */
#define BPF_EXIT	0x90	/* function return */

/* Register numbers */
enum {
	BPF_REG_0 = 0,
	BPF_REG_1,
	BPF_REG_2,
	BPF_REG_3,
	BPF_REG_4,
	BPF_REG_5,
	BPF_REG_6,
	BPF_REG_7,
	BPF_REG_8,
	BPF_REG_9,
	BPF_REG_10,
	__MAX_BPF_REG,
};

/* BPF has 10 general purpose 64-bit registers and stack frame. */
#define MAX_BPF_REG	__MAX_BPF_REG

struct bpf_insn {
	__u8	code;		/* opcode */
	__u8	dst_reg:4;	/* dest register */
	__u8	src_reg:4;	/* source register */
	__s16	off;		/* signed offset */
	__s32	imm;		/* signed immediate constant */
};

/* Key of an a BPF_MAP_TYPE_LPM_TRIE entry */
struct bpf_lpm_trie_key {
	__u32	prefixlen;	/* up to 32 for AF_INET, 128 for AF_INET6 */
	__u8	data[0];	/* Arbitrary size */
};

struct bpf_cgroup_storage_key {
	__u64	cgroup_inode_id;	/* cgroup inode id */
	__u32	attach_type;		/* program attach type */
};

/* BPF syscall commands, see bpf(2) man-page for details. */
enum bpf_cmd {
	BPF_MAP_CREATE,
	BPF_MAP_LOOKUP_ELEM,
	BPF_MAP_UPDATE_ELEM,
	BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY,
	BPF_PROG_LOAD,
	BPF_OBJ_PIN,
	BPF_OBJ_GET,
	BPF_PROG_ATTACH,
	BPF_PROG_DETACH,
	BPF_PROG_TEST_RUN,
	BPF_PROG_GET_NEXT_ID,
	BPF_MAP_GET_NEXT_ID,
	BPF_PROG_GET_FD_BY_ID,
	BPF_MAP_GET_FD_BY_ID,
	BPF_OBJ_GET_INFO_BY_FD,
	BPF_PROG_QUERY,
	BPF_RAW_TRACEPOINT_OPEN,
	BPF_BTF_LOAD,
	BPF_BTF_GET_FD_BY_ID,
	BPF_TASK_FD_QUERY,
	BPF_MAP_LOOKUP_AND_DELETE_ELEM,
	BPF_MAP_FREEZE,
	BPF_BTF_GET_NEXT_ID,
	BPF_MAP_LOOKUP_BATCH,
	BPF_MAP_LOOKUP_AND_DELETE_BATCH,
	BPF_MAP_UPDATE_BATCH,
	BPF_MAP_DELETE_BATCH,
	BPF_LINK_CREATE,
	BPF_LINK_UPDATE,
	BPF_LINK_GET_FD_BY_ID,
	BPF_LINK_GET_NEXT_ID,
	BPF_ENABLE_STATS,
	BPF_ITER_CREATE,
};

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PROG_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_STACK_TRACE,
	BPF_MAP_TYPE_CGROUP_ARRAY,
	BPF_MAP_TYPE_LRU_HASH,
	BPF_MAP_TYPE_LRU_PERCPU_HASH,
	BPF_MAP_TYPE_LPM_TRIE,
	BPF_MAP_TYPE_ARRAY_OF_MAPS,
	BPF_MAP_TYPE_HASH_OF_MAPS,
	BPF_MAP_TYPE_DEVMAP,
	BPF_MAP_TYPE_SOCKMAP,
	BPF_MAP_TYPE_CPUMAP,
	BPF_MAP_TYPE_XSKMAP,
	BPF_MAP_TYPE_SOCKHASH,
	BPF_MAP_TYPE_CGROUP_STORAGE,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
	BPF_MAP_TYPE_QUEUE,
	BPF_MAP_TYPE_STACK,
	BPF_MAP_TYPE_SK_STORAGE,
	BPF_MAP_TYPE_DEVMAP_HASH,
	BPF_MAP_TYPE_STRUCT_OPS,
	BPF_MAP_TYPE_RINGBUF,
};

/* Note that tracing related programs such as
 * BPF_PROG_TYPE_{KPROBE,TRACEPOINT,PERF_EVENT,RAW_TRACEPOINT}
 * are not subject to a stable API since kernel internal data
 * structures can change from release to release and may
 * therefore break existing tracing BPF programs. Tracing BPF
 * programs correspond to /a/ specific kernel which is to be
 * analyzed, and not /a/ specific kernel /and/ all future ones.
 */
enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_CGROUP_SKB,
	BPF_PROG_TYPE_CGROUP_SOCK,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
	BPF_PROG_TYPE_SOCK_OPS,
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_CGROUP_DEVICE,
	BPF_PROG_TYPE_SK_MSG,
	BPF_PROG_TYPE_RAW_TRACEPOINT,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
	BPF_PROG_TYPE_LWT_SEG6LOCAL,
	BPF_PROG_TYPE_LIRC_MODE2,
	BPF_PROG_TYPE_SK_REUSEPORT,
	BPF_PROG_TYPE_FLOW_DISSECTOR,
	BPF_PROG_TYPE_CGROUP_SYSCTL,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
	BPF_PROG_TYPE_CGROUP_SOCKOPT,
	BPF_PROG_TYPE_TRACING,
	BPF_PROG_TYPE_STRUCT_OPS,
	BPF_PROG_TYPE_EXT,
	BPF_PROG_TYPE_LSM,
	BPF_PROG_TYPE_SK_LOOKUP,
};

enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS,
	BPF_CGROUP_INET_EGRESS,
	BPF_CGROUP_INET_SOCK_CREATE,
	BPF_CGROUP_SOCK_OPS,
	BPF_SK_SKB_STREAM_PARSER,
	BPF_SK_SKB_STREAM_VERDICT,
	BPF_CGROUP_DEVICE,
	BPF_SK_MSG_VERDICT,
	BPF_CGROUP_INET4_BIND,
	BPF_CGROUP_INET6_BIND,
	BPF_CGROUP_INET4_CONNECT,
	BPF_CGROUP_INET6_CONNECT,
	BPF_CGROUP_INET4_POST_BIND,
	BPF_CGROUP_INET6_POST_BIND,
	BPF_CGROUP_UDP4_SENDMSG,
	BPF_CGROUP_UDP6_SENDMSG,
	BPF_LIRC_MODE2,
	BPF_FLOW_DISSECTOR,
	BPF_CGROUP_SYSCTL,
	BPF_CGROUP_UDP4_RECVMSG,
	BPF_CGROUP_UDP6_RECVMSG,
	BPF_CGROUP_GETSOCKOPT,
	BPF_CGROUP_SETSOCKOPT,
	BPF_TRACE_RAW_TP,
	BPF_TRACE_FENTRY,
	BPF_TRACE_FEXIT,
	BPF_MODIFY_RETURN,
	BPF_LSM_MAC,
	BPF_TRACE_ITER,
	BPF_CGROUP_INET4_GETPEERNAME,
	BPF_CGROUP_INET6_GETPEERNAME,
	BPF_CGROUP_INET4_GETSOCKNAME,
	BPF_CGROUP_INET6_GETSOCKNAME,
	BPF_XDP_DEVMAP,
	BPF_CGROUP_INET_SOCK_RELEASE,
	BPF_XDP_CPUMAP,
	BPF_SK_LOOKUP,
	__MAX_BPF_ATTACH_TYPE
};

#define MAX_BPF_ATTACH_TYPE __MAX_BPF_ATTACH_TYPE

enum bpf_link_type {
	BPF_LINK_TYPE_UNSPEC = 0,
	BPF_LINK_TYPE_RAW_TRACEPOINT = 1,
	BPF_LINK_TYPE_TRACING = 2,
	BPF_LINK_TYPE_CGROUP = 3,
	BPF_LINK_TYPE_ITER = 4,
	BPF_LINK_TYPE_NETNS = 5,

	MAX_BPF_LINK_TYPE,
};

/* cgroup-bpf attach flags used in BPF_PROG_ATTACH command
 *
 * NONE(default): No further bpf programs allowed in the subtree.
 *
 * BPF_F_ALLOW_OVERRIDE: If a sub-cgroup installs some bpf program,
 * the program in this cgroup yields to sub-cgroup program.
 *
 * BPF_F_ALLOW_MULTI: If a sub-cgroup installs some bpf program,
 * that cgroup program gets run in addition to the program in this cgroup.
 *
 * Only one program is allowed to be attached to a cgroup with
 * NONE or BPF_F_ALLOW_OVERRIDE flag.
 * Attaching another program on top of NONE or BPF_F_ALLOW_OVERRIDE will
 * release old program and attach the new one. Attach flags has to match.
 *
 * Multiple programs are allowed to be attached to a cgroup with
 * BPF_F_ALLOW_MULTI flag. They are executed in FIFO order
 * (those that were attached first, run first)
 * The programs of sub-cgroup are executed first, then programs of
 * this cgroup and then programs of parent cgroup.
 * When children program makes decision (like picking TCP CA or sock bind)
 * parent program has a chance to override it.
 *
 * With BPF_F_ALLOW_MULTI a new program is added to the end of the list of
 * programs for a cgroup. Though it's possible to replace an old program at
 * any position by also specifying BPF_F_REPLACE flag and position itself in
 * replace_bpf_fd attribute. Old program at this position will be released.
 *
 * A cgroup with MULTI or OVERRIDE flag allows any attach flags in sub-cgroups.
 * A cgroup with NONE doesn't allow any programs in sub-cgroups.
 * Ex1:
 * cgrp1 (MULTI progs A, B) ->
 *    cgrp2 (OVERRIDE prog C) ->
 *      cgrp3 (MULTI prog D) ->
 *        cgrp4 (OVERRIDE prog E) ->
 *          cgrp5 (NONE prog F)
 * the event in cgrp5 triggers execution of F,D,A,B in that order.
 * if prog F is detached, the execution is E,D,A,B
 * if prog F and D are detached, the execution is E,A,B
 * if prog F, E and D are detached, the execution is C,A,B
 *
 * All eligible programs are executed regardless of return code from
 * earlier programs.
 */
#define BPF_F_ALLOW_OVERRIDE	(1U << 0)
#define BPF_F_ALLOW_MULTI	(1U << 1)
#define BPF_F_REPLACE		(1U << 2)

/* If BPF_F_STRICT_ALIGNMENT is used in BPF_PROG_LOAD command, the
 * verifier will perform strict alignment checking as if the kernel
 * has been built with CONFIG_EFFICIENT_UNALIGNED_ACCESS not set,
 * and NET_IP_ALIGN defined to 2.
 */
#define BPF_F_STRICT_ALIGNMENT	(1U << 0)

/* If BPF_F_ANY_ALIGNMENT is used in BPF_PROF_LOAD command, the
 * verifier will allow any alignment whatsoever.  On platforms
 * with strict alignment requirements for loads ands stores (such
 * as sparc and mips) the verifier validates that all loads and
 * stores provably follow this requirement.  This flag turns that
 * checking and enforcement off.
 *
 * It is mostly used for testing when we want to validate the
 * context and memory access aspects of the verifier, but because
 * of an unaligned access the alignment check would trigger before
 * the one we are interested in.
 */
#define BPF_F_ANY_ALIGNMENT	(1U << 1)

/* BPF_F_TEST_RND_HI32 is used in BPF_PROG_LOAD command for testing purpose.
 * Verifier does sub-register def/use analysis and identifies instructions whose
 * def only matters for low 32-bit, high 32-bit is never referenced later
 * through implicit zero extension. Therefore verifier notifies JIT back-ends
 * that it is safe to ignore clearing high 32-bit for these instructions. This
 * saves some back-ends a lot of code-gen. However such optimization is not
 * necessary on some arches, for example x86_64, arm64 etc, whose JIT back-ends
 * hence hasn't used verifier's analysis result. But, we really want to have a
 * way to be able to verify the correctness of the described optimization on
 * x86_64 on which testsuites are frequently exercised.
 *
 * So, this flag is introduced. Once it is set, verifier will randomize high
 * 32-bit for those instructions who has been identified as safe to ignore them.
 * Then, if verifier is not doing correct analysis, such randomization will
 * regress tests to expose bugs.
 */
#define BPF_F_TEST_RND_HI32	(1U << 2)

/* The verifier internal test flag. Behavior is undefined */
#define BPF_F_TEST_STATE_FREQ	(1U << 3)

/* When BPF ldimm64's insn[0].src_reg != 0 then this can have
 * two extensions:
 *
 * insn[0].src_reg:  BPF_PSEUDO_MAP_FD   BPF_PSEUDO_MAP_VALUE
 * insn[0].imm:      map fd              map fd
 * insn[1].imm:      0                   offset into value
 * insn[0].off:      0                   0
 * insn[1].off:      0                   0
 * ldimm64 rewrite:  address of map      address of map[0]+offset
 * verifier type:    CONST_PTR_TO_MAP    PTR_TO_MAP_VALUE
 */
#define BPF_PSEUDO_MAP_FD	1
#define BPF_PSEUDO_MAP_VALUE	2

/* when bpf_call->src_reg == BPF_PSEUDO_CALL, bpf_call->imm == pc-relative
 * offset to another bpf function
 */
#define BPF_PSEUDO_CALL		1

/* flags for BPF_MAP_UPDATE_ELEM command */
enum {
	BPF_ANY		= 0, /* create new element or update existing */
	BPF_NOEXIST	= 1, /* create new element if it didn't exist */
	BPF_EXIST	= 2, /* update existing element */
	BPF_F_LOCK	= 4, /* spin_lock-ed map_lookup/map_update */
};

/* flags for BPF_MAP_CREATE command */
enum {
	BPF_F_NO_PREALLOC	= (1U << 0),
/* Instead of having one common LRU list in the
 * BPF_MAP_TYPE_LRU_[PERCPU_]HASH map, use a percpu LRU list
 * which can scale and perform better.
 * Note, the LRU nodes (including free nodes) cannot be moved
 * across different LRU lists.
 */
	BPF_F_NO_COMMON_LRU	= (1U << 1),
/* Specify numa node during map creation */
	BPF_F_NUMA_NODE		= (1U << 2),

/* Flags for accessing BPF object from syscall side. */
	BPF_F_RDONLY		= (1U << 3),
	BPF_F_WRONLY		= (1U << 4),

/* Flag for stack_map, store build_id+offset instead of pointer */
	BPF_F_STACK_BUILD_ID	= (1U << 5),

/* Zero-initialize hash function seed. This should only be used for testing. */
	BPF_F_ZERO_SEED		= (1U << 6),

/* Flags for accessing BPF object from program side. */
	BPF_F_RDONLY_PROG	= (1U << 7),
	BPF_F_WRONLY_PROG	= (1U << 8),

/* Clone map from listener for newly accepted socket */
	BPF_F_CLONE		= (1U << 9),

/* Enable memory-mapping BPF map */
	BPF_F_MMAPABLE		= (1U << 10),
};

/* Flags for BPF_PROG_QUERY. */

/* Query effective (directly attached + inherited from ancestor cgroups)
 * programs that will be executed for events within a cgroup.
 * attach_flags with this flag are returned only for directly attached programs.
 */
#define BPF_F_QUERY_EFFECTIVE	(1U << 0)

/* type for BPF_ENABLE_STATS */
enum bpf_stats_type {
	/* enabled run_time_ns and run_cnt */
	BPF_STATS_RUN_TIME = 0,
};

enum bpf_stack_build_id_status {
	/* user space need an empty entry to identify end of a trace */
	BPF_STACK_BUILD_ID_EMPTY = 0,
	/* with valid build_id and offset */
	BPF_STACK_BUILD_ID_VALID = 1,
	/* couldn't get build_id, fallback to ip */
	BPF_STACK_BUILD_ID_IP = 2,
};

#define BPF_BUILD_ID_SIZE 20
struct bpf_stack_build_id {
	__s32		status;
	unsigned char	build_id[BPF_BUILD_ID_SIZE];
	union {
		__u64	offset;
		__u64	ip;
	};
};

#define BPF_OBJ_NAME_LEN 16U

union bpf_attr {
	struct { /* anonymous struct used by BPF_MAP_CREATE command */
		__u32	map_type;	/* one of enum bpf_map_type */
		__u32	key_size;	/* size of key in bytes */
		__u32	value_size;	/* size of value in bytes */
		__u32	max_entries;	/* max number of entries in a map */
		__u32	map_flags;	/* BPF_MAP_CREATE related
					 * flags defined above.
					 */
		__u32	inner_map_fd;	/* fd pointing to the inner map */
		__u32	numa_node;	/* numa node (effective only if
					 * BPF_F_NUMA_NODE is set).
					 */
		char	map_name[BPF_OBJ_NAME_LEN];
		__u32	map_ifindex;	/* ifindex of netdev to create on */
		__u32	btf_fd;		/* fd pointing to a BTF type data */
		__u32	btf_key_type_id;	/* BTF type_id of the key */
		__u32	btf_value_type_id;	/* BTF type_id of the value */
		__u32	btf_vmlinux_value_type_id;/* BTF type_id of a kernel-
						   * struct stored as the
						   * map value
						   */
	};

	struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
		__u32		map_fd;
		__aligned_u64	key;
		union {
			__aligned_u64 value;
			__aligned_u64 next_key;
		};
		__u64		flags;
	};

	struct { /* struct used by BPF_MAP_*_BATCH commands */
		__aligned_u64	in_batch;	/* start batch,
						 * NULL to start from beginning
						 */
		__aligned_u64	out_batch;	/* output: next start batch */
		__aligned_u64	keys;
		__aligned_u64	values;
		__u32		count;		/* input/output:
						 * input: # of key/value
						 * elements
						 * output: # of filled elements
						 */
		__u32		map_fd;
		__u64		elem_flags;
		__u64		flags;
	} batch;

	struct { /* anonymous struct used by BPF_PROG_LOAD command */
		__u32		prog_type;	/* one of enum bpf_prog_type */
		__u32		insn_cnt;
		__aligned_u64	insns;
		__aligned_u64	license;
		__u32		log_level;	/* verbosity level of verifier */
		__u32		log_size;	/* size of user buffer */
		__aligned_u64	log_buf;	/* user supplied buffer */
		__u32		kern_version;	/* not used */
		__u32		prog_flags;
		char		prog_name[BPF_OBJ_NAME_LEN];
		__u32		prog_ifindex;	/* ifindex of netdev to prep for */
		/* For some prog types expected attach type must be known at
		 * load time to verify attach type specific parts of prog
		 * (context accesses, allowed helpers, etc).
		 */
		__u32		expected_attach_type;
		__u32		prog_btf_fd;	/* fd pointing to BTF type data */
		__u32		func_info_rec_size;	/* userspace bpf_func_info size */
		__aligned_u64	func_info;	/* func info */
		__u32		func_info_cnt;	/* number of bpf_func_info records */
		__u32		line_info_rec_size;	/* userspace bpf_line_info size */
		__aligned_u64	line_info;	/* line info */
		__u32		line_info_cnt;	/* number of bpf_line_info records */
		__u32		attach_btf_id;	/* in-kernel BTF type id to attach to */
		__u32		attach_prog_fd; /* 0 to attach to vmlinux */
	};

	struct { /* anonymous struct used by BPF_OBJ_* commands */
		__aligned_u64	pathname;
		__u32		bpf_fd;
		__u32		file_flags;
	};

	struct { /* anonymous struct used by BPF_PROG_ATTACH/DETACH commands */
		__u32		target_fd;	/* container object to attach to */
		__u32		attach_bpf_fd;	/* eBPF program to attach */
		__u32		attach_type;
		__u32		attach_flags;
		__u32		replace_bpf_fd;	/* previously attached eBPF
						 * program to replace if
						 * BPF_F_REPLACE is used
						 */
	};

	struct { /* anonymous struct used by BPF_PROG_TEST_RUN command */
		__u32		prog_fd;
		__u32		retval;
		__u32		data_size_in;	/* input: len of data_in */
		__u32		data_size_out;	/* input/output: len of data_out
						 *   returns ENOSPC if data_out
						 *   is too small.
						 */
		__aligned_u64	data_in;
		__aligned_u64	data_out;
		__u32		repeat;
		__u32		duration;
		__u32		ctx_size_in;	/* input: len of ctx_in */
		__u32		ctx_size_out;	/* input/output: len of ctx_out
						 *   returns ENOSPC if ctx_out
						 *   is too small.
						 */
		__aligned_u64	ctx_in;
		__aligned_u64	ctx_out;
	} test;

	struct { /* anonymous struct used by BPF_*_GET_*_ID */
		union {
			__u32		start_id;
			__u32		prog_id;
			__u32		map_id;
			__u32		btf_id;
			__u32		link_id;
		};
		__u32		next_id;
		__u32		open_flags;
	};

	struct { /* anonymous struct used by BPF_OBJ_GET_INFO_BY_FD */
		__u32		bpf_fd;
		__u32		info_len;
		__aligned_u64	info;
	} info;

	struct { /* anonymous struct used by BPF_PROG_QUERY command */
		__u32		target_fd;	/* container object to query */
		__u32		attach_type;
		__u32		query_flags;
		__u32		attach_flags;
		__aligned_u64	prog_ids;
		__u32		prog_cnt;
	} query;

	struct { /* anonymous struct used by BPF_RAW_TRACEPOINT_OPEN command */
		__u64 name;
		__u32 prog_fd;
	} raw_tracepoint;

	struct { /* anonymous struct for BPF_BTF_LOAD */
		__aligned_u64	btf;
		__aligned_u64	btf_log_buf;
		__u32		btf_size;
		__u32		btf_log_size;
		__u32		btf_log_level;
	};

	struct {
		__u32		pid;		/* input: pid */
		__u32		fd;		/* input: fd */
		__u32		flags;		/* input: flags */
		__u32		buf_len;	/* input/output: buf len */
		__aligned_u64	buf;		/* input/output:
						 *   tp_name for tracepoint
						 *   symbol for kprobe
						 *   filename for uprobe
						 */
		__u32		prog_id;	/* output: prod_id */
		__u32		fd_type;	/* output: BPF_FD_TYPE_* */
		__u64		probe_offset;	/* output: probe_offset */
		__u64		probe_addr;	/* output: probe_addr */
	} task_fd_query;

	struct { /* struct used by BPF_LINK_CREATE command */
		__u32		prog_fd;	/* eBPF program to attach */
		__u32		target_fd;	/* object to attach to */
		__u32		attach_type;	/* attach type */
		__u32		flags;		/* extra flags */
	} link_create;

	struct { /* struct used by BPF_LINK_UPDATE command */
		__u32		link_fd;	/* link fd */
		/* new program fd to update link with */
		__u32		new_prog_fd;
		__u32		flags;		/* extra flags */
		/* expected link's program fd; is specified only if
		 * BPF_F_REPLACE flag is set in flags */
		__u32		old_prog_fd;
	} link_update;

	struct { /* struct used by BPF_ENABLE_STATS command */
		__u32		type;
	} enable_stats;

	struct { /* struct used by BPF_ITER_CREATE command */
		__u32		link_fd;
		__u32		flags;
	} iter_create;

} __attribute__((aligned(8)));

#define __BPF_FUNC_MAPPER(FN)		\
	FN(unspec),			\
	FN(map_lookup_elem),		\
	FN(map_update_elem),		\
	FN(map_delete_elem),		\
	FN(probe_read),			\
	FN(ktime_get_ns),		\
	FN(trace_printk),		\
	FN(get_prandom_u32),		\
	FN(get_smp_processor_id),	\
	FN(skb_store_bytes),		\
	FN(l3_csum_replace),		\
	FN(l4_csum_replace),		\
	FN(tail_call),			\
	FN(clone_redirect),		\
	FN(get_current_pid_tgid),	\
	FN(get_current_uid_gid),	\
	FN(get_current_comm),		\
	FN(get_cgroup_classid),		\
	FN(skb_vlan_push),		\
	FN(skb_vlan_pop),		\
	FN(skb_get_tunnel_key),		\
	FN(skb_set_tunnel_key),		\
	FN(perf_event_read),		\
	FN(redirect),			\
	FN(get_route_realm),		\
	FN(perf_event_output),		\
	FN(skb_load_bytes),		\
	FN(get_stackid),		\
	FN(csum_diff),			\
	FN(skb_get_tunnel_opt),		\
	FN(skb_set_tunnel_opt),		\
	FN(skb_change_proto),		\
	FN(skb_change_type),		\
	FN(skb_under_cgroup),		\
	FN(get_hash_recalc),		\
	FN(get_current_task),		\
	FN(probe_write_user),		\
	FN(current_task_under_cgroup),	\
	FN(skb_change_tail),		\
	FN(skb_pull_data),		\
	FN(csum_update),		\
	FN(set_hash_invalid),		\
	FN(get_numa_node_id),		\
	FN(skb_change_head),		\
	FN(xdp_adjust_head),		\
	FN(probe_read_str),		\
	FN(get_socket_cookie),		\
	FN(get_socket_uid),		\
	FN(set_hash),			\
	FN(setsockopt),			\
	FN(skb_adjust_room),		\
	FN(redirect_map),		\
	FN(sk_redirect_map),		\
	FN(sock_map_update),		\
	FN(xdp_adjust_meta),		\
	FN(perf_event_read_value),	\
	FN(perf_prog_read_value),	\
	FN(getsockopt),			\
	FN(override_return),		\
	FN(sock_ops_cb_flags_set),	\
	FN(msg_redirect_map),		\
	FN(msg_apply_bytes),		\
	FN(msg_cork_bytes),		\
	FN(msg_pull_data),		\
	FN(bind),			\
	FN(xdp_adjust_tail),		\
	FN(skb_get_xfrm_state),		\
	FN(get_stack),			\
	FN(skb_load_bytes_relative),	\
	FN(fib_lookup),			\
	FN(sock_hash_update),		\
	FN(msg_redirect_hash),		\
	FN(sk_redirect_hash),		\
	FN(lwt_push_encap),		\
	FN(lwt_seg6_store_bytes),	\
	FN(lwt_seg6_adjust_srh),	\
	FN(lwt_seg6_action),		\
	FN(rc_repeat),			\
	FN(rc_keydown),			\
	FN(skb_cgroup_id),		\
	FN(get_current_cgroup_id),	\
	FN(get_local_storage),		\
	FN(sk_select_reuseport),	\
	FN(skb_ancestor_cgroup_id),	\
	FN(sk_lookup_tcp),		\
	FN(sk_lookup_udp),		\
	FN(sk_release),			\
	FN(map_push_elem),		\
	FN(map_pop_elem),		\
	FN(map_peek_elem),		\
	FN(msg_push_data),		\
	FN(msg_pop_data),		\
	FN(rc_pointer_rel),		\
	FN(spin_lock),			\
	FN(spin_unlock),		\
	FN(sk_fullsock),		\
	FN(tcp_sock),			\
	FN(skb_ecn_set_ce),		\
	FN(get_listener_sock),		\
	FN(skc_lookup_tcp),		\
	FN(tcp_check_syncookie),	\
	FN(sysctl_get_name),		\
	FN(sysctl_get_current_value),	\
	FN(sysctl_get_new_value),	\
	FN(sysctl_set_new_value),	\
	FN(strtol),			\
	FN(strtoul),			\
	FN(sk_storage_get),		\
	FN(sk_storage_delete),		\
	FN(send_signal),		\
	FN(tcp_gen_syncookie),		\
	FN(skb_output),			\
	FN(probe_read_user),		\
	FN(probe_read_kernel),		\
	FN(probe_read_user_str),	\
	FN(probe_read_kernel_str),	\
	FN(tcp_send_ack),		\
	FN(send_signal_thread),		\
	FN(jiffies64),			\
	FN(read_branch_records),	\
	FN(get_ns_current_pid_tgid),	\
	FN(xdp_output),			\
	FN(get_netns_cookie),		\
	FN(get_current_ancestor_cgroup_id),	\
	FN(sk_assign),			\
	FN(ktime_get_boot_ns),		\
	FN(seq_printf),			\
	FN(seq_write),			\
	FN(sk_cgroup_id),		\
	FN(sk_ancestor_cgroup_id),	\
	FN(ringbuf_output),		\
	FN(ringbuf_reserve),		\
	FN(ringbuf_submit),		\
	FN(ringbuf_discard),		\
	FN(ringbuf_query),		\
	FN(csum_level),			\
	FN(skc_to_tcp6_sock),		\
	FN(skc_to_tcp_sock),		\
	FN(skc_to_tcp_timewait_sock),	\
	FN(skc_to_tcp_request_sock),	\
	FN(skc_to_udp6_sock),		\
	FN(get_task_stack),		\
	/* */

/* integer value in 'imm' field of BPF_CALL instruction selects which helper
 * function eBPF program intends to call
 */
#define __BPF_ENUM_FN(x) BPF_FUNC_ ## x
enum bpf_func_id {
	__BPF_FUNC_MAPPER(__BPF_ENUM_FN)
	__BPF_FUNC_MAX_ID,
};
#undef __BPF_ENUM_FN

/* All flags used by eBPF helper functions, placed here. */

/* BPF_FUNC_skb_store_bytes flags. */
enum {
	BPF_F_RECOMPUTE_CSUM		= (1ULL << 0),
	BPF_F_INVALIDATE_HASH		= (1ULL << 1),
};

/* BPF_FUNC_l3_csum_replace and BPF_FUNC_l4_csum_replace flags.
 * First 4 bits are for passing the header field size.
 */
enum {
	BPF_F_HDR_FIELD_MASK		= 0xfULL,
};

/* BPF_FUNC_l4_csum_replace flags. */
enum {
	BPF_F_PSEUDO_HDR		= (1ULL << 4),
	BPF_F_MARK_MANGLED_0		= (1ULL << 5),
	BPF_F_MARK_ENFORCE		= (1ULL << 6),
};

/* BPF_FUNC_clone_redirect and BPF_FUNC_redirect flags. */
enum {
	BPF_F_INGRESS			= (1ULL << 0),
};

/* BPF_FUNC_skb_set_tunnel_key and BPF_FUNC_skb_get_tunnel_key flags. */
enum {
	BPF_F_TUNINFO_IPV6		= (1ULL << 0),
};

/* flags for both BPF_FUNC_get_stackid and BPF_FUNC_get_stack. */
enum {
	BPF_F_SKIP_FIELD_MASK		= 0xffULL,
	BPF_F_USER_STACK		= (1ULL << 8),
/* flags used by BPF_FUNC_get_stackid only. */
	BPF_F_FAST_STACK_CMP		= (1ULL << 9),
	BPF_F_REUSE_STACKID		= (1ULL << 10),
/* flags used by BPF_FUNC_get_stack only. */
	BPF_F_USER_BUILD_ID		= (1ULL << 11),
};

/* BPF_FUNC_skb_set_tunnel_key flags. */
enum {
	BPF_F_ZERO_CSUM_TX		= (1ULL << 1),
	BPF_F_DONT_FRAGMENT		= (1ULL << 2),
	BPF_F_SEQ_NUMBER		= (1ULL << 3),
};

/* BPF_FUNC_perf_event_output, BPF_FUNC_perf_event_read and
 * BPF_FUNC_perf_event_read_value flags.
 */
enum {
	BPF_F_INDEX_MASK		= 0xffffffffULL,
	BPF_F_CURRENT_CPU		= BPF_F_INDEX_MASK,
/* BPF_FUNC_perf_event_output for sk_buff input context. */
	BPF_F_CTXLEN_MASK		= (0xfffffULL << 32),
};

/* Current network namespace */
enum {
	BPF_F_CURRENT_NETNS		= (-1L),
};

/* BPF_FUNC_csum_level level values. */
enum {
	BPF_CSUM_LEVEL_QUERY,
	BPF_CSUM_LEVEL_INC,
	BPF_CSUM_LEVEL_DEC,
	BPF_CSUM_LEVEL_RESET,
};

/* BPF_FUNC_skb_adjust_room flags. */
enum {
	BPF_F_ADJ_ROOM_FIXED_GSO	= (1ULL << 0),
	BPF_F_ADJ_ROOM_ENCAP_L3_IPV4	= (1ULL << 1),
	BPF_F_ADJ_ROOM_ENCAP_L3_IPV6	= (1ULL << 2),
	BPF_F_ADJ_ROOM_ENCAP_L4_GRE	= (1ULL << 3),
	BPF_F_ADJ_ROOM_ENCAP_L4_UDP	= (1ULL << 4),
	BPF_F_ADJ_ROOM_NO_CSUM_RESET	= (1ULL << 5),
};

enum {
	BPF_ADJ_ROOM_ENCAP_L2_MASK	= 0xff,
	BPF_ADJ_ROOM_ENCAP_L2_SHIFT	= 56,
};

#define BPF_F_ADJ_ROOM_ENCAP_L2(len)	(((__u64)len & \
					  BPF_ADJ_ROOM_ENCAP_L2_MASK) \
					 << BPF_ADJ_ROOM_ENCAP_L2_SHIFT)

/* BPF_FUNC_sysctl_get_name flags. */
enum {
	BPF_F_SYSCTL_BASE_NAME		= (1ULL << 0),
};

/* BPF_FUNC_sk_storage_get flags */
enum {
	BPF_SK_STORAGE_GET_F_CREATE	= (1ULL << 0),
};

/* BPF_FUNC_read_branch_records flags. */
enum {
	BPF_F_GET_BRANCH_RECORDS_SIZE	= (1ULL << 0),
};

/* BPF_FUNC_bpf_ringbuf_commit, BPF_FUNC_bpf_ringbuf_discard, and
 * BPF_FUNC_bpf_ringbuf_output flags.
 */
enum {
	BPF_RB_NO_WAKEUP		= (1ULL << 0),
	BPF_RB_FORCE_WAKEUP		= (1ULL << 1),
};

/* BPF_FUNC_bpf_ringbuf_query flags */
enum {
	BPF_RB_AVAIL_DATA = 0,
	BPF_RB_RING_SIZE = 1,
	BPF_RB_CONS_POS = 2,
	BPF_RB_PROD_POS = 3,
};

/* BPF ring buffer constants */
enum {
	BPF_RINGBUF_BUSY_BIT		= (1U << 31),
	BPF_RINGBUF_DISCARD_BIT		= (1U << 30),
	BPF_RINGBUF_HDR_SZ		= 8,
};

/* BPF_FUNC_sk_assign flags in bpf_sk_lookup context. */
enum {
	BPF_SK_LOOKUP_F_REPLACE		= (1ULL << 0),
	BPF_SK_LOOKUP_F_NO_REUSEPORT	= (1ULL << 1),
};

/* Mode for BPF_FUNC_skb_adjust_room helper. */
enum bpf_adj_room_mode {
	BPF_ADJ_ROOM_NET,
	BPF_ADJ_ROOM_MAC,
};

/* Mode for BPF_FUNC_skb_load_bytes_relative helper. */
enum bpf_hdr_start_off {
	BPF_HDR_START_MAC,
	BPF_HDR_START_NET,
};

/* Encapsulation type for BPF_FUNC_lwt_push_encap helper. */
enum bpf_lwt_encap_mode {
	BPF_LWT_ENCAP_SEG6,
	BPF_LWT_ENCAP_SEG6_INLINE,
	BPF_LWT_ENCAP_IP,
};

#define __bpf_md_ptr(type, name)	\
union {					\
	type name;			\
	__u64 :64;			\
} __attribute__((aligned(8)))

/* user accessible mirror of in-kernel sk_buff.
 * new fields can only be added to the end of this structure
 */
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;

	/* Accessed by BPF_PROG_TYPE_sk_skb types from here to ... */
	__u32 family;
	__u32 remote_ip4;	/* Stored in network byte order */
	__u32 local_ip4;	/* Stored in network byte order */
	__u32 remote_ip6[4];	/* Stored in network byte order */
	__u32 local_ip6[4];	/* Stored in network byte order */
	__u32 remote_port;	/* Stored in network byte order */
	__u32 local_port;	/* stored in host byte order */
	/* ... here. */

	__u32 data_meta;
	__bpf_md_ptr(struct bpf_flow_keys *, flow_keys);
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
	__bpf_md_ptr(struct bpf_sock *, sk);
	__u32 gso_size;
};

struct bpf_tunnel_key {
	__u32 tunnel_id;
	union {
		__u32 remote_ipv4;
		__u32 remote_ipv6[4];
	};
	__u8 tunnel_tos;
	__u8 tunnel_ttl;
	__u16 tunnel_ext;	/* Padding, future use. */
	__u32 tunnel_label;
};

/* user accessible mirror of in-kernel xfrm_state.
 * new fields can only be added to the end of this structure
 */
struct bpf_xfrm_state {
	__u32 reqid;
	__u32 spi;	/* Stored in network byte order */
	__u16 family;
	__u16 ext;	/* Padding, future use. */
	union {
		__u32 remote_ipv4;	/* Stored in network byte order */
		__u32 remote_ipv6[4];	/* Stored in network byte order */
	};
};

/* Generic BPF return codes which all BPF program types may support.
 * The values are binary compatible with their TC_ACT_* counter-part to
 * provide backwards compatibility with existing SCHED_CLS and SCHED_ACT
 * programs.
 *
 * XDP is handled seprately, see XDP_*.
 */
enum bpf_ret_code {
	BPF_OK = 0,
	/* 1 reserved */
	BPF_DROP = 2,
	/* 3-6 reserved */
	BPF_REDIRECT = 7,
	/* >127 are reserved for prog type specific return codes.
	 *
	 * BPF_LWT_REROUTE: used by BPF_PROG_TYPE_LWT_IN and
	 *    BPF_PROG_TYPE_LWT_XMIT to indicate that skb had been
	 *    changed and should be routed based on its new L3 header.
	 *    (This is an L3 redirect, as opposed to L2 redirect
	 *    represented by BPF_REDIRECT above).
	 */
	BPF_LWT_REROUTE = 128,
};

struct bpf_sock {
	__u32 bound_dev_if;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 mark;
	__u32 priority;
	/* IP address also allows 1 and 2 bytes access */
	__u32 src_ip4;
	__u32 src_ip6[4];
	__u32 src_port;		/* host byte order */
	__u32 dst_port;		/* network byte order */
	__u32 dst_ip4;
	__u32 dst_ip6[4];
	__u32 state;
	__s32 rx_queue_mapping;
};

struct bpf_tcp_sock {
	__u32 snd_cwnd;		/* Sending congestion window		*/
	__u32 srtt_us;		/* smoothed round trip time << 3 in usecs */
	__u32 rtt_min;
	__u32 snd_ssthresh;	/* Slow start size threshold		*/
	__u32 rcv_nxt;		/* What we want to receive next		*/
	__u32 snd_nxt;		/* Next sequence we send		*/
	__u32 snd_una;		/* First byte we want an ack for	*/
	__u32 mss_cache;	/* Cached effective mss, not including SACKS */
	__u32 ecn_flags;	/* ECN status bits.			*/
	__u32 rate_delivered;	/* saved rate sample: packets delivered */
	__u32 rate_interval_us;	/* saved rate sample: time elapsed */
	__u32 packets_out;	/* Packets which are "in flight"	*/
	__u32 retrans_out;	/* Retransmitted packets out		*/
	__u32 total_retrans;	/* Total retransmits for entire connection */
	__u32 segs_in;		/* RFC4898 tcpEStatsPerfSegsIn
				 * total number of segments in.
				 */
	__u32 data_segs_in;	/* RFC4898 tcpEStatsPerfDataSegsIn
				 * total number of data segments in.
				 */
	__u32 segs_out;		/* RFC4898 tcpEStatsPerfSegsOut
				 * The total number of segments sent.
				 */
	__u32 data_segs_out;	/* RFC4898 tcpEStatsPerfDataSegsOut
				 * total number of data segments sent.
				 */
	__u32 lost_out;		/* Lost packets			*/
	__u32 sacked_out;	/* SACK'd packets			*/
	__u64 bytes_received;	/* RFC4898 tcpEStatsAppHCThruOctetsReceived
				 * sum(delta(rcv_nxt)), or how many bytes
				 * were acked.
				 */
	__u64 bytes_acked;	/* RFC4898 tcpEStatsAppHCThruOctetsAcked
				 * sum(delta(snd_una)), or how many bytes
				 * were acked.
				 */
	__u32 dsack_dups;	/* RFC4898 tcpEStatsStackDSACKDups
				 * total number of DSACK blocks received
				 */
	__u32 delivered;	/* Total data packets delivered incl. rexmits */
	__u32 delivered_ce;	/* Like the above but only ECE marked packets */
	__u32 icsk_retransmits;	/* Number of unrecovered [RTO] timeouts */
};

struct bpf_sock_tuple {
	union {
		struct {
			__be32 saddr;
			__be32 daddr;
			__be16 sport;
			__be16 dport;
		} ipv4;
		struct {
			__be32 saddr[4];
			__be32 daddr[4];
			__be16 sport;
			__be16 dport;
		} ipv6;
	};
};

struct bpf_xdp_sock {
	__u32 queue_id;
};

#define XDP_PACKET_HEADROOM 256

/* User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will
 * result in packet drops and a warning via bpf_warn_invalid_xdp_action().
 */
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

/* user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 */
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	/* Below access go through struct xdp_rxq_info */
	__u32 ingress_ifindex; /* rxq->dev->ifindex */
	__u32 rx_queue_index;  /* rxq->queue_index  */

	__u32 egress_ifindex;  /* txq->dev->ifindex */
};

/* DEVMAP map-value layout
 *
 * The struct data-layout of map-value is a configuration interface.
 * New members can only be added to the end of this structure.
 */
struct bpf_devmap_val {
	__u32 ifindex;   /* device index */
	union {
		int   fd;  /* prog fd on map write */
		__u32 id;  /* prog id on map read */
	} bpf_prog;
};

/* CPUMAP map-value layout
 *
 * The struct data-layout of map-value is a configuration interface.
 * New members can only be added to the end of this structure.
 */
struct bpf_cpumap_val {
	__u32 qsize;	/* queue size to remote target CPU */
	union {
		int   fd;	/* prog fd on map write */
		__u32 id;	/* prog id on map read */
	} bpf_prog;
};

enum sk_action {
	SK_DROP = 0,
	SK_PASS,
};

/* user accessible metadata for SK_MSG packet hook, new fields must
 * be added to the end of this structure
 */
struct sk_msg_md {
	__bpf_md_ptr(void *, data);
	__bpf_md_ptr(void *, data_end);

	__u32 family;
	__u32 remote_ip4;	/* Stored in network byte order */
	__u32 local_ip4;	/* Stored in network byte order */
	__u32 remote_ip6[4];	/* Stored in network byte order */
	__u32 local_ip6[4];	/* Stored in network byte order */
	__u32 remote_port;	/* Stored in network byte order */
	__u32 local_port;	/* stored in host byte order */
	__u32 size;		/* Total size of sk_msg */

	__bpf_md_ptr(struct bpf_sock *, sk); /* current socket */
};

struct sk_reuseport_md {
	/*
	 * Start of directly accessible data. It begins from
	 * the tcp/udp header.
	 */
	__bpf_md_ptr(void *, data);
	/* End of directly accessible data */
	__bpf_md_ptr(void *, data_end);
	/*
	 * Total length of packet (starting from the tcp/udp header).
	 * Note that the directly accessible bytes (data_end - data)
	 * could be less than this "len".  Those bytes could be
	 * indirectly read by a helper "bpf_skb_load_bytes()".
	 */
	__u32 len;
	/*
	 * Eth protocol in the mac header (network byte order). e.g.
	 * ETH_P_IP(0x0800) and ETH_P_IPV6(0x86DD)
	 */
	__u32 eth_protocol;
	__u32 ip_protocol;	/* IP protocol. e.g. IPPROTO_TCP, IPPROTO_UDP */
	__u32 bind_inany;	/* Is sock bound to an INANY address? */
	__u32 hash;		/* A hash of the packet 4 tuples */
};

#define BPF_TAG_SIZE	8

struct bpf_prog_info {
	__u32 type;
	__u32 id;
	__u8  tag[BPF_TAG_SIZE];
	__u32 jited_prog_len;
	__u32 xlated_prog_len;
	__aligned_u64 jited_prog_insns;
	__aligned_u64 xlated_prog_insns;
	__u64 load_time;	/* ns since boottime */
	__u32 created_by_uid;
	__u32 nr_map_ids;
	__aligned_u64 map_ids;
	char name[BPF_OBJ_NAME_LEN];
	__u32 ifindex;
	__u32 gpl_compatible:1;
	__u32 :31; /* alignment pad */
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 nr_jited_ksyms;
	__u32 nr_jited_func_lens;
	__aligned_u64 jited_ksyms;
	__aligned_u64 jited_func_lens;
	__u32 btf_id;
	__u32 func_info_rec_size;
	__aligned_u64 func_info;
	__u32 nr_func_info;
	__u32 nr_line_info;
	__aligned_u64 line_info;
	__aligned_u64 jited_line_info;
	__u32 nr_jited_line_info;
	__u32 line_info_rec_size;
	__u32 jited_line_info_rec_size;
	__u32 nr_prog_tags;
	__aligned_u64 prog_tags;
	__u64 run_time_ns;
	__u64 run_cnt;
} __attribute__((aligned(8)));

struct bpf_map_info {
	__u32 type;
	__u32 id;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	char  name[BPF_OBJ_NAME_LEN];
	__u32 ifindex;
	__u32 btf_vmlinux_value_type_id;
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 btf_id;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
} __attribute__((aligned(8)));

struct bpf_btf_info {
	__aligned_u64 btf;
	__u32 btf_size;
	__u32 id;
} __attribute__((aligned(8)));

struct bpf_link_info {
	__u32 type;
	__u32 id;
	__u32 prog_id;
	union {
		struct {
			__aligned_u64 tp_name; /* in/out: tp_name buffer ptr */
			__u32 tp_name_len;     /* in/out: tp_name buffer len */
		} raw_tracepoint;
		struct {
			__u32 attach_type;
		} tracing;
		struct {
			__u64 cgroup_id;
			__u32 attach_type;
		} cgroup;
		struct  {
			__u32 netns_ino;
			__u32 attach_type;
		} netns;
	};
} __attribute__((aligned(8)));

/* User bpf_sock_addr struct to access socket fields and sockaddr struct passed
 * by user and intended to be used by socket (e.g. to bind to, depends on
 * attach type).
 */
struct bpf_sock_addr {
	__u32 user_family;	/* Allows 4-byte read, but no write. */
	__u32 user_ip4;		/* Allows 1,2,4-byte read and 4-byte write.
				 * Stored in network byte order.
				 */
	__u32 user_ip6[4];	/* Allows 1,2,4,8-byte read and 4,8-byte write.
				 * Stored in network byte order.
				 */
	__u32 user_port;	/* Allows 1,2,4-byte read and 4-byte write.
				 * Stored in network byte order
				 */
	__u32 family;		/* Allows 4-byte read, but no write */
	__u32 type;		/* Allows 4-byte read, but no write */
	__u32 protocol;		/* Allows 4-byte read, but no write */
	__u32 msg_src_ip4;	/* Allows 1,2,4-byte read and 4-byte write.
				 * Stored in network byte order.
				 */
	__u32 msg_src_ip6[4];	/* Allows 1,2,4,8-byte read and 4,8-byte write.
				 * Stored in network byte order.
				 */
	__bpf_md_ptr(struct bpf_sock *, sk);
};

/* User bpf_sock_ops struct to access socket values and specify request ops
 * and their replies.
 * Some of this fields are in network (bigendian) byte order and may need
 * to be converted before use (bpf_ntohl() defined in samples/bpf/bpf_endian.h).
 * New fields can only be added at the end of this structure
 */
struct bpf_sock_ops {
	__u32 op;
	union {
		__u32 args[4];		/* Optionally passed to bpf program */
		__u32 reply;		/* Returned by bpf program	    */
		__u32 replylong[4];	/* Optionally returned by bpf prog  */
	};
	__u32 family;
	__u32 remote_ip4;	/* Stored in network byte order */
	__u32 local_ip4;	/* Stored in network byte order */
	__u32 remote_ip6[4];	/* Stored in network byte order */
	__u32 local_ip6[4];	/* Stored in network byte order */
	__u32 remote_port;	/* Stored in network byte order */
	__u32 local_port;	/* stored in host byte order */
	__u32 is_fullsock;	/* Some TCP fields are only valid if
				 * there is a full socket. If not, the
				 * fields read as zero.
				 */
	__u32 snd_cwnd;
	__u32 srtt_us;		/* Averaged RTT << 3 in usecs */
	__u32 bpf_sock_ops_cb_flags; /* flags defined in uapi/linux/tcp.h */
	__u32 state;
	__u32 rtt_min;
	__u32 snd_ssthresh;
	__u32 rcv_nxt;
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 mss_cache;
	__u32 ecn_flags;
	__u32 rate_delivered;
	__u32 rate_interval_us;
	__u32 packets_out;
	__u32 retrans_out;
	__u32 total_retrans;
	__u32 segs_in;
	__u32 data_segs_in;
	__u32 segs_out;
	__u32 data_segs_out;
	__u32 lost_out;
	__u32 sacked_out;
	__u32 sk_txhash;
	__u64 bytes_received;
	__u64 bytes_acked;
	__bpf_md_ptr(struct bpf_sock *, sk);
};

/* Definitions for bpf_sock_ops_cb_flags */
enum {
	BPF_SOCK_OPS_RTO_CB_FLAG	= (1<<0),
	BPF_SOCK_OPS_RETRANS_CB_FLAG	= (1<<1),
	BPF_SOCK_OPS_STATE_CB_FLAG	= (1<<2),
	BPF_SOCK_OPS_RTT_CB_FLAG	= (1<<3),
/* Mask of all currently supported cb flags */
	BPF_SOCK_OPS_ALL_CB_FLAGS       = 0xF,
};

/* List of known BPF sock_ops operators.
 * New entries can only be added at the end
 */
enum {
	BPF_SOCK_OPS_VOID,
	BPF_SOCK_OPS_TIMEOUT_INIT,	/* Should return SYN-RTO value to use or
					 * -1 if default value should be used
					 */
	BPF_SOCK_OPS_RWND_INIT,		/* Should return initial advertized
					 * window (in packets) or -1 if default
					 * value should be used
					 */
	BPF_SOCK_OPS_TCP_CONNECT_CB,	/* Calls BPF program right before an
					 * active connection is initialized
					 */
	BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,	/* Calls BPF program when an
						 * active connection is
						 * established
						 */
	BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,	/* Calls BPF program when a
						 * passive connection is
						 * established
						 */
	BPF_SOCK_OPS_NEEDS_ECN,		/* If connection's congestion control
					 * needs ECN
					 */
	BPF_SOCK_OPS_BASE_RTT,		/* Get base RTT. The correct value is
					 * based on the path and may be
					 * dependent on the congestion control
					 * algorithm. In general it indicates
					 * a congestion threshold. RTTs above
					 * this indicate congestion
					 */
	BPF_SOCK_OPS_RTO_CB,		/* Called when an RTO has triggered.
					 * Arg1: value of icsk_retransmits
					 * Arg2: value of icsk_rto
					 * Arg3: whether RTO has expired
					 */
	BPF_SOCK_OPS_RETRANS_CB,	/* Called when skb is retransmitted.
					 * Arg1: sequence number of 1st byte
					 * Arg2: # segments
					 * Arg3: return value of
					 *       tcp_transmit_skb (0 => success)
					 */
	BPF_SOCK_OPS_STATE_CB,		/* Called when TCP changes state.
					 * Arg1: old_state
					 * Arg2: new_state
					 */
	BPF_SOCK_OPS_TCP_LISTEN_CB,	/* Called on listen(2), right after
					 * socket transition to LISTEN state.
					 */
	BPF_SOCK_OPS_RTT_CB,		/* Called on every RTT.
					 */
};

/* List of TCP states. There is a build check in net/ipv4/tcp.c to detect
 * changes between the TCP and BPF versions. Ideally this should never happen.
 * If it does, we need to add code to convert them before calling
 * the BPF sock_ops function.
 */
enum {
	BPF_TCP_ESTABLISHED = 1,
	BPF_TCP_SYN_SENT,
	BPF_TCP_SYN_RECV,
	BPF_TCP_FIN_WAIT1,
	BPF_TCP_FIN_WAIT2,
	BPF_TCP_TIME_WAIT,
	BPF_TCP_CLOSE,
	BPF_TCP_CLOSE_WAIT,
	BPF_TCP_LAST_ACK,
	BPF_TCP_LISTEN,
	BPF_TCP_CLOSING,	/* Now a valid state */
	BPF_TCP_NEW_SYN_RECV,

	BPF_TCP_MAX_STATES	/* Leave at the end! */
};

enum {
	TCP_BPF_IW		= 1001,	/* Set TCP initial congestion window */
	TCP_BPF_SNDCWND_CLAMP	= 1002,	/* Set sndcwnd_clamp */
};

struct bpf_perf_event_value {
	__u64 counter;
	__u64 enabled;
	__u64 running;
};

enum {
	BPF_DEVCG_ACC_MKNOD	= (1ULL << 0),
	BPF_DEVCG_ACC_READ	= (1ULL << 1),
	BPF_DEVCG_ACC_WRITE	= (1ULL << 2),
};

enum {
	BPF_DEVCG_DEV_BLOCK	= (1ULL << 0),
	BPF_DEVCG_DEV_CHAR	= (1ULL << 1),
};

struct bpf_cgroup_dev_ctx {
	/* access_type encoded as (BPF_DEVCG_ACC_* << 16) | BPF_DEVCG_DEV_* */
	__u32 access_type;
	__u32 major;
	__u32 minor;
};

struct bpf_raw_tracepoint_args {
	__u64 args[0];
};

/* DIRECT:  Skip the FIB rules and go to FIB table associated with device
 * OUTPUT:  Do lookup from egress perspective; default is ingress
 */
enum {
	BPF_FIB_LOOKUP_DIRECT  = (1U << 0),
	BPF_FIB_LOOKUP_OUTPUT  = (1U << 1),
};

enum {
	BPF_FIB_LKUP_RET_SUCCESS,      /* lookup successful */
	BPF_FIB_LKUP_RET_BLACKHOLE,    /* dest is blackholed; can be dropped */
	BPF_FIB_LKUP_RET_UNREACHABLE,  /* dest is unreachable; can be dropped */
	BPF_FIB_LKUP_RET_PROHIBIT,     /* dest not allowed; can be dropped */
	BPF_FIB_LKUP_RET_NOT_FWDED,    /* packet is not forwarded */
	BPF_FIB_LKUP_RET_FWD_DISABLED, /* fwding is not enabled on ingress */
	BPF_FIB_LKUP_RET_UNSUPP_LWT,   /* fwd requires encapsulation */
	BPF_FIB_LKUP_RET_NO_NEIGH,     /* no neighbor entry for nh */
	BPF_FIB_LKUP_RET_FRAG_NEEDED,  /* fragmentation required to fwd */
};

struct bpf_fib_lookup {
	/* input:  network family for lookup (AF_INET, AF_INET6)
	 * output: network family of egress nexthop
	 */
	__u8	family;

	/* set if lookup is to consider L4 data - e.g., FIB rules */
	__u8	l4_protocol;
	__be16	sport;
	__be16	dport;

	/* total length of packet from network header - used for MTU check */
	__u16	tot_len;

	/* input: L3 device index for lookup
	 * output: device index from FIB lookup
	 */
	__u32	ifindex;

	union {
		/* inputs to lookup */
		__u8	tos;		/* AF_INET  */
		__be32	flowinfo;	/* AF_INET6, flow_label + priority */

		/* output: metric of fib result (IPv4/IPv6 only) */
		__u32	rt_metric;
	};

	union {
		__be32		ipv4_src;
		__u32		ipv6_src[4];  /* in6_addr; network order */
	};

	/* input to bpf_fib_lookup, ipv{4,6}_dst is destination address in
	 * network header. output: bpf_fib_lookup sets to gateway address
	 * if FIB lookup returns gateway route
	 */
	union {
		__be32		ipv4_dst;
		__u32		ipv6_dst[4];  /* in6_addr; network order */
	};

	/* output */
	__be16	h_vlan_proto;
	__be16	h_vlan_TCI;
	__u8	smac[6];     /* ETH_ALEN */
	__u8	dmac[6];     /* ETH_ALEN */
};

enum bpf_task_fd_type {
	BPF_FD_TYPE_RAW_TRACEPOINT,	/* tp name */
	BPF_FD_TYPE_TRACEPOINT,		/* tp name */
	BPF_FD_TYPE_KPROBE,		/* (symbol + offset) or addr */
	BPF_FD_TYPE_KRETPROBE,		/* (symbol + offset) or addr */
	BPF_FD_TYPE_UPROBE,		/* filename + offset */
	BPF_FD_TYPE_URETPROBE,		/* filename + offset */
};

enum {
	BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG		= (1U << 0),
	BPF_FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL		= (1U << 1),
	BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP		= (1U << 2),
};

struct bpf_flow_keys {
	__u16	nhoff;
	__u16	thoff;
	__u16	addr_proto;			/* ETH_P_* of valid addrs */
	__u8	is_frag;
	__u8	is_first_frag;
	__u8	is_encap;
	__u8	ip_proto;
	__be16	n_proto;
	__be16	sport;
	__be16	dport;
	union {
		struct {
			__be32	ipv4_src;
			__be32	ipv4_dst;
		};
		struct {
			__u32	ipv6_src[4];	/* in6_addr; network order */
			__u32	ipv6_dst[4];	/* in6_addr; network order */
		};
	};
	__u32	flags;
	__be32	flow_label;
};

struct bpf_func_info {
	__u32	insn_off;
	__u32	type_id;
};

#define BPF_LINE_INFO_LINE_NUM(line_col)	((line_col) >> 10)
#define BPF_LINE_INFO_LINE_COL(line_col)	((line_col) & 0x3ff)

struct bpf_line_info {
	__u32	insn_off;
	__u32	file_name_off;
	__u32	line_off;
	__u32	line_col;
};

struct bpf_spin_lock {
	__u32	val;
};

struct bpf_sysctl {
	__u32	write;		/* Sysctl is being read (= 0) or written (= 1).
				 * Allows 1,2,4-byte read, but no write.
				 */
	__u32	file_pos;	/* Sysctl file position to read from, write to.
				 * Allows 1,2,4-byte read an 4-byte write.
				 */
};

struct bpf_sockopt {
	__bpf_md_ptr(struct bpf_sock *, sk);
	__bpf_md_ptr(void *, optval);
	__bpf_md_ptr(void *, optval_end);

	__s32	level;
	__s32	optname;
	__s32	optlen;
	__s32	retval;
};

struct bpf_pidns_info {
	__u32 pid;
	__u32 tgid;
};

/* User accessible data for SK_LOOKUP programs. Add new fields at the end. */
struct bpf_sk_lookup {
	__bpf_md_ptr(struct bpf_sock *, sk); /* Selected socket */

	__u32 family;		/* Protocol family (AF_INET, AF_INET6) */
	__u32 protocol;		/* IP protocol (IPPROTO_TCP, IPPROTO_UDP) */
	__u32 remote_ip4;	/* Network byte order */
	__u32 remote_ip6[4];	/* Network byte order */
	__u32 remote_port;	/* Network byte order */
	__u32 local_ip4;	/* Network byte order */
	__u32 local_ip6[4];	/* Network byte order */
	__u32 local_port;	/* Host byte order */
};

struct bpf_verifier_env;
struct bpf_verifier_log;
struct perf_event;
struct bpf_prog;
struct bpf_prog_aux;
struct bpf_map;
struct sock;
struct seq_file;
struct btf;
struct btf_type;
struct exception_table_entry;
struct seq_operations;

extern struct idr btf_idr;

int map_check_no_btf(const struct bpf_map *map,
		     const struct btf *btf,
		     const struct btf_type *key_type,
		     const struct btf_type *value_type);

extern const struct bpf_map_ops bpf_map_offload_ops;

/* function argument constraints */
enum bpf_arg_type {
	ARG_DONTCARE = 0,	/* unused argument in helper function */

	/* the following constraints used to prototype
	 * bpf_map_lookup/update/delete_elem() functions
	 */
	ARG_CONST_MAP_PTR,	/* const argument used as pointer to bpf_map */
	ARG_PTR_TO_MAP_KEY,	/* pointer to stack used as map key */
	ARG_PTR_TO_MAP_VALUE,	/* pointer to stack used as map value */
	ARG_PTR_TO_UNINIT_MAP_VALUE,	/* pointer to valid memory used to store a map value */
	ARG_PTR_TO_MAP_VALUE_OR_NULL,	/* pointer to stack used as map value or NULL */

	/* the following constraints used to prototype bpf_memcmp() and other
	 * functions that access data on eBPF program stack
	 */
	ARG_PTR_TO_MEM,		/* pointer to valid memory (stack, packet, map value) */
	ARG_PTR_TO_MEM_OR_NULL, /* pointer to valid memory or NULL */
	ARG_PTR_TO_UNINIT_MEM,	/* pointer to memory does not need to be initialized,
				 * helper function must fill all bytes or clear
				 * them in error case.
				 */

	ARG_CONST_SIZE,		/* number of bytes accessed from memory */
	ARG_CONST_SIZE_OR_ZERO,	/* number of bytes accessed from memory or 0 */

	ARG_PTR_TO_CTX,		/* pointer to context */
	ARG_PTR_TO_CTX_OR_NULL,	/* pointer to context or NULL */
	ARG_ANYTHING,		/* any (initialized) argument is ok */
	ARG_PTR_TO_SPIN_LOCK,	/* pointer to bpf_spin_lock */
	ARG_PTR_TO_SOCK_COMMON,	/* pointer to sock_common */
	ARG_PTR_TO_INT,		/* pointer to int */
	ARG_PTR_TO_LONG,	/* pointer to long */
	ARG_PTR_TO_SOCKET,	/* pointer to bpf_sock (fullsock) */
	ARG_PTR_TO_SOCKET_OR_NULL,	/* pointer to bpf_sock (fullsock) or NULL */
	ARG_PTR_TO_BTF_ID,	/* pointer to in-kernel struct */
	ARG_PTR_TO_ALLOC_MEM,	/* pointer to dynamically allocated memory */
	ARG_PTR_TO_ALLOC_MEM_OR_NULL,	/* pointer to dynamically allocated memory or NULL */
	ARG_CONST_ALLOC_SIZE_OR_ZERO,	/* number of allocated bytes requested */
};

/* type of values returned from helper functions */
enum bpf_return_type {
	RET_INTEGER,			/* function returns integer */
	RET_VOID,			/* function doesn't return anything */
	RET_PTR_TO_MAP_VALUE,		/* returns a pointer to map elem value */
	RET_PTR_TO_MAP_VALUE_OR_NULL,	/* returns a pointer to map elem value or NULL */
	RET_PTR_TO_SOCKET_OR_NULL,	/* returns a pointer to a socket or NULL */
	RET_PTR_TO_TCP_SOCK_OR_NULL,	/* returns a pointer to a tcp_sock or NULL */
	RET_PTR_TO_SOCK_COMMON_OR_NULL,	/* returns a pointer to a sock_common or NULL */
	RET_PTR_TO_ALLOC_MEM_OR_NULL,	/* returns a pointer to dynamically allocated memory or NULL */
	RET_PTR_TO_BTF_ID_OR_NULL,	/* returns a pointer to a btf_id or NULL */
};

/* eBPF function prototype used by verifier to allow BPF_CALLs from eBPF programs
 * to in-kernel helper functions and for adjusting imm32 field in BPF_CALL
 * instructions after verifying
 */
struct bpf_func_proto {
	u64 (*func)(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
	bool gpl_only;
	bool pkt_access;
	enum bpf_return_type ret_type;
	union {
		struct {
			enum bpf_arg_type arg1_type;
			enum bpf_arg_type arg2_type;
			enum bpf_arg_type arg3_type;
			enum bpf_arg_type arg4_type;
			enum bpf_arg_type arg5_type;
		};
		enum bpf_arg_type arg_type[5];
	};
	int *btf_id; /* BTF ids of arguments */
	bool (*check_btf_id)(u32 btf_id, u32 arg); /* if the argument btf_id is
						    * valid. Often used if more
						    * than one btf id is permitted
						    * for this argument.
						    */
	int *ret_btf_id; /* return value btf_id */
};

/* bpf_context is intentionally undefined structure. Pointer to bpf_context is
 * the first argument to eBPF programs.
 * For socket filters: 'struct bpf_context *' == 'struct sk_buff *'
 */
struct bpf_context;

enum bpf_access_type {
	BPF_READ = 1,
	BPF_WRITE = 2
};

/* types of values stored in eBPF registers */
/* Pointer types represent:
 * pointer
 * pointer + imm
 * pointer + (u16) var
 * pointer + (u16) var + imm
 * if (range > 0) then [ptr, ptr + range - off) is safe to access
 * if (id > 0) means that some 'var' was added
 * if (off > 0) means that 'imm' was added
 */
enum bpf_reg_type {
	NOT_INIT = 0,		 /* nothing was written into register */
	SCALAR_VALUE,		 /* reg doesn't contain a valid pointer */
	PTR_TO_CTX,		 /* reg points to bpf_context */
	CONST_PTR_TO_MAP,	 /* reg points to struct bpf_map */
	PTR_TO_MAP_VALUE,	 /* reg points to map element value */
	PTR_TO_MAP_VALUE_OR_NULL,/* points to map elem value or NULL */
	PTR_TO_STACK,		 /* reg == frame_pointer + offset */
	PTR_TO_PACKET_META,	 /* skb->data - meta_len */
	PTR_TO_PACKET,		 /* reg points to skb->data */
	PTR_TO_PACKET_END,	 /* skb->data + headlen */
	PTR_TO_FLOW_KEYS,	 /* reg points to bpf_flow_keys */
	PTR_TO_SOCKET,		 /* reg points to struct bpf_sock */
	PTR_TO_SOCKET_OR_NULL,	 /* reg points to struct bpf_sock or NULL */
	PTR_TO_SOCK_COMMON,	 /* reg points to sock_common */
	PTR_TO_SOCK_COMMON_OR_NULL, /* reg points to sock_common or NULL */
	PTR_TO_TCP_SOCK,	 /* reg points to struct tcp_sock */
	PTR_TO_TCP_SOCK_OR_NULL, /* reg points to struct tcp_sock or NULL */
	PTR_TO_TP_BUFFER,	 /* reg points to a writable raw tp's buffer */
	PTR_TO_XDP_SOCK,	 /* reg points to struct xdp_sock */
	PTR_TO_BTF_ID,		 /* reg points to kernel struct */
	PTR_TO_BTF_ID_OR_NULL,	 /* reg points to kernel struct or NULL */
	PTR_TO_MEM,		 /* reg points to valid memory region */
	PTR_TO_MEM_OR_NULL,	 /* reg points to valid memory region or NULL */
};

/* The information passed from prog-specific *_is_valid_access
 * back to the verifier.
 */
struct bpf_insn_access_aux {
	enum bpf_reg_type reg_type;
	union {
		int ctx_field_size;
		u32 btf_id;
	};
	struct bpf_verifier_log *log; /* for verbose logs */
};

static inline void
bpf_ctx_record_field_size(struct bpf_insn_access_aux *aux, u32 size)
{
	aux->ctx_field_size = size;
}

struct bpf_prog_ops {
	int (*test_run)(struct bpf_prog *prog, const union bpf_attr *kattr,
			union bpf_attr *uattr);
};

struct bpf_verifier_ops {
	/* return eBPF function prototype for verification */
	const struct bpf_func_proto *
	(*get_func_proto)(enum bpf_func_id func_id,
			  const struct bpf_prog *prog);

	/* return true if 'size' wide access at offset 'off' within bpf_context
	 * with 'type' (read or write) is allowed
	 */
	bool (*is_valid_access)(int off, int size, enum bpf_access_type type,
				const struct bpf_prog *prog,
				struct bpf_insn_access_aux *info);
	int (*gen_prologue)(struct bpf_insn *insn, bool direct_write,
			    const struct bpf_prog *prog);
	int (*gen_ld_abs)(const struct bpf_insn *orig,
			  struct bpf_insn *insn_buf);
	u32 (*convert_ctx_access)(enum bpf_access_type type,
				  const struct bpf_insn *src,
				  struct bpf_insn *dst,
				  struct bpf_prog *prog, u32 *target_size);
	int (*btf_struct_access)(struct bpf_verifier_log *log,
				 const struct btf_type *t, int off, int size,
				 enum bpf_access_type atype,
				 u32 *next_btf_id);
};

struct bpf_prog_offload_ops {
	/* verifier basic callbacks */
	int (*insn_hook)(struct bpf_verifier_env *env,
			 int insn_idx, int prev_insn_idx);
	int (*finalize)(struct bpf_verifier_env *env);
	/* verifier optimization callbacks (called after .finalize) */
	int (*replace_insn)(struct bpf_verifier_env *env, u32 off,
			    struct bpf_insn *insn);
	int (*remove_insns)(struct bpf_verifier_env *env, u32 off, u32 cnt);
	/* program management callbacks */
	int (*prepare)(struct bpf_prog *prog);
	int (*translate)(struct bpf_prog *prog);
	void (*destroy)(struct bpf_prog *prog);
};

enum bpf_cgroup_storage_type {
	BPF_CGROUP_STORAGE_SHARED,
	BPF_CGROUP_STORAGE_PERCPU,
	__BPF_CGROUP_STORAGE_MAX
};

#define MAX_BPF_CGROUP_STORAGE_TYPE __BPF_CGROUP_STORAGE_MAX

/* The longest tracepoint has 12 args.
 * See include/trace/bpf_probe.h
 */
#define MAX_BPF_FUNC_ARGS 12

struct btf_func_model {
	u8 ret_size;
	u8 nr_args;
	u8 arg_size[MAX_BPF_FUNC_ARGS];
};

/* Restore arguments before returning from trampoline to let original function
 * continue executing. This flag is used for fentry progs when there are no
 * fexit progs.
 */
#define BPF_TRAMP_F_RESTORE_REGS	BIT(0)
/* Call original function after fentry progs, but before fexit progs.
 * Makes sense for fentry/fexit, normal calls and indirect calls.
 */
#define BPF_TRAMP_F_CALL_ORIG		BIT(1)
/* Skip current frame and return to parent.  Makes sense for fentry/fexit
 * programs only. Should not be used with normal calls and indirect calls.
 */
#define BPF_TRAMP_F_SKIP_FRAME		BIT(2)

/* Each call __bpf_prog_enter + call bpf_func + call __bpf_prog_exit is ~50
 * bytes on x86.  Pick a number to fit into BPF_IMAGE_SIZE / 2
 */
#define BPF_MAX_TRAMP_PROGS 40

struct bpf_tramp_progs {
	struct bpf_prog *progs[BPF_MAX_TRAMP_PROGS];
	int nr_progs;
};

#define BPF_DISPATCHER_MAX 48 /* Fits in 2048B */

static __always_inline unsigned int bpf_dispatcher_nop_func(
	const void *ctx,
	const struct bpf_insn *insnsi,
	unsigned int (*bpf_func)(const void *,
				 const struct bpf_insn *))
{
	return bpf_func(ctx, insnsi);
}
#ifdef CONFIG_BPF_JIT
struct bpf_trampoline *bpf_trampoline_lookup(u64 key);
int bpf_trampoline_link_prog(struct bpf_prog *prog);
int bpf_trampoline_unlink_prog(struct bpf_prog *prog);
void bpf_trampoline_put(struct bpf_trampoline *tr);
#define BPF_DISPATCHER_INIT(_name) {				\
	.mutex = __MUTEX_INITIALIZER(_name.mutex),		\
	.func = &_name##_func,					\
	.progs = {},						\
	.num_progs = 0,						\
	.image = NULL,						\
	.image_off = 0,						\
	.ksym = {						\
		.name  = #_name,				\
		.lnode = LIST_HEAD_INIT(_name.ksym.lnode),	\
	},							\
}

#define DEFINE_BPF_DISPATCHER(name)					\
	noinline unsigned int bpf_dispatcher_##name##_func(		\
		const void *ctx,					\
		const struct bpf_insn *insnsi,				\
		unsigned int (*bpf_func)(const void *,			\
					 const struct bpf_insn *))	\
	{								\
		return bpf_func(ctx, insnsi);				\
	}								\
	EXPORT_SYMBOL(bpf_dispatcher_##name##_func);			\
	struct bpf_dispatcher bpf_dispatcher_##name =			\
		BPF_DISPATCHER_INIT(bpf_dispatcher_##name);
#define DECLARE_BPF_DISPATCHER(name)					\
	unsigned int bpf_dispatcher_##name##_func(			\
		const void *ctx,					\
		const struct bpf_insn *insnsi,				\
		unsigned int (*bpf_func)(const void *,			\
					 const struct bpf_insn *));	\
	extern struct bpf_dispatcher bpf_dispatcher_##name;
#define BPF_DISPATCHER_FUNC(name) bpf_dispatcher_##name##_func
#define BPF_DISPATCHER_PTR(name) (&bpf_dispatcher_##name)
#else

static inline void bpf_trampoline_put(struct bpf_trampoline *tr) {}
#define DEFINE_BPF_DISPATCHER(name)
#define DECLARE_BPF_DISPATCHER(name)
#define BPF_DISPATCHER_FUNC(name) bpf_dispatcher_nop_func
#define BPF_DISPATCHER_PTR(name) NULL
static inline void bpf_dispatcher_change_prog(struct bpf_dispatcher *d,
					      struct bpf_prog *from,
					      struct bpf_prog *to) {}
static inline bool is_bpf_image_address(unsigned long address)
{
	return false;
}
#endif

struct bpf_func_info_aux {
	u16 linkage;
	bool unreliable;
};

enum bpf_jit_poke_reason {
	BPF_POKE_REASON_TAIL_CALL,
};

/* Descriptor of pokes pointing /into/ the JITed image. */
struct bpf_jit_poke_descriptor {
	void *ip;
	union {
		struct {
			struct bpf_map *map;
			u32 key;
		} tail_call;
	};
	bool ip_stable;
	u8 adj_off;
	u16 reason;
};

/* reg_type info for ctx arguments */
struct bpf_ctx_arg_aux {
	u32 offset;
	enum bpf_reg_type reg_type;
	u32 btf_id;
};

struct bpf_struct_ops_value;
struct btf_type;
struct btf_member;

#define BPF_STRUCT_OPS_MAX_NR_MEMBERS 64
struct bpf_struct_ops {
	const struct bpf_verifier_ops *verifier_ops;
	int (*init)(struct btf *btf);
	int (*check_member)(const struct btf_type *t,
			    const struct btf_member *member);
	int (*init_member)(const struct btf_type *t,
			   const struct btf_member *member,
			   void *kdata, const void *udata);
	int (*reg)(void *kdata);
	void (*unreg)(void *kdata);
	const struct btf_type *type;
	const struct btf_type *value_type;
	const char *name;
	struct btf_func_model func_models[BPF_STRUCT_OPS_MAX_NR_MEMBERS];
	u32 type_id;
	u32 value_id;
};

#if defined(CONFIG_BPF_JIT) && defined(CONFIG_BPF_SYSCALL)
#define BPF_MODULE_OWNER ((void *)((0xeB9FUL << 2) + POISON_POINTER_DELTA))
const struct bpf_struct_ops *bpf_struct_ops_find(u32 type_id);
void bpf_struct_ops_init(struct btf *btf, struct bpf_verifier_log *log);
bool bpf_struct_ops_get(const void *kdata);
void bpf_struct_ops_put(const void *kdata);
int bpf_struct_ops_map_sys_lookup_elem(struct bpf_map *map, void *key,
				       void *value);
static inline bool bpf_try_module_get(const void *data, struct module *owner)
{
	if (owner == BPF_MODULE_OWNER)
		return bpf_struct_ops_get(data);
	else
		return try_module_get(owner);
}
static inline void bpf_module_put(const void *data, struct module *owner)
{
	if (owner == BPF_MODULE_OWNER)
		bpf_struct_ops_put(data);
	else
		module_put(owner);
}
#else
static inline const struct bpf_struct_ops *bpf_struct_ops_find(u32 type_id)
{
	return NULL;
}
static inline void bpf_struct_ops_init(struct btf *btf,
				       struct bpf_verifier_log *log)
{
}
#endif

#define BPF_COMPLEXITY_LIMIT_INSNS      1000000 /* yes. 1M insns */
#define MAX_TAIL_CALL_CNT 32

#define BPF_F_ACCESS_MASK	(BPF_F_RDONLY |		\
				 BPF_F_RDONLY_PROG |	\
				 BPF_F_WRONLY |		\
				 BPF_F_WRONLY_PROG)

#define BPF_MAP_CAN_READ	BIT(0)
#define BPF_MAP_CAN_WRITE	BIT(1)

static inline bool bpf_map_flags_access_ok(u32 access_flags)
{
	return (access_flags & (BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG)) !=
	       (BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG);
}

int bpf_prog_calc_tag(struct bpf_prog *fp);
const char *kernel_type_name(u32 btf_type_id);

const struct bpf_func_proto *bpf_get_trace_printk_proto(void);

typedef unsigned long (*bpf_ctx_copy_t)(void *dst, const void *src,
					unsigned long off, unsigned long len);
typedef u32 (*bpf_convert_ctx_access_t)(enum bpf_access_type type,
					const struct bpf_insn *src,
					struct bpf_insn *dst,
					struct bpf_prog *prog,
					u32 *target_size);

u64 bpf_event_output(struct bpf_map *map, u64 flags, void *meta, u64 meta_size,
		     void *ctx, u64 ctx_size, bpf_ctx_copy_t ctx_copy);

/* To be used by __cgroup_bpf_run_filter_skb for EGRESS BPF progs
 * so BPF programs can request cwr for TCP packets.
 *
 * Current cgroup skb programs can only return 0 or 1 (0 to drop the
 * packet. This macro changes the behavior so the low order bit
 * indicates whether the packet should be dropped (0) or not (1)
 * and the next bit is a congestion notification bit. This could be
 * used by TCP to call tcp_enter_cwr()
 *
 * Hence, new allowed return values of CGROUP EGRESS BPF programs are:
 *   0: drop packet
 *   1: keep packet
 *   2: drop packet and cn
 *   3: keep packet and cn
 *
 * This macro then converts it to one of the NET_XMIT or an error
 * code that is then interpreted as drop packet (and no cn):
 *   0: NET_XMIT_SUCCESS  skb should be transmitted
 *   1: NET_XMIT_DROP     skb should be dropped and cn
 *   2: NET_XMIT_CN       skb should be transmitted and cn
 *   3: -EPERM            skb should be dropped
 */
#define BPF_PROG_CGROUP_INET_EGRESS_RUN_ARRAY(array, ctx, func)		\
	({						\
		struct bpf_prog_array_item *_item;	\
		struct bpf_prog *_prog;			\
		struct bpf_prog_array *_array;		\
		u32 ret;				\
		u32 _ret = 1;				\
		u32 _cn = 0;				\
		migrate_disable();			\
		rcu_read_lock();			\
		_array = rcu_dereference(array);	\
		_item = &_array->items[0];		\
		while ((_prog = READ_ONCE(_item->prog))) {		\
			bpf_cgroup_storage_set(_item->cgroup_storage);	\
			ret = func(_prog, ctx);		\
			_ret &= (ret & 1);		\
			_cn |= (ret & 2);		\
			_item++;			\
		}					\
		rcu_read_unlock();			\
		migrate_enable();			\
		if (_ret)				\
			_ret = (_cn ? NET_XMIT_CN : NET_XMIT_SUCCESS);	\
		else					\
			_ret = (_cn ? NET_XMIT_DROP : -EPERM);		\
		_ret;					\
	})

#define BPF_PROG_RUN_ARRAY(array, ctx, func)		\
	__BPF_PROG_RUN_ARRAY(array, ctx, func, false)

#define BPF_PROG_RUN_ARRAY_CHECK(array, ctx, func)	\
	__BPF_PROG_RUN_ARRAY(array, ctx, func, true)

#ifdef CONFIG_BPF_SYSCALL
DECLARE_PER_CPU(int, bpf_prog_active);
extern struct mutex bpf_stats_enabled_mutex;

/*
 * Block execution of BPF programs attached to instrumentation (perf,
 * kprobes, tracepoints) to prevent deadlocks on map operations as any of
 * these events can happen inside a region which holds a map bucket lock
 * and can deadlock on it.
 *
 * Use the preemption safe inc/dec variants on RT because migrate disable
 * is preemptible on RT and preemption in the middle of the RMW operation
 * might lead to inconsistent state. Use the raw variants for non RT
 * kernels as migrate_disable() maps to preempt_disable() so the slightly
 * more expensive save operation can be avoided.
 */
static inline void bpf_disable_instrumentation(void)
{
	migrate_disable();
	if (IS_ENABLED(CONFIG_PREEMPT_RT))
		this_cpu_inc(bpf_prog_active);
	else
		__this_cpu_inc(bpf_prog_active);
}

static inline void bpf_enable_instrumentation(void)
{
	if (IS_ENABLED(CONFIG_PREEMPT_RT))
		this_cpu_dec(bpf_prog_active);
	else
		__this_cpu_dec(bpf_prog_active);
	migrate_enable();
}

extern const struct file_operations bpf_map_fops;
extern const struct file_operations bpf_prog_fops;
extern const struct file_operations bpf_iter_fops;

#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) \
	extern const struct bpf_prog_ops _name ## _prog_ops; \
	extern const struct bpf_verifier_ops _name ## _verifier_ops;
#define BPF_MAP_TYPE(_id, _ops) \
	extern const struct bpf_map_ops _ops;
#define BPF_LINK_TYPE(_id, _name)
#include <linux/bpf_types.h>
#undef BPF_PROG_TYPE
#undef BPF_MAP_TYPE
#undef BPF_LINK_TYPE

extern const struct bpf_prog_ops bpf_offload_prog_ops;
extern const struct bpf_verifier_ops tc_cls_act_analyzer_ops;
extern const struct bpf_verifier_ops xdp_analyzer_ops;

struct bpf_prog *bpf_prog_get(u32 ufd);
struct bpf_prog *bpf_prog_get_type_dev(u32 ufd, enum bpf_prog_type type,
				       bool attach_drv);
void bpf_prog_add(struct bpf_prog *prog, int i);
void bpf_prog_sub(struct bpf_prog *prog, int i);
void bpf_prog_inc(struct bpf_prog *prog);
struct bpf_prog * __must_check bpf_prog_inc_not_zero(struct bpf_prog *prog);
void bpf_prog_put(struct bpf_prog *prog);
int __bpf_prog_charge(struct user_struct *user, u32 pages);
void __bpf_prog_uncharge(struct user_struct *user, u32 pages);
void __bpf_free_used_maps(struct bpf_prog_aux *aux,
			  struct bpf_map **used_maps, u32 len);

void bpf_prog_free_id(struct bpf_prog *prog, bool do_idr_lock);
void bpf_map_free_id(struct bpf_map *map, bool do_idr_lock);

struct bpf_map *bpf_map_get(u32 ufd);
struct bpf_map *bpf_map_get_with_uref(u32 ufd);
struct bpf_map *__bpf_map_get(struct fd f);
void bpf_map_inc(struct bpf_map *map);
void bpf_map_inc_with_uref(struct bpf_map *map);
struct bpf_map * __must_check bpf_map_inc_not_zero(struct bpf_map *map);
void bpf_map_put_with_uref(struct bpf_map *map);
void bpf_map_put(struct bpf_map *map);
int bpf_map_charge_memlock(struct bpf_map *map, u32 pages);
void bpf_map_uncharge_memlock(struct bpf_map *map, u32 pages);
int bpf_map_charge_init(struct bpf_map_memory *mem, u64 size);
void bpf_map_charge_finish(struct bpf_map_memory *mem);
void bpf_map_charge_move(struct bpf_map_memory *dst,
			 struct bpf_map_memory *src);
void *bpf_map_area_alloc(u64 size, int numa_node);
void *bpf_map_area_mmapable_alloc(u64 size, int numa_node);
void bpf_map_area_free(void *base);
void bpf_map_init_from_attr(struct bpf_map *map, union bpf_attr *attr);
int  generic_map_lookup_batch(struct bpf_map *map,
			      const union bpf_attr *attr,
			      union bpf_attr __user *uattr);
int  generic_map_update_batch(struct bpf_map *map,
			      const union bpf_attr *attr,
			      union bpf_attr __user *uattr);
int  generic_map_delete_batch(struct bpf_map *map,
			      const union bpf_attr *attr,
			      union bpf_attr __user *uattr);
struct bpf_map *bpf_map_get_curr_or_next(u32 *id);

extern int sysctl_unprivileged_bpf_disabled;

static inline bool bpf_allow_ptr_leaks(void)
{
	return perfmon_capable();
}

static inline bool bpf_allow_ptr_to_map_access(void)
{
	return perfmon_capable();
}

static inline bool bpf_bypass_spec_v1(void)
{
	return perfmon_capable();
}

static inline bool bpf_bypass_spec_v4(void)
{
	return perfmon_capable();
}

int bpf_map_new_fd(struct bpf_map *map, int flags);
int bpf_prog_new_fd(struct bpf_prog *prog);

struct bpf_link {
	atomic64_t refcnt;
	u32 id;
	enum bpf_link_type type;
	const struct bpf_link_ops *ops;
	struct bpf_prog *prog;
	struct work_struct work;
};

struct bpf_link_primer {
	struct bpf_link *link;
	struct file *file;
	int fd;
	u32 id;
};

struct bpf_link_ops {
	void (*release)(struct bpf_link *link);
	void (*dealloc)(struct bpf_link *link);
	int (*update_prog)(struct bpf_link *link, struct bpf_prog *new_prog,
			   struct bpf_prog *old_prog);
	void (*show_fdinfo)(const struct bpf_link *link, struct seq_file *seq);
	int (*fill_link_info)(const struct bpf_link *link,
			      struct bpf_link_info *info);
};

void bpf_link_init(struct bpf_link *link, enum bpf_link_type type,
		   const struct bpf_link_ops *ops, struct bpf_prog *prog);
int bpf_link_prime(struct bpf_link *link, struct bpf_link_primer *primer);
int bpf_link_settle(struct bpf_link_primer *primer);
void bpf_link_cleanup(struct bpf_link_primer *primer);
void bpf_link_inc(struct bpf_link *link);
void bpf_link_put(struct bpf_link *link);
int bpf_link_new_fd(struct bpf_link *link);
struct file *bpf_link_new_file(struct bpf_link *link, int *reserved_fd);
struct bpf_link *bpf_link_get_from_fd(u32 ufd);

int bpf_obj_pin_user(u32 ufd, const char __user *pathname);
int bpf_obj_get_user(const char __user *pathname, int flags);

#define BPF_ITER_FUNC_PREFIX "bpf_iter_"
#define DEFINE_BPF_ITER_FUNC(target, args...)			\
	extern int bpf_iter_ ## target(args);			\
	int __init bpf_iter_ ## target(args) { return 0; }

typedef int (*bpf_iter_init_seq_priv_t)(void *private_data);
typedef void (*bpf_iter_fini_seq_priv_t)(void *private_data);

#define BPF_ITER_CTX_ARG_MAX 2
struct bpf_iter_reg {
	const char *target;
	const struct seq_operations *seq_ops;
	bpf_iter_init_seq_priv_t init_seq_private;
	bpf_iter_fini_seq_priv_t fini_seq_private;
	u32 seq_priv_size;
	u32 ctx_arg_info_size;
	struct bpf_ctx_arg_aux ctx_arg_info[BPF_ITER_CTX_ARG_MAX];
};

struct bpf_iter_meta {
	__bpf_md_ptr(struct seq_file *, seq);
	u64 session_id;
	u64 seq_num;
};

int bpf_iter_reg_target(const struct bpf_iter_reg *reg_info);
void bpf_iter_unreg_target(const struct bpf_iter_reg *reg_info);
bool bpf_iter_prog_supported(struct bpf_prog *prog);
int bpf_iter_link_attach(const union bpf_attr *attr, struct bpf_prog *prog);
int bpf_iter_new_fd(struct bpf_link *link);
bool bpf_link_is_iter(struct bpf_link *link);
struct bpf_prog *bpf_iter_get_info(struct bpf_iter_meta *meta, bool in_stop);
int bpf_iter_run_prog(struct bpf_prog *prog, void *ctx);

int bpf_percpu_hash_copy(struct bpf_map *map, void *key, void *value);
int bpf_percpu_array_copy(struct bpf_map *map, void *key, void *value);
int bpf_percpu_hash_update(struct bpf_map *map, void *key, void *value,
			   u64 flags);
int bpf_percpu_array_update(struct bpf_map *map, void *key, void *value,
			    u64 flags);

int bpf_stackmap_copy(struct bpf_map *map, void *key, void *value);

int bpf_fd_array_map_update_elem(struct bpf_map *map, struct file *map_file,
				 void *key, void *value, u64 map_flags);
int bpf_fd_array_map_lookup_elem(struct bpf_map *map, void *key, u32 *value);
int bpf_fd_htab_map_update_elem(struct bpf_map *map, struct file *map_file,
				void *key, void *value, u64 map_flags);
int bpf_fd_htab_map_lookup_elem(struct bpf_map *map, void *key, u32 *value);

int bpf_get_file_flag(int flags);
int bpf_check_uarg_tail_zero(void __user *uaddr, size_t expected_size,
			     size_t actual_size);

/* memcpy that is used with 8-byte aligned pointers, power-of-8 size and
 * forced to use 'long' read/writes to try to atomically copy long counters.
 * Best-effort only.  No barriers here, since it _will_ race with concurrent
 * updates from BPF programs. Called from bpf syscall and mostly used with
 * size 8 or 16 bytes, so ask compiler to inline it.
 */
static inline void bpf_long_memcpy(void *dst, const void *src, u32 size)
{
	const long *lsrc = src;
	long *ldst = dst;

	size /= sizeof(long);
	while (size--)
		*ldst++ = *lsrc++;
}

/* verify correctness of eBPF program */
int bpf_check(struct bpf_prog **fp, union bpf_attr *attr,
	      union bpf_attr __user *uattr);
void bpf_patch_call_args(struct bpf_insn *insn, u32 stack_depth);

/* Map specifics */
struct xdp_buff;
struct sk_buff;

struct bpf_dtab_netdev *__dev_map_lookup_elem(struct bpf_map *map, u32 key);
struct bpf_dtab_netdev *__dev_map_hash_lookup_elem(struct bpf_map *map, u32 key);
void __dev_flush(void);
int dev_xdp_enqueue(struct net_device *dev, struct xdp_buff *xdp,
		    struct net_device *dev_rx);
int dev_map_enqueue(struct bpf_dtab_netdev *dst, struct xdp_buff *xdp,
		    struct net_device *dev_rx);
int dev_map_generic_redirect(struct bpf_dtab_netdev *dst, struct sk_buff *skb,
			     struct bpf_prog *xdp_prog);
bool dev_map_can_have_prog(struct bpf_map *map);

struct bpf_cpu_map_entry *__cpu_map_lookup_elem(struct bpf_map *map, u32 key);
void __cpu_map_flush(void);
int cpu_map_enqueue(struct bpf_cpu_map_entry *rcpu, struct xdp_buff *xdp,
		    struct net_device *dev_rx);
bool cpu_map_prog_allowed(struct bpf_map *map);

/* Return map's numa specified by userspace */
static inline int bpf_map_attr_numa_node(const union bpf_attr *attr)
{
	return (attr->map_flags & BPF_F_NUMA_NODE) ?
		attr->numa_node : NUMA_NO_NODE;
}

struct bpf_prog *bpf_prog_get_type_path(const char *name, enum bpf_prog_type type);
int array_map_alloc_check(union bpf_attr *attr);

int bpf_prog_test_run_xdp(struct bpf_prog *prog, const union bpf_attr *kattr,
			  union bpf_attr __user *uattr);
int bpf_prog_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
			  union bpf_attr __user *uattr);
int bpf_prog_test_run_tracing(struct bpf_prog *prog,
			      const union bpf_attr *kattr,
			      union bpf_attr __user *uattr);
int bpf_prog_test_run_flow_dissector(struct bpf_prog *prog,
				     const union bpf_attr *kattr,
				     union bpf_attr __user *uattr);
bool btf_ctx_access(int off, int size, enum bpf_access_type type,
		    const struct bpf_prog *prog,
		    struct bpf_insn_access_aux *info);
int btf_struct_access(struct bpf_verifier_log *log,
		      const struct btf_type *t, int off, int size,
		      enum bpf_access_type atype,
		      u32 *next_btf_id);
int btf_resolve_helper_id(struct bpf_verifier_log *log,
			  const struct bpf_func_proto *fn, int);

int btf_distill_func_proto(struct bpf_verifier_log *log,
			   struct btf *btf,
			   const struct btf_type *func_proto,
			   const char *func_name,
			   struct btf_func_model *m);

struct bpf_reg_state;
int btf_check_func_arg_match(struct bpf_verifier_env *env, int subprog,
			     struct bpf_reg_state *regs);
int btf_prepare_func_args(struct bpf_verifier_env *env, int subprog,
			  struct bpf_reg_state *reg);
int btf_check_type_match(struct bpf_verifier_env *env, struct bpf_prog *prog,
			 struct btf *btf, const struct btf_type *t);

struct bpf_prog *bpf_prog_by_id(u32 id);

const struct bpf_func_proto *bpf_base_func_proto(enum bpf_func_id func_id);
#else /* !CONFIG_BPF_SYSCALL */
static inline struct bpf_prog *bpf_prog_get(u32 ufd)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline struct bpf_prog *bpf_prog_get_type_dev(u32 ufd,
						     enum bpf_prog_type type,
						     bool attach_drv)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void bpf_prog_add(struct bpf_prog *prog, int i)
{
}

static inline void bpf_prog_sub(struct bpf_prog *prog, int i)
{
}

static inline void bpf_prog_put(struct bpf_prog *prog)
{
}

static inline void bpf_prog_inc(struct bpf_prog *prog)
{
}

static inline int bpf_obj_get_user(const char *pathname, int flags)
{
	return -EOPNOTSUPP;
}

static inline struct net_device  *__dev_map_lookup_elem(struct bpf_map *map,
						       u32 key)
{
	return NULL;
}

static inline struct net_device  *__dev_map_hash_lookup_elem(struct bpf_map *map,
							     u32 key)
{
	return NULL;
}
static inline bool dev_map_can_have_prog(struct bpf_map *map)
{
	return false;
}

static inline void __dev_flush(void)
{
}

struct xdp_buff;
struct bpf_dtab_netdev;

static inline
int dev_xdp_enqueue(struct net_device *dev, struct xdp_buff *xdp,
		    struct net_device *dev_rx)
{
	return 0;
}

static inline
int dev_map_enqueue(struct bpf_dtab_netdev *dst, struct xdp_buff *xdp,
		    struct net_device *dev_rx)
{
	return 0;
}

struct sk_buff;

static inline int dev_map_generic_redirect(struct bpf_dtab_netdev *dst,
					   struct sk_buff *skb,
					   struct bpf_prog *xdp_prog)
{
	return 0;
}

static inline
struct bpf_cpu_map_entry *__cpu_map_lookup_elem(struct bpf_map *map, u32 key)
{
	return NULL;
}

static inline void __cpu_map_flush(void)
{
}

static inline int cpu_map_enqueue(struct bpf_cpu_map_entry *rcpu,
				  struct xdp_buff *xdp,
				  struct net_device *dev_rx)
{
	return 0;
}

static inline bool cpu_map_prog_allowed(struct bpf_map *map)
{
	return false;
}

static inline struct bpf_prog *bpf_prog_get_type_path(const char *name,
				enum bpf_prog_type type)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline const struct bpf_func_proto *
bpf_base_func_proto(enum bpf_func_id func_id)
{
	return NULL;
}
#endif /* CONFIG_BPF_SYSCALL */

static inline struct bpf_prog *bpf_prog_get_type(u32 ufd,
						 enum bpf_prog_type type)
{
	return bpf_prog_get_type_dev(ufd, type, false);
}

bool bpf_prog_get_ok(struct bpf_prog *, enum bpf_prog_type *, bool);

int bpf_prog_offload_compile(struct bpf_prog *prog);
void bpf_prog_offload_destroy(struct bpf_prog *prog);
int bpf_prog_offload_info_fill(struct bpf_prog_info *info,
			       struct bpf_prog *prog);

int bpf_map_offload_info_fill(struct bpf_map_info *info, struct bpf_map *map);

int bpf_map_offload_lookup_elem(struct bpf_map *map, void *key, void *value);
int bpf_map_offload_update_elem(struct bpf_map *map,
				void *key, void *value, u64 flags);
int bpf_map_offload_delete_elem(struct bpf_map *map, void *key);
int bpf_map_offload_get_next_key(struct bpf_map *map,
				 void *key, void *next_key);

bool bpf_offload_prog_map_match(struct bpf_prog *prog, struct bpf_map *map);

struct bpf_offload_dev *
bpf_offload_dev_create(const struct bpf_prog_offload_ops *ops, void *priv);
void bpf_offload_dev_destroy(struct bpf_offload_dev *offdev);
void *bpf_offload_dev_priv(struct bpf_offload_dev *offdev);

#if defined(CONFIG_NET) && defined(CONFIG_BPF_SYSCALL)
int bpf_prog_offload_init(struct bpf_prog *prog, union bpf_attr *attr);

static inline bool bpf_prog_is_dev_bound(const struct bpf_prog_aux *aux)
{
	return aux->offload_requested;
}

static inline bool bpf_map_is_dev_bound(struct bpf_map *map)
{
	return unlikely(map->ops == &bpf_map_offload_ops);
}

struct bpf_map *bpf_map_offload_map_alloc(union bpf_attr *attr);
void bpf_map_offload_map_free(struct bpf_map *map);
#else
static inline int bpf_prog_offload_init(struct bpf_prog *prog,
					union bpf_attr *attr)
{
	return -EOPNOTSUPP;
}

static inline bool bpf_prog_is_dev_bound(struct bpf_prog_aux *aux)
{
	return false;
}

static inline bool bpf_map_is_dev_bound(struct bpf_map *map)
{
	return false;
}

static inline struct bpf_map *bpf_map_offload_map_alloc(union bpf_attr *attr)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void bpf_map_offload_map_free(struct bpf_map *map)
{
}
#endif /* CONFIG_NET && CONFIG_BPF_SYSCALL */

#if defined(CONFIG_BPF_STREAM_PARSER)
int sock_map_prog_update(struct bpf_map *map, struct bpf_prog *prog,
			 struct bpf_prog *old, u32 which);
int sock_map_get_from_fd(const union bpf_attr *attr, struct bpf_prog *prog);
int sock_map_prog_detach(const union bpf_attr *attr, enum bpf_prog_type ptype);
void sock_map_unhash(struct sock *sk);
void sock_map_close(struct sock *sk, long timeout);
#else
static inline int sock_map_prog_update(struct bpf_map *map,
				       struct bpf_prog *prog,
				       struct bpf_prog *old, u32 which)
{
	return -EOPNOTSUPP;
}

static inline int sock_map_get_from_fd(const union bpf_attr *attr,
				       struct bpf_prog *prog)
{
	return -EINVAL;
}

static inline int sock_map_prog_detach(const union bpf_attr *attr,
				       enum bpf_prog_type ptype)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_BPF_STREAM_PARSER */

#if defined(CONFIG_INET) && defined(CONFIG_BPF_SYSCALL)
void bpf_sk_reuseport_detach(struct sock *sk);
int bpf_fd_reuseport_array_lookup_elem(struct bpf_map *map, void *key,
				       void *value);
int bpf_fd_reuseport_array_update_elem(struct bpf_map *map, void *key,
				       void *value, u64 map_flags);
#else
static inline void bpf_sk_reuseport_detach(struct sock *sk)
{
}

#ifdef CONFIG_BPF_SYSCALL
static inline int bpf_fd_reuseport_array_lookup_elem(struct bpf_map *map,
						     void *key, void *value)
{
	return -EOPNOTSUPP;
}

static inline int bpf_fd_reuseport_array_update_elem(struct bpf_map *map,
						     void *key, void *value,
						     u64 map_flags)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_BPF_SYSCALL */
#endif /* defined(CONFIG_INET) && defined(CONFIG_BPF_SYSCALL) */

/* verifier prototypes for helper functions called from eBPF programs */
extern const struct bpf_func_proto bpf_map_lookup_elem_proto;
extern const struct bpf_func_proto bpf_map_update_elem_proto;
extern const struct bpf_func_proto bpf_map_delete_elem_proto;
extern const struct bpf_func_proto bpf_map_push_elem_proto;
extern const struct bpf_func_proto bpf_map_pop_elem_proto;
extern const struct bpf_func_proto bpf_map_peek_elem_proto;

extern const struct bpf_func_proto bpf_get_prandom_u32_proto;
extern const struct bpf_func_proto bpf_get_smp_processor_id_proto;
extern const struct bpf_func_proto bpf_get_numa_node_id_proto;
extern const struct bpf_func_proto bpf_tail_call_proto;
extern const struct bpf_func_proto bpf_ktime_get_ns_proto;
extern const struct bpf_func_proto bpf_ktime_get_boot_ns_proto;
extern const struct bpf_func_proto bpf_get_current_pid_tgid_proto;
extern const struct bpf_func_proto bpf_get_current_uid_gid_proto;
extern const struct bpf_func_proto bpf_get_current_comm_proto;
extern const struct bpf_func_proto bpf_get_stackid_proto;
extern const struct bpf_func_proto bpf_get_stack_proto;
extern const struct bpf_func_proto bpf_get_task_stack_proto;
extern const struct bpf_func_proto bpf_sock_map_update_proto;
extern const struct bpf_func_proto bpf_sock_hash_update_proto;
extern const struct bpf_func_proto bpf_get_current_cgroup_id_proto;
extern const struct bpf_func_proto bpf_get_current_ancestor_cgroup_id_proto;
extern const struct bpf_func_proto bpf_msg_redirect_hash_proto;
extern const struct bpf_func_proto bpf_msg_redirect_map_proto;
extern const struct bpf_func_proto bpf_sk_redirect_hash_proto;
extern const struct bpf_func_proto bpf_sk_redirect_map_proto;
extern const struct bpf_func_proto bpf_spin_lock_proto;
extern const struct bpf_func_proto bpf_spin_unlock_proto;
extern const struct bpf_func_proto bpf_get_local_storage_proto;
extern const struct bpf_func_proto bpf_strtol_proto;
extern const struct bpf_func_proto bpf_strtoul_proto;
extern const struct bpf_func_proto bpf_tcp_sock_proto;
extern const struct bpf_func_proto bpf_jiffies64_proto;
extern const struct bpf_func_proto bpf_get_ns_current_pid_tgid_proto;
extern const struct bpf_func_proto bpf_event_output_data_proto;
extern const struct bpf_func_proto bpf_ringbuf_output_proto;
extern const struct bpf_func_proto bpf_ringbuf_reserve_proto;
extern const struct bpf_func_proto bpf_ringbuf_submit_proto;
extern const struct bpf_func_proto bpf_ringbuf_discard_proto;
extern const struct bpf_func_proto bpf_ringbuf_query_proto;
extern const struct bpf_func_proto bpf_skc_to_tcp6_sock_proto;
extern const struct bpf_func_proto bpf_skc_to_tcp_sock_proto;
extern const struct bpf_func_proto bpf_skc_to_tcp_timewait_sock_proto;
extern const struct bpf_func_proto bpf_skc_to_tcp_request_sock_proto;
extern const struct bpf_func_proto bpf_skc_to_udp6_sock_proto;

const struct bpf_func_proto *bpf_tracing_func_proto(
	enum bpf_func_id func_id, const struct bpf_prog *prog);

const struct bpf_func_proto *tracing_prog_func_proto(
  enum bpf_func_id func_id, const struct bpf_prog *prog);

/* Shared helpers among cBPF and eBPF. */
void bpf_user_rnd_init_once(void);
u64 bpf_user_rnd_u32(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
u64 bpf_get_raw_cpu_id(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);

enum bpf_text_poke_type {
	BPF_MOD_CALL,
	BPF_MOD_JUMP,
};

/* these two functions are called from generated trampoline */
u64 __bpf_prog_enter(void);
void __bpf_prog_exit(struct bpf_prog *prog, u64 start);


/* Helper macros for filter block array initializers. */

/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

#define BPF_ALU64_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_ALU32_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

#define BPF_ALU64_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_ALU32_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Endianess conversion, cpu_to_{l,b}e(), {l,b}e_to_cpu() */

#define BPF_ENDIAN(TYPE, DST, LEN)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_END | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = LEN })

/* Short form of mov, dst_reg = src_reg */

#define BPF_MOV64_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_MOV32_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* Short form of mov, dst_reg = imm32 */

#define BPF_MOV64_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_MOV32_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Special form of mov32, used for doing explicit zero extension on dst. */
#define BPF_ZEXT_REG(DST)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = DST,					\
		.off   = 0,					\
		.imm   = 1 })

static inline bool insn_is_zext(const struct bpf_insn *insn)
{
	return insn->code == (BPF_ALU | BPF_MOV | BPF_X) && insn->imm == 1;
}

/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
#define BPF_LD_IMM64(DST, IMM)					\
	BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_DW | BPF_IMM,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = (__u32) (IMM) }),			\
	((struct bpf_insn) {					\
		.code  = 0, /* zero is reserved opcode */	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((__u64) (IMM)) >> 32 })

/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
#define BPF_LD_MAP_FD(DST, MAP_FD)				\
	BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)

/* Short form of mov based on type, BPF_X: dst_reg = src_reg, BPF_K: dst_reg = imm32 */

#define BPF_MOV64_RAW(TYPE, DST, SRC, IMM)			\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_MOV32_RAW(TYPE, DST, SRC, IMM)			\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })

/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */

#define BPF_LD_ABS(SIZE, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Indirect packet access, R0 = *(uint *) (skb->data + src_reg + imm32) */

#define BPF_LD_IND(SIZE, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_IND,	\
		.dst_reg = 0,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })

/* Memory load, dst_reg = *(uint *) (src_reg + off16) */

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = src_reg */

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Atomic memory add, *(uint *)(dst_reg + off16) += src_reg */

#define BPF_STX_XADD(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_XADD,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = imm32 */

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc + off16 */

#define BPF_JMP_REG(OP, DST, SRC, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */

#define BPF_JMP_IMM(OP, DST, IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Like BPF_JMP_REG, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_REG(OP, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_JMP32 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Like BPF_JMP_IMM, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_IMM(OP, DST, IMM, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_JMP32 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Unconditional jumps, goto pc + off16 */

#define BPF_JMP_A(OFF)						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_JA,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Relative call */

#define BPF_CALL_REL(TGT)					\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_CALL,			\
		.dst_reg = 0,					\
		.src_reg = BPF_PSEUDO_CALL,			\
		.off   = 0,					\
		.imm   = TGT })

/* Function call */

#define BPF_CAST_CALL(x)					\
		((u64 (*)(u64, u64, u64, u64, u64))(x))

#define BPF_EMIT_CALL(FUNC)					\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_CALL,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((FUNC) - __bpf_call_base) })

/* Raw code statement block */

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)			\
	((struct bpf_insn) {					\
		.code  = CODE,					\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Program exit */

#define BPF_EXIT_INSN()						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_EXIT,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })

/* Internal classic blocks for direct assignment */

#define __BPF_STMT(CODE, K)					\
	((struct sock_filter) BPF_STMT(CODE, K))

#define __BPF_JUMP(CODE, K, JT, JF)				\
	((struct sock_filter) BPF_JUMP(CODE, K, JT, JF))

#define bytes_to_bpf_size(bytes)				\
({								\
	int bpf_size = -EINVAL;					\
								\
	if (bytes == sizeof(u8))				\
		bpf_size = BPF_B;				\
	else if (bytes == sizeof(u16))				\
		bpf_size = BPF_H;				\
	else if (bytes == sizeof(u32))				\
		bpf_size = BPF_W;				\
	else if (bytes == sizeof(u64))				\
		bpf_size = BPF_DW;				\
								\
	bpf_size;						\
})

#define bpf_size_to_bytes(bpf_size)				\
({								\
	int bytes = -EINVAL;					\
								\
	if (bpf_size == BPF_B)					\
		bytes = sizeof(u8);				\
	else if (bpf_size == BPF_H)				\
		bytes = sizeof(u16);				\
	else if (bpf_size == BPF_W)				\
		bytes = sizeof(u32);				\
	else if (bpf_size == BPF_DW)				\
		bytes = sizeof(u64);				\
								\
	bytes;							\
})

#define BPF_SIZEOF(type)					\
	({							\
		const int __size = bytes_to_bpf_size(sizeof(type)); \
		BUILD_BUG_ON(__size < 0);			\
		__size;						\
	})

#define BPF_FIELD_SIZEOF(type, field)				\
	({							\
		const int __size = bytes_to_bpf_size(sizeof_field(type, field)); \
		BUILD_BUG_ON(__size < 0);			\
		__size;						\
	})

#define BPF_LDST_BYTES(insn)					\
	({							\
		const int __size = bpf_size_to_bytes(BPF_SIZE((insn)->code)); \
		WARN_ON(__size < 0);				\
		__size;						\
	})

#define __BPF_MAP_0(m, v, ...) v
#define __BPF_MAP_1(m, v, t, a, ...) m(t, a)
#define __BPF_MAP_2(m, v, t, a, ...) m(t, a), __BPF_MAP_1(m, v, __VA_ARGS__)
#define __BPF_MAP_3(m, v, t, a, ...) m(t, a), __BPF_MAP_2(m, v, __VA_ARGS__)
#define __BPF_MAP_4(m, v, t, a, ...) m(t, a), __BPF_MAP_3(m, v, __VA_ARGS__)
#define __BPF_MAP_5(m, v, t, a, ...) m(t, a), __BPF_MAP_4(m, v, __VA_ARGS__)

#define __BPF_REG_0(...) __BPF_PAD(5)
#define __BPF_REG_1(...) __BPF_MAP(1, __VA_ARGS__), __BPF_PAD(4)
#define __BPF_REG_2(...) __BPF_MAP(2, __VA_ARGS__), __BPF_PAD(3)
#define __BPF_REG_3(...) __BPF_MAP(3, __VA_ARGS__), __BPF_PAD(2)
#define __BPF_REG_4(...) __BPF_MAP(4, __VA_ARGS__), __BPF_PAD(1)
#define __BPF_REG_5(...) __BPF_MAP(5, __VA_ARGS__)

#define __BPF_MAP(n, ...) __BPF_MAP_##n(__VA_ARGS__)
#define __BPF_REG(n, ...) __BPF_REG_##n(__VA_ARGS__)

#define __BPF_CAST(t, a)						       \
	(__force t)							       \
	(__force							       \
	 typeof(__builtin_choose_expr(sizeof(t) == sizeof(unsigned long),      \
				      (unsigned long)0, (t)0))) a
#define __BPF_V void
#define __BPF_N

#define __BPF_DECL_ARGS(t, a) t   a
#define __BPF_DECL_REGS(t, a) u64 a

#define __BPF_PAD(n)							       \
	__BPF_MAP(n, __BPF_DECL_ARGS, __BPF_N, u64, __ur_1, u64, __ur_2,       \
		  u64, __ur_3, u64, __ur_4, u64, __ur_5)

#define BPF_CALL_x(x, name, ...)					       \
	static __always_inline						       \
	u64 ____##name(__BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__));   \
	typedef u64 (*btf_##name)(__BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__)); \
	u64 name(__BPF_REG(x, __BPF_DECL_REGS, __BPF_N, __VA_ARGS__));	       \
	u64 name(__BPF_REG(x, __BPF_DECL_REGS, __BPF_N, __VA_ARGS__))	       \
	{								       \
		return ((btf_##name)____##name)(__BPF_MAP(x,__BPF_CAST,__BPF_N,__VA_ARGS__));\
	}								       \
	static __always_inline						       \
	u64 ____##name(__BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__))

#define BPF_CALL_0(name, ...)	BPF_CALL_x(0, name, __VA_ARGS__)
#define BPF_CALL_1(name, ...)	BPF_CALL_x(1, name, __VA_ARGS__)
#define BPF_CALL_2(name, ...)	BPF_CALL_x(2, name, __VA_ARGS__)
#define BPF_CALL_3(name, ...)	BPF_CALL_x(3, name, __VA_ARGS__)
#define BPF_CALL_4(name, ...)	BPF_CALL_x(4, name, __VA_ARGS__)
#define BPF_CALL_5(name, ...)	BPF_CALL_x(5, name, __VA_ARGS__)

#define bpf_ctx_range(TYPE, MEMBER)						\
	offsetof(TYPE, MEMBER) ... offsetofend(TYPE, MEMBER) - 1
#define bpf_ctx_range_till(TYPE, MEMBER1, MEMBER2)				\
	offsetof(TYPE, MEMBER1) ... offsetofend(TYPE, MEMBER2) - 1
#if BITS_PER_LONG == 64
# define bpf_ctx_range_ptr(TYPE, MEMBER)					\
	offsetof(TYPE, MEMBER) ... offsetofend(TYPE, MEMBER) - 1
#else
# define bpf_ctx_range_ptr(TYPE, MEMBER)					\
	offsetof(TYPE, MEMBER) ... offsetof(TYPE, MEMBER) + 8 - 1
#endif /* BITS_PER_LONG == 64 */

#define bpf_target_off(TYPE, MEMBER, SIZE, PTR_SIZE)				\
	({									\
		BUILD_BUG_ON(sizeof_field(TYPE, MEMBER) != (SIZE));		\
		*(PTR_SIZE) = (SIZE);						\
		offsetof(TYPE, MEMBER);						\
	})

struct bpf_prog {
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
	enum bpf_prog_type	type;		/* Type of BPF program */
	enum bpf_attach_type	expected_attach_type; /* For some prog types */
	u32			len;		/* Number of filter blocks */
	u32			jited_len;	/* Size of jited insns in bytes */
	u8			tag[BPF_TAG_SIZE];
	struct bpf_prog_aux	*aux;		/* Auxiliary fields */
	struct sock_fprog_kern	*orig_prog;	/* Original BPF program */
	unsigned int		(*bpf_func)(const void *ctx,
					    const struct bpf_insn *insn);
	/* Instructions for interpreter */
	struct sock_filter	insns[0];
	struct bpf_insn		insnsi[];
};


u64 __bpf_call_base(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
#define __bpf_call_base_args \
	((u64 (*)(u64, u64, u64, u64, u64, const struct bpf_insn *)) \
	 __bpf_call_base)

struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog);
void bpf_jit_compile(struct bpf_prog *prog);
bool bpf_jit_needs_zext(void);
bool bpf_helper_changes_pkt_data(void *func);


#ifdef CONFIG_BPF_JIT
extern int bpf_jit_enable;
extern int bpf_jit_harden;
extern int bpf_jit_kallsyms;
extern long bpf_jit_limit;

typedef void (*bpf_jit_fill_hole_t)(void *area, unsigned int size);

struct bpf_binary_header *
bpf_jit_binary_alloc(unsigned int proglen, u8 **image_ptr,
		     unsigned int alignment,
		     bpf_jit_fill_hole_t bpf_fill_ill_insns);
void bpf_jit_binary_free(struct bpf_binary_header *hdr);
u64 bpf_jit_alloc_exec_limit(void);
void *bpf_jit_alloc_exec(unsigned long size);
void bpf_jit_free_exec(void *addr);
void bpf_jit_free(struct bpf_prog *fp);

int bpf_jit_get_func_addr(const struct bpf_prog *prog,
			  const struct bpf_insn *insn, bool extra_pass,
			  u64 *func_addr, bool *func_addr_fixed);

struct bpf_prog *bpf_jit_blind_constants(struct bpf_prog *fp);
void bpf_jit_prog_release_other(struct bpf_prog *fp, struct bpf_prog *fp_other);

static inline void bpf_jit_dump(unsigned int flen, unsigned int proglen,
				u32 pass, void *image)
{
	pr_err("flen=%u proglen=%u pass=%u image=%pK\n", flen,
	       proglen, pass, image);
}

static inline bool bpf_jit_is_ebpf(void)
{
# ifdef CONFIG_HAVE_EBPF_JIT
	return true;
# else
	return false;
# endif
}

static inline bool ebpf_jit_enabled(void)
{
	return bpf_jit_enable && bpf_jit_is_ebpf();
}

static inline bool bpf_prog_ebpf_jited(const struct bpf_prog *fp)
{
	return fp->jited && bpf_jit_is_ebpf();
}

static inline bool bpf_jit_blinding_enabled(struct bpf_prog *prog)
{
	/* These are the prerequisites, should someone ever have the
	 * idea to call blinding outside of them, we make sure to
	 * bail out.
	 */
	if (!bpf_jit_is_ebpf())
		return false;
	if (!prog->jit_requested)
		return false;
	if (!bpf_jit_harden)
		return false;
	if (bpf_jit_harden == 1)
		return false;

	return true;
}

static inline bool bpf_jit_kallsyms_enabled(void)
{
	/* There are a couple of corner cases where kallsyms should
	 * not be enabled f.e. on hardening.
	 */
	if (bpf_jit_harden)
		return false;
	if (!bpf_jit_kallsyms)
		return false;
	if (bpf_jit_kallsyms == 1)
		return true;

	return false;
}

const char *__bpf_address_lookup(unsigned long addr, unsigned long *size,
				 unsigned long *off, char *sym);
bool is_bpf_text_address(unsigned long addr);
int bpf_get_kallsym(unsigned int symnum, unsigned long *value, char *type,
		    char *sym);

static inline const char *
bpf_address_lookup(unsigned long addr, unsigned long *size,
		   unsigned long *off, char **modname, char *sym)
{
	const char *ret = __bpf_address_lookup(addr, size, off, sym);

	if (ret && modname)
		*modname = NULL;
	return ret;
}

void bpf_prog_kallsyms_add(struct bpf_prog *fp);
void bpf_prog_kallsyms_del(struct bpf_prog *fp);

#else /* CONFIG_BPF_JIT */

static inline bool ebpf_jit_enabled(void)
{
	return false;
}

static inline bool bpf_jit_blinding_enabled(struct bpf_prog *prog)
{
	return false;
}

static inline bool bpf_prog_ebpf_jited(const struct bpf_prog *fp)
{
	return false;
}

static inline int
bpf_jit_add_poke_descriptor(struct bpf_prog *prog,
			    struct bpf_jit_poke_descriptor *poke)
{
	return -ENOTSUPP;
}

static inline void bpf_jit_free(struct bpf_prog *fp)
{
	bpf_prog_unlock_free(fp);
}

static inline bool bpf_jit_kallsyms_enabled(void)
{
	return false;
}

static inline const char *
__bpf_address_lookup(unsigned long addr, unsigned long *size,
		     unsigned long *off, char *sym)
{
	return NULL;
}

static inline bool is_bpf_text_address(unsigned long addr)
{
	return false;
}

static inline int bpf_get_kallsym(unsigned int symnum, unsigned long *value,
				  char *type, char *sym)
{
	return -ERANGE;
}

static inline const char *
bpf_address_lookup(unsigned long addr, unsigned long *size,
		   unsigned long *off, char **modname, char *sym)
{
	return NULL;
}

static inline void bpf_prog_kallsyms_add(struct bpf_prog *fp)
{
}

static inline void bpf_prog_kallsyms_del(struct bpf_prog *fp)
{
}

#endif /* CONFIG_BPF_JIT */

#endif /* _LINUX_BPF_H */
