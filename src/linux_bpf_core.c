#include "type-fixes.h"
#include "linux-errno.h"
#include "linux-bpf.h"
#include "bpf_jit_arch.h"
#include "libebpf/linux-jit-bpf.h"
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#include <time.h>
#endif

int bpf_jit_enable = true;
// const int bpf_jit_harden;
// const int bpf_jit_kallsyms;
// const long bpf_jit_limit;

static inline struct bpf_binary_header *
bpf_jit_binary_hdr(const struct bpf_prog *fp)
{
	unsigned long real_start = (unsigned long)fp->bpf_func;
	unsigned long addr = real_start & PAGE_MASK;

	return (void *)addr;
}

/* This symbol is only overridden by archs that have different
 * requirements than the usual eBPF JITs, f.e. when they only
 * implement cBPF JIT, do not set images read-only, etc.
 */
void bpf_jit_free(struct bpf_prog *fp)
{
	if (fp->jited) {
		struct bpf_binary_header *hdr = bpf_jit_binary_hdr(fp);

		// bpf_jit_binary_free(hdr);
	}

	__bpf_prog_free(fp);
}

void *bpf_jit_alloc_exec(unsigned long size)
{
	return malloc(size);
}

void bpf_jit_free_exec(void *addr)
{
	free(addr);
}

struct bpf_binary_header *
bpf_jit_binary_alloc(unsigned int proglen, u8 **image_ptr,
		     unsigned int alignment,
		     bpf_jit_fill_hole_t bpf_fill_ill_insns)
{
	struct bpf_binary_header *hdr;
	u32 size, hole, start;

	if(!is_power_of_2(alignment) ||
		     alignment > BPF_IMAGE_ALIGNMENT) {
				printf("!is_power_of_2(alignment) || alignment > BPF_IMAGE_ALIGNMENT");
	}

	/* Most of BPF filters are really small, but if some of them
	 * fill a page, allow at least 128 extra bytes to insert a
	 * random section of illegal instructions.
	 */
	size = round_up(proglen + sizeof(*hdr) + 128, PAGE_SIZE);

	// if (bpf_jit_charge_modmem(size))
	// 	return NULL;
	hdr = bpf_jit_alloc_exec(size);
	if (!hdr) {
		// bpf_jit_uncharge_modmem(size);
		return NULL;
	}

	/* Fill space with illegal/arch-dep instructions. */
	bpf_fill_ill_insns(hdr, size);

	hdr->size = size;
	hole = min(size - (proglen + sizeof(*hdr)),
		     PAGE_SIZE - sizeof(*hdr));
	// get_random_u32_below(hole)
	start = (hole - 1) & ~(alignment - 1);

	/* Leave a random number of instructions before BPF code. */
	*image_ptr = &hdr->image[start];

	return hdr;
}

void bpf_jit_binary_free(struct bpf_binary_header *hdr)
{
	bpf_jit_free_exec(hdr);
}

typedef unsigned int (*bpf_dispatcher_fn)(const void *ctx,
					  const struct bpf_insn *insnsi,
					  unsigned int (*bpf_func)(const void *,
								   const struct bpf_insn *));

static u32 __bpf_prog_run(const struct bpf_prog *prog,
					  const void *ctx,
					  bpf_dispatcher_fn dfunc)
{
	return dfunc(ctx, prog->insnsi, prog->bpf_func);
}

unsigned int bpf_prog_run_jit(const struct bpf_prog *prog, const void *ctx) {
	return __bpf_prog_run(prog, ctx, bpf_dispatcher_nop_func);
}


struct bpf_prog *bpf_prog_alloc_no_stats(unsigned int size)
{
	struct bpf_prog_aux *aux;
	struct bpf_prog *fp;

	size = round_up(size, PAGE_SIZE);
	fp = calloc(size, 1);
	if (fp == NULL)
		return NULL;

	aux = calloc(1, sizeof(*aux));
	if (aux == NULL) {
		free(fp);
		return NULL;
	}
	fp->pages = size / PAGE_SIZE;
	fp->aux = aux;
	fp->aux->prog = fp;
	fp->jit_requested = ebpf_jit_enabled();

	return fp;
}

struct bpf_prog *bpf_prog_alloc(unsigned int size)
{
	struct bpf_prog *prog;

	prog = bpf_prog_alloc_no_stats(size);
	if (!prog)
		return NULL;

	return prog;
}

int bpf_prog_alloc_jited_linfo(struct bpf_prog *prog)
{
	if (!prog->aux->nr_linfo || !prog->jit_requested)
		return 0;

	prog->aux->jited_linfo = calloc(prog->aux->nr_linfo,
					  sizeof(*prog->aux->jited_linfo));
	if (!prog->aux->jited_linfo)
		return -ENOMEM;

	return 0;
}

void bpf_prog_jit_attempt_done(struct bpf_prog *prog)
{
	if (prog->aux->jited_linfo &&
	    (!prog->jited || !prog->aux->jited_linfo[0])) {
		free(prog->aux->jited_linfo);
		prog->aux->jited_linfo = NULL;
	}

	free(prog->aux->kfunc_tab);
	prog->aux->kfunc_tab = NULL;
}

/* The jit engine is responsible to provide an array
 * for insn_off to the jited_off mapping (insn_to_jit_off).
 *
 * The idx to this array is the insn_off.  Hence, the insn_off
 * here is relative to the prog itself instead of the main prog.
 * This array has one entry for each xlated bpf insn.
 *
 * jited_off is the byte off to the last byte of the jited insn.
 *
 * Hence, with
 * insn_start:
 *      The first bpf insn off of the prog.  The insn off
 *      here is relative to the main prog.
 *      e.g. if prog is a subprog, insn_start > 0
 * linfo_idx:
 *      The prog's idx to prog->aux->linfo and jited_linfo
 *
 * jited_linfo[linfo_idx] = prog->bpf_func
 *
 * For i > linfo_idx,
 *
 * jited_linfo[i] = prog->bpf_func +
 *	insn_to_jit_off[linfo[i].insn_off - insn_start - 1]
 */
void bpf_prog_fill_jited_linfo(struct bpf_prog *prog,
			       const u32 *insn_to_jit_off)
{
	u32 linfo_idx, insn_start, insn_end, nr_linfo, i;
	const struct bpf_line_info *linfo;
	void **jited_linfo;

	if (!prog->aux->jited_linfo)
		/* Userspace did not provide linfo */
		return;

	linfo_idx = prog->aux->linfo_idx;
	linfo = &prog->aux->linfo[linfo_idx];
	insn_start = linfo[0].insn_off;
	insn_end = insn_start + prog->len;

	jited_linfo = &prog->aux->jited_linfo[linfo_idx];
	jited_linfo[0] = prog->bpf_func;

	nr_linfo = prog->aux->nr_linfo - linfo_idx;

	for (i = 1; i < nr_linfo && linfo[i].insn_off < insn_end; i++)
		/* The verifier ensures that linfo[i].insn_off is
		 * strictly increasing
		 */
		jited_linfo[i] = prog->bpf_func +
			insn_to_jit_off[linfo[i].insn_off - insn_start - 1];
}

void __bpf_prog_free(struct bpf_prog *fp)
{
	if (fp->aux) {
		free(fp->aux->poke_tab);
		free(fp->aux);
	}
	free(fp);
}

static inline u32 bpf_prog_insn_size(const struct bpf_prog *prog)
{
	return prog->len * sizeof(struct bpf_insn);
}

struct bpf_prog *bpf_prog_load(union bpf_attr *attr)
{
	struct bpf_prog *prog, *dst_prog = NULL;
	struct btf *attach_btf = NULL;
	bool is_gpl = false;

	/* remove kernel checkers here */

	/* plain bpf_prog allocation */
	prog = bpf_prog_alloc(bpf_prog_size(attr->insn_cnt));
	if (!prog) {
		return NULL;
	}

	prog->expected_attach_type = attr->expected_attach_type;
	prog->aux->attach_btf = attach_btf;
	prog->aux->attach_btf_id = attr->attach_btf_id;
	prog->aux->dst_prog = dst_prog;
	prog->aux->offload_requested = false; // origin is: !!attr->prog_ifindex;

	prog->aux->user = NULL; // get_current_user();
	prog->len = attr->insn_cnt;

	memcpy(prog->insnsi,
			     (void*)attr->insns,
			     bpf_prog_insn_size(prog));

	prog->orig_prog = NULL;
	prog->jited = 0;

	prog->gpl_compatible = is_gpl ? 1 : 0;

	prog->aux->load_time = 0;
	strncpy(prog->aux->name, attr->prog_name,
			       sizeof(attr->prog_name));

	/* run eBPF verifier */
	// err = bpf_check(&prog, attr, uattr);
	return prog;
}

/* Free internal BPF program */
void bpf_prog_free(struct bpf_prog *fp)
{
	struct bpf_prog_aux *aux = fp->aux;

	for (int i = 0; i < aux->func_cnt; i++)
		bpf_jit_free(aux->func[i]);
	if (aux->func_cnt) {
		free(aux->func);
	} else {
		bpf_jit_free(aux->prog);
	}
}

static void bpf_prog_clone_free(struct bpf_prog *fp)
{
	/* aux was stolen by the other clone, so we cannot free
	 * it from this path! It will be freed eventually by the
	 * other program on release.
	 *
	 * At this point, we don't need a deferred release since
	 * clone is guaranteed to not be locked.
	 */
	fp->aux = NULL;
	__bpf_prog_free(fp);
}

void bpf_jit_prog_release_other(struct bpf_prog *fp, struct bpf_prog *fp_other)
{
	/* We have to repoint aux->prog to self, as we don't
	 * know whether fp here is the clone or the original.
	 */
	fp->aux->prog = fp;
	bpf_prog_clone_free(fp_other);
}

/* Base function for offset calculation. Needs to go into .text section,
 * therefore keeping it non-static as well; will also be used by JITs
 * anyway later on, so do not let the compiler omit it. This also needs
 * to go into kallsyms for correlation from e.g. bpftool, so naming
 * must not change.
 */
noinline u64 __bpf_call_base(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return 0;
}

/* The logic is similar to BPF_PROG_RUN, but with an explicit
 * rcu_read_lock() and migrate_disable() which are required
 * for the trampoline. The macro is split into
 * call _bpf_prog_enter
 * call prog->bpf_func
 * call __bpf_prog_exit
 */
u64 __bpf_prog_enter(void)
{
#ifdef __linux__
	u64 start = clock();
#elif
	u64 start = 0;
#endif
	printf("__bpf_prog_enter %lu\n", start);
	return start;
}

void __bpf_prog_exit(struct bpf_prog *prog, u64 start)
{
	// do nothing
	printf("__bpf_prog_exit %lu\n", start);
}

int bpf_jit_get_func_addr(const struct bpf_prog *prog,
			  const struct bpf_insn *insn, bool extra_pass,
			  u64 *func_addr, bool *func_addr_fixed)
{
	s16 off = insn->off;
	s32 imm = insn->imm;
	u8 *addr;

	*func_addr_fixed = insn->src_reg != BPF_PSEUDO_CALL;
	if (!*func_addr_fixed) {
		/* Place-holder address till the last pass has collected
		 * all addresses for JITed subprograms in which case we
		 * can pick them up from prog->aux.
		 */
		if (!extra_pass)
			addr = NULL;
		else if (prog->aux->func &&
			 off >= 0 && off < prog->aux->func_cnt)
			addr = (u8 *)prog->aux->func[off]->bpf_func;
		else
			return -EINVAL;
	} else {
		/* Address of a BPF helper call. Since part of the core
		 * kernel, it's always at a fixed location. __bpf_call_base
		 * and the helper with imm relative to it are both in core
		 * kernel.
		 */
		addr = (u8 *)__bpf_call_base + imm;
	}

	*func_addr = (unsigned long)addr;
	return 0;
}
