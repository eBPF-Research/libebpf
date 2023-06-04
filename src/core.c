#include "type-fixes.h"
#include "linux-errno.h"
#include "linux-bpf.h"
#include "bpf_jit_arch.h"
#include <stdlib.h>
#include <string.h>

int bpf_jit_enable = true;
// const int bpf_jit_harden;
// const int bpf_jit_kallsyms;
// const long bpf_jit_limit;

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

	if (bpf_jit_charge_modmem(size))
		return NULL;
	hdr = bpf_jit_alloc_exec(size);
	if (!hdr) {
		bpf_jit_uncharge_modmem(size);
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
	u32 size = hdr->size;

	bpf_jit_free_exec(hdr);
	bpf_jit_uncharge_modmem(size);
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
	fp = malloc(size);
	if (fp == NULL)
		return NULL;

	aux = malloc(sizeof(*aux));
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
 * jited_off is the byte off to the end of the jited insn.
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

struct bpf_prog *bpf_prog_get(const void* code, unsigned int code_len) {
	struct bpf_prog *prog = bpf_prog_alloc(code_len);
	memcpy(prog->insnsi, code, code_len);
	return prog;
}
