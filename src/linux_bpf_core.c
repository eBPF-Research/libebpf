#include "type-fixes.h"
#include "linux-errno.h"
#include "linux_bpf.h"
#include "bpf_jit_arch.h"
#include "ebpf_vm.h"
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
// for mmap and munmap, to let jit code be executable
#include <sys/mman.h>
#include <time.h>
#endif

static inline __attribute__((const))
bool is_power_of_2(unsigned long n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

void *bpf_jit_alloc_exec(unsigned long size)
{
	LOG_DEBUG("bpf_jit_alloc_exec for size: %ld\n", size);
#ifdef __linux__
	void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS ,-1, 0);
    if(mem == MAP_FAILED) {
        return false;
    }
	return mem;
#else
	return malloc(size);
#endif
}

void bpf_jit_free_exec(void *addr)
{
	LOG_DEBUG("bpf_jit_free_exec for addr: %p\n", addr);
#ifdef __linux__
	munmap(addr, 0);
#else
	free(addr);
#endif
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

typedef unsigned int (*bpf_dispatcher_fn)(const void *ctx,
					  const struct bpf_insn *insnsi,
					  unsigned int (*bpf_func)(const void *,
								   const struct bpf_insn *));

void __bpf_prog_free(struct ebpf_vm *fp)
{
	if (fp->aux) {
		free(fp->aux->poke_tab);
		free(fp->aux);
	}
	free(fp);
}

/* Base function for offset calculation. Needs to go into .text section,
 * therefore keeping it non-static as well; will also be used by JITs
 * anyway later on, so do not let the compiler omit it. This also needs
 * to go into kallsyms for correlation from e.g. bpftool, so naming
 * must not change.
 */
__attribute__((__noinline__)) u64 __bpf_call_base(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
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

void __bpf_prog_exit(struct ebpf_vm *prog, u64 start)
{
	// do nothing
	printf("__bpf_prog_exit %lu\n", start);
}

int bpf_jit_get_func_addr(const struct ebpf_vm *prog,
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
