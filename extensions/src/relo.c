// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/relo_core.h>
#include <bpf/hashmap.h>
#include <bpf/btf.h>
#include <bpf/libbpf_internal.h>

#define MARKED UINT32_MAX

struct btfgen_info {
	struct btf *src_btf;
	struct btf *marked_btf; /* btf structure used to mark used types */
};

static size_t btfgen_hash_fn(long key, void *ctx)
{
	return key;
}

static bool btfgen_equal_fn(long k1, long k2, void *ctx)
{
	return k1 == k2;
}

static void btfgen_free_info(struct btfgen_info *info)
{
	if (!info)
		return;

	btf__free(info->src_btf);
	btf__free(info->marked_btf);

	free(info);
}

static struct btfgen_info *
btfgen_new_info(const char *targ_btf_path)
{
	struct btfgen_info *info;
	int err;

	info = calloc(1, sizeof(*info));
	if (!info)
		return NULL;

	info->src_btf = btf__parse(targ_btf_path, NULL);
	if (!info->src_btf) {
		err = -errno;
		printf("failed parsing '%s' BTF file: %s", targ_btf_path, strerror(errno));
		goto err_out;
	}

	info->marked_btf = btf__parse(targ_btf_path, NULL);
	if (!info->marked_btf) {
		err = -errno;
		printf("failed parsing '%s' BTF file: %s", targ_btf_path, strerror(errno));
		goto err_out;
	}

	return info;

err_out:
	btfgen_free_info(info);
	errno = -err;
	return NULL;
}


static void btfgen_mark_member(struct btfgen_info *info, int type_id, int idx)
{
	const struct btf_type *t = btf__type_by_id(info->marked_btf, type_id);
	struct btf_member *m = btf_members(t) + idx;

	m->name_off = MARKED;
}

static int
btfgen_mark_type(struct btfgen_info *info, unsigned int type_id, bool follow_pointers)
{
	const struct btf_type *btf_type = btf__type_by_id(info->src_btf, type_id);
	struct btf_type *cloned_type;
	struct btf_param *param;
	struct btf_array *array;
	int err, i;

	if (type_id == 0)
		return 0;

	/* mark type on cloned BTF as used */
	cloned_type = (struct btf_type *) btf__type_by_id(info->marked_btf, type_id);
	cloned_type->name_off = MARKED;

	/* recursively mark other types needed by it */
	switch (btf_kind(btf_type)) {
	case BTF_KIND_UNKN:
	case BTF_KIND_INT:
	case BTF_KIND_FLOAT:
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		break;
	case BTF_KIND_PTR:
		if (follow_pointers) {
			err = btfgen_mark_type(info, btf_type->type, follow_pointers);
			if (err)
				return err;
		}
		break;
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_TYPEDEF:
		err = btfgen_mark_type(info, btf_type->type, follow_pointers);
		if (err)
			return err;
		break;
	case BTF_KIND_ARRAY:
		array = btf_array(btf_type);

		/* mark array type */
		err = btfgen_mark_type(info, array->type, follow_pointers);
		/* mark array's index type */
		err = err ? : btfgen_mark_type(info, array->index_type, follow_pointers);
		if (err)
			return err;
		break;
	case BTF_KIND_FUNC_PROTO:
		/* mark ret type */
		err = btfgen_mark_type(info, btf_type->type, follow_pointers);
		if (err)
			return err;

		/* mark parameters types */
		param = btf_params(btf_type);
		for (i = 0; i < btf_vlen(btf_type); i++) {
			err = btfgen_mark_type(info, param->type, follow_pointers);
			if (err)
				return err;
			param++;
		}
		break;
	/* tells if some other type needs to be handled */
	default:
		printf("unsupported kind: %s (%d)", btf_kind_str(btf_type), type_id);
		return -EINVAL;
	}

	return 0;
}

static int btfgen_record_field_relo(struct btfgen_info *info, struct bpf_core_spec *targ_spec)
{
	struct btf *btf = info->src_btf;
	const struct btf_type *btf_type;
	struct btf_member *btf_member;
	struct btf_array *array;
	unsigned int type_id = targ_spec->root_type_id;
	int idx, err;

	/* mark root type */
	btf_type = btf__type_by_id(btf, type_id);
	err = btfgen_mark_type(info, type_id, false);
	if (err)
		return err;

	/* mark types for complex types (arrays, unions, structures) */
	for (int i = 1; i < targ_spec->raw_len; i++) {
		/* skip typedefs and mods */
		while (btf_is_mod(btf_type) || btf_is_typedef(btf_type)) {
			type_id = btf_type->type;
			btf_type = btf__type_by_id(btf, type_id);
		}

		switch (btf_kind(btf_type)) {
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			idx = targ_spec->raw_spec[i];
			btf_member = btf_members(btf_type) + idx;

			/* mark member */
			btfgen_mark_member(info, type_id, idx);

			/* mark member's type */
			type_id = btf_member->type;
			btf_type = btf__type_by_id(btf, type_id);
			err = btfgen_mark_type(info, type_id, false);
			if (err)
				return err;
			break;
		case BTF_KIND_ARRAY:
			array = btf_array(btf_type);
			type_id = array->type;
			btf_type = btf__type_by_id(btf, type_id);
			break;
		default:
			printf("unsupported kind: %s (%d)",
			      btf_kind_str(btf_type), btf_type->type);
			return -EINVAL;
		}
	}

	return 0;
}

/* Mark types, members, and member types. Compared to btfgen_record_field_relo,
 * this function does not rely on the target spec for inferring members, but
 * uses the associated BTF.
 *
 * The `behind_ptr` argument is used to stop marking of composite types reached
 * through a pointer. This way, we can keep BTF size in check while providing
 * reasonable match semantics.
 */
static int btfgen_mark_type_match(struct btfgen_info *info, __u32 type_id, bool behind_ptr)
{
	const struct btf_type *btf_type;
	struct btf *btf = info->src_btf;
	struct btf_type *cloned_type;
	int i, err;

	if (type_id == 0)
		return 0;

	btf_type = btf__type_by_id(btf, type_id);
	/* mark type on cloned BTF as used */
	cloned_type = (struct btf_type *)btf__type_by_id(info->marked_btf, type_id);
	cloned_type->name_off = MARKED;

	switch (btf_kind(btf_type)) {
	case BTF_KIND_UNKN:
	case BTF_KIND_INT:
	case BTF_KIND_FLOAT:
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
		break;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION: {
		struct btf_member *m = btf_members(btf_type);
		__u16 vlen = btf_vlen(btf_type);

		if (behind_ptr)
			break;

		for (i = 0; i < vlen; i++, m++) {
			/* mark member */
			btfgen_mark_member(info, type_id, i);

			/* mark member's type */
			err = btfgen_mark_type_match(info, m->type, false);
			if (err)
				return err;
		}
		break;
	}
	case BTF_KIND_CONST:
	case BTF_KIND_FWD:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
		return btfgen_mark_type_match(info, btf_type->type, behind_ptr);
	case BTF_KIND_PTR:
		return btfgen_mark_type_match(info, btf_type->type, true);
	case BTF_KIND_ARRAY: {
		struct btf_array *array;

		array = btf_array(btf_type);
		/* mark array type */
		err = btfgen_mark_type_match(info, array->type, false);
		/* mark array's index type */
		err = err ? : btfgen_mark_type_match(info, array->index_type, false);
		if (err)
			return err;
		break;
	}
	case BTF_KIND_FUNC_PROTO: {
		__u16 vlen = btf_vlen(btf_type);
		struct btf_param *param;

		/* mark ret type */
		err = btfgen_mark_type_match(info, btf_type->type, false);
		if (err)
			return err;

		/* mark parameters types */
		param = btf_params(btf_type);
		for (i = 0; i < vlen; i++) {
			err = btfgen_mark_type_match(info, param->type, false);
			if (err)
				return err;
			param++;
		}
		break;
	}
	/* tells if some other type needs to be handled */
	default:
		printf("unsupported kind: %s (%d)", btf_kind_str(btf_type), type_id);
		return -EINVAL;
	}

	return 0;
}

/* Mark types, members, and member types. Compared to btfgen_record_field_relo,
 * this function does not rely on the target spec for inferring members, but
 * uses the associated BTF.
 */
static int btfgen_record_type_match_relo(struct btfgen_info *info, struct bpf_core_spec *targ_spec)
{
	return btfgen_mark_type_match(info, targ_spec->root_type_id, false);
}

static int btfgen_record_type_relo(struct btfgen_info *info, struct bpf_core_spec *targ_spec)
{
	return btfgen_mark_type(info, targ_spec->root_type_id, true);
}

static int btfgen_record_enumval_relo(struct btfgen_info *info, struct bpf_core_spec *targ_spec)
{
	return btfgen_mark_type(info, targ_spec->root_type_id, false);
}

static int btfgen_record_reloc(struct btfgen_info *info, struct bpf_core_spec *res)
{
	switch (res->relo_kind) {
	case BPF_CORE_FIELD_BYTE_OFFSET:
	case BPF_CORE_FIELD_BYTE_SIZE:
	case BPF_CORE_FIELD_EXISTS:
	case BPF_CORE_FIELD_SIGNED:
	case BPF_CORE_FIELD_LSHIFT_U64:
	case BPF_CORE_FIELD_RSHIFT_U64:
		return btfgen_record_field_relo(info, res);
	case BPF_CORE_TYPE_ID_LOCAL: /* BPF_CORE_TYPE_ID_LOCAL doesn't require kernel BTF */
		return 0;
	case BPF_CORE_TYPE_ID_TARGET:
	case BPF_CORE_TYPE_EXISTS:
	case BPF_CORE_TYPE_SIZE:
		return btfgen_record_type_relo(info, res);
	case BPF_CORE_TYPE_MATCHES:
		return btfgen_record_type_match_relo(info, res);
	case BPF_CORE_ENUMVAL_EXISTS:
	case BPF_CORE_ENUMVAL_VALUE:
		return btfgen_record_enumval_relo(info, res);
	default:
		return -EINVAL;
	}
}

static struct bpf_core_cand_list *
btfgen_find_cands(const struct btf *local_btf, const struct btf *targ_btf, __u32 local_id)
{
	const struct btf_type *local_type;
	struct bpf_core_cand_list *cands = NULL;
	struct bpf_core_cand local_cand = {};
	size_t local_essent_len;
	const char *local_name;
	int err;

	local_cand.btf = local_btf;
	local_cand.id = local_id;

	local_type = btf__type_by_id(local_btf, local_id);
	if (!local_type) {
		err = -EINVAL;
		goto err_out;
	}

	local_name = btf__name_by_offset(local_btf, local_type->name_off);
	if (!local_name) {
		err = -EINVAL;
		goto err_out;
	}
	local_essent_len = bpf_core_essential_name_len(local_name);

	cands = calloc(1, sizeof(*cands));
	if (!cands)
		return NULL;

	err = bpf_core_add_cands(&local_cand, local_essent_len, targ_btf, "vmlinux", 1, cands);
	if (err)
		goto err_out;

	return cands;

err_out:
	bpf_core_free_cands(cands);
	errno = -err;
	return NULL;
}

// static bool prog_contains_insn(const struct bpf_program *prog, size_t insn_idx)
// {
// 	return insn_idx >= prog->sec_insn_off &&
// 	       insn_idx < prog->sec_insn_off + prog->sec_insn_cnt;
// }

// static struct bpf_program *find_prog_by_sec_insn(const struct bpf_object *obj,
// 						 size_t sec_idx, size_t insn_idx)
// {
// 	int l = 0, r = obj->nr_programs - 1, m;
// 	struct bpf_program *prog;

// 	if (!obj->nr_programs)
// 		return NULL;

// 	while (l < r) {
// 		m = l + (r - l + 1) / 2;
// 		prog = &obj->programs[m];

// 		if (prog->sec_idx < sec_idx ||
// 		    (prog->sec_idx == sec_idx && prog->sec_insn_off <= insn_idx))
// 			l = m;
// 		else
// 			r = m - 1;
// 	}
// 	/* matching program could be at index l, but it still might be the
// 	 * wrong one, so we need to double check conditions for the last time
// 	 */
// 	prog = &obj->programs[l];
// 	if (prog->sec_idx == sec_idx && prog_contains_insn(prog, insn_idx))
// 		return prog;
// 	return NULL;
// }

/* Record relocation information for a single BPF object */
static int btfgen_record_obj(struct btfgen_info *info, const char *obj_path)
{
	const struct btf_ext_info_sec *sec;
	const struct bpf_core_relo *relo;
	const struct btf_ext_info *seg;
	struct hashmap_entry *entry;
	struct hashmap *cand_cache = NULL;
	struct btf_ext *btf_ext = NULL;
	unsigned int relo_idx;
	struct btf *btf = NULL;
	size_t i;
	int err;
	struct bpf_program *prog;
	struct bpf_insn *insn;
	struct bpf_object *obj;
	const char *sec_name;
	int insn_idx, sec_idx, sec_num;

	obj = bpf_object__open(obj_path);
	if (!obj) {
		err = -errno;
		printf("failed to open BPF object '%s': %s", obj_path, strerror(errno));
		return err;
	}
	btf = btf__parse(obj_path, &btf_ext);
	if (!btf) {
		err = -errno;
		printf("failed to parse BPF object '%s': %s\n", obj_path, strerror(errno));
		return err;
	}

	if (!btf_ext) {
		printf("failed to parse BPF object '%s': section %s not found\n",
		      obj_path, BTF_EXT_ELF_SEC);
		err = -EINVAL;
		goto out;
	}

	if (btf_ext->core_relo_info.len == 0) {
		printf("failed to parse BPF object '%s', no inst to relocate\n",
		      obj_path);
		err = 0;
		goto out;
	}

	cand_cache = hashmap__new(btfgen_hash_fn, btfgen_equal_fn, NULL);
	if (IS_ERR(cand_cache)) {
		err = PTR_ERR(cand_cache);
		goto out;
	}

	seg = &btf_ext->core_relo_info;
	// sec_num = 0;
	for_each_btf_ext_sec(seg, sec) {
		// sec_idx = seg->sec_idxs[sec_num];
		// sec_num++;
		// printf("sec_idx: %d\n", sec_idx);
		for_each_btf_ext_rec(seg, sec, relo_idx, relo) {
			struct bpf_core_spec specs_scratch[3] = {};
			struct bpf_core_relo_res targ_res = {};
			struct bpf_core_cand_list *cands = NULL;
			const char *sec_name = btf__name_by_offset(btf, sec->sec_name_off);
			printf("sec_name: %s\n", sec_name);
			
			// prog = find_prog_by_sec_insn(obj, sec_idx, insn_idx);
			// if (!prog) {
			// 	/* When __weak subprog is "overridden" by another instance
			// 	 * of the subprog from a different object file, linker still
			// 	 * appends all the .BTF.ext info that used to belong to that
			// 	 * eliminated subprogram.
			// 	 * This is similar to what x86-64 linker does for relocations.
			// 	 * So just ignore such relocations just like we ignore
			// 	 * subprog instructions when discovering subprograms.
			// 	 */
			// 	pr_debug("sec '%s': skipping CO-RE relocation #%d for insn #%d belonging to eliminated weak subprogram\n",
			// 		 sec_name, i, insn_idx);
			// 	continue;
			// }
			/* no need to apply CO-RE relocation if the program is
			 * not going to be loaded
			 */

			/* adjust insn_idx from section frame of reference to the local
			 * program's frame of reference; (sub-)program code is not yet
			 * relocated, so it's enough to just subtract in-section offset
			 */
			// insn_idx = insn_idx - prog->sec_insn_off;
			// if (insn_idx >= prog->insns_cnt)
			// 	return -EINVAL;
			// insn = &prog->insns[insn_idx];

			if (relo->kind != BPF_CORE_TYPE_ID_LOCAL &&
			    !hashmap__find(cand_cache, relo->type_id, &cands)) {
				cands = btfgen_find_cands(btf, info->src_btf, relo->type_id);
				if (!cands) {
					err = -errno;
					goto out;
				}

				err = hashmap__set(cand_cache, relo->type_id, cands,
						   NULL, NULL);
				if (err)
					goto out;
			}

			err = bpf_core_calc_relo_insn(sec_name, relo, relo_idx, btf, cands,
						      specs_scratch, &targ_res);
			if (err)
				goto out;

			// err = bpf_core_patch_insn(sec_name, insn, insn_idx, relo, relo_idx, &targ_res);
			// if (err) {
			// 	printf("prog '%s': relo #%d: failed to patch insn #%u: %d\n",
			// 		sec_name, relo_idx, insn_idx, err);
			// 	goto out;
			// }
			/* specs_scratch[2] is the target spec */
			err = btfgen_record_reloc(info, &specs_scratch[2]);
			if (err)
				goto out;
		}
	}

out:
	btf__free(btf);
	btf_ext__free(btf_ext);

	if (!IS_ERR_OR_NULL(cand_cache)) {
		hashmap__for_each_entry(cand_cache, entry, i) {
			bpf_core_free_cands(entry->pvalue);
		}
		hashmap__free(cand_cache);
	}

	return err;
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		printf("Usage: %s <obj_path>\n", argv[0]);
		return 1;
	}
	const char *obj_path = argv[1];
	const char* btf_path = argv[2];
	struct btfgen_info* info = btfgen_new_info(btf_path);
	if (!info) {
		printf("failed to create btfgen_info\n");
		return 1;
	}
	return btfgen_record_obj(info, obj_path);
}
