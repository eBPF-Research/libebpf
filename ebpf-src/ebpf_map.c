#include "ebpf_map.h"
#include <string.h>
#include <stdio.h>
#include "ebpf_allocator.h"

/*------------------------------------------------------------------------
	ebpf dynamic array
*/
typedef struct DArray {
	int end;
	int max;
	sz_t el_sz;
	void **contents;
} DArray;

DArray* DArray_create(sz_t el_sz, sz_t initial_max) {
	DArray *arr = ebpf_malloc(sizeof(DArray));
	arr->max = initial_max;
	arr->el_sz = el_sz;
	arr->end = 0;
	arr->contents = ebpf_calloc(initial_max, sizeof(void *));
	return arr;
}

void DArray_set(DArray* arr, int index, void *val) {
	if (index >= arr->max) {
		return;
	}
	if (index > arr->end) {
		arr->end = index;
	}
	arr->contents[index] = val;
}

DArray* DArray_get(DArray* arr, int index) {
	if (index < arr->max) {
		return arr->contents[index];
	}
	return NULL;
}

int DArray_push(DArray *arr, void *el) {
	arr->contents[arr->end] = el;
	arr->end++;
	if (arr->end >= arr->max) {
		//return DArray_expand(arr);
	}
	return 0;
}

void* DArray_pop(DArray *arr) {
	if (arr->end > 0) {
		void *el = arr->contents[arr->end - 1];
		arr->contents[arr->end - 1] = NULL;
		arr->end--;
		return el;
	}
	return NULL;
}

void DArray_destory(DArray* arr) {
	
}

void DArray_clear(DArray* arr) {

}

static inline int DArray_resize(DArray *arr, int new_sz) {
	void * contents = ebpf_realloc(arr->contents, arr->max * sizeof(void *), new_sz * sizeof(void *));
	arr->max = new_sz;
	if (contents == NULL) {
		return -1;
	}
	arr->contents = contents;
	return 0;
}

int DArray_expand(DArray* arr) {
	int old_max = arr->max;
	int step = 5;
	if (old_max > 100) {
		step *= 2;
	}
	step = step > 1000 ? 1000 : step;
	return DArray_resize(arr, old_max + step);
}

static u32 str_hash_fn(const void *key)
{
	char *skey = (char *)key;
	int len = strlen(skey);
	u32 hash = 0;
	for (int i = 0; i < len; i++) {
		hash += skey[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return hash;
}

static bool str_equal_fn(const void *a, const void *b)
{
	return strcmp(a, b) == 0;
}

// typedef int (*Hashmap_cmp) (void *key1, void *key2);
// typedef u32 (*Hashmap_hash)(void *key);

typedef struct Hashmap {
	DArray *buckets;
	u32 bucket_num;
	int(*Hashmap_cmp) (void *key1, void *key2);
	u32 (*Hashmap_hash)(void *key);
} Hashmap;

typedef struct HashmapNode {
	void *key;
	void *value;
	u32 hash;
} HashmapNode;

Hashmap *Hashmap_create() {
	Hashmap *map = ebpf_calloc(1, sizeof(Hashmap));
	map->Hashmap_cmp = str_equal_fn;
	map->Hashmap_hash = str_hash_fn;
	map->bucket_num = 8;
	map->buckets = DArray_create(sizeof(DArray*), map->bucket_num);
	map->buckets->end = map->bucket_num;
	return map;
}

void Hashmap_destroy(Hashmap * map) {

}

static inline HashmapNode* Hashmap_node_create(int hash, void *key, void *val) {
	HashmapNode *node = calloc(1, sizeof(HashmapNode));
	node->key = key;
	node->hash = hash;
	node->value = val;
	return node;
}

static inline DArray* Hashmap_find_bucket(Hashmap *map, void *key, int create, u32 *hash_out) {
	u32 hash = map->Hashmap_hash(key);
	int bucket_index = hash % map->bucket_num;
	*hash_out = hash;
	DArray *bucket = DArray_get(map->buckets, bucket_index);
	if (!bucket && create) {
		bucket = DArray_create(sizeof(void*), 10);
		DArray_set(map->buckets, bucket_index, bucket);
	}
	return bucket;
}

int Hashmap_set(Hashmap * map, void *key, void *data) {
	u32 hash = 0;
	DArray *bucket = Hashmap_find_bucket(map, key, 1, &hash);
	HashmapNode *node = Hashmap_node_create(hash, key, data);
	DArray_push(bucket, node);
	return 0;
}

static inline int Hashmap_get_node(Hashmap *map, u32 hash, DArray *bucket, void *key) {
	for (int i = 0; i < bucket->end; i++) {
		HashmapNode *node = DArray_get(bucket, i);
		if (node->hash == hash && map->Hashmap_cmp(node->key, key)) {
			return i;
		}
	}
	return -1;
}

void *Hashmap_get(Hashmap * map, void *key) {
	u32 hash = 0;
	DArray *bucket = Hashmap_find_bucket(map, key, 0, &hash);
	if (!bucket) {
		return NULL;
	}
	int i = Hashmap_get_node(map, hash, bucket, key);
	if (i == -1) {
		return NULL;
	}
	HashmapNode *node = DArray_get(bucket, i);
	return node->value;
}

void *Hashmap_delete(Hashmap * map, void *key) {
	u32 hash = 0;
	DArray *bucket = Hashmap_find_bucket(map, key, 0, &hash);
	int i = Hashmap_get_node(map, hash, bucket, key);
	if (i == -1) {
		return NULL;
	}
	HashmapNode *cur = DArray_get(bucket, i);
	void *val = cur->value;
	
	HashmapNode *tail = DArray_pop(bucket);
	if (tail != cur) {
		DArray_set(bucket, i, tail);
	}
	ebpf_free(cur);

	return val;
}

void dump_hashmap(Hashmap *map) {

}

void test_hashmap_pass1() {
	Hashmap *map = Hashmap_create();
	char k1[] = "key1";
	char v1[] = "value1";
	for (int i = 0; i < 1000; i++) {
		char key[10] = { 0 };
		sprintf(key, "key%d", i);
		char val[10] = { 0 };
		sprintf(val, "val%d", i);
		Hashmap_set(map, key, val);
		printf("round: %d get value: %s\n", i, Hashmap_get(map, key));
		Hashmap_delete(map, key);
	}
	Hashmap_set(map, k1, v1);
	void *v2 = Hashmap_get(map, k1);
	printf("get value: %s\n", v2);
	Hashmap_delete(map, k1);
	void *v3 = Hashmap_get(map, k1);
	printf("get value: %s\n", v3);
}
/*------------------------------------------------------------------------
	ebpf hashtable API
	Rewrite naive hashmap
*/

// better hash map
typedef struct hashmap_entry {
	const void *key;
	void *value;
	struct hashmap_entry *next;
} hashmap_entry;

typedef struct hashmap {

	hashmap_entry **buckets;

	sz_t cap;
	sz_t sz;
} hashmap;


/*------------------------------------------------------------------------
	ebpf hashtable API
	TODO:
	1. naive hashmap
	2. save struct
	3. mininal api: set/get/del
*/

typedef struct NaiveHashmap {
	ebpf_map map;
	Hashmap naive_hashmap;
} NaiveHashmap;

//ebpf_map_ops hashmap_ops = {
//	.map_lookup_elem = Hash
//};