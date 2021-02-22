#ifndef HASHMAP_H_
#define HASHMAP_H_
#include <stdint.h>
#include <stddef.h>

typedef struct list_head {
	struct list_head *next;
} list_head;


typedef struct mapentry {
	void *key;
	void *val;
} mapentry;

typedef struct hashmap {
	mapentry **bukets;
} hashmap;

/*
 * save pointers, do not copy data
 */
typedef struct darray {
	int cur_size;
	int max_size;
	void *vals[0];
} darray;

darray *darray_new(int initial_size);
void darray_destroy(darray *arr);
int darray_add(darray *arr, void *val);
void darray_set(darray *arr, int key, void *val);
void* darray_get(darray *arr, int key);
void darray_del(darray *arr, int key);

// save pointer
/* get O(1)
*/
typedef struct arraymap {
	uint16_t max_size;
	uint16_t cur_size;
	// list_head *del; 
	void **keys;
	void **vals;
} arraymap;

arraymap *arraymap_new(int initial_size);
void arraymap_destroy(arraymap *map);
void arraymap_set(arraymap *map, void *key, void *val);
void* arraymap_get(arraymap *map, void * key);
void arraymap_del(arraymap *map, void * key);

/*
 * red-black tree
 *
 */
typedef struct treemap {
	mapentry *bukets;
} treemap;




#endif
