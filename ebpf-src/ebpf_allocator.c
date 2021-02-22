#include "ebpf_allocator.h"
#include "ebpf_porting.h"
#include <string.h>
/*

*/

void* ebpf_malloc(size_t size) {
	return (void *) my_os_malloc(size);
}

// void* ebpf_realloc(void* rmem, size_t newsize) {
// 	return (void*) my_os_realloc(rmem, newsize);
// }

void* ebpf_realloc(void *rmem, size_t orisize, size_t newsize) {
	if (newsize == 0) {
		ebpf_free(rmem);
		return NULL;
	} else if (rmem == NULL) {
		return ebpf_malloc(newsize);
	} else if (newsize <= orisize) {
		return rmem;
	} else {
		void *pnew = ebpf_malloc(newsize);
		if (pnew != NULL) {
//			uint8_t *xdes = pnew;
//			uint8_t *xsrc = rmem;
//			while(orisize--) *xdes++ = *xsrc++;
			memcpy(pnew, rmem, orisize);
			ebpf_free(rmem);
		}
		return pnew;
	}
}

void* ebpf_calloc(size_t nelem, size_t elmsize) {
	return (void*) my_os_calloc(nelem, elmsize);
}

void ebpf_free(void* rmem) {
	my_os_free(rmem);
}
