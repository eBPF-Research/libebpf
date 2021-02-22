#ifndef EBPF_PORTING_H_
#define EBPF_PORTING_H_

// #define LINUX_TEST
// #define AARH64

//#define RT_THREAD

/*
endian
*/


#ifdef RT_THREAD
// https://github.com/RT-Thread/rt-thread/blob/b2e800d1624b444f9ab52d6f5f0050404a94c50a/components/libc/compilers/armlibc/mem_std.c
#include "rtthread.h"

#define my_os_malloc rt_malloc
#define my_os_calloc rt_calloc
#define my_os_realloc rt_realloc
#define my_os_free rt_free

#endif
#if defined(Win32) || defined(LINUX_TEST)
#include <stdlib.h>
#define my_os_malloc malloc
#define my_os_calloc calloc
#define my_os_realloc realloc
#define my_os_free free

#define DEBUG_LOG printf

#else

#if defined(NRF52_NO_OS)

#define my_os_malloc malloc
#define my_os_calloc calloc
#define my_os_realloc realloc
#define my_os_free free
#endif // NRF52_NO_OS

#if defined(ZEPHYR_OS)
#include <zephyr.h>

// static void* k_realloc(void *rmem, size_t newsize) {
// 	if (newsize == 0) {
// 		k_free(rmem);
// 		return NULL;
// 	} else if (rmem == NULL) {
// 		return k_malloc(newsize);
// 	} else {
// 		void *pnew = k_malloc(newsize);
// 		if (pnew) {
// 			memcpy(pnew, rmem, newsize - 4);
// 			k_free(rmem);
// 		}
// 		return pnew;
// 	}
// }

#define my_os_malloc k_malloc
#define my_os_calloc k_calloc
// #define my_os_realloc k_realloc
#define my_os_free k_free

#endif // end ZEPHYR_OS

#ifdef STM32L475_NO_OS
#include "malloc.h"
#include <string.h>

static void* my_malloc(size_t size) {
	return mymalloc(1, size);
}

static void* my_calloc(size_t nelem, size_t elmsize) {
	size_t size = nelem * elmsize;
	void *mem = mymalloc(1, size);
	memset(mem, 0, size);
	return mem;
}

static void my_free(void* rmem) {
	myfree(1, rmem);
}

#define my_os_malloc my_malloc
#define my_os_calloc my_calloc
//#define my_os_realloc realloc
#define my_os_free my_free

#endif

#ifdef DEV_QEMU

#define my_os_malloc malloc
#define my_os_calloc calloc
#define my_os_realloc realloc
#define my_os_free free

#endif

 
#endif // else window or Linux

#endif
