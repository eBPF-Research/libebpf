#ifndef UBPF_TYPES_H_
#define UBPF_TYPES_H_
#include "ebpf_porting.h"
#include <stdbool.h>
#include <stdint.h>

// #define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// platform 
// x64 ebpf
// #ifdef AARH32
// typedef unsigned long uintptr;
// #else
// typedef unsigned long long uintptr;
// #endif // 

typedef uintptr_t uintptr;

#ifndef NULL
#define NULL 0
#endif


typedef unsigned char		u8;
typedef unsigned short		u16;
typedef unsigned int		u32;
typedef unsigned long long	u64;
typedef signed char		s8;
typedef short			s16;
typedef int				s32;
typedef long long		s64;
typedef unsigned long  sz_t;

#ifndef uint32_t

// typedef u8  uint8_t;
// typedef u16 uint16_t;
// typedef u32 uint32_t;
// typedef u64 uint64_t;
// typedef s8  int8_t;
// typedef s16 int16_t;
// typedef s32 int32_t;
// typedef s64 int64_t;

#endif

#define min(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);	\
	_x < _y ? _x : _y; })

#define max(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);	\
	_x > _y ? _x : _y; })

#define min_t(type, a, b) min(((type) a), ((type) b))
#define max_t(type, a, b) max(((type) a), ((type) b))

//#ifndef bool
//typedef int bool;
//#endif
//
//#ifndef true
//#define true 1
//#endif
//
//#ifndef false
//#define false 0
//#endif

static inline u16 __swap16(u16 x)
{
	return (u16) ((((u16)(x) & (u16)0x00ffU) << 8) | (((u16)(x) & (u16)0xff00U) >> 8));
}

static inline u32 __swap32(u32 x) {
	return (u32) ((((u32)(x) & (u32)0x000000ffUL) << 24) |
		(((u32)(x) & (u32)0x0000ff00UL) << 8) | 
		(((u32)(x) & (u32)0x00ff0000UL) >> 8) | 
		(((u32)(x) & (u32)0xff000000UL) >> 24));
}

static inline u64 __swap64(u64 x) {
	return (u64) ((((u64)(x) & (u64)0x00000000000000ffULL) << 56) |
		(((u64)(x) & (u64)0x000000000000ff00ULL) << 40) |
		(((u64)(x) & (u64)0x0000000000ff0000ULL) << 24) |
		(((u64)(x) & (u64)0x00000000ff000000ULL) << 8) |
		(((u64)(x) & (u64)0x000000ff00000000ULL) >> 8) |
		(((u64)(x) & (u64)0x0000ff0000000000ULL) >> 24) |
		(((u64)(x) & (u64)0x00ff000000000000ULL) >> 40) |
		(((u64)(x) & (u64)0xff00000000000000ULL) >> 56));

}


// https://gist.github.com/panzi/6856583
// https://code.woboq.org/gcc/include/bits/byteswap.h.html
// https://elixir.bootlin.com/linux/v5.7.2/source/include/linux/byteorder
#if __BYTE_ORDER == __LITTLE_ENDIAN
// 
	#define my_htole16(x) (x)
	#define my_htole32(x) (x)
	#define my_htole64(x) (x)
// 
	#define my_htobe16(x) __swap16(x)
	#define my_htobe32(x) __swap32(x)
	#define my_htobe64(x) __swap64(x)
#else
// 
	#define my_htole16(x) __swap16(x)
	#define my_htole32(x) __swap32(x)
	#define my_htole64(x) __swap64(x)
// 
	#define my_htobe16(x) (x)
	#define my_htobe32(x) (x)
	#define my_htobe64(x) (x)
#endif

#endif
