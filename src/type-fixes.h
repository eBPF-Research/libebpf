#ifndef TYPE_FIXED_H
#define TYPE_FIXED_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>

typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint64_t u64;
typedef int64_t s64;

#ifndef __ASSEMBLY__

#endif /* __ASSEMBLY__ */

#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (__typeof__(x))(a) - 1)
/* @a is a power of 2 value */
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define PTR_ALIGN(p, a)		((typeof(p))ALIGN((unsigned long)(p), (a)))

#define SZ_1				0x00000001
#define SZ_2				0x00000002
#define SZ_4				0x00000004
#define SZ_8				0x00000008

#define SZ_1K				0x00000400
#define SZ_2K				0x00000800
#define SZ_4K				0x00001000
#define SZ_64K				0x00010000
#define SZ_256K				0x00040000

#define SZ_1M				0x00100000
#define SZ_2M				0x00200000
#define SZ_128M				0x08000000
#define SZ_512M				0x20000000

/**
 * round_up - round up to next specified power of 2
 * @x: the value to round
 * @y: multiple to round up to (must be a power of 2)
 *
 * Rounds @x up to next multiple of @y (which must be a power of 2).
 * To perform arbitrary rounding up, use roundup() below.
 */
#define round_up(x, y) ((((x)-1) | ((__typeof__(x))((y)-1)))+1)

/**
 * round_down - round down to next specified power of 2
 * @x: the value to round
 * @y: multiple to round down to (must be a power of 2)
 *
 * Rounds @x down to next multiple of @y (which must be a power of 2).
 * To perform arbitrary rounding down, use rounddown() below.
 */
#define round_down(x, y) ((x) & ~((__typeof__(x))((y)-1)))

#define BIT(nr)			(1UL << (nr))
#define BIT_ULL(nr)		(1ULL << (nr))

#ifndef min
#define min(x, y) ({                \
   typeof(x) _min1 = (x);          \
   typeof(y) _min2 = (y);          \
   (void) (&_min1 == &_min2);      \
   _min1 < _min2 ? _min1 : _min2; })
#endif

#ifndef max
#define max(x, y) ({                \
   typeof(x) _max1 = (x);          \
   typeof(y) _max2 = (y);          \
   (void) (&_max1 == &_max2);      \
   _max1 > _max2 ? _max1 : _max2; })
#endif

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                  \
    const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
    (type *)( (char *)__mptr - offsetof(type,member) );})

#endif // TYPE_FIXED_H
