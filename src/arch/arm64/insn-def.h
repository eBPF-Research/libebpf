/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __ASM_INSN_DEF_H
#define __ASM_INSN_DEF_H

#define FAULT_BRK_IMM			0x100

/* A64 instructions are always 32 bits. */
#define	AARCH64_INSN_SIZE		4

/*
 * BRK instruction encoding
 * The #imm16 value should be placed at bits[20:5] within BRK ins
 */
#define AARCH64_BREAK_MON	0xd4200000

/*
 * BRK instruction for provoking a fault on purpose
 * Unlike kgdb, #imm16 value with unallocated handler is used for faulting.
 */
#define AARCH64_BREAK_FAULT	(AARCH64_BREAK_MON | (FAULT_BRK_IMM << 5))


/*
 * PSR bits
 */
#define PSR_MODE_EL0t	0x00000000
#define PSR_MODE_EL1t	0x00000004
#define PSR_MODE_EL1h	0x00000005
#define PSR_MODE_EL2t	0x00000008
#define PSR_MODE_EL2h	0x00000009
#define PSR_MODE_EL3t	0x0000000c
#define PSR_MODE_EL3h	0x0000000d
#define PSR_MODE_MASK	0x0000000f

/* AArch32 CPSR bits */
#define PSR_MODE32_BIT		0x00000010

/* AArch64 SPSR bits */
#define PSR_F_BIT	0x00000040
#define PSR_I_BIT	0x00000080
#define PSR_A_BIT	0x00000100
#define PSR_D_BIT	0x00000200
#define PSR_BTYPE_MASK	0x00000c00
#define PSR_SSBS_BIT	0x00001000
#define PSR_PAN_BIT	0x00400000
#define PSR_UAO_BIT	0x00800000
#define PSR_DIT_BIT	0x01000000
#define PSR_TCO_BIT	0x02000000
#define PSR_V_BIT	0x10000000
#define PSR_C_BIT	0x20000000
#define PSR_Z_BIT	0x40000000
#define PSR_N_BIT	0x80000000

#define PSR_BTYPE_SHIFT		10

#define cpu_to_le64(x) (( __le64)(__u64)(x))
#define le64_to_cpu(x) (( __u64)(__le64)(x))
#define cpu_to_le32(x) (( __le32)(u32)(x))
#define le32_to_cpu(x) (( u32)(__le32)(x))
#define cpu_to_le16(x) (( __le16)(__u16)(x))
#define le16_to_cpu(x) (( __u16)(__le16)(x))

static __always_inline __le64 __cpu_to_le64p(const __u64 *p)
{
	return ( __le64)*p;
}
static __always_inline __u64 __le64_to_cpup(const __le64 *p)
{
	return ( __u64)*p;
}
static __always_inline __le32 __cpu_to_le32p(const u32 *p)
{
	return ( __le32)*p;
}
static __always_inline u32 __le32_to_cpup(const __le32 *p)
{
	return ( u32)*p;
}
static __always_inline __le16 __cpu_to_le16p(const __u16 *p)
{
	return ( __le16)*p;
}
static __always_inline __u16 __le16_to_cpup(const __le16 *p)
{
	return ( __u16)*p;
}

/*
 * BUILD_BUG_ON_ZERO is not available in h files included from asm files,
 * disable the input check if that is the case.
 */
#define GENMASK_INPUT_CHECK(h, l) 0
#define BITS_PER_LONG 64
#define __GENMASK(h, l) \
	(((~(0UL)) - ((1UL) << (l)) + 1) & \
	 (~(0UL) >> (BITS_PER_LONG - 1 - (h))))
#define GENMASK(h, l) \
	(GENMASK_INPUT_CHECK(h, l) + __GENMASK(h, l))

#endif /* __ASM_INSN_DEF_H */
