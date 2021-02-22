#ifndef JIT_THUMB2_H_
#define JIT_THUMB2_H_
#include "ebpf_types.h"

// typedef unsigned char		u8;
// typedef unsigned short		u16;
// typedef unsigned int		u32;
// typedef unsigned long long	u64;
// typedef signed char		s8;
// typedef short			s16;
// typedef int				s32;
// typedef long long		s64;

// #define USE_JIT_TEST
// #define DEBUG
// #ifdef DEBUG
// #define DEBUG_LOG(...)								\
// do {												\
// 	my_printf(__VA_ARGS__);							\
// } while (0)
// #else
// #define DEBUG_LOG(...) do {} while(0)
// #endif // end DEBUG

#define ERR_IMM(imm) DEBUG_LOG("Invalide imm value. Line:%d Val:%d\n", __LINE__, imm)

/*
ARM®v7-M Architecture Reference Manual

INSTUCTIONS DEFINES
*/
#define THUMB2_IT 0xbf00
#define THUMB2_MOV_REG 0x4600
#define THUMB2_MOVS_REG 0x0000
#define THUMB2_MOVW_REG 0xea4f0000
#define THUMB2_ASRW_REG 0xfa40f000
#define THUMB2_ASRW_IMM 0xea4f0020
#define THUMB2_LSLW_REG 0xfa00f000
#define THUMB2_LSRW_REG 0xfa20f000
#define THUMB2_LSRW_IMM 0xea4f0010
#define THUMB2_ORRW_REG 0xea400000
#define THUMB2_ORR_REG 0x4300 // overflow
#define THUMB2_RSBW_REG 0xebc00000
#define THUMB2_RSBW_IMM 0xf1c00000
#define THUMB2_STR_IMM 0xf8400000
#define THUMB2_STRD_IMM 0xe8400000
#define THUMB2_LDRD_IMM 0xe9500000
#define THUMB2_PUSH_T1 0xb400
#define THUMB2_PUSH_W 0xe92d0000
#define THUMB2_POP_W 0xe8bd0000
#define THUMB2_SUB_IMM_T1 0x1e00
#define THUMB2_SUB_IMM_T2 0x3800
#define THUMB2_SUBW_IMM 0xf2a00000
#define THUMB2_ADD_IMM_T2 0x3000
#define THUMB2_ADD_REG_T2 0x4400
#define THUMB2_ADDW_REG 0xeb000000
#define THUMB2_CMP_REG_T1 0x4280
#define THUMB2_CMP_REG_T2 0x4500
#define THUMB2_CMPW_REG 0xebb00f00
#define THUMB2_SBCW_REG 0xeb600000
#define THUMB2_B_COND_T1 0xd000
#define THUMB2_B_T2 0xe000
#define THUMB2_BLX_REG_T1 0x4780
#define THUMB2_BW_COND_T3 0xf0008000
#define THUMB2_BW_T4 0xf0009000
#define THUMB2_MUL_T2 0xfb00f000
#define THUMB2_UMULL_T2 0xfba00000

#define IT_MASK_NONE 0b1000
#define COND_EQ 0b0000
#define COND_NE 0b0001
#define COND_CS 0b0010
#define COND_CC 0b0011
#define COND_MI 0b0100
#define COND_PL 0b0101
#define COND_VS 0b0110
#define COND_VC 0b0111
#define COND_HI 0b1000
#define COND_LS 0b1001
#define COND_GE 0b1010
#define COND_LT 0b1011
#define COND_GT 0b1100
#define COND_LE 0b1101
#define COND_AL 0b1110 // None, always uncondition

/*
shift LR type: A7-183 A7.4.2 Shift Operations
register shift types
// type: Shift_C(R[m], shift_t, shift_n, APSR.C);
*/
#define SRTYPE_LSL		0
#define SRTYPE_LSR		1
#define SRTYPE_ASR		2
#define SRTYPE_ROR		3
#define SRTYPE_ASL		(SRTYPE_LSL)
/*
Flag S
*/
#define FLAG_NOS   0
#define FLAG_S     1

/*
wback
*/
#define WBACK_NO 0
#define WBACK_YES 1

/*
// sp must 8-bit aligned
// PUSH and POP are always 32-bit, and the addresses of the
// transfers in stack operations must be aligned to 32-bit word boundaries
*/
#define CALLEE_MASK	(1 << ARM_R4 | 1 << ARM_R5 | 1 << ARM_R6 | \
			 1 << ARM_R7 | 1 << ARM_R8 | 1 << ARM_R9 | 1 << ARM_FP)
#define CALLEE_PUSH_MASK (CALLEE_MASK | 1 << ARM_LR)
#define CALLEE_POP_MASK  (CALLEE_MASK | 1 << ARM_PC)

/*
Rd: destination, dst
Rn: first op, src
Rm: second op, shift base
Rnt: dst and second op
*/

static inline u32 _thumb32_UMULL_T2(s8 RdLo, s8 RdHi, s8 Rn, s8 Rm) {
    return (THUMB2_UMULL_T2) | (Rn << 16) | (RdLo << 12) | (RdHi << 8) | (Rm);
}

static inline u32 _thumb32_MUL_T2(s8 Rd, s8 Rn, s8 Rm) {
    return (THUMB2_MUL_T2) | (Rn << 16) | (Rd << 8) | (Rm);
}

static inline u16 _thumb16_IT_T1(u8 cond, u8 mask) {
    return (THUMB2_IT) | (cond << 4) | (mask);
}

static inline u32 _thumb32_RSBW_IMM_T2(s8 Rd, s8 Rn, s32 shiftImm12, u8 flagS) {
    s32 imm8 = shiftImm12 & 0xff;
    s32 imm3 = (shiftImm12 >> 8) & 0b111;
    s32 i = (shiftImm12 >> 11) & 0x1;
    return (THUMB2_RSBW_IMM) | (i << 26) | (flagS << 20) | (Rn << 16) | (imm3 << 12) | (Rd << 8) | (imm8);
}

static inline u32 _thumb32_RSBW_REG_T1(s8 Rd, s8 Rn, s8 Rm, s32 shiftImm5, u8 srtype, u8 flagS) {
    s32 imm2 = shiftImm5 & 0b11;
    s32 imm3 = (shiftImm5 >> 2) & 0b111;
    return (THUMB2_RSBW_REG) | (flagS << 20) | (Rn << 16) | (imm3 << 12) | (Rd << 8) |
        (imm2 << 6) | (srtype << 4) | (Rm);
}

static inline u16 _thumb16_B_T1(s32 offImm9, s8 cond) {
    u16 imm8 = (offImm9 >> 1) & 0x00ff;
    return (THUMB2_B_COND_T1) | (cond << 8) | (imm8);
}

static inline u16 _thumb16_B_T2(s32 offImm12) {
    u32 imm11 = (offImm12 >> 1) & 0x7ff;
    return (THUMB2_B_T2) | (imm11);
}

static inline u16 _thumb16_BLX_REG_T1(s8 Rm) {
    return (THUMB2_BLX_REG_T1) | (Rm << 3);
}

static inline u32 _thumb32_BW_T3(s32 offImm20, s8 cond) {
    u32 S = offImm20 < 0;
    u32 imm11 = (offImm20 >> 1) & 0x7ff;
    u32 imm6 = (offImm20 >> 12) & 0x3f;
    u32 J1 = (offImm20 >> 18) & 0x1;
    u32 J2 = (offImm20 >> 19) & 0x1;
    return (THUMB2_BW_COND_T3) | (S << 26) | (cond << 22) | (imm6 << 16) | (J1 << 13) | (J2 << 11) | (imm11);
}

static inline u32 _thumb32_BW_T4(s32 offImm23) {
    s32 S = offImm23 < 0;
    s32 imm11 = (offImm23 >> 1) & 0x7ff;
    s32 imm10 = (offImm23 >> 12) & 0x3ff;
    s32 I1 = (offImm23 >> 18) & 0x1;
    s32 I2 = (offImm23 >> 19) & 0x1;
    s32 J1 = (~I1 ^ S) & 0x1;
    s32 J2 = (~I2 ^ S) & 0x1;
    return (THUMB2_BW_COND_T3) | (S << 26) | (imm10 << 16) | (J1 << 13) | (J2 << 11) | (imm11);
}

static inline u32 _thumb32_SBCW_T2(s8 Rd, s8 Rn, s8 Rm, s32 shiftImm5, u8 srtype, u8 flagS) {
    s32 imm3 = (shiftImm5 >> 2) & 0b111;
    s32 imm2 = shiftImm5 & 0b11;
    return (THUMB2_SBCW_REG) | (flagS << 20) | (Rn << 16) | (imm3 << 12) | (Rd << 8) |
         (imm2 << 6) | (srtype << 4) | (Rm);
}

static inline u16 _thumb16_CMP_REG_T1(s8 Rn, s8 Rm) {
    return (THUMB2_CMP_REG_T1) | (Rm << 3) | (Rn);
}

static inline u16 _thumb16_CMP_REG_T2(s8 Rn, s8 Rm) {
    u16 N = (Rn & 0b1000) >> 3;
    u16 Rn3 = Rn & 0b111;
    return (THUMB2_CMP_REG_T2) | (N << 7) | (Rm << 3) | (Rn3);
}

static inline u32 _thumb32_CMPW_REG_T3(s8 Rn, s8 Rm, s32 offImm5, u8 srtype) {
    u32 imm3 = (offImm5 >> 2) & 0b111;
    u32 imm2 = offImm5 & 0b11;
    return (THUMB2_CMPW_REG) | (Rn << 16) | (imm3 << 12) | 
        (imm2 << 6) | (srtype << 4) | (Rm);
}

static inline u16 _thumb16_ADD_IMM_T2(s8 RDn, s32 imm8) {
    u16 imm = imm8 & 0xff;
    return (THUMB2_ADD_IMM_T2) | (RDn << 8) | (imm);
}

static inline u16 _thumb16_ADD_REG_T2(s8 RDn, s8 Rm) {
    u16 DN = (RDn >> 3) & 0x1;
    u16 rdn = RDn & 0b111;
    return (THUMB2_ADD_REG_T2) | (DN << 7) | (Rm << 3) | (rdn);
}

static inline u32 _thumb32_ADDW_REG_T3(s8 Rd, s8 Rn, s8 Rm, s32 offImm5, u8 srtype, u8 flagS) {
    u32 imm3 = (offImm5 >> 2) & 0b111;
    u32 imm2 = offImm5 & 0b11;
    return (THUMB2_ADDW_REG) | (flagS << 20) | (Rn << 16) | (imm3 << 12) | (Rd << 8) | 
        (imm2 << 6) | (srtype << 4) | (Rm);
}

static inline u16 _thumb16_MOV_REG_T1(s8 Rd, s8 Rm) {
    u16 D = (Rd >> 3) & 0b1000;
    u16 Rd3 = Rd & 0b111;
    return (THUMB2_MOV_REG) | (D << 7) | (Rm << 3) | (Rd3);
}

static inline u16 _thumb16_MOVS_REG_T2(s8 Rd, s8 Rm) {
    return (THUMB2_MOVS_REG) | (Rm << 3) | (Rd);
}

static inline u32 _thumb32_MOVW_REG_T3(s8 Rd, s8 Rm, u8 flagS) {
    return (THUMB2_MOVW_REG) | (flagS << 20) | (Rd << 8) | (Rm);
}

static inline u16 _thumb16_SUB_IMM_T1(s8 Rd3, s8 Rn3, s32 imm3) {
    imm3 = imm3 & 0b111;
    return (THUMB2_SUB_IMM_T1) | (imm3 << 6) | (Rn3 << 3) | (Rd3);
}

static inline u16 _thumb16_SUB_IMM_T2(s8 Rdn3, s32 imm8) {
    imm8 = imm8 & 0xff;
    return (THUMB2_SUB_IMM_T1) | (Rdn3 << 8) | imm8;
}

static inline u32 _thumb32_SUBW_IMM_T4(s8 Rd, s8 Rn, s32 imm12, u8 flagS) {
    u32 i = (imm12 >> 11) & 0x1;
    u32 imm3 = (imm12 >> 8) & 0b11;
    u32 imm8 = imm12 & 0xff;
    return (THUMB2_SUBW_IMM) | (i << 26) | (Rn << 16) | (imm3 << 12) | (Rd << 8) | (imm8); 
}

static inline u16 _thumb16_PUSH_T1(s32 reg_mask) {
    u16 M = (reg_mask >> 14) & 0x1;
    u16 reg_list = reg_mask & 0xff;
    return (THUMB2_PUSH_T1) | (M << 8) | (reg_list);
}

static inline u32 _thumb32_PUSHW_T2(s32 reg_mask) {
    u32 M = (reg_mask >> 14) & 0x1;
    u32 reg_list = reg_mask & 0x1fff;
    return (THUMB2_PUSH_W) | (M << 14) | (reg_list);
}

static inline u32 _thumb32_POPW_T2(s32 reg_mask) {
    u32 M = (reg_mask >> 14) & 0x1;
    u32 P = (reg_mask >> 15) & 0x1;
    u32 reg_list = reg_mask & 0x1fff;
    return (THUMB2_POP_W) | (P << 15) | (M << 14) | (reg_list);
}

static inline u32 _thumb32_LDRD_IMM_T1(s8 Rt[], s8 Rn, s32 offImm8, u8 wback) {
    if (offImm8 < -255 || offImm8 > 255) {
        // DEBUG_LOG("Invalide imm value. Line:%d Val:%d\n", __LINE__, offImm8);
        return -1;
    }
    u32 P = offImm8 != 0, U = offImm8 > 0;
    u32 imm8 = offImm8 > 0 ? offImm8 : -offImm8;
    imm8 = imm8 & 0xff;
    u32 flag = (P << 3) | (U << 2) | (wback & 0x1);
    u32 inst = (THUMB2_LDRD_IMM) | (flag << 21) | (Rn << 16) | (Rt[1] << 12) | (Rt[0] << 8) | (imm8);
    return inst;
}

static inline u32 _thumb32_STRD_IMM_T1(s8 RnSrc[], s8 RtDst,  s16 offImm8) {
    u32 P = offImm8 != 0;
    u32 U = offImm8 > 0, W = 0;
    u32 imm8 = offImm8 > 0 ? offImm8 : -offImm8;
    u32 inst = (THUMB2_STRD_IMM) | (P << 24) | (U << 23) | (W << 22) | 
        (RtDst << 16) | (RnSrc[1] << 12) | (RnSrc[0] << 8) | (imm8);
    return inst;
}

static inline u32 _thumb32_ASRW_IMM_T2(s8 Rd, s8 Rm, s32 imm5, u8 flagS) {
    u32 imm3 = (imm5 >> 2) & 0b111;
    u32 imm2 = imm5 & 0b11;
    return (THUMB2_ASRW_IMM) | (flagS << 20) | (imm3 << 12) | (Rd << 8) | (imm2 << 6) | (Rm);
}

static inline u32 _thumb32_ASRW_REG_T2(s8 Rd, s8 Rn, s8 Rm, u8 flagS) {
    return (THUMB2_ASRW_REG) | (flagS << 20) | (Rn << 16) | (Rd << 8) | (Rm);
}

static inline u32 _thumb32_LSLW_REG_T2(s8 Rd, s8 Rn, s8 Rm, u8 flagS) {
    return (THUMB2_LSLW_REG) | (flagS << 20) | (Rn << 16) | (Rd << 8) | (Rm);
}

// ARM_MOV_SR
static inline u32 _thumb32_LSRW_REG_T2(s8 Rd, s8 Rn, s8 Rm, u8 flagS) {
    return (THUMB2_LSRW_REG) | (flagS << 20) | (Rn << 16) | (Rd << 8) | (Rm);
}

// ARM_MOV_SI Page A7-282
static inline u32 _thumb32_LSRW_IMM_T2(s8 Rd, s8 Rm, s32 shiftImm5, u8 flagS) {
    if (shiftImm5 < 0 || shiftImm5 > 0b11111) {
        // DEBUG_LOG("Invalide imm value. Line:%d Val:%d\n", __LINE__, shiftImm5);
        return -1;
    }
    u32 imm3 = (shiftImm5 >> 2) & 0b111;
    u32 imm2 = shiftImm5 & 0b11; 
    u32 inst = (THUMB2_LSRW_IMM) | (flagS << 20) | (imm3 << 12) | (Rd << 8) | (imm2 << 6) | (Rm);
    return inst;
}

// ARM_ORR_SI Page A7-310
// type: Shift_C(R[m], shift_t, shift_n, APSR.C);
static inline u32 _thumb32_ORRW_REG_T2(s8 Rd, s8 Rn, s8 Rm, s32 shiftImm5, u8 srtype, u8 flagS) {
    if (shiftImm5 < 0 || shiftImm5 > 0b11111) {
        // DEBUG_LOG("Invalide imm value. Line:%d Val:%d\n", __LINE__, shiftImm5);
        return -1;
    }
    u32 imm3 = (shiftImm5 >> 2) & 0b111;
    u32 imm2 = shiftImm5 & 0b11; 
    u32 inst = (THUMB2_ORRW_REG) | (flagS << 20) | (Rn << 16) | (imm3 << 12)
             | (Rd << 8) | (imm2 << 6) | (srtype << 4) | (Rm); 
    return inst;
}

#ifdef USE_JIT_TEST
static void test_all_inst() {
    DEBUG_LOG("_thumb32_LSRW_IMM_T2: %x -> lsr.w r1, r2, #5\n", _thumb32_LSRW_IMM_T2(1, 2, 5, FLAG_NOS));
    DEBUG_LOG("_thumb32_ORRW_REG_T2: %x -> orr.w r1, r2, r3, lsl #5\n", _thumb32_ORRW_REG_T2(1, 2, 3, 5, SRTYPE_LSL, FLAG_NOS));
}
#endif // USE_JIT_TEST

#endif
