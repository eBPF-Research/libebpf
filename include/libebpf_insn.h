#ifndef _LIBEBPF_INSN_H
#define _LIBEBPF_INSN_H

#include <stdint.h>
struct libebpf_insn {
    union {
        uint8_t code;
        struct {
            uint8_t insn_class : 3;
            uint8_t src : 1;
            uint8_t code : 4;
        } code_alu;
        struct {
            uint8_t insn_class : 3;
            uint8_t size : 2;
            uint8_t mode : 3;
        } code_load_store;
    };
    uint8_t src_reg : 4;
    uint8_t dst_reg : 4;
    uint16_t offset;
    uint32_t imm;
};

#define BPF_CLASS_LD 0x00
#define BPF_CLASS_LDX 0x01
#define BPF_CLASS_ST 0x02
#define BPF_CLASS_STX 0x03
#define BPF_CLASS_ALU 0x04
#define BPF_CLASS_JMP 0x05
#define BPF_CLASS_JMP32 0x06
#define BPF_CLASS_ALU64 0x07

#define BPF_SOURCE_K 0x00
#define BPF_SOURCE_X 0x08

#define BPF_ALU_ADD 0x00
#define BPF_ALU_SUB 0x10
#define BPF_ALU_MUL 0x20
#define BPF_ALU_DIV_SDIV 0x30
#define BPF_ALU_OR 0x40
#define BPF_ALU_AND 0x50
#define BPF_ALU_LSH 0x60
#define BPF_ALU_RSH 0x70
#define BPF_ALU_NEG 0x80
#define BPF_ALU_MOD_SMOD 0x90
#define BPF_ALU_XOR 0xa0
#define BPF_ALU_MOV_MOVSX 0xb0
#define BPF_ALU_ARSH 0xc0
#define BPF_ALU_END 0xd0

#define BPF_END_TO_LE 0x00
#define BPF_END_TO_BE 0x08

#define BPF_JMP_JA 0x00
#define BPF_JMP_JEQ 0x10
#define BPF_JMP_JGT 0x20
#define BPF_JMP_JGE 0x30
#define BPF_JMP_JSET 0x40
#define BPF_JMP_JNE 0x50
#define BPF_JMP_JSGT 0x60
#define BPF_JMP_JSGE 0x70
#define BPF_JMP_CALL 0x80
#define BPF_JMP_EXIT 0x90
#define BPF_JMP_JLT 0xa0
#define BPF_JMP_JLE 0xb0
#define BPF_JMP_JSLT 0xc0
#define BPF_JMP_JSLE 0xd0

#define BPF_LS_MODE_IMM 0x00
#define BPF_LS_MODE_ABS 0x20
#define BPF_LS_MODE_IND 0x40
#define BPF_LS_MODE_MEM 0x60
#define BPF_LS_MODE_MEMSX 0x80
#define BPF_LS_MODE_ATOMIC 0xc0

// Byte
#define BPF_LS_SIZE_B 0x10
// 2 bytes
#define BPF_LS_SIZE_H 0x08
// 4 bytes
#define BPF_LS_SIZE_W 0x00
// 8 bytes
#define BPF_LS_SIZE_DW 0x18

#define BPF_ATOMIC_ADD 0x00
#define BPF_ATOMIC_OR 0x40
#define BPF_ATOMIC_AND 0x50
#define BPF_ATOMIC_XOR 0xa0
#define BPF_ATOMIC_FETCH 0x01
#define BPF_ATOMIC_XCHG 0xe0 | BPF_ATOMIC_FETCH
#define BPF_ATOMIC_CMPXCHG 0xf0 | BPF_ATOMIC_FETCH

#endif
