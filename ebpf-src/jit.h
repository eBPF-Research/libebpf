#ifndef JIT_H_
#define JIT_H_
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/*
TODO:
move test function to jit_dev_test
*/

void jit_run_test();
void run_all_tests();
void run_jit_func(uint8_t *code, int code_len, void *ctx);


#define EBPF_STACK_SIZE 256
#define JIT_FINISH 0xffff


struct ebpf_vm;
void gen_jit_code(struct ebpf_vm *vm);

#define JIT_STATIC_MEM
// static mem or dynamic allocate
typedef struct jit_mem {
    uint8_t *jit_code;
    int code_size;
    uint8_t *jmp_offsets;
} jit_mem;

jit_mem* jit_mem_allocate(int insts_num);
void jit_mem_free(jit_mem *mem);

struct ebpf_inst;
typedef struct jit_state {
    struct ebpf_inst *insts;
    int inst_num;
    uint8_t *jit_code;
    int size;
    int idx;
    int err_line;
    uint32_t *offsets;
    uint32_t __bpf_call_base;
    jit_mem *jmem;
    // int inst_loc;
    bool needGen; // pre-pass or generate-pass
} jit_state;

void jit_compile(jit_state *state);
void jit_dump_inst(jit_state *state);
void jit_state_set_mem(jit_state *state, jit_mem *mem);

static inline void
emit_bytes(struct jit_state *state, void *data, uint32_t len) 
{
    // my_printf("emit_bytes: %s 0x%x\n", state->jit_code, *((uint16_t*) data));
    if (state->needGen) {
        memcpy(state->jit_code + state->idx, data, len);
    }
    
    // uint8_t *d = (uint8_t *) data;
    // for (int i = 0; i < len; i++) {
    //     state->jit_code[state->idx + i] = d[i];
    //     my_printf("state->jit_code[%d] = 0x%x\n", state->idx + i, d[i]);
    // }
    state->idx += len;
}

// static inline void
// emit1(struct jit_state *state, uint8_t x)
// {
//     emit_bytes(state, &x, sizeof(x));
// }

static inline void
emit2(struct jit_state *state, uint16_t x)
{
    emit_bytes(state, &x, sizeof(x));
    //state->inst_loc += 1;
}

// little edian
static inline void
emit4(struct jit_state *state, uint32_t x)
{
    uint16_t *u2 = (uint16_t *) (&x);
    emit2(state, u2[1]);
    emit2(state, u2[0]);
    // emit_bytes(state, &u2[1], sizeof(u2[1]));
    // emit_bytes(state, &u2[0], sizeof(u2[0]));
}

#endif
