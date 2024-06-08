#ifndef _EBPF_SPINLOCK_H
#define _EBPF_SPINLOCK_H
#include <stdatomic.h>
#include <stdbool.h>

typedef struct {
    bool locked;
} ebpf_spinlock_t;

static void ebpf_spinlock_init(volatile ebpf_spinlock_t *lock) {
    __atomic_clear(&lock->locked, __ATOMIC_SEQ_CST);
}

static void ebpf_spinlock_lock(ebpf_spinlock_t *lock) {
    while (__atomic_test_and_set(&lock->locked, __ATOMIC_SEQ_CST)) {
#if defined(__x86_64__) || defined(__i386__)
        __asm__ __volatile__("pause\n" : : : "memory");
#endif
    }
}

static void ebpf_spinlock_unlock(ebpf_spinlock_t *lock) {
     __atomic_clear(&lock->locked, __ATOMIC_SEQ_CST);
}

static bool ebpf_spinlock_trylock(ebpf_spinlock_t *lock) {
    return !__atomic_test_and_set(&lock->locked, __ATOMIC_SEQ_CST);
}

#endif
