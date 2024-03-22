#ifndef _EBPF_SPINLOCK_H
#define _EBPF_SPINLOCK_H
#include <stdatomic.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdbool.h>

typedef struct {
    atomic_bool locked;
} ebpf_spinlock_t;

static void ebpf_spinlock_init(ebpf_spinlock_t *lock) {
    atomic_store(&lock->locked, false);
}

static void ebpf_spinlock_lock(ebpf_spinlock_t *lock) {
    while (atomic_exchange(&lock->locked, true)) {
#if defined(__x86_64__) || defined(__i386__)
        __asm__ __volatile__("pause\n" : : : "memory");
#endif
    }
}

static void ebpf_spinlock_unlock(ebpf_spinlock_t *lock) {
    atomic_store(&lock->locked, false);
}

static bool ebpf_spinlock_trylock(ebpf_spinlock_t *lock) {
    return !atomic_exchange(&lock->locked, true);
}

#endif
