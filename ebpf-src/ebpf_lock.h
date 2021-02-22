#ifndef EBPF_LOCK_H_
#define EBPF_LOCK_H_

#define SPIN_INIT(q) ebpf_lock_init(&(q)->lock);
#define SPIN_LOCK(q) ebpf_lock_lock(&(q)->lock);
#define SPIN_UNLOCK(q) ebpf_lock_unlock(&(q)->lock);
#define SPIN_DESTROY(q) ebpf_lock_destroy(&(q)->lock);

typedef struct ebpf_lock {
	int lock;
} ebpf_lock;

static inline void
ebpf_lock_init(ebpf_lock *lock) {
	lock->lock = 0;
}

#if defined(SYS_CORTEX_M4)

static void arch_irq_lock(void) {
	unsigned int tmp;
	// __asm__ volatile(
	// 	"mov %1, %2;"
	// 	"mrs %0, BASEPRI;"
	// 	"msr BASEPRI, %1;"
	// 	"isb;"
	// 	: "=r"(key), "=r"(tmp)
	// 	: "i"(0)
	// 	: "memory");
}

#endif

#ifdef Win32

static inline void
ebpf_lock_lock(ebpf_lock *lock) {
	while (InterlockedExchange(&lock->lock, 1)) {}
}

static inline void
ebpf_lock_unlock(ebpf_lock *lock) {
	InterlockedExchange(&lock->lock, 0);
	//__sync_lock_release(&lock->lock);
	// __atomic_test_and_set
}

static inline void
ebpf_lock_destroy(ebpf_lock *lock) {
	(void)lock;
}

#endif

#endif // !EBPF_LOCK_H_
