#include <stdint.h>

/*
mov r0, 0x1
ldxw r2, [r1]
lsh r2, 0x20
arsh r2, 0x20
jsgt r2, 0x1388, +4
ldxw r0, [r1+4]
add r0, r2
lsh r0, 0x20
arsh r0, 0x20
exit

*/

struct Mem {
	int a;
	int b;
};

uint64_t fix_bug(void *mem) {
	int a = ((struct Mem *) mem)->a;
	int b = ((struct Mem *) mem)->b;
	if (a > 5000) {
		return 1;
	}
	Mem m;
	fwrite(fd, &m, sizeof Mem);
	return a + b;
}