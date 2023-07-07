#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include "hook.h"

struct regs {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15;
};

void my_patch_function(struct regs* r) {
    printf("Hello from hook! ");
    int parm1 = r->rdi;
    char* str = (char*)r->rsi;
    char c = (char)r->rdx;
    printf("Args: %d, %s, %c\n", parm1, str, c);
}

void my_hook_function() {
    struct regs r;
    asm volatile (
        "mov %%rax, %0\n"
        "mov %%rbx, %1\n"
        "mov %%rcx, %2\n"
        "mov %%rdx, %3\n"
        "mov %%rsi, %4\n"
        "mov %%rdi, %5\n"
        "mov %%rbp, %6\n"
        "mov %%r8, %7\n"
        "mov %%r9, %8\n"
        "mov %%r10, %9\n"
        "mov %%r11, %10\n"
        "mov %%r12, %11\n"
        "mov %%r13, %12\n"
        "mov %%r14, %13\n"
        "mov %%r15, %14\n"
        : "=m"(r.rax), "=m"(r.rbx), "=m"(r.rcx), "=m"(r.rdx), "=m"(r.rsi), "=m"(r.rdi), "=m"(r.rbp),
          "=m"(r.r8), "=m"(r.r9), "=m"(r.r10), "=m"(r.r11), "=m"(r.r12), "=m"(r.r13), "=m"(r.r14), "=m"(r.r15)
        :
        : 
    );

    my_patch_function(&r);

    asm volatile (
        "mov %0, %%rax\n"
        "mov %1, %%rbx\n"
        "mov %2, %%rcx\n"
        "mov %3, %%rdx\n"
        "mov %4, %%rsi\n"
        "mov %5, %%rdi\n"
        "mov %6, %%rbp\n"
        "mov %7, %%r8\n"
        "mov %8, %%r9\n"
        "mov %9, %%r10\n"
        "mov %10, %%r11\n"
        "mov %11, %%r12\n"
        "mov %12, %%r13\n"
        "mov %13, %%r14\n"
        "mov %14, %%r15\n"
        :
        : "m"(r.rax), "m"(r.rbx), "m"(r.rcx), "m"(r.rdx), "m"(r.rsi), "m"(r.rdi), "m"(r.rbp),
          "m"(r.r8), "m"(r.r9), "m"(r.r10), "m"(r.r11), "m"(r.r12), "m"(r.r13), "m"(r.r14), "m"(r.r15)
    );
}

// This is the original function to hook.
int my_function(int parm1, char* str, char c)
{
	printf("origin func: Args: %d, %s, %c\n", parm1, str, c);
	return 35;
}

int main()
{
	int res;
    res = my_function(1, "hello aaa", 'c');
	printf("origin func return: %d\n", res);

	inline_hook(my_function, my_hook_function);

	// Now calling the function will actually call the hook function.
	res = my_function(2, "hello bbb", 'd');
	printf("hooked func return: %d\n", res);

	remove_hook(my_function);

	// Now calling the function will call the original function.
	res = my_function(3, "hello ccc", 'e');
	printf("origin func return: %d\n", res);

	return 0;
}
