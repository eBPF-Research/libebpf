#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include "hook.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// This is the hook function.
void my_hook_function()
{
	printf("Hello from hook!\n");
}

// This is the original function to hook.
void my_function()
{
	printf("Hello, world!\n");
}

void *get_page_addr(void *addr)
{
	return (void *)((uintptr_t)addr & ~(getpagesize() - 1));
}

void inline_hook(void *orig_func, void *hook_func)
{
	// Store the original bytes of the function.
	unsigned char orig_bytes[5];
	memcpy(orig_bytes, orig_func, 5);

	// Make the memory page writable.
	mprotect(get_page_addr(orig_func), getpagesize(),
		 PROT_READ | PROT_WRITE | PROT_EXEC);

	// Write a jump instruction at the start of the original function.
	*((unsigned char *)orig_func + 0) = 0xE9; // JMP instruction
	*((void **)((unsigned char *)orig_func + 1)) =
		(unsigned char *)hook_func - (unsigned char *)orig_func - 5;

	// Make the memory page executable only.
	mprotect(get_page_addr(orig_func), getpagesize(),
		 PROT_READ | PROT_EXEC);
}

int main()
{
	inline_hook(my_function, my_hook_function);

	// Now calling the function will actually call the hook function.
	my_function();

	return 0;
}
