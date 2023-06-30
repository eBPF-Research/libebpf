#include <stdio.h>
#include <stdint.h>

void my_function() {
    printf("Hello, world!\n");
}

int main() {
    uintptr_t func_offset = 0x...; // Fill this with the actual offset

    // Cast the offset to a function pointer
    void (*func_ptr)() = (void (*)())func_offset;

    // Call the function through the pointer
    func_ptr();

    return 0;
}
