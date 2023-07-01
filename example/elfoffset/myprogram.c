#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

void my_function() {
    printf("Hello, world!\n");
}

int main() {
    FILE *file = fopen("myprogram.off.txt", "r");
    if (file == NULL) {
        printf("Cannot open offsets file!\n");
        return 1;
    }

    uintptr_t offset = 0;
    char name[256];

    while (fscanf(file, "%lx %*s %255s", &offset, name) == 2) {
        if (strcmp(name, "my_function") == 0) {
            break;
        }
    }

    fclose(file);

    if (strcmp(name, "my_function") != 0) {
        printf("Did not find my_function!\n");
        return 1;
    }

    // Cast the offset to a function pointer
    void (*func_ptr)() = (void (*)())offset;

    // Call the function through the pointer
    func_ptr();

    return 0;
}
