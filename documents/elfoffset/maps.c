#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

void my_function() {
    printf("Hello, world!\n");
}

uintptr_t get_base_address(const char* program_name) {
    uintptr_t base_address = 0;

    FILE* maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) {
        printf("Cannot open /proc/self/maps\n");
        exit(1);
    }

    char line[256];
    while (fgets(line, sizeof(line), maps) != NULL) {
        printf("line: %s\n", line);
        char perms[5];
        sscanf(line, "%" PRIxPTR "-%*x %4s", &base_address, perms);
        if (perms[2] == 'x' && strstr(line, program_name) != NULL) {
            printf("Found base address %" PRIxPTR "\n", base_address);
            break;
        }
    }

    fclose(maps);
    return base_address;
}

int main() {
    uintptr_t base_address = get_base_address("maps");
    if (base_address == 0) {
        printf("Cannot find base address\n");
        return 1;
    }

    FILE* offsets = fopen("maps.off.txt", "r");
    if (offsets == NULL) {
        printf("Cannot open offsets file\n");
        return 1;
    }

    uintptr_t offset = 0;
    char name[256]  = "";

    while (fscanf(offsets, "%lx %*s %255s", &offset, name) == 2) {
        if (strcmp(name, "my_function") == 0) {
            printf("Found function %s at offset %" PRIxPTR "\n", name, offset);
            break;
        }
    }

    fclose(offsets);

    if (strcmp(name, "my_function") != 0) {
        printf("Cannot find function\n");
        return 1;
    }

    void (*func_ptr)() = (void (*)())(base_address + offset - 0x1000);
    printf("%lx, %lx, func_ptr %p\n",base_address, offset,  func_ptr);
    printf("real address %p\n", (void*)my_function);
    func_ptr();

    return 0;
}
