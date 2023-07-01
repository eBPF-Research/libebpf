#include <stdio.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#ifndef __SYM_USE_ELF_PIE__
#define __SYM_USE_ELF_PIE__ 1
#endif
#ifndef __SYM_USE_ELF_NO_PIE__
#define __SYM_USE_ELF_NO_PIE__ 0
#endif
#ifndef __SYM_USE_DLSYM__
#define __SYM_USE_DLSYM__ 0
#endif

#define ERR_BUFFER_SIZE 256

static void *get_function_addr_dlsym(const char * func_name, char** err_msg) {
    void* handle = dlopen(NULL, RTLD_LAZY); // Open the current executable
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        if (err_msg)
            *err_msg = dlerror();
        return NULL;
    }

    dlerror(); // Clear any existing error

    // Find the function in the executable's symbol table
    void *func_ptr = dlsym(handle, "my_function");

    char* error = dlerror();
    if (error) {
        fprintf(stderr, "error: %s\n", error);
        if (err_msg)
            *err_msg = dlerror();
        return NULL;
    }

    dlclose(handle); // Close the executable

    return func_ptr;
}

static void* get_function_addr_elf_pie(const char* func_name, char* err_msg) {
    uintptr_t base_address = 0;
    FILE* maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) {
        sprintf(err_msg, "Cannot open /proc/self/maps");
        return NULL;
    }

    char line[256];
    while (fgets(line, sizeof(line), maps) != NULL) {
        char perms[5];
        sscanf(line, "%" PRIxPTR "-%*x %4s", &base_address, perms);
        if (perms[2] == 'x') {
            break;
        }
    }

    fclose(maps);

    if (base_address == 0) {
        sprintf(err_msg, "Cannot find base address");
        return NULL;
    }

    FILE* offsets = fopen("maps.off.txt", "r");
    if (offsets == NULL) {
        sprintf(err_msg, "Cannot open offsets file");
        return NULL;
    }

    uintptr_t offset = 0;
    char name[256] = "";
    while (fscanf(offsets, "%lx %*s %255s", &offset, name) == 2) {
        if (strcmp(name, func_name) == 0) {
            break;
        }
    }

    fclose(offsets);

    if (strcmp(name, func_name) != 0) {
        sprintf(err_msg, "Cannot find function %s", func_name);
        return NULL;
    }

    void* func_addr = (void*)(base_address + offset - 0x1000);
    return func_addr;
}

void* get_function_addr_elf_no_pie(const char* func_name, char* err_msg) {
    FILE *file = fopen("myprogram.off.txt", "r");
    if (file == NULL) {
        sprintf(err_msg, "Cannot open offsets file!");
        return NULL;
    }

    uintptr_t offset = 0;
    char name[256];

    while (fscanf(file, "%lx %*s %255s", &offset, name) == 2) {
        if (strcmp(name, func_name) == 0) {
            break;
        }
    }

    fclose(file);

    if (strcmp(name, func_name) != 0) {
        sprintf(err_msg, "Did not find %s!", func_name);
        return NULL;
    }

    // Cast the offset to a function pointer
    void* func_ptr = (void (*)())offset;

    return func_ptr;
}

void *get_function_addr(const char * func_name, char** err_msg) {
    char err_buffer[ERR_BUFFER_SIZE];
    void* res = NULL;
#if __SYM_USE_DLSYM__
    res = get_function_addr_dlsym(func_name, err_msg);
    if (err_msg)
        strncpy(err_buffer, *err_msg, ERR_BUFFER_SIZE);
#elif __SYM_USE_ELF_NO_PIE__
    res = get_function_addr_elf_no_pie(func_name, err_buffer);
#elif __SYM_USE_ELF_PIE__
    res = get_function_addr_elf_pie(func_name, err_buffer);
#else
    #error "No symbol resolution method defined"
#endif
    if (err_msg && res == NULL)
        *err_msg = strdup(err_buffer);
    return res;
}
