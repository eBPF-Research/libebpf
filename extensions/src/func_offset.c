#include <stdio.h>
#include <dlfcn.h>

void *get_function_addr(const char * func_name, char** err_msg) {
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
