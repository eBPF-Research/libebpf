#include <stdio.h>
#include <dlfcn.h>

void my_function() {
    printf("Hello, world!\n");
}

int main() {
    void* handle = dlopen(NULL, RTLD_LAZY); // Open the current executable
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        return 1;
    }

    dlerror(); // Clear any existing error

    // Find the function in the executable's symbol table
    void (*func_ptr)() = dlsym(handle, "my_function");

    char* error = dlerror();
    if (error) {
        fprintf(stderr, "error: %s\n", error);
        return 1;
    }

    // Call the function through the pointer
    func_ptr();

    dlclose(handle); // Close the executable

    return 0;
}
