# dlsym

It's indeed unusual and more complex to dynamically determine the offset and execute a function at runtime. For this, you would need to parse the binary's symbol table at runtime. Here's a rough idea of how you might do it using the dlfcn library's `dlsym` function, which can find a function's address in a dynamically linked executable at runtime:

```c
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
        fprintf(stderr, "%s\n", error);
        return 1;
    }

    // Call the function through the pointer
    func_ptr();

    dlclose(handle); // Close the executable

    return 0;
}
```

This example uses the `dlopen` function to open the current executable (the `NULL` argument means to open the current process's symbol table), the `dlsym` function to find the function in the symbol table, and a function pointer to call the function.

This approach requires that your executable is dynamically linked and the function is exposed in the symbol table, i.e., it's not declared as `static` and not stripped out by the linker or strip tool. You may need to pass the `-rdynamic` option to the linker (usually via `-Wl,-export-dynamic` gcc option) to ensure that the symbol is included in the dynamic symbol table.

Again, manipulating function pointers like this can be dangerous and is generally not recommended unless you know what you are doing. The best way to call a function at runtime is typically to use a function pointer that is set at compile time.
