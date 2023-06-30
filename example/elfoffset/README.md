# get the function offset and jump to the function at runtime dynamically

Indeed, getting the function offset dynamically during runtime would require you to parse the symbol table of the binary. This is a complex task that would usually be done using a library like libelf or libbfd.

However, if you want a simpler solution that uses command-line tools, you can use `nm` or `readelf` to create a text file with the function offsets, and then read that file at runtime. Here's how you might do it:

1. **Compile your program with debug symbols and without ASLR**:

    ```bash
    gcc -g -fno-pie -no-pie myprogram.c -o myprogram
    ```

2. **Create a text file with the function offsets**:

    ```bash
    nm myprogram | grep ' T ' > offsets.txt
    ```

    This command will create a text file called `offsets.txt` that contains the offsets of all the functions in `myprogram`. The 'T' indicates that we are interested in the text (code) section of the binary.

3. **Read the offsets file at runtime and create function pointers**:

    Here's an example in C that reads the offsets file and creates a function pointer for `my_function`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

void my_function() {
    printf("Hello, world!\n");
}

int main() {
    FILE *file = fopen("offsets.txt", "r");
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
```

This program reads the offsets file, line by line, until it finds `my_function`. It then creates a function pointer using the offset and calls the function.

**Note** that this only works if your program is compiled without ASLR (hence the `-no-pie` flag to gcc). If ASLR is enabled, the offsets will be different every time the program is run. Also note that this example only works for function with no parameters, if your function has parameters, you need to adjust the function pointer type accordingly.

**Please be aware** that parsing the symbol table and manually creating function pointers like this is risky and not generally recommended. It can easily lead to crashes, undefined behavior, or security vulnerabilities if not done properly. Use it carefully and only if you understand exactly what you are doing.
