# hook demo

实现 Inline Hook 的方法是可行的，但是这在现代操作系统中可能会遇到一些问题，因为它们通常会阻止你修改执行代码。在某些情况下，你可能需要禁用某些内存保护机制，例如数据执行防止（DEP）或地址空间布局随机化（ASLR）。另外，这种技术在处理现代的编译器优化时可能会有困难，因为它们可能会将函数内联，或者以其他方式修改函数的结构。下面是实现 Inline Hook 的基本步骤：

1. **找到目标函数的地址**：首先，你需要找到你想要 Hook 的函数在内存中的地址。你可以使用上面的 `get_function_addr_elf_no_pie` 或 `get_function_addr_elf_pie` 函数来获取这个地址。

2. **备份原始指令**：由于你要修改目标函数的开始部分来插入跳转指令，你需要首先备份原始的指令，以便在你的 Hook 函数执行完毕后，可以跳回并执行这些被覆盖的指令。

3. **写入跳转指令**：然后，你需要在目标函数的开始部分写入一个跳转指令，这个指令将程序的执行流引导到你的 Hook 函数。

4. **创建你的 Hook 函数**：你的 Hook 函数将替代目标函数的开始部分。它应该首先执行你想要插入的代码，然后执行备份的原始指令，最后跳回到目标函数的剩余部分。

5. **修改内存权限**：在默认情况下，你的程序的代码段是只读的，这是为了防止程序意外或恶意地修改自己的代码。因此，你需要使用 `mprotect` 函数来修改目标函数的内存页的权限，使其成为可写的。

6. **恢复内存权限**：在修改了目标函数之后，你应该再次使用 `mprotect` 函数来恢复内存页的原始权限。

请注意，这种技术可能违反一些操作系统或硬件的保护机制，因此它可能不会在所有系统或配置上都能正常工作。在使用这种技术时，你应当格外小心，确保你完全理解你的修改可能带来的后果。

## build and run

### for x86

Below is an example of how you can modify your code to perform an inline hook for the `my_function`. This is a simplistic approach and works specifically for this case. This is just an illustrative example. For real-world scenarios, a more complex method would need to be employed, considering thread-safety, re-entrant code, and more.

```c
void inline_hook(void *orig_func, void *hook_func) {
    // Store the original bytes of the function.
    unsigned char orig_bytes[5];
    memcpy(orig_bytes, orig_func, 5);

    // Make the memory page writable.
    mprotect(get_page_addr(orig_func), getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC);

    // Write a jump instruction at the start of the original function.
    *((unsigned char *)orig_func + 0) = 0xE9; // JMP instruction
    *((void **)((unsigned char *)orig_func + 1)) = (unsigned char *)hook_func - (unsigned char *)orig_func - 5;

    // Make the memory page executable only.
    mprotect(get_page_addr(orig_func), getpagesize(), PROT_READ | PROT_EXEC);
}

```
In this example, `my_function` is the original function that is hooked. `my_hook_function` is the function that gets called instead of `my_function`. The `inline_hook` function performs the actual hook by overwriting the start of `my_function` with a jump (`JMP`) instruction to `my_hook_function`.

When you now call `my_function` in your `main`, `my_hook_function` is called instead.

Please note that this code is simplified and makes a few assumptions:

- The functions `my_function` and `my_hook_function` are in the same memory page. If they aren't, the jump offset from `my_function` to `my_hook_function` might not fit in the 4 bytes available in the jump instruction.
- The first 5 bytes of `my_function` can be safely overwritten. If there's a multi-byte instruction that starts within the first 5 bytes but doesn't end before the 6th byte, this will crash.
- The functions `my_function` and `my_hook_function` don't move in memory. If they do (for example, if they're in a shared library that gets unloaded and reloaded at a different address), the jump instruction will jump to the wrong place and likely crash.

```console
$ make
$ ./maps
Hello, world!
Hello from hook!
Hello, world!
```

### for arm32

Note that in ARM32, the Program Counter (PC) is usually 2 instructions ahead, which is why we subtract 8 (2 instructions * 4 bytes/instruction) when calculating the offset. This might differ between different ARM versions or modes (Thumb vs ARM, etc.) so please adjust accordingly to your target's specifics.

Also, you need to increase the SIZE_ORIG_BYTES from 16 to 20 because the minimal branch instruction in ARM is 4 bytes and you're going to replace 5 instructions. This is needed because the branch instruction uses a relative offset and you cannot be sure how far your hook function will be. If your function and hook are within 32MB of each other, you could only replace the first 4 bytes with a branch and wouldn't need to touch the rest.

Remember that manipulating code at runtime can be error-prone and architecture-specific. The code can behave differently based on where it's loaded in memory, how the compiler has optimized it, whether it's running in Thumb or ARM mode, and so on. Always thoroughly test the code in the exact conditions where it will be used.

```console
$ make arm
$ ./maps-arm32
Hello, world!
Hello from hook!
Hello, world!
```

### for arm64

Similar to ARM32, ARM64 uses the ARM instruction set. However, there are differences and specifics to consider for ARM64. For example, the encoding of the branch instruction is different and because of the larger address space, you have to create a trampoline for larger offsets that can't be reached by a single branch instruction. The trampoline should be close to the original function so it can be reached by a branch instruction and from there, it will load the full 64 bit address of the hook function.

```console
$ make arm64
$ ./maps-arm64
Hello, world!
Hello from hook!
Hello, world!
```
