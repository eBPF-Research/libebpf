# libffi

libffi 是一个外部函数接口库 (Foreign Function Interface Library)，用于在运行时动态地调用 C 语言函数。这个库提供了一个机制，用于指定函数的参数类型和返回值类型，并提供了创建和调用这样的函数的能力。

这是 libffi 的一个基本示例，该示例定义了一个函数 `add`，该函数接受两个整数参数并返回它们的和：

```c
#include <stdio.h>
#include <ffi.h>

int add(int x, int y) {
    return x + y;
}

int main()
{
    ffi_cif cif;  
    void *args[2];  
    long arg1, arg2, result;  
    ffi_type *arg_types[3];  

    arg_types[0] = &ffi_type_sint32;  // Define the argument types
    arg_types[1] = &ffi_type_sint32;
    arg_types[2] = NULL; 

    if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &ffi_type_sint32, arg_types) == FFI_OK)
    {
        arg1 = 2;
        arg2 = 3;
        args[0] = &arg1;
        args[1] = &arg2;
        ffi_call(&cif, FFI_FN(add), &result, args);  // call the function
        printf("result: %ld\n", result);
    }
    return 0;
}
```

在这个示例中，我们首先定义了 `ffi_cif` 结构以及用于存放参数和结果的空间。然后，我们使用 `ffi_prep_cif` 函数来准备调用接口。我们传入了 ABI (Application Binary Interface) 类型，参数个数，返回值类型，以及参数类型数组。最后，我们使用 `ffi_call` 来调用函数，传入我们准备好的 `ffi_cif` 结构，函数地址，结果的存放地址，以及参数值数组。

这是 libffi 的一个非常基础的使用示例，实际上 libffi 还能够用于更加复杂的场景，比如调用成员函数，处理结构体参数等。

注意，你需要链接 libffi 库来编译和运行这个程序，编译指令可能类似于：`gcc -o test test.c -lffi`。

另外，由于 libffi 的 API 可能存在一些复杂性，很多时候我们在实际开发中可能更倾向于使用一些更高级的语言特性（比如 C++ 的函数对象，或者 Python 的 ctypes 模块）来实现类似的功能。

在 Ubuntu 上运行这个 libffi 示例程序的步骤如下：

1. 首先，你需要安装 libffi 库。在 Ubuntu 上，你可以通过 apt 包管理器来安装。打开终端，然后输入以下命令：

    ```bash
    sudo apt-get update
    sudo apt-get install libffi-dev
    ```

    这将安装 libffi 库以及其开发文件（包括头文件和链接库）。

2. 接着，创建一个名为 `test.c` 的 C 文件，并把上述示例代码复制到该文件中。

3. 使用 gcc 编译器编译该文件。在终端中，导航到你的 `test.c` 文件所在的目录，然后输入以下命令：

    ```bash
    gcc -o test test.c -lffi
    ```

    这将生成一个名为 `test` 的可执行文件。

4. 运行该程序：

    ```bash
    ./test
    ```

    如果一切顺利，你应该会在终端看到 `result: 5` 这样的输出。这表示 `add` 函数被成功调用，返回了正确的结果。

注意：由于 libffi 是一个系统库，安装它可能需要 root 权限。在使用 `sudo` 命令时，可能需要你输入你的用户密码。

## ebpf ffi

首先，需要一个系统来描述你想要调用的函数。这可能涉及到存储函数指针、参数类型、参数数量等信息。在你的例子中，函数的参数和返回值都是 `uint64_t` 类型，这简化了问题，但是仍然需要一种方式来表示和存储这些函数。

其次，需要一种方式在运行时查找和调用这些函数。这可能涉及到解析函数的信息，准备函数的参数，然后跳转到函数的地址执行代码。

请注意，这是一个基本的设计，并且可能需要根据具体需求进行修改。例如，可能需要支持不同类型的参数和返回值，或者可能需要在 eBPF 程序中调用具有不同数量参数的函数。此外，你还需要考虑如何处理错误，例如，如果一个 eBPF 程序试图调用一个未注册的函数，或者如果一个函数调用失败。

在实现这个系统的过程中，需要密切注意安全性问题。例如:

- 需要确保 eBPF 程序不能调用任意的函数，只能调用已经被注册的函数。
- 需要确保 eBPF 程序不能通过构造恶意的参数来攻击你的系统。
