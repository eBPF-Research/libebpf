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
