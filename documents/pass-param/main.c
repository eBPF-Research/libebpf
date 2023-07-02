#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <ffi.h>
#include "hook.h"

// This is the hook function.
void my_hook_function(ffi_cif* cif, void* ret, void* args[], void* userdata)
{
    int parm1 = *(int*)args[0];
    char* str = *(char**)args[1];
    char c = *(char*)args[2];
    double x = *(double*)args[3];

    printf("Hello from hook! Args: %d, %s, %c, %f\n", parm1, str, c, x);
    
    // Call the original function
	return 42;
}

// This is the original function to hook.
int my_function(int parm1, char* str, char c, double x)
{
	printf("origin func: %d,  str %s, double %lf, %c\n", parm1, str, x, c);
	return 35;
}

int my_test_hook_function(int parm1, char* str, char c, double x)
{
	printf("test hook func: %d,  str %s, double %lf, %c\n", parm1, str, x, c);
	return 35;
}

int main()
{
	int res;
    res = my_function(1, "hello aaa", 'c', 3.14);
	printf("origin func return: %d\n", res);

    ffi_cif cif;
    ffi_type* args[4];
    ffi_closure *closure;
    
    void *bound_func;
    int rc;
    
    // Initialize the argument info vectors    
    args[0] = &ffi_type_sint;
    args[1] = &ffi_type_pointer;
    args[2] = &ffi_type_schar;
    args[3] = &ffi_type_double;
    
    // Initialize the cif
    if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 4,
                     &ffi_type_sint, args) == FFI_OK)
    {
        closure = ffi_closure_alloc(sizeof(ffi_closure), &bound_func);
        
        if (ffi_prep_closure_loc(closure, &cif, my_hook_function,
                                 my_function, bound_func) != FFI_OK)
        {
            printf("ffi_prep_closure_loc failed\n");
            return 1;
        }
        
        // Now we can call the function using the "bound_func" pointer
        rc = ((int (*)(int, char*, char, double))bound_func)(0, "hello xxx", 'f', 2.14);

		inline_hook(my_function, bound_func);

		// Now calling the function will actually call the hook function.
		res = my_function(2, "hello bbb", 'd', 4.14159);

		printf("hooked func return: %d\n", res);

		// remove_hook(my_function);
        
        ffi_closure_free(closure);
    }

	// Now calling the function will call the original function.
	res = my_function(3, "hello ccc", 'e', 5.1415926);
	printf("origin func return: %d\n", res);

	return 0;
}
