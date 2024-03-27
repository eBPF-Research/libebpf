# libebpf

Features:
- Full featured eBPF intepreter, support all features listed on https://docs.kernel.org/bpf/standardization/instruction-set.html
- External helpers support
- Passes all unit tests of ubpf vm tests

## How to use?

Add this directory into your CMake project, and links target `libebpf`. See `libebpf*.h` for details.

## How to run vm tests?

- Build CMake target `libebpf_test_runner`
- `cd vm-test && python3.8 -m venv env`
- `source ./env/bin/activate`
- `pip install -r requirements.txt`
- `pytest`

## How to run ebpf_state tests?
- Build CMake target `ebpf_state_test`
- Run `./build/execution-test/ebpf_state_test`

## Notes on ebpf_state

`ebpf_vm` is just a virtual machine, it doesn't have ability to manage or access maps. We provide `ebpf_state` for such operations. You may create a `ebpf_state` and create maps in it. Before running your ebpf programs using ebpf_vm, you should call `ebpf_state__setup_internal_helpers` to setup internal helpers (such as `bpf_map_lookup_elem`) to the vm, and should also point `ebpf_state__thread_global_context` to the context you want to use. Then you can run your ebpf programs with access to the context.

## Notes on FFI
You may call `ebpf_state__register_ffi_function` to register a FFI function. FFI functions are type safe, which means that it always accept int64_t and returns int64_t at the bpf side, but it would convert the received argument to the proper types when calling the FFI function.
You may use some helper macros for FFI callling in the BPF side. see `libebpf_ffi.bpf.h` for details.
You may use `LIBEBPF_EXPORT_FUNCTION_ARG[N]` (where `[N]` is an integer range 0 to 6) to export a function and automatically registers when the ebpf_state was created. This macro is only applicatable in the target `libebpf`, since it needs a modified link process
