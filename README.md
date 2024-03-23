# libebpf

Features:
- Full featured eBPF intepreter, support all features listed on https://docs.kernel.org/bpf/standardization/instruction-set.html
- External helpers support
- Passes all unit tests of ubpf vm tests

## How to use?

Add this directory into your CMake project, and links target `libebpf`. See `libebpf.h` for details.

## How to run vm tests?

- Build CMake target `libebpf_test_runner`
- `cd vm-test && python3.8 -m venv env`
- `source ./env/bin/activate`
- `pip install -r requirements.txt`
- `pytest`

## How to run execution context tests?
- Build CMake target `ebpf_execution_context_test`
- Run `./build/execution-test/ebpf_execution_context_test`

## Notes on ebpf_execution_context

`ebpf_vm` is just a virtual machine, it doesn't have ability to manage or access maps. We provide `ebpf_execution_context` for such operations. You may create a `ebpf_execution_context` and create maps in it. Before running your ebpf programs using ebpf_vm, you should call `ebpf_execution_context__setup_internal_helpers` to setup internal helpers (such as `bpf_map_lookup_elem`) to the vm, and should also point `ebpf_execution_context__thread_global_context` to the context you want to use. Then you can run your ebpf programs with access to the context.
