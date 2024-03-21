# libebpf

Features:
- Full featured eBPF intepreter, support all features listed on https://docs.kernel.org/bpf/standardization/instruction-set.html
- External helpers support
- Passes all unit tests of ubpf vm tests

## How to use?

Add this directory into your CMake project, and links target `libebpf`. See `libebpf.h` for details.

## How to run tests?

- Build CMake target `libebpf_test_runner` (bash build.sh)
- `cd test && python3 -m venv env`
- `source ./env/bin/activate`
- `pip install -r requirements.txt`
- `pytest`
