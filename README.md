# libebpf

## install arm32 arm64 build and qemu

arm32:

```bash
sudo apt-get install -y gcc-arm-linux-gnueabi qemu-user
```

arm64:

```bash
sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
```

## build and run

arm32

```sh
make build-arm32
make run-arm32
```

arm64

```sh
make build-arm64
make run-arm64
```

on the current platform

```sh
make build
build/bin/Debug/libebpf
```

### compile bpf insts  

install pyelftools

```sh
pip3 install pyelftools
```

run

```bash
python3 extensions/tools/compile_code.py -s example/bpf/test1.bpf.c 
```

## extensions

support load from a elf file, relocation on btf.

compile and generate btf info(need to install `pahole` first):

```sh
make build-ext
```

run:

```sh
build/extensions/vm-exten example/bpf/btf-relo.bpf.o vm-exten.btf
```

The example for bpf relocate is in [example/bpf/btf-relo.bpf.c](example/bpf/btf-relo.bpf.c)

### build examples

```sh
cd example/bpf
make
```

### test for pytest

Use python3.8 and pytest

```sh
python3.8 -m venv test
source test/bin/activate
sudo apt install python3-pytest
pip install -r test/requirements.txt
make build-x86 # or arm32 arm64
make test
```
