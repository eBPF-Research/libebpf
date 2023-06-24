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

x86

```sh
make build-x86
build/bin/Debug/libebpf
```

### 编译bpf指令  

install pyelftools

```sh
pip3 install pyelftools
```

run

```bash
python3 tools/compile_code.py -s example/bpf/test1.bpf.c 
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

## Debug with qemu-user

```sh
qemu-arm -g 1234 build/bin/Debug/libebpf
```

in another shell

```sh
gdb-multiarch build/bin/Debug/libebpf
target remote :1234
```

start debug.

## for ffi:

for arm32 and arm64 compatible, this is ok:

```
static uint64_t
gather_bytes(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e)
{
    return (((uint64_t)a) << (uint64_t)32) | (((uint32_t)b) << (uint64_t)24) | (((uint32_t)c) << (uint64_t)16) | (((uint16_t)d) << (uint64_t)8) | (uint64_t)e;
}
```

this is not ok:

```
static uint64_t
gather_bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e)
{
    return (((uint64_t)a) << (uint64_t)32) | (((uint32_t)b) << (uint64_t)24) | (((uint32_t)c) << (uint64_t)16) | (((uint16_t)d) << (uint64_t)8) | (uint64_t)e;
}
```

all args for helpers should be uint64_t to keep correct.

## more source code are from

- https://elixir.bootlin.com/linux/v5.7
