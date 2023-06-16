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

## more source code are from

- https://elixir.bootlin.com/linux/v5.7
