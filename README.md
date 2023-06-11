# libebpf

## more source code are from

- https://elixir.bootlin.com/linux/v6.2

## install arm32 arm64 build and qemu

arm32:

```bash
sudo apt-get install -y gcc-arm-linux-gnueabi qemu-user
```

arm64:

```bash
sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
```


### 编译bpf指令  

```bash
$ python3 tools/compile_code.py -s example/bpf/test1.bpf.c 

```