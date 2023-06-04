-include ../scripts/Makefile.lib
-include Makefile.lib

.PHONY: build-arch
LINUX_CFLAGS :=  \
	-I../include \
	-I. \
	-DCONFIG_BPF_JIT \
	-fno-omit-frame-pointer \
	-fno-strict-overflow \
	-fshort-wchar \
	-fno-strict-aliasing \
	-fno-PIE \
	-fno-common \
	-fno-delete-null-pointer-checks \
	-fno-optimize-sibling-calls \
	-fno-stack-check \
	-std=gnu89\
	-Wno-gnu \
	-O2 \

LINUX_CFLAGS_EXTRA = $(LINUX_CFLAGS) -fno-PIE -ffunction-sections -fdata-sections -fno-PIC

%.o: %.c arch/riscv/net/bpf_jit.h
	$(CC) $(LINUX_CFLAGS_EXTRA) -g -c $< -o $@

build-arch: arch/arm64/bpf_jit_comp.o arch/arm/bpf_jit_32.o bpf_jit_comp.o

arch/arm64/bpf_jit_comp.o: arch/arm64/bpf_jit_comp.c ../include/linux-bpf.h
	$(CC) $(LINUX_CFLAGS_EXTRA) -Iarch/arm64 -DCONFIG_ARM64_BTI_KERNEL=1 -g -c $< -o $@

arch/arm/bpf_jit_32.o: arch/arm/bpf_jit_32.c ../include/linux-bpf.h
	$(CC) $(LINUX_CFLAGS_EXTRA) -Iarch/arm -g -c $< -o $@

arch/x86/bpf_jit_comp.o: arch/x86/bpf_jit_comp.c ../include/linux-bpf.h
	$(CC) $(LINUX_CFLAGS_EXTRA) -g -c $< -o $@

arch/x86/bpf_jit_comp32.o: arch/x86/bpf_jit_comp32.c ../include/linux-bpf.h
	$(CC) $(LINUX_CFLAGS_EXTRA) -g -c $< -o $@

core.o: core.c
	$(CC) $(LINUX_CFLAGS_EXTRA) -Iarch/x86 -g -c $< -o $@

clean:
	rm arch/arm64/bpf_jit_comp.o arch/arm/bpf_jit_32.o arch/x86/bpf_jit_comp.o arch/x86/bpf_jit_comp32.o
