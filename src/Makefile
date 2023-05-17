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

arch/arm64/net/bpf_jit_comp.o: arch/arm64/net/bpf_jit_comp.c
	$(CC) $(LINUX_CFLAGS_EXTRA) -Iarch/arm64 -DCONFIG_ARM64_BTI_KERNEL=1 -g -c $< -o $@

 arch/x86/net/bpf_jit_comp.o: arch/x86/net/bpf_jit_comp.c
	$(CC) $(LINUX_CFLAGS_EXTRA) -g -c $< -o $@
