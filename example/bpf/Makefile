# BPF compiler
BPF_CC = clang
# BPF C flags
BPF_CFLAGS = -O2 -target bpf -c -g
# BPF source files
BPF_SRCS = $(wildcard *.bpf.c)
# BPF object files
BPF_OBJS = $(BPF_SRCS:.c=.o)

all: $(BPF_OBJS) base.btf

%.bpf.o: %.bpf.c
	$(BPF_CC) $(BPF_CFLAGS) $< -o $@

base.btf:
	clang -g -c btf-base.c -o btf-base.bpf.o
	pahole  --btf_encode_detached base.btf btf-base.bpf.o

clean:
	rm -f $(BPF_OBJS) base.btf
