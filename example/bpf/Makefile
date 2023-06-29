# BPF compiler
BPF_CC = clang
# BPF C flags
BPF_CFLAGS = -O2 -target bpf -c -g
# BPF source files
BPF_SRCS = $(wildcard *.bpf.c)
# BPF object files
BPF_OBJS = $(BPF_SRCS:.c=.o)

all: $(BPF_OBJS)

%.o: %.c
	$(BPF_CC) $(BPF_CFLAGS) $< -o $@

clean:
	rm -f $(BPF_OBJS)
