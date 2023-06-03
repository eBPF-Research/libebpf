# old makefile

```makefile

# make V=1 // to see full commands
ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n' "$(1)" "$(2)" "$(if $(3), $(3))";
endif

CLANG := clang-13
CFLAGS ?= -g -O2 -Werror -Wall 
LDLIBS := -lm

BIN_DIR = bin
OUT_DIR := $(BIN_DIR)/objs
SRC_FILES = $(wildcard src/*.c)
OBJ_FILES = $(patsubst src/%.c, $(OUT_DIR)/%.o, $(SRC_FILES))
BPF_FILES = $(wildcard example/bpf/*.ebpf.c)
BPF_ELF = $(patsubst example/bpf/%.ebpf.c, $(BIN_DIR)/bpf/%.ebpf, $(BPF_FILES))

mk_out_dir:
	$(Q)mkdir -p $(OUT_DIR)
	$(Q)mkdir -p $(BIN_DIR)/bpf

# make libebpf
libebpf: bin/libebpf.a

bin/objs/%.o: src/%.c | mk_out_dir
	$(Q)$(CC) $(CFLAGS) -I include/libebpf/ -c $< -o $@

bin/libebpf.a: $(OBJ_FILES)
	$(call msg,AR,$@)
	$(Q)$(AR) rcs $@ $(OUT_DIR)/*.o

example: libebpf ## make test program
	$(call msg,build example,$@)
	$(Q)$(CC) example/test_vm.c -static $(CFLAGS) $(LDLIBS)  -I include/libebpf/ -L bin/ -l:libebpf.a -o bin/vm
	$(Q)$(CC) example/test_code.c -static $(CFLAGS) $(LDLIBS)  -I include/libebpf/ -L bin/ -l:libebpf.a -o bin/code


# 单元测试
# 测试libebpf基本功能
# %.ebpf: %.ebpf.c
# 	$(call msg,build bpf,$@)
# 	$(CLANG) -g -O2 -target bpf  -c $^ -o bin/bpf/$@
$(BIN_DIR)/bpf/%.ebpf: example/bpf/%.ebpf.c
	$(call msg,build bpf,$@)
	$(CLANG) -g -O2 -target bpf  -c $^ -o $@

smoke_test: example $(BPF_ELF)
	$(call msg,smoke test,$@)
	$(Q)python3 tools/write_mem.py
	$(Q)mv mem $(BIN_DIR)/
	# $(BIN_DIR)/vm -m $(BIN_DIR)/mem $(BIN_DIR)/bpf/test1.ebpf
	$(Q)python3 tools/compile_code.py -s example/bpf/test1.ebpf.c -f example/test_code.h
	$(BIN_DIR)/code

unitest:
	$(call msg,unitest,$@)
	nosetests3 -v test
```