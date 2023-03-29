
# Debug with qemu-user

```sh
qemu-arm -g 1234 build/bin/Debug/libebpf
qemu-arm -cpu any -L /usr/arm-linux-gnueabihf/build/bin/Debug/libebpf
```

in another shell

```sh
gdb-multiarch -ex "target remote :1234" build/bin/Debug/libebpf
```

start debug.

```
b /home/yunwei/libebpf/example/main.c:76
layout asm

│  >0x9b7d0     andeq       r7, r9, r4, asr #9                      │
│   0x9b7d4     andeq       r7, r9, r4, asr #9                      │
│   0x9b7d8     andeq       r0, r0, r0                              │
│   0x9b7dc     andeq       r0, r0, r0                              │
│   0x9b7e0     sub sp, sp, #80     ; 0x50                          │
│   0x9b7e4                 ; <UNDEFINED> instruction: 0xe14b24f0   │
│   0x9b7e8     mov r2, #0                                          │
│   0x9b7ec                 ; <UNDEFINED> instruction: 0xe14b24f8   │
│   0x9b7f0     mov r2, r0                                          │
│   0x9b7f4     mov r0, #2                                          │
│   0x9b7f8     mov r1, #0                                          │
│   0x9b7fc     mov sp, r11                                         │
│   0x9b800     pop {r4, r5, r6, r7, r8, r9, r11, pc} 
```

to show the disassemble code.

## llvm-objdump

use llvm-objdump to view the btf code:

```
$ llvm-objdump -h /home/yunwei/libebpf
/example/bpf/btf-relo.bpf.o

/home/yunwei/libebpf/example/bpf/btf-relo.bpf.o:        file format elf64-bpf

Sections:
Idx Name                   Size     VMA              Type
  0                        00000000 0000000000000000 
  1 .strtab                000000e5 0000000000000000 
  2 .text                  00000020 0000000000000000 TEXT
  3 .bss                   00000008 0000000000000000 BSS
  4 .debug_abbrev          00000086 0000000000000000 DEBUG
  5 .debug_info            00000086 0000000000000000 DEBUG
  6 .rel.debug_info        00000040 0000000000000000 
  7 .debug_str_offsets     00000034 0000000000000000 DEBUG
  8 .rel.debug_str_offsets 000000b0 0000000000000000 
  9 .debug_str             00000072 0000000000000000 DEBUG
 10 .debug_addr            00000018 0000000000000000 DEBUG
 11 .rel.debug_addr        00000020 0000000000000000 
 12 .BTF                   0000014e 0000000000000000 
 13 .rel.BTF               00000010 0000000000000000 
 14 .BTF.ext               00000080 0000000000000000 
 15 .rel.BTF.ext           00000050 0000000000000000 
 16 .debug_frame           00000028 0000000000000000 DEBUG
 17 .rel.debug_frame       00000020 0000000000000000 
 18 .debug_line            00000066 0000000000000000 DEBUG
 19 .rel.debug_line        00000030 0000000000000000 
 20 .debug_line_str        00000030 0000000000000000 DEBUG
 21 .llvm_addrsig          00000000 0000000000000000 
 22 .symtab                00000120 0000000000000000 
```