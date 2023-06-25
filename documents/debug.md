
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
