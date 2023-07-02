CC=gcc
ARM32CC=arm-linux-gnueabi-gcc
ARM64CC=aarch64-linux-gnu-gcc
CFLAGS=-g -fno-pie -no-pie
ARMCFLAGS=-g -fpie

.PHONY: all clean arm32 arm64 x86

all: maps.off.txt 

maps: maps.c hook.c
	$(CC) $(CFLAGS) maps.c hook.c -o maps

maps.off.txt: maps
	nm maps | grep ' T ' > maps.off.txt

x86: maps.off.txt

arm32: maps-arm32.off.txt
	cp maps-arm32.off.txt maps.off.txt

maps-arm32: maps.c hook.c
	$(ARM32CC) $(ARMCFLAGS) maps.c hook.c -static -o maps-arm32

maps-arm32.off.txt: maps-arm32
	arm-linux-gnueabi-nm maps-arm32 | grep ' T ' > maps-arm32.off.txt

arm64: maps-arm64.off.txt
	cp maps-arm64.off.txt maps.off.txt

maps-arm64: maps.c hook.c
	$(ARM64CC) $(ARMCFLAGS) maps.c hook.c -static -o maps-arm64

maps-arm64.off.txt: maps-arm64
	aarch64-linux-gnu-nm maps-arm64 | grep ' T ' > maps-arm64.off.txt

clean:
	rm -f maps maps-arm32 maps-arm64 maps.off.txt maps-arm32.off.txt maps-arm64.off.txt
