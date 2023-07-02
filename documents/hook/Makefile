CC=gcc
ARMCC=arm-linux-gnueabi-gcc
CFLAGS=-g -fno-pie -no-pie
ARMCFLAGS=-g -fpie

.PHONY: all clean arm x86

all: maps.off.txt maps-arm.off.txt

maps: maps.c hook.c
	$(CC) $(CFLAGS) maps.c hook.c -o maps

maps.off.txt: maps
	nm maps | grep ' T ' > maps.off.txt

x86: maps.off.txt
arm: maps-arm.off.txt
	cp maps-arm.off.txt maps.off.txt

maps-arm: maps.c hook.c
	$(ARMCC) $(ARMCFLAGS) maps.c hook.c -static -o maps-arm

maps-arm.off.txt: maps-arm
	arm-linux-gnueabi-nm maps-arm | grep ' T ' > maps-arm.off.txt

clean:
	rm -f maps maps-arm maps.off.txt maps-arm.off.txt
