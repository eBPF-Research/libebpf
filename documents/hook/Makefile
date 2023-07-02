CC=gcc
CFLAGS=-g -fno-pie -no-pie

.PHONY: all clean

all: maps.off.txt 

# myprogram: myprogram.c
# 	$(CC) -fno-pie -no-pie myprogram.c -o myprogram

# myprogram.off.txt: myprogram
# 	nm myprogram | grep ' T ' > myprogram.off.txt

maps: maps.c hook.c
	$(CC) -g -fpie maps.c hook.c -o maps

maps.off.txt: maps
	nm maps | grep ' T ' > maps.off.txt

clean:
	rm -f maps myprogram offsets.txt
