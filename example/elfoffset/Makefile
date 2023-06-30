CC=gcc
CFLAGS=-g -fno-pie -no-pie
TARGET=myprogram

.PHONY: all clean

all: $(TARGET) offsets.txt
	./$(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) $< -o $@

offsets.txt: $(TARGET)
	nm $(TARGET) | grep ' T ' > offsets.txt

clean:
	rm -f $(TARGET) offsets.txt
