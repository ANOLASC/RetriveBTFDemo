GCC = gcc
TARGET = btfdemo

clean:
	rm $(TARGET)

INCLUDE += -I./libbpf/include/uapi
LIBRARY_PATH += -L./libbpf/src/
DYNSO += -lbpf
DYNSO += -lelf
DYNSO += -lz

CFLAGS += -static
CFLAGS += -Wall
CFLAGS += -o

$(TARGET): main.c
	$(GCC) main.c $(INCLUDE) $(LIBRARY_PATH) $(DYNSO) $(CFLAGS) $(TARGET) -g

.DEFAULT_GOAL := $(TARGET)
