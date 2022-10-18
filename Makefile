GCC = gcc
CLANG = clang-15
TARGET = btfdemo
MTARGET = map

clean:
	rm $(TARGET) $(MTARGET) *.o

INCLUDE += -I./libbpf/include
INCLUDE += -I./
# INCLUDE += -I/kernel-src/samples/bpf
# INCLUDE += -I/home/asss/Code/xdp-tutorial/headers

LIBRARY_PATH += -L./libbpf/src/
DYNSO += -lbpf
DYNSO += -lelf
DYNSO += -lz

CFLAGS += -static
CFLAGS += -Wall
CFLAGS += -o

$(TARGET): main.c
	$(GCC) main.c $(INCLUDE) $(LIBRARY_PATH) $(DYNSO) $(CFLAGS) $(TARGET) -g

mapmain:
	$(GCC) mapmain.c $(INCLUDE) $(LIBRARY_PATH) $(DYNSO) $(CFLAGS) mapmain -g

map: map.c
	$(CLANG) -O2 -target bpf -D__TARGET_ARCH_x86_64 -c map.c $(INCLUDE) $(CFLAGS) map -g

btf_load: btf_load.c
	$(GCC) btf_load.c $(INCLUDE) $(LIBRARY_PATH) $(DYNSO) $(CFLAGS) btf_load -g

.DEFAULT_GOAL := $(TARGET)
