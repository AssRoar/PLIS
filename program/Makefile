CLANG ?= clang
LLVM_STRIP ?= llvm-strip
ARCH := x86
INCLUDES := -I/usr/include -I/usr/include/x86_64-linux-gnu
LIBS_DIR := -L/usr/lib/lib64 -L/usr/lib/x86_64-linux-gnu
LIBS := -lbpf -lelf

.PHONY: all clean run

all: security.skel.h security.bpf.o security

run: all
	sudo ./security

clean:
	rm -f *.o
	rm -f security.skel.h

security.bpf.o: security.bpf.c
	$(CLANG) -g -O2 -Wall -target bpf -D__KERNEL__ -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $< -o $@
	$(LLVM_STRIP) -g $@

security.skel.h: security.bpf.o
	sudo bpftool gen skeleton $< > $@

security: security.c security.skel.h
	$(CC) -g -Wall -c $< -o $@.o
	$(CC) -g -o $@ $(LIBS_DIR) $@.o $(LIBS)

.DELETE_ON_ERROR: