CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

CFLAGS := -g -O2 -Wall
LDFLAGS :=

.PHONY: all clean

all: vmlinux.h tcp_tracker.h tcp_tracker

# 生成vmlinux.h（确保正确权限）
vmlinux.h:
	sudo $(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > temp_vmlinux.h
	mv temp_vmlinux.h vmlinux.h
	chmod 644 vmlinux.h  # 确保可读权限

# 编译BPF程序（BPF程序不需要静态编译）
tcp_tracker.bpf.o: tcp_tracker.bpf.c vmlinux.h tcp_tracker.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 \
	         -I. -c $< -o $@
	@if [ -f "$@" ]; then \
		sudo chown $(USER):$(USER) "$@"; \
		$(LLVM_STRIP) -g "$@"; \
	else \
		echo "Compilation failed"; \
		exit 1; \
	fi

# 生成BPF skeleton头文件
tcp_tracker.skel.h: tcp_tracker.bpf.o
	$(BPFTOOL) gen skeleton $< > $@
	chmod 644 $@  # 确保可读权限

# 编译用户空间程序（静态链接）
tcp_tracker: tcp_tracker.c tcp_tracker.skel.h
	$(CC) $(CFLAGS) -I. -c $< -o tcp_tracker.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ tcp_tracker.o -lbpf -lelf -lz

clean:
	rm -f *.o
	rm -f tcp_tracker
	rm -f tcp_tracker.skel.h
