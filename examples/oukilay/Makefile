all: build-ebpf build run

build-ebpf:
	mkdir -p ebpf/bin
	clang -D__KERNEL__ -DCONFIG_64BIT -D__BPF_TRACING__ -DKBUILD_MODNAME='"oukilay"' \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused -Wall \
		-Werror \
		-O2 -emit-llvm \
		-fno-stack-protector \
		-fno-color-diagnostics \
		-fno-unwind-tables \
		-fno-asynchronous-unwind-tables \
		-fno-jump-tables \
		-isystem /usr/src/linux-headers-$$(uname -r)/include \
		-isystem /usr/src/linux-headers-$$(uname -r)/include/uapi \
		-isystem /usr/src/linux-headers-$$(uname -r)/include/generated/uapi \
		-isystem /usr/src/linux-headers-$$(uname -r)/arch/x86/include \
		-isystem /usr/src/linux-headers-$$(uname -r)/arch/x86/include/uapi \
		-isystem /usr/src/linux-headers-$$(uname -r)/arch/x86/include/generated \
		ebpf/main.c \
		-c -o - | llc -march=bpf -filetype=obj -o ebpf/bin/probe.o
	go-bindata -pkg main -prefix "ebpf/bin" -o "probe.go" "ebpf/bin/probe.o"

build:
	go build -o bin/main .

run:
	sudo bin/main
