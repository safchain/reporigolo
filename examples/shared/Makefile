server: build-ebpf build-server run-server

build-ebpf:
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-I/lib/modules/$$(uname -r)/build/include \
		-I/lib/modules/$$(uname -r)/build/include/uapi \
		-I/lib/modules/$$(uname -r)/build/include/generated/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/generated \
		-O2 -emit-llvm \
		server/c/main.c \
		-c -o - | llc -march=bpf -filetype=obj -o probe.o

build-server:
	go build -o bin/server server/main.go

run-server:
	sudo bin/server

client: build-client run-client

build-client:
	go build -o bin/client client/main.go

run-client:
	bin/client

