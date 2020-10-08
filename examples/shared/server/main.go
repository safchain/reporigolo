package main

import (
	"log"
	"net"
	"os"
	"syscall"

	"github.com/iovisor/gobpf/elf"
)

const ebpfBytecode = "probe.o"

func sendFD(conn *net.UnixConn, fds ...int) error {
	f, err := conn.File()
	if err != nil {
		return err
	}
	socket := int(f.Fd())
	defer f.Close()

	rights := syscall.UnixRights(fds...)
	return syscall.Sendmsg(socket, nil, rights, nil, 0)
}

func serverMapFD(fds ...int) {
	os.Remove("/tmp/maps.sock")

	l, err := net.Listen("unix", "/tmp/maps.sock")
	if err != nil {
		log.Fatal("listen error:", err)
	}
	os.Chmod("/tmp/maps.sock", 0666)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("accept error:", err)
		}

		sendFD(conn.(*net.UnixConn), fds...)
		conn.Close()
	}
}

func main() {
	module := elf.NewModule(ebpfBytecode)
	if err := module.Load(nil); err != nil {
		panic(err)
	}

	module.EnableKprobes(-1)

	m := module.Map("read")
	if m == nil {
		panic("Map: read not found")
	}

	p := module.Map(("perf"))
	if m == nil {
		panic("Map: perf not found")
	}

	serverMapFD(m.Fd(), p.Fd())
}
