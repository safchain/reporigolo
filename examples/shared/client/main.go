package main

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

const ebpfBytecode = "probe.o"

func recvMapFDs() ([]int, error) {
	conn, err := net.Dial("unix", "/tmp/maps.sock")
	if err != nil {
		panic(err)
	}

	f, err := conn.(*net.UnixConn).File()
	if err != nil {
		panic(err)
	}
	socket := int(f.Fd())
	defer f.Close()

	// recvmsg
	buf := make([]byte, syscall.CmsgSpace(4))
	_, _, _, _, err = syscall.Recvmsg(socket, nil, buf, 0)
	if err != nil {
		panic(err)
	}

	// parse control msgs
	var msgs []syscall.SocketControlMessage
	msgs, err = syscall.ParseSocketControlMessage(buf)

	return syscall.ParseUnixRights(&msgs[0])
}

func main() {
	fds, err := recvMapFDs()
	if err != nil {
		panic(err)
	}
	fmt.Printf("FDs: %d\n", fds)

	m, err := ebpf.NewMapFromFD(fds[0])
	if err != nil {
		panic(err)
	}

	p, err := ebpf.NewMapFromFD(fds[0])
	if err != nil {
		panic(err)
	}

	perfReader, err := perf.NewReader(p, 1)
	if err != nil {
		panic(err)
	}

	for {
		record, err := perfReader.Read()
		if err != nil {
			time.Sleep(time.Second)
		} else {
			fmt.Printf("%+v\n", record.RawSample)
		}
	}

	for {
		var pid uint32
		var size uint64

		entries := m.Iterate()
		for entries.Next(&pid, &size) {
			fmt.Printf("PID: %d => %d bytes \n", pid, size)
		}

		time.Sleep(time.Second)
	}
}
