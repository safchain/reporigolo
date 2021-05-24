package main

import (
	"fmt"
	"github.com/DataDog/ebpf/manager"
	"os"
	"os/signal"
	"time"
	"syscall"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		&manager.Probe{
			UID:     "ouki_openat",
			Section: "kprobe/__x64_sys_openat",
		},
		&manager.Probe{
			UID:     "ouki_openat_ret",
			Section: "kretprobe/__x64_sys_openat",
		},
		&manager.Probe{
			UID:     "ouki_read",
			Section: "kprobe/__x64_sys_read",
		},
		&manager.Probe{
			UID:     "ouki_read_ret",
			Section: "kretprobe/__x64_sys_read",
		},
		&manager.Probe{
			UID:     "ouki_getname_flags",
			Section: "kprobe/getname_flags",
		},
	},
}

var r = []manager.TailCallRoute{
	{
		ProgArrayName: "read_ret_progs",
		Key:           1,
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			Section: "kprobe/kmsg",
		},
	},
	{
		ProgArrayName: "read_ret_progs",
		Key:           2,
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			Section: "kprobe/kprobe_events",
		},
	},
}

var c = []manager.ConstantEditor{}

func kmsg() (uint64, error) {
	err := syscall.Mkfifo("/tmp/.0", 0666)
	if err != nil {
		return 0, err
	}

	_, err = os.OpenFile("/tmp/.0", os.O_CREATE, os.ModeNamedPipe)
	if err != nil {
		return 0, err
	}

	fmt.Printf("opened :)\n")

	return 0, nil
}

func main() {
	go kmsg()

	options := manager.Options{
		DefaultKProbeMaxActive: 512,
		DefaultProbeRetry:      2,
		DefaultProbeRetryDelay: time.Second,
		TailCallRouter:         r,
		ConstantEditors: c,
	}

	options.ConstantEditors = append(options.ConstantEditors,
		manager.ConstantEditor{
			Name:  "kmsg_fd",
			Value: uint64(0),
		},
	)

	// Initialize the manager
	if err := m.InitWithOptions(recoverAssets(), options); err != nil {
		panic(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		panic(err)
	}

	fmt.Println("successfullssy started")

	wait()

	// Close the manager
	if err := m.Stop(manager.CleanAll); err != nil {
		panic(err)
	}
}

// wait - Waits until an interrupt or kill signal is sent
func wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)
	<-sig
	fmt.Println()
}
