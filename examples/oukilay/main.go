package main

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/manager"
)

var m = &manager.Manager{
	Probes: []*manager.Probe{
		{
			UID:     "ouki_openat_ret",
			Section: "kretprobe/__x64_sys_openat",
		},
		{
			UID:     "ouki_read",
			Section: "kprobe/__x64_sys_read",
		},
		{
			UID:     "ouki_read_ret",
			Section: "kretprobe/__x64_sys_read",
		},
		{
			UID:     "ouki_vfs_open",
			Section: "kprobe/vfs_open",
		},
	},
}

const (
	KMSG_PROG           = 1
	KPROBE_EVENTS_PROG  = 2
	FILL_WITH_ZERO_PROG = 3
)

var r = []manager.TailCallRoute{
	{
		ProgArrayName: "read_ret_progs",
		Key:           KMSG_PROG,
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			Section: "kprobe/kmsg",
		},
	},
	{
		ProgArrayName: "read_ret_progs",
		Key:           KPROBE_EVENTS_PROG,
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			Section: "kprobe/kprobe_events",
		},
	},
	{
		ProgArrayName: "read_ret_progs",
		Key:           FILL_WITH_ZERO_PROG,
		ProbeIdentificationPair: manager.ProbeIdentificationPair{
			Section: "kprobe/fill_with_zero",
		},
	},
}

var ByteOrder = binary.LittleEndian

func FNVHashByte(b []byte) uint64 {
	hash := fnv.New64a()
	hash.Write(b)
	return hash.Sum64()
}

func FNVHashStr(s string) uint64 {
	return FNVHashByte([]byte(s))
}

// PathKey represents a path node used to match in-kernel path
type PathKey struct {
	Path string
	Pos  uint64
}

// Write write binary representation
func (p *PathKey) Write(buffer []byte) {
	hash := FNVHashStr(p.Path)
	ByteOrder.PutUint64(buffer[0:8], hash)
	ByteOrder.PutUint64(buffer[8:16], p.Pos)
}

// Bytes returns array of byte representation
func (p *PathKey) Bytes() []byte {
	b := make([]byte, 16)
	p.Write(b)
	return b
}

// PathKeys returns a list of PathKey for the given path
func PathKeys(s string) []PathKey {
	var keys []PathKey

	els := strings.Split(s, "/")
	last := len(els) - 1

	for i, el := range els {
		keys = append(keys, PathKey{
			Path: el,
			Pos:  uint64(last - i),
		})
	}

	return keys
}

// PutPath put the path in the kernel map
func PutPath(m *ebpf.Map, path string, action PathAction) error {
	var zeroAction PathAction
	for i, key := range PathKeys(path) {
		if i == 0 {
			if err := m.Put(key.Bytes(), action.Bytes()); err != nil {
				return err
			}
		} else {
			if err := m.Put(key.Bytes(), zeroAction.Bytes()); err != nil {
				return err
			}
		}
	}

	return nil
}

const (
	KmsgAction uint64 = iota + 1
	KProbeEventsAction
)

// PathAction represents actions to apply for a path
type PathAction struct {
	FSType string
	Action uint64
}

// Write write binary representation
func (p *PathAction) Write(buffer []byte) {
	hash := FNVHashStr(p.FSType)
	ByteOrder.PutUint64(buffer[0:8], hash)
	ByteOrder.PutUint64(buffer[8:16], p.Action)
}

// Bytes returns array of byte representation
func (p *PathAction) Bytes() []byte {
	b := make([]byte, 16)
	p.Write(b)
	return b
}

var c = []manager.ConstantEditor{}

func main() {
	options := manager.Options{
		DefaultKProbeMaxActive: 512,
		DefaultProbeRetry:      2,
		DefaultProbeRetryDelay: time.Second,
		TailCallRouter:         r,
		ConstantEditors:        c,
	}

	// Initialize the manager
	if err := m.InitWithOptions(recoverAssets(), options); err != nil {
		panic(err)
	}

	// Start the manager
	if err := m.Start(); err != nil {
		panic(err)
	}

	fmt.Println("successfully started")

	keysMap, _, err := m.GetMap("oukilay_path_keys")
	if err != nil {
		log.Fatalf("unbale to insert keys: %s", err)
	}

	if keysMap != nil {
		action := PathAction{
			FSType: "devtmpfs",
			Action: KmsgAction,
		}
		if err := PutPath(keysMap, "kmsg", action); err != nil {
			log.Fatalf("unbale to insert keys: %s", err)
		}
	}

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
