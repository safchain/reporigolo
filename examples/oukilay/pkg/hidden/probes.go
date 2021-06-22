package hidden

import "github.com/DataDog/ebpf/manager"

var (
	MainProbes = []*manager.Probe{
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
	}

	OverrideProbes = []*manager.Probe{
		{
			UID:     "Second",
			Section: "kretprobe/__x64_sys_getdents64",
		},
	}
)
