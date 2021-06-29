package hidden

import "github.com/DataDog/ebpf/manager"

var (
	MainProbes = []*manager.Probe{
		{
			Section: "kprobe/__x64_sys_finit_module",
		},
		{
			Section: "kprobe/__x64_sys_kill",
		},
		{
			Section: "kprobe/__x64_sys_signal",
		},
		{
			Section: "kretprobe/__x64_sys_openat",
		},
		{
			Section: "kretprobe/__x64_sys_stat",
		},
		{
			Section: "kretprobe/__x64_sys_lstat",
		},
		{
			Section: "kretprobe/__x64_sys_newlstat",
		},
		{
			Section: "kretprobe/__x64_sys_fstat",
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
			Section: "kprobe/vfs_getattr",
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
			Section: "kprobe/__x64_sys_unlink",
		},
		{
			Section: "kprobe/__x64_sys_unlinkat",
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
