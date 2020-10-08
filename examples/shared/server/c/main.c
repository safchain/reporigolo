#include <linux/kconfig.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/ptrace.h>
#pragma clang diagnostic pop

#include "include/bpf_map.h"
#include "include/bpf.h"
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps/read") map_read = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(size_t),
    .max_entries = 512,
    .map_flags = BPF_F_NO_PREALLOC,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct read_t
{
    u64 pid;
    size_t size;
};

struct bpf_map_def SEC("maps/perf") read_events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 64
};

SEC("kprobe/vfs_read")
int kprobe__vfs_read(struct pt_regs *ctx)
{   
    u32 pid;
    size_t size;

    pid = bpf_get_current_pid_tgid();

    size = (size_t) PT_REGS_PARM3(ctx);
    size_t *prev = bpf_map_lookup_elem(&map_read, &pid);
    if (prev) {
        size += *prev;
    }

    bpf_map_update_elem(&map_read, &pid, &size, BPF_ANY);

    struct read_t rd = {
        .pid = pid,
        .size = size
    };

    bpf_perf_event_output(ctx, &read_events, BPF_F_CURRENT_CPU, &rd, sizeof(rd));

    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
