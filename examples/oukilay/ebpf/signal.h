#ifndef __SIGNAL_H
#define __SIGNAL_H

#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/dirent.h>

#include "include/bpf.h"
#include "include/bpf_helpers.h"

static __attribute__((always_inline)) int handle_signal(struct pt_regs *ctx)
{
    u64 rk_pid;
    LOAD_CONSTANT("rk_pid", rk_pid);

   /* struct pt_regs *rctx = (struct pt_regs *)PT_REGS_PARM1(ctx);

    int pid;
    bpf_probe_read(&pid, sizeof(pid), &PT_REGS_PARM1(rctx));

    if (pid == rk_pid)
    {
        bpf_override_return(ctx, -ESRCH);
    }*/

    return 0;
}

SEC("kprobe/__x64_sys_signal")
int __x64_sys_signal(struct pt_regs *ctx)
{
    return handle_signal(ctx);
}

SEC("kprobe/__x64_sys_kill")
int __x64_sys_kill(struct pt_regs *ctx)
{
    return handle_signal(ctx);
}

#endif