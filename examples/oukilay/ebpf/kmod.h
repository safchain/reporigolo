#ifndef __KMOD_H
#define __KMOD_H

#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/dirent.h>

#include "include/bpf.h"
#include "include/bpf_helpers.h"

SEC("kprobe/__x64_sys_finit_module")
int __x64_sys_finit_module(struct pt_regs *ctx)
{
    bpf_override_return(ctx, -3);

    return 0;
}

#endif