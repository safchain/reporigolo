#ifndef __OVERRIDE_CNT_USER_H
#define __OVERRIDE_CNT_USER_H

#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/version.h>

#include "include/bpf.h"
#include "include/bpf_helpers.h"

#include "common.h"
#include "hash.h"

SEC("kprobe/override_content")
int override_content(struct pt_regs *ctx)
{
    bpf_printk("USER\n");

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

    struct rk_fd_content_key_t fd_content_key = {
        .id = fd_attr->action.override_id,
        .chunk = fd_attr->override_chunk,
    };

    bpf_printk("ZZ: %s\n", fd_attr->override_chunk);

    struct rk_fd_content_t *fd_content = (struct rk_fd_content_t *)bpf_map_lookup_elem(&rk_fd_contents, &fd_content_key);
    if (!fd_content)
    {
        return 0;
    }

    int i = 0;

#pragma unroll
    for (i = 0; i != sizeof(fd_content->content); i++)
    {
        if (i == fd_content->size)
        {
            break;
        }

        bpf_probe_write_user(fd_attr->read_buf + i, &fd_content->content[i], 1);
    }

    return 0;
}
#endif
