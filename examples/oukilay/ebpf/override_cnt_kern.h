#ifndef __OVERRIDE_CNT_KERN_H
#define __OVERRIDE_CNT_KERN_H

#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/version.h>

#include "include/bpf.h"
#include "include/bpf_helpers.h"

#include "common.h"
#include "hash.h"

void __attribute__((always_inline)) override_content(struct pt_regs *ctx, struct rk_fd_attr_t *fd_attr)
{
    struct rk_fd_content_key_t fd_content_key = {
        .id = fd_attr->action.override_id,
        .chunk = fd_attr->override_chunk,
    };

    struct rk_fd_content_t *fd_content = (struct rk_fd_content_t *)bpf_map_lookup_elem(&rk_fd_contents, &fd_content_key);
    if (fd_content)
    {
        bpf_override_return(ctx, fd_content->size);
    }
    else
    {
        bpf_override_return(ctx, 0);
    }

    fd_attr->override_chunk++;
}

#endif