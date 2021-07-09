#ifndef __HASH_H
#define __HASH_H

#include "defs.h"

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
            break;
        update_hash_byte(hash, str[i]);
    }
}

#endif