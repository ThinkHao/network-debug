#ifndef __BPF_ENDIAN_H__
#define __BPF_ENDIAN_H__

#include <stdint.h>

static __attribute__((always_inline)) uint16_t bpf_ntohs(uint16_t h)
{
    return (h & 0x00ff) << 8 | (h & 0xff00) >> 8;
}

static __attribute__((always_inline)) uint16_t bpf_htons(uint16_t h)
{
    return (h & 0x00ff) << 8 | (h & 0xff00) >> 8;
}

static __attribute__((always_inline)) uint32_t bpf_ntohl(uint32_t h)
{
    return ((h & 0x000000ff) << 24) |
           ((h & 0x0000ff00) << 8)  |
           ((h & 0x00ff0000) >> 8)  |
           ((h & 0xff000000) >> 24);
}

static __attribute__((always_inline)) uint32_t bpf_htonl(uint32_t h)
{
    return ((h & 0x000000ff) << 24) |
           ((h & 0x0000ff00) << 8)  |
           ((h & 0x00ff0000) >> 8)  |
           ((h & 0xff000000) >> 24);
}

#endif // __BPF_ENDIAN_H__
