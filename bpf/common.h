#ifndef __COMMON_H__
#define __COMMON_H__

#include <stddef.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdint.h>

/* Event types */
#define EVT_NFHOOK    1
#define EVT_XMIT      2
#define EVT_DROP      3
#define EVT_ROUTE     4

/* Netfilter hook points */
#define NF_INET_PRE_ROUTING   0
#define NF_INET_LOCAL_IN      1
#define NF_INET_FORWARD       2
#define NF_INET_LOCAL_OUT     3
#define NF_INET_POST_ROUTING  4

/* IP protocols */
#define IPPROTO_ICMP   1
#define IPPROTO_TCP    6
#define IPPROTO_UDP   17

/* BPF map types */
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4

/* Kernel structs */
struct pt_regs {
    uint64_t di;
    uint64_t si;
    uint64_t dx;
    uint64_t cx;
    uint64_t r8;
    uint64_t r9;
    uint64_t sp;
    uint64_t bp;
    uint64_t ax;
    uint64_t ip;
};

struct iphdr {
    uint8_t  version:4;
    uint8_t  ihl:4;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct icmphdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    union {
        struct {
            uint16_t id;
            uint16_t sequence;
        } echo;
        uint32_t gateway;
        struct {
            uint16_t __unused;
            uint16_t mtu;
        } frag;
        uint8_t reserved[4];
    } un;
};

struct sk_buff {
    uint64_t head;
    uint32_t network_header;
    uint32_t transport_header;
};

#endif /* __COMMON_H__ */
