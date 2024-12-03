//go:build ignore

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// 定义事件类型
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

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, sizeof(uint32_t));
    __uint(max_entries, 128);
} events SEC(".maps");

struct pkt_info {
    uint32_t event_type;     // 事件类型
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    char ifname[16];
    uint32_t hook;           // netfilter hook点
    uint32_t verdict;        // 处理结果
    uint32_t mark;           // 数据包标记
    uint32_t table;          // iptables表
    uint32_t chain;          // iptables链
    uint32_t rule_id;        // 规则ID
    uint8_t icmp_type;       // ICMP类型
    uint8_t icmp_code;       // ICMP代码
    char action[32];      // 动作描述
    uint32_t seq;            // ICMP序列号
    uint32_t drop_reason;    // 丢包原因
};

// 跟踪 netfilter 钩子点
SEC("kprobe/nf_hook_slow")
int trace_nf_hook(struct pt_regs *ctx)
{
    struct pkt_info info = {};
    info.event_type = EVT_NFHOOK;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &info, sizeof(info));
    return 0;
}

// 跟踪数据包发送
SEC("kprobe/dev_queue_xmit")
int trace_xmit(struct pt_regs *ctx)
{
    struct pkt_info info = {};
    info.event_type = EVT_XMIT;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &info, sizeof(info));
    return 0;
}

// 跟踪数据包丢弃
SEC("kprobe/kfree_skb")
int trace_drop(struct pt_regs *ctx)
{
    struct pkt_info info = {};
    info.event_type = EVT_DROP;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &info, sizeof(info));
    return 0;
}

// 跟踪路由决策
SEC("kprobe/ip_route_input_noref")
int trace_route(struct pt_regs *ctx)
{
    struct pkt_info info = {};
    info.event_type = EVT_ROUTE;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &info, sizeof(info));
    return 0;
}
