// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
struct event {
    __u64 ts;
    __u32 src;
    __u32 dst;
    __u8 proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1<<20); // 1MB
} events SEC(".maps");

SEC("xdp")
int xdp_basic(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    struct event *e;
    e = bpf_ringbuf_reserve(&events,sizeof(*e), 0);
    if(!e)
        return XDP_PASS;
    e->ts = bpf_ktime_get_ns();
    e->src = ip->saddr;
    e->dst = ip->daddr;
    e->proto = ip-> protocol;

    bpf_ringbuf_submit(e, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
