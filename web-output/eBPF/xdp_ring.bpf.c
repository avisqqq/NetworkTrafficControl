// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // for IP
    __type(value, __u8);// dummy values
}blacklist SEC(".maps");

struct event {
    __u64 ts;
    __u64 seq;
    __u32 src;
    __u32 dst;
    __u8 proto;
    __u8 pad[7]; 
};

struct{
    __uint(type,BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key,__u32);
    __type(value,__u64);
} stats SEC(".maps");

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
    // FILTER SSH CONNECTION
    if(ip->protocol == IPPROTO_TCP){
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        if(bpf_ntohs(tcp->dest) == 22 ||
            bpf_ntohs(tcp->source) == 22)
                return XDP_PASS;
    }

    // BLACK LIST LOGIC
    __u32 src = ip-> saddr;
    __u32 dst = ip-> daddr;
    //Register stats table
    __u32 drop_key = 1;
    __u64 *drop = bpf_map_lookup_elem(&stats, &drop_key);
    __u32 pass_key = 0;
    __u64 *pass = bpf_map_lookup_elem(&stats, &pass_key);
    if (!drop || !pass)
    return XDP_PASS;
    //
    bpf_printk("SRC=%x DST=%x\n", src, dst);

    if(bpf_map_lookup_elem(&blacklist, &src) ||
           bpf_map_lookup_elem(&blacklist, &dst)){
        __sync_fetch_and_add(drop, 1);
        return XDP_DROP;
    }



    struct event *e;
    e = bpf_ringbuf_reserve(&events,sizeof(*e), 0);
    if(!e)
        return XDP_PASS;
    e->ts = bpf_ktime_get_ns();
    e->seq = *pass;
    __sync_fetch_and_add(pass, 1);
    e->src = ip->saddr;
    e->dst = ip->daddr;
    e->proto = ip-> protocol;

    bpf_ringbuf_submit(e, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
