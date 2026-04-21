// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif



//Single package structure for ring buffer
struct event {
    __u64 ts;
    __u64 seq;
    __u32 src;
    __u32 dst;
    __u8 proto;
    __u8 action;
    __u8 pad[6]; 
};


enum event_action{
    ACT_PASS = 0,
    ACT_DROP = 1,
    ACT_SKIP = 2,
    ACT_SSH_BYPASS = 3,
};

enum stat_key{
    STAT_PASS = 0,
    STAT_DROP = 1,
    STAT_SKIP = 2,
};

//Blacklist declaration
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // for IP
    __type(value, __u8);// dummy values
}blacklist SEC(".maps");

//Whitelist declaration
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32); // for IP
    __type(value, __u8);// dummy values
}whitelist SEC(".maps");

//Stats table declaration
struct{
    __uint(type,BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key,__u32);
    __type(value,__u64);
} stats SEC(".maps");

//Ring buffer declaration(All packages will be sent to user space through this buffer)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1<<20); // 1MB
} events SEC(".maps");

struct{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} seq_map SEC(".maps");

static __always_inline void inc_stat(__u32 key){
    __u64 *v = bpf_map_lookup_elem(&stats, &key);
    if(v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline __u64 next_seq(void){
    __u32 key = 0;
    __u64 *v = bpf_map_lookup_elem(&seq_map, &key);
    if (!v)
        return 0;
    return __sync_fetch_and_add(v, 1);
}

static __always_inline void emit_event(__u32 src, __u32 dst, __u8 proto, __u8 action){
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if(!e)
        return;

    e->ts = bpf_ktime_get_boot_ns();
    e->seq = next_seq();
    e->src = src;
    e->dst = dst;
    e->proto = proto;
    e->action = action;

    bpf_ringbuf_submit(e, 0);
}

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

    __u32 ip_hdr_len = ip->ihl * 4;
    if(ip_hdr_len < sizeof(*ip))
        return XDP_PASS;
    if((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    __u32 src = ip->saddr;
    __u32 dst = ip->daddr;
    

    // FILTER SSH CONNECTION
    if(ip->protocol == IPPROTO_TCP){
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        if(bpf_ntohs(tcp->dest) == 22 ||
            bpf_ntohs(tcp->source) == 22){
            emit_event(src, dst, ip->protocol, ACT_SSH_BYPASS);
                return XDP_PASS;
        }
    }

    if(bpf_map_lookup_elem(&blacklist, &src) ||
           bpf_map_lookup_elem(&blacklist, &dst)){
        inc_stat(STAT_DROP);
        emit_event(src, dst, ip->protocol, ACT_DROP);
        return XDP_DROP;
    }

    if(bpf_map_lookup_elem(&whitelist, &src) ||
           bpf_map_lookup_elem(&whitelist, &dst)){
        inc_stat(STAT_SKIP);
        emit_event(src, dst, ip->protocol, ACT_SKIP);
        return XDP_PASS;
    }

    inc_stat(STAT_PASS);
    emit_event(src, dst, ip->protocol, ACT_PASS);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
