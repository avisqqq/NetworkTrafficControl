// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#define DIR_INGRESS 0
#define DIR_EGRESS  1

struct event {
    __u64 ts;
    __u64 seq;

    __u8 src[16];
    __u8 dst[16];

    __u16 src_port;
    __u16 dst_port;
    __u16 pkt_size;

    __u8 proto;
    __u8 action;
    __u8 ip_version;
    __u8 direction;
    __u8 tcp_flags;
    __u8 pad[1];
};

enum event_action {
    ACT_PASS = 0,
    ACT_DROP = 1,
    ACT_SKIP = 2,
    ACT_SSH_BYPASS = 3,
};

enum stat_key {
    STAT_PASS = 0,
    STAT_DROP = 1,
    STAT_SKIP = 2,
};

struct ip_key {
    __u8 version;
    __u8 addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ip_key);
    __type(value, __u8);
} blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ip_key);
    __type(value, __u8);
} whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} seq_map SEC(".maps");

static __always_inline void inc_stat(__u32 key) {
    __u64 *v = bpf_map_lookup_elem(&stats, &key);
    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline __u64 next_seq(void) {
    __u32 key = 0;
    __u64 *v = bpf_map_lookup_elem(&seq_map, &key);
    if (!v)
        return 0;
    return __sync_fetch_and_add(v, 1);
}

static __always_inline void fill_ipv4_key(struct ip_key *key, __u32 addr) {
    __builtin_memset(key, 0, sizeof(*key));
    key->version = 4;
    __builtin_memcpy(key->addr, &addr, 4);
}

static __always_inline void fill_ipv6_key(struct ip_key *key, const struct in6_addr *addr) {
    __builtin_memset(key, 0, sizeof(*key));
    key->version = 6;
    __builtin_memcpy(key->addr, addr, 16);
}

static __always_inline void emit_event(
        const __u8 *src,
        const __u8 *dst,
        __u8 ip_version,
        __u8 proto,
        __u8 action,
        __u8 direction,
        __u16 src_port,
        __u16 dst_port,
        __u16 pkt_size,
        __u8 tcp_flags) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->ts = bpf_ktime_get_boot_ns();
    e->seq = next_seq();

    __builtin_memset(e->src, 0, 16);
    __builtin_memset(e->dst, 0, 16);

    if (ip_version == 4) {
        __builtin_memcpy(e->src, src, 4);
        __builtin_memcpy(e->dst, dst, 4);
    } else {
        __builtin_memcpy(e->src, src, 16);
        __builtin_memcpy(e->dst, dst, 16);
    }

    e->proto      = proto;
    e->action     = action;
    e->ip_version = ip_version;
    e->direction  = direction;
    e->src_port   = src_port;
    e->dst_port   = dst_port;
    e->pkt_size   = pkt_size;
    e->tcp_flags  = tcp_flags;

    bpf_ringbuf_submit(e, 0);
}

static __always_inline int handle_ipv4(
        void *data_end,
        struct ethhdr *eth,
        __u8 direction) {
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(*ip))
        return TC_ACT_OK;
    if ((void *)ip + ip_hdr_len > data_end)
        return TC_ACT_OK;

    __u32 src = ip->saddr;
    __u32 dst = ip->daddr;
    __u16 pkt_size = bpf_ntohs(ip->tot_len);

    __u16 src_port = 0, dst_port = 0;
    __u8  tcp_flags = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        src_port  = bpf_ntohs(tcp->source);
        dst_port  = bpf_ntohs(tcp->dest);
        tcp_flags = ((__u8 *)tcp)[13]; // flags byte: CWR|ECE|URG|ACK|PSH|RST|SYN|FIN
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    }

    struct ip_key src_key, dst_key;
    fill_ipv4_key(&src_key, src);
    fill_ipv4_key(&dst_key, dst);

    if (ip->protocol == IPPROTO_TCP && (src_port == 22 || dst_port == 22)) {
        emit_event((const __u8 *)&src, (const __u8 *)&dst, 4, ip->protocol,
                   ACT_SSH_BYPASS, direction, src_port, dst_port, pkt_size, tcp_flags);
        return TC_ACT_OK;
    }

    if (bpf_map_lookup_elem(&blacklist, &src_key) ||
        bpf_map_lookup_elem(&blacklist, &dst_key)) {
        inc_stat(STAT_DROP);
        emit_event((const __u8 *)&src, (const __u8 *)&dst, 4, ip->protocol,
                   ACT_DROP, direction, src_port, dst_port, pkt_size, tcp_flags);
        return TC_ACT_SHOT;
    }

    if (bpf_map_lookup_elem(&whitelist, &src_key) ||
        bpf_map_lookup_elem(&whitelist, &dst_key)) {
        inc_stat(STAT_SKIP);
        emit_event((const __u8 *)&src, (const __u8 *)&dst, 4, ip->protocol,
                   ACT_SKIP, direction, src_port, dst_port, pkt_size, tcp_flags);
        return TC_ACT_OK;
    }

    inc_stat(STAT_PASS);
    emit_event((const __u8 *)&src, (const __u8 *)&dst, 4, ip->protocol,
               ACT_PASS, direction, src_port, dst_port, pkt_size, tcp_flags);
    return TC_ACT_OK;
}

static __always_inline int handle_ipv6(
        void *data_end,
        struct ethhdr *eth,
        __u8 direction) {
    struct ipv6hdr *ipv6 = (void *)(eth + 1);
    if ((void *)(ipv6 + 1) > data_end)
        return TC_ACT_OK;

    __u16 pkt_size  = bpf_ntohs(ipv6->payload_len) + sizeof(*ipv6);
    __u16 src_port  = 0, dst_port = 0;
    __u8  tcp_flags = 0;

    if (ipv6->nexthdr == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ipv6 + 1);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        src_port  = bpf_ntohs(tcp->source);
        dst_port  = bpf_ntohs(tcp->dest);
        tcp_flags = ((__u8 *)tcp)[13];
    } else if (ipv6->nexthdr == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ipv6 + 1);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    }

    struct ip_key src_key, dst_key;
    fill_ipv6_key(&src_key, &ipv6->saddr);
    fill_ipv6_key(&dst_key, &ipv6->daddr);

    if (ipv6->nexthdr == IPPROTO_TCP && (src_port == 22 || dst_port == 22)) {
        emit_event((const __u8 *)&ipv6->saddr, (const __u8 *)&ipv6->daddr, 6, ipv6->nexthdr,
                   ACT_SSH_BYPASS, direction, src_port, dst_port, pkt_size, tcp_flags);
        return TC_ACT_OK;
    }

    if (bpf_map_lookup_elem(&blacklist, &src_key) ||
        bpf_map_lookup_elem(&blacklist, &dst_key)) {
        inc_stat(STAT_DROP);
        emit_event((const __u8 *)&ipv6->saddr, (const __u8 *)&ipv6->daddr, 6, ipv6->nexthdr,
                   ACT_DROP, direction, src_port, dst_port, pkt_size, tcp_flags);
        return TC_ACT_SHOT;
    }

    if (bpf_map_lookup_elem(&whitelist, &src_key) ||
        bpf_map_lookup_elem(&whitelist, &dst_key)) {
        inc_stat(STAT_SKIP);
        emit_event((const __u8 *)&ipv6->saddr, (const __u8 *)&ipv6->daddr, 6, ipv6->nexthdr,
                   ACT_SKIP, direction, src_port, dst_port, pkt_size, tcp_flags);
        return TC_ACT_OK;
    }

    inc_stat(STAT_PASS);
    emit_event((const __u8 *)&ipv6->saddr, (const __u8 *)&ipv6->daddr, 6, ipv6->nexthdr,
               ACT_PASS, direction, src_port, dst_port, pkt_size, tcp_flags);
    return TC_ACT_OK;
}

static __always_inline int tc_handle(struct __sk_buff *skb, __u8 direction) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u16 h_proto = bpf_ntohs(eth->h_proto);

    if (h_proto == ETH_P_IP)
        return handle_ipv4(data_end, eth, direction);

    if (h_proto == ETH_P_IPV6)
        return handle_ipv6(data_end, eth, direction);

    return TC_ACT_OK;
}

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) {
    return tc_handle(skb, DIR_INGRESS);
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb) {
    return tc_handle(skb, DIR_EGRESS);
}

char LICENSE[] SEC("license") = "GPL";