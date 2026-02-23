// SPDX-License-Indetifier: GPL-2.0
#include <bits/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

SEC("xdp")
int xdp_basic(struct xdp_md *ctx){
	void *data = (void *)(long)ctx->data;	
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if(bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return XDP_PASS;


	struct iphdr *ip = (void *)(eth + 1);
	if((void *)(ip + 1) > data_end)
		return XDP_PASS;

	__u32 src = ip->saddr;
	__u32 dst = ip->daddr;

	if(ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
		if((void *)(tcp + 1) > data_end)
			return XDP_PASS;
		bpf_printk("TCP packet\n");
	}
	else if(ip->protocol == IPPROTO_UDP){
		struct udphdr *udp = (void *)ip + ip-> ihl * 4;
		if((void*)(udp + 1) > data_end)
			return XDP_PASS;

		bpf_printk("UPD packet\n");
	}
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

