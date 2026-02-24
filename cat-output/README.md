NetworkTrafficControl (my notes)
What is this?

This is my experiment with eBPF + XDP on Raspberry Pi.

Goal:

Catch packets directly in the Linux kernel before the normal networking stack processes them.

RPi acts as gateway:

WiFi clients → RPi → Internet

I attach an XDP program to an interface (wlan0 or eth0) and inspect packets at ingress.

What happens when a packet arrives?

Packet enters interface

XDP program runs immediately

I parse:

Ethernet header

IPv4 header

TCP / UDP

Program returns:

XDP_PASS → packet continues normally

XDP_DROP → packet is blocked

Currently using XDP_PASS.

Why vmlinux.h?

Instead of using /usr/include/linux/... headers (which break for eBPF), I generate:

sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

This file contains struct definitions from the running kernel (via BTF).

Benefits:

No header mismatch

No asm/types.h errors

Clean CO-RE workflow

If kernel updates → regenerate vmlinux.h.

How I compile

On RPi:

clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 \
  -c xdp_events.bpf.c -o xdp_events.bpf.o

This produces eBPF bytecode (not ARM, not x86).

How I attach
sudo ip link set dev wlan0 xdp obj xdp_events.bpf.o sec xdp

Check:

ip -details link show wlan0

If I see:

prog/xdp id XX

then XDP is attached.

Detach:

sudo ip link set dev wlan0 xdp off
Debugging with trace_pipe

When using:

bpf_printk("TCP packet\n");

Read output:

sudo mount -t debugfs none /sys/kernel/debug
sudo cat /sys/kernel/debug/tracing/trace_pipe

Example output:

bpf_trace_printk: TCP packet

Notes:

trace_pipe blocks

rate limited

debug only

not for production

XDP mode

On RPi WiFi I see:

xdpgeneric

This means:

Driver does not support native XDP

Kernel uses generic fallback mode

Lower performance

OK for development

For better performance → attach to eth0 (WAN).
