#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

struct flow_meta {
    struct flow_key key;
    __u32 pkt_len;
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, __u8);
} flow_classes SEC(".maps");

SEC("tc")
int tc_classifier(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->ihl < 5)
        return TC_ACT_OK;

    struct flow_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.proto  = ip->protocol;

    void *l4 = (void *)ip + (ip->ihl * 4);
    if (l4 > data_end)
        return TC_ACT_OK;

    if (key.proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    } else if (key.proto == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    } else {
        return TC_ACT_OK;
    }

    __u8 *dscp = bpf_map_lookup_elem(&flow_classes, &key);
    if (dscp) {
        skb->priority = *dscp;
        return TC_ACT_OK;
    }

    struct flow_meta *meta = bpf_ringbuf_reserve(&ringbuf, sizeof(*meta), 0);
    if (meta) {
        meta->key = key;
        meta->pkt_len = skb->len;
        meta->timestamp = bpf_ktime_get_ns();
        bpf_ringbuf_submit(meta, 0);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";