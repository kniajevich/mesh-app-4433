#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

#define QOS_MARK_MASK 0xFF000000
#define QOS_MARK_SHIFT 24

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad[3];
};

struct flow_metrics {
    __u8  class_id;
    __u8  classified;
    __u16 pkt_count;
    __u32 last_len;
    __u64 last_time;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_metrics);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_table SEC(".maps");

SEC("classifier")
int tc_classify(struct __sk_buff *skb) {
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

    struct flow_key key = {0};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;

    void *l4_hdr = (void *)ip + (ip->ihl * 4);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        key.src_port = bpf_ntohs(tcp->source);
        key.dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        key.src_port = bpf_ntohs(udp->source);
        key.dst_port = bpf_ntohs(udp->dest);
    } else {
        return TC_ACT_OK;
    }

    __u64 now = bpf_ktime_get_ns();
    __u32 pkt_len = skb->len;

    struct flow_metrics *metric = bpf_map_lookup_elem(&flow_table, &key);
    if (metric) {
        if (metric->classified) {
            __u32 mark = skb->mark;
            mark &= ~QOS_MARK_MASK;
            mark |= ((__u32)metric->class_id << QOS_MARK_SHIFT);

            /* Принудительная 32-битная атомарная запись без разбивки на байты */
            asm volatile("" : "+r"(mark));
            skb->mark = mark;
        } else {
            metric->pkt_count++;
            metric->last_len = pkt_len;
            metric->last_time = now;
        }
    } else {
        struct flow_metrics init_m = {
            .class_id = 2,
            .classified = 0,
            .pkt_count = 1,
            .last_len = pkt_len,
            .last_time = now
        };
        bpf_map_update_elem(&flow_table, &key, &init_m, BPF_ANY);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
