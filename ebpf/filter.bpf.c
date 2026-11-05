#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

// Маска старшего байта skb->mark для изоляции от внутренних меток OpenWrt fw4
#define QOS_MARK_MASK 0xFF000000
#define QOS_MARK_SHIFT 24

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

struct flow_metrics {
    __u8  class_id;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_metrics);
} flow_table SEC(".maps");

SEC("classifier")
int tc_classify(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Проверка Ethernet заголовка
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    // Проверка IPv4 заголовка
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Защита от malformed пакетов: IHL должна быть не менее 5
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
        // Big-Endian в Host-Endian
        key.src_port = bpf_ntohs(tcp->source);
        key.dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        // Big-Endian в Host-Endian
        key.src_port = bpf_ntohs(udp->source);
        key.dst_port = bpf_ntohs(udp->dest);
    } else {
        return TC_ACT_OK;
    }

    struct flow_metrics *metric = bpf_map_lookup_elem(&flow_table, &key);
    if (metric) {
        // Запись класса strictly в верхний байт без затирания NAT/маршрутных меток fw4
        __u32 current_mark = skb->mark & ~QOS_MARK_MASK;
        skb->mark = current_mark | ((__u32)metric->class_id << QOS_MARK_SHIFT);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
