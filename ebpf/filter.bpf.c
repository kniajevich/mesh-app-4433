#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  _pad[3];
};

struct flow_metrics {
    __u8  class_id;
    __u8  classified;
    __u16 pkt_count;
    __u32 last_len;
    __u64 last_time;
};

// Заменено на LRU_HASH: ядро автоматически вытесняет неактивные сессии при 65k+ соединений
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
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

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    struct flow_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((unsigned char *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        key.src_port = bpf_ntohs(tcp->source);
        key.dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)((unsigned char *)ip + (ip->ihl * 4));
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        key.src_port = bpf_ntohs(udp->source);
        key.dst_port = bpf_ntohs(udp->dest);
    } else {
        return TC_ACT_OK;
    }

    struct flow_metrics *metric = bpf_map_lookup_elem(&flow_table, &key);
    __u64 now = bpf_ktime_get_ns();

    if (!metric) {
        struct flow_metrics new_metric = {};
        new_metric.class_id = 0;
        new_metric.classified = 0;
        new_metric.pkt_count = 1;
        new_metric.last_len = skb->len;
        new_metric.last_time = now;
        bpf_map_update_elem(&flow_table, &key, &new_metric, BPF_NOEXIST);
    } else {
        if (metric->pkt_count < 65535)
            metric->pkt_count++;
        metric->last_len = skb->len;
        metric->last_time = now;

        if (metric->classified) {
            skb->mark = ((__u32)metric->class_id << 24) | (skb->mark & 0x00FFFFFF);
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
