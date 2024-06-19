#include <linux/bpf.h>
#include <linux/if_ether.h> // Include linux/if_ether.h for ETH_P_IP
#include <linux/in.h>       // Include linux/in.h for IPPROTO_TCP
#include <linux/tcp.h>
#include <linux/ip.h>   
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <netinet/in.h>

// Define cursor_advance function
static __always_inline void *cursor_advance(void *cursor, __u32 delta) {
    return (void *)(long long)(cursor + delta);
}

// Define BPF map
struct bpf_map_def SEC("maps") port_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u16),
    .max_entries = 1,
};

// Define BPF program
SEC("prog")
int drop_tcp_packets(struct __sk_buff *skb) {
    void *cursor = (void *)(long long)skb->data;
    struct ethhdr *eth = cursor;
    struct iphdr *ip = cursor_advance(cursor, sizeof(*eth)); // Use cursor_advance
    struct tcphdr *tcp = cursor_advance(cursor, sizeof(*eth) + sizeof(*ip)); // Use cursor_advance
    __u32 key = 0;
    __u16 *port = bpf_map_lookup_elem(&port_map, &key);

    if (eth->h_proto != htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    if (port && tcp->dest == htons(*port)) {
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
