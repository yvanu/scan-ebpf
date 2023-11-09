// +build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

static volatile unsigned const long PORT;
static volatile unsigned const long PORT=12343;
#define MAX_SOCKS 64
#define MAX_MAP_ENTRIES 16


struct bpf_map_def SEC("maps") xsks_map = {
        .type = BPF_MAP_TYPE_XSKMAP,
        .key_size = sizeof(int),
        .value_size = sizeof(int),
        .max_entries = MAX_SOCKS,
};

struct bpf_map_def SEC("maps") qidconf_map = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(int),
        .max_entries = MAX_SOCKS,
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32); // source IPv4 address
	__type(value, __u32); // packet count
} xdp_stats_map SEC(".maps");



SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx){


    __u32 src_ip;
    int *qidconf, index = ctx->rx_queue_index;
    qidconf = bpf_map_lookup_elem(&qidconf_map, &index);
    if (!qidconf)
        return XDP_PASS;
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u16 h_proto = eth->h_proto;
    if ((void*)eth + sizeof(*eth) <= data_end) {
        if (bpf_htons(h_proto) == ETH_P_IP) {
            struct iphdr *ip = data + sizeof(*eth);
            if ((void*)ip + sizeof(*ip) <= data_end) {
                src_ip = (__u32)(ip->saddr);
                __u32 *pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &src_ip);
                if (pkt_count){
//                    if pkt_count>0{
//                        __sync_fetch_and_add(pkt_count, -1);
//                    }
                    return XDP_PASS;
                }else{
                    if (ip->protocol == IPPROTO_TCP) {
                        __u32 init_pkt_count = 1;
                        bpf_map_update_elem(&xdp_stats_map, &src_ip, &init_pkt_count, BPF_ANY);
                        // 验证目的端口是不是扫描程序的端口
                        struct tcphdr *tcp = (void*)(long)ip+sizeof(*ip);
                        if ((void*)tcp + sizeof(*tcp) <= data_end){
                            if (tcp->dest == bpf_htons(PORT)){
                                return bpf_redirect_map(&xsks_map, index, 0);
                            }
                        }
                    }
                }
            }
        }
    }
    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";