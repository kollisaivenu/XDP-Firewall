#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} ip_blacklist SEC(".maps");

static __always_inline void *ptr_at(const struct xdp_md *ctx, int offset) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if(data + offset > data_end) return NULL;

    return data + offset;
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    strct ethhdr *eth = ptr_at(ctx, 0);

    if (!eth) return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS

    struct iphdr *ip = ptr_at(ctx, sizeof(*eth));

    if (!ip) return XDP_PASS;

    __u32 source_ip = ip->saddr;
    __u32 *is_blocked = bpf_map_lookup_elem(&ip_blacklist, &source_ip);

    if (is_blocked) {
        bpf_printk("XDP Drop: Blocked IP %x", source_ip);
        return XDP_DROP;
    }

    return XDP_PASS;
}