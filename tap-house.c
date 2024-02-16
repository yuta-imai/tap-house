#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/bpf.h>

#define IP_PROTO_GRE 47

struct gre_hdr
{
    u16 flags;
    u16 protocol;
};

struct packet_key
{
    u32 protocol;
    u32 src_ip;
    u32 src_port;
    u32 dst_ip;
    u32 dst_port;
};

struct packet_value
{
    u64 payload_len_total;
    u32 packet_count;
};

BPF_HASH(packet_stats, struct packet_key, struct packet_value);

static __always_inline int parse_gre(struct xdp_md *ctx, u8 *data, u64 nh_off, struct packet_key *key)
{
    struct gre_hdr *gre_hdr;
    gre_hdr = (struct gre_hdr *)(data + nh_off);

    if ((void *)(gre_hdr + 1) > (void *)(long)ctx->data_end)
    {
        return XDP_DROP;
    }

    // GRE flags and protocol can be processed here if needed

    nh_off += sizeof(struct gre_hdr);
    return nh_off;
}

int gre_aggregate_filter(struct xdp_md *ctx)
{
    u8 *data = (u8 *)(long)ctx->data;
    u8 *data_end = (u8 *)(long)ctx->data_end;
    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr *ip;
    struct iphdr *inner_ip;
    u64 nh_off = sizeof(*eth);
    struct packet_key key = {};
    struct packet_value *value, init_val = {};

    // Drop packets that are not large enough to contain an Ethernet header
    if (data + nh_off > data_end)
        return XDP_DROP;

    // Drop non-IP packets
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_DROP;

    // Parse IP header
    ip = (struct iphdr *)(data + nh_off);
    nh_off += sizeof(struct iphdr);
    if (data + nh_off > data_end)
        return XDP_DROP;

    // Let PASS all non-mirrored packets by SORACOM Junction
    if (ip->daddr != htonl(0x0A000064) || ip->protocol != IP_PROTO_GRE)
        return XDP_PASS;

    // Parse GRE header and remove the encapsulation
    nh_off = parse_gre(ctx, data, nh_off, &key);
    if (nh_off == XDP_DROP)
        return XDP_DROP;

    // Parse inner IP header
    nh_off += sizeof(struct ethhdr);
    inner_ip = (struct iphdr *)(data + nh_off);
    if ((void *)(inner_ip + 1) > (void *)(long)ctx->data_end)
        return XDP_DROP;

    // Set key values for BPF map
    key.protocol = inner_ip->protocol;
    key.src_ip = inner_ip->saddr;
    key.dst_ip = inner_ip->daddr;
    key.src_port = 0; // Update if needed
    key.dst_port = 0; // Update if needed

    // Lookup or initialize the value in the hash map
    value = packet_stats.lookup_or_init(&key, &init_val);
    if (value)
    {
        value->payload_len_total += data_end - data - nh_off;
        value->packet_count++;
    }
    return XDP_DROP;
}
