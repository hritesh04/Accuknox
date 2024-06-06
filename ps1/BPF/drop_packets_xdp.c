#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <bpf/bpf_helpers.h>

#define TYPE_TCP 1
#define TYPE_UDP 2

#define ACTION_PASS 1
#define ACTION_DROP 2

struct event {
    __u8 type;
    __u8 action;  
};


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256*1024);
} buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 1);
} port_data SEC(".maps");


SEC("xdp")
int xdp_drop_tcp_ports(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // check if the packet is at least large enough to contain the Ethernet header
    // if not checked give bpf verfier - memory out of boundary error
    if (data + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    // check if the packet is IP
    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        
        // check if the packet is large enough to contain the IP header
        // if not checked give bpf verfier - memory out of boundary error
        if ((void *)(ip + 1) > data_end) {
            return XDP_PASS;
        }

        struct event *e = bpf_ringbuf_reserve(&buffer,sizeof(struct event),0);
        if (!e){
 		    return XDP_PASS;
        }

        e->type=TYPE_UDP;

        // check if the packet is TCP
        if (ip->protocol == IPPROTO_TCP) {
            // get the tcp header
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

            // check if the packet is large enough to contain TCP header
            // if not checked give bpf verfier - memory out of boundary error
            if ((void *)(tcp + 1) > data_end) {
                bpf_ringbuf_discard(e, 0);
                return XDP_PASS;
            }

            e->type=TYPE_TCP;

            // initialized default port and a key to lookup associated value from the bfp_hash
            __u64 port = 4040;
            __u64 key = 0;
            __u64 *customPort = bpf_map_lookup_elem(&port_data,&key);

            if(customPort){
                port = *customPort;
            }

            // drop packets destined for specific TCP ports (default 4040)
            if (tcp->dest == htons(port)) {
                e->action = ACTION_DROP;
                bpf_ringbuf_submit(e,0);
                
                return XDP_DROP;
            }
        }

        e->action=ACTION_PASS;
        bpf_ringbuf_submit(e,0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
