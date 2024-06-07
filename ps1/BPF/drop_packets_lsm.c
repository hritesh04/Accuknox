#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <netinet/in.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "shared.h"


SEC("lsm/socket_connect")
int lsm_tcp_drop(struct socket *sock, struct sockaddr *address, int addrlen){
    if (!sock || !address)
        return 0;                                                                             
                                                                        
    struct event *e = bpf_ringbuf_reserve(&buffer,sizeof(struct event),0);
        if (!e){
 		    return 0;
        }
    
    e->type = TYPE_TCP;

    // Extract destination port from the sockaddr structure
    unsigned short port = ntohs(((struct sockaddr_in *)address)->sin_port);

    __u64 key = 0;
    __u64 block_port = 4040;
    __u64 *custom_port = bpf_map_lookup_elem(&port_data,&key);

    if(custom_port){
        block_port = *custom_port;
    }

    if (port == block_port) {
        e->action = ACTION_DROP;
        bpf_ringbuf_submit(e, 0);
        return -EPERM;
    }

    e->action = ACTION_PASS;
    bpf_ringbuf_submit(e,0);
    return 0;
}

char _license[] SEC("license") = "GPL";