#ifndef SHARED_H
#define SHARED_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct event {
    __u8 type;
    __u8 action;  
};


#define TYPE_TCP 1
#define TYPE_UDP 2

#define ACTION_PASS 1
#define ACTION_DROP 2


#define EPERM 13

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

#endif /* SHARED_H */