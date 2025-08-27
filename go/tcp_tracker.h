// tcp_tracker.h
#ifndef TCP_TRACKER_H
#define TCP_TRACKER_H
// 定义TCP状态常量
#ifndef TCP_ESTABLISHED
#define TCP_ESTABLISHED 1
#endif
#ifndef TCP_CLOSE
#define TCP_CLOSE 7
#endif

struct conn_event {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 newstate;
    __u32 pid;
    char comm[16];
};
