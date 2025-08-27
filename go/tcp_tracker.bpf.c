#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tcp_tracker.h"
// 定义 perf buffer
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");


// 辅助函数：网络字节序转主机字节序（简化版）
static __u16 ntohs_simple(__u16 net_short)
{
    return (net_short >> 8) | (net_short << 8);
}

// 在内核态打印事件信息
static void print_event(struct conn_event *e)
{
    // 直接打印所有信息在一行
    bpf_printk("Event: %s[%d]",
               e->comm, e->pid);
}

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    // 只关注TCP连接建立和关闭事件
    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    if (ctx->newstate != TCP_ESTABLISHED && ctx->newstate != TCP_CLOSE)
        return 0;

    // 获取进程信息
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct conn_event e = {};
    e.protocol = ctx->protocol;
    e.pid = pid;
    e.newstate = ctx->newstate;

    // 正确读取IP地址
    bpf_probe_read_kernel(&e.saddr, sizeof(e.saddr), &ctx->saddr);
    bpf_probe_read_kernel(&e.daddr, sizeof(e.daddr), &ctx->daddr);

    // 读取端口号
    e.sport = ctx->sport;
    e.dport = ctx->dport;

    // 获取进程名
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    // 调试输出
    bpf_printk("Sending event: pid=%d, saddr=%x, daddr=%x", pid, e.saddr, e.daddr);

    // 打印事件详情
    print_event(&e);

    // 发送到perf buffer
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}
