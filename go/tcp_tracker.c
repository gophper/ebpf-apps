#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcp_tracker.skel.h"
#include "tcp_tracker.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

// 打印连接信息
static void print_event(struct conn_event *e)
{
    char saddr_str[INET_ADDRSTRLEN];
    char daddr_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &e->saddr, saddr_str, sizeof(saddr_str));
    inet_ntop(AF_INET, &e->daddr, daddr_str, sizeof(daddr_str));

    const char *state_str = (e->newstate == TCP_ESTABLISHED) ? "ESTABLISHED" : "CLOSED";

    printf("%-16s %-6d %-15s:%-5d -> %-15s:%-5d %s\n",
           e->comm, e->pid, saddr_str, ntohs(e->sport),
           daddr_str, ntohs(e->dport), state_str);
}



// perf buffer 回调函数
static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    printf("DEBUG: Received event, size: %u bytes, expected: %zu\n",
           size, sizeof(struct conn_event));

    // 检查数据大小是否匹配
    if (size != sizeof(struct conn_event)) {
        fprintf(stderr, "ERROR: Size mismatch! Expected %zu, got %u\n",
                sizeof(struct conn_event), size);
        return;
    }

    struct conn_event *e = data;

    // 检查指针有效性
    if (!e) {
        fprintf(stderr, "ERROR: Null data pointer!\n");
        return;
    }

    printf("DEBUG: Event contents - pid: %d, saddr: %x\n", e->pid, e->saddr);
    print_event(e);
}


int main(int argc, char **argv)
{

    printf("Event structure size: %zu bytes\n", sizeof(struct conn_event));
    struct tcp_tracker_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("%-16s %-6s %-21s -> %-21s %s\n",
           "COMM", "PID", "LOCAL", "REMOTE", "STATE");
    printf("---------------------------------------------------------------\n");

    // 打开和加载BPF程序
    skel = tcp_tracker_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 附加BPF程序
    err = tcp_tracker_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // 设置perf buffer
    struct perf_buffer_opts pb_opts = {
            .sample_cb = handle_event,
            .lost_cb = NULL,
            .ctx = NULL,
    };

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, &pb_opts);
    if (!pb) {
        err = -1;
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
    }

    printf("Tracking TCP connections... Press Ctrl-C to stop.\n");

    // 主循环
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

    cleanup:
    if (pb) perf_buffer__free(pb);
    tcp_tracker_bpf__destroy(skel);

    return err;
}
