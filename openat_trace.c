#include <bpf/bpf_helpers.h>
#include "headers.h"

#ifndef __NR_openat
#define __NR_openat 257
#endif

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_openat(struct sys_enter_ctx *ctx)
{
    if (ctx->__syscall_nr != __NR_openat)
        return 0;

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->tgid = (__u32)pid_tgid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->path, sizeof(e->path), filename);

    e->flags = (__s32)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
