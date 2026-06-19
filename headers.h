#ifndef __OPENAT_TRACE_BPF_H__
#define __OPENAT_TRACE_BPF_H__

#define PATH_MAX 4096
#define COMM_MAX 64
#define ARGS_MAX 6

struct event {
    __u32 pid;
    __u32 tgid;
    char comm[COMM_MAX];
    char path[PATH_MAX];
    __s32 flags;
};

struct sys_enter_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned long args[ARGS_MAX];
};

#endif
