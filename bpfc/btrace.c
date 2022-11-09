#include <asm/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/bpf.h>

struct syscall_data_t {
    u32 pid;
    u32 tgid;
    u32 syscallId;
    u64 ret;
    u64 args[6];
    char strBuf[256];
    unsigned char type;
};

BPF_PERF_OUTPUT(syscall_events);

struct sysdesc_t {
    u32 stringMask;
};
BPF_HASH(sysdesc, u32, struct sysdesc_t);

RAW_TRACEPOINT_PROBE(sys_enter){
    
    PROCESS_FILTER

    //ctx->args[0]指向的内容才是真正的寄存器
    struct pt_regs *regs = (struct pt_regs*)(ctx->args[0]);
    unsigned long syscall_id = ctx->args[1];

    struct syscall_data_t data = {0};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid;
    data.syscallId = syscall_id;
    data.tgid = pid_tgid >> 32;
    u32 key = syscall_id;
    struct sysdesc_t *desc = sysdesc.lookup(&key);
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        bpf_probe_read_kernel(&data.args[i], sizeof(u64), &regs->regs[i]);
        if (desc) {
            u32 pmask = 1 << i;
            u32 mask = desc->stringMask;
            //由于字符串参数不知道多长，ebpf栈只有512字节，所以只能分组发送
            if (mask & pmask) {
                data.strBuf[0] = 0;
                data.type = 2;
                bpf_probe_read_str(data.strBuf, sizeof(data.strBuf), (void*)data.args[i]);
                syscall_events.perf_submit(ctx, &data, sizeof(data));
            }
        }
    }
    data.type = 1;
    syscall_events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

RAW_TRACEPOINT_PROBE(sys_exit){
    struct pt_regs *regs = (struct pt_regs*)(ctx->args[0]);
    u64 ret = ctx->args[1];
    struct syscall_data_t data = {0};
    data.type = 3;
    data.ret = ret;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid;
    data.tgid = pid_tgid >> 32;
    //data.syscallId = syscall_id;

    //TODO get syscall id
    return 0;
}