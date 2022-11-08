#include <asm/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/bpf.h>

struct syscall_data_t {
    u32 pid;
    u32 tgid;
    u32 syscallId;
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
    char proc_name[50] = {0};
    struct pt_regs *regs = 0;

    bpf_get_current_comm(&proc_name, sizeof(proc_name));
    if (proc_name[0] == 'a' && proc_name[1] == '.' && proc_name[2] == 'o' && proc_name[3] == 'u' && proc_name[4] == 't') {
        //ctx->args[0]指向的内容才是真正的寄存器
        regs = (struct pt_regs*)(ctx->args[0]);
        unsigned long syscall_id = ctx->args[1];

        struct syscall_data_t data = {0};
        u64 pid_tgid = bpf_get_current_pid_tgid();
        data.pid = pid_tgid;
        data.syscallId = syscall_id;
        data.tgid = pid_tgid >> 32;
        u32 key = syscall_id;
        struct sysdesc_t *desc = sysdesc.lookup(&key);
        if (desc) {
            u32 mask = desc->stringMask;
            u32 offset = 0;
            #pragma unroll
            for (int i = 0; i < 6; i++) {
                bpf_probe_read_kernel(&data.args[i], sizeof(u64), &regs->regs[i]);
                u32 pmask = 1 << i;
                //由于字符串参数不知道多长，ebpf栈只有512字节，所以只能分组发送
                if (mask & pmask) {
                    data.strBuf[0] = 0;
                    data.type = 2;
                    bpf_probe_read_str(data.strBuf, sizeof(data.strBuf), (void*)data.args[i]);
                    syscall_events.perf_submit(ctx, &data, sizeof(data));
                }
            }
            data.type = 1;
            syscall_events.perf_submit(ctx, &data, sizeof(data));
        }
        else {
            bpf_trace_printk("sys_enter syscall id %d\n", syscall_id);
        }
    }

    return 0;
}

RAW_TRACEPOINT_PROBE(sys_exit){

    //struct pt_regs *regs;
    //regs = (struct pt_regs *) ctx->args[0];
    // struct pt_regs _regs;
    // bpf_probe_read(&_regs, sizeof(_regs), (void*)ctx->args[0]);
    // int ret = ctx->args[1];

    // bpf_trace_printk("exit syscall ret %d\n", ret);
    return 0;
}