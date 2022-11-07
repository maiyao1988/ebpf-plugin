#include <asm/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/bpf.h>


struct sysdesc_t {
    u32 nArgs;
    u32 stringMask;
    char syscallName[50];
};
//BPF_PERF_OUTPUT(events);
BPF_HASH(sysdesc, u32, struct sysdesc_t);

RAW_TRACEPOINT_PROBE(sys_enter){
    // // TP_PROTO(struct task_struct *p)
    // struct task_struct *p = (struct task_struct *)ctx->args[0];
    // u32 tgid, pid;
    // bpf_probe_read_kernel(&tgid, sizeof(tgid), &p->tgid);
    // bpf_probe_read_kernel(&pid, sizeof(pid), &p->pid);
    // return trace_enqueue(tgid, pid);
    //uint64_t id2 = 0;   
    //bpf_probe_read_kernel(&id2, sizeof(id2), &regs->regs[7]);
    char proc_name[50] = {0};
    struct pt_regs *regs = 0;

    bpf_get_current_comm(&proc_name, sizeof(proc_name));
    if (proc_name[0] == 'a' && proc_name[1] == '.' && proc_name[2] == 'o' && proc_name[3] == 'u' && proc_name[4] == 't') {
        //ctx->args[0]指向的内容才是真正的寄存器
        regs = (struct pt_regs*)(ctx->args[0]);
        unsigned long syscall_id = ctx->args[1];
        //if (syscall_id == 334) {
        if (syscall_id == 48) {
            bpf_trace_printk("call faccessat\n");
            u32 key = syscall_id;
            struct sysdesc_t *val = sysdesc.lookup(&key);
            bpf_trace_printk("map val %p\n", val);
            if (val) {
                bpf_trace_printk("%d %d %s\n", val->nArgs, val->stringMask, val->syscallName);
            }

            const char *filename = 0;
            //ctx->args[0]指向的内容是内核地址，不能直接用，要用需要read kernel
            bpf_probe_read_kernel(&filename, sizeof(filename), &PT_REGS_PARM2(regs));

            bpf_probe_read_str(proc_name, sizeof(proc_name), (void *)filename);
            bpf_trace_printk("filename %s %p\n", proc_name, filename);
        }
        bpf_trace_printk("sys_enter syscall id %d\n", syscall_id);
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