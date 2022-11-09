#!/usr/bin/python
from __future__ import print_function

from datetime import datetime
from time import sleep
import argparse
import json
from bcc import BPF
from utils.bpf_utils import *

parser = argparse.ArgumentParser(description="Hide `su` binary.")

program_filter = parser.add_mutually_exclusive_group(required=True)
program_filter.add_argument("-p", "--pid", type=int)
program_filter.add_argument("-n", "--name", type=str)

parser.add_argument("--dump_prog", action="store_true")
args = parser.parse_args()

bpf_text = """
#include <asm/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/bpf.h>

struct syscall_w_fname_data_t {
    u64 timestamp;
    long pid;
    char fname[NAME_MAX];
};

BPF_PERF_OUTPUT(syscall_fname_events);

int syscall__faccessat(struct pt_regs *ctx, int dfd,
    const char __user* filename)
{
    PROCESS_FILTER

    struct syscall_w_fname_data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    data.timestamp = bpf_ktime_get_ns();

    bpf_probe_read(&data.fname, sizeof(data.fname), (void *)filename);

    size_t fname_len = 0;
    #pragma unroll
    for (fname_len = 0; fname_len < NAME_MAX; fname_len++) {
        if (data.fname[fname_len] == '\\0') {
            break;
        }
    }

    if (data.fname[fname_len - 3] == '/' &&
        data.fname[fname_len - 2] == 's' &&
        data.fname[fname_len - 1] == 'u')
    {
        char placeholder[] = "/tmp/aGGGGGG";
        long r = bpf_probe_write_user((void*)filename, placeholder, sizeof(placeholder));
        bpf_trace_printk("bpf_probe_write_user return %lld\\n", r);
        syscall_fname_events.perf_submit(ctx, &data, sizeof(data));
    }

    SUPERUSER_FILES

    return 0;
}
"""

if args.pid:
    bpf_text = insert_pid_filter(bpf_text, args.pid)
else:
    bpf_text = insert_name_filter(bpf_text, args.name)


superuser_files_filter = ""
for f in [
    "/system/app/Superuser.apk",
    "/system/xbin/daemonsu",
    "/system/etc/init.d/99SuperSUDaemon",
    "/system/bin/.ext/.su",
    "/system/etc/.has_su_daemon",
    "/system/etc/.installed_su_daemon",
    "/dev/com.koushikdutta.superuser.daemon"
]:
    compare_statement = []
    for index, char in enumerate(f):
        compare_statement.append(
            "(data.fname[{}] == '{}')".format(index, char))
    compare_statement = " && ".join(compare_statement)

    tmp_filter = """
    if ({}) {{
        char placeholder[] = "/tmp/aGGGGGG";
        long r = bpf_probe_write_user((void*)filename, placeholder, sizeof(placeholder));
        bpf_trace_printk("bpf_probe_write_user return %ld\\n", r);
        syscall_fname_events.perf_submit(ctx, &data, sizeof(data));
    }}
    """.format(compare_statement)

    superuser_files_filter += tmp_filter

bpf_text = bpf_text.replace("SUPERUSER_FILES", superuser_files_filter)


if args.dump_prog:
    print(bpf_text)
    exit()


def print_faccessat_event(cpu, data, size):
    event = b["syscall_fname_events"].event(data)
    print("[{}] [{}] {}".format(event.timestamp, event.pid, event.fname))

print("Hiding `su`... CTRL-C to quit.")
b = BPF(text=bpf_text)

syscall_fnname = b.get_syscall_fnname("faccessat")
b.attach_kprobe(event=syscall_fnname, fn_name="syscall__faccessat")

b["syscall_fname_events"].open_perf_buffer(print_faccessat_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()