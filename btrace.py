#!/usr/bin/python
# -*- coding: utf-8 -*-

from datetime import datetime
import argparse
import json
from bcc import BPF
from ctypes import *
import argparse
import utils.sys_arm32
import utils.sys_arm64
import utils.bpf_utils

class SysDesc(Structure):
    _fields_ = [
            ("stringMask", c_int32)
    ]
#
class InputDesc(Structure):
    _fields_ = [
            ("is32", c_byte)
    ]
#

g_sys_platform = utils.sys_arm64

g_sysStrParamMap = {}

def print_syscall_event(cpu, data, size):
    event = b["syscall_events"].event(data)

    if (event.type == 1):
        systbl = g_sys_platform.g_systbl
        if (event.syscallId in systbl):
            sysUserDesc = systbl[event.syscallId]
            sysMask = 0
            n = len(sysUserDesc)
            if (n > 2):
                sysMask = sysUserDesc[2]
            #
            syscallName = sysUserDesc[1]
            nArgs = sysUserDesc[0]
            outStr = "%d-%d %s(%d) (0x%08x) (0x%08x)"%(event.tgid, event.pid, syscallName, event.syscallId, event.pc, event.lr)
            listId = 0
            for i in range(0, nArgs):
                mask = 1 << i
                if (mask & sysMask):
                    assert (event.pid, event.syscallId) in g_sysStrParamMap
                    paramList = g_sysStrParamMap[(event.pid, event.syscallId)]
                    valStr = paramList[listId]
                    listId += 1
                    outStr += " [%s]"%valStr
                #
                else:
                    outStr += " [0x%08x]"%event.args[i]
                #
            #
            print(outStr)
            if ((event.pid, event.syscallId) in g_sysStrParamMap):
                g_sysStrParamMap.pop((event.pid, event.syscallId))
            #
        #
        else:
            print("%d-%d *unknown*(%d) (0x%08x) (0x%08x) [0x%08x] [0x%08x] [0x%08x] [0x%08x] [0x%08x] [0x%08x]"%(event.tgid, event.pid, event.syscallId, event.pc, event.lr, event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5]))
        #
    elif (event.type == 2):
        #收集字符串参数
        val = None
        if (event.pid, event.syscallId) in g_sysStrParamMap:
            val = g_sysStrParamMap[(event.pid, event.syscallId)]
        else:
            val = []
            g_sysStrParamMap[(event.pid, event.syscallId)] = val
        #
        val.append(event.strBuf)
        #print("2 pid %d %r"%(event.pid, event.strBuf))
    #
    elif(event.type == 3):        
        systbl = g_sys_platform.g_systbl
        if (event.syscallId in systbl):
            sysUserDesc = systbl[event.syscallId]
            syscallName = sysUserDesc[1]
            outStr = "%d-%d %s(%d) return [0x%08x]"%(event.tgid, event.pid, syscallName, event.syscallId, event.ret)
            print(outStr)
        #
        else:
           print("%d-%d *unknown*(%d) return [0x%08x]"%(event.tgid, event.pid, event.syscallId, event.ret)) 
    #
#


#raw_tracepoint work since kernel 4.17
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="trace syscall.")

    program_filter = parser.add_mutually_exclusive_group(required=True)
    program_filter.add_argument("-p", "--pid", help="use process id filter", type=int)
    program_filter.add_argument("-t", "--tid", help="use thread id filter", type=int)
    program_filter.add_argument("-u", "--uid", help="use user id filter", type=int)
    program_filter.add_argument("-n", "--name", help="use process name filter", type=str)

    program_platform = parser.add_mutually_exclusive_group(required=True)

    program_platform.add_argument("-m32", help="the target process is 32bit", action="store_true")
    program_platform.add_argument("-m64", help="the target process is 64bit", action="store_true")

    args = parser.parse_args()

    c_file = "bpfc/btrace.c"
    with open(c_file, "r") as f:
        c_src = f.read()
        if args.pid:
            c_src = utils.bpf_utils.insert_pid_filter(c_src, args.pid)
        elif args.tid:
            c_src = utils.bpf_utils.insert_tid_filter(c_src, args.tid)
        elif args.uid:
            c_src = utils.bpf_utils.insert_uid_filter(c_src, args.uid)
        else:
            c_src = utils.bpf_utils.insert_name_filter(c_src, args.name)
        #
        b = BPF(text=c_src)
        input_map = b["input"]
        if(args.m32):
            inputVal = InputDesc(c_byte(1))
            input_map[c_int(0)] = inputVal
            g_sys_platform = utils.sys_arm32
        #
        else:
            inputVal = InputDesc(c_byte(0))
            input_map[c_int(0)] = inputVal
            g_sys_platform = utils.sys_arm64
        #
        systbl = g_sys_platform.g_systbl
        tbl = b["sysdesc"]
        for sysId in systbl:
            sysUserDesc = systbl[sysId]
            sysMask = 0
            n = len(sysUserDesc)
            if (n > 2):
                sysMask = sysUserDesc[2]
            sysval = SysDesc(c_int32(sysMask))
            tbl[c_int(sysId)] = sysval
        #
        print("monitoring...")
        #page_cnt必须设置大一点，否则会丢包
        b["syscall_events"].open_perf_buffer(print_syscall_event, page_cnt=2048)

        while True:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()
            #
        #
        #b.trace_print()
    #
#