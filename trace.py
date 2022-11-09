#!/usr/bin/python
# -*- coding: utf-8 -*-

from datetime import datetime
import argparse
import json
from bcc import BPF
from ctypes import *
import utils.sys_arm32
import utils.sys_arm64
import utils.bpf_utils

class SysDesc(Structure):
    _fields_ = [
            ("stringMask", c_int32)
            ]
#
g_sysStrParamMap = {}

def print_syscall_event(cpu, data, size):
    event = b["syscall_events"].event(data)

    if (event.type == 1):
        systbl = utils.sys_arm64.g_systbl
        if (event.syscallId in systbl):
            sysUserDesc = systbl[event.syscallId]
            sysMask = 0
            n = len(sysUserDesc)
            if (n > 2):
                sysMask = sysUserDesc[2]
            #
            syscallName = sysUserDesc[1]
            nArgs = sysUserDesc[0]
            outStr = "%d-%d %s(%d)"%(event.tgid, event.pid, syscallName, event.syscallId)
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
            print("pid %d id %d %d"%(event.pid, event.syscallId, event.args[1]))
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
#

#raw_tracepoint work since kernel 4.17
if __name__ == "__main__":
    c_file = "bpfc/trace.c"
    with open(c_file, "r") as f:
        c_src = f.read()
        c_src = utils.bpf_utils.insert_name_filter(c_src, "a.out")
        b = BPF(text=c_src)
        print("after compile")
        tbl = b["sysdesc"]

        systbl = utils.sys_arm64.g_systbl

        for sysId in systbl:
            sysUserDesc = systbl[sysId]
            sysMask = 0
            n = len(sysUserDesc)
            if (n > 2):
                sysMask = sysUserDesc[2]
            sysval = SysDesc(c_int32(sysMask))
            tbl[c_int(sysId)] = sysval
        #
        print("ready...")
        b["syscall_events"].open_perf_buffer(print_syscall_event)

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