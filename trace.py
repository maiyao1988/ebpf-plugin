#!/usr/bin/python
# -*- coding: utf-8 -*-

from datetime import datetime
import argparse
import json
from bcc import BPF
from ctypes import *
import sys_arm32
import sys_arm64

class SysDesc(Structure):
    _fields_ = [("nArgs", c_int32),
            ("stringMask", c_int32),
            ("syscallName", c_char * 50)]
#
g_sysmaps = {}

def print_syscall_event(cpu, data, size):
    event = b["syscall_events"].event(data)

    if (event.type == 1):
        systbl = sys_arm64.g_systbl
        if (event.syscallId in systbl):
            sysUserDesc = systbl[event.syscallId]
            sysMask = 0
            n = len(sysUserDesc)
            if (n > 2):
                sysMask = sysUserDesc[2]
            #
            syscallName = sysUserDesc[1]
            nArgs = sysUserDesc[0]
            outStr = "%d -- %s(%d)"%(event.pid, syscallName, event.syscallId)
            listId = 0
            for i in range(0, nArgs):
                mask = 1 << i
                if (mask & sysMask):
                    assert (event.pid, event.syscallId) in g_sysmaps
                    paramList = g_sysmaps[(event.pid, event.syscallId)]
                    valStr = paramList[listId][1]
                    listId += 1
                    outStr += " [%s]"%valStr
                #
                else:
                    outStr += " [0x%08x]"%event.args[i]
                #
            #
            print(outStr)
            if ((event.pid, event.syscallId) in g_sysmaps):
                g_sysmaps.pop((event.pid, event.syscallId))
            #
        #
        else:
            print("pid %d id %d %d"%(event.pid, event.syscallId, event.args[1]))
    elif (event.type == 2):
        #收集字符串参数
        val = None
        if (event.pid, event.syscallId) in g_sysmaps:
            val = g_sysmaps[(event.pid, event.syscallId)]
        else:
            val = []
            g_sysmaps[(event.pid, event.syscallId)] = val
        #
        val.append((event.paramsIdx, event.strBuf))
        #print("2 pid %d %d %r"%(event.pid, event.paramsIdx, event.strBuf))
    #
#

#raw_tracepoint work since kernel 4.17
if __name__ == "__main__":
    b = BPF(src_file="trace.c")
    print("after compile")
    tbl = b["sysdesc"]

    systbl = sys_arm64.g_systbl

    for sysId in systbl:
        sysUserDesc = systbl[sysId]
        nArgs = sysUserDesc[0]
        syscallName = sysUserDesc[1].encode("utf-8")
        sysMask = 0
        n = len(sysUserDesc)
        if (n > 2):
            sysMask = sysUserDesc[2]
        sysval = SysDesc(c_int32(nArgs), c_int32(sysMask), syscallName)
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