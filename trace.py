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

    b.trace_print()
#