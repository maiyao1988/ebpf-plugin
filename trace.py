#!/usr/bin/python
# -*- coding: utf-8 -*-

from datetime import datetime
import argparse
import json
from bcc import BPF
from ctypes import *
class SysDesc(Structure):
    _fields_ = [("nArgs", c_int32),
            ("stringMask", c_int32),
            ("syscallName", c_char * 50)]

if __name__ == "__main__":
    b = BPF(src_file="trace.c")
    print("after compile")
    syscall = {}
    tbl = b["sysdesc"]
    print(tbl)
    print(dir(tbl))
    syscallNameTp = c_char * 50
    print(syscallNameTp)
    sysval = SysDesc(c_int32(2), c_int32(1<<1), b"faccessat")
    tbl[c_int(48)] = sysval
    b.trace_print()
#