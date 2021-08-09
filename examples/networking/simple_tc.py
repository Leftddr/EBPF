#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
'''
  IPRoute.tc : 
    트래픽 컨트롤을 위한 "Swiss knife"를 의미한다.
  IPRoute.tc('command', 'kind', 'handle') 형태를 가진다.
  'handle' :
    1:0    ->    0x10000
    1:1    ->    0x10001
    ff:0   ->   0xff0000
    ffff:1 -> 0xffff0001
  앞에것은 그대로 가져다 쓰고, 뒤에것은 bit로 변환하여 사용한다.
'''
from bcc import BPF
from pyroute2 import IPRoute

ipr = IPRoute()

text = """
int hello(struct __sk_buff *skb) {
  return 1;
}
"""

try:
    b = BPF(text=text, debug=0)
    fn = b.load_func("hello", BPF.SCHED_CLS)
    ipr.link("add", ifname="t1a", kind="veth", peer="t1b")
    idx = ipr.link_lookup(ifname="t1a")[0]

    ipr.tc("add", "ingress", idx, "ffff:")
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd,
           name=fn.name, parent="ffff:", action="ok", classid=1)
    ipr.tc("add", "sfq", idx, "1:")
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd,
           name=fn.name, parent="1:", action="ok", classid=1)
finally:
    if "idx" in locals(): ipr.link("del", index=idx)
print("BPF tc functionality - SCHED_CLS: OK")
