#!/usr/bin/python
#
# tc_perf_event.py  Output skb and meta data through perf event
#
# Copyright (c) 2016-present, Facebook, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import ctypes as ct
import pyroute2
import socket

bpf_txt = """
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/bpf.h>
// 여기서 perf를 할 수 있는 이름을 output으로 지정해 놓는다.
// 이것도 buffer를 의미, 즉 원하는 정보를 넣고 빼고 하는 곳이다.
// user_space에서 원하는 정보를 넣고 뺀다.
BPF_PERF_OUTPUT(skb_events);

struct eth_hdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	unsigned short  h_proto;
};
//egress면 packet을 내보내는 거다.
int handle_egress(struct __sk_buff *skb)
{
    //data -> ehternet_header이 들어있다.
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct eth_hdr *eth = data;
    //ehternet_header 크기만큼 건너뛰면 content가 들어있다.
	struct ipv6hdr *ip6h = data + sizeof(*eth);
	u32 magic = 0xfaceb00c;

	/* single length check */
	if (data + sizeof(*eth) + sizeof(*ip6h) > data_end)
		return TC_ACT_OK;
    //ethernet protocol을 의미한다.
	if (eth->h_proto == htons(ETH_P_IPV6) &&
    //ip의 protocol을 의미한다.
	    ip6h->nexthdr == IPPROTO_ICMPV6)
            //원하는 자료를 넣어놓는다. magic number를 통해 데이터를 구분한다.
	        skb_events.perf_submit_skb(skb, skb->len, &magic, sizeof(magic));

	return TC_ACT_OK;
}"""
# event-driven이기 때문에, event 함수를 등록하면 이런 함수 형태를 지닌다.
def print_skb_event(cpu, data, size):
    #ct.Structure : c언어에서 사용되는 표준 크기를 의미한다.
    class SkbEvent(ct.Structure):
        _fields_ =  [ ("magic", ct.c_uint32),
                      ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32))) ]
    #data를 SkbEvent로 casting하고, 그 내용을 return한다.
    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
    icmp_type = int(skb_event.raw[54])

    # Only print for echo request
    if icmp_type == 128:
        src_ip = bytes(bytearray(skb_event.raw[22:38]))
        dst_ip = bytes(bytearray(skb_event.raw[38:54]))
        print("%-3s %-32s %-12s 0x%08x" %
                #socket.inet_ntop는 해당 ip에 대한 정보를 출력해준다.
              (cpu, socket.inet_ntop(socket.AF_INET6, src_ip),
               socket.inet_ntop(socket.AF_INET6, dst_ip),
               skb_event.magic))

try:
    b = BPF(text=bpf_txt)
    fn = b.load_func("handle_egress", BPF.SCHED_CLS)

    ipr = pyroute2.IPRoute()
    #ipr.link는 command에 따라 행동하는 방식이 달라지지만 여기서는 me와 you를 연결하는
    #virtual ethernet을 만든다.
    ipr.link("add", ifname="me", kind="veth", peer="you")
    #연결된 interface를 찾아본다.
    me = ipr.link_lookup(ifname="me")[0]
    you = ipr.link_lookup(ifname="you")[0]
    for idx in (me, you):
        ipr.link('set', index=idx, state='up')
    # set up 'clsact' queue on interface 'me'
    ipr.tc("add", "clsact", me)
    # set up 'bpf' on interface me
    ipr.tc("add-filter", "bpf", me, ":1", fd=fn.fd, name=fn.name,
           parent="ffff:fff3", classid=1, direct_action=True)
    #이벤트를 등록해 놓는다.
    #위에서 BPF_PERF_OUTPUT으로 등록된 "skb_events"를 사용한다.
    b["skb_events"].open_perf_buffer(print_skb_event)
    print('Try: "ping6 ff02::1%me"\n')
    print("%-3s %-32s %-12s %-10s" % ("CPU", "SRC IP", "DST IP", "Magic"))
    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        pass
finally:
    if "me" in locals(): ipr.link("del", index=me)
