#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from builtins import input
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
from random import shuffle
from time import sleep
from simulation import Simulation
import sys

ipr = IPRoute()
ipdb = IPDB(nl=ipr)

num_clients = 3
num_vlans = 16

# load the bpf program
# 가상 네트워크 통신을 만들고, 함수를 등록하여 tracing하는 코드이다.
# interfaces -> ethernet, lo -> up, lo => localhost를 의미한다.
b = BPF(src_file="vlan_learning.c", debug=0)
phys_fn = b.load_func("handle_phys2virt", BPF.SCHED_CLS)
virt_fn = b.load_func("handle_virt2phys", BPF.SCHED_CLS)

ingress = b.get_table("ingress")
egress = b.get_table("egress")
#virtual lan을 시뮬레이션하는 코드이다.
class VlanSimulation(Simulation):
    def __init__(self, ipdb):
        super(VlanSimulation, self).__init__(ipdb)

    def start(self):
        # start identical workers each in a namespace
        for i in range(0, num_clients):
            httpmod = ("SimpleHTTPServer" if sys.version_info[0] < 3
                       else "http.server")
            cmd = ["python", "-m", httpmod, "80"]
            # worker%d는 Linux NameSpace를 의미한다.
            self._create_ns("worker%d" % i, cmd=cmd, fn=virt_fn, action="drop",
                            ipaddr="172.16.1.5/24")

        # simulate a physical eth vlan trunk
        # 호스트와 컨테이너를 연결할 가상의 ethernet을 만든다.
        with self.ipdb.create(ifname="eth0a", kind="veth", peer="eth0b") as v:
            v.up()
        self.ipdb.interfaces.eth0b.up().commit()

        # eth0a will be hooked to clients with vlan interfaces
        # add the bpf program to eth0b for demuxing phys2virt packets
        # eth0a -> eth0b
        v = self.ipdb.interfaces["eth0b"]
        ipr.tc("add", "ingress", v["index"], "ffff:")
        ipr.tc("add-filter", "bpf", v["index"], ":1", fd=phys_fn.fd,
               name=phys_fn.name, parent="ffff:", action="drop", classid=1)

        # allocate vlans randomly
        available_vlans = [i for i in range(2, 2 + num_vlans)]
        shuffle(available_vlans)
        available_ips = [[i for i in range(100, 105)] for i in range(0, num_clients)]

        # these are simulations of physical clients
        for i in range(0, num_clients):
            #파이썬도 비트 사용이 가능하구나...
            macaddr = ("02:00:00:%.2x:%.2x:%.2x" %
                       ((i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff))

            # assign this client to the given worker
            # 해당 NameSpace의 interface의 index값을 가져온다.
            idx = self.ipdb.interfaces["worker%da" % i]["index"]
            #u64형태로 key를 변환해야 데이터 베이스를 사용할 수 있다.
            mac = int(macaddr.replace(":", ""), 16)
            ingress[ingress.Key(mac)] = ingress.Leaf(idx, 0, 0, 0, 0)

            # test traffic with curl loop
            cmd = ["bash", "-c",
                   "for i in {1..8}; do curl 172.16.1.5 -o /dev/null; sleep 1; done"]
            client_ifc = self.ipdb.create(ifname="eth0a.%d" % i, kind="vlan",
                                          link=self.ipdb.interfaces["eth0a"],
                                          vlan_id=available_vlans.pop(0)).commit()
            (out_ifc, in_ifc) = self._create_ns("client%d" % i, in_ifc=client_ifc,
                                                ipaddr="172.16.1.100/24",
                                                macaddr=macaddr, cmd=cmd)[1:3]

try:
    sim = VlanSimulation(ipdb)
    sim.start()
    sleep(10)
    input("Press enter to exit: ")

    stats_collect = {}
    for key, leaf in ingress.items():
        stats_collect[key.value] = [leaf.tx_pkts, leaf.tx_bytes, 0, 0]
    for key, leaf in egress.items():
        x = stats_collect.get(key.value, [0, 0, 0, 0])
        x[2] = leaf.tx_pkts
        x[3] = leaf.tx_bytes
    for k, v in stats_collect.items():
        print("mac %.12x rx pkts = %u, rx bytes = %u" % (k, v[0], v[1]))
        print("                 tx pkts = %u, tx bytes = %u" % (v[2], v[3]))
finally:
    if "eth0a" in ipdb.interfaces: ipdb.interfaces.eth0a.remove().commit()
    if "sim" in locals(): sim.release()
    ipdb.release()
