import os
import subprocess
import pyroute2
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
'''
    알아야될 개념 )
        NetWork NameSpace, Ethernet interface, IPRoute.link, IPDB, up()
        IPRoute vs IPDB : 
            동기 vs 비동기, 추가적인 스레드 사용여부
        
        NetWork NameSpace : 
            프로세스를 실행할 때, 시스템의 리소스를 분리해서 실행할 수 있도록 도와주는 기능.
        Ehternet interface : 
            MAC address or Ethernet Port
            컴퓨터에서 다른 ip주소까지 가는 것을 말한다.
        Container : 
            운영체제 수준의 가상화 기술로 리눅스 커널을 '공유'(이 부분에서 VM과 다름) 하면서 프로세스를 격리된 환경에서 실행.
        veth : 호스트와 (네트워크 네임스페이스만 격리된)컨테이너를 연결하는 가상 인터페이스를 의미.
               항상 pair로써 만들어진다.
        Bridge Network :
            물리장비나 소프트웨어를 통해 구성한 가상 스위치
        ip forward : 
            NAT를 이용해 특정 ip를 다른 ip로 바꾸어서 경로를 바꾸어서 보내주는 것.
'''
class Simulation(object):
    """
    Helper class for controlling multiple namespaces. Inherit from
    this class and setup your namespaces.
    """
    #call when class institanate
    def __init__(self, ipdb):
        #ipdb는 비동기적으로 운영되는 database를 의미한다.
        self.ipdb = ipdb
        self.ipdbs = {}
        self.namespaces = []
        self.processes = []
        self.released = False

    # helper function to add additional ifc to namespace
    # if called directly outside Simulation class, "ifc_base_name" should be
    # different from "name", the "ifc_base_name" and "name" are the same for
    # the first ifc created by namespace
    # 리눅스 네임스페이스란 프로세스의 네트워크 환경을 분리할 수 있는 네임스페이스
    # 네트워크 테스트나 컨테이너 구현에서 활용됩니다. 
    # 리눅스 컨테이너는 리눅스 네임스페이스와 루트 파일 시스템 격리 등 리눅스의 다양한 기능을 사용해 격리시킨 프로세스를 의미합니다.
    '''
        1) NameSpace가 있는지 확인하고, NameSpace를 만든다.
        2) interface에 virtual ethernet을 만들어 연결시킨다 (in_fic, out_ifc).
        3) 'add', 'add-filter'등을 통해 link하고, hook function을 연결시킨다.
    '''
    def _ns_add_ifc(self, name, ns_ifc, ifc_base_name=None, in_ifc=None,
                    out_ifc=None, ipaddr=None, macaddr=None, fn=None, cmd=None,
                    action="ok", disable_ipv6=False):
        if name in self.ipdbs:
            ns_ipdb = self.ipdbs[name]
        else:
            try:
                #NetNS : Network NameSpace를 의미한다.
                #컨테이너를 만들기 위해 NetWork NameSpace를 만든다.
                nl=NetNS(name)
                self.namespaces.append(nl)
            except KeyboardInterrupt:
                # remove the namespace if it has been created
                pyroute2.netns.remove(name)
                raise
            #NameSpace에 대한 정보를 저장할 DB를 의미한다.
            ns_ipdb = IPDB(nl)
            #NetNs변수의 namespace에 IPDB를 넣어놓는다.
            #ns_ipdb : nampspace에 있는 ipdb를 의미한다.
            self.ipdbs[nl.netns] = ns_ipdb
            if disable_ipv6:
                cmd1 = ["sysctl", "-q", "-w",
                       "net.ipv6.conf.default.disable_ipv6=1"]
                # NSPopen : The NSPopen object implicitly spawns a child python process to be run in the background in a network namespace
                # 해당 NameSpace 안에서 특정 프로세스를 실행시켜서 원하는 일을 하게 한다.
                nsp = NSPopen(ns_ipdb.nl.netns, cmd1)
                # NSPopen will be started in its turn from this child
                nsp.wait(); nsp.release()
            try:
                #ns_ipdb->interfaces->lo->up->commit
                #lo : loopback, up : ready
                ns_ipdb.interfaces.lo.up().commit()
            except pyroute2.ipdb.exceptions.CommitException:
                print("Warning, commit for lo failed, operstate may be unknown")
        if in_ifc:
            in_ifname = in_ifc.ifname
            with in_ifc as v:
                # move half of veth into namespace
                v.net_ns_fd = ns_ipdb.nl.netns
        else:
            # delete the potentially leaf-over veth interfaces
            ipr = IPRoute()
            # link_lookup : 해당 interface 이름에 해당하는 link의 정보를 보여준다.
            for i in ipr.link_lookup(ifname='%sa' % ifc_base_name): ipr.link("del", index=i)
            ipr.close()
            try:
                # 현재 ifc_base_name을 이용하여 virtual interfaces를 만든다.
                # The IPDB.create() call has the same syntax as IPRoute.link(‘add’, …), 
                # except you shouldn’t specify the ‘add’ command. Refer to IPRoute docs for details.
                # ifc_base_name을 이용하여, virtual ethernet을 만든다.
                '''
                    ipdb.create는 interface name, kind, peer name을 이용해 kind에 해당하는 
                    veth, vlan등을 만들고 이를 연결시킨다.
                '''
                out_ifc = self.ipdb.create(ifname="%sa" % ifc_base_name, kind="veth",
                                           peer="%sb" % ifc_base_name).commit()
                # peer는 out_ifc의 pair쌍을 의미한다.
                in_ifc = self.ipdb.interfaces[out_ifc.peer]
                in_ifname = in_ifc.ifname
                with in_ifc as v:
                    v.net_ns_fd = ns_ipdb.nl.netns
            except KeyboardInterrupt:
                # explicitly remove the interface
                # 모든 인터페이스를 삭제한다.
                out_ifname = "%sa" % ifc_base_name
                if out_ifname in self.ipdb.interfaces: self.ipdb.interfaces[out_ifname].remove().commit()
                raise

        if out_ifc: out_ifc.up().commit()
        try:
            # this is a workaround for fc31 and possible other disto's.
            # when interface 'lo' is already up, do another 'up().commit()'
            # has issues in fc31.
            # the workaround may become permanent if we upgrade pyroute2
            # in all machines.
            # 준비된 상태인지 확인한다.
            if 'state' in ns_ipdb.interfaces.lo.keys():
                if ns_ipdb.interfaces.lo['state'] != 'up':
                    ns_ipdb.interfaces.lo.up().commit()
            else:
                ns_ipdb.interfaces.lo.up().commit()
        except pyroute2.ipdb.exceptions.CommitException:
            print("Warning, commit for lo failed, operstate may be unknown")
        ns_ipdb.initdb()
        # ifc : interfaces를 의미한다.
        in_ifc = ns_ipdb.interfaces[in_ifname]
        with in_ifc as v:
            v.ifname = ns_ifc
            # 해당 interface의 ip와 Mac address를 설정한다.
            if ipaddr: v.add_ip("%s" % ipaddr)
            if macaddr: v.address = macaddr
            # 준비 상태로 만든다.
            v.up()
        if disable_ipv6:
            cmd1 = ["sysctl", "-q", "-w",
                   "net.ipv6.conf.%s.disable_ipv6=1" % out_ifc.ifname]
            subprocess.call(cmd1)
        if fn and out_ifc:
            #ipdb -> network link -> tc 붙인다.
            #nl.tc('add', 'queue name', 'interface name')
            self.ipdb.nl.tc("add", "ingress", out_ifc["index"], "ffff:")
            #add-filter이기 때문에, bpf를 이용한 함수를 붙인다.
            self.ipdb.nl.tc("add-filter", "bpf", out_ifc["index"], ":1",
                            fd=fn.fd, name=fn.name, parent="ffff:",
                            action=action, classid=1)
        if cmd:
            self.processes.append(NSPopen(ns_ipdb.nl.netns, cmd))
        return (ns_ipdb, out_ifc, in_ifc)

    # helper function to create a namespace and a veth connecting it
    def _create_ns(self, name, in_ifc=None, out_ifc=None, ipaddr=None,
                   macaddr=None, fn=None, cmd=None, action="ok", disable_ipv6=False):
        (ns_ipdb, out_ifc, in_ifc) = self._ns_add_ifc(name, "eth0", name, in_ifc, out_ifc,
                                                      ipaddr, macaddr, fn, cmd, action,
                                                      disable_ipv6)
        return (ns_ipdb, out_ifc, in_ifc)

    def release(self):
        if self.released: return
        self.released = True
        for p in self.processes:
            if p.released: continue
            try:
                p.kill()
                p.wait()
            except:
                pass
            finally:
                p.release()
        for name, db in self.ipdbs.items(): db.release()
        for ns in self.namespaces: ns.remove()

