#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# Copyright (c) 2021 Chenyue Zhou

from __future__ import print_function
import os
import sys
import time
import atexit
import argparse

from bcc import BPF, BPFAttachType, lib


examples = """examples:
    ./sockmap.py -c /root/cgroup # attach to /root/cgroup
"""
parser = argparse.ArgumentParser(
        description="pipe data across multiple sockets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
parser.add_argument("-c", "--cgroup", required=True,
        help="Specify the cgroup address. Note. must be cgroup2")

bpf_text = '''
/*
    전체적인 이해는 이렇다.
    1) 데이터를 저장할 저장소를 만든다.
    2) 함수를 load하고 attach하여 user function을 심는다.
    3) 저장된 map을 통해 원하는 자료를 꺼내온다.
*/
#include <net/sock.h>

#define MAX_SOCK_OPS_MAP_ENTRIES 65535

struct sock_key {
    u32 remote_ip4;
    u32 local_ip4;
    u32 remote_port;
    u32 local_port;
    u32 family;
};
//BPF_SOCKHASH : sock_hash라는 name을 가지는 hash map을 만든다.
//key는 여러 자료구조를 형태로 가질 수 있다.
BPF_SOCKHASH(sock_hash, struct sock_key, MAX_SOCK_OPS_MAP_ENTRIES);

static __always_inline void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops) {
    struct sock_key skk = {
        .remote_ip4 = skops->remote_ip4,
        .local_ip4  = skops->local_ip4,
        .local_port = skops->local_port,
        .remote_port  = bpf_ntohl(skops->remote_port),
        .family = skops->family,
    };
    int ret;
    //TRACE 할 때, 커널내에서 쓰이는 printk이다.
    bpf_trace_printk("remote-port: %d, local-port: %d\\n", skk.remote_port,
                     skk.local_port);
    //BPF_NOEXIST 상태이면 HASH MAP을 UPDATE한다.
    ret = sock_hash.sock_hash_update(skops, &skk, BPF_NOEXIST);
    if (ret) {
        bpf_trace_printk("bpf_sock_hash_update() failed. %d\\n", -ret);
        return;
    }

    bpf_trace_printk("Sockhash op: %d, port %d --> %d\\n", skops->op,
                     skk.local_port, skk.remote_port);
}

int bpf_sockhash(struct bpf_sock_ops *skops) {
    u32 op = skops->op;

    /* ipv4 only */
    if (skops->family != AF_INET)
	return 0;

    switch (op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            bpf_sock_ops_ipv4(skops);
            break;
        default:
            break;
    }

    return 0;
}

int bpf_redir(struct sk_msg_md *msg) {
    if (msg->family != AF_INET)
        return SK_PASS;

    if (msg->remote_ip4 != msg->local_ip4)
        return SK_PASS;

    struct sock_key skk = {
        .remote_ip4 = msg->local_ip4,
        .local_ip4  = msg->remote_ip4,
        .local_port = bpf_ntohl(msg->remote_port),
        .remote_port = msg->local_port,
        .family = msg->family,
    };
    int ret = 0;
    /*
        bpf_msg_redirect_hash(). 
        The helper functions cannot be accessed directly and must be accessed through predefined helpers 
        of the form BPF_FUNC_msg_redirect_hash since the kernel verifier for BPF programs only allows calls 
        to these predefined helpers from UAPI linux/bpf.h defined in ‘enum bpf_func_id’ (see the code for the macro definition)
    */
    ret = sock_hash.msg_redirect_hash(msg, &skk, BPF_F_INGRESS);
    bpf_trace_printk("try redirect port %d --> %d\\n", msg->local_port,
                     bpf_ntohl(msg->remote_port));
    if (ret != SK_PASS)
        bpf_trace_printk("redirect port %d --> %d failed\\n", msg->local_port,
                         bpf_ntohl(msg->remote_port));

    return ret;
}
'''
args = parser.parse_args()
bpf = BPF(text=bpf_text)
#함수를 여러개 등록할 수도 있다.
func_sock_ops = bpf.load_func("bpf_sockhash", bpf.SOCK_OPS)
func_sock_redir = bpf.load_func("bpf_redir", bpf.SK_MSG)
# raise if error
fd = os.open(args.cgroup, os.O_RDONLY)
map_fd = lib.bpf_table_fd(bpf.module, b"sock_hash")
# 내가 정의해놓은 function을 붙여 넣는다.
# fd : read_only로 붙여 놓는다.
# map_fd : "sock_hash"로 명명된 hash_map을 가리키는 fd를 만든다.
# 
bpf.attach_func(func_sock_ops, fd, BPFAttachType.CGROUP_SOCK_OPS)
bpf.attach_func(func_sock_redir, map_fd, BPFAttachType.SK_MSG_VERDICT)
# 프로세스가 죽기 전에, 등록된 함수를 떼어놓고 죽는다.
def detach_all():
    bpf.detach_func(func_sock_ops, fd, BPFAttachType.CGROUP_SOCK_OPS)
    bpf.detach_func(func_sock_redir, map_fd, BPFAttachType.SK_MSG_VERDICT)
    print("Detaching...")

atexit.register(detach_all)

while True:
    try:
        bpf.trace_print()
        sleep(1)
    except KeyboardInterrupt:
        sys.exit(0)
