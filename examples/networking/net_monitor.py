#!/usr/bin/python
#
# net_monitor.py Aggregates incoming network traffic
# outputs source ip, destination ip, the number of their network traffic, and current time
# how to use : net_monitor.py <net_interface> 
# 
# Copyright (c) 2020 YoungEun Choe

from bcc import BPF
import time
from ast import literal_eval
import sys

def help():
    print("execute: {0} <net_interface>".format(sys.argv[0]))
    print("e.g.: {0} eno1\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 2:
    help()
elif len(sys.argv) == 2:
    INTERFACE = sys.argv[1]

#여기서 주석처리 하여 c언어로 코드를 짜고, 이를 변수에 넣어놓는다.
bpf_text = """

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>

#define IP_TCP 6
#define IP_UDP 17
#define IP_ICMP 1
#define ETH_HLEN 14

//BPF_PERF_OUTPUT : BPF tables을 생성하고 event data를 user space에 전달한다.
BPF_PERF_OUTPUT(skb_events);
//BPF_HASH : HASHED MAP을 만든다.
BPF_HASH(packet_cnt, u64, long, 256); 

int packet_monitor(struct __sk_buff *skb) {
    u8 *cursor = 0;
    u32 saddr, daddr;
    long* count = 0;
    long one = 1;
    u64 pass_value = 0;
    
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    //ip변수에는 시작주소, 도착주소와 같은 정보가 담겨있다.
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    if (ip->nextp != IP_TCP) 
    {
        if (ip -> nextp != IP_UDP) 
        {
            if (ip -> nextp != IP_ICMP) 
                return 0; 
        }
    }
    
    saddr = ip -> src;
    daddr = ip -> dst;
    //시작주소 32bit, 목적지 주소 32bit
    //둘을 64bit 한 변수에 반반씩 넣어놓는다.
    pass_value = saddr;
    pass_value = pass_value << 32;
    pass_value = pass_value + daddr;
    //그 주소로 들어오고 나가는 packet를 관찰한다.
    //packet_cnt는 HASHED MAP을 의미한다.
    //key가 u64이기 때문에 주소를 key로 건다고 할 수 있다.
    count = packet_cnt.lookup(&pass_value); 
    if (count)  // check if this map exists
        *count += 1;
    else        // if the map for the key doesn't exist, create one
        {
            packet_cnt.update(&pass_value, &one);
        }
    return -1;
}

"""

from ctypes import *
import ctypes as ct
import sys
import socket
import os
import struct

OUTPUT_INTERVAL = 1
#BPF함수를 통해, bpf_text에 넣어진 코드를 만든다.
bpf = BPF(text=bpf_text)
#함수를 load한다. 그리고 이를 변수에 넣어놓는다.
function_skb_matching = bpf.load_func("packet_monitor", BPF.SOCKET_FILTER)
#위에서 load한 function을 raw_socket부분에 attach한다.
BPF.attach_raw_socket(function_skb_matching, INTERFACE)

    # retrieeve packet_cnt map
#packet_cnt map을 가져온다.
packet_cnt = bpf.get_table('packet_cnt')    # retrieeve packet_cnt map

def decimal_to_human(input_value):
    input_value = int(input_value)
    hex_value = hex(input_value)[2:]
    #2개씩 끊어서 16진수로 만든다.
    #1 : 4bit, 8개 : 32bit => 이를 16진수로 보여주기 위함이다.
    pt3 = literal_eval((str('0x'+str(hex_value[-2:]))))
    pt2 = literal_eval((str('0x'+str(hex_value[-4:-2]))))
    pt1 = literal_eval((str('0x'+str(hex_value[-6:-4]))))
    pt0 = literal_eval((str('0x'+str(hex_value[-8:-6]))))
    result = str(pt0)+'.'+str(pt1)+'.'+str(pt2)+'.'+str(pt3)
    return result

try:
    while True :
        time.sleep(OUTPUT_INTERVAL)
        #hash_map이므로 .items를 이용해 내용을 가져온다.
        packet_cnt_output = packet_cnt.items()
        #아이템의 개수를 확인한다.
        output_len = len(packet_cnt_output)
        print('\n')
        for i in range(0,output_len):
            if (len(str(packet_cnt_output[i][0]))) != 30:
                continue
            temp = int(str(packet_cnt_output[i][0])[8:-2]) # initial output omitted from the kernel space program
            temp = int(str(bin(temp))[2:]) # raw file
            #처음 32개
            src = int(str(temp)[:32],2) # part1
            #후 32개 
            dst = int(str(temp)[32:],2)
            #패킷 개수 확인
            pkt_num = str(packet_cnt_output[i][1])[7:-1]

            monitor_result = 'source address : ' + decimal_to_human(str(src)) + ' ' + 'destination address : ' + \
            decimal_to_human(str(dst)) + ' ' + pkt_num + ' ' + 'time : ' + str(time.localtime()[0])+\
            ';'+str(time.localtime()[1]).zfill(2)+';'+str(time.localtime()[2]).zfill(2)+';'+\
            str(time.localtime()[3]).zfill(2)+';'+str(time.localtime()[4]).zfill(2)+';'+\
            str(time.localtime()[5]).zfill(2)
            print(monitor_result)

            # time.time() outputs time elapsed since 00:00 hours, 1st, Jan., 1970.
        #map을 삭제한다.
        packet_cnt.clear() # delete map entires after printing output. confiremd it deletes values and keys too 
        
except KeyboardInterrupt:
    sys.stdout.close()
    pass

