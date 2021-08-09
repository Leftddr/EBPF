#!/usr/bin/python
#
# This is a Hello World example that uses BPF_PERF_OUTPUT.

from bcc import BPF
from bcc.utils import printb

# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
//This is part of the recommended mechanism for transferring per-event data from kernel to user space.
BPF_PERF_OUTPUT(events);
//기본적으로 다른 함수들은 BPF에서 제공해 주는 함수들이다.
//예를 들면 DATA를 얻거나 이런 함수들
//예시로는, BPF_GET_CURRENT_PID_TGID() 등이 있다 => BPF전용 함수이다.
int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    //for submitting custom event data to user space
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# process event
start = 0
# 함수의 형태는 대거 이렇다.
def print_event(cpu, data, size):
    global start
    #tc_perf_data.py나 여기서 data변수를 통해 데이터에 접근한다.
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    printb(b"%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid,
        b"Hello, perf_output!"))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
