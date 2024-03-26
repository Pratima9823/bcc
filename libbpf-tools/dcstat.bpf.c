#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "dcstat.h"

__u64 stats[S_MAXSTAT] = {};

SEC("kprobe/lookup_fast")
int BPF_KPROBE(lookup_fast) {
    u64 key = S_REFS;
    stats[key]++;
    return 0; // Add return statement
}

SEC("kretprobe/d_lookup")
int BPF_KRETPROBE(d_lookup) { // Remove the ctx parameter declaration
    u64 key = S_SLOW;
    stats[key]++;
    if (PT_REGS_RC(ctx) == 0) {
        key = S_MISS;
        stats[key]++;
    }
    return 0; // Add return statement
}

char LICENSE[] SEC("license") = "GPL";

