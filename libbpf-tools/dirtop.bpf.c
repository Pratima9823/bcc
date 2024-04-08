#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "dirtop.h"

#define MAX_ENTRIES 10240
#define INODES_NUMBER 100

extern const volatile __u32 target_pid;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct file_id);
    __type(value, struct file_stat);
} entries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, INODES_NUMBER);
    __type(key, __u64);
    __type(value, __u8);
} inode_filter_map SEC(".maps");

// Function prototype declaration
void get_file_path(struct file *file, char *buf, size_t buf_size);

static int probe_entry(struct pt_regs *ctx, struct file *file, size_t count, enum op op) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (target_pid && pid != target_pid) {
        return 0;
    }
    struct file_id key = {.pid = pid, .tid = pid_tgid & 0xFFFFFFFF};
    struct file_stat *valuep;
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct inode *finode = BPF_CORE_READ(dentry, d_inode);
    __u64 ino = BPF_CORE_READ(finode, i_ino);

    key.inode = ino;
    valuep = bpf_map_lookup_elem(&entries, &key);
    if (!valuep) {
        struct file_stat zero_value = {};
        get_file_path(file, zero_value.filename, PATH_MAX); // Corrected call
        bpf_map_update_elem(&entries, &key, &zero_value, BPF_ANY);
        valuep = bpf_map_lookup_elem(&entries, &key);
    }
    if (!valuep) {
        return 0; // Failed to find or create the entry
    }

    if (op == READ) {
        valuep->reads++;
        valuep->read_bytes += count;
    } else if (op == WRITE) {
        valuep->writes++;
        valuep->write_bytes += count;
    }

    get_file_path(file, valuep->filename, PATH_MAX); // Corrected call

    bpf_map_update_elem(&entries, &key, valuep, BPF_ANY);
    return 0;
}

void get_file_path(struct file *file, char *buf, size_t buf_size) {
    if (buf_size == 0) {
        return;
    }
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct dentry *parent_dentry;
    buf[0] = '\0';
    char tmp_buf[256];
    int buflen = buf_size;
    #pragma unroll
    for (int i = 0; i < 20; i++) {
        if (dentry == NULL) {
            break;
        }
        struct qstr d_name = BPF_CORE_READ(dentry, d_name);
        bpf_probe_read_kernel_str(tmp_buf, sizeof(tmp_buf), d_name.name);
        int len = bpf_core_str_len(tmp_buf, sizeof(tmp_buf));
        if (len > buflen - 1) break;
        if (buf[0] != '\0') {
            bpf_core_str_prepend(buf, buflen, "/", 1);
        }
        bpf_core_str_prepend(buf, buflen, tmp_buf, len);
        parent_dentry = BPF_CORE_READ(dentry, d_parent);
        if (parent_dentry == dentry) {
            break;
        }
        dentry = parent_dentry;
        buflen -= len + 1;
    }
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(vfs_read_entry, struct file *file, char *buf, size_t count, loff_t *pos) {
    return probe_entry(ctx, file, count, READ);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write_entry, struct file *file, const char *buf, size_t count, loff_t *pos) {
    return probe_entry(ctx, file, count, WRITE);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

