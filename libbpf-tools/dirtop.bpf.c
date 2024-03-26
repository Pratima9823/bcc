#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "stat.h"
#include "dirtop.h"

#define MAX_ENTRIES 10240
#define INODES_NUMBER 100
const volatile bool regular_file_only = true;
static struct file_stat zero_value = {};
volatile const __u32 target_pid = 0;

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


static void get_file_path(struct file *file, char *buf, size_t buf_size) {
    struct dentry *dentry;
    struct qstr dname;
    char parent_buf[256] = {}; // Temporary buffer for parent dentry name

    // Safely read the file's dentry
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);

    // Attempt to read the name of the file from its dentry
    bpf_probe_read_kernel(&dname, sizeof(dname), &dentry->d_name);
    bpf_probe_read_kernel(buf, buf_size, dname.name);

    // Attempt to read the parent dentry, and then its name
    struct dentry *parent_dentry = NULL;
    bpf_probe_read_kernel(&parent_dentry, sizeof(parent_dentry), &dentry->d_parent);
    if (parent_dentry) {
        bpf_probe_read_kernel(&dname, sizeof(dname), &parent_dentry->d_name);
        bpf_probe_read_kernel(parent_buf, sizeof(parent_buf), dname.name);

        // Prepend the parent directory name to the file name
        // Ensure we do not exceed the buffer size
        int len = bpf_snprintf(buf, buf_size, "%s/%s", parent_buf, buf);
        if (len >= buf_size) {
            // Handle buffer overflow if occurred
            buf[buf_size - 1] = '\0'; // Ensure null-termination
        }
    }
}

static int probe_entry(struct pt_regs *ctx, struct file *file, size_t count, enum op op) {
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    struct file_id key = {};
    struct file_stat *valuep;
    struct dentry *dentry;
    __u64 ino;
    __u8 *found;
     if (target_pid && pid != target_pid) {
        return 0;

    
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);
    if (!dentry) return 0;

    
    bpf_probe_read_kernel(&ino, sizeof(ino), &dentry->d_inode->i_ino);

    
    found = bpf_map_lookup_elem(&inode_filter_map, &ino);
    if (found) {
        
        bpf_probe_read_kernel(&key.inode, sizeof(key.inode), &file->f_inode->i_ino);
        if (key.inode == 0) return 0;

        valuep = bpf_map_lookup_elem(&entries, &key);
        if (!valuep) {
            bpf_map_update_elem(&entries, &key, &zero_value, BPF_ANY);
            valuep = bpf_map_lookup_elem(&entries, &key);
            if (!valuep) return 0;
            
            
            bpf_get_current_comm(&valuep->comm, sizeof(valuep->comm));
            get_file_path(file, valuep->filename, sizeof(valuep->filename));
        }
        
        
        if (op == READ) {
            valuep->reads++;
            valuep->read_bytes += count;
        } else  {
            valuep->writes++;
            valuep->write_bytes += count;
        }
        return 0; 
    }
     }
    
    return 0;
};

SEC("kprobe/vfs_read")
int BPF_KPROBE(vfs_read_entry, struct file *file, char *buf, size_t count, loff_t *pos)
{
	return probe_entry(ctx, file, count, READ);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write_entry, struct file *file, const char *buf, size_t count, loff_t *pos)
{
	return probe_entry(ctx, file, count, WRITE);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";


