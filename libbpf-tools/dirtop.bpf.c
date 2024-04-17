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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1024);
} pid_map SEC(".maps");

static int probe_entry(struct pt_regs *ctx, struct file *file, size_t count, enum op op) 
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	struct file_id key = {};
	struct file_stat *valuep;
	struct dentry *dentry;
	struct inode *dinode;
	struct inode *finode;
	
	__u64 ino;
	__u8 *found;
	bpf_probe_read_kernel(&dentry, sizeof(dentry), &file->f_path.dentry);
	if (!dentry)
		return 0;
	bpf_probe_read_kernel(&dentry, sizeof(dentry), &dentry->d_parent);
	bpf_probe_read_kernel(&dinode, sizeof(dinode), &dentry->d_inode);
	bpf_probe_read_kernel(&ino, sizeof(unsigned long), &(dinode->i_ino));
	found = bpf_map_lookup_elem(&inode_filter_map, &ino);
	if (found) {
		bpf_probe_read_kernel(&finode, sizeof(finode), &file->f_inode);
		bpf_probe_read_kernel(&key.inode, sizeof(key.inode), &(finode->i_ino));
		if (key.inode == 0)
			return 0;
		valuep = bpf_map_lookup_elem(&entries, &key);
		if (!valuep) {
			bpf_map_update_elem(&entries, &key, &zero_value, BPF_ANY);
			valuep = bpf_map_lookup_elem(&entries, &key);
			if (!valuep)
				return 0;
		}
	       	if (op == READ) {
			valuep->reads++;
			valuep->read_bytes += count;
		} else {
			valuep->writes++;
			valuep->write_bytes += count;
		}
		bpf_map_update_elem(&entries, &key, valuep, BPF_ANY);
	}
	return 0;
}

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


