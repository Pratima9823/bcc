/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __DIRTOP_H
#define __DIRTOP_H

#define PATH_MAX        4096
#define TASK_COMM_LEN   16
#define DIRECTORY_INODE {0}



enum op {
        READ,
        WRITE,
};

struct file_id {
        __u64 inode;
};

struct file_stat {
        __u64 reads;
        __u64 read_bytes;
        __u64 writes;
        __u64 write_bytes;
        __u32 pid;

        char filename[PATH_MAX];
        char comm[TASK_COMM_LEN];
        char type;
};

#endif /* __DIRTOP_H */

