#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "dirtop.h"
#include "dirtop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define OUTPUT_ROWS_LIMIT 10240
#define MAX_DIRS 100
static char *inode_path = NULL;

enum SORT {
    ALL,
    READS,
    WRITES,
    RBYTES,
    WBYTES,
};

static volatile sig_atomic_t exiting = 0;
static char *directory_paths = NULL; // Variable to store directory paths from the command line
static pid_t target_pid = 0;
static bool clear_screen = true;
static bool regular_file_only = true;
static int output_rows = 20;
static int sort_by = ALL;
static int interval = 1;
static int count = 99999999;
static bool verbose = false;

const char *argp_program_version = "dirtop 0.1";
const char *argp_program_bug_address = "https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
    "Trace file reads/writes by directories.\n"
    "\n"
    "USAGE: dirtop [-h] [interval] [count] [-p PID]\n"
    "\n"
    "EXAMPLES:\n"
    "    dirtop   '/hdfs/uuid/*/yarn'          # file I/O top, refresh every 1s\n"
    "    dirtop   '/hdfs/uuid/*/yarn' 5 10     # 5s summaries, 10 times\n";

static const struct argp_option opts[] = {
    {"directories", 'd', "DIRS", 0, "Directories to monitor (comma-separated list)"},
    {"noclear", 'C', NULL, 0, "Don't clear the screen"},
    {"all", 'a', NULL, 0, "Include special files"},
    {"sort", 's', "SORT", 0, "Sort columns, default all [all, reads, writes, rbytes, wbytes]"},
    {"file", 'f', "FILE", 0, "File or directory to get the inode ID"},
    {"rows", 'r', "ROWS", 0, "Maximum rows to print, default 20"},
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    long pid, rows;
    static int pos_args;

    switch (key) {
    case 'p':
            errno = 0;
            pid = strtol(arg, NULL, 10);
            if (errno || pid <= 0) {
                warn("invalid PID: %s\n", arg);
                argp_usage(state);
            }
            target_pid = pid;
            break;
    case 'C':
            clear_screen = false;
            break;
    case 'a':
                regular_file_only = false;
                break;

    case 's':
            if (!strcmp(arg, "all")) {
                sort_by = ALL;
            } else if (!strcmp(arg, "reads")) {
                sort_by = READS;
            } else if (!strcmp(arg, "writes")) {
                sort_by = WRITES;
            } else if (!strcmp(arg, "rbytes")) {
                sort_by = RBYTES;
            } else if (!strcmp(arg, "wbytes")) {
                sort_by = WBYTES;
            } else {
                warn("invalid sort method: %s\n", arg);
                argp_usage(state);
            }
            break;
    case 'f':
            inode_path = strdup(arg); // Allocate and copy the path
            if (!inode_path) {
                warn("Failed to allocate memory for the inode path\n");
                argp_usage(state);
            }
            break;
    case 'r':
            errno = 0;
            rows = strtol(arg, NULL, 10);
            if (errno || rows <= 0) {
                warn("invalid rows: %s\n", arg);
                argp_usage(state);
            }
            output_rows = rows;
            if (output_rows > OUTPUT_ROWS_LIMIT)
                output_rows = OUTPUT_ROWS_LIMIT;
            break;
    case 'v':
            verbose = true;
            break;
    case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
    case 'd':
            if (directory_paths) {
                free(directory_paths);
            }
            directory_paths = strdup(arg);
            if (!directory_paths) {
                warn("Failed to duplicate directory paths\n");
                argp_usage(state);
            }
            break;

    case ARGP_KEY_ARG:
            errno = 0;
            if (pos_args == 0) {
                interval = strtol(arg, NULL, 10);
                if (errno || interval <= 0) {
                    warn("invalid interval\n");
                    argp_usage(state);
                }
            } else if (pos_args == 1) {
                count = strtol(arg, NULL, 10);
                if (errno || count <= 0) {
                    warn("invalid count\n");
                    argp_usage(state);
                }
            } else {
                warn("unrecognized positional argument: %s\n", arg);
                argp_usage(state);
            }
            pos_args++;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;

}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
        if (level == LIBBPF_DEBUG && !verbose)
                return 0;
        return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
        exiting = 1;
}

static int sort_column(const void *obj1, const void *obj2)
{
        struct file_stat *s1 = (struct file_stat *)obj1;
        struct file_stat *s2 = (struct file_stat *)obj2;

        if (sort_by == READS) {
                return s2->reads - s1->reads;
        } else if (sort_by == WRITES) {
                return s2->writes - s1->writes;
        } else if (sort_by == RBYTES) {
                return s2->read_bytes - s1->read_bytes;
        } else if (sort_by == WBYTES) {
                return s2->write_bytes - s1->write_bytes;
        } else {
                return (s2->reads + s2->writes + s2->read_bytes + s2->write_bytes)
                     - (s1->reads + s1->writes + s1->read_bytes + s1->write_bytes);
        }
}

static int print_stat(struct dirtop_bpf *obj) {
    FILE *f;
    time_t t;
    struct tm *tm;
    char ts[16], buf[256];
    struct file_id key, *prev_key = NULL;
    static struct file_stat values[OUTPUT_ROWS_LIMIT];
    int n, i, err = 0, rows = 0;
    int fd = bpf_map__fd(obj->maps.entries);

    f = fopen("/proc/loadavg", "r");
    if (f) {
        time(&t);
        tm = localtime(&t);
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);
        memset(buf, 0, sizeof(buf));
        n = fread(buf, 1, sizeof(buf), f);
        if (n)
            printf("%8s loadavg: %s\n", ts, buf);
        fclose(f);
    }

    // Corrected header to match expected output
    printf("%-7s %-16s %-6s %-6s %s\n", "READS", "WRITES", "R_Kb", "W_Kb", "PATH");

    while (1) {
        err = bpf_map_get_next_key(fd, prev_key, &key);
        if (err) {
            if (errno == ENOENT) {
                err = 0;
                break;
            }
            warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
            return err;
        }
        err = bpf_map_lookup_elem(fd, &key, &values[rows++]);
        if (err) {
            warn("bpf_map_lookup_elem failed: %s\n", strerror(errno));
            return err;
        }
        prev_key = &key;
    }

    qsort(values, rows, sizeof(struct file_stat), sort_column);
    rows = rows < output_rows ? rows : output_rows;
    for (i = 0; i < rows; i++) {
        // Corrected print statement to use the proper format specifiers
        printf("%-7llu %-16llu %-6llu %-6llu %s\n",
               values[i].reads, values[i].writes,
               values[i].read_bytes / 1024, values[i].write_bytes / 1024,
               values[i].filename);
    }

    printf("\n");
    prev_key = NULL;

    while (1) {
        err = bpf_map_get_next_key(fd, prev_key, &key);
        if (err) {
            if (errno == ENOENT) {
                err = 0;
                break;
            }
            warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
            return err;
        }
        err = bpf_map_delete_elem(fd, &key);
        if (err) {
            warn("bpf_map_delete_elem failed: %s\n", strerror(errno));
            return err;
        }
        prev_key = &key;
    }
    return err;
}

void populate_inode_map(struct dirtop_bpf *obj, const char *root_directories) {
    char *dirs = strdup(root_directories); // Make a writable copy
    if (!dirs) {
        perror("strdup failed");
        return;
    }

    char *dir = strtok(dirs, ",");
    struct stat statbuf;
    while (dir) {
        if (stat(dir, &statbuf) == 0) {
            __u32 key = statbuf.st_ino; // Inode number as the key
            __u64 value = 1; // Dummy value
            if (bpf_map_update_elem(bpf_map__fd(obj->maps.inode_filter_map), &key, &value, BPF_ANY) != 0) {
                warn("Failed to insert inode number into the map\n");
            }
        } else {
            warn("Could not get stats for directory: %s\n", dir);
        }
        dir = strtok(NULL, ",");
    }

    free(dirs);
}

int main(int argc, char **argv) {
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };

    struct dirtop_bpf *obj;
    int err;

    // Parse command-line arguments
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;
     if (inode_path) {
        struct stat statbuf;
        if (stat(inode_path, &statbuf) == 0) {
            printf("Considering %s with inode_id %lu\n", inode_path, (unsigned long)statbuf.st_ino);
            // Add your additional print statement here
            printf("Tracing... Output every %d secs. Hit Ctrl-C to end\n", interval);
        } else {
            warn("Could not get stats for the file or directory: %s\n", inode_path);
            return 1; // or handle the error as appropriate
        }
    }


    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    // Open and load BPF object
    obj = dirtop_bpf__open_and_load();
    if (!obj) {
        warn("failed to open and load BPF object\n");
        return 1;
    }

    // Optional: Update BPF program configuration based on command-line arguments
    if (target_pid)
        obj->rodata->target_pid = target_pid;

    // Attach BPF program
    err = dirtop_bpf__attach(obj);
    if (err) {
        warn("failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    // Handle program exit signal
    if (signal(SIGINT, sig_int) == SIG_ERR) {
        warn("can't set signal handler: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    // Populate inode map with directory inodes if paths are provided
    if (directory_paths) {
        populate_inode_map(obj, directory_paths);
    }

    // Main loop: print stats and handle user inputs
    while (!exiting) {
        sleep(interval);

        if (clear_screen) {
            err = system("clear");
            if (err) goto cleanup;
        }

        err = print_stat(obj);
        if (err) goto cleanup;

        count--;
                if (exiting || !count)
                        goto cleanup; // Exit after count iterations
    }

cleanup:
    if (directory_paths) {
        free(directory_paths); // Clean up allocated directory paths
    }
    dirtop_bpf__destroy(obj);
    cleanup_core_btf(&open_opts); // Free BPF resources
    return err != 0;
}







