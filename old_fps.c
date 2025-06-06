#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>
#include <execinfo.h>
#define MAX_MATCHES 2

void crash_handler(int sig) {
    void *buffer[32];
    int nptrs = backtrace(buffer, 32);
    fprintf(stderr, "Error: signal %d\n", sig);
    backtrace_symbols_fd(buffer, nptrs, STDERR_FILENO);
    exit(1);
}


// Helper: Find PID by process name
pid_t find_pid_by_name(const char *process_name) {
    DIR *dir = opendir("/proc/");
    if (!dir) {
        perror("opendir /proc");
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;

        pid_t pid = atoi(entry->d_name);
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);

        FILE *f = fopen(path, "r");
        if (f) {
            char name[256];
            if (fgets(name, sizeof(name), f)) {
                name[strcspn(name, "\n")] = 0;
                if (strcmp(name, process_name) == 0) {
                    fclose(f);
                    closedir(dir);
		            printf("Found sober.\n");
                    return pid;
                }
            }
            fclose(f);
	    }
    }
    closedir(dir);
    return -1;
}

ssize_t read_process_mem(pid_t pid, void* addr, void* buf, size_t len) {
    struct iovec local[1];
    struct iovec remote[1];
    local[0].iov_base = buf;
    local[0].iov_len = len;
    remote[0].iov_base = addr;
    remote[0].iov_len = len;

    return process_vm_readv(pid, local, 1, remote, 1, 0);
}

ssize_t write_process_mem(pid_t pid, void* addr, void* buf, size_t len) {
    struct iovec local[1];
    struct iovec remote[1];
    local[0].iov_base = buf;
    local[0].iov_len = len;
    remote[0].iov_base = addr;
    remote[0].iov_len = len;

    return process_vm_writev(pid, local, 1, remote, 1, 0);
}

size_t find_all_occurrences(pid_t pid, int32_t target, unsigned long *results, size_t max_results) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        perror("fopen maps");
        return 0;
    }

    char line[512];
    size_t count = 0;
    printf("Searching for addresses.\n");

    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[5];

        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
            continue;

        // Only check readable and writable regions
        if (perms[0] != 'r' || perms[1] != 'w')
            continue;

        unsigned long region_size = end - start;
        if (region_size == 0 || region_size > (512UL * 1024 * 1024))  // Skip absurdly large/empty regions
            continue;

        char *buffer = malloc(region_size);
        if (!buffer)
            continue;

        ssize_t nread = read_process_mem(pid, (void *)start, buffer, region_size);
        if (nread <= 0 || (size_t)nread > region_size || nread < (ssize_t)sizeof(int32_t)) {
            free(buffer);
            continue;
        }

        for (ssize_t i = 0; i <= nread - (ssize_t)sizeof(int32_t); i++) {
            int32_t val;
            memcpy(&val, buffer + i, sizeof(int32_t));

            if (val == target) {
                if (count < max_results) {
                    results[count++] = start + i;
                } else {
                    break;
                }
            }
        }

        free(buffer);

        // Stop scanning if we already have enough matches
        if (count >= max_results)
            break;
    }

    fclose(maps);
    return count;
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <int32_value_to_find>\n", argv[0]);
        return 1;
    }
    system("clear");

    signal(SIGSEGV, crash_handler);
    signal(SIGABRT, crash_handler);

    int32_t target = atoi(argv[1]);
    pid_t pid = find_pid_by_name("sober") - 1;
    if (pid <= -1) {
        fprintf(stderr, "Process 'sober' not found\n");
        return 1;
    }

    unsigned long matches[MAX_MATCHES];
    size_t count = find_all_occurrences(pid, target, matches, MAX_MATCHES);

    if (count == 0) {
        printf("No matches found.\n");
        return 1;
    }

    printf("Found %zu candidate(s)\n", count);
    //for (size_t i = 0; i < count; i++) {
    //    printf("  0x%lx\n", matches[i]);
    //}

    char input[64];
    while (1) {
        printf("> ");
        fflush(stdout);

        if (!fgets(input, sizeof(input), stdin)) break;
        int32_t new_val = atoi(input);

        for (size_t i = 0; i < count; i++) {
            if (write_process_mem(pid, (void*)matches[i], &new_val, sizeof(int32_t)) != sizeof(int32_t)) {
                fprintf(stderr, "Failed to write to 0x%lx\n", matches[i]);
            } else {
                //printf("Wrote %d to 0x%lx\n", new_val, matches[i]);
            }
        }
    }
    return 0;
}
