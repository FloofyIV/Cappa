#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <malloc.h>  // For malloc_trim


#define RBLXNAME "Main"
#define MAX_REGIONS 512
#define THREADS 12
#define CHUNK_SIZE ( 4UL * 1024 * 1024 )

struct region {
    unsigned long start;
    unsigned long end;
};

pid_t findproc(const char *proc_name, int scans) {            // we could probably find a more reliable
    DIR *dir = opendir("/proc/");
    if (!dir) return -1;

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
                if (strcmp(name, proc_name) == 0) {
                    fclose(f);
                    closedir(dir);
                    if (scans == 0) printf("Found %s\n", proc_name);
                    return pid;
                }
            }
            fclose(f);
        }
    }
    closedir(dir);
    return -1;
}

ssize_t rmem(pid_t pid, void* addr, void* buf, size_t len) {
    struct iovec local = { .iov_base = buf, .iov_len = len };
    struct iovec remote = { .iov_base = addr, .iov_len = len };
    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

ssize_t wmem(pid_t pid, void* addr, void* buf, size_t len) {
    struct iovec local = { .iov_base = buf, .iov_len = len };
    struct iovec remote = { .iov_base = addr, .iov_len = len };
    return process_vm_writev(pid, &local, 1, &remote, 1, 0);
}

typedef struct {
    pid_t pid;
    int32_t target;
    struct region *reg;
    size_t regcount;
    unsigned long *results;
    size_t *gcount;
    pthread_mutex_t *lock;
    bool *qexit;
} scan_args;

void *scan_worker(void *arg) {
    scan_args *args = arg;

    for (size_t i = 0; i < args->regcount; ++i) {
        if (*args->qexit) break;

        unsigned long start = args->reg[i].start;
        unsigned long end = args->reg[i].end;
        size_t region_size = end - start;

        if (region_size == 0 || region_size > (512UL * 1024 * 1024)) continue;

        size_t offset = 0;
        while (offset < region_size) {
            if (*args->qexit) break;

            size_t scan_size = (region_size - offset) > CHUNK_SIZE ? CHUNK_SIZE : (region_size - offset);

            char *buffer = mmap(NULL, scan_size, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (buffer == MAP_FAILED) break;

            ssize_t nread = rmem(args->pid, (void *)(start + offset), buffer, scan_size);
            if (nread <= 0 || (size_t)nread > scan_size) {
                munmap(buffer, scan_size);
                break;
            }

            for (ssize_t j = 0; j <= nread - (ssize_t)sizeof(int32_t); j += sizeof(int32_t)) {
                if (*args->qexit) break;

                int32_t val;
                memcpy(&val, buffer + j, sizeof(int32_t));
                if (val == args->target) {
                    pthread_mutex_lock(args->lock);
                    if (*args->gcount == 0) {
                        args->results[0] = start + offset + j;
                        *args->gcount = 1;
                        *args->qexit = true;
                    }
                    pthread_mutex_unlock(args->lock);
                    break;
                }
            }

            munmap(buffer, scan_size);
            offset += scan_size;
        }
    }

    return NULL;
}

size_t findaddrs(pid_t pid, int32_t target, unsigned long *results, int scancount) {
    FILE *maps;
    char maps_path[64], line[512];
    struct region regions[MAX_REGIONS];
    size_t region_count = 0;

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    maps = fopen(maps_path, "r");
    if (!maps) return 0;

    if (scancount == 0)
        printf("Attached to process: %i (%s)\nSearching for addresses...\n", pid, RBLXNAME);

    while (fgets(line, sizeof(line), maps) && region_count < MAX_REGIONS) {
        unsigned long start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
            continue;
        if (perms[0] != 'r' || perms[1] != 'w') continue;
        regions[region_count++] = (struct region){start, end};
    }
    fclose(maps);

    pthread_t threads[THREADS];
    scan_args args[THREADS];
    size_t count = 0;
    pthread_mutex_t count_lock = PTHREAD_MUTEX_INITIALIZER;
    bool early_exit = false;

    for (int i = 0; i < THREADS; i++) {
        size_t chunk = region_count / THREADS;
        args[i].pid = pid;
        args[i].target = target;
        args[i].reg = &regions[i * chunk];
        args[i].regcount = (i == THREADS - 1) ? (region_count - i * chunk) : chunk;
        args[i].results = results;
        args[i].gcount = &count;
        args[i].lock = &count_lock;
        args[i].qexit = &early_exit;
        pthread_create(&threads[i], NULL, scan_worker, &args[i]);
    }

    for (int i = 0; i < THREADS; i++)
        pthread_join(threads[i], NULL);

    malloc_trim(0);
    return count;
}

bool isalive(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    return access(path, F_OK) == 0;
}

volatile int attached = 0;
pid_t gpid = -1;
unsigned long match_addr = 0;
size_t count = 0;

pthread_mutex_t attach_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t attach_cond = PTHREAD_COND_INITIALIZER;

void *monitor_thread(void *arg) {
    while (1) {
        usleep(10*1000);
        if (attached && !isalive(gpid)) {
            printf("\nProcess exited. Waiting to reattach...\n");
            pthread_mutex_lock(&attach_lock);
            attached = 0;
            pthread_cond_signal(&attach_cond);
            pthread_mutex_unlock(&attach_lock);
        }
    }
    return NULL;
}

void *input_thread(void *arg) {
    char input[32];
    while (1) {
        pthread_mutex_lock(&attach_lock);
        while (!attached)
            pthread_cond_wait(&attach_cond, &attach_lock);
        pthread_mutex_unlock(&attach_lock);

        if (!fgets(input, sizeof(input), stdin)) continue;
        input[strcspn(input, "\n")] = 0;

        if (strcmp(input, "exit") == 0 || strcmp(input, "quit") == 0) {
            printf("Exiting.\n");
            exit(0);
        }

        int32_t new_val = atoi(input);
        if (wmem(gpid, (void*)match_addr, &new_val, sizeof(int32_t)) != sizeof(int32_t))
            fprintf(stderr, "Failed to write to 0x%lx\n", match_addr);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("do: ./Cappa <fps cap>\n");
        return 1;
    }

    int32_t target = atoi(argv[1]);
    pthread_t monitor, input;
    pthread_create(&monitor, NULL, monitor_thread, NULL);
    pthread_create(&input, NULL, input_thread, NULL);
    int scans = 0;
    while (1) {
        if (!attached) {
            pid_t pid = findproc(RBLXNAME, scans);
            if (pid <= -1) {
                usleep(10*1000);
                continue;
            }

            gpid = pid;
            struct timeval t1, t2;
            gettimeofday(&t1, NULL);
            unsigned long addr = 0;
            count = findaddrs(pid, target, &addr, scans);
            gettimeofday(&t2, NULL);

            double elapsed = (t2.tv_sec - t1.tv_sec) * 1000.0;
            elapsed += (t2.tv_usec - t1.tv_usec) / 1000.0;
            printf("Scan took %.2f ms\n", elapsed);

            if (count < 1) {
                printf("Failed, no matches.\n");
                usleep(50*1000);
                continue;
            }

            match_addr = addr;
            printf("Found address: 0x%lx\n", match_addr);
            pthread_mutex_lock(&attach_lock);
            attached = 1;
            scans = 0;
            pthread_cond_signal(&attach_cond);
            pthread_mutex_unlock(&attach_lock);
        }
        usleep(10*1000);
    }

    return 0;
}