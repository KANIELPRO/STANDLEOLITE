#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef struct {
    uint64_t start, end, off;
    char perms[5];
    char path[512];
} Map;

static void mkpath(const char *p) {
    char tmp[1024];
    size_t n = strlen(p);
    if (n >= sizeof(tmp)) return;
    memcpy(tmp, p, n + 1);
    for (size_t i = 1; i < n; ++i) {
        if (tmp[i] == '/') {
            tmp[i] = 0;
            mkdir(tmp, 0771);
            tmp[i] = '/';
        }
    }
    mkdir(tmp, 0771);
}

static int parse_maps(Map *out, int max) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return -1;
    char line[1024], perms[8], path[512];
    unsigned long long s, e, off;
    int count = 0;
    while (fgets(line, sizeof(line), f) && count < max) {
        perms[0] = path[0] = 0;
        int n = sscanf(line, "%llx-%llx %7s %llx %*s %*s %511[^\n]",
                       &s, &e, perms, &off, path);
        if (n < 4) continue;
        if (!strstr(line, "libunity.so")) continue;
        Map *m = &out[count++];
        m->start = s; m->end = e; m->off = off;
        snprintf(m->perms, sizeof(m->perms), "%s", perms);
        snprintf(m->path, sizeof(m->path), "%s", n >= 5 ? path : "libunity.so");
    }
    fclose(f);
    return count;
}static int dump_range(int fd, uint64_t start, uint64_t len, const char *path) {
    int out = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (out < 0) return -1;
    uint8_t *buf = (uint8_t*)malloc(1024 * 1024);
    if (!buf) { close(out); return -2; }
    uint64_t pos = start, left = len;
    while (left) {
        size_t want = (size_t)(left > 1024*1024 ? 1024*1024 : left);
        ssize_t got = pread(fd, buf, want, (off_t)pos);
        if (got <= 0) { free(buf); close(out); return -3; }
        ssize_t wr = write(out, buf, (size_t)got);
        if (wr != got) { free(buf); close(out); return -4; }
        pos += (uint64_t)got;
        left -= (uint64_t)got;
    }
    fsync(out);
    close(out);
    free(buf);
    return 0;
}

static void *worker(void *unused) {
    (void)unused;
    sleep(12);
    const char *dir = "/sdcard/Android/data/com.stand.cherry.prod/files/standdump";
    mkpath(dir);
    char report[1200];
    snprintf(report, sizeof(report), "%s/report.txt", dir);
    FILE *r = fopen(report, "w");
    if (!r) return 0;
    fprintf(r, "SELFDUMP_START\nPID=%d\n", getpid());
    fflush(r);
    Map maps[64];
    int mc = parse_maps(maps, 64);
    fprintf(r, "LIBUNITY_MAPS=%d\n", mc);
    fflush(r);

    FILE *mf = fopen("/proc/self/maps", "r");
    if (mf) {
        char line[1024];
        while (fgets(line, sizeof(line), mf))
            if (strstr(line, "libunity.so")) fputs(line, r);
        fclose(mf);
    }

    int mem = open("/proc/self/mem", O_RDONLY);
    if (mem < 0) {
        fprintf(r, "MEM_OPEN_ERR=%d:%s\n", errno, strerror(errno));
        fclose(r);
        return 0;
    }

    for (int i = 0; i < mc; ++i) {
        char fn[1200];
        const Map *m = &maps[i];
        const char *kind = strchr(m->perms, 'x') ? "text" :
                           strchr(m->perms, 'w') ? "rw" : "ro";
        snprintf(fn, sizeof(fn), "%s/libunity.%02d.%s.%llx-%llx.off-%llx.bin",
                 dir, i, kind,
                 (unsigned long long)m->start,
                 (unsigned long long)m->end,
                 (unsigned long long)m->off);
        uint64_t len = m->end - m->start;
        int rc = dump_range(mem, m->start, len, fn);
        fprintf(r, "DUMP[%d] start=0x%llx end=0x%llx off=0x%llx len=0x%llx rc=%d file=%s\n",
                i, (unsigned long long)m->start, (unsigned long long)m->end,
                (unsigned long long)m->off, (unsigned long long)len, rc, fn);
        fflush(r);
    }
    close(mem);
    fprintf(r, "SELFDUMP_DONE\n");
    fclose(r);
    return 0;
}

__attribute__((constructor))
static void init_selfdump(void) {
    pthread_t t;
    if (pthread_create(&t, 0, worker, 0) == 0)
        pthread_detach(t);
}
