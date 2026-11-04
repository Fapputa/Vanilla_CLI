/* Memory scanner engine for the F8 memory editor (Cheat Engine style).
 *
 * Linux: /proc/<pid>/maps for the regions, process_vm_readv/writev for the
 * transfers (with /proc/<pid>/mem as a fallback, which can also write into
 * read-only pages). Reading another process needs ptrace rights: root, or
 * kernel.yama.ptrace_scope = 0, or the process being a child of Abyss
 * (mem_launch), which works with the default ptrace_scope = 1.
 * Windows: the Win32 calls live in winproc.c (OpenProcess, VirtualQueryEx,
 * ReadProcessMemory, WriteProcessMemory, Toolhelp snapshots).
 *
 * A first scan walks every writable region and keeps the addresses that
 * match; next scans only re-check those addresses. "Unknown initial value"
 * keeps a copy of the writable memory instead, compared on the next scan. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "memscan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <limits.h>
#include <time.h>

#ifdef _WIN32
int    win_mem_procs(int *pids, char (*names)[128], int max);
int    win_mem_open(int pid, unsigned long *errcode);
void   win_mem_close(void);
int    win_mem_alive(void);
int    win_mem_regions(uint64_t *starts, uint64_t *ends, int *writable, char (*names)[160], int max);
size_t win_mem_read(uint64_t addr, void *buf, size_t n);
int    win_mem_write(uint64_t addr, const void *buf, size_t n);
#else
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif

void (*mem_progress)(uint64_t done, uint64_t total) = NULL;

static int  g_pid = 0;
static char g_name[128];
static bool g_att = false;
#ifndef _WIN32
static int   g_memfd = -1;
static pid_t g_child = 0;          /* started by mem_launch */
#endif

/* ─── Processes ─────────────────────────────────────────────────── */

static int proc_cmp(const void *a, const void *b) {
    return ((const MemProc *)b)->pid - ((const MemProc *)a)->pid;   /* newest first */
}

#ifndef _WIN32
static bool read_small(const char *path, char *buf, size_t sz) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    ssize_t n = read(fd, buf, sz - 1);
    close(fd);
    if (n < 0) return false;
    buf[n] = '\0';
    return true;
}
#endif

int mem_list_procs(MemProc **out) {
    int n = 0, cap = 256;
    MemProc *v = malloc((size_t)cap * sizeof *v);
    if (!v) { *out = NULL; return 0; }
#ifdef _WIN32
    int pids[4096];
    static char names[4096][128];
    int k = win_mem_procs(pids, names, 4096);
    for (int i = 0; i < k; i++) {
        if (n >= cap) { cap *= 2; v = realloc(v, (size_t)cap * sizeof *v); }
        v[n].pid = pids[i];
        snprintf(v[n].name, sizeof v[n].name, "%s", names[i]);
        v[n].rss_kb = 0;
        n++;
    }
#else
    DIR *d = opendir("/proc");
    if (!d) { *out = v; return 0; }
    long page_kb = sysconf(_SC_PAGESIZE) / 1024;
    struct dirent *e;
    int self = (int)getpid();
    while ((e = readdir(d))) {
        if (!isdigit((unsigned char)e->d_name[0])) continue;
        int pid = atoi(e->d_name);
        if (pid == self) continue;
        char path[64], buf[512];
        snprintf(path, sizeof path, "/proc/%d/statm", pid);
        if (!read_small(path, buf, sizeof buf)) continue;
        unsigned long long size = 0, res = 0;
        if (sscanf(buf, "%llu %llu", &size, &res) != 2 || size == 0) continue;   /* kernel thread */
        snprintf(path, sizeof path, "/proc/%d/comm", pid);
        if (!read_small(path, buf, sizeof buf)) continue;
        buf[strcspn(buf, "\n")] = '\0';
        char name[128];
        snprintf(name, sizeof name, "%s", buf);
        if (strlen(name) >= 15) {                         /* comm is cut at 15 chars */
            char cmd[512];
            snprintf(path, sizeof path, "/proc/%d/cmdline", pid);
            if (read_small(path, cmd, sizeof cmd) && cmd[0]) {
                const char *b = strrchr(cmd, '/');
                snprintf(name, sizeof name, "%s", b ? b + 1 : cmd);
            }
        }
        if (n >= cap) { cap *= 2; v = realloc(v, (size_t)cap * sizeof *v); }
        v[n].pid = pid;
        snprintf(v[n].name, sizeof v[n].name, "%s", name);
        v[n].rss_kb = res * (unsigned long long)page_kb;
        n++;
    }
    closedir(d);
#endif
    qsort(v, (size_t)n, sizeof *v, proc_cmp);
    *out = v;
    return n;
}

bool mem_attached(void)     { return g_att; }
int  mem_pid(void)          { return g_pid; }
const char *mem_pname(void) { return g_name; }

bool mem_alive(void) {
    if (!g_att) return false;
#ifdef _WIN32
    return win_mem_alive() != 0;
#else
    if (g_child > 0) {
        int st;
        if (waitpid(g_child, &st, WNOHANG) == g_child) { g_child = 0; return false; }
    }
    return kill(g_pid, 0) == 0 || errno == EPERM;
#endif
}

void mem_detach(void) {
#ifdef _WIN32
    win_mem_close();
#else
    if (g_memfd >= 0) close(g_memfd);
    g_memfd = -1;
#endif
    g_att = false;
    g_pid = 0;
    g_name[0] = '\0';
}

bool mem_attach(int pid, const char *name, char *err, size_t esz) {
    mem_detach();
    err[0] = '\0';
#ifdef _WIN32
    unsigned long code = 0;
    if (!win_mem_open(pid, &code)) {
        if (code == 5)
            snprintf(err, esz, "Access denied to %s (%d): run Abyss as administrator", name, pid);
        else
            snprintf(err, esz, "Cannot open process %d (Windows error %lu)", pid, code);
        return false;
    }
    g_pid = pid;
    g_att = true;
#else
    g_pid = pid;
    g_att = true;
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/mem", pid);
    g_memfd = open(path, O_RDWR);
    if (g_memfd < 0) g_memfd = open(path, O_RDONLY);

    /* probe one byte of the first readable region */
    MemRegion *rg = NULL;
    int nr = mem_regions(&rg, false);
    bool ok = false;
    int why = 0;
    for (int i = 0; i < nr && !ok; i++) {
        uint8_t b;
        struct iovec l = { &b, 1 }, r = { (void *)(uintptr_t)rg[i].start, 1 };
        if (process_vm_readv(pid, &l, 1, &r, 1, 0) == 1) ok = true;
        else why = errno;
        if (why == EPERM || why == ESRCH) break;
    }
    free(rg);
    if (!ok && g_memfd >= 0 && nr > 0) ok = true;           /* /proc/pid/mem works */
    if (!ok) {
        g_att = false;
        if (why == ESRCH) snprintf(err, esz, "Process %d has exited", pid);
        else if (nr == 0 && why == 0)
            snprintf(err, esz, "Cannot read the memory map of %d (permission?)", pid);
        else {
            char scope[16] = "?";
            read_small("/proc/sys/kernel/yama/ptrace_scope", scope, sizeof scope);
            scope[strcspn(scope, "\n")] = '\0';
            snprintf(err, esz,
                     "Permission denied (ptrace_scope=%s): launch it from the list with ^O, "
                     "run Abyss with sudo, or: sudo sysctl kernel.yama.ptrace_scope=0", scope);
        }
        if (g_memfd >= 0) close(g_memfd);
        g_memfd = -1;
        g_pid = 0;
        return false;
    }
#endif
    snprintf(g_name, sizeof g_name, "%s", name ? name : "?");
    return true;
}

bool mem_launch(const char *cmdline, char *err, size_t esz) {
#ifdef _WIN32
    (void)cmdline;
    snprintf(err, esz, "On Windows, start the program normally and pick it in the list");
    return false;
#else
    if (!cmdline || !*cmdline) { snprintf(err, esz, "No command"); return false; }
    char full[4200];
    snprintf(full, sizeof full, "exec %s", cmdline);
    pid_t pid = fork();
    if (pid < 0) { snprintf(err, esz, "fork failed: %s", strerror(errno)); return false; }
    if (pid == 0) {
        setsid();
        int nul = open("/dev/null", O_RDWR);
        if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); }
        execl("/bin/sh", "sh", "-c", full, (char *)NULL);
        _exit(127);
    }
    g_child = pid;
    struct timespec ts = { 0, 250 * 1000000L };             /* let it exec */
    nanosleep(&ts, NULL);
    int st;
    if (waitpid(pid, &st, WNOHANG) == pid) {
        g_child = 0;
        snprintf(err, esz, "The program exited right away (exit %d)", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        return false;
    }
    char name[128], comm[128], path[64];
    snprintf(path, sizeof path, "/proc/%d/comm", pid);
    if (read_small(path, comm, sizeof comm)) { comm[strcspn(comm, "\n")] = '\0'; snprintf(name, sizeof name, "%s", comm); }
    else snprintf(name, sizeof name, "%.60s", cmdline);
    return mem_attach(pid, name, err, esz);
#endif
}

/* ─── Regions & transfers ──────────────────────────────────────── */

int mem_regions(MemRegion **out, bool writable_only) {
    int n = 0, cap = 256;
    MemRegion *v = malloc((size_t)cap * sizeof *v);
    *out = v;
    if (!v || !g_pid) return 0;
#ifdef _WIN32
    enum { MAXR = 65536 };
    uint64_t *st = malloc(MAXR * sizeof *st), *en = malloc(MAXR * sizeof *en);
    int *wr = malloc(MAXR * sizeof *wr);
    char (*nm)[160] = malloc(MAXR * sizeof *nm);
    int k = (st && en && wr && nm) ? win_mem_regions(st, en, wr, nm, MAXR) : 0;
    for (int i = 0; i < k; i++) {
        if (writable_only && !wr[i]) continue;
        if (n >= cap) { cap *= 2; v = realloc(v, (size_t)cap * sizeof *v); *out = v; }
        v[n].start = st[i]; v[n].end = en[i]; v[n].write = wr[i] != 0;
        snprintf(v[n].name, sizeof v[n].name, "%s", nm[i]);
        n++;
    }
    free(st); free(en); free(wr); free(nm);
#else
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", g_pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[1024];
    while (fgets(line, sizeof line, f)) {
        unsigned long long a, b;
        char perms[8] = "", file[800] = "";
        if (sscanf(line, "%llx-%llx %7s %*s %*s %*s %799[^\n]", &a, &b, perms, file) < 3) continue;
        if (perms[0] != 'r') continue;
        if (writable_only && perms[1] != 'w') continue;
        char *fn = file;
        while (*fn == ' ') fn++;
        /* device mappings (GPU, ...) can have side effects or hang on read */
        if (!strncmp(fn, "/dev/", 5) || !strcmp(fn, "[vvar]") || !strcmp(fn, "[vsyscall]") ||
            !strncmp(fn, "[vvar", 5)) continue;
        if (n >= cap) { cap *= 2; v = realloc(v, (size_t)cap * sizeof *v); *out = v; }
        v[n].start = a; v[n].end = b; v[n].write = perms[1] == 'w';
        const char *base = strrchr(fn, '/');
        snprintf(v[n].name, sizeof v[n].name, "%s", *fn ? (base ? base + 1 : fn) : "anonymous");
        n++;
    }
    fclose(f);
#endif
    return n;
}

size_t mem_read(uint64_t addr, void *buf, size_t n) {
    if (!g_att || !n) return 0;
#ifdef _WIN32
    return win_mem_read(addr, buf, n);
#else
    struct iovec l = { buf, n }, r = { (void *)(uintptr_t)addr, n };
    ssize_t got = process_vm_readv(g_pid, &l, 1, &r, 1, 0);
    if (got > 0) return (size_t)got;
    if (g_memfd >= 0) {
        got = pread(g_memfd, buf, n, (off_t)addr);
        if (got > 0) return (size_t)got;
    }
    return 0;
#endif
}

bool mem_write(uint64_t addr, const void *buf, size_t n) {
    if (!g_att || !n) return false;
#ifdef _WIN32
    return win_mem_write(addr, buf, n) != 0;
#else
    struct iovec l = { (void *)buf, n }, r = { (void *)(uintptr_t)addr, n };
    if (process_vm_writev(g_pid, &l, 1, &r, 1, 0) == (ssize_t)n) return true;
    if (g_memfd >= 0 && pwrite(g_memfd, buf, n, (off_t)addr) == (ssize_t)n) return true;
    return false;
#endif
}

/* ─── Values ───────────────────────────────────────────────────── */

static const char *type_names[MT_COUNT] = {
    "int8", "int16", "int32", "int64", "float", "double", "text", "text UTF-16", "bytes"
};
static const int type_sizes[MT_COUNT] = { 1, 2, 4, 8, 4, 8, 0, 0, 0 };

const char *mem_type_name(MemType t) { return t < MT_COUNT ? type_names[t] : "?"; }
int         mem_type_size(MemType t) { return t < MT_COUNT ? type_sizes[t] : 0; }

static const char *mode_names[MS_COUNT] = {
    "exact value", "bigger than", "smaller than", "between", "unknown initial value",
    "increased", "decreased", "increased by", "decreased by", "changed", "unchanged"
};
const char *mem_mode_name(MemScanMode m) { return m < MS_COUNT ? mode_names[m] : "?"; }

bool mem_mode_needs_value(MemScanMode m) {
    return m == MS_EXACT || m == MS_BIGGER || m == MS_SMALLER || m == MS_BETWEEN ||
           m == MS_INC_BY || m == MS_DEC_BY;
}

bool mem_mode_first_ok(MemScanMode m) {
    return m == MS_EXACT || m == MS_BIGGER || m == MS_SMALLER || m == MS_BETWEEN || m == MS_UNKNOWN;
}

static bool is_float(MemType t) { return t == MT_F32 || t == MT_F64; }
static bool is_num(MemType t)   { return t <= MT_F64; }

bool mem_mode_ok_for(MemType t, MemScanMode m) {
    if (is_num(t)) return true;
    return m == MS_EXACT || m == MS_CHANGED || m == MS_UNCHANGED;
}

static bool parse_i64(const char *s, int64_t *out) {
    while (*s == ' ') s++;
    bool neg = *s == '-';
    const char *p = s + (neg || *s == '+');
    int base = (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) ? 16 : 10;
    if (base == 16) p += 2;
    if (!isxdigit((unsigned char)*p)) return false;
    char *end;
    errno = 0;
    unsigned long long u = strtoull(p, &end, base);
    if (errno) return false;
    while (*end == ' ') end++;
    if (*end) return false;
    *out = neg ? -(int64_t)u : (int64_t)u;
    return true;
}

static bool parse_f(const char *s, double *out, double *tol) {
    while (*s == ' ') s++;
    char *end;
    errno = 0;
    double d = strtod(s, &end);
    if (end == s || errno) return false;
    while (*end == ' ') end++;
    if (*end) return false;
    const char *dot = strchr(s, '.');
    int dec = 0;
    if (dot) for (const char *q = dot + 1; isdigit((unsigned char)*q); q++) dec++;
    *out = d;
    *tol = 0.5 * pow(10.0, -dec);           /* "100" matches 99.5..100.5, "1.25" 1.245..1.255 */
    return true;
}

static void put_le(uint8_t *b, int64_t v, int size) {
    for (int i = 0; i < size; i++) b[i] = (uint8_t)((uint64_t)v >> (8 * i));
}

static bool fits(int64_t v, int size) {
    switch (size) {
        case 1: return v >= INT8_MIN  && v <= UINT8_MAX;
        case 2: return v >= INT16_MIN && v <= UINT16_MAX;
        case 4: return v >= INT32_MIN && v <= (int64_t)UINT32_MAX;
        default: return true;
    }
}

bool mem_parse(MemType t, MemScanMode m, const char *text, MemValue *v, char *err, size_t esz) {
    memset(v, 0, sizeof *v);
    v->type = t;
    v->size = mem_type_size(t);
    memset(v->mask, 0xFF, sizeof v->mask);
    err[0] = '\0';
    if (!mem_mode_needs_value(m)) return true;
    if (!text) text = "";

    if (t == MT_STR) {
        size_t n = strlen(text);
        if (n == 0 || n > sizeof v->bytes) { snprintf(err, esz, "Text: 1 to 256 bytes"); return false; }
        memcpy(v->bytes, text, n);
        v->size = (int)n;
        return true;
    }
    if (t == MT_STR16) {                                  /* UTF-8 -> UTF-16LE */
        int o = 0;
        for (const unsigned char *p = (const unsigned char *)text; *p && o + 4 <= (int)sizeof v->bytes; ) {
            uint32_t cp;
            if (*p < 0x80) cp = *p++;
            else if ((*p & 0xE0) == 0xC0 && p[1]) { cp = ((uint32_t)(*p & 0x1F) << 6) | (p[1] & 0x3F); p += 2; }
            else if ((*p & 0xF0) == 0xE0 && p[1] && p[2]) { cp = ((uint32_t)(*p & 0x0F) << 12) | ((uint32_t)(p[1] & 0x3F) << 6) | (p[2] & 0x3F); p += 3; }
            else if ((*p & 0xF8) == 0xF0 && p[1] && p[2] && p[3]) { cp = ((uint32_t)(*p & 0x07) << 18) | ((uint32_t)(p[1] & 0x3F) << 12) | ((uint32_t)(p[2] & 0x3F) << 6) | (p[3] & 0x3F); p += 4; }
            else { cp = '?'; p++; }
            if (cp >= 0x10000) {
                cp -= 0x10000;
                uint16_t hi = (uint16_t)(0xD800 + (cp >> 10)), lo = (uint16_t)(0xDC00 + (cp & 0x3FF));
                v->bytes[o++] = (uint8_t)hi; v->bytes[o++] = (uint8_t)(hi >> 8);
                v->bytes[o++] = (uint8_t)lo; v->bytes[o++] = (uint8_t)(lo >> 8);
            } else { v->bytes[o++] = (uint8_t)cp; v->bytes[o++] = (uint8_t)(cp >> 8); }
        }
        if (o == 0) { snprintf(err, esz, "Empty text"); return false; }
        v->size = o;
        return true;
    }
    if (t == MT_BYTES) {                                  /* "DE AD ?? EF" or "DEAD??EF" */
        int n = 0;
        bool real = false;
        for (const char *p = text; *p; ) {
            if (*p == ' ' || *p == ',') { p++; continue; }
            if (n >= (int)sizeof v->bytes) { snprintf(err, esz, "At most 256 bytes"); return false; }
            if (*p == '?') {
                v->mask[n] = 0; v->bytes[n++] = 0;
                p += p[1] == '?' ? 2 : 1;
                continue;
            }
            if (!isxdigit((unsigned char)p[0]) || !isxdigit((unsigned char)p[1])) {
                snprintf(err, esz, "Bytes: hex pairs like DE AD ?? EF");
                return false;
            }
            char h[3] = { p[0], p[1], 0 };
            v->bytes[n] = (uint8_t)strtoul(h, NULL, 16);
            v->mask[n++] = 0xFF;
            real = true;
            p += 2;
        }
        if (!real) { snprintf(err, esz, "Bytes: give at least one real byte"); return false; }
        v->size = n;
        return true;
    }

    /* numbers; "between" is written  10..20  */
    char a[128], b[128] = "";
    snprintf(a, sizeof a, "%s", text);
    if (m == MS_BETWEEN) {
        char *dd = strstr(a, "..");
        if (!dd) { snprintf(err, esz, "Between: write it as  low..high"); return false; }
        *dd = '\0';
        snprintf(b, sizeof b, "%s", dd + 2);
    }
    if (is_float(t)) {
        if (!parse_f(a, &v->f, &v->tol) || (m == MS_BETWEEN && !parse_f(b, &v->f2, &v->tol))) {
            snprintf(err, esz, "Not a number: %.60s", text);
            return false;
        }
        if (t == MT_F32) { float x = (float)v->f; memcpy(v->bytes, &x, 4); }
        else memcpy(v->bytes, &v->f, 8);
    } else {
        if (!parse_i64(a, &v->i) || (m == MS_BETWEEN && !parse_i64(b, &v->i2))) {
            snprintf(err, esz, "Not an integer: %.60s", text);
            return false;
        }
        if (m == MS_EXACT && !fits(v->i, v->size)) {
            snprintf(err, esz, "%lld does not fit in %s", (long long)v->i, type_names[t]);
            return false;
        }
        put_le(v->bytes, v->i, v->size);
    }
    return true;
}

static int64_t get_i(MemType t, const uint8_t *p) {
    switch (t) {
        case MT_I8:  return (int8_t)p[0];
        case MT_I16: { int16_t x; memcpy(&x, p, 2); return x; }
        case MT_I32: { int32_t x; memcpy(&x, p, 4); return x; }
        default:     { int64_t x; memcpy(&x, p, 8); return x; }
    }
}

static double get_f(MemType t, const uint8_t *p) {
    if (t == MT_F32) { float x; memcpy(&x, p, 4); return x; }
    double x; memcpy(&x, p, 8); return x;
}

void mem_format(MemType t, const uint8_t *p, int len, char *out, size_t sz) {
    out[0] = '\0';
    if (is_num(t)) {
        if (len < mem_type_size(t)) { snprintf(out, sz, "??"); return; }
        if (t == MT_F32)      snprintf(out, sz, "%.7g", get_f(t, p));
        else if (t == MT_F64) snprintf(out, sz, "%.15g", get_f(t, p));
        else                  snprintf(out, sz, "%lld", (long long)get_i(t, p));
        return;
    }
    size_t o = 0;
    if (t == MT_STR) {
        for (int i = 0; i < len && o + 2 < sz; i++) {
            unsigned char c = p[i];
            out[o++] = (c >= 32 && c != 127) ? (char)c : '.';
        }
    } else if (t == MT_STR16) {
        for (int i = 0; i + 1 < len && o + 5 < sz; i += 2) {
            uint32_t c = (uint32_t)p[i] | ((uint32_t)p[i + 1] << 8);
            if (c < 32) { out[o++] = '.'; continue; }
            if (c < 0x80) out[o++] = (char)c;
            else if (c < 0x800) { out[o++] = (char)(0xC0 | (c >> 6)); out[o++] = (char)(0x80 | (c & 0x3F)); }
            else if (c < 0xD800 || c >= 0xE000) {
                out[o++] = (char)(0xE0 | (c >> 12)); out[o++] = (char)(0x80 | ((c >> 6) & 0x3F)); out[o++] = (char)(0x80 | (c & 0x3F));
            } else out[o++] = '?';
        }
    } else {
        for (int i = 0; i < len && o + 4 < sz; i++) o += (size_t)snprintf(out + o, sz - o, "%s%02X", i ? " " : "", p[i]);
    }
    out[o < sz ? o : sz - 1] = '\0';
}

/* ─── Matching ─────────────────────────────────────────────────── */

static inline bool match(MemType t, MemScanMode m, const uint8_t *cur, const uint8_t *prev,
                         const MemValue *v, int size) {
    switch (m) {
        case MS_CHANGED:   return memcmp(cur, prev, (size_t)size) != 0;
        case MS_UNCHANGED: return memcmp(cur, prev, (size_t)size) == 0;
        default: break;
    }
    if (!is_num(t)) {                                     /* text, bytes: exact */
        for (int i = 0; i < size; i++) if ((cur[i] & v->mask[i]) != (v->bytes[i] & v->mask[i])) return false;
        return true;
    }
    if (is_float(t)) {
        double c = get_f(t, cur);
        if (isnan(c) || isinf(c)) return false;
        double p = prev ? get_f(t, prev) : 0;
        switch (m) {
            case MS_EXACT:     return fabs(c - v->f) <= v->tol;
            case MS_BIGGER:    return c > v->f;
            case MS_SMALLER:   return c < v->f;
            case MS_BETWEEN:   return c >= v->f && c <= v->f2;
            case MS_INCREASED: return c > p;
            case MS_DECREASED: return c < p;
            case MS_INC_BY:    return fabs((c - p) - v->f) <= v->tol;
            case MS_DEC_BY:    return fabs((p - c) - v->f) <= v->tol;
            default:           return false;
        }
    }
    int64_t c = get_i(t, cur), p = prev ? get_i(t, prev) : 0;
    switch (m) {
        case MS_EXACT:     return memcmp(cur, v->bytes, (size_t)size) == 0;
        case MS_BIGGER:    return c > v->i;
        case MS_SMALLER:   return c < v->i;
        case MS_BETWEEN:   return c >= v->i && c <= v->i2;
        case MS_INCREASED: return c > p;
        case MS_DECREASED: return c < p;
        case MS_INC_BY:    return c - p == v->i;
        case MS_DEC_BY:    return p - c == v->i;
        default:           return false;
    }
}

/* ─── Results & snapshot ───────────────────────────────────────── */

void mem_results_free(MemResults *r) {
    free(r->addr); free(r->prev);
    memset(r, 0, sizeof *r);
}

static bool res_push(MemResults *r, uint64_t a, const uint8_t *val, int size) {
    if (r->n >= MEM_MAX_RESULTS) { r->overflow = true; return false; }
    if (r->n >= r->cap) {
        size_t nc = r->cap ? r->cap * 2 : 4096;
        if (nc > MEM_MAX_RESULTS) nc = MEM_MAX_RESULTS;
        uint64_t *na = realloc(r->addr, nc * sizeof *na);
        if (!na) { r->overflow = true; return false; }
        r->addr = na;
        uint8_t *np = realloc(r->prev, nc * MEM_PREV);
        if (!np) { r->overflow = true; return false; }
        r->prev = np;
        r->cap = nc;
    }
    r->addr[r->n] = a;
    memset(r->prev + r->n * MEM_PREV, 0, MEM_PREV);
    memcpy(r->prev + r->n * MEM_PREV, val, (size_t)(size < MEM_PREV ? size : MEM_PREV));
    r->n++;
    return true;
}

typedef struct { uint64_t start; size_t len; uint8_t *data; } SnapReg;
static SnapReg *g_snap = NULL;
static int      g_nsnap = 0;
static int      g_snap_step = 4;

static void snap_free(void) {
    for (int i = 0; i < g_nsnap; i++) free(g_snap[i].data);
    free(g_snap);
    g_snap = NULL;
    g_nsnap = 0;
}

bool mem_has_snapshot(void) { return g_nsnap > 0; }

#define CHUNK     (4u << 20)
#define SNAP_MAX  (2048ull << 20)

static int step_for(MemType t, bool aligned) {
    int s = mem_type_size(t);
    if (!aligned || s <= 1) return 1;
    return s >= 4 ? 4 : s;
}

/* ─── Scans ────────────────────────────────────────────────────── */

bool mem_first_scan(MemType t, MemScanMode m, const MemValue *v, bool aligned,
                    MemResults *r, char *err, size_t esz) {
    mem_results_free(r);
    snap_free();
    err[0] = '\0';
    if (!g_att) { snprintf(err, esz, "No process"); return false; }
    if (!mem_mode_first_ok(m) || !mem_mode_ok_for(t, m)) { snprintf(err, esz, "Not a first-scan mode"); return false; }

    MemRegion *rg;
    int nr = mem_regions(&rg, true);
    uint64_t total = 0, done = 0;
    for (int i = 0; i < nr; i++) total += rg[i].end - rg[i].start;
    if (nr == 0) { free(rg); snprintf(err, esz, "No readable memory (process gone?)"); return false; }

    if (m == MS_UNKNOWN) {
        if (total > SNAP_MAX) {
            free(rg);
            snprintf(err, esz, "%llu MB of writable memory: too much to copy, scan for a value instead",
                     (unsigned long long)(total >> 20));
            return false;
        }
        g_snap = calloc((size_t)nr, sizeof *g_snap);
        for (int i = 0; i < nr; i++) {
            size_t len = (size_t)(rg[i].end - rg[i].start);
            uint8_t *d = malloc(len);
            if (!d) { snap_free(); free(rg); snprintf(err, esz, "Out of memory for the snapshot"); return false; }
            size_t got = 0;
            while (got < len) {
                size_t want = len - got > CHUNK ? CHUNK : len - got;
                size_t k = mem_read(rg[i].start + got, d + got, want);
                if (k == 0) { memset(d + got, 0, want); k = want; }
                got += k;
            }
            g_snap[g_nsnap++] = (SnapReg){ rg[i].start, len, d };
            done += len;
            if (mem_progress) mem_progress(done, total);
        }
        g_snap_step = step_for(t, aligned);
        free(rg);
        return true;
    }

    int size = is_num(t) ? mem_type_size(t) : v->size;
    int step = is_num(t) ? step_for(t, aligned) : 1;
    uint8_t *buf = malloc(CHUNK + 256);
    if (!buf) { free(rg); snprintf(err, esz, "Out of memory"); return false; }

    /* the exact-integer case is the common one: compare machine words */
    bool fast = m == MS_EXACT && is_num(t) && !is_float(t);
    uint64_t needle = 0;
    if (is_num(t)) memcpy(&needle, v->bytes, (size_t)size);
    int first = -1;                                       /* text / bytes: first fixed byte */
    if (!is_num(t)) for (int i = 0; i < size; i++) if (v->mask[i]) { first = i; break; }

    for (int ri = 0; ri < nr && !r->overflow; ri++) {
        for (uint64_t pos = rg[ri].start; pos < rg[ri].end && !r->overflow; pos += CHUNK) {
            uint64_t left = rg[ri].end - pos;
            size_t want = left > CHUNK + (uint64_t)size - 1 ? CHUNK + (size_t)size - 1 : (size_t)left;
            size_t n = mem_read(pos, buf, want);
            size_t limit = n >= (size_t)size ? n - (size_t)size + 1 : 0;   /* last start + 1 */
            if (limit > CHUNK) limit = CHUNK;
            size_t i0 = (size_t)((step - (int)(pos % (uint64_t)step)) % step);
            if (!is_num(t)) {
                for (size_t i = 0; i < limit; ) {
                    if (first >= 0) {
                        const uint8_t *hit = memchr(buf + i + first, v->bytes[first], limit - i);
                        if (!hit) break;
                        i = (size_t)(hit - buf) - (size_t)first;
                    }
                    if (match(t, m, buf + i, NULL, v, size) && !res_push(r, pos + i, buf + i, size)) break;
                    i++;
                }
            } else if (fast && size == 4) {
                uint32_t nd = (uint32_t)needle;
                for (size_t i = i0; i < limit; i += (size_t)step) {
                    uint32_t x; memcpy(&x, buf + i, 4);
                    if (x == nd && !res_push(r, pos + i, buf + i, 4)) break;
                }
            } else if (fast && size == 8) {
                for (size_t i = i0; i < limit; i += (size_t)step) {
                    uint64_t x; memcpy(&x, buf + i, 8);
                    if (x == needle && !res_push(r, pos + i, buf + i, 8)) break;
                }
            } else {
                for (size_t i = i0; i < limit; i += (size_t)step)
                    if (match(t, m, buf + i, NULL, v, size) && !res_push(r, pos + i, buf + i, size)) break;
            }
            done += limit;
            if (mem_progress) mem_progress(done, total);
        }
    }
    free(buf);
    free(rg);
    if (r->overflow)
        snprintf(err, esz, "More than %u matches: kept the first ones, refine with a next scan",
                 MEM_MAX_RESULTS);
    return true;
}

bool mem_next_scan(MemType t, MemScanMode m, const MemValue *v, MemResults *r, char *err, size_t esz) {
    err[0] = '\0';
    if (!g_att) { snprintf(err, esz, "No process"); return false; }
    if (!mem_mode_ok_for(t, m) || m == MS_UNKNOWN) { snprintf(err, esz, "Not a next-scan mode"); return false; }
    int size = is_num(t) ? mem_type_size(t) : v->size;
    if (!is_num(t) && size <= 0) size = MEM_PREV;

    if (g_nsnap) {                                        /* after "unknown initial value" */
        mem_results_free(r);
        uint64_t total = 0, done = 0;
        for (int i = 0; i < g_nsnap; i++) total += g_snap[i].len;
        uint8_t *buf = malloc(CHUNK + 16);
        int step = g_snap_step;
        for (int si = 0; si < g_nsnap && !r->overflow; si++) {
            SnapReg *s = &g_snap[si];
            for (size_t off = 0; off < s->len && !r->overflow; off += CHUNK) {
                size_t want = s->len - off > CHUNK ? CHUNK : s->len - off;
                size_t n = mem_read(s->start + off, buf, want);
                size_t i0 = (size_t)((step - (int)((s->start + off) % (uint64_t)step)) % step);
                for (size_t i = i0; i + (size_t)size <= n; i += (size_t)step)
                    if (match(t, m, buf + i, s->data + off + i, v, size) &&
                        !res_push(r, s->start + off + i, buf + i, size)) break;
                done += want;
                if (mem_progress) mem_progress(done, total);
            }
        }
        free(buf);
        snap_free();
        if (r->overflow)
            snprintf(err, esz, "More than %u matches: kept the first ones, refine again", MEM_MAX_RESULTS);
        return true;
    }

    /* refine the result list: addresses are sorted, read them by blocks */
    static uint8_t blk[1 << 16];
    uint64_t bstart = 0;
    size_t   blen = 0;
    size_t   k = 0;
    for (size_t i = 0; i < r->n; i++) {
        uint64_t a = r->addr[i];
        if (!(blen && a >= bstart && a + (uint64_t)size <= bstart + blen)) {
            bstart = a;
            blen = mem_read(a, blk, sizeof blk);
            if (blen < (size_t)size) { blen = 0; continue; }       /* gone: drop it */
        }
        const uint8_t *cur = blk + (a - bstart);
        if (match(t, m, cur, r->prev + i * MEM_PREV, v, size)) {
            r->addr[k] = a;
            memset(r->prev + k * MEM_PREV, 0, MEM_PREV);
            memcpy(r->prev + k * MEM_PREV, cur, (size_t)(size < MEM_PREV ? size : MEM_PREV));
            k++;
        }
        if (mem_progress && (i & 0xFFFF) == 0) mem_progress(i, r->n);
    }
    r->n = k;
    r->overflow = false;
    return true;
}
