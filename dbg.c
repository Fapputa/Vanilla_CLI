/* Minimal ptrace debugger for the F9 view.
 *
 * Done here: dbg_launch (fork + PTRACE_TRACEME + execv, stopped at the
 * exec), dbg_attach (PTRACE_ATTACH to a running process), dbg_detach,
 * dbg_kill, dbg_state, dbg_stop_reason, dbg_pid, dbg_status,
 * dbg_get_regs, dbg_cont, dbg_step, dbg_run_to, dbg_interrupt, dbg_poll,
 * dbg_ui_timeout, the breakpoints, the load base (dbg_load_delta,
 * dbg_to_rt, dbg_to_file).
 *
 * Load base: right after the stop of dbg_launch / dbg_attach, load_base()
 * takes the first line of /proc/pid/maps whose path is the program
 * (readlink /proc/pid/exe) and lines its start up with the PT_LOAD that
 * holds that file offset: g_base_addr = process address - file address
 * (for a PIE linked at 0, the start of that mapping). An ET_EXEC is not
 * moved: 0. No such line: AT_ENTRY of /proc/pid/auxv - e_entry of the
 * ELF file. The ELF header comes from /proc/pid/exe (the path launched
 * as a fallback). Nothing works: 0, as before. g_img_lo / g_img_hi are
 * the file addresses of the image (the PT_LOAD span, page-rounded):
 * dbg_to_file refuses anything else (libc, stack, heap...).
 *
 * Breakpoints: g_bp is the sorted list of file addresses the user set
 * (kept as file addresses: the base changes at each launch). to_rt()
 * turns them into process addresses where the bytes are touched. The
 * int3 bytes are written (PEEKTEXT / POKETEXT, one byte inside the
 * aligned word) just before a dbg_cont / dbg_run_to resume and taken out
 * again at every reported stop (set_stopped), so a stopped process
 * always shows its original code. g_ins records what is in memory now.
 * A hit (SIGTRAP, si_code SI_KERNEL, rip - 1 in g_ins) moves rip back
 * to the breakpoint. Resuming from an address that has a breakpoint
 * first single-steps over it with nothing written, then writes them all
 * and continues (g_stepover, in on_status). dbg_step writes none: one
 * instruction cannot reach another breakpoint. The temporary breakpoint
 * of dbg_run_to only stops when rsp >= its value at the call (a deeper
 * frame steps over it and goes on); any reported stop ends it. A second
 * exec forgets the bytes written in the old image and turns the user
 * breakpoints off until the next launch / attach (and dbg_to_file off:
 * the file shown is not what runs any more).
 *
 * Resume (dbg_cont / dbg_step): the signal of the last stop, if any, is
 * delivered, then settle() polls waitpid(WNOHANG) for DBG_SETTLE_MS at
 * most. dbg_interrupt sends SIGSTOP and waits DBG_INTR_MS at most (a
 * process in uninterruptible sleep stays DBG_RUNNING). When another
 * signal stops it before that SIGSTOP, the stop is reported as that
 * signal and the SIGSTOP, still pending, is swallowed when it comes.
 * Same for a step blocked in a syscall: the SIGSTOP ends the syscall,
 * the step trap (synchronous) is reported first, so dbg_interrupt
 * returns stopped with DBG_STOP_STEP.
 *
 * Detach: a process taken with dbg_attach is given back running
 * (PTRACE_DETACH), a signal that stopped it is delivered then. A process
 * started by dbg_launch is killed and reaped instead: it is a child of
 * Abyss, stopped before its dynamic loader, with its stdio on a terminal
 * only Abyss reads, so letting it go would only leave a zombie behind.
 *
 * Console: the debuggee gets its own session (setsid) whose controlling
 * terminal is a pseudo-terminal (g_con: master side, non-blocking, opened
 * before the fork): stdin / stdout / stderr. It stays open after the exit
 * (what is left of the output can still be read) and closes at the next
 * launch, kill or detach. Without a pty (posix_openpt failed): /dev/null,
 * as before. A refused attach explains kernel.yama.ptrace_scope. Calls stay short: the only blocking waits
 * are for the stop that follows an attach or an exec. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "dbg.h"
#include <stdio.h>
#include <string.h>

#if defined(__linux__) && defined(__x86_64__)
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <limits.h>
#include <elf.h>
#include <sys/ioctl.h>
#include <termios.h>
#define DBG_OK 1
#endif

static DbgState g_state   = DBG_NONE;
static DbgStop  g_stop    = DBG_STOP_NONE;
static int      g_pid     = 0;
static bool     g_ours    = false;     /* started by dbg_launch (our child)    */
static int      g_sig     = 0;         /* signal to deliver on the next resume */
static bool     g_fault_ok = false;    /* g_fault: address a SIGSEGV / SIGBUS faulted on */
static uint64_t g_fault   = 0;
static int      g_wstatus = 0;         /* waitpid status of the exit           */
static int      g_lastpid = 0;         /* pid shown once the debuggee is gone  */
static int      g_con     = -1;        /* pty master of its console, -1: none  */

/* load base (see the top of the file) */
static uint64_t g_base_addr = 0;       /* process addr - file addr (0: non-PIE) */
static uint64_t g_img_lo = 0;          /* file addresses of the image,          */
static uint64_t g_img_hi = 0;          /* [lo, hi); hi 0: unknown               */

/* breakpoints (see the top of the file) */
static uint64_t g_bp[DBG_MAX_BP];      /* file addresses, ascending            */
static int      g_nbp = 0;
static int      g_nins = 0;            /* int3 bytes in memory now (g_ins)     */
static bool     g_bp_off = false;      /* a second exec: user bps not written  */
static bool     g_tmp_on = false;      /* dbg_run_to in progress               */
static uint64_t g_stop_rip = 0;        /* rip at the last reported stop        */
#if defined(__linux__) && defined(__x86_64__)
static uint64_t g_ins[DBG_MAX_BP + 1]; /* int3 written there (process addr)    */
static uint8_t  g_orig[DBG_MAX_BP + 1];/* the byte it replaced                 */
static uint64_t g_tmp = 0;             /* dbg_run_to: its file address         */
static uint64_t g_tmp_rsp = 0;         /* rsp when it was asked                */
#endif

static int bp_index(uint64_t file_addr) {
    int lo = 0, hi = g_nbp;
    while (lo < hi) {
        int mid = (lo + hi) / 2;
        if (g_bp[mid] < file_addr) lo = mid + 1; else hi = mid;
    }
    return lo;                          /* insertion point */
}

static bool bp_find(uint64_t file_addr) {
    int i = bp_index(file_addr);
    return i < g_nbp && g_bp[i] == file_addr;
}

static void reset(void) {
#ifdef DBG_OK
    if (g_con >= 0) close(g_con);
#endif
    g_con = -1;
    g_state = DBG_NONE;
    g_stop = DBG_STOP_NONE;
    g_pid = 0;
    g_ours = false;
    g_sig = 0;
    g_fault_ok = false;
    g_wstatus = 0;
    g_nins = 0;                        /* the process they were in is gone */
    g_bp_off = false;
    g_tmp_on = false;
    g_base_addr = 0;
    g_img_lo = g_img_hi = 0;
}

#ifdef DBG_OK

static bool g_stepping = false;        /* last resume was PTRACE_SINGLESTEP     */
static bool g_stepover = false;        /* that step only gets past a breakpoint */
static int  g_swallow  = 0;            /* pid with a SIGSTOP of ours pending    */
static bool g_intr     = false;        /* dbg_interrupt waits for that SIGSTOP  */

static bool read_small(const char *path, char *buf, size_t sz) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    size_t n = fread(buf, 1, sz - 1, f);
    fclose(f);
    buf[n] = '\0';
    return n > 0;
}

/* TracerPid from /proc/pid/status (0: none or unknown) */
static int tracer_of(int pid) {
    char path[64], buf[4096];
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    if (!read_small(path, buf, sizeof buf)) return 0;
    const char *t = strstr(buf, "\nTracerPid:");
    return t ? atoi(t + 11) : 0;
}

static pid_t wait_pid(pid_t pid, int *st, int flags) {
    pid_t r;
    do r = waitpid(pid, st, flags | __WALL); while (r < 0 && errno == EINTR);
    return r;
}

/* Waits for the SIGSTOP we sent (PTRACE_ATTACH or kill); other signals
 * that stop the tracee first are passed on to it. false: it died (*st
 * says how) or waitpid / ptrace failed (*st = 0, errno set). */
static bool wait_sigstop(pid_t pid, int *st) {
    for (;;) {
        *st = 0;
        if (wait_pid(pid, st, 0) != pid) { *st = 0; return false; }
        if (WIFEXITED(*st) || WIFSIGNALED(*st)) return false;
        if (!WIFSTOPPED(*st)) continue;
        int sig = WSTOPSIG(*st);
        if (sig == SIGSTOP) return true;
        if (ptrace(PTRACE_CONT, pid, NULL, (void *)(long)sig) < 0) { *st = 0; return false; }
    }
}

static void note_exit(int st) {
    g_wstatus = st;
    g_state = DBG_EXITED;
    g_stop = DBG_STOP_NONE;
    g_lastpid = g_pid;
    g_pid = 0;
    g_ours = false;
    g_sig = 0;
    g_nins = 0;
    g_tmp_on = false;
}

/* ---- load base ---- */

#define DBG_MAX_PHDR 64

typedef struct {
    uint16_t   type;                   /* ET_EXEC, ET_DYN...                   */
    uint64_t   entry;
    int        nph;
    Elf64_Phdr ph[DBG_MAX_PHDR];
} ElfInfo;

static bool elf_read(const char *file, ElfInfo *e) {
    int fd = open(file, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    Elf64_Ehdr h;
    bool ok = pread(fd, &h, sizeof h, 0) == (ssize_t)sizeof h
           && memcmp(h.e_ident, ELFMAG, SELFMAG) == 0
           && h.e_ident[EI_CLASS] == ELFCLASS64
           && h.e_phentsize == sizeof(Elf64_Phdr);
    if (ok) {
        e->type = h.e_type;
        e->entry = h.e_entry;
        e->nph = h.e_phnum < DBG_MAX_PHDR ? h.e_phnum : DBG_MAX_PHDR;
        size_t len = (size_t)e->nph * sizeof(Elf64_Phdr);
        ok = pread(fd, e->ph, len, (off_t)h.e_phoff) == (ssize_t)len;
    }
    close(fd);
    return ok;
}

/* AT_ENTRY of the process (0: unknown) */
static uint64_t auxv_entry(int pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/auxv", pid);
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    uint64_t kv[2], entry = 0;
    while (fread(kv, sizeof kv, 1, f) == 1 && kv[0] != AT_NULL)
        if (kv[0] == AT_ENTRY) { entry = kv[1]; break; }
    fclose(f);
    return entry;
}

/* First line of /proc/pid/maps mapping `exe`: its start and file offset */
static bool maps_first(int pid, const char *exe, uint64_t *start, uint64_t *off) {
    char path[64], line[PATH_MAX + 128];
    snprintf(path, sizeof path, "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return false;
    bool found = false;
    while (!found && fgets(line, sizeof line, f)) {
        unsigned long long lo, hi, o;
        char perm[8];
        int n = 0;
        if (sscanf(line, "%llx-%llx %7s %llx %*s %*s %n", &lo, &hi, perm, &o, &n) < 4 || n == 0)
            continue;
        char *p = line + n;
        p[strcspn(p, "\n")] = '\0';
        if (strcmp(p, exe) == 0) { *start = lo; *off = o; found = true; }
    }
    fclose(f);
    return found;
}

/* Sets g_base_addr / g_img_lo / g_img_hi for the stopped debuggee g_pid.
 * `path`: the program launched (NULL for an attach). */
static void load_base(const char *path) {
    uint64_t pg = (uint64_t)sysconf(_SC_PAGESIZE);
    if (pg == 0 || (pg & (pg - 1))) pg = 4096;
    char link[64], exe[PATH_MAX];
    snprintf(link, sizeof link, "/proc/%d/exe", g_pid);
    ssize_t n = readlink(link, exe, sizeof exe - 1);
    if (n > 0) exe[n] = '\0';
    else if (!path || !realpath(path, exe)) exe[0] = '\0';

    static ElfInfo e;                       /* ~3.6 KB: off the stack */
    bool elf = elf_read(link, &e) || (path && elf_read(path, &e));
    uint64_t lo = UINT64_MAX, hi = 0;
    if (elf)
        for (int i = 0; i < e.nph; i++) {
            if (e.ph[i].p_type != PT_LOAD) continue;
            uint64_t a = e.ph[i].p_vaddr & ~(pg - 1);
            uint64_t z = (e.ph[i].p_vaddr + e.ph[i].p_memsz + pg - 1) & ~(pg - 1);
            if (a < lo) lo = a;
            if (z > hi) hi = z;
        }
    if (hi > lo) { g_img_lo = lo; g_img_hi = hi; }
    g_base_addr = 0;
    if (elf && e.type == ET_EXEC) return;   /* not moved */

    uint64_t start, off;
    if (exe[0] && maps_first(g_pid, exe, &start, &off)) {
        if (elf) {
            for (int i = 0; i < e.nph; i++)
                if (e.ph[i].p_type == PT_LOAD && (e.ph[i].p_offset & ~(pg - 1)) == off) {
                    g_base_addr = start - (e.ph[i].p_vaddr & ~(pg - 1));
                    return;
                }
            if (g_img_hi && off == 0) { g_base_addr = start - g_img_lo; return; }
        } else if (off == 0) {
            g_base_addr = start;            /* PIE linked at 0, the usual case */
            return;
        }
    }
    uint64_t at = auxv_entry(g_pid);        /* fallback */
    if (elf && at) g_base_addr = at - e.entry;
}

#endif /* DBG_OK */

bool dbg_attach(int pid, char *err, size_t esz) {
    err[0] = '\0';
#ifndef DBG_OK
    (void)pid;
#ifdef _WIN32
    snprintf(err, esz, "débogueur indisponible sous Windows");
#else
    snprintf(err, esz, "Linux x86-64 uniquement");
#endif
    return false;
#else
    if (pid <= 0) { snprintf(err, esz, "Invalid pid %d", pid); return false; }
    if (pid == (int)getpid()) { snprintf(err, esz, "Cannot debug Abyss itself"); return false; }
    if (pid == g_pid && g_state == DBG_STOPPED) return true;      /* already ours */
    dbg_detach();

    if (ptrace(PTRACE_ATTACH, (pid_t)pid, NULL, NULL) < 0) {
        int why = errno;
        int tr = why == EPERM ? tracer_of(pid) : 0;
        if (why == ESRCH)
            snprintf(err, esz, "No process %d", pid);
        else if (tr > 0)
            snprintf(err, esz, "Process %d is already traced by pid %d", pid, tr);
        else if (why == EPERM) {
            char scope[16] = "?";
            read_small("/proc/sys/kernel/yama/ptrace_scope", scope, sizeof scope);
            scope[strcspn(scope, "\n")] = '\0';
            snprintf(err, esz,
                     "Permission denied (ptrace_scope=%s): launch it from Abyss, "
                     "run Abyss with sudo, or: sudo sysctl kernel.yama.ptrace_scope=0", scope);
        } else
            snprintf(err, esz, "ptrace(ATTACH, %d): %s", pid, strerror(why));
        return false;
    }

    int st;
    if (!wait_sigstop((pid_t)pid, &st)) {
        if (WIFEXITED(st) || WIFSIGNALED(st))
            snprintf(err, esz, "Process %d exited while attaching", pid);
        else {
            snprintf(err, esz, "Process %d: no stop after the attach (%s)", pid, strerror(errno));
            ptrace(PTRACE_DETACH, (pid_t)pid, NULL, NULL);
        }
        return false;
    }

    reset();
    g_pid = g_lastpid = pid;
    g_ours = false;
    g_state = DBG_STOPPED;
    g_stop = DBG_STOP_INTERRUPT;           /* our SIGSTOP: not re-delivered */
    load_base(NULL);
    return true;
#endif
}

#ifdef DBG_OK
static void bp_remove_all(void);
#endif

void dbg_detach(void) {
#ifdef DBG_OK
    /* an attached process goes on running: stop it the usual way first,
     * which takes the int3 bytes out (and puts rip back on a hit) */
    if (!g_ours && g_pid > 0 && g_state == DBG_RUNNING) dbg_interrupt();
    if (g_pid > 0 && (g_state == DBG_STOPPED || g_state == DBG_RUNNING)) {
        pid_t pid = (pid_t)g_pid;
        int st;
        if (g_ours) {
            kill(pid, SIGKILL);
            wait_pid(pid, &st, 0);
        } else {
            if (g_state == DBG_RUNNING) {
                /* PTRACE_DETACH needs a stopped tracee */
                if (g_swallow != g_pid) kill(pid, SIGSTOP);  /* else on its way */
                if (!wait_sigstop(pid, &st)) { reset(); return; }
                g_swallow = 0;
                g_sig = 0;                      /* that SIGSTOP is ours */
                bp_remove_all();
            }
            if (ptrace(PTRACE_DETACH, pid, NULL, (void *)(long)g_sig) < 0 && errno == ESRCH)
                wait_pid(pid, &st, WNOHANG);             /* died meanwhile */
        }
    }
#endif
    reset();
}

bool dbg_launch(const char *path, char *const argv[], char *err, size_t esz) {
    err[0] = '\0';
#ifndef DBG_OK
    (void)path; (void)argv;
#ifdef _WIN32
    snprintf(err, esz, "débogueur indisponible sous Windows");
#else
    snprintf(err, esz, "Linux x86-64 uniquement");
#endif
    return false;
#else
    if (!path || !*path) { snprintf(err, esz, "No program"); return false; }
    dbg_detach();

    /* console: a pty (name taken here, ptsname is not async-signal-safe) */
    char slave[128] = "";
    int mfd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (mfd >= 0 && (grantpt(mfd) < 0 || unlockpt(mfd) < 0 || ptsname_r(mfd, slave, sizeof slave) != 0)) {
        close(mfd);
        mfd = -1;
    }
    if (mfd >= 0) {
        struct winsize ws = { .ws_row = 24, .ws_col = 80 };
        ioctl(mfd, TIOCSWINSZ, &ws);
        fcntl(mfd, F_SETFL, fcntl(mfd, F_GETFL) | O_NONBLOCK);
    }

    /* everything the child needs is ready before the fork: between fork
     * and exec it only makes async-signal-safe calls */
    char *dflt[2] = { (char *)path, NULL };
    char *const *av = argv ? argv : dflt;
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) < 0) {
        snprintf(err, esz, "pipe: %s", strerror(errno));
        if (mfd >= 0) close(mfd);
        return false;
    }

    pid_t pid = fork();
    if (pid < 0) {
        snprintf(err, esz, "fork failed: %s", strerror(errno));
        close(fds[0]); close(fds[1]);
        if (mfd >= 0) close(mfd);
        return false;
    }
    if (pid == 0) {
        close(fds[0]);
        setsid();                          /* the pty opened next becomes its terminal */
        int t = slave[0] ? open(slave, O_RDWR) : -1;
        if (t < 0) t = open("/dev/null", O_RDWR);
        if (t >= 0) { dup2(t, 0); dup2(t, 1); dup2(t, 2); if (t > 2) close(t); }
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0) execv(path, av);
        int e = errno;                     /* exec failed: tell the parent why */
        ssize_t w = write(fds[1], &e, sizeof e);
        (void)w;
        _exit(127);
    }
    close(fds[1]);

    /* the pipe closes on a successful exec (O_CLOEXEC), or brings errno */
    int cerr = 0;
    ssize_t n;
    do n = read(fds[0], &cerr, sizeof cerr); while (n < 0 && errno == EINTR);
    close(fds[0]);

    int st;
    if (wait_pid(pid, &st, 0) != pid) {
        snprintf(err, esz, "waitpid: %s", strerror(errno));
        kill(pid, SIGKILL);
        wait_pid(pid, &st, 0);
        if (mfd >= 0) close(mfd);
        return false;
    }
    if (n == (ssize_t)sizeof cerr) {
        snprintf(err, esz, "Cannot run %.200s: %s", path, strerror(cerr));
        if (WIFSTOPPED(st)) { kill(pid, SIGKILL); wait_pid(pid, &st, 0); }
        if (mfd >= 0) close(mfd);
        return false;
    }
    if (WIFEXITED(st) || WIFSIGNALED(st)) {
        snprintf(err, esz, "%.200s exited right away", path);
        if (mfd >= 0) close(mfd);
        return false;
    }
    if (!WIFSTOPPED(st) || WSTOPSIG(st) != SIGTRAP) {
        snprintf(err, esz, "Unexpected stop after exec (signal %d)",
                 WIFSTOPPED(st) ? WSTOPSIG(st) : -1);
        kill(pid, SIGKILL);
        wait_pid(pid, &st, 0);
        if (mfd >= 0) close(mfd);
        return false;
    }
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)(long)PTRACE_O_EXITKILL) < 0) {
        snprintf(err, esz, "ptrace(SETOPTIONS): %s", strerror(errno));
        kill(pid, SIGKILL);
        wait_pid(pid, &st, 0);
        if (mfd >= 0) close(mfd);
        return false;
    }

    reset();
    g_con = mfd;
    g_pid = g_lastpid = (int)pid;
    g_ours = true;
    g_state = DBG_STOPPED;
    g_stop = DBG_STOP_EXEC;                /* its SIGTRAP is not re-delivered */
    load_base(path);
    return true;
#endif
}

DbgState dbg_state(void) {
#ifdef DBG_OK
    /* a stopped tracee can still be SIGKILLed from outside: notice it.
     * (While it runs, its stops are dbg_poll's to collect.) */
    if (g_state == DBG_STOPPED && g_pid > 0) {
        int st;
        if (wait_pid((pid_t)g_pid, &st, WNOHANG) == g_pid && (WIFEXITED(st) || WIFSIGNALED(st)))
            note_exit(st);
    }
#endif
    return g_state;
}

void dbg_status(char *out, size_t sz) {
    if (!out || sz == 0) return;
    switch (dbg_state()) {
    case DBG_NONE:
        snprintf(out, sz, "no debuggee");
        break;
    case DBG_RUNNING:
        snprintf(out, sz, "running (pid %d)", g_pid);
        break;
    case DBG_EXITED:
#ifdef DBG_OK
        if (WIFEXITED(g_wstatus))
            snprintf(out, sz, "exited with code %d", WEXITSTATUS(g_wstatus));
        else if (WIFSIGNALED(g_wstatus)) {
            int s = WTERMSIG(g_wstatus);
            const char *name = strsignal(s);
            snprintf(out, sz, "killed by signal %d (%s)", s, name ? name : "?");
        } else
#endif
            snprintf(out, sz, "exited (pid %d)", g_lastpid);
        break;
    case DBG_STOPPED:
        switch (g_stop) {
        case DBG_STOP_EXEC:
            snprintf(out, sz, "stopped at exec (pid %d)", g_pid);
            break;
        case DBG_STOP_INTERRUPT:
            snprintf(out, sz, g_ours ? "interrupted (pid %d)" : "attached, stopped (pid %d)", g_pid);
            break;
        case DBG_STOP_SIGNAL: {
#ifdef DBG_OK
            const char *name = strsignal(g_sig);
#else
            const char *name = NULL;
#endif
            char at[48] = "";
            if (g_fault_ok) snprintf(at, sizeof at, ", address 0x%llx", (unsigned long long)g_fault);
            snprintf(out, sz, "stopped by signal %d (%s%s) (pid %d)", g_sig, name ? name : "?", at, g_pid);
            break;
        }
        case DBG_STOP_BP:
            snprintf(out, sz, "breakpoint at 0x%llx (pid %d)", (unsigned long long)g_stop_rip, g_pid);
            break;
        case DBG_STOP_TEMP:
            snprintf(out, sz, "reached 0x%llx (pid %d)", (unsigned long long)g_stop_rip, g_pid);
            break;
        case DBG_STOP_STEP:
            snprintf(out, sz, "stepped to 0x%llx (pid %d)", (unsigned long long)g_stop_rip, g_pid);
            break;
        default:
            snprintf(out, sz, "stopped (pid %d)", g_pid);
            break;
        }
        break;
    }
}

/* ---- registers, resume, interrupt -------------------------------------- */

#define DBG_POLL_MS  50        /* wgetch timeout while the debuggee runs     */
#define DBG_INTR_MS  1000      /* dbg_interrupt: longest wait for the SIGSTOP */
/* a wait status that is neither WIFEXITED nor WIFSIGNALED: dbg_status
 * shows "exited (pid n)" for a debuggee reaped by someone else */
#define ST_UNKNOWN   0xffff

#ifdef DBG_OK

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool resume(int sig) {
    return ptrace(g_stepping ? PTRACE_SINGLESTEP : PTRACE_CONT, (pid_t)g_pid,
                  NULL, (void *)(long)sig) == 0;
}

/* ---- breakpoint bytes ---- */

/* file address -> process address */
static uint64_t to_rt(uint64_t file_addr) { return file_addr + g_base_addr; }

/* Writes byte `b` at process address `at` through the aligned word that
 * holds it (it cannot cross into an unmapped page); *old gets the byte
 * that was there. */
static bool poke_byte(uint64_t at, uint8_t b, uint8_t *old) {
    uint64_t base = at & ~(uint64_t)7;
    unsigned sh = (unsigned)(at & 7) * 8;
    errno = 0;
    long w = ptrace(PTRACE_PEEKTEXT, (pid_t)g_pid, (void *)base, NULL);
    if (errno) return false;
    uint64_t v = (uint64_t)w;
    if (old) *old = (uint8_t)(v >> sh);
    v = (v & ~((uint64_t)0xff << sh)) | ((uint64_t)b << sh);
    return ptrace(PTRACE_POKETEXT, (pid_t)g_pid, (void *)base, (void *)v) == 0;
}

static int ins_index(uint64_t at) {
    for (int i = 0; i < g_nins; i++) if (g_ins[i] == at) return i;
    return -1;
}

static void ins_one(uint64_t at) {
    if (ins_index(at) >= 0) return;     /* run_to on a user breakpoint */
    uint8_t old;
    if (poke_byte(at, 0xCC, &old)) {    /* unmapped (set without a debuggee): skipped */
        g_ins[g_nins] = at;
        g_orig[g_nins] = old;
        g_nins++;
    }
}

/* writes the int3 of every breakpoint, the stopped process about to go on */
static void bp_insert_all(void) {
    if (!g_bp_off)
        for (int i = 0; i < g_nbp; i++) ins_one(to_rt(g_bp[i]));
    if (g_tmp_on) ins_one(to_rt(g_tmp));
}

/* puts the original bytes back (each one only touches its own byte, so
 * breakpoints that share a word come out in any order) */
static void bp_remove_all(void) {
    for (int i = g_nins; i-- > 0; ) poke_byte(g_ins[i], g_orig[i], NULL);
    g_nins = 0;
}

/* Every stop reported to the caller comes here: the int3 bytes go out,
 * a dbg_run_to is over, rip is kept for dbg_status. */
static void set_stopped(DbgStop why, int sig) {
    bp_remove_all();
    g_tmp_on = false;
    g_stepover = false;
    g_state = DBG_STOPPED;
    g_stop = why;
    g_sig = sig;
    g_fault_ok = false;
    struct user_regs_struct u;
    g_stop_rip = ptrace(PTRACE_GETREGS, (pid_t)g_pid, NULL, &u) == 0 ? u.rip : 0;
}

/* An int3 trap: one of ours? Then rip goes back onto it and the stop is
 * reported, or, for the dbg_run_to target reached in a deeper frame, the
 * process steps over it and goes on. false: not ours. */
static bool bp_hit(void) {
    struct user_regs_struct u;
    if (ptrace(PTRACE_GETREGS, (pid_t)g_pid, NULL, &u) < 0) return false;
    uint64_t at = u.rip - 1;
    if (ins_index(at) < 0) return false;
    u.rip = at;
    if (ptrace(PTRACE_SETREGS, (pid_t)g_pid, NULL, &u) < 0) return false;
    if (g_tmp_on && to_rt(g_tmp) == at && u.rsp >= g_tmp_rsp) {
        set_stopped(DBG_STOP_TEMP, 0);
        return true;
    }
    if (!g_bp_off && bp_find(at - g_base_addr)) {
        set_stopped(DBG_STOP_BP, 0);
        return true;
    }
    bp_remove_all();                    /* a recursive call: not this frame */
    g_stepping = g_stepover = true;
    if (!resume(0)) set_stopped(DBG_STOP_TEMP, 0);
    return true;
}

/* One waitpid status of the running debuggee. true: it is not running
 * any more (stopped or gone). */
static bool on_status(int st) {
    if (WIFEXITED(st) || WIFSIGNALED(st)) { note_exit(st); return true; }
    if (!WIFSTOPPED(st)) return false;
    int sig = WSTOPSIG(st);
    siginfo_t si;
    /* fails (EINVAL) on a group-stop: a stop signal already delivered */
    bool has_si = ptrace(PTRACE_GETSIGINFO, (pid_t)g_pid, NULL, &si) == 0;

    if (sig == SIGSTOP && has_si && g_swallow == g_pid) {      /* ours */
        g_swallow = 0;
        if (!g_intr && resume(0)) return false;               /* left over */
        set_stopped(DBG_STOP_INTERRUPT, 0);
        return true;
    }
    if (sig == SIGTRAP && g_stepping && g_stepover) {
        /* past the breakpoint it resumed on: write them all, go on */
        g_stepping = g_stepover = false;
        bp_insert_all();
        if (resume(0)) return false;
        set_stopped(DBG_STOP_STEP, 0);
        return true;
    }
    if (sig == SIGTRAP && g_stepping) {
        set_stopped(DBG_STOP_STEP, 0);
        return true;
    }
    if (sig == SIGTRAP && has_si && si.si_code == SI_KERNEL && g_nins > 0 && bp_hit())
        return g_state != DBG_RUNNING;
    if (sig == SIGTRAP && has_si && si.si_code == SI_USER && si.si_pid == g_pid) {
        g_nins = 0;                             /* trap of a second exec: */
        g_bp_off = true;                        /* the old image is gone  */
        g_img_lo = g_img_hi = 0;
        set_stopped(DBG_STOP_EXEC, 0);
        return true;
    }
    set_stopped(DBG_STOP_SIGNAL, sig);          /* delivered on the next resume */
    if (has_si && (sig == SIGSEGV || sig == SIGBUS) && si.si_code > 0) {   /* sent by the kernel */
        g_fault = (uint64_t)(uintptr_t)si.si_addr;
        g_fault_ok = true;
    }
    return true;
}

/* Collects the stop of the running debuggee, waiting `ms` at most
 * (0: only what is already there). */
static void settle(int ms) {
    long long end = mono_ms() + ms;
    long ns = 50000;                            /* 50 us, doubled up to 2 ms */
    while (g_state == DBG_RUNNING) {
        int st;
        pid_t r = wait_pid((pid_t)g_pid, &st, WNOHANG);
        if (r == (pid_t)g_pid) { on_status(st); continue; }
        if (r < 0) { note_exit(ST_UNKNOWN); return; }       /* ECHILD: gone */
        if (mono_ms() >= end) return;
        struct timespec ts = { 0, ns };
        nanosleep(&ts, NULL);
        if (ns < 2000000) ns *= 2;
    }
}

static bool need_stopped(char *err, size_t esz) {
    switch (dbg_state()) {
    case DBG_STOPPED: return true;
    case DBG_RUNNING: snprintf(err, esz, "The program is running (interrupt it first)"); break;
    case DBG_EXITED:  snprintf(err, esz, "The program has exited"); break;
    default:          snprintf(err, esz, "No program to debug"); break;
    }
    return false;
}

/* true when rip is on a breakpoint (user or run_to target) */
static bool on_bp(void) {
    struct user_regs_struct u;
    if (ptrace(PTRACE_GETREGS, (pid_t)g_pid, NULL, &u) < 0) return false;
    if (g_tmp_on && to_rt(g_tmp) == u.rip) return true;
    if (g_bp_off) return false;
    for (int i = 0; i < g_nbp; i++) if (to_rt(g_bp[i]) == u.rip) return true;
    return false;
}

static bool start(bool step, char *err, size_t esz) {
    if (!need_stopped(err, esz)) return false;
    g_stepping = step;
    g_stepover = false;
    if (!step) {
        if (on_bp()) g_stepping = g_stepover = true;   /* step past it first */
        else bp_insert_all();
    }
    if (!resume(g_sig)) {
        int e = errno;
        bp_remove_all();
        snprintf(err, esz, "ptrace(%s): %s", g_stepping ? "SINGLESTEP" : "CONT", strerror(e));
        g_stepover = false;
        dbg_state();                            /* killed from outside? */
        return false;
    }
    g_state = DBG_RUNNING;
    g_stop = DBG_STOP_NONE;
    g_sig = 0;
    settle(DBG_SETTLE_MS);
    return true;
}

#endif /* DBG_OK */

bool dbg_get_regs(DbgRegs *r) {
#ifndef DBG_OK
    (void)r;
    return false;
#else
    if (!r || dbg_state() != DBG_STOPPED) return false;
    struct user_regs_struct u;
    if (ptrace(PTRACE_GETREGS, (pid_t)g_pid, NULL, &u) < 0) return false;
    r->rip = u.rip;  r->rsp = u.rsp;  r->rbp = u.rbp;
    r->rax = u.rax;  r->rbx = u.rbx;  r->rcx = u.rcx;  r->rdx = u.rdx;
    r->rsi = u.rsi;  r->rdi = u.rdi;  r->rflags = u.eflags;
    return true;
#endif
}

bool dbg_cont(char *err, size_t esz) {
    err[0] = '\0';
#ifndef DBG_OK
#ifdef _WIN32
    snprintf(err, esz, "débogueur indisponible sous Windows");
#else
    snprintf(err, esz, "Linux x86-64 uniquement");
#endif
    return false;
#else
    return start(false, err, esz);
#endif
}

bool dbg_step(char *err, size_t esz) {
    err[0] = '\0';
#ifndef DBG_OK
#ifdef _WIN32
    snprintf(err, esz, "débogueur indisponible sous Windows");
#else
    snprintf(err, esz, "Linux x86-64 uniquement");
#endif
    return false;
#else
    return start(true, err, esz);
#endif
}

/* true when the debuggee is stopped on return */
bool dbg_interrupt(void) {
#ifndef DBG_OK
    return false;
#else
    if (dbg_state() == DBG_STOPPED) return true;
    if (g_state != DBG_RUNNING) return false;
    settle(0);                                  /* a stop already waiting */
    if (g_state != DBG_RUNNING) return g_state == DBG_STOPPED;
    if (g_swallow != g_pid) {                   /* not one still on its way */
        if (kill((pid_t)g_pid, SIGSTOP) < 0) { settle(0); return g_state == DBG_STOPPED; }
        g_swallow = g_pid;
    }
    g_intr = true;
    settle(DBG_INTR_MS);
    g_intr = false;
    return g_state == DBG_STOPPED;
#endif
}

int dbg_ui_timeout(void) {
    return g_state == DBG_RUNNING ? DBG_POLL_MS : -1;
}

/* ---- kill, stop reason, pid, poll -------------------------------------- */

#ifndef DBG_OK
static void unavailable(char *err, size_t esz) {
#ifdef _WIN32
    snprintf(err, esz, "débogueur indisponible sous Windows");
#else
    snprintf(err, esz, "Linux x86-64 uniquement");
#endif
}
#endif

void dbg_kill(void) {
#ifdef DBG_OK
    if (g_pid > 0 && (g_state == DBG_STOPPED || g_state == DBG_RUNNING)) {
        /* a tracer is told of its tracee's death even when it is not its
         * parent: waitpid reaps ours and collects an attached one */
        int st;
        kill((pid_t)g_pid, SIGKILL);
        wait_pid((pid_t)g_pid, &st, 0);
    }
    g_swallow = 0;
#endif
    reset();
}

DbgStop dbg_stop_reason(void) {
    return dbg_state() == DBG_STOPPED ? g_stop : DBG_STOP_NONE;
}

int dbg_pid(void) {
    DbgState s = dbg_state();
    return s == DBG_STOPPED || s == DBG_RUNNING ? g_pid : 0;
}

bool dbg_poll(void) {
#ifndef DBG_OK
    return false;
#else
    DbgState before = g_state;
    if (g_state == DBG_RUNNING) settle(0);
    else dbg_state();                           /* killed while stopped */
    return g_state != before;
#endif
}

/* ---- breakpoints, run to ----------------------------------------------- */

#ifdef DBG_OK
/* `at` (process address) must be in an executable mapping of the
 * stopped debuggee */
static bool check_code(uint64_t file_addr, char *err, size_t esz) {
    uint64_t at = to_rt(file_addr);
    char path[64], line[512];
    snprintf(path, sizeof path, "/proc/%d/maps", g_pid);
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(err, esz, "%s: %s", path, strerror(errno)); return false; }
    bool found = false, exec = false;
    while (!found && fgets(line, sizeof line, f)) {
        unsigned long long lo, hi;
        char perm[8];
        if (sscanf(line, "%llx-%llx %7s", &lo, &hi, perm) != 3) continue;
        if (at >= lo && at < hi) { found = true; exec = perm[2] == 'x'; }
    }
    fclose(f);
    if (!found)
        snprintf(err, esz, "0x%llx (0x%llx in the process) is not mapped in pid %d",
                 (unsigned long long)file_addr, (unsigned long long)at, g_pid);
    else if (!exec)
        snprintf(err, esz, "0x%llx is not code (no exec permission)", (unsigned long long)file_addr);
    return found && exec;
}
#endif

bool dbg_bp_add(uint64_t addr, char *err, size_t esz) {
    err[0] = '\0';
#ifndef DBG_OK
    (void)addr;
    unavailable(err, esz);
    return false;
#else
    DbgState s = dbg_state();
    if (s == DBG_RUNNING) { snprintf(err, esz, "The program is running (interrupt it first)"); return false; }
    int i = bp_index(addr);
    if (i < g_nbp && g_bp[i] == addr) return true;            /* already there */
    if (g_nbp >= DBG_MAX_BP) { snprintf(err, esz, "Too many breakpoints (%d)", DBG_MAX_BP); return false; }
    if (s == DBG_STOPPED && !check_code(addr, err, esz)) return false;
    memmove(g_bp + i + 1, g_bp + i, (size_t)(g_nbp - i) * sizeof g_bp[0]);
    g_bp[i] = addr;
    g_nbp++;
    return true;
#endif
}

bool dbg_bp_remove(uint64_t addr, char *err, size_t esz) {
    err[0] = '\0';
#ifdef DBG_OK
    if (dbg_state() == DBG_RUNNING) { snprintf(err, esz, "The program is running (interrupt it first)"); return false; }
#endif
    /* nothing to restore: the bytes are out while it is stopped */
    int i = bp_index(addr);
    if (i >= g_nbp || g_bp[i] != addr) {
        snprintf(err, esz, "No breakpoint at 0x%llx", (unsigned long long)addr);
        return false;
    }
    memmove(g_bp + i, g_bp + i + 1, (size_t)(g_nbp - i - 1) * sizeof g_bp[0]);
    g_nbp--;
    return true;
}

/* ---- console ----------------------------------------------------------- */

long dbg_console_read(char *buf, size_t sz) {
#ifndef DBG_OK
    (void)buf; (void)sz;
    return -1;
#else
    if (g_con < 0) return -1;
    if (!buf || !sz) return 0;
    ssize_t n;
    do n = read(g_con, buf, sz); while (n < 0 && errno == EINTR);
    if (n >= 0) return (long)n;
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EIO ? 0 : -1;   /* EIO: no writer left */
#endif
}

long dbg_console_write(const char *buf, size_t n) {
#ifndef DBG_OK
    (void)buf; (void)n;
    return -1;
#else
    if (g_con < 0 || !(g_state == DBG_STOPPED || g_state == DBG_RUNNING)) return -1;
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(g_con, buf + done, n - done);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) break;                       /* full (EAGAIN): the rest is dropped */
        done += (size_t)w;
    }
    return (long)done;
#endif
}

bool dbg_bp_has(uint64_t addr) {
    return bp_find(addr);
}

/* copies min(n, max) addresses and returns that; out NULL: returns n */
int dbg_bp_list(uint64_t *out, int max) {
    if (!out) return g_nbp;
    int n = g_nbp < max ? g_nbp : max;
    if (n <= 0) return 0;
    memcpy(out, g_bp, (size_t)n * sizeof g_bp[0]);
    return n;
}

/* refused (does nothing) while the program runs, like dbg_bp_remove */
void dbg_bp_clear(void) {
#ifdef DBG_OK
    if (dbg_state() == DBG_RUNNING) return;
#endif
    g_nbp = 0;
}

bool dbg_run_to(uint64_t addr, char *err, size_t esz) {
    err[0] = '\0';
#ifndef DBG_OK
    (void)addr;
    unavailable(err, esz);
    return false;
#else
    if (!need_stopped(err, esz)) return false;
    if (!check_code(addr, err, esz)) return false;
    struct user_regs_struct u;
    if (ptrace(PTRACE_GETREGS, (pid_t)g_pid, NULL, &u) < 0) {
        snprintf(err, esz, "ptrace(GETREGS): %s", strerror(errno));
        return false;
    }
    g_tmp = addr;
    g_tmp_rsp = u.rsp;
    g_tmp_on = true;
    if (!start(false, err, esz)) { g_tmp_on = false; return false; }
    return true;
#endif
}

/* ---- load base -------------------------------------------------------- */

uint64_t dbg_load_delta(void) {
    return g_base_addr;
}

uint64_t dbg_to_rt(uint64_t file_addr) {
    return file_addr + g_base_addr;
}

bool dbg_to_file(uint64_t rt, uint64_t *file_addr) {
    uint64_t f = rt - g_base_addr;
    if (g_img_hi == 0 || f < g_img_lo || f >= g_img_hi) return false;
    if (file_addr) *file_addr = f;
    return true;
}
