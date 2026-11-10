/* Minimal ptrace debugger for the F9 view.
 *
 * Done here: dbg_launch (fork + PTRACE_TRACEME + execv, stopped at the
 * exec), dbg_attach (PTRACE_ATTACH to a running process), dbg_detach,
 * dbg_kill, dbg_state, dbg_stop_reason, dbg_pid, dbg_status,
 * dbg_get_regs, dbg_set_regs, dbg_cont, dbg_step, dbg_run_to,
 * dbg_interrupt, dbg_poll, dbg_ui_timeout, the breakpoints, the load base
 * (dbg_load_delta, dbg_to_rt, dbg_to_file).
 *
 * Load base: right after the stop of dbg_launch / dbg_attach, load_base()
 * takes the first line of /proc/pid/maps whose path is the program
 * (readlink /proc/pid/exe) and lines its start up with the PT_LOAD that
 * holds that file offset: g_base_addr = process address - file address
 * (for a PIE linked at 0, the start of that mapping). An ET_EXEC is not
 * moved: 0. No such line: AT_ENTRY of /proc/pid/auxv - e_entry of the
 * ELF file (ELF32 auxv: 4-byte pairs). The ELF header (ELF64 or ELF32) comes
 * from /proc/pid/exe (the path launched as a fallback). Nothing works: 0,
 * as before. g_img_lo / g_img_hi are the file addresses of the image (the
 * PT_LOAD span, page-rounded): dbg_to_file refuses anything else (libc,
 * stack, heap...). A 32-bit debuggee goes through the same 64-bit ptrace
 * calls (user_regs_struct, eip in rip, zero-extended); dbg_bits tells.
 *
 * i386 programs without a system loader (dbg_launch): when the PT_INTERP of an
 * ELF32 i386 file ends in ld-linux.so.2 and does not exist (access F_OK, or
 * ABYSS_TEST_NO_SYSTEM_INTERP=1 for the tests), the program runs under the
 * i386 loader carried by the executable itself: ld-linux.so.2, libc.so.6,
 * libm.so.6, libdl.so.2, libpthread.so.0 and librt.so.1, put in at build time
 * by ld32blob.S (Makefile, ABYSS_LD32_BLOB; Linux only). ld32_cache writes them
 * to $XDG_CACHE_HOME/abyss/i32-<tag>/ (~/.cache when XDG_CACHE_HOME is unset or
 * relative), <tag> being taken from their SHA-256, so another set of files gets
 * another directory. The directory is created 0700 (group and others lose any
 * right they have there) and must belong to the user; each
 * file is checked (regular, the user's, size, SHA-256) at every such launch and
 * a missing or different one is written again: a nameless file (O_TMPFILE),
 * synced, then given a temporary name and renamed onto the right one, so a file
 * there is always whole. Nothing is ever deleted. A directory that cannot be
 * written refuses the launch and says where. Nothing is read from a directory
 * next to the executable. A build without those files refuses too. Before anything is debugged,
 * `ld.so --library-path ... --list program` (no relocation, no code run) says
 * what it cannot find or load: a missing library is named, any other message
 * of ld.so is passed on, ENOEXEC means a kernel without 32-bit support. Then:
 * execv(<cache>/ld-linux.so.2, { it, "--library-path", "$LD_LIBRARY_PATH:<cache>",
 * ["--argv0", argv[0]] (only when argv[0] is not the path), path, argv[1]... }).
 * The environment, the current directory and the stdio are those of a direct
 * launch; --library-path stands for LD_LIBRARY_PATH (still searched first, ld.so
 * ignores the variable once the option is there), nothing is added to the
 * environment. What differs, and cannot be avoided: /proc/self/exe, AT_ENTRY,
 * AT_PHDR and AT_EXECFN of the program are those of ld.so, and a PIE lands next
 * to the libraries (ld.so maps it) instead of the kernel's place.
 * At the exec stop the program is not mapped yet: ld32_wait lets ld.so go one
 * syscall at a time (PTRACE_SYSCALL, a few dozen, no single-step) until every
 * PT_LOAD of the program is in /proc/pid/maps with its file offset and
 * permissions, on a syscall exit, before any library is loaded: that is the
 * DBG_STOP_EXEC stop. From there the program is g_target (its realpath, as maps
 * shows it), not /proc/pid/exe: load base from its first mapping, entry =
 * its e_entry + that base (the internal entry int3), dbg_to_file on its span.
 *
 * Breakpoints: the model is in dbg_bp.h (module + rva, enabled, hits,
 * condition). The int3 bytes are written (PEEKTEXT / POKETEXT, one byte
 * inside the aligned word) just before a dbg_cont / dbg_run_to resume and
 * taken out again at every reported stop (set_stopped), so a stopped
 * process always shows its original code. g_ins records what is in memory
 * now. Before writing, each address is checked against /proc/pid/maps:
 * nothing mapped, not executable or a shared mapping (a write would reach
 * the file on disk) leaves it out and tells why (DbgBp.state,
 * dbg_bp_take_news). A byte that is not 0xCC when it comes out was
 * rewritten by the program: left as it is (DbgBp.overwritten), the next
 * resume saves the new byte. A hit (SIGTRAP, si_code SI_KERNEL, rip - 1 in
 * g_ins) moves rip back to the breakpoint and counts a pass; a false
 * condition steps over and goes on without a stop. Resuming from an
 * address that has a breakpoint first single-steps over it with nothing
 * written, then writes them all and continues (g_stepover, in on_status).
 * dbg_step writes none: one instruction cannot reach another breakpoint.
 * Hardware breakpoints: DR0-DR3 (PTRACE_POKEUSER), execute length 1, only
 * armed during a resume like the int3 bytes; a hit is SIGTRAP TRAP_HWBKPT,
 * rip already on the breakpoint. A module not mapped yet stays pending: when
 * one exists at the launch an internal int3 on AT_ENTRY stops the program
 * once the dynamic loader has mapped its libraries, silently. A pass is an
 * arrival on the breakpoint, however it comes: an int3, a debug register or a
 * dbg_step landing there (one that stays on the same instruction, rep movs,
 * does not count); leaving it never counts, so a loop gives the same hits, and
 * `hits` conditions the same stops, stepped or run. The temporary breakpoint
 * of dbg_run_to only stops when rsp >= its value at the call, in the thread
 * that asked (a deeper frame or another thread steps over it and goes on);
 * any reported stop ends it. A second
 * exec forgets the bytes written in the old image and turns the user
 * breakpoints off until the next launch / attach (and dbg_to_file off:
 * the file shown is not what runs any more).
 *
 * Resume (dbg_cont / dbg_step): the signal of the last stop, if any, is
 * delivered, then settle() polls waitpid(WNOHANG) on each thread (never -1:
 * other children of Abyss are not ours) for DBG_SETTLE_MS at
 * most. dbg_interrupt sends SIGSTOP and waits DBG_INTR_MS at most (a
 * process in uninterruptible sleep stays DBG_RUNNING). When another
 * signal stops it before that SIGSTOP, the stop is reported as that
 * signal and the SIGSTOP, still pending, is swallowed when it comes.
 * Same for a step blocked in a syscall: the SIGSTOP ends the syscall,
 * the step trap (synchronous) is reported first, so dbg_interrupt
 * returns stopped with DBG_STOP_STEP.
 *
 * Threads: all of them are traced (PTRACE_O_TRACECLONE; dbg_attach takes each
 * one of /proc/pid/task) and they stop together. Whenever a thread reports
 * something the others get a SIGSTOP (stop_world), and the bytes only change
 * then: nobody can run past a breakpoint taken out for a moment. g_tid is the
 * thread of the last stop: its registers are the ones shown, dbg_step and the
 * step over a breakpoint move it alone (a step blocked on another thread waits
 * for dbg_interrupt), dbg_cont / dbg_run_to start them all. What another thread
 * met while stopping is not lost: an int3 or a debug register trap is undone
 * (rip back, RF off) and comes again at the resume, counted then; a signal is
 * kept in DbgThr.pend and reported at the next dbg_cont. A SIGSTOP of ours that
 * arrives after something else is swallowed when it comes (DbgThr.swallow). The
 * first thread can be gone while the others run (pthread_exit): it stays in the
 * list as a zombie, its exit status comes last. Exit statuses of the other
 * threads must be collected first, or waiting for it would never end. Children
 * (fork) are not followed: they keep the int3 bytes of the moment of the fork.
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
#include <sys/syscall.h>
#include <dirent.h>
#include <termios.h>
#include <stddef.h>
#include <sys/stat.h>
#include <pwd.h>
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

#ifdef DBG_OK
/* threads (see the top of the file) */
typedef struct {
    pid_t tid;
    bool  stopped;                     /* in a ptrace stop, ours to resume      */
    bool  swallow;                     /* a SIGSTOP of ours is on its way       */
    bool  pend;                        /* stopped by something not reported yet */
    bool  zombie;                      /* the first thread, gone before the rest */
    int   pend_st;                     /* its wait status                       */
    int   dsig;                        /* signal to deliver at its next resume  */
} DbgThr;
static DbgThr  *g_thr = NULL;
static int      g_nthr = 0, g_capthr = 0;
static int      g_rr = 0;              /* settle: where the next look starts    */
static pid_t    g_tid = 0;             /* thread of the last stop               */
#endif

#include "dbg_bp.h"                    /* the list, g_base_addr (0: non-PIE)    */

/* load base (see the top of the file) */
static uint64_t g_img_lo = 0;          /* file addresses of the image,          */
static uint64_t g_img_hi = 0;          /* [lo, hi); hi 0: unknown               */

/* breakpoints (see the top of the file) */
static int      g_nins = 0;            /* int3 bytes in memory now (g_ins)     */
static bool     g_bp_off = false;      /* a second exec: user bps not written  */
static bool     g_tmp_on = false;      /* dbg_run_to in progress               */
static uint64_t g_stop_rip = 0;        /* rip at the last reported stop        */
#if defined(__linux__) && defined(__x86_64__)
static uint64_t g_ins[DBG_MAX_BP + 2]; /* int3 written there (process addr)    */
static uint8_t  g_orig[DBG_MAX_BP + 2];/* the byte it replaced                 */
static uint64_t g_tmp = 0;             /* dbg_run_to: its file address         */
static uint64_t g_tmp_rsp = 0;         /* rsp when it was asked                */
static pid_t    g_tmp_tid = 0;         /* by which thread                      */
static uint64_t g_step_from = 0;       /* rip before the dbg_step in progress  */
static uint64_t g_dr[DBG_MAX_HW];      /* armed debug registers, for new threads */
static uint64_t g_dr7 = 0;
static bool     g_hw_armed = false;    /* DR7 set in the debuggee              */
static uint64_t g_entry_rt = 0;        /* AT_ENTRY of the process, 0: unknown  */
static bool     g_entry_on = false;    /* internal int3 on it, in g_ins        */
static bool     g_entry_done = false;  /* the loader has run                   */
/* ELF32 launched through the embedded ld-linux.so.2 (see dbg_launch): the program
 * is g_target (realpath), not /proc/pid/exe, which is that loader */
static bool     g_ld32 = false;
static char     g_target[PATH_MAX];
#endif

static void reset(void) {
#ifdef DBG_OK
    if (g_con >= 0) close(g_con);
    g_nthr = 0;
    g_tid = 0;
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
#ifdef DBG_OK
    g_hw_armed = false;
    g_entry_rt = 0;
    g_entry_on = g_entry_done = false;
    g_ld32 = false;
    g_target[0] = '\0';
#endif
    bpm_session_end();
}

#ifdef DBG_OK

static bool g_stepping = false;        /* last resume was PTRACE_SINGLESTEP     */
static bool g_stepover = false;        /* that step only gets past a breakpoint */
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

static int thr_index(pid_t tid) {
    for (int i = 0; i < g_nthr; i++) if (g_thr[i].tid == tid) return i;
    return -1;
}

/* A new traced thread, stopped. false: no room (it is let go). */
static bool thr_add(pid_t tid) {
    if (g_nthr == g_capthr) {
        int cap = g_capthr ? g_capthr * 2 : 16;
        DbgThr *n = realloc(g_thr, (size_t)cap * sizeof *n);
        if (!n) { ptrace(PTRACE_DETACH, tid, NULL, NULL); return false; }
        g_thr = n;
        g_capthr = cap;
    }
    g_thr[g_nthr++] = (DbgThr){ .tid = tid, .stopped = true };
    return true;
}

/* g_tid goes to a live thread when it was this one */
static void thr_del(int i) {
    pid_t tid = g_thr[i].tid;
    memmove(&g_thr[i], &g_thr[i + 1], (size_t)(g_nthr - i - 1) * sizeof *g_thr);
    g_nthr--;
    if (g_tid != tid) return;
    g_tid = g_pid;
    for (int k = 0; k < g_nthr; k++)
        if (g_thr[k].stopped && !g_thr[k].zombie) { g_tid = g_thr[k].tid; break; }
}

/* the kernel's state letter of a thread, 0: unknown */
static char thr_state(pid_t tid) {
    char p[64], b[512];
    snprintf(p, sizeof p, "/proc/%d/task/%d/stat", g_pid, tid);
    if (!read_small(p, b, sizeof b)) return 0;
    char *e = strrchr(b, ')');
    return e && e[1] && e[2] ? e[2] : 0;
}

static void note_exit(int st) {
    g_nthr = 0;
    g_tid = 0;
    g_wstatus = st;
    g_state = DBG_EXITED;
    g_stop = DBG_STOP_NONE;
    g_lastpid = g_pid;
    g_pid = 0;
    g_ours = false;
    g_sig = 0;
    g_nins = 0;
    g_tmp_on = false;
    g_hw_armed = false;
    g_entry_on = false;
    bpm_session_end();
}

/* ---- load base ---- */

#define DBG_MAX_PHDR 64

typedef struct {
    uint16_t   type;                   /* ET_EXEC, ET_DYN...                   */
    uint16_t   machine;
    int        bits;                   /* 32, 64                               */
    uint64_t   entry;
    int        nph;
    Elf64_Phdr ph[DBG_MAX_PHDR];       /* ELF32: widened                       */
} ElfInfo;

static bool elf_read(const char *file, ElfInfo *e) {
    int fd = open(file, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    unsigned char id[EI_NIDENT];
    bool ok = pread(fd, id, sizeof id, 0) == (ssize_t)sizeof id && memcmp(id, ELFMAG, SELFMAG) == 0;
    if (ok && id[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr h;
        ok = pread(fd, &h, sizeof h, 0) == (ssize_t)sizeof h && h.e_phentsize == sizeof(Elf64_Phdr);
        if (ok) {
            e->bits = 64;
            e->type = h.e_type;
            e->machine = h.e_machine;
            e->entry = h.e_entry;
            e->nph = h.e_phnum < DBG_MAX_PHDR ? h.e_phnum : DBG_MAX_PHDR;
            size_t len = (size_t)e->nph * sizeof(Elf64_Phdr);
            ok = pread(fd, e->ph, len, (off_t)h.e_phoff) == (ssize_t)len;
        }
    } else if (ok && id[EI_CLASS] == ELFCLASS32) {
        Elf32_Ehdr h;
        ok = pread(fd, &h, sizeof h, 0) == (ssize_t)sizeof h && h.e_phentsize == sizeof(Elf32_Phdr);
        if (ok) {
            e->bits = 32;
            e->type = h.e_type;
            e->machine = h.e_machine;
            e->entry = h.e_entry;
            e->nph = h.e_phnum < DBG_MAX_PHDR ? h.e_phnum : DBG_MAX_PHDR;
            for (int i = 0; ok && i < e->nph; i++) {
                Elf32_Phdr p;
                ok = pread(fd, &p, sizeof p, (off_t)(h.e_phoff + (uint64_t)i * sizeof p)) == (ssize_t)sizeof p;
                if (!ok) break;
                e->ph[i].p_type = p.p_type;
                e->ph[i].p_flags = p.p_flags;
                e->ph[i].p_offset = p.p_offset;
                e->ph[i].p_vaddr = p.p_vaddr;
                e->ph[i].p_paddr = p.p_paddr;
                e->ph[i].p_filesz = p.p_filesz;
                e->ph[i].p_memsz = p.p_memsz;
                e->ph[i].p_align = p.p_align;
            }
        }
    } else
        ok = false;
    close(fd);
    return ok;
}

/* lowest page and end of the PT_LOAD span; false: none */
static bool elf_span(const ElfInfo *e, uint64_t pg, uint64_t *lo, uint64_t *hi) {
    *lo = UINT64_MAX;
    *hi = 0;
    for (int i = 0; i < e->nph; i++) {
        if (e->ph[i].p_type != PT_LOAD) continue;
        uint64_t a = e->ph[i].p_vaddr & ~(pg - 1);
        uint64_t z = (e->ph[i].p_vaddr + e->ph[i].p_memsz + pg - 1) & ~(pg - 1);
        if (a < *lo) *lo = a;
        if (z > *hi) *hi = z;
    }
    return *hi > *lo;
}

/* AT_ENTRY of the process (0: unknown). The auxv of a 32-bit process is made
 * of 4-byte pairs. */
static uint64_t auxv_entry(int pid, int bits) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/auxv", pid);
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    uint64_t entry = 0;
    if (bits == 32) {
        uint32_t kv[2];
        while (fread(kv, sizeof kv, 1, f) == 1 && kv[0] != AT_NULL)
            if (kv[0] == AT_ENTRY) { entry = kv[1]; break; }
    } else {
        uint64_t kv[2];
        while (fread(kv, sizeof kv, 1, f) == 1 && kv[0] != AT_NULL)
            if (kv[0] == AT_ENTRY) { entry = kv[1]; break; }
    }
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

static uint64_t page_size(void) {
    uint64_t pg = (uint64_t)sysconf(_SC_PAGESIZE);
    return pg == 0 || (pg & (pg - 1)) ? 4096 : pg;
}

/* Sets g_base_addr / g_img_lo / g_img_hi / g_bits for the stopped debuggee
 * g_pid. `path`: the program launched (NULL for an attach). */
static void find_base(const char *path) {
    uint64_t pg = page_size();
    char link[64], exe[PATH_MAX];
    static ElfInfo e;                       /* ~3.6 KB: off the stack */
    bool elf;
    uint64_t lo, hi;
    if (g_ld32) {
        /* /proc/pid/exe and AT_ENTRY are those of ld.so: the program is the
         * file it mapped (ld32_wait waited for that), its entry is its own */
        snprintf(exe, sizeof exe, "%s", g_target);
        elf = elf_read(g_target, &e);
        if (elf) g_bits = e.bits;
        if (elf && elf_span(&e, pg, &lo, &hi)) { g_img_lo = lo; g_img_hi = hi; }
        g_base_addr = 0;
        g_entry_rt = 0;
        if (!elf) return;
        uint64_t start, off;
        if (e.type != ET_EXEC && maps_first(g_pid, exe, &start, &off))
            for (int i = 0; i < e.nph; i++)
                if (e.ph[i].p_type == PT_LOAD && (e.ph[i].p_offset & ~(pg - 1)) == off) {
                    g_base_addr = start - (e.ph[i].p_vaddr & ~(pg - 1));
                    break;
                }
        g_entry_rt = e.entry + g_base_addr;
        return;
    }
    snprintf(link, sizeof link, "/proc/%d/exe", g_pid);
    ssize_t n = readlink(link, exe, sizeof exe - 1);
    if (n > 0) exe[n] = '\0';
    else if (!path || !realpath(path, exe)) exe[0] = '\0';

    elf = elf_read(link, &e) || (path && elf_read(path, &e));
    if (elf) g_bits = e.bits;
    if (elf && elf_span(&e, pg, &lo, &hi)) { g_img_lo = lo; g_img_hi = hi; }
    g_base_addr = 0;
    g_entry_rt = auxv_entry(g_pid, elf ? e.bits : 64);
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
    if (elf && g_entry_rt) g_base_addr = g_entry_rt - e.entry;   /* fallback */
}

/* A new process is stopped: where it is, breakpoints placed from their rva */
static void load_base(const char *path) {
    find_base(path);
    bpm_rebase(g_img_lo);
    bpm_new_session();
    if (!g_prog[0]) {
        const char *src = path;
        char exe[PATH_MAX], link[64];
        snprintf(link, sizeof link, "/proc/%d/exe", g_pid);
        ssize_t n = g_ld32 ? 0 : readlink(link, exe, sizeof exe - 1);
        if (g_ld32) src = g_target;
        else if (n > 0) { exe[n] = '\0'; src = exe; }
        if (src) {
            const char *sl = strrchr(src, '/');
            snprintf(g_prog, sizeof g_prog, "%.*s", DBG_MOD_MAX - 1, sl ? sl + 1 : src);
        }
    }
}

/* What an exec failure means when the message of errno alone would mislead:
 * ENOENT on a file that exists is its missing interpreter. */
/* PT_INTERP of `path` (in, 256 bytes); false: none */
static bool read_interp(const char *path, const ElfInfo *e, char in[256]) {
    for (int i = 0; i < e->nph; i++) {
        if (e->ph[i].p_type != PT_INTERP) continue;
        in[0] = '\0';
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            size_t len = e->ph[i].p_filesz < 255 ? (size_t)e->ph[i].p_filesz : 255;
            ssize_t got = pread(fd, in, len, (off_t)e->ph[i].p_offset);
            in[got > 0 ? got : 0] = '\0';
            close(fd);
        }
        return true;
    }
    return false;
}

static void exec_error(const char *path, int cerr, char *err, size_t esz) {
    static ElfInfo e;
    bool elf = elf_read(path, &e);
    char in[256];
    if (cerr == ENOENT && elf && access(path, F_OK) == 0 && read_interp(path, &e, in)) {
        snprintf(err, esz, "Cannot run %.150s: its %d-bit loader %.80s is not installed", path, e.bits, in);
        return;
    }
    if (cerr == ENOEXEC && elf && e.bits == 32) {
        snprintf(err, esz, "Cannot run %.150s: this kernel does not run 32-bit programs", path);
        return;
    }
    snprintf(err, esz, "Cannot run %.200s: %s", path, strerror(cerr));
}

#endif /* DBG_OK */

#ifdef DBG_OK
/* Takes the other threads of an attached process, until no new one shows up
 * (one not taken yet can still create threads). One that is gone meanwhile is
 * simply not there. */
static void attach_threads(void) {
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/task", g_pid);
    for (bool grew = true; grew; ) {
        grew = false;
        DIR *d = opendir(p);
        if (!d) return;
        struct dirent *e;
        while ((e = readdir(d))) {
            pid_t tid = (pid_t)atoi(e->d_name);
            if (tid <= 0 || thr_index(tid) >= 0) continue;
            if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) < 0) continue;
            int st;
            if (!wait_sigstop(tid, &st)) continue;
            ptrace(PTRACE_SETOPTIONS, tid, NULL, (void *)(long)PTRACE_O_TRACECLONE);
            if (!thr_add(tid)) continue;
            grew = true;
        }
        closedir(d);
    }
}
#endif

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

    g_pid = pid;                           /* thr_state */
    bool gone = thr_state((pid_t)pid) == 'Z';
    g_pid = 0;
    if (gone) {                            /* ptrace refuses a zombie: nothing to wait on */
        snprintf(err, esz, "Process %d: its first thread has exited, attach is not possible", pid);
        return false;
    }
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
    g_tid = (pid_t)pid;
    ptrace(PTRACE_SETOPTIONS, (pid_t)pid, NULL, (void *)(long)PTRACE_O_TRACECLONE);
    thr_add((pid_t)pid);
    attach_threads();
    load_base(NULL);
    g_entry_done = true;                   /* its loader ran long ago */
    return true;
#endif
}

#ifdef DBG_OK
static void bp_remove_all(void);

static long long mono_ms(void);

/* SIGKILL and every exit status: those of the other threads first (known or
 * not: one can be just born), the first thread's only comes after them. */
static void kill_all(void) {
    kill((pid_t)g_pid, SIGKILL);
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/task", g_pid);
    long long end = mono_ms() + 5000;
    while (mono_ms() < end) {
        int st;
        DIR *d = opendir(p);
        if (d) {
            struct dirent *e;
            while ((e = readdir(d))) {
                pid_t tid = (pid_t)atoi(e->d_name);
                if (tid > 0 && tid != (pid_t)g_pid) wait_pid(tid, &st, WNOHANG);
            }
            closedir(d);
        }
        pid_t r = wait_pid((pid_t)g_pid, &st, WNOHANG);
        if (r < 0 || (r == (pid_t)g_pid && (WIFEXITED(st) || WIFSIGNALED(st)))) return;
        struct timespec ts = { 0, 50000 };
        nanosleep(&ts, NULL);
    }
}
#endif

void dbg_detach(void) {
#ifdef DBG_OK
    /* an attached process goes on running: stop it the usual way first,
     * which takes the int3 bytes out (and puts rip back on a hit) */
    if (!g_ours && g_pid > 0 && g_state == DBG_RUNNING) dbg_interrupt();
    if (g_pid > 0 && (g_state == DBG_STOPPED || g_state == DBG_RUNNING)) {
        if (g_ours)
            kill_all();
        else {
            /* PTRACE_DETACH needs a stopped tracee with no SIGSTOP of ours left */
            bool was_running = g_state == DBG_RUNNING;
            for (int i = 0; i < g_nthr; i++) {
                DbgThr *t = &g_thr[i];
                if (t->zombie) continue;
                int st;
                if (t->stopped && t->swallow && ptrace(PTRACE_CONT, t->tid, NULL, NULL) < 0) continue;
                if (!t->stopped && !t->swallow) syscall(SYS_tgkill, g_pid, t->tid, SIGSTOP);
                if (t->stopped && !t->swallow) continue;
                if (!wait_sigstop(t->tid, &st)) { t->zombie = true; continue; }
                t->stopped = true;
                t->swallow = false;
            }
            if (was_running) { g_sig = 0; bp_remove_all(); }    /* that SIGSTOP is ours */
            for (int i = 0; i < g_nthr; i++) {
                DbgThr *t = &g_thr[i];
                if (t->zombie) continue;
                int sig = t->tid == g_tid ? g_sig : t->pend ? WSTOPSIG(t->pend_st) : t->dsig;
                if (ptrace(PTRACE_DETACH, t->tid, NULL, (void *)(long)sig) < 0 && errno == ESRCH) {
                    int st;
                    wait_pid(t->tid, &st, WNOHANG);          /* died meanwhile */
                }
            }
        }
    }
#endif
    reset();
}

#ifdef DBG_OK
/* ---- ELF32 without a system loader: the embedded one (see dbg_launch) ---- */

#define LD32_LOADER  "ld-linux.so.2"
#define LD32_WAIT_MS 5000      /* ld.so: longest time to map the program / to --list */
#define LD32_TEST_ENV "ABYSS_TEST_NO_SYSTEM_INTERP"   /* tests: "1" = loader absent */

#ifdef ABYSS_LD32_BLOB
/* SHA-256 (FIPS 180-4) of the embedded files and of their copies on disk */
typedef struct { uint32_t h[8]; uint64_t n; uint8_t b[64]; size_t k; } Sha256;

#define SHA_ROR(x, r) ((x) >> (r) | (x) << (32 - (r)))
static void sha_block(uint32_t *h, const uint8_t *p) {
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (int i = 16; i < 64; i++)
        w[i] = w[i - 16] + (SHA_ROR(w[i - 15], 7) ^ SHA_ROR(w[i - 15], 18) ^ w[i - 15] >> 3) + w[i - 7] +
               (SHA_ROR(w[i - 2], 17) ^ SHA_ROR(w[i - 2], 19) ^ w[i - 2] >> 10);
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = hh + (SHA_ROR(e, 6) ^ SHA_ROR(e, 11) ^ SHA_ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (SHA_ROR(a, 2) ^ SHA_ROR(a, 13) ^ SHA_ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}
static void sha_init(Sha256 *s) {
    static const uint32_t iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    memcpy(s->h, iv, sizeof iv);
    s->n = 0;
    s->k = 0;
}
static void sha_add(Sha256 *s, const void *data, size_t n) {
    const uint8_t *p = data;
    s->n += n;
    if (s->k) {
        size_t t = 64 - s->k < n ? 64 - s->k : n;
        memcpy(s->b + s->k, p, t);
        s->k += t; p += t; n -= t;
        if (s->k < 64) return;
        sha_block(s->h, s->b);
        s->k = 0;
    }
    for (; n >= 64; p += 64, n -= 64) sha_block(s->h, p);
    memcpy(s->b, p, n);
    s->k = n;
}
static void sha_end(Sha256 *s, uint8_t out[32]) {
    uint64_t bits = s->n * 8;
    uint8_t pad[72] = { 0x80 };
    size_t np = (s->k < 56 ? 56 : 120) - s->k;
    for (int i = 0; i < 8; i++) pad[np + (size_t)i] = (uint8_t)(bits >> (56 - 8 * i));
    sha_add(s, pad, np + 8);
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(s->h[i / 4] >> (24 - 8 * (i % 4)));
}

/* the files (ld32blob.S), the loader first */
#define LD32_SYM(n) extern const unsigned char abyss_ld32_##n[] __attribute__((visibility("hidden"))), \
                                               abyss_ld32_##n##_end[] __attribute__((visibility("hidden")))
LD32_SYM(0); LD32_SYM(1); LD32_SYM(2); LD32_SYM(3); LD32_SYM(4); LD32_SYM(5);
static const struct { const char *name; const unsigned char *lo, *hi; } g_ld32_emb[] = {
    { LD32_LOADER,       abyss_ld32_0, abyss_ld32_0_end },
    { "libc.so.6",       abyss_ld32_1, abyss_ld32_1_end },
    { "libm.so.6",       abyss_ld32_2, abyss_ld32_2_end },
    { "libdl.so.2",      abyss_ld32_3, abyss_ld32_3_end },
    { "libpthread.so.0", abyss_ld32_4, abyss_ld32_4_end },
    { "librt.so.1",      abyss_ld32_5, abyss_ld32_5_end },
};
#define LD32_NEMB (sizeof g_ld32_emb / sizeof g_ld32_emb[0])
static uint8_t g_ld32_sum[LD32_NEMB][32];   /* SHA-256 of each */
static char    g_ld32_tag[17];              /* i32-<tag>: from the names, sizes and sums */

static void ld32_sums(void) {
    if (g_ld32_tag[0]) return;
    Sha256 all;
    sha_init(&all);
    for (size_t i = 0; i < LD32_NEMB; i++) {
        Sha256 s;
        uint64_t n = (uint64_t)(g_ld32_emb[i].hi - g_ld32_emb[i].lo);
        sha_init(&s);
        sha_add(&s, g_ld32_emb[i].lo, (size_t)n);
        sha_end(&s, g_ld32_sum[i]);
        sha_add(&all, g_ld32_emb[i].name, strlen(g_ld32_emb[i].name) + 1);
        sha_add(&all, &n, sizeof n);
        sha_add(&all, g_ld32_sum[i], 32);
    }
    uint8_t d[32];
    sha_end(&all, d);
    for (int i = 0; i < 8; i++) snprintf(g_ld32_tag + 2 * i, 3, "%02x", d[i]);
}

/* $XDG_CACHE_HOME (absolute only, as the XDG spec says), else $HOME/.cache, else
 * the home of the passwd entry; no trailing '/' */
static bool ld32_base(char *out, size_t sz) {
    const char *x = getenv("XDG_CACHE_HOME");
    int n;
    if (x && x[0] == '/') n = snprintf(out, sz, "%s", x);
    else {
        const char *h = getenv("HOME");
        if (!h || h[0] != '/') {
            struct passwd *pw = getpwuid(geteuid());
            h = pw && pw->pw_dir && pw->pw_dir[0] == '/' ? pw->pw_dir : NULL;
        }
        if (!h) return false;
        n = snprintf(out, sz, "%s/.cache", h);
    }
    if (n < 0 || n >= (int)sz) return false;
    while (n > 1 && out[n - 1] == '/') out[--n] = '\0';
    return true;
}

/* mkdir -p, 0700 for what it creates. 0 or errno. */
static int ld32_mkdirs(char *p) {
    for (char *s = p + 1; ; s++) {
        if (*s && *s != '/') continue;
        char c = *s;
        *s = '\0';
        int e = mkdir(p, 0700) == 0 || errno == EEXIST ? 0 : errno;
        *s = c;
        if (e) return e;
        if (!c) return 0;
    }
}

/* file i in the directory dfd is the embedded one: a regular file of the
 * user's, not writable by others, the loader executable, same size, same SHA-256 */
static bool ld32_same(int dfd, size_t i) {
    static uint8_t buf[1 << 16];
    int fd = openat(dfd, g_ld32_emb[i].name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st;
    uint64_t want = (uint64_t)(g_ld32_emb[i].hi - g_ld32_emb[i].lo), got = 0;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() && !(st.st_mode & 022) &&
              (i || (st.st_mode & S_IXUSR)) && (uint64_t)st.st_size == want;
    if (ok) {
        Sha256 s;
        sha_init(&s);
        ssize_t r;
        while ((r = read(fd, buf, sizeof buf)) > 0 || (r < 0 && errno == EINTR))
            if (r > 0) { sha_add(&s, buf, (size_t)r); got += (uint64_t)r; }
        uint8_t d[32];
        sha_end(&s, d);
        ok = r == 0 && got == want && !memcmp(d, g_ld32_sum[i], 32);
    }
    close(fd);
    return ok;
}

/* file i written into dfd so that its name only ever shows a whole file: a
 * nameless file (O_TMPFILE; a named .NAME.PID.N where the file system has none)
 * filled and synced, linked as .NAME.PID.N, renamed onto NAME. 0 or errno. */
static int ld32_put(int dfd, size_t i) {
    static unsigned seq;
    const char *name = g_ld32_emb[i].name;
    mode_t mode = i ? 0600 : 0700;
    char tmp[96];
    snprintf(tmp, sizeof tmp, ".%s.%d.%u", name, (int)getpid(), seq++);
    bool named = false;
    int fd = openat(dfd, ".", O_TMPFILE | O_WRONLY | O_CLOEXEC, mode);
    if (fd < 0) {
        if (errno != EOPNOTSUPP && errno != EISDIR && errno != EINVAL) return errno;
        fd = openat(dfd, tmp, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, mode);
        if (fd < 0) return errno;
        named = true;
    }
    int e = 0;
    for (const unsigned char *p = g_ld32_emb[i].lo; !e && p < g_ld32_emb[i].hi; ) {
        ssize_t w = write(fd, p, (size_t)(g_ld32_emb[i].hi - p));
        if (w > 0) p += w;
        else if (w == 0) e = EIO;
        else if (errno != EINTR) e = errno;
    }
    if (!e && fchmod(fd, mode) < 0) e = errno;      /* whatever the umask */
    if (!e && fsync(fd) < 0) e = errno;
    if (!e && !named) {
        char pp[64];
        snprintf(pp, sizeof pp, "/proc/self/fd/%d", fd);
        if (linkat(AT_FDCWD, pp, dfd, tmp, AT_SYMLINK_FOLLOW) < 0) e = errno;
        else named = true;
    }
    if (!e && renameat(dfd, tmp, dfd, name) < 0) e = errno;
    if (e && named && ftruncate(fd, 0) < 0) { /* left as it is: never deleted */ }
    close(fd);
    return e;
}

/* The directory holding the embedded files, each one checked and the missing or
 * different ones written again (see dbg_launch). false: why, in err (the end of
 * a sentence). */
static bool ld32_cache(char *dir, size_t sz, char *err, size_t esz) {
    ld32_sums();
    char base[PATH_MAX];
    if (!ld32_base(base, sizeof base)) {
        snprintf(err, esz, "Abyss has nowhere to put its own (set XDG_CACHE_HOME or HOME)");
        return false;
    }
    int n = snprintf(dir, sz, "%s/abyss/i32-%s", base, g_ld32_tag);
    if (n < 0 || n >= (int)sz) { snprintf(err, esz, "the cache path %.150s is too long", base); return false; }
    if (strpbrk(dir, ":;$")) {                     /* ld.so would split / expand it */
        snprintf(err, esz, "the cache path %.150s holds ':', ';' or '$', which ld.so cannot take (set XDG_CACHE_HOME)",
                 dir);
        return false;
    }
    struct stat st;
    int e = 0;
    if (lstat(dir, &st) < 0) {
        e = errno == ENOENT ? ld32_mkdirs(dir) : errno;
        if (!e && lstat(dir, &st) < 0) e = errno;
    }
    if (e) goto unwritable;
    if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid()) {
        snprintf(err, esz, "%.200s is not a directory of yours (move it away, or set XDG_CACHE_HOME)", dir);
        return false;
    }
    /* group / others lose their rights; the user's own are left as they are
     * (a cache made read-only on purpose stays so) */
    if ((st.st_mode & 07077) && chmod(dir, st.st_mode & 0700) < 0 && (st.st_mode & 022)) {
        snprintf(err, esz, "%.200s is writable by others and cannot be made private: %s", dir, strerror(errno));
        return false;
    }
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0) { e = errno; goto unwritable; }
    bool wrote = false;
    for (size_t i = 0; !e && i < LD32_NEMB; i++) {
        if (ld32_same(dfd, i)) continue;
        e = ld32_put(dfd, i);
        if (!e && !ld32_same(dfd, i)) e = EIO;     /* written, not read back as such */
        wrote = true;
    }
    if (wrote && !e) fsync(dfd);
    close(dfd);
    if (!e) return true;
unwritable:
    /* the reason before the path: a long path may be cut on screen */
    snprintf(err, esz, "Abyss cannot write its own (%s) to %.200s: set XDG_CACHE_HOME to a writable directory",
             strerror(e), dir);
    return false;
}
#else
static bool ld32_cache(char *dir, size_t sz, char *err, size_t esz) {
    (void)dir; (void)sz;
    snprintf(err, esz, "this build of Abyss carries none (install the i386 glibc, or rebuild Abyss "
             "with ABYSS32=<directory of the i386 ld-linux.so.2, libc.so.6...>)");
    return false;
}
#endif

/* The loader `in` of an i386 program is absent: the embedded one stands in
 * for it */
static bool ld32_wanted(const ElfInfo *e, const char *in) {
    if (e->bits != 32 || e->machine != EM_386 || !in[0]) return false;
    const char *t = getenv(LD32_TEST_ENV);
    bool absent = (t && t[0] && strcmp(t, "0")) || access(in, F_OK) != 0;
    const char *sl = strrchr(in, '/');
    return absent && !strcmp(sl ? sl + 1 : in, LD32_LOADER);
}

/* ld.so --list of the program: what it needs and cannot find comes out
 * before any process is debugged. ld.so maps the libraries in that mode, it
 * neither relocates nor runs anything. false: err says why. */
static bool ld32_check(const char *path, const char *ldso, const char *libdir, const char *libpath,
                       char *err, size_t esz) {
    int out[2], ex[2];
    if (pipe2(out, O_CLOEXEC) < 0) { snprintf(err, esz, "pipe: %s", strerror(errno)); return false; }
    if (pipe2(ex, O_CLOEXEC) < 0) {
        snprintf(err, esz, "pipe: %s", strerror(errno));
        close(out[0]); close(out[1]);
        return false;
    }
    char *av[] = { (char *)ldso, "--library-path", (char *)libpath, "--list", (char *)path, NULL };
    pid_t pid = fork();
    if (pid < 0) {
        snprintf(err, esz, "fork failed: %s", strerror(errno));
        close(out[0]); close(out[1]); close(ex[0]); close(ex[1]);
        return false;
    }
    if (pid == 0) {
        int nul = open("/dev/null", O_RDONLY);
        if (nul >= 0) { dup2(nul, 0); if (nul > 2) close(nul); }
        dup2(out[1], 1);
        dup2(out[1], 2);
        execv(ldso, av);
        int e = errno;
        ssize_t w = write(ex[1], &e, sizeof e);
        (void)w;
        _exit(127);
    }
    close(out[1]);
    close(ex[1]);
    int cerr = 0;
    ssize_t n;
    do n = read(ex[0], &cerr, sizeof cerr); while (n < 0 && errno == EINTR);
    close(ex[0]);

    /* its output, until it closes the pipe or the time is up */
    char txt[2048];
    size_t len = 0;
    fcntl(out[0], F_SETFL, fcntl(out[0], F_GETFL) | O_NONBLOCK);
    long long end = mono_ms() + LD32_WAIT_MS;
    int st = 0;
    bool reaped = false, late = false;
    for (;;) {
        ssize_t r = read(out[0], txt + len, sizeof txt - 1 - len);
        if (r > 0) { len += (size_t)r; if (len < sizeof txt - 1) continue; }
        if (r == 0 || len >= sizeof txt - 1) break;          /* end, or enough */
        if (r < 0 && errno != EAGAIN && errno != EINTR) break;
        if (wait_pid(pid, &st, WNOHANG) == pid) { reaped = true; break; }
        if (mono_ms() > end) { late = true; break; }
        struct timespec ts = { 0, 1000000 };
        nanosleep(&ts, NULL);
    }
    if (reaped) {                                            /* what it wrote last */
        ssize_t r;
        while (len < sizeof txt - 1 && (r = read(out[0], txt + len, sizeof txt - 1 - len)) > 0) len += (size_t)r;
    }
    close(out[0]);
    txt[len] = '\0';
    while (!reaped) {
        pid_t r = wait_pid(pid, &st, WNOHANG);
        if (r == pid || r < 0) { reaped = true; break; }
        if (late || mono_ms() > end) { late = true; kill(pid, SIGKILL); wait_pid(pid, &st, 0); break; }
        struct timespec ts = { 0, 1000000 };
        nanosleep(&ts, NULL);
    }

    if (n == (ssize_t)sizeof cerr) {
        if (cerr == ENOEXEC) snprintf(err, esz, "Cannot run %.150s: this kernel does not run 32-bit programs", path);
        else snprintf(err, esz, "Cannot run %.100s: %.150s: %s", path, ldso, strerror(cerr));
        return false;
    }
    if (late) { snprintf(err, esz, "Cannot run %.150s: %.100s --list did not answer", path, ldso); return false; }

    /* the list itself is indented: any other line is ld.so's own words, fatal
     * ("<prog>: error while loading shared libraries: <lib>: cannot open shared
     * object file: ...", code 127) or not (a missing symbol version, code 0 in
     * this mode, fatal when the program runs) */
    char *line = NULL;
    for (char *l = txt; *l; ) {
        size_t k = strcspn(l, "\n");
        if (k && l[0] != '\t') { line = l; l[k] = '\0'; break; }
        l += k + (l[k] == '\n');
    }
    bool ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
    if (ok && !line) return true;
    if (!line) line = txt + len;                            /* "" */
    static const char ewl[] = "error while loading shared libraries: ", cop[] = "cannot open shared object file";
    char *w = strstr(line, ewl);
    if (w) {
        char *lib = w + sizeof ewl - 1, *c = strstr(lib, ": ");
        if (c && !strncmp(c + 2, cop, sizeof cop - 1)) {
            *c = '\0';
            snprintf(err, esz, "Cannot run %.100s: it needs %.60s, which is neither installed nor among the i386 "
                     "libraries of Abyss (%.150s/): put its directory in LD_LIBRARY_PATH", path, lib, libdir);
            return false;
        }
    }
    size_t pl = strlen(path);
    if (!strncmp(line, path, pl) && !strncmp(line + pl, ": ", 2)) line += pl + 2;
    if (line[0]) snprintf(err, esz, "Cannot run %.100s: ld.so: %.180s", path, line);
    else if (WIFEXITED(st)) snprintf(err, esz, "Cannot run %.150s: ld.so --list exited with code %d", path, WEXITSTATUS(st));
    else snprintf(err, esz, "Cannot run %.150s: ld.so --list killed by signal %d", path, WIFSIGNALED(st) ? WTERMSIG(st) : 0);
    return false;
}

/* Every PT_LOAD of the program in place, with its permissions and file offset:
 * what ld.so maps before it reads the libraries */
static bool ld32_mapped(pid_t pid, const char *target, const ElfInfo *e) {
    char p[64], line[PATH_MAX + 128];
    snprintf(p, sizeof p, "/proc/%d/maps", pid);
    FILE *f = fopen(p, "r");
    if (!f) return false;
    enum { MAXL = 64 };
    struct { uint64_t lo, hi, off; char perm[5]; } m[MAXL];
    int nm = 0;
    while (nm < MAXL && fgets(line, sizeof line, f)) {
        unsigned long long lo, hi, o;
        char perm[8];
        int n = 0;
        if (sscanf(line, "%llx-%llx %7s %llx %*s %*s %n", &lo, &hi, perm, &o, &n) < 4 || !n) continue;
        char *nm_ = line + n;
        nm_[strcspn(nm_, "\n")] = '\0';
        if (strcmp(nm_, target)) continue;
        m[nm].lo = lo; m[nm].hi = hi; m[nm].off = o;
        snprintf(m[nm].perm, sizeof m[nm].perm, "%.4s", perm);
        nm++;
    }
    fclose(f);
    if (!nm) return false;
    uint64_t pg = page_size();
    int first = -1;
    for (int i = 0; i < e->nph; i++)
        if (e->ph[i].p_type == PT_LOAD && (first < 0 || e->ph[i].p_vaddr < e->ph[first].p_vaddr)) first = i;
    if (first < 0) return false;
    uint64_t base = 0;                              /* ET_EXEC: where it is linked */
    if (e->type != ET_EXEC) {                       /* the lowest mapping: its first PT_LOAD */
        if (m[0].off != (e->ph[first].p_offset & ~(pg - 1))) return false;
        base = m[0].lo - (e->ph[first].p_vaddr & ~(pg - 1));
    }
    for (int i = 0; i < e->nph; i++) {
        const Elf64_Phdr *s = &e->ph[i];
        if (s->p_type != PT_LOAD || !s->p_filesz) continue;
        uint64_t a = base + (s->p_vaddr & ~(pg - 1));
        int k = 0;
        while (k < nm && !(m[k].lo <= a && a < m[k].hi)) k++;
        if (k == nm) return false;
        if (m[k].off + (a - m[k].lo) != (s->p_offset & ~(pg - 1))) return false;
        if (m[k].perm[0] != (s->p_flags & PF_R ? 'r' : '-') || m[k].perm[1] != (s->p_flags & PF_W ? 'w' : '-') ||
            m[k].perm[2] != (s->p_flags & PF_X ? 'x' : '-')) return false;
    }
    return true;
}

/* ld.so, stopped at its exec, maps the program itself: one syscall at a time
 * (PTRACE_SYSCALL, a few dozen) until ld32_mapped holds, on a syscall exit.
 * false: err says why; *gone: it has exited and been reaped (not to kill). */
static bool ld32_wait(pid_t pid, const char *path, const char *target, const ElfInfo *e, int con,
                      bool *gone, char *err, size_t esz) {
    *gone = false;
    long opt = PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE;
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)(opt | PTRACE_O_TRACESYSGOOD)) < 0) {
        snprintf(err, esz, "ptrace(SETOPTIONS): %s", strerror(errno));
        return false;
    }
    bool in_sys = false;
    int sig = 0;
    long long end = mono_ms() + LD32_WAIT_MS;
    for (int n = 0; n < 100000; n++) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(long)sig) < 0) {
            snprintf(err, esz, "ptrace(SYSCALL): %s", strerror(errno));
            return false;
        }
        sig = 0;
        int st;
        pid_t r;
        long ns = 20000;
        while ((r = wait_pid(pid, &st, WNOHANG)) == 0) {
            if (mono_ms() > end) {
                snprintf(err, esz, "Cannot run %.150s: ld.so did not map it within %d s", path, LD32_WAIT_MS / 1000);
                return false;
            }
            struct timespec ts = { 0, ns };
            nanosleep(&ts, NULL);
            if (ns < 1000000) ns *= 2;
        }
        if (r != pid) { snprintf(err, esz, "waitpid: %s", strerror(errno)); return false; }
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            *gone = true;
            char txt[512] = "";
            long got = con >= 0 ? (long)read(con, txt, sizeof txt - 1) : -1;
            txt[got > 0 ? got : 0] = '\0';
            char *line = txt;
            while (*line == '\r' || *line == '\n' || *line == ' ') line++;
            line[strcspn(line, "\r\n")] = '\0';
            if (line[0]) snprintf(err, esz, "Cannot run %.100s: ld.so: %.180s", path, line);
            else if (WIFEXITED(st)) snprintf(err, esz, "%.200s exited right away (code %d)", path, WEXITSTATUS(st));
            else snprintf(err, esz, "%.200s killed by signal %d before it was mapped", path, WTERMSIG(st));
            return false;
        }
        if (!WIFSTOPPED(st)) continue;
        if (WSTOPSIG(st) == (SIGTRAP | 0x80)) {
            in_sys = !in_sys;
            if (!in_sys && ld32_mapped(pid, target, e)) {
                if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)opt) < 0) {
                    snprintf(err, esz, "ptrace(SETOPTIONS): %s", strerror(errno));
                    return false;
                }
                return true;
            }
            continue;
        }
        if (st >> 16) continue;                     /* a ptrace event */
        sig = WSTOPSIG(st);                         /* its own signal: delivered */
    }
    snprintf(err, esz, "Cannot run %.150s: ld.so did not map it", path);
    return false;
}

/* What dbg_launch runs for `path`. 0: the program itself, as always. 1: the
 * embedded ld.so (ld32_cache), *xav its argv (malloc'd), g_target-to-be in
 * `target`. -1: refused, err says why. */
static int ld32_plan(const char *path, char *const *av, char ***xav, char *ldso, size_t ldsz,
                     char *target, char **libpath, char *err, size_t esz) {
    static ElfInfo e;
    char in[256];
    if (!elf_read(path, &e) || !read_interp(path, &e, in) || !ld32_wanted(&e, in)) return 0;
    if (!realpath(path, target)) return 0;          /* the exec says why */
    char dir[PATH_MAX], why[400];
    if (!ld32_cache(dir, sizeof dir, why, sizeof why)) {      /* the name only: the cache path is long */
        const char *b = strrchr(path, '/');
        snprintf(err, esz, "Cannot run %.60s: its 32-bit loader %.60s is not installed, and %s", b ? b + 1 : path, in, why);
        return -1;
    }
    snprintf(ldso, ldsz, "%s/" LD32_LOADER, dir);

    /* --library-path stands for LD_LIBRARY_PATH, which ld.so then ignores:
     * that one first, as a direct launch would search it */
    const char *llp = getenv("LD_LIBRARY_PATH");
    size_t need = strlen(dir) + (llp && *llp ? strlen(llp) + 1 : 0) + 1;
    *libpath = malloc(need);
    int ac = 0;
    while (av[ac]) ac++;
    *xav = calloc((size_t)ac + 8, sizeof **xav);
    if (!*libpath || !*xav) {
        free(*libpath); free(*xav); *libpath = NULL; *xav = NULL;
        snprintf(err, esz, "Out of memory");
        return -1;
    }
    snprintf(*libpath, need, "%s%s%s", llp && *llp ? llp : "", llp && *llp ? ":" : "", dir);
    if (!ld32_check(path, ldso, dir, *libpath, err, esz)) {
        free(*libpath); free(*xav); *libpath = NULL; *xav = NULL;
        return -1;
    }
    char **v = *xav;
    int k = 0;
    v[k++] = ldso;
    v[k++] = "--library-path";
    v[k++] = *libpath;
    if (ac > 0 && strcmp(av[0], path)) {            /* ld.so gives it the path otherwise */
        v[k++] = "--argv0";
        v[k++] = av[0];
    }
    v[k++] = (char *)path;
    for (int i = 1; i < ac; i++) v[k++] = av[i];
    v[k] = NULL;
    return 1;
}
#endif

#ifdef DBG_OK
/* fork + PTRACE_TRACEME + execv(exe, xv): `path` itself, or ld.so with the
 * program in its arguments (ld32, `target` = realpath of path) */
static bool spawn_traced(const char *path, const char *exe, char *const *xv, bool ld32, const char *target,
                         char *err, size_t esz) {
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
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0) execv(exe, xv);
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
        exec_error(path, cerr, err, esz);
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
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)(long)(PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE)) < 0) {
        snprintf(err, esz, "ptrace(SETOPTIONS): %s", strerror(errno));
        kill(pid, SIGKILL);
        wait_pid(pid, &st, 0);
        if (mfd >= 0) close(mfd);
        return false;
    }
    if (ld32) {                            /* stopped in ld.so: the program is not there yet */
        static ElfInfo te;
        bool gone = false;
        bool ok = elf_read(target, &te);
        if (!ok) snprintf(err, esz, "Cannot read %.200s", target);
        else ok = ld32_wait(pid, path, target, &te, mfd, &gone, err, esz);
        if (!ok) {
            if (!gone) { kill(pid, SIGKILL); wait_pid(pid, &st, 0); }
            if (mfd >= 0) close(mfd);
            return false;
        }
    }

    reset();
    g_con = mfd;
    g_pid = g_lastpid = (int)pid;
    g_ours = true;
    g_state = DBG_STOPPED;
    g_stop = DBG_STOP_EXEC;                /* its SIGTRAP is not re-delivered */
    g_tid = pid;
    thr_add(pid);
    if (ld32) {
        g_ld32 = true;
        snprintf(g_target, sizeof g_target, "%s", target);
    }
    load_base(path);
    return true;
}
#endif

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
    static ElfInfo ei;
    if (elf_read(path, &ei) && !((ei.bits == 64 && ei.machine == EM_X86_64) || (ei.bits == 32 && ei.machine == EM_386))) {
        snprintf(err, esz, "Cannot debug %.150s: only x86-64 (ELF64) and x86 (ELF32) programs", path);
        return false;
    }
    dbg_detach();

    /* the system has no loader for this i386 program: the embedded
     * ld-linux.so.2 runs it (ld32_plan); otherwise the program itself, as always */
    char *dflt[2] = { (char *)path, NULL };
    char *const *av = argv ? argv : dflt;
    static char ldso[PATH_MAX + 32], target[PATH_MAX];
    char **xav = NULL, *libpath = NULL;
    int plan = ld32_plan(path, av, &xav, ldso, sizeof ldso, target, &libpath, err, esz);
    if (plan < 0) return false;
    bool ok = spawn_traced(path, plan ? ldso : path, plan ? xav : av, plan == 1, target, err, esz);
    free(xav);
    free(libpath);
    return ok;
#endif
}

#ifdef DBG_OK
static void thr_absorb(DbgThr *t, int st);
#endif

DbgState dbg_state(void) {
#ifdef DBG_OK
    /* a stopped tracee can still be SIGKILLed from outside: notice it.
     * (While it runs, its stops are dbg_poll's to collect.) */
    if (g_state == DBG_STOPPED && g_pid > 0) {
        int st;
        for (int i = g_nthr; i-- > 1; )          /* the first thread's status comes last */
            if (wait_pid(g_thr[i].tid, &st, WNOHANG) == g_thr[i].tid) {
                if (WIFEXITED(st) || WIFSIGNALED(st)) thr_del(i);
                else thr_absorb(&g_thr[i], st);
            }
        if (wait_pid((pid_t)g_pid, &st, WNOHANG) == g_pid && (WIFEXITED(st) || WIFSIGNALED(st)))
            note_exit(st);
    }
#endif
    return g_state;
}

void dbg_status(char *out, size_t sz) {
    if (!out || sz == 0) return;
    /* the stop of a thread other than the first says which one */
    char pidn[48];
#ifdef DBG_OK
    if (g_tid > 0 && g_tid != (pid_t)g_pid) snprintf(pidn, sizeof pidn, "pid %d, thread %d", g_pid, (int)g_tid);
    else
#endif
    snprintf(pidn, sizeof pidn, "pid %d", g_pid);
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
            snprintf(out, sz, g_ours ? "interrupted (%s)" : "attached, stopped (%s)", pidn);
            break;
        case DBG_STOP_SIGNAL: {
#ifdef DBG_OK
            const char *name = strsignal(g_sig);
#else
            const char *name = NULL;
#endif
            char at[48] = "";
            if (g_fault_ok) snprintf(at, sizeof at, ", address 0x%llx", (unsigned long long)g_fault);
            snprintf(out, sz, "stopped by signal %d (%s%s) (%s)", g_sig, name ? name : "?", at, pidn);
            break;
        }
        case DBG_STOP_BP:
            snprintf(out, sz, "breakpoint at 0x%llx (%s)", (unsigned long long)g_stop_rip, pidn);
            break;
        case DBG_STOP_TEMP:
            snprintf(out, sz, "reached 0x%llx (%s)", (unsigned long long)g_stop_rip, pidn);
            break;
        case DBG_STOP_STEP:
            snprintf(out, sz, "stepped to 0x%llx (%s)", (unsigned long long)g_stop_rip, pidn);
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
#define DBG_PASS_MS  20        /* longest extra time settle gives to silent passes */
/* a wait status that is neither WIFEXITED nor WIFSIGNALED: dbg_status
 * shows "exited (pid n)" for a debuggee reaped by someone else */
#define ST_UNKNOWN   0xffff

#ifdef DBG_OK

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* One thread goes on: the one being stepped stepping, the others freely. */
static bool resume_one(DbgThr *t, int sig) {
    if (ptrace(g_stepping && t->tid == g_tid ? PTRACE_SINGLESTEP : PTRACE_CONT, t->tid,
               NULL, (void *)(long)sig) < 0) return false;
    t->stopped = false;
    return true;
}

/* A step: g_tid alone. Otherwise every stopped thread, those with something to
 * report stay until settle reports it. true: g_tid has been resumed. */
static bool resume(int sig) {
    int k = thr_index(g_tid);
    if (k < 0) { errno = ESRCH; return false; }
    if (!resume_one(&g_thr[k], sig)) return false;
    if (!g_stepping)
        for (int i = 0; i < g_nthr; i++) {
            DbgThr *t = &g_thr[i];
            if (!t->stopped || t->pend || t->zombie) continue;
            if (resume_one(t, t->dsig)) t->dsig = 0;
        }
    return true;
}

/* ---- breakpoint bytes ---- */

/* file address -> process address */
static uint64_t to_rt(uint64_t file_addr) { return file_addr + g_base_addr; }

static bool peek_byte(uint64_t at, uint8_t *out) {
    uint64_t base = at & ~(uint64_t)7;
    errno = 0;
    long w = ptrace(PTRACE_PEEKTEXT, g_tid, (void *)base, NULL);
    if (errno) return false;
    *out = (uint8_t)((uint64_t)w >> ((unsigned)(at & 7) * 8));
    return true;
}

/* Writes byte `b` at process address `at` through the aligned word that
 * holds it (it cannot cross into an unmapped page); *old gets the byte
 * that was there. */
static bool poke_byte(uint64_t at, uint8_t b, uint8_t *old) {
    uint64_t base = at & ~(uint64_t)7;
    unsigned sh = (unsigned)(at & 7) * 8;
    errno = 0;
    long w = ptrace(PTRACE_PEEKTEXT, g_tid, (void *)base, NULL);
    if (errno) return false;
    uint64_t v = (uint64_t)w;
    if (old) *old = (uint8_t)(v >> sh);
    v = (v & ~((uint64_t)0xff << sh)) | ((uint64_t)b << sh);
    return ptrace(PTRACE_POKETEXT, g_tid, (void *)base, (void *)v) == 0;
}

static int ins_index(uint64_t at) {
    for (int i = 0; i < g_nins; i++) if (g_ins[i] == at) return i;
    return -1;
}

/* true: an int3 of ours is at `at` now */
static bool ins_one(uint64_t at) {
    if (ins_index(at) >= 0) return true;  /* run_to on a user breakpoint */
    uint8_t old;
    if (!poke_byte(at, 0xCC, &old)) return false;
    g_ins[g_nins] = at;
    g_orig[g_nins] = old;
    g_nins++;
    return true;
}

/* ---- mappings of the stopped debuggee ---- */

#define DBG_MAX_MAPS 8192
typedef struct { uint64_t lo, hi; char perm[5]; } MapRange;
static MapRange g_maps[DBG_MAX_MAPS];
static int      g_nmaps;
static bool     g_maps_ok;             /* the whole list is known */

static void maps_load(void) {
    char path[64], line[PATH_MAX + 128];
    snprintf(path, sizeof path, "/proc/%d/maps", g_pid);
    g_nmaps = 0;
    FILE *f = fopen(path, "r");
    g_maps_ok = f != NULL;
    if (!f) return;
    while (fgets(line, sizeof line, f)) {
        unsigned long long lo, hi;
        char perm[8];
        if (sscanf(line, "%llx-%llx %7s", &lo, &hi, perm) != 3) continue;
        if (g_nmaps == DBG_MAX_MAPS) { g_maps_ok = false; break; }
        g_maps[g_nmaps].lo = lo;
        g_maps[g_nmaps].hi = hi;
        snprintf(g_maps[g_nmaps].perm, sizeof g_maps[g_nmaps].perm, "%.4s", perm);
        g_nmaps++;
    }
    fclose(f);
}

/* What a write at `at` would meet, from the list of maps_load. List unknown:
 * OK, the write itself decides. */
static DbgBpState maps_state(uint64_t at) {
    int lo = 0, hi = g_nmaps;
    while (lo < hi) {                   /* the kernel lists them in address order */
        int mid = (lo + hi) / 2;
        if (g_maps[mid].hi <= at) lo = mid + 1; else hi = mid;
    }
    if (lo >= g_nmaps || at < g_maps[lo].lo) return g_maps_ok ? DBG_BPS_UNMAPPED : DBG_BPS_OK;
    if (g_maps[lo].perm[2] != 'x') return DBG_BPS_NOEXEC;
    if (g_maps[lo].perm[3] == 's') return DBG_BPS_SHARED;
    return DBG_BPS_OK;
}

/* the process address of (module, rva) if a file of that name is mapped:
 * its lowest mapping, which starts at file offset 0 */
static bool module_rt(const char *module, uint64_t rva, uint64_t *rt) {
    char path[64], line[PATH_MAX + 128];
    snprintf(path, sizeof path, "/proc/%d/maps", g_pid);
    FILE *f = fopen(path, "r");
    if (!f) return false;
    bool found = false;
    while (!found && fgets(line, sizeof line, f)) {
        unsigned long long lo, hi, off;
        int n = 0;
        if (sscanf(line, "%llx-%llx %*s %llx %*s %*s %n", &lo, &hi, &off, &n) < 3 || !n) continue;
        char *p = line + n;
        p[strcspn(p, "\n")] = '\0';
        const char *sl = strrchr(p, '/');
        if (off == 0 && !strcmp(sl ? sl + 1 : p, module)) { *rt = lo + rva; found = true; }
    }
    fclose(f);
    return found;
}

/* ---- debug registers ---- */

/* a debug register belongs to one thread: all of them get it. What counts is
 * the answer for the current one, another can be dying. */
static bool dr_write(int i, uint64_t v) {
    size_t off = offsetof(struct user, u_debugreg) + (size_t)i * 8;
    for (int k = 0; k < g_nthr; k++)
        if (g_thr[k].tid != g_tid && g_thr[k].stopped) ptrace(PTRACE_POKEUSER, g_thr[k].tid, (void *)off, (void *)v);
    return ptrace(PTRACE_POKEUSER, g_tid, (void *)off, (void *)v) == 0;
}

static void hw_disarm(void) {
    if (g_hw_armed) dr_write(7, 0);
    g_hw_armed = false;
}

/* Execute breakpoints on the ones marked hw and placeable (state OK). */
static void hw_arm(void) {
    int slot = 0;
    uint64_t dr7 = 0;
    for (int i = 0; i < g_nbp; i++) {
        DbgBp *b = &g_bp[i];
        if (!b->hw || !b->enabled || b->state != DBG_BPS_OK) continue;
        if (slot >= DBG_MAX_HW || !dr_write(slot, bpm_rt(b))) {
            b->state = DBG_BPS_HWFAIL;
            bp_tell("refused by the debug registers", b);
            continue;
        }
        g_dr[slot] = bpm_rt(b);
        dr7 |= (uint64_t)1 << (slot * 2);       /* local enable; RW = 00 (execute), LEN = 00 */
        slot++;
    }
    if (!dr7) return;
    g_hw_armed = dr_write(7, dr7);
    g_dr7 = dr7;
    if (!g_hw_armed)
        for (int i = 0; i < g_nbp; i++)
            if (g_bp[i].hw && g_bp[i].state == DBG_BPS_OK) {
                g_bp[i].state = DBG_BPS_HWFAIL;
                bp_tell("refused by the debug registers", &g_bp[i]);
            }
}

/* writes the int3 of every breakpoint, the stopped process about to go on */
static void bp_insert_all(void) {
    maps_load();
    bool pending = false;
    for (int i = 0; i < g_nbp; i++) {
        DbgBp *b = &g_bp[i];
        DbgBpState was = b->state;
        if (g_bp_off || !b->enabled) { b->state = DBG_BPS_IDLE; continue; }
        if (!b->main && !module_rt(b->module, b->rva, &b->rt)) {
            b->rt = 0;
            b->state = DBG_BPS_PENDING;
            pending = true;
            continue;
        }
        uint64_t at = bpm_rt(b);
        b->state = maps_state(at);
        if (b->state == DBG_BPS_OK && !b->hw && !ins_one(at)) b->state = DBG_BPS_UNMAPPED;
        if (b->state != was)
            switch (b->state) {
                case DBG_BPS_UNMAPPED: bp_tell("not placed: nothing is mapped there", b); break;
                case DBG_BPS_NOEXEC:   bp_tell("not placed: not code (no exec permission)", b); break;
                case DBG_BPS_SHARED:   bp_tell("not placed: shared mapping, a write would reach the file", b); break;
                default: break;
            }
    }
    if (!g_bp_off) hw_arm();
    if (g_tmp_on) ins_one(to_rt(g_tmp));
    if (pending && !g_entry_done && g_entry_rt) g_entry_on = ins_one(g_entry_rt);
}

/* puts the original bytes back (each one only touches its own byte, so
 * breakpoints that share a word come out in any order); a byte the program
 * rewrote meanwhile is its own, not ours to restore */
static void bp_remove_all(void) {
    hw_disarm();
    for (int i = g_nins; i-- > 0; ) {
        uint8_t cur;
        if (!peek_byte(g_ins[i], &cur)) continue;
        if (cur == 0xCC) { poke_byte(g_ins[i], g_orig[i], NULL); continue; }
        int k = bpm_at_rt(g_ins[i]);
        if (k >= 0 && !g_bp[k].overwritten) {
            g_bp[k].overwritten = true;
            bp_tell("was overwritten by the program (self-modifying code): its new byte is kept", &g_bp[k]);
        }
    }
    g_nins = 0;
    g_entry_on = false;
}

/* ---- threads: all stopped together ---- */

/* A thread born from a clone we were told of: its first stop is on its way.
 * It starts with the debug registers, and stays stopped when `hold`. */
static void thr_born(pid_t tid, bool hold) {
    int st;
    if (wait_pid(tid, &st, 0) != tid || !WIFSTOPPED(st) || !thr_add(tid)) return;
    DbgThr *t = &g_thr[g_nthr - 1];
    if (WSTOPSIG(st) != SIGSTOP) { t->swallow = true; t->pend = true; t->pend_st = st; hold = true; }
    if (g_hw_armed) {
        for (int i = 0; i < DBG_MAX_HW; i++)
            if (g_dr7 >> (i * 2) & 1)
                ptrace(PTRACE_POKEUSER, tid, (void *)(offsetof(struct user, u_debugreg) + (size_t)i * 8), (void *)g_dr[i]);
        ptrace(PTRACE_POKEUSER, tid, (void *)(offsetof(struct user, u_debugreg) + 7 * 8), (void *)g_dr7);
    }
    if (!hold) resume_one(t, 0);
}

/* The clone event of `tid` (st): true, its child is in the list */
static bool thr_clone_event(int st, pid_t tid, bool hold) {
    if (st >> 16 != PTRACE_EVENT_CLONE) return false;
    unsigned long child = 0;
    if (ptrace(PTRACE_GETEVENTMSG, tid, NULL, &child) == 0 && child) thr_born((pid_t)child, hold);
    return true;
}

/* A stop met while the others stop too, or during a step of another thread:
 * nothing to tell now (see the top of the file). */
static void thr_absorb(DbgThr *t, int st) {
    int k = (int)(t - g_thr);
    t->stopped = true;
    if (thr_clone_event(st, t->tid, true)) {
        t = &g_thr[k];                          /* the list may have moved */
        if (t->swallow) resume_one(t, 0);       /* its SIGSTOP is still to come */
        return;
    }
    int sig = WSTOPSIG(st);
    siginfo_t si;
    if (ptrace(PTRACE_GETSIGINFO, t->tid, NULL, &si) < 0) return;   /* group-stop */
    if (sig == SIGSTOP && t->swallow) { t->swallow = false; return; }
    if (sig == SIGTRAP && si.si_code == SI_KERNEL && g_nins > 0) {
        struct user_regs_struct u;
        if (ptrace(PTRACE_GETREGS, t->tid, NULL, &u) == 0 && ins_index(u.rip - 1) >= 0) {
            u.rip--;
            ptrace(PTRACE_SETREGS, t->tid, NULL, &u);
            return;
        }
    }
    if (sig == SIGTRAP && si.si_code == TRAP_HWBKPT && g_hw_armed) {
        struct user_regs_struct u;
        if (ptrace(PTRACE_GETREGS, t->tid, NULL, &u) == 0) {
            u.eflags &= ~(unsigned long long)0x10000;   /* RF: it must trap again */
            ptrace(PTRACE_SETREGS, t->tid, NULL, &u);
        }
        return;
    }
    t->pend = true;
    t->pend_st = st;
}

/* Every thread stopped, within DBG_STOP_MS (one in uninterruptible sleep stays
 * as it is, still looked at by settle). false: the program is gone. */
#define DBG_STOP_MS 1000
static bool stop_world(void) {
    bool gone = false;
    int gone_st = 0;
    for (int i = 0; i < g_nthr; i++) {
        DbgThr *t = &g_thr[i];
        if (t->stopped || t->swallow || t->zombie) continue;
        if (syscall(SYS_tgkill, g_pid, t->tid, SIGSTOP) == 0) t->swallow = true;
    }
    long long t0 = mono_ms();
    for (long ns = 20000;;) {
        bool wait_more = false;
        for (int i = 0; i < g_nthr; ) {
            DbgThr *t = &g_thr[i];
            if (t->stopped || t->zombie) { i++; continue; }
            int st;
            pid_t tid = t->tid;
            pid_t r = wait_pid(tid, &st, WNOHANG);
            if (r == tid && WIFSTOPPED(st)) {
                thr_absorb(t, st);
                wait_more = wait_more || !g_thr[i].stopped;
                i++;
            } else if (r == tid || r < 0) {
                if (tid == (pid_t)g_pid) { gone = true; gone_st = r == tid ? st : ST_UNKNOWN; }
                thr_del(i);
            } else {
                if (mono_ms() - t0 > 5 && tid == (pid_t)g_pid && thr_state(tid) == 'Z')
                    t->zombie = true;
                else
                    wait_more = true;
                i++;
            }
        }
        if (gone) { note_exit(gone_st); return false; }
        if (!wait_more || mono_ms() - t0 >= DBG_STOP_MS) return true;
        struct timespec ts = { 0, ns };
        nanosleep(&ts, NULL);
        if (ns < 1000000) ns *= 2;
    }
}

/* Every stop reported to the caller comes here: the int3 bytes go out,
 * a dbg_run_to is over, rip is kept for dbg_status. */
static void set_stopped(DbgStop why, int sig) {
    if (!stop_world()) return;
    bp_remove_all();
    g_tmp_on = false;
    g_stepover = false;
    g_state = DBG_STOPPED;
    g_stop = why;
    g_sig = sig;
    g_fault_ok = false;
    struct user_regs_struct u;
    g_stop_rip = ptrace(PTRACE_GETREGS, g_tid, NULL, &u) == 0 ? u.rip : 0;
}

static void regs_from(const struct user_regs_struct *u, DbgRegs *r) {
    r->rip = u->rip;  r->rsp = u->rsp;  r->rbp = u->rbp;
    r->rax = u->rax;  r->rbx = u->rbx;  r->rcx = u->rcx;  r->rdx = u->rdx;
    r->rsi = u->rsi;  r->rdi = u->rdi;  r->rflags = u->eflags;
    bool w = g_bits != 32;
    r->r8  = w ? u->r8  : 0;  r->r9  = w ? u->r9  : 0;
    r->r10 = w ? u->r10 : 0;  r->r11 = w ? u->r11 : 0;
    r->r12 = w ? u->r12 : 0;  r->r13 = w ? u->r13 : 0;
    r->r14 = w ? u->r14 : 0;  r->r15 = w ? u->r15 : 0;
}

/* The thread is at `at`, a place of ours, nothing executed there yet: a
 * reported stop, or (run_to target in a deeper frame, false condition,
 * internal entry stop) a step over it and on. */
static void bp_reached(uint64_t at, const struct user_regs_struct *u) {
    if (!stop_world()) return;                  /* nobody moves from here on */
    int i = g_bp_off ? -1 : bpm_at_rt(at);
    if (g_entry_on && at == g_entry_rt) { g_entry_on = false; g_entry_done = true; }
    if (i >= 0) g_bp[i].hits++;
    if (g_tmp_on && to_rt(g_tmp) == at && g_tid == g_tmp_tid && u->rsp >= g_tmp_rsp) {
        g_last_bp = i;
        set_stopped(DBG_STOP_TEMP, 0);
        return;
    }
    if (i >= 0) {
        DbgRegs r;
        regs_from(u, &r);
        if (cond_true(&g_bp[i], &r)) {
            g_last_bp = i;
            set_stopped(DBG_STOP_BP, 0);
            return;
        }
    }
    bp_remove_all();
    g_stepping = g_stepover = true;
    if (!resume(0)) set_stopped(DBG_STOP_TEMP, 0);
}

/* An int3 trap of `tid`: one of ours? Then rip goes back onto it and that
 * thread is the current one. false: not ours. */
static bool bp_hit(pid_t tid) {
    struct user_regs_struct u;
    if (ptrace(PTRACE_GETREGS, tid, NULL, &u) < 0) return false;
    uint64_t at = u.rip - 1;
    if (ins_index(at) < 0) return false;
    u.rip = at;
    if (ptrace(PTRACE_SETREGS, tid, NULL, &u) < 0) return false;
    g_tid = tid;
    bp_reached(at, &u);
    return true;
}

/* A debug register trap: rip is on the breakpoint already. */
static bool hw_hit(pid_t tid) {
    struct user_regs_struct u;
    if (ptrace(PTRACE_GETREGS, tid, NULL, &u) < 0) return false;
    g_tid = tid;
    bp_reached(u.rip, &u);
    return true;
}

/* A dbg_step lands: one more pass when there is a breakpoint (see the top of
 * the file). */
static void step_landed(void) {
    struct user_regs_struct u;
    if (g_bp_off || ptrace(PTRACE_GETREGS, g_tid, NULL, &u) < 0 || u.rip == g_step_from) return;
    int i = bpm_at_rt(u.rip);
    if (i >= 0) g_bp[i].hits++;
}

/* One waitpid status of thread `tid` of the running debuggee. true: it is not
 * running any more (stopped or gone). */
static bool on_status(pid_t tid, int st) {
    int k = thr_index(tid);
    if (WIFEXITED(st) || WIFSIGNALED(st)) {
        if (tid == (pid_t)g_pid) { note_exit(st); return true; }
        bool was = tid == g_tid;
        if (k >= 0) thr_del(k);
        if (!was || !g_stepping) return false;
        /* the thread being stepped is gone (its exit syscall): nothing else moves */
        if (g_stepover) {
            g_stepping = g_stepover = false;
            bp_insert_all();
            if (resume(0)) return false;
        }
        set_stopped(DBG_STOP_STEP, 0);
        return true;
    }
    if (!WIFSTOPPED(st) || k < 0) return false;
    DbgThr *t = &g_thr[k];
    t->stopped = true;
    if (g_stepping && tid != g_tid) {           /* left over: only g_tid moves */
        thr_absorb(t, st);
        return false;
    }
    if (thr_clone_event(st, tid, g_stepping)) {
        t = &g_thr[k];                          /* the list may have moved */
        if (resume_one(t, 0)) return false;
        set_stopped(DBG_STOP_SIGNAL, 0);
        return true;
    }
    int sig = WSTOPSIG(st);
    siginfo_t si;
    /* fails (EINVAL) on a group-stop: a stop signal already delivered */
    bool has_si = ptrace(PTRACE_GETSIGINFO, tid, NULL, &si) == 0;

    if (sig == SIGSTOP && has_si && t->swallow) {       /* ours */
        t->swallow = false;
        if (!g_intr && resume_one(t, 0)) return false;   /* left over */
        g_tid = tid;
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
        step_landed();
        set_stopped(DBG_STOP_STEP, 0);
        return true;
    }
    if (sig == SIGTRAP && has_si && si.si_code == SI_KERNEL && g_nins > 0 && bp_hit(tid))
        return g_state != DBG_RUNNING;
    if (sig == SIGTRAP && has_si && si.si_code == TRAP_HWBKPT && g_hw_armed && hw_hit(tid))
        return g_state != DBG_RUNNING;
    g_tid = tid;
    if (sig == SIGTRAP && has_si && si.si_code == SI_USER && si.si_pid == g_pid) {
        g_nins = 0;                             /* trap of a second exec: */
        g_hw_armed = false;                     /* the old image is gone  */
        g_entry_on = false;
        g_bp_off = true;
        g_img_lo = g_img_hi = 0;
        {                                       /* it may be of the other width */
            static ElfInfo e;
            char link[64];
            snprintf(link, sizeof link, "/proc/%d/exe", g_pid);
            if (elf_read(link, &e)) g_bits = e.bits;
        }
        /* the others died in the exec, whichever thread called it */
        g_tid = (pid_t)g_pid;
        for (int i = g_nthr; i-- > 0; ) {
            if (g_thr[i].tid == (pid_t)g_pid) continue;
            int x;
            wait_pid(g_thr[i].tid, &x, WNOHANG);
            memmove(&g_thr[i], &g_thr[i + 1], (size_t)(g_nthr - i - 1) * sizeof *g_thr);
            g_nthr--;
        }
        k = thr_index((pid_t)g_pid);
        if (k >= 0) { g_thr[k].stopped = true; g_thr[k].zombie = false; g_thr[k].pend = false; }
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
    long long hard = end + DBG_PASS_MS;         /* passes of a false condition */
    long ns = 50000;                            /* 50 us, doubled up to 2 ms */
    while (g_state == DBG_RUNNING) {
        int st;
        pid_t r = 0, tid = 0;
        if (!g_stepping)                        /* kept from the last stop_world */
            for (int i = 0; i < g_nthr && !r; i++)
                if (g_thr[i].pend) {
                    g_thr[i].pend = false;
                    st = g_thr[i].pend_st;
                    r = tid = g_thr[i].tid;
                }
        for (int n = 0; !r && n < g_nthr; n++) {
            int i = (g_rr + n) % g_nthr;
            if (g_thr[i].stopped) continue;
            tid = g_thr[i].tid;
            r = wait_pid(tid, &st, WNOHANG);
            if (r < 0) {                        /* ECHILD: gone */
                if (tid == (pid_t)g_pid) { note_exit(ST_UNKNOWN); return; }
                st = 0;                         /* an exit status for on_status */
                r = tid;
            }
            if (r) g_rr = i + 1;
        }
        if (r) {
            on_status(tid, st);
            /* it stops again soon when it goes round a loop: wait a little for
             * that (a poll would take one pass each DBG_POLL_MS), the UI first */
            long long now = mono_ms();
            if (now >= hard) return;
            if (now + 2 > end) end = now + 2 < hard ? now + 2 : hard;
            ns = 50000;
            continue;
        }
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
    if (ptrace(PTRACE_GETREGS, g_tid, NULL, &u) < 0) return false;
    if (g_tmp_on && to_rt(g_tmp) == u.rip) return true;
    return !g_bp_off && bpm_at_rt(u.rip) >= 0;
}

static bool start(bool step, char *err, size_t esz) {
    if (!need_stopped(err, esz)) return false;
    /* what another thread met during the last stop is told first, nothing moves */
    for (int i = 0; i < g_nthr; i++) {
        if (!g_thr[i].pend) continue;
        int k = thr_index(g_tid);
        if (k >= 0) g_thr[k].dsig = g_sig;
        g_sig = 0;
        g_stepping = g_stepover = false;
        g_last_bp = -1;
        g_state = DBG_RUNNING;
        g_stop = DBG_STOP_NONE;
        settle(DBG_SETTLE_MS);
        return true;
    }
    g_stepping = step;
    g_stepover = false;
    g_last_bp = -1;
    if (!step) {
        if (on_bp()) g_stepping = g_stepover = true;   /* step past it first */
        else bp_insert_all();
    } else {
        struct user_regs_struct u;
        g_step_from = ptrace(PTRACE_GETREGS, g_tid, NULL, &u) == 0 ? u.rip : 0;
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
    if (ptrace(PTRACE_GETREGS, g_tid, NULL, &u) < 0) return false;
    regs_from(&u, r);
    return true;
#endif
}

/* GETREGS first: what DbgRegs does not carry (segments, fs_base, orig_rax...)
 * goes back as it is. TF stays the thread's (GETREGS hides a TF of ptrace's
 * own single step). A new rip: orig_rax -1, or the kernel would restart an
 * interrupted system call by moving the new rip back 2 bytes. */
bool dbg_set_regs(const DbgRegs *r) {
#ifndef DBG_OK
    (void)r;
    return false;
#else
    if (!r || dbg_state() != DBG_STOPPED) return false;
    if (g_bits == 32) {
        uint64_t hi = (r->rip | r->rsp | r->rbp | r->rax | r->rbx | r->rcx | r->rdx | r->rsi | r->rdi | r->rflags) >> 32;
        uint64_t ext = r->r8 | r->r9 | r->r10 | r->r11 | r->r12 | r->r13 | r->r14 | r->r15;
        if (hi || ext) return false;
    }
    struct user_regs_struct u;
    if (ptrace(PTRACE_GETREGS, g_tid, NULL, &u) < 0) return false;
    if (r->rip != u.rip) u.orig_rax = (unsigned long long)-1;
    u.rip = r->rip;  u.rsp = r->rsp;  u.rbp = r->rbp;
    u.rax = r->rax;  u.rbx = r->rbx;  u.rcx = r->rcx;  u.rdx = r->rdx;
    u.rsi = r->rsi;  u.rdi = r->rdi;
    const uint64_t tf = 0x100;                  /* trap flag */
    u.eflags = (r->rflags & ~tf) | (u.eflags & tf);
    if (g_bits != 32) {
        u.r8  = r->r8;   u.r9  = r->r9;   u.r10 = r->r10;  u.r11 = r->r11;
        u.r12 = r->r12;  u.r13 = r->r13;  u.r14 = r->r14;  u.r15 = r->r15;
    }
    return ptrace(PTRACE_SETREGS, g_tid, NULL, &u) == 0;
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
    /* one thread stops (the current one if it can), the others follow */
    DbgThr *t = NULL;
    for (int i = 0; i < g_nthr; i++) {
        DbgThr *c = &g_thr[i];
        if (c->stopped || c->zombie) continue;
        if (!t || c->tid == g_tid) t = c;
    }
    if (!t) { settle(0); return g_state == DBG_STOPPED; }
    if (!t->swallow) {                          /* not one still on its way */
        if (syscall(SYS_tgkill, g_pid, t->tid, SIGSTOP) < 0) { settle(0); return g_state == DBG_STOPPED; }
        t->swallow = true;
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
    /* a tracer is told of its tracee's death even when it is not its
     * parent: waitpid reaps ours and collects an attached one */
    if (g_pid > 0 && (g_state == DBG_STOPPED || g_state == DBG_RUNNING)) kill_all();
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

/* hooks of dbg_bp.h */

static bool bp_hook_can_change(char *err, size_t esz) {
#ifndef DBG_OK
    unavailable(err, esz);
    return false;
#else
    if (dbg_state() != DBG_RUNNING) return true;
    snprintf(err, esz, "The program is running (interrupt it first)");
    return false;
#endif
}

static bool bp_hook_stopped(void) {
    return dbg_state() == DBG_STOPPED;
}

/* `at` (process address) must be in a private executable mapping of the
 * stopped debuggee */
static bool bp_hook_check_code(uint64_t at, uint64_t shown, char *err, size_t esz) {
#ifndef DBG_OK
    (void)at; (void)shown; (void)err; (void)esz;
    return false;
#else
    maps_load();
    if (!g_maps_ok && !g_nmaps) { snprintf(err, esz, "/proc/%d/maps: %s", g_pid, strerror(errno)); return false; }
    switch (maps_state(at)) {
        case DBG_BPS_UNMAPPED:
            snprintf(err, esz, "0x%llx (0x%llx in the process) is not mapped in pid %d",
                     (unsigned long long)shown, (unsigned long long)at, g_pid);
            return false;
        case DBG_BPS_NOEXEC:
            snprintf(err, esz, "0x%llx is not code (no exec permission)", (unsigned long long)shown);
            return false;
        case DBG_BPS_SHARED:
            snprintf(err, esz, "0x%llx is in a shared mapping: a breakpoint would be written to the file", (unsigned long long)shown);
            return false;
        default:
            return true;
    }
#endif
}

static bool bp_hook_module_ok(char *err, size_t esz) {
#ifndef DBG_OK
    unavailable(err, esz);
    return false;
#else
    (void)err; (void)esz;
    return true;
#endif
}

static bool bp_hook_hw_ok(char *err, size_t esz) {
    return bp_hook_module_ok(err, esz);
}

static bool bp_hook_module_rt(const char *module, uint64_t rva, uint64_t *rt) {
#ifndef DBG_OK
    (void)module; (void)rva; (void)rt;
    return false;
#else
    return module_rt(module, rva, rt);
#endif
}

void dbg_bp_image(const char *path) {
    const char *sl = path ? strrchr(path, '/') : NULL;
    snprintf(g_prog, sizeof g_prog, "%.*s", DBG_MOD_MAX - 1, sl ? sl + 1 : path ? path : "");
#ifdef DBG_OK
    static ElfInfo e;
    uint64_t lo, hi;
    if (path && elf_read(path, &e)) {
        g_bits = e.bits;
        if (elf_span(&e, page_size(), &lo, &hi)) { bpm_rebase(lo); return; }
    } else
        g_bits = 0;
    bpm_rebase(0);
#endif
}

/* ---- memory ------------------------------------------------------------ */

void dbg_mask_int3(int pid, uint64_t rt, void *buf, size_t n) {
#ifndef DBG_OK
    (void)pid; (void)rt; (void)buf; (void)n;
#else
    if (pid != g_pid || pid <= 0) return;
    for (int i = 0; i < g_nins; i++)
        if (g_ins[i] >= rt && g_ins[i] - rt < n) ((uint8_t *)buf)[g_ins[i] - rt] = g_orig[i];
#endif
}

bool dbg_read_mem(uint64_t rt, void *buf, size_t n) {
#ifndef DBG_OK
    (void)rt; (void)buf; (void)n;
    return false;
#else
    if (!buf || !n || g_pid <= 0 || !(g_state == DBG_STOPPED || g_state == DBG_RUNNING)) return false;
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/mem", g_pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    ssize_t got = pread(fd, buf, n, (off_t)rt);
    close(fd);
    if (got != (ssize_t)n) return false;
    dbg_mask_int3(g_pid, rt, buf, n);
    return true;
#endif
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

bool dbg_run_to(uint64_t addr, char *err, size_t esz) {
    err[0] = '\0';
#ifndef DBG_OK
    (void)addr;
    unavailable(err, esz);
    return false;
#else
    if (!need_stopped(err, esz)) return false;
    if (!bp_hook_check_code(to_rt(addr), addr, err, esz)) return false;
    struct user_regs_struct u;
    if (ptrace(PTRACE_GETREGS, g_tid, NULL, &u) < 0) {
        snprintf(err, esz, "ptrace(GETREGS): %s", strerror(errno));
        return false;
    }
    g_tmp = addr;
    g_tmp_rsp = u.rsp;
    g_tmp_tid = g_tid;
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

/* ---- mappings ---------------------------------------------------------- */

bool dbg_map_name(uint64_t rt, char *out, size_t sz) {
#ifndef DBG_OK
    (void)rt; (void)out; (void)sz;
    return false;
#else
    if (!out || !sz || g_pid <= 0 || !(g_state == DBG_STOPPED || g_state == DBG_RUNNING)) return false;
    char p[64], line[PATH_MAX + 128];
    snprintf(p, sizeof p, "/proc/%d/maps", g_pid);
    FILE *f = fopen(p, "r");
    if (!f) return false;
    bool ok = false;
    while (!ok && fgets(line, sizeof line, f)) {
        unsigned long long lo, hi;
        int n = 0;
        if (sscanf(line, "%llx-%llx %*s %*s %*s %*s %n", &lo, &hi, &n) < 2 || !n) continue;
        if (rt < lo || rt >= hi) continue;
        char *nm = line + n;
        nm[strcspn(nm, "\n")] = '\0';
        snprintf(out, sz, "%s", nm);
        ok = true;
    }
    fclose(f);
    return ok;
#endif
}

