/* Minimal ptrace debugger for the F9 view. Linux x86-64 Abyss debugs ELF64
 * (x86-64) and ELF32 (i386) programs; dbg_win.c, same interface, PE32+
 * (x64) and PE32 (i386, through WOW64).
 *
 * One debuggee at a time, started by dbg_launch (fork + PTRACE_TRACEME +
 * execv): it stops right after the exec, before the dynamic loader runs.
 * Its stdin / stdout / stderr are a pseudo-terminal that only Abyss
 * reads and writes (dbg_console_read / dbg_console_write), so it cannot
 * draw over the TUI. PTRACE_O_EXITKILL: it dies with Abyss. An i386 program
 * whose loader /lib/ld-linux.so.2 is not installed runs under the i386
 * loader carried by the Linux executable (ld-linux.so.2, libc.so.6...,
 * written to $XDG_CACHE_HOME/abyss/; see dbg.c): stopped once ld.so has
 * mapped it, before its libraries.
 *
 * Addresses: every address passed in (breakpoints, dbg_run_to) is a
 * virtual address of the ELF file, as disview.c shows it. After the
 * launch, dbg.c finds the load base of the program in /proc/pid/maps
 * (auxv AT_ENTRY as a fallback) and adds the ASLR offset itself (0 for a
 * non-PIE ET_EXEC). Registers come back as they are in the process:
 * dbg_to_file turns rip (or any pointer) back into a file address.
 *
 * Resuming never blocks the UI: dbg_cont / dbg_step / dbg_run_to resume
 * the process and wait at most DBG_SETTLE_MS for it to stop; a program
 * still running after that is DBG_RUNNING, and dbg_poll (non-blocking,
 * to call from the wgetch loop, see dbg_ui_timeout) reports its next
 * stop. Breakpoints (int3) are only written while the process runs and
 * are taken out at every stop, so its memory always shows the original
 * bytes while it is stopped. They are kept across relaunches, stored as
 * an offset in their module (DbgBp.rva) and placed again from the load base
 * of each new process. A byte that is no longer 0xCC when it comes out was
 * rewritten by the program (self-modifying code): it is left as it is and
 * reported (DbgBp.overwritten). dbg_read_mem never shows an int3 of ours,
 * even while the process runs. The file on disk is never written, and an
 * address in a shared mapping (a write there would reach the file) is
 * refused.
 *
 * Threads: all the threads of the debuggee are traced and stop together;
 * the registers and dbg_step are those of the thread of the last stop
 * (dbg_status names it when it is not the first). dbg_step moves that thread
 * alone (Linux: the others stay stopped; Windows: they are suspended for the
 * step): when it blocks on another thread, dbg_interrupt gets it back.
 *
 * Limits: child processes are not traced (a child that reaches a breakpoint
 * written at the time of its fork dies of SIGTRAP, its parent lives on); a
 * second exec from the program disables the breakpoints; breakpoints cannot be changed while
 * the program runs (dbg_interrupt it first); a module loaded by dlopen is
 * only resolved at the next stop of the program.
 *
 * Other systems: every call fails with "débogueur indisponible sous
 * Windows" (or "Linux x86-64 uniquement"). */
#ifndef DBG_H
#define DBG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define DBG_MAX_BP     256
#define DBG_MAX_HW     4       /* DR0-DR3                                   */
#define DBG_MOD_MAX    64      /* module name, with its final NUL           */
#define DBG_COND_MAX   48      /* condition as text, with its final NUL     */
#define DBG_SETTLE_MS  100     /* how long a resume waits for the next stop */

typedef enum {
    DBG_NONE,                  /* no debuggee                                */
    DBG_STOPPED,               /* stopped: registers, breakpoints, resume    */
    DBG_RUNNING,               /* running: dbg_poll reports the next stop    */
    DBG_EXITED                 /* exited or killed: dbg_status says how      */
} DbgState;

typedef enum {
    DBG_STOP_NONE,
    DBG_STOP_EXEC,             /* right after the exec (dbg_launch)          */
    DBG_STOP_BP,               /* on a breakpoint (rip = its address)        */
    DBG_STOP_TEMP,             /* dbg_run_to reached its address             */
    DBG_STOP_STEP,             /* dbg_step done                              */
    DBG_STOP_SIGNAL,           /* a signal: delivered on the next resume     */
    DBG_STOP_INTERRUPT         /* dbg_interrupt                              */
} DbgStop;

/* 32-bit process: eip... zero-extended, r8-r15 are 0 (see dbg_bits) */
typedef struct {
    uint64_t rip, rsp, rbp, rax, rbx, rcx, rdx, rsi, rdi, rflags;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
} DbgRegs;

typedef enum {
    DBG_BPS_IDLE,              /* no process, or disabled                    */
    DBG_BPS_OK,                /* placed at the last resume                  */
    DBG_BPS_PENDING,           /* its module is not loaded (yet)             */
    DBG_BPS_UNMAPPED,          /* nothing mapped there: not placed           */
    DBG_BPS_NOEXEC,            /* not code: not placed                       */
    DBG_BPS_SHARED,            /* shared mapping (the file): not placed      */
    DBG_BPS_HWFAIL             /* the debug registers refused it             */
} DbgBpState;

typedef struct {
    uint64_t   va;             /* file address (program); other module: 0    */
    uint64_t   rva;            /* offset in its module                       */
    uint64_t   rt;             /* process address, 0: none now               */
    char       module[DBG_MOD_MAX];   /* file name of the module             */
    bool       main;           /* of the program                             */
    bool       enabled;
    bool       hw;             /* debug register instead of an int3          */
    bool       overwritten;    /* the program rewrote the int3 at some point */
    DbgBpState state;
    uint64_t   hits;           /* arrivals in this process, condition met or not: by
                                * an int3, a debug register or a step landing on it;
                                * leaving it does not count */
    bool       has_cond;       /* stops only when the condition holds        */
    uint8_t    creg, cwidth, cop;
    uint64_t   cval;
    char       cond[DBG_COND_MAX];    /* as text, "" : none                  */
} DbgBp;

/* Starts `path` stopped at its exec (argv NULL: { path, NULL }). A
 * previous debuggee is killed first. */
bool     dbg_launch(const char *path, char *const argv[], char *err, size_t esz);
void     dbg_kill(void);                   /* kills and reaps; -> DBG_NONE */
/* Takes a running process with PTRACE_ATTACH and stops it (ptrace rights
 * needed, see kernel.yama.ptrace_scope). A previous debuggee is let go
 * first, as by dbg_detach. */
bool     dbg_attach(int pid, char *err, size_t esz);
/* Lets the debuggee go -> DBG_NONE: an attached process is detached and
 * resumes; one started by dbg_launch is killed and reaped. */
void     dbg_detach(void);

DbgState dbg_state(void);
DbgStop  dbg_stop_reason(void);            /* of the last stop             */
int      dbg_pid(void);                    /* 0: none                      */
/* One line: "breakpoint at 0x401136", "running (pid 1234)",
 * "exited with code 0", "killed by signal 11 (Segmentation fault)",
 * "stopped by signal 11 (Segmentation fault, address 0x1c8)" (the
 * address it faulted on, for a SIGSEGV / SIGBUS from the kernel)... */
void     dbg_status(char *out, size_t sz);

/* Non-blocking: collects the stop of a running debuggee. true when the
 * state changed (redraw). */
bool     dbg_poll(void);
/* wgetch timeout while the debuggee runs (so dbg_poll gets called), -1
 * otherwise. */
int      dbg_ui_timeout(void);

/* Resume a stopped debuggee. true: resumed (look at dbg_state: it may
 * have stopped again or exited already). A signal that stopped it is
 * delivered now. */
bool     dbg_cont(char *err, size_t esz);
bool     dbg_step(char *err, size_t esz);          /* one instruction    */
/* Runs until `addr` (file address) is reached in the current frame or
 * an outer one (rsp >= its value now: a recursive call does not stop
 * there), or something else stops it. The step over of a call: run to
 * the instruction after it. */
bool     dbg_run_to(uint64_t addr, char *err, size_t esz);
bool     dbg_interrupt(void);                      /* SIGSTOP a running one */

/* Breakpoints, by file address. Allowed without a debuggee (checked
 * against the code of the program when one is stopped), refused while it
 * runs. */
bool     dbg_bp_add(uint64_t addr, char *err, size_t esz);
bool     dbg_bp_remove(uint64_t addr, char *err, size_t esz);
bool     dbg_bp_has(uint64_t addr);
/* the program's (ascending, file addresses), then the other modules'
 * (process address, 0 until resolved); returns n, out NULL: their number */
int      dbg_bp_list(uint64_t *out, int max);
void     dbg_bp_clear(void);

/* Tells the model which program the breakpoints belong to, before any
 * process: its name (module of the program) and link base (for the rvas). */
void     dbg_bp_image(const char *path);
/* A breakpoint in another module, by file name and offset from the start of
 * that module, e.g. ("libc.so.6", 0x2a1c0). Pending until the module is
 * mapped (looked up at every resume, and at the entry point of a dynamic
 * program). Linux only: refused on Windows. The name of the program itself
 * means an ordinary breakpoint. */
bool     dbg_bp_add_module(const char *module, uint64_t rva, char *err, size_t esz);
/* The list by index (0 .. dbg_bp_list(NULL, 0) - 1), which changes when a
 * breakpoint is added or removed; -1: none there. */
int      dbg_bp_index(uint64_t addr);
int      dbg_bp_index_module(const char *module, uint64_t rva);
bool     dbg_bp_info(int i, DbgBp *out);
bool     dbg_bp_remove_i(int i, char *err, size_t esz);
bool     dbg_bp_enable_i(int i, bool on, char *err, size_t esz);
/* cond: "<reg> <op> <number>" (rax == 0x10, eax != 0, hits >= 3), unsigned;
 * NULL or "": no condition. A pass where it is false only counts in hits; a
 * step landing there counts too, and is reported as a step in any case. */
bool     dbg_bp_cond_i(int i, const char *cond, char *err, size_t esz);
/* Debug register (DR0-DR3) instead of an int3: no byte written. Linux only:
 * refused on Windows. */
bool     dbg_bp_hw_i(int i, bool on, char *err, size_t esz);
int      dbg_bp_stopped_on(void);                  /* index, last stop; -1: none */
/* A breakpoint that could not be placed or was overwritten since the last
 * call: one line for the user. false: nothing new. */
bool     dbg_bp_take_news(char *out, size_t sz);

/* Console of a debuggee started by dbg_launch (a pty: echo and line
 * editing like a terminal, "\r\n" line ends). dbg_console_read takes what
 * the program wrote, without blocking (0: nothing now); it still works
 * after the exit, until the next launch / kill / detach. dbg_console_write
 * sends input while the program lives: a line ends with "\n", "\x03" is
 * Ctrl-C (SIGINT), "\x04" Ctrl-D (end of input). Both return -1 when
 * there is no console (attached process, closed, other systems). */
long     dbg_console_read(char *buf, size_t sz);
long     dbg_console_write(const char *buf, size_t n);

/* Registers of a stopped debuggee (values of the process). */
bool     dbg_get_regs(DbgRegs *r);
/* Writes them (thread of the last stop, as dbg_get_regs): take them with
 * dbg_get_regs, change some, write them all back. The trap flag of rflags
 * stays the debugger's (the thread's own is kept); the system may drop other
 * flag bits. A 32-bit process: every value must fit in 32 bits and r8-r15 be
 * 0, else false and nothing written. When rip changes, a system call the
 * stop interrupted is not restarted on the resume (Linux: orig_rax -1, as gdb
 * does). false: not stopped, refused, or the system refused. */
bool     dbg_set_regs(const DbgRegs *r);
/* 32 / 64: architecture of the debuggee (of dbg_bp_image's program before
 * the launch), 0 when unknown. */
int      dbg_bits(void);
/* link base of the program (lowest PT_LOAD page, ImageBase): file address =
 * this + rva */
uint64_t dbg_link_base(void);
/* n bytes of its memory at process address rt, as the program wrote them:
 * int3 bytes of ours are replaced by the original ones, while it runs too.
 * false: not all of them are readable, or no debuggee. */
bool     dbg_read_mem(uint64_t rt, void *buf, size_t n);
/* Same mask on bytes read at rt by someone else (the F8 view), when `pid` is
 * the debuggee. */
void     dbg_mask_int3(int pid, uint64_t rt, void *buf, size_t n);

/* Path of the mapping of the debuggee holding process address rt
 * ("/usr/lib/libc.so.6", "" for anonymous memory). false: nothing mapped
 * there, no debuggee, or another system. */
bool     dbg_map_name(uint64_t rt, char *out, size_t sz);

/* ASLR offset: process address = file address + dbg_load_delta(). */
uint64_t dbg_load_delta(void);
uint64_t dbg_to_rt(uint64_t file_addr);
/* false when `rt` is not inside the program's image (libc, stack...) */
bool     dbg_to_file(uint64_t rt, uint64_t *file_addr);

#endif
