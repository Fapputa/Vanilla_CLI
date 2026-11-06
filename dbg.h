/* Minimal ptrace debugger for the F9 view (Linux x86-64 only).
 *
 * One debuggee at a time, started by dbg_launch (fork + PTRACE_TRACEME +
 * execv): it stops right after the exec, before the dynamic loader runs.
 * Its stdin / stdout / stderr are a pseudo-terminal that only Abyss
 * reads and writes (dbg_console_read / dbg_console_write), so it cannot
 * draw over the TUI. PTRACE_O_EXITKILL: it dies with Abyss.
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
 * bytes while it is stopped. They are kept across relaunches.
 *
 * Limits: the threads and children of the debuggee are not traced (a
 * breakpoint hit by one of them kills the process with SIGTRAP); a
 * second exec from the program disables the breakpoints; breakpoints
 * cannot be added or removed while the program runs (dbg_interrupt it
 * first).
 *
 * Other systems: every call fails with "débogueur indisponible sous
 * Windows" (or "Linux x86-64 uniquement"). */
#ifndef DBG_H
#define DBG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define DBG_MAX_BP     256
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

typedef struct {
    uint64_t rip, rsp, rbp, rax, rbx, rcx, rdx, rsi, rdi, rflags;
} DbgRegs;

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
int      dbg_bp_list(uint64_t *out, int max);      /* ascending, returns n */
void     dbg_bp_clear(void);

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

/* ASLR offset: process address = file address + dbg_load_delta(). */
uint64_t dbg_load_delta(void);
uint64_t dbg_to_rt(uint64_t file_addr);
/* false when `rt` is not inside the program's image (libc, stack...) */
bool     dbg_to_file(uint64_t rt, uint64_t *file_addr);

#endif
