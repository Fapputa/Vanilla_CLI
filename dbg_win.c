/* Debugger of the F9 view, Windows version: same interface as dbg.c
 * (dbg.h), on the native Win32 debugging API instead of ptrace. Built in
 * place of dbg.c by the Windows Makefile; the whole file is behind
 * _WIN32, so it compiles to nothing anywhere else.
 *
 * Done here: dbg_launch, dbg_attach, dbg_detach, dbg_kill, dbg_state,
 * dbg_status, dbg_pid, dbg_stop_reason, dbg_poll, dbg_ui_timeout,
 * dbg_cont, dbg_step, dbg_run_to, dbg_interrupt, dbg_get_regs, the
 * breakpoints, the load base (dbg_load_delta, dbg_to_rt, dbg_to_file).
 * Not yet (they return false / -1, as dbg.c does on Windows): console,
 * mappings.
 *
 * Load base: F9 shows the addresses of the file, ImageBase + RVA (see
 * peload.c). The program is mapped at lpBaseOfImage of its
 * CREATE_PROCESS_DEBUG_EVENT (for an attach: the base of the module
 * whose path is the program's, from EnumProcessModules, or
 * EnumProcessModulesEx(LIST_MODULES_ALL) for a 32-bit (WOW64) program,
 * that event as a fallback). g_base_addr = that base - the ImageBase of the file, read in
 * the PE header of the hFile of the event (the path when there is none,
 * the header in memory as a last resort: the loader may have written the
 * real base there). g_img_lo / g_img_hi: ImageBase, + SizeOfImage, for
 * dbg_to_file.
 *
 * Breakpoints: the dbg.c model, the list is in dbg_bp.h (rva from
 * ImageBase, enabled, hits, condition; kept across launches: the base
 * changes each time). Not handled here, refused with a message: other
 * modules than the program, hardware breakpoints (the debug registers are
 * per thread, every thread would have to be followed). The int3
 * bytes go in (ReadProcessMemory of the original byte, WriteProcessMemory
 * of 0xCC, FlushInstructionCache) just before a dbg_cont / dbg_run_to
 * resume and come out again at every reported stop (stop_on), so a
 * stopped process always shows its own code. Each address is first
 * checked with VirtualQueryEx: not committed, not executable or a mapped
 * file view is left out and told (DbgBp.state, dbg_bp_take_news). A byte
 * that is not 0xCC when it comes out was rewritten by the program: left
 * as it is (DbgBp.overwritten). g_ins records what is in
 * memory now. A hit (EXCEPTION_BREAKPOINT at an address of g_ins) puts
 * rip of that thread back onto the breakpoint (SetThreadContext, the
 * exception leaves it one past the int3) and counts a pass; a false
 * condition steps over it and goes on. Resuming a thread whose rip is
 * on a breakpoint first single-steps it (trap flag) with nothing
 * written, then writes them all and goes on (g_stepover). dbg_step
 * writes none. The temporary breakpoint of dbg_run_to only stops in the
 * thread that asked, when rsp >= its value then (a deeper frame steps
 * over it and goes on); any reported stop ends it.
 *
 * Threads and breakpoints: while a thread steps over a breakpoint (no int3
 * in memory), every other thread known here (from CREATE_PROCESS and
 * CREATE_THREAD, out at EXIT_THREAD) is held: SuspendThread before the
 * resume, ResumeThread once the single step is done and the bytes are back
 * (g_hold), so no thread passes a breakpoint while its int3 is out. A
 * thread created meanwhile is held from its CREATE_THREAD; one that ends
 * while held is resumed and dropped at its EXIT_THREAD. The stepping thread
 * ending during its step (step over or dbg_step) ends the step: the int3
 * bytes go back, then the others are released; if one cannot be written
 * back, the debuggee stops on that EXIT_THREAD instead (DBG_STOP_INTERRUPT,
 * why in dbg_bp_take_news, nothing held, no int3 in). Two threads can
 * hit int3 bytes at once: the second hit arrives after the bytes went out.
 * During a hold it is not reported: rip goes back onto the int3 and the
 * thread stays held, so it traps again once the bytes are in (one stop,
 * one hit, and the step over of the first thread is not cut short).
 * Outside a hold it is reported (an int3 exception at a breakpoint whose
 * byte, back in memory, is not 0xCC is still ours, rip put back). The hold
 * also ends at every reported stop (a stop that cuts a step over short, the
 * end of the process), before a kill, when a process is let go, and before
 * dbg_interrupt asks for its break-in (that thread must run; the int3 bytes
 * go back first, see below), so no thread is left suspended: a step over
 * whose one instruction blocks keeps the others held until dbg_interrupt or
 * a kill.
 * A SuspendThread that fails on a live thread refuses the resume (dbg_cont
 * / dbg_run_to say why, nothing stays held); a ResumeThread that fails
 * twice on a live thread is told (dbg_bp_take_news) and tried again at
 * every later end of a hold. dbg_step holds the other threads the same way
 * (it writes no int3, but another thread's int3 trap queued before the
 * stop it resumes would otherwise cut its step short before it ran: that
 * thread stays on the breakpoint and traps there again, the same pass
 * reported twice); like the single step of dbg.c, only the current thread
 * moves. Limit, not handled: an instruction that waits for another thread
 * (a syscall, a lock held by a held thread) never ends under dbg_step
 * either: DBG_RUNNING, the others held, until dbg_interrupt or a kill.
 * dbg_interrupt then holds the stepping thread too (its trap flag and rip
 * kept), writes the int3 bytes back and only then releases the others
 * (hold_back_in), so none passes a breakpoint: one held on its int3 after
 * a trap (rip put back) traps again and stops. The stop ends the step and
 * the hold. A stepping thread that had not begun its instruction (rip
 * still where the step began, an int3 there now) traps there when it next
 * runs: that trap is its departure (g_dep_tid), not a pass: no hit, no
 * stop, it steps over it. If the stepping thread cannot be held or an int3
 * cannot be written back, nothing changes (the bytes out again, the step
 * going on, the others held): dbg_interrupt fails and says why
 * (dbg_bp_take_news).
 * The single-step of a step that another stop cut short is swallowed when
 * it comes (g_late_tid).
 *
 * Model: Windows freezes every thread of the debuggee from the moment a
 * debug event is reported until the debugger answers it with
 * ContinueDebugEvent. "Stopped" is exactly that: one event received and
 * not continued yet (g_ev_pid / g_ev_tid, g_ev_pending). dbg_launch and
 * dbg_attach both stop on the CREATE_PROCESS_DEBUG_EVENT, the first event
 * of a debuggee (for a launch: before ntdll's loader has run, like the
 * stop at exec of dbg.c).
 *
 * Resume (dbg_cont / dbg_step): the pending event is continued, then
 * settle() answers the events that follow for DBG_SETTLE_MS at most, as
 * dbg.c does with waitpid; a program still going after that is
 * DBG_RUNNING and dbg_poll (WaitForDebugEvent 0) takes the rest. LOAD_DLL,
 * UNLOAD_DLL, CREATE_THREAD, EXIT_THREAD, OUTPUT_DEBUG_STRING go on
 * silently; EXIT_PROCESS -> DBG_EXITED; EXCEPTION_SINGLE_STEP ->
 * DBG_STOP_STEP; EXCEPTION_BREAKPOINT -> DBG_STOP_BP (an int3 /
 * __debugbreak of the program: rip is already past it, resuming goes on
 * after it), except the ones the system raises for the debugger, which
 * are answered without stopping: the loader breakpoint of a launch (the
 * first one; a WOW64 debuggee under Windows also raises a second one,
 * STATUS_WX86_BREAKPOINT in its 32-bit ntdll, see sys_bp), the break-in
 * thread of an attach and of DebugBreakProcess (at ntdll!DbgBreakPoint;
 * WOW64: also the 32-bit ntdll's). Any other exception is passed on to the
 * program (DBG_EXCEPTION_NOT_HANDLED) without stopping: a crash ends as
 * DBG_EXITED with its NTSTATUS.
 *
 * Threads: the registers (and dbg_step) are those of the thread that
 * stopped; after dbg_interrupt (which stops in the injected break-in
 * thread) those of the first thread of the process, while it lives. Every
 * thread runs during a dbg_step, only the stepped one has the trap flag (a
 * step over of a breakpoint holds the others, see above).
 * 32-bit (WOW64) programs: launched and attached like x64 ones; g_wow64
 * (IsWow64Process, at load_base / module_base) sends their registers
 * through the Wow64 calls (ctx_get / ctx_set: Wow64Get/SetThreadContext,
 * never Wow64SuspendThread), takes STATUS_WX86_BREAKPOINT /
 * STATUS_WX86_SINGLE_STEP as an int3 / a single step, and the second
 * loader breakpoint of the 32-bit ntdll (sys_bp). Checked on a mock of
 * the API and under Wine only, not on a Windows machine.
 *
 * Launch: CreateProcessA with DEBUG_ONLY_THIS_PROCESS (DEBUG_PROCESS
 * would also debug every child the program starts, and nothing here
 * would ever answer their events: they would hang) and CREATE_NEW_CONSOLE
 * (the program gets its own console window, so it cannot draw over the
 * TUI; dbg_console_read / write return -1). DebugSetProcessKillOnExit
 * TRUE: it dies with Abyss, like PTRACE_O_EXITKILL.
 *
 * Attach: DebugActiveProcess, then the CREATE_PROCESS_DEBUG_EVENT that the
 * system makes up for the running process. DebugSetProcessKillOnExit
 * FALSE: if Abyss quits, the process is let go, not killed.
 *
 * Detach: an attached process is given back running (pending event
 * continued, then DebugActiveProcessStop). A running one is interrupted
 * first, as dbg.c does, which takes the int3 bytes out (if that fails
 * they are taken out while it runs). A process started by
 * dbg_launch is killed (TerminateProcess) and its events drained up to
 * EXIT_PROCESS_DEBUG_EVENT, as dbg.c kills and reaps its child.
 *
 * Thread: WaitForDebugEvent / ContinueDebugEvent only work in the thread
 * that called CreateProcess / DebugActiveProcess: every dbg_* call must
 * come from the same thread (the UI thread). The longest waits are for
 * the first event (DBG_START_MS), for the end of a killed process
 * (DBG_KILL_MS) and for the break-in of dbg_interrupt (DBG_INTR_MS).
 *
 * Paths and messages are in the ANSI code page, like winproc.c. */
#ifdef _WIN32

#include "dbg.h"
#include <windows.h>
#define PSAPI_VERSION 2        /* EnumProcessModules = K32EnumProcessModules (kernel32) */
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "dbg_bp.h"            /* the list, g_base_addr */

#define DBG_POLL_MS   50       /* wgetch timeout while the debuggee runs      */
#define DBG_START_MS  10000    /* launch / attach: longest wait, first event  */
#define DBG_KILL_MS   3000     /* kill: longest wait for the exit             */
#define DBG_INTR_MS   1000     /* dbg_interrupt: longest wait for the break-in */
#define DBG_TF        0x100    /* trap flag of EFlags                          */
#define DBG_WX86_BREAKPOINT 0x4000001Fu  /* loader breakpoint of a WOW64 program */
#define DBG_SETTLE_EXTRA 64    /* events still taken once the wait time is out */
#define DBG_PASS_MS   2        /* settle: wait for the next silent pass        */

static DbgState g_state   = DBG_NONE;
static DbgStop  g_stop    = DBG_STOP_NONE;
static int      g_pid     = 0;
static bool     g_ours    = false;     /* started by dbg_launch                */
static int      g_lastpid = 0;         /* pid shown once the debuggee is gone  */
static HANDLE   g_hproc   = NULL;      /* our own handle on the process        */
static HANDLE   g_hthread = NULL;      /* our own handle on its first thread   */
static DWORD    g_exit    = 0;         /* exit code, once DBG_EXITED           */
static bool     g_exit_ok = false;     /* g_exit is known                      */

/* the debug event the debuggee is stopped on (not continued yet) */
static bool     g_ev_pending = false;
static DWORD    g_ev_pid  = 0;
static DWORD    g_ev_tid  = 0;

static DWORD    g_main_tid = 0;        /* first thread (g_hthread), 0 once it ended */
static DWORD    g_cur_tid  = 0;        /* thread of dbg_get_regs / dbg_step        */
static DWORD    g_step_tid = 0;        /* thread whose trap flag dbg_step set      */
static bool     g_sys_bp   = false;    /* the loader breakpoint is still to come   */
static bool     g_sys_wx86 = false;    /* WOW64: the 32-bit ntdll's may follow (sys_bp) */
static uint64_t g_brk32    = 0;        /* WOW64: its DbgBreakPoint, 0: unknown (break_addr) */
static int      g_brk_pending = 0;     /* break-in breakpoints still to come       */
static bool     g_intr     = false;    /* dbg_interrupt waits for one              */
static uint64_t g_stop_rip = 0;        /* rip (or int3 address) of the last stop   */

/* load base (see the top of the file) */
static uint64_t g_img_lo = 0;          /* file addresses of the image,         */
static uint64_t g_img_hi = 0;          /* [lo, hi); hi 0: unknown              */

/* breakpoints (see the top of the file) */
static uint64_t g_ins[DBG_MAX_BP + 1]; /* int3 written there (process addr)    */
static uint8_t  g_orig[DBG_MAX_BP + 1];/* the byte it replaced                 */
static int      g_nins = 0;
static bool     g_tmp_on  = false;     /* dbg_run_to in progress               */
static uint64_t g_tmp     = 0;         /* its file address                     */
static uint64_t g_tmp_rsp = 0;         /* rsp when it was asked                */
static DWORD    g_tmp_tid = 0;         /* in that thread                       */
static bool     g_stepover = false;    /* g_step_tid only gets past a breakpoint */
static DWORD    g_late_tid = 0;        /* its step cut short: the trap may still come */
static uint64_t g_step_from = 0;       /* rip before the step (over) in progress */
static DWORD    g_dep_tid = 0;         /* held by dbg_interrupt before its step began: */
static uint64_t g_dep_at  = 0;         /* its next int3 trap there is no pass          */
static bool     g_pass = false;        /* settle: a silent pass, another comes soon */
static bool     g_wow64 = false;       /* a 32-bit (WOW64) debuggee: ctx_get / ctx_set use the Wow64 calls */

/* threads of the debuggee, for the hold of a step over (see the top of the file) */
typedef struct {
    DWORD  tid;
    HANDLE h;                          /* ours while it is held suspended, else NULL */
} DbgThr;
static DbgThr  *g_thr = NULL;
static int      g_nthr = 0, g_cthr = 0;
static bool     g_hold = false;        /* a step over holds the other threads      */

/* GetLastError() `e` as text, without the trailing ".\r\n" */
static void win_error(DWORD e, char *out, size_t sz) {
    if (!sz) return;
    out[0] = '\0';
    DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             NULL, e, 0, out, (DWORD)sz, NULL);
    while (n > 0 && (out[n - 1] == '\r' || out[n - 1] == '\n' || out[n - 1] == ' ' || out[n - 1] == '.'))
        out[--n] = '\0';
    if (n == 0) snprintf(out, sz, "error %lu", (unsigned long)e);
}

static void close_h(HANDLE *h) {
    if (*h) CloseHandle(*h);
    *h = NULL;
}

static void break_dll32(const DEBUG_EVENT *ev);   /* break_addr's, after the memory readers */

/* The handles an event hands to the debugger that it must close itself
 * (the hProcess / hThread of CREATE_PROCESS belong to the system). Every
 * event goes through here first: a WOW64 debuggee's LOAD_DLL is also
 * looked at for its 32-bit ntdll (break_dll32). */
static void close_event_files(DEBUG_EVENT *ev) {
    if (g_wow64 && ev->dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && ev->dwProcessId == (DWORD)g_pid) break_dll32(ev);
    if (ev->dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && ev->u.CreateProcessInfo.hFile)
        CloseHandle(ev->u.CreateProcessInfo.hFile);
    else if (ev->dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && ev->u.LoadDll.hFile)
        CloseHandle(ev->u.LoadDll.hFile);
}

/* Answer to an event we do not stop on: an exception goes on to the
 * program's own handlers, anything else just continues. */
static void continue_event(const DEBUG_EVENT *ev) {
    DWORD how = ev->dwDebugEventCode == EXCEPTION_DEBUG_EVENT ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
    ContinueDebugEvent(ev->dwProcessId, ev->dwThreadId, how);
}

static void continue_pending(void) {
    if (g_ev_pending) ContinueDebugEvent(g_ev_pid, g_ev_tid, DBG_CONTINUE);
    g_ev_pending = false;
}

static void thr_clear(void);

static void reset(void) {
    thr_clear();
    close_h(&g_hproc);
    close_h(&g_hthread);
    g_state = DBG_NONE;
    g_stop = DBG_STOP_NONE;
    g_pid = 0;
    g_ours = false;
    g_exit = 0;
    g_exit_ok = false;
    g_ev_pending = false;
    g_ev_pid = g_ev_tid = 0;
    g_main_tid = g_cur_tid = g_step_tid = 0;
    g_sys_bp = false;
    g_sys_wx86 = false;
    g_brk32 = 0;
    g_brk_pending = 0;
    g_intr = false;
    g_stop_rip = 0;
    g_nins = 0;                        /* the process they were in is gone */
    g_tmp_on = false;
    g_stepover = false;
    g_late_tid = 0;
    g_dep_tid = 0;
    g_wow64 = false;
    g_base_addr = 0;
    g_img_lo = g_img_hi = 0;
    bpm_session_end();
}

/* The debuggee is gone: keep its exit code for dbg_status (`code`: the
 * one of its EXIT_PROCESS event, NULL: ask its handle). The process
 * handle stays open (closed at the next launch / attach / detach). */
static void note_exit(const DWORD *code) {
    DWORD c = 0;
    if (code) { c = *code; g_exit_ok = true; }
    else g_exit_ok = g_hproc && GetExitCodeProcess(g_hproc, &c) && c != STILL_ACTIVE;
    g_exit = g_exit_ok ? c : 0;
    g_state = DBG_EXITED;
    g_stop = DBG_STOP_NONE;
    g_lastpid = g_pid;
    g_pid = 0;
    g_ours = false;
    g_ev_pending = false;
    g_step_tid = 0;
    g_sys_bp = false;
    g_sys_wx86 = false;
    g_brk_pending = 0;
    g_nins = 0;
    g_tmp_on = false;
    g_stepover = false;
    g_late_tid = 0;
    g_dep_tid = 0;
    thr_clear();                       /* resumes fail on the ended threads: handles closed */
    bpm_session_end();
}

/* ---- threads ----------------------------------------------------------- */

/* A handle on thread `tid` of the debuggee with context access; *own:
 * the caller closes it. */
static HANDLE thread_handle(DWORD tid, bool *own) {
    *own = false;
    if (!tid) return NULL;
    if (tid == g_main_tid && g_hthread) return g_hthread;
    HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME
                          | THREAD_QUERY_INFORMATION, FALSE, tid);
    *own = h != NULL;
    return h;
}

static bool get_ctx(DWORD tid, CONTEXT *c, DWORD flags) {
    bool own;
    HANDLE h = thread_handle(tid, &own);
    if (!h) return false;
    memset(c, 0, sizeof *c);
    c->ContextFlags = flags;
    bool ok = GetThreadContext(h, c) != 0;
    if (own) CloseHandle(h);
    return ok;
}

static bool set_tf_wow64(DWORD tid, bool on);     /* after the neutral context */

/* Sets or clears the trap flag of thread `tid`. Suspended meanwhile: it
 * may be running (dbg_detach of a running process). A WOW64 debuggee
 * (g_wow64): the 32-bit eflags, through ctx_get / ctx_set; an x64 one: the
 * CONTEXT_CONTROL read and write below, as before WOW64. */
static bool set_tf(DWORD tid, bool on) {
    bool own;
    HANDLE h = thread_handle(tid, &own);
    if (!h) return false;
    bool susp = SuspendThread(h) != (DWORD)-1;
    bool ok;
    if (g_wow64) {
        ok = set_tf_wow64(tid, on);
    } else {
        CONTEXT c;
        memset(&c, 0, sizeof c);
        c.ContextFlags = CONTEXT_CONTROL;
        ok = GetThreadContext(h, &c) != 0;
        if (ok) {
            if (on) c.EFlags |= DBG_TF; else c.EFlags &= ~(DWORD)DBG_TF;
            ok = SetThreadContext(h, &c) != 0;
        }
    }
    if (susp) ResumeThread(h);
    if (own) CloseHandle(h);
    return ok;
}

/* ---- the hold of a step over (see the top of the file) ---- */

static DbgThr *thr_find(DWORD tid) {
    for (int i = 0; i < g_nthr; i++) if (g_thr[i].tid == tid) return &g_thr[i];
    return NULL;
}

/* thread `tid` of the debuggee exists (NULL: no memory to note it) */
static DbgThr *thr_add(DWORD tid) {
    DbgThr *t = thr_find(tid);
    if (t) return t;
    if (g_nthr == g_cthr) {
        int n = g_cthr ? 2 * g_cthr : 16;
        DbgThr *p = realloc(g_thr, (size_t)n * sizeof *p);
        if (!p) return NULL;
        g_thr = p;
        g_cthr = n;
    }
    t = &g_thr[g_nthr++];
    t->tid = tid;
    t->h = NULL;
    return t;
}

static bool thr_ended(HANDLE h) {
    return WaitForSingleObject(h, 0) == WAIT_OBJECT_0;
}

/* Suspends thread t, held until thr_unhold. true: held, or it has ended
 * (nothing to hold); false: *e = the error. */
static bool thr_hold(DbgThr *t, DWORD *e) {
    if (t->h) return true;
    HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | SYNCHRONIZE, FALSE, t->tid);
    if (!h) { *e = GetLastError(); return *e == ERROR_INVALID_PARAMETER; }   /* no such thread now */
    if (SuspendThread(h) == (DWORD)-1) {
        *e = GetLastError();
        bool ended = thr_ended(h);
        CloseHandle(h);
        return ended;
    }
    t->h = h;
    return true;
}

/* Resumes thread t if held (a second try at once). false: ResumeThread
 * failed on a live thread, *e = the error: still held. */
static bool thr_unhold(DbgThr *t, DWORD *e) {
    if (!t->h) return true;
    for (int i = 0; i < 2; i++)
        if (ResumeThread(t->h) != (DWORD)-1) { close_h(&t->h); return true; }
    *e = GetLastError();
    if (thr_ended(t->h)) { close_h(&t->h); return true; }
    return false;
}

/* The hold ends: every held thread resumed (one a failed ResumeThread kept
 * is tried again; still failing, it is told). */
static void unhold_all(void) {
    g_hold = false;
    for (int i = 0; i < g_nthr; i++) {
        DWORD e = 0;
        if (thr_unhold(&g_thr[i], &e) || g_bp_news[0]) continue;
        char msg[96];
        win_error(e, msg, sizeof msg);
        snprintf(g_bp_news, sizeof g_bp_news, "ResumeThread failed (thread %lu still suspended, tried again at the next stop): %.50s",
                 (unsigned long)g_thr[i].tid, msg);
    }
}

/* A step (over) of thread `tid` begins: every other known thread is held.
 * false: one could not be (err says which and why), none is held. */
static bool hold_others(DWORD tid, char *err, size_t esz) {
    for (int i = 0; i < g_nthr; i++) {
        DWORD e = 0;
        if (g_thr[i].tid == tid || thr_hold(&g_thr[i], &e)) continue;
        DWORD bad = g_thr[i].tid;
        unhold_all();
        char msg[256];
        win_error(e, msg, sizeof msg);
        snprintf(err, esz, "SuspendThread (thread %lu): %s: not resumed, the step would let the other threads pass "
                 "the breakpoint", (unsigned long)bad, msg);
        return false;
    }
    g_hold = true;
    return true;
}

/* thread `tid` ended (EXIT_THREAD): resumed if held, out of the list */
static void thr_del(DWORD tid) {
    DbgThr *t = thr_find(tid);
    if (tid == g_dep_tid) g_dep_tid = 0;
    if (!t) return;
    if (t->h) { ResumeThread(t->h); close_h(&t->h); }
    *t = g_thr[--g_nthr];
}

/* the process is gone or let go: nothing held, the list emptied */
static void thr_clear(void) {
    unhold_all();
    for (int i = 0; i < g_nthr; i++) close_h(&g_thr[i].h);
    g_nthr = 0;
}

/* A dbg_step is over (done or cut short by another stop): trap flag out,
 * the threads a step over held resumed. */
static void end_step(void) {
    if (g_step_tid) set_tf(g_step_tid, false);
    g_step_tid = 0;
    g_stepover = false;
    unhold_all();
}

static bool set_rip_wow64(DWORD tid, uint64_t rip);   /* after the neutral context */

/* rip of thread `tid` (stopped) := rip. A WOW64 debuggee (g_wow64): the
 * 32-bit eip, through ctx_get / ctx_set (false, nothing written, for a rip
 * above 4 GiB); an x64 one: the CONTEXT_CONTROL read and write below, as
 * before WOW64. */
static bool set_rip(DWORD tid, uint64_t rip) {
    if (g_wow64) return set_rip_wow64(tid, rip);
    bool own;
    HANDLE h = thread_handle(tid, &own);
    if (!h) return false;
    CONTEXT c;
    memset(&c, 0, sizeof c);
    c.ContextFlags = CONTEXT_CONTROL;
    bool ok = GetThreadContext(h, &c) != 0;
    if (ok) {
        c.Rip = rip;
        ok = SetThreadContext(h, &c) != 0;
    }
    if (own) CloseHandle(h);
    return ok;
}

/* ---- neutral thread context (WOW64) --------------------------------------
 * One view of a thread's registers for both kinds of debuggee. g_wow64
 * false: an x64 thread, GetThreadContext / SetThreadContext, CONTEXT_FULL.
 * g_wow64 true: a 32-bit thread of a WOW64 process, Wow64GetThreadContext /
 * Wow64SetThreadContext, WOW64_CONTEXT_FULL (the 64-bit calls do not reach
 * its 32-bit registers on Windows); every field is the 32-bit register
 * zero-extended, r8..r15 are 0, and ctx_set refuses (false, nothing written,
 * GetLastError not set) a value that does not fit: a bit above 31, or
 * r8..r15 not 0. Wow64SuspendThread is never called (Wine 11.21 has it as a
 * stub that aborts the caller): SuspendThread works on WOW64 threads too.
 * The thread must be frozen (stopped on a debug event, or suspended).
 * ctx_set reads the full context first and changes only the fields below.
 * Only set_tf and set_rip (ctx_get / ctx_set), dbg_get_regs and bp_hit
 * (ctx_get, regs_from_ctx: esp and the condition registers), dbg_run_to
 * (ctx_get: esp) and the ip readers on_bp, stop_on, the EXIT_THREAD of a
 * stepping thread, the step count, start and hold_back_in (ctx_get, through
 * ip_wow64) use it, and only for a WOW64 debuggee (their g_wow64 branches);
 * an x64 debuggee keeps get_ctx and regs_from (CONTEXT directly), as before
 * WOW64. */

typedef struct {
    uint64_t ip, sp, flags;
    uint64_t ax, bx, cx, dx, si, di, bp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
} DbgCtx;

static void ctx_from64(const CONTEXT *c, DbgCtx *x) {
    x->ip = c->Rip;  x->sp = c->Rsp;  x->flags = c->EFlags;
    x->ax = c->Rax;  x->bx = c->Rbx;  x->cx = c->Rcx;  x->dx = c->Rdx;
    x->si = c->Rsi;  x->di = c->Rdi;  x->bp = c->Rbp;
    x->r8  = c->R8;  x->r9  = c->R9;  x->r10 = c->R10; x->r11 = c->R11;
    x->r12 = c->R12; x->r13 = c->R13; x->r14 = c->R14; x->r15 = c->R15;
}

static void ctx_to64(const DbgCtx *x, CONTEXT *c) {
    c->Rip = x->ip;  c->Rsp = x->sp;  c->EFlags = (DWORD)x->flags;
    c->Rax = x->ax;  c->Rbx = x->bx;  c->Rcx = x->cx;  c->Rdx = x->dx;
    c->Rsi = x->si;  c->Rdi = x->di;  c->Rbp = x->bp;
    c->R8  = x->r8;  c->R9  = x->r9;  c->R10 = x->r10; c->R11 = x->r11;
    c->R12 = x->r12; c->R13 = x->r13; c->R14 = x->r14; c->R15 = x->r15;
}

static void ctx_from32(const WOW64_CONTEXT *c, DbgCtx *x) {
    memset(x, 0, sizeof *x);               /* r8..r15 and the high halves: 0 */
    x->ip = c->Eip;  x->sp = c->Esp;  x->flags = c->EFlags;
    x->ax = c->Eax;  x->bx = c->Ebx;  x->cx = c->Ecx;  x->dx = c->Edx;
    x->si = c->Esi;  x->di = c->Edi;  x->bp = c->Ebp;
}

/* x fits a 32-bit context: nothing above bit 31, r8..r15 0 */
static bool ctx_fits32(const DbgCtx *x) {
    uint64_t hi = (x->ip | x->sp | x->flags | x->ax | x->bx | x->cx | x->dx | x->si | x->di | x->bp) >> 32;
    uint64_t ext = x->r8 | x->r9 | x->r10 | x->r11 | x->r12 | x->r13 | x->r14 | x->r15;
    return !hi && !ext;
}

static void ctx_to32(const DbgCtx *x, WOW64_CONTEXT *c) {
    c->Eip = (DWORD)x->ip;  c->Esp = (DWORD)x->sp;  c->EFlags = (DWORD)x->flags;
    c->Eax = (DWORD)x->ax;  c->Ebx = (DWORD)x->bx;  c->Ecx = (DWORD)x->cx;  c->Edx = (DWORD)x->dx;
    c->Esi = (DWORD)x->si;  c->Edi = (DWORD)x->di;  c->Ebp = (DWORD)x->bp;
}

/* registers of thread `tid` (frozen) -> *x; false: *x all 0 */
static bool ctx_get(DWORD tid, DbgCtx *x) {
    memset(x, 0, sizeof *x);
    bool own;
    HANDLE h = thread_handle(tid, &own);
    if (!h) return false;
    bool ok;
    if (g_wow64) {
        WOW64_CONTEXT c;
        memset(&c, 0, sizeof c);
        c.ContextFlags = WOW64_CONTEXT_FULL;
        ok = Wow64GetThreadContext(h, &c) != 0;
        if (ok) ctx_from32(&c, x);
    } else {
        CONTEXT c;
        memset(&c, 0, sizeof c);
        c.ContextFlags = CONTEXT_FULL;
        ok = GetThreadContext(h, &c) != 0;
        if (ok) ctx_from64(&c, x);
    }
    if (own) CloseHandle(h);
    return ok;
}

/* registers of thread `tid` (frozen) := *x (see above for WOW64) */
static bool ctx_set(DWORD tid, const DbgCtx *x) {
    if (g_wow64 && !ctx_fits32(x)) return false;
    bool own;
    HANDLE h = thread_handle(tid, &own);
    if (!h) return false;
    bool ok;
    if (g_wow64) {
        WOW64_CONTEXT c;
        memset(&c, 0, sizeof c);
        c.ContextFlags = WOW64_CONTEXT_FULL;
        ok = Wow64GetThreadContext(h, &c) != 0;
        if (ok) {
            ctx_to32(x, &c);
            ok = Wow64SetThreadContext(h, &c) != 0;
        }
    } else {
        CONTEXT c;
        memset(&c, 0, sizeof c);
        c.ContextFlags = CONTEXT_FULL;
        ok = GetThreadContext(h, &c) != 0;
        if (ok) {
            ctx_to64(x, &c);
            ok = SetThreadContext(h, &c) != 0;
        }
    }
    if (own) CloseHandle(h);
    return ok;
}

/* set_tf of a WOW64 debuggee (thread already suspended by set_tf): the
 * trap flag of the 32-bit eflags, the other registers written back as read */
static bool set_tf_wow64(DWORD tid, bool on) {
    DbgCtx x;
    if (!ctx_get(tid, &x)) return false;
    if (on) x.flags |= DBG_TF; else x.flags &= ~(uint64_t)DBG_TF;
    return ctx_set(tid, &x);
}

/* set_rip of a WOW64 debuggee: eip of the 32-bit context, the other
 * registers (esp, ebp, eflags and its trap flag...) written back as read */
static bool set_rip_wow64(DWORD tid, uint64_t rip) {
    DbgCtx x;
    if (!ctx_get(tid, &x)) return false;
    x.ip = rip;
    return ctx_set(tid, &x);
}

/* The ip readers of a WOW64 debuggee (on_bp, stop_on, the EXIT_THREAD of
 * a stepping thread, the step count, start, hold_back_in): *ip = eip of
 * thread `tid` (frozen), zero-extended, through ctx_get; false: *ip 0 */
static bool ip_wow64(DWORD tid, uint64_t *ip) {
    DbgCtx x;
    bool ok = ctx_get(tid, &x);            /* false: x all 0 */
    *ip = x.ip;
    return ok;
}

/* ---- memory, load base ------------------------------------------------- */

static bool mem_read(uint64_t at, void *buf, size_t n) {
    SIZE_T got = 0;
    return g_hproc && ReadProcessMemory(g_hproc, (LPCVOID)(uintptr_t)at, buf, n, &got) && got == n;
}

/* Writes byte `b` at process address `at` (WriteProcessMemory lifts the
 * page protection of the code itself), then flushes it from the
 * instruction cache; *old gets the byte that was there. */
static bool poke_byte(uint64_t at, uint8_t b, uint8_t *old) {
    uint8_t o;
    SIZE_T put = 0;
    if (!mem_read(at, &o, 1)) return false;
    if (!WriteProcessMemory(g_hproc, (LPVOID)(uintptr_t)at, &b, 1, &put) || put != 1) return false;
    FlushInstructionCache(g_hproc, (LPCVOID)(uintptr_t)at, 1);
    if (old) *old = o;
    return true;
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* PE header readers: `src` is a file handle / a process address */
typedef bool (*ReadAt)(void *src, uint64_t off, void *buf, DWORD n);

static bool read_file_at(void *src, uint64_t off, void *buf, DWORD n) {
    OVERLAPPED ov;                             /* a synchronous handle reads at this offset too */
    memset(&ov, 0, sizeof ov);
    ov.Offset = (DWORD)off;
    ov.OffsetHigh = (DWORD)(off >> 32);
    DWORD got = 0;
    return ReadFile((HANDLE)src, buf, n, &got, &ov) && got == n;
}

static bool read_mem_at(void *src, uint64_t off, void *buf, DWORD n) {
    return mem_read((uint64_t)(uintptr_t)src + off, buf, n);
}

/* ImageBase, SizeOfImage and width (64: PE32+, 32: PE32) of a PE header */
static bool pe_header(ReadAt rd, void *src, uint64_t *image_base, uint32_t *size, int *bits) {
    uint8_t mz[0x40], h[24 + 64];             /* "PE\0\0", COFF header, optional header */
    if (!rd(src, 0, mz, sizeof mz) || mz[0] != 'M' || mz[1] != 'Z') return false;
    uint32_t lfa = le32(mz + 0x3c);
    if (lfa > 0x10000000u || !rd(src, lfa, h, sizeof h) || memcmp(h, "PE\0\0", 4)) return false;
    const uint8_t *o = h + 24;
    unsigned magic = o[0] | o[1] << 8;
    if (magic == 0x20b) *image_base = (uint64_t)le32(o + 24) | (uint64_t)le32(o + 28) << 32;
    else if (magic == 0x10b) *image_base = le32(o + 28);
    else return false;
    *size = le32(o + 56);
    *bits = magic == 0x20b ? 64 : 32;
    return true;
}

/* the same from the file `path` */
static bool pe_header_path(const char *path, uint64_t *image_base, uint32_t *size, int *bits) {
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return false;
    bool ok = pe_header(read_file_at, f, image_base, size, bits);
    CloseHandle(f);
    return ok;
}

/* g_wow64: the process of g_hproc is a 32-bit one under WOW64
 * (IsWow64Process); false when that cannot be told (no handle, the call
 * fails): the x64 code. Never Wow64SuspendThread (a stub that aborts under
 * Wine). */
static void wow64_detect(void) {
    BOOL w = FALSE;
    g_wow64 = g_hproc && IsWow64Process(g_hproc, &w) && w;
}

/* Base of the module of the stopped process whose path is the program's
 * (EnumProcessModules: an attach, the loader has run); `exe` gets that
 * path ("" if unknown). Sets g_wow64 first: a WOW64 program is in the
 * 32-bit module list, EnumProcessModulesEx(LIST_MODULES_ALL) (the default
 * list of a 64-bit caller is the 64-bit one); x64: EnumProcessModules, as
 * before WOW64. */
static bool module_base(char *exe, DWORD esz, uint64_t *base) {
    static HMODULE mods[1024];
    char name[MAX_PATH * 2];
    DWORD need = 0;
    wow64_detect();
    if (!GetModuleFileNameExA(g_hproc, NULL, exe, esz)) { exe[0] = '\0'; return false; }
    if (g_wow64) {
        if (!EnumProcessModulesEx(g_hproc, mods, sizeof mods, &need, LIST_MODULES_ALL)) return false;
    } else if (!EnumProcessModules(g_hproc, mods, sizeof mods, &need)) return false;
    DWORD n = need / sizeof mods[0];
    if (n > sizeof mods / sizeof mods[0]) n = sizeof mods / sizeof mods[0];
    for (DWORD i = 0; i < n; i++)
        if (GetModuleFileNameExA(g_hproc, mods[i], name, sizeof name) && !_stricmp(name, exe)) {
            *base = (uint64_t)(uintptr_t)mods[i];
            return true;
        }
    return false;
}

/* Sets g_base_addr / g_img_lo / g_img_hi: the program is mapped at
 * process address `base` (0: unknown); its file is `hfile` (NULL: none)
 * or `path`. Nothing known: 0, dbg_to_file refuses everything. */
static void find_base(HANDLE hfile, const char *path, uint64_t base) {
    g_base_addr = 0;
    g_img_lo = g_img_hi = 0;
    if (!base) return;
    uint64_t ib = 0;
    uint32_t size = 0;
    int bits = 0;
    bool ok = hfile && pe_header(read_file_at, hfile, &ib, &size, &bits);
    if (!ok && path && *path) ok = pe_header_path(path, &ib, &size, &bits);
    if (!ok) ok = pe_header(read_mem_at, (void *)(uintptr_t)base, &ib, &size, &bits);
    if (!ok) return;
    g_bits = bits;
    g_link_lo = ib;
    g_base_addr = base - ib;
    if (size && ib <= UINT64_MAX - size) { g_img_lo = ib; g_img_hi = ib + size; }
}

/* A new process is stopped: 32-bit or not (g_wow64, from g_hproc), where
 * it is, breakpoints placed from their rva */
static void load_base(HANDLE hfile, const char *path, uint64_t base) {
    wow64_detect();
    find_base(hfile, path, base);
    bpm_rebase(g_link_lo);
    bpm_new_session();
}

/* ---- breakpoint bytes ---- */

/* file address -> process address */
static uint64_t to_rt(uint64_t file_addr) { return file_addr + g_base_addr; }

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

/* What a write at `at` would meet. A mapped view of a file (MEM_MAPPED) can
 * be shared with that file, an image section is copied on write. */
static DbgBpState mem_state(uint64_t at) {
    MEMORY_BASIC_INFORMATION mi;
    if (!VirtualQueryEx(g_hproc, (LPCVOID)(uintptr_t)at, &mi, sizeof mi) || mi.State != MEM_COMMIT)
        return DBG_BPS_UNMAPPED;
    if (!(mi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        || (mi.Protect & PAGE_GUARD))
        return DBG_BPS_NOEXEC;
    if (mi.Type == MEM_MAPPED) return DBG_BPS_SHARED;
    return DBG_BPS_OK;
}

/* writes the int3 of every breakpoint, the stopped process about to go on */
static void bp_insert_all(void) {
    for (int i = 0; i < g_nbp; i++) {
        DbgBp *b = &g_bp[i];
        DbgBpState was = b->state;
        if (!b->enabled) { b->state = DBG_BPS_IDLE; continue; }
        uint64_t at = bpm_rt(b);
        b->state = mem_state(at);
        if (b->state == DBG_BPS_OK && !ins_one(at)) b->state = DBG_BPS_UNMAPPED;
        if (b->state != was)
            switch (b->state) {
                case DBG_BPS_UNMAPPED: bp_tell("not placed: nothing is mapped there", b); break;
                case DBG_BPS_NOEXEC:   bp_tell("not placed: not code (no exec permission)", b); break;
                case DBG_BPS_SHARED:   bp_tell("not placed: mapped file view, a write would reach the file", b); break;
                default: break;
            }
    }
    if (g_tmp_on) ins_one(to_rt(g_tmp));
}

/* after bp_insert_all: the process address of an enabled breakpoint (or the
 * dbg_run_to target) that could take its int3 and has none; 0: all in */
static uint64_t bp_missing(void) {
    for (int i = 0; i < g_nbp; i++) {
        uint64_t at = bpm_rt(&g_bp[i]);
        if (g_bp[i].enabled && ins_index(at) < 0 && mem_state(at) == DBG_BPS_OK) return at;
    }
    if (g_tmp_on && ins_index(to_rt(g_tmp)) < 0 && mem_state(to_rt(g_tmp)) == DBG_BPS_OK) return to_rt(g_tmp);
    return 0;
}

/* puts the original bytes back; a byte the program rewrote meanwhile is its
 * own, not ours to restore */
static void bp_remove_all(void) {
    for (int i = g_nins; i-- > 0; ) {
        uint8_t cur;
        if (!mem_read(g_ins[i], &cur, 1)) continue;
        if (cur == 0xCC) { poke_byte(g_ins[i], g_orig[i], NULL); continue; }
        int k = bpm_at_rt(g_ins[i]);
        if (k >= 0 && !g_bp[k].overwritten) {
            g_bp[k].overwritten = true;
            bp_tell("was overwritten by the program (self-modifying code): its new byte is kept", &g_bp[k]);
        }
    }
    g_nins = 0;
}

/* is process address `at` the place of a breakpoint (or the run_to target)? */
static bool bp_at_rt(uint64_t at) {
    return (g_tmp_on && to_rt(g_tmp) == at) || bpm_at_rt(at) >= 0;
}

/* An int3 trap at a breakpoint that is no longer written (another thread
 * hit it before the bytes came out, see the top of the file)? */
static bool bp_stale(uint64_t at) {
    uint8_t b;
    bool known = bp_at_rt(at);
    for (int i = 0; !known && i < g_nbp; i++) known = bpm_rt(&g_bp[i]) == at;   /* disabled since */
    return ins_index(at) < 0 && known && mem_read(at, &b, 1) && b != 0xCC;
}

static bool on_bp(DWORD tid) {
    uint64_t ip;
    if (g_wow64) return ip_wow64(tid, &ip) && bp_at_rt(ip);   /* eip, the 32-bit context */
    CONTEXT c;
    return get_ctx(tid, &c, CONTEXT_CONTROL) && bp_at_rt(c.Rip);
}

/* ntdll!DbgBreakPoint, where the break-in thread of DebugActiveProcess /
 * DebugBreakProcess stops (ntdll is at the same address in every 64-bit
 * process of a boot). 0: unknown. A WOW64 debuggee's 32-bit ntdll is not
 * the debugger's: its DbgBreakPoint is g_brk32 (break_dll32). */
static uint64_t break_addr(void) {
    static bool done = false;
    static uint64_t at = 0;
    if (!done) {
        HMODULE m = GetModuleHandleA("ntdll.dll");
        FARPROC p = m ? GetProcAddress(m, "DbgBreakPoint") : NULL;
        at = (uint64_t)(uintptr_t)p;
        done = true;
    }
    return at;
}

/* WOW64 (g_wow64): LOAD_DLL event `ev` of the debuggee. A PE32 whose
 * export directory names it ntdll.dll is its 32-bit ntdll: g_brk32 := its
 * export DbgBreakPoint, read in the debuggee's memory (the name table is
 * sorted: a binary search, as the loader does). Anything else, or
 * unreadable: g_brk32 unchanged. Wine 11.21 sends no LOAD_DLL for its
 * 32-bit ntdll (tests/win/t_dbg.c, scenario W): g_brk32 stays 0 there. */
static void break_dll32(const DEBUG_EVENT *ev) {
    static const char dll[] = "ntdll.dll", fn[] = "DbgBreakPoint";
    uint64_t base = (uint64_t)(uintptr_t)ev->u.LoadDll.lpBaseOfDll;
    uint8_t mz[0x40], h[24 + 104], d[40], r[4];
    char s[sizeof dll], nm[sizeof fn];
    if (!base || !mem_read(base, mz, sizeof mz) || mz[0] != 'M' || mz[1] != 'Z') return;
    uint32_t lfa = le32(mz + 0x3c);
    if (lfa > 0x10000000u || !mem_read(base + lfa, h, sizeof h) || memcmp(h, "PE\0\0", 4)) return;
    const uint8_t *o = h + 24;                /* optional header: PE32, an export directory */
    if ((o[0] | o[1] << 8) != 0x10b || le32(o + 92) < 1) return;
    uint32_t er = le32(o + 96), es = le32(o + 100);
    if (!er || es < sizeof d || !mem_read(base + er, d, sizeof d)) return;
    if (!mem_read(base + le32(d + 12), s, sizeof s) || s[sizeof s - 1] || _stricmp(s, dll)) return;
    uint32_t nfn = le32(d + 20), funcs = le32(d + 28), names = le32(d + 32), ords = le32(d + 36);
    uint32_t lo = 0, hi = le32(d + 24);
    while (lo < hi) {                         /* names compared with their NUL: strcmp's order */
        uint32_t mid = lo + (hi - lo) / 2;
        if (!mem_read(base + names + 4ull * mid, r, 4) || !mem_read(base + le32(r), nm, sizeof nm)) return;
        int c = memcmp(nm, fn, sizeof fn);
        if (c < 0) lo = mid + 1;
        else if (c > 0) hi = mid;
        else {
            uint8_t ob[2];
            if (!mem_read(base + ords + 2ull * mid, ob, 2)) return;
            uint32_t ord = (uint32_t)(ob[0] | ob[1] << 8);
            if (ord >= nfn || !mem_read(base + funcs + 4ull * ord, r, 4)) return;
            uint32_t rva = le32(r);
            if (rva && (rva < er || rva - er >= es)) g_brk32 = base + rva;   /* not a forwarder */
            return;
        }
    }
}

/* Is breakpoint event `ev` one the system raised for the debugger? 0:
 * no (the program's own), 1: a loader breakpoint of a launch, 2: a
 * break-in (attach, DebugBreakProcess). It is counted off. A launch has
 * one loader breakpoint (g_sys_bp), except a WOW64 one under Windows: the
 * 64-bit ntdll raises EXCEPTION_BREAKPOINT, then the 32-bit ntdll
 * STATUS_WX86_BREAKPOINT (Wine: one EXCEPTION_BREAKPOINT, in its 32-bit
 * ntdll). So for a WOW64 debuggee a first one that is EXCEPTION_BREAKPOINT
 * sets g_sys_wx86: the next breakpoint is the loader's too if it is
 * STATUS_WX86_BREAKPOINT, and the program's own clears it (under Wine no
 * second one comes); a break-in leaves it. A break-in is at
 * ntdll!DbgBreakPoint, for a WOW64 debuggee also at its 32-bit ntdll's
 * (g_brk32). An x64 debuggee: as before WOW64 (g_sys_wx86 never set). */
static int sys_bp(const DEBUG_EVENT *ev) {
    DWORD code = ev->u.Exception.ExceptionRecord.ExceptionCode;
    if (g_sys_bp) {
        g_sys_bp = false;
        g_sys_wx86 = g_wow64 && code == EXCEPTION_BREAKPOINT;   /* Windows: the 64-bit ntdll's, the 32-bit one follows */
        return 1;
    }
    if (g_sys_wx86 && code == DBG_WX86_BREAKPOINT) { g_sys_wx86 = false; return 1; }
    if (g_brk_pending > 0) {
        uint64_t at = (uint64_t)(uintptr_t)ev->u.Exception.ExceptionRecord.ExceptionAddress;
        uint64_t brk = break_addr();
        if (!brk || at == brk || (g_wow64 && g_brk32 && at == g_brk32)) { g_brk_pending--; return 2; }
    }
    g_sys_wx86 = false;                       /* the program's own: the loader's are past */
    return 0;
}

/* Answers every event of process `pid` until its EXIT_PROCESS_DEBUG_EVENT
 * (continued too: the system then closes its handles), waiting `ms` at
 * most in all. Events of any other process are passed on. true: the exit
 * came. */
static bool drain_to_exit(DWORD pid, DWORD ms) {
    DWORD t0 = GetTickCount();
    for (;;) {
        DWORD used = GetTickCount() - t0;
        DEBUG_EVENT ev;
        if (!WaitForDebugEvent(&ev, used >= ms ? 0 : ms - used)) return false;
        close_event_files(&ev);
        bool done = ev.dwProcessId == pid && ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT;
        continue_event(&ev);
        if (done) return true;
    }
}

/* Waits (`ms` at most) for the CREATE_PROCESS_DEBUG_EVENT of `pid` and
 * leaves it pending: the process is stopped. Earlier events of other
 * processes (none expected) are passed on. false: *why says what came
 * instead (0: nothing in time, else the event code). */
static bool wait_create(DWORD pid, DWORD ms, DEBUG_EVENT *out, DWORD *why) {
    DWORD t0 = GetTickCount();
    *why = 0;
    for (;;) {
        DWORD used = GetTickCount() - t0;
        DEBUG_EVENT ev;
        if (!WaitForDebugEvent(&ev, used >= ms ? 0 : ms - used)) return false;
        if (ev.dwProcessId == pid && ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            *out = ev;
            return true;
        }
        close_event_files(&ev);
        if (ev.dwProcessId == pid && ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            continue_event(&ev);
            *why = EXIT_PROCESS_DEBUG_EVENT;
            return false;
        }
        continue_event(&ev);
    }
}

/* Kills the debuggee (launched or attached) and waits for its end. */
static void kill_and_reap(void) {
    DWORD pid = (DWORD)g_pid;
    unhold_all();                            /* none left suspended if it does not die */
    TerminateProcess(g_hproc, DBG_TERMINATE_PROCESS);
    continue_pending();                      /* it cannot die while frozen */
    if (!drain_to_exit(pid, DBG_KILL_MS))
        DebugActiveProcessStop(pid);         /* no exit event in time: cut it loose */
    WaitForSingleObject(g_hproc, DBG_KILL_MS);
}

/* Quotes one argument for CommandLineToArgvW / the MSVC and MinGW CRTs:
 * a run of backslashes is doubled only in front of a quote. false: no
 * room in `out`. */
static bool quote_arg(const char *a, char *out, size_t sz, size_t *len) {
    size_t n = *len;
#define PUT(c) do { if (n + 1 >= sz) return false; out[n++] = (c); } while (0)
    if (n > 0) PUT(' ');
    if (*a && !strpbrk(a, " \t\n\v\"")) {
        while (*a) PUT(*a++);
    } else {
        PUT('"');
        for (;; a++) {
            size_t bs = 0;
            while (*a == '\\') { bs++; a++; }
            if (!*a) { while (bs--) { PUT('\\'); PUT('\\'); } break; }
            if (*a == '"') { while (bs--) { PUT('\\'); PUT('\\'); } PUT('\\'); PUT('"'); continue; }
            while (bs--) PUT('\\');
            PUT(*a);
        }
        PUT('"');
    }
#undef PUT
    out[n] = '\0';
    *len = n;
    return true;
}

/* ---- launch, attach, detach, kill -------------------------------------- */

bool dbg_launch(const char *path, char *const argv[], char *err, size_t esz) {
    err[0] = '\0';
    if (!path || !*path) { snprintf(err, esz, "No program"); return false; }
    dbg_detach();

    char app[MAX_PATH * 2];
    if (strlen(path) >= sizeof app) { snprintf(err, esz, "Path too long"); return false; }
    strcpy(app, path);
    for (char *p = app; *p; p++) if (*p == '/') *p = '\\';

    /* command line: argv[0] is the program when argv is NULL */
    size_t cap = 32768, len = 0;              /* CreateProcess's own limit */
    char *cmd = malloc(cap);
    if (!cmd) { snprintf(err, esz, "Out of memory"); return false; }
    cmd[0] = '\0';
    bool fits = true;
    if (argv && argv[0])
        for (int i = 0; fits && argv[i]; i++) fits = quote_arg(argv[i], cmd, cap, &len);
    else
        fits = quote_arg(app, cmd, cap, &len);
    if (!fits) { free(cmd); snprintf(err, esz, "Command line too long"); return false; }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);
    BOOL ok = CreateProcessA(app, cmd, NULL, NULL, FALSE,
                             DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                             NULL, NULL, &si, &pi);
    DWORD e = GetLastError();
    free(cmd);
    if (!ok) {
        char msg[256];
        win_error(e, msg, sizeof msg);
        snprintf(err, esz, "Cannot run %.200s: %s", path, msg);
        return false;
    }
    DebugSetProcessKillOnExit(TRUE);          /* it dies with Abyss */

    DEBUG_EVENT ev;
    DWORD why;
    if (!wait_create(pi.dwProcessId, DBG_START_MS, &ev, &why)) {
        if (why == EXIT_PROCESS_DEBUG_EVENT)
            snprintf(err, esz, "%.200s exited right away", path);
        else {
            snprintf(err, esz, "%.200s: no debug event after %d s", path, DBG_START_MS / 1000);
            TerminateProcess(pi.hProcess, DBG_TERMINATE_PROCESS);
            if (!drain_to_exit(pi.dwProcessId, DBG_KILL_MS)) DebugActiveProcessStop(pi.dwProcessId);
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }

    reset();
    g_hproc = pi.hProcess;
    g_hthread = pi.hThread;
    g_pid = g_lastpid = (int)pi.dwProcessId;
    g_ours = true;
    g_ev_pending = true;
    g_ev_pid = ev.dwProcessId;
    g_ev_tid = ev.dwThreadId;
    g_main_tid = pi.dwThreadId;
    g_cur_tid = ev.dwThreadId;
    thr_add(ev.dwThreadId);
    g_sys_bp = true;                          /* ntdll's loader breakpoint comes next */
    g_state = DBG_STOPPED;
    g_stop = DBG_STOP_EXEC;
    load_base(ev.u.CreateProcessInfo.hFile, app, (uint64_t)(uintptr_t)ev.u.CreateProcessInfo.lpBaseOfImage);
    close_event_files(&ev);
    return true;
}

bool dbg_attach(int pid, char *err, size_t esz) {
    err[0] = '\0';
    if (pid <= 0) { snprintf(err, esz, "Invalid pid %d", pid); return false; }
    if ((DWORD)pid == GetCurrentProcessId()) { snprintf(err, esz, "Cannot debug Abyss itself"); return false; }
    if (pid == g_pid && dbg_state() == DBG_STOPPED) return true;          /* already ours */
    dbg_detach();

    if (!DebugActiveProcess((DWORD)pid)) {
        DWORD e = GetLastError();
        /* say why in plain words when the process itself tells */
        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
        BOOL other = FALSE;
        if (!h && GetLastError() == ERROR_INVALID_PARAMETER)
            snprintf(err, esz, "No process %d", pid);
        else if (h && CheckRemoteDebuggerPresent(h, &other) && other)
            snprintf(err, esz, "Process %d is already being debugged", pid);
        else if (e == ERROR_ACCESS_DENIED)
            snprintf(err, esz, "Permission denied: process %d runs as another user, elevated or "
                     "protected (run Abyss as administrator)", pid);
        else if (e == ERROR_NOT_SUPPORTED)
            snprintf(err, esz, "Process %d cannot be debugged from this Abyss (32 / 64-bit mismatch?)", pid);
        else {
            char msg[256];
            win_error(e, msg, sizeof msg);
            snprintf(err, esz, "DebugActiveProcess(%d): %s", pid, msg);
        }
        if (h) CloseHandle(h);
        return false;
    }
    DebugSetProcessKillOnExit(FALSE);         /* Abyss quitting lets it go */

    DEBUG_EVENT ev;
    DWORD why;
    if (!wait_create((DWORD)pid, DBG_START_MS, &ev, &why)) {
        if (why == EXIT_PROCESS_DEBUG_EVENT)
            snprintf(err, esz, "Process %d exited while attaching", pid);
        else
            snprintf(err, esz, "Process %d: no debug event after the attach", pid);
        DebugActiveProcessStop((DWORD)pid);
        return false;
    }

    /* our own copies: those of the event are the system's */
    HANDLE me = GetCurrentProcess(), hp = NULL, ht = NULL;
    if (!DuplicateHandle(me, ev.u.CreateProcessInfo.hProcess, me, &hp, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        char msg[256];
        win_error(GetLastError(), msg, sizeof msg);
        snprintf(err, esz, "Process %d: %s", pid, msg);
        close_event_files(&ev);
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
        DebugActiveProcessStop((DWORD)pid);
        return false;
    }
    if (!DuplicateHandle(me, ev.u.CreateProcessInfo.hThread, me, &ht, 0, FALSE, DUPLICATE_SAME_ACCESS))
        ht = NULL;                            /* only for the registers, later */

    reset();
    g_hproc = hp;
    g_hthread = ht;
    g_pid = g_lastpid = pid;
    g_ours = false;
    g_ev_pending = true;
    g_ev_pid = ev.dwProcessId;
    g_ev_tid = ev.dwThreadId;
    g_main_tid = ev.dwThreadId;
    g_cur_tid = ev.dwThreadId;
    thr_add(ev.dwThreadId);                   /* the others: their CREATE_THREAD follow */
    g_brk_pending = 1;                        /* the break-in thread of the attach */
    g_state = DBG_STOPPED;
    g_stop = DBG_STOP_INTERRUPT;              /* "attached, stopped" */

    /* where the program is: its module (the loader has run), else the event */
    uint64_t base = (uint64_t)(uintptr_t)ev.u.CreateProcessInfo.lpBaseOfImage;
    char exe[MAX_PATH * 2];
    module_base(exe, sizeof exe, &base);
    load_base(ev.u.CreateProcessInfo.hFile, exe, base);
    close_event_files(&ev);
    return true;
}

/* Gives an attached process back. A trap flag left set, an int3 byte
 * still written or a break-in still to come would raise an exception
 * with no debugger to answer it, which kills the program: the flag and
 * the bytes go out, the break-in is waited for (DBG_INTR_MS at most) and
 * answered first. When int3 bytes were still written (it was running),
 * the events already queued are answered too (DBG_SETTLE_EXTRA at most):
 * an int3 hit just before the bytes came out gets its rip put back. A
 * WOW64 debuggee (g_wow64): Windows raises them as STATUS_WX86_BREAKPOINT /
 * STATUS_WX86_SINGLE_STEP, taken like EXCEPTION_BREAKPOINT /
 * EXCEPTION_SINGLE_STEP (Wine raises the usual two); an x64 one: those two
 * only, as before WOW64. */
static void let_go(void) {
    const DWORD wx86_step = 0x4000001Eu;      /* STATUS_WX86_SINGLE_STEP */
    DWORD pid = (DWORD)g_pid;
    end_step();
    int queued = g_nins > 0 ? DBG_SETTLE_EXTRA : 0;   /* hits that may be queued */
    bp_remove_all();                          /* only while running: out at every stop */
    continue_pending();
    DWORD t0 = GetTickCount();
    for (;;) {
        DWORD used = GetTickCount() - t0;
        bool wait = (g_sys_bp || g_brk_pending > 0) && used < DBG_INTR_MS;
        if (!wait && queued-- <= 0) break;
        DEBUG_EVENT ev;
        if (!WaitForDebugEvent(&ev, wait ? DBG_INTR_MS - used : 0)) break;
        close_event_files(&ev);
        DWORD code = ev.u.Exception.ExceptionRecord.ExceptionCode;
        bool brk = code == EXCEPTION_BREAKPOINT || (g_wow64 && code == DBG_WX86_BREAKPOINT);
        bool step = code == EXCEPTION_SINGLE_STEP || (g_wow64 && code == wx86_step);
        if (ev.dwProcessId == pid && ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && (brk || step)) {
            uint64_t at = (uint64_t)(uintptr_t)ev.u.Exception.ExceptionRecord.ExceptionAddress;
            if (brk && bp_stale(at)) set_rip(ev.dwThreadId, at);
            else if (brk) sys_bp(&ev);
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
            continue;
        }
        continue_event(&ev);
        if (ev.dwProcessId == pid && ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) break;
    }
    DebugActiveProcessStop(pid);              /* drops the events still queued */
}

void dbg_detach(void) {
    /* a running attached process: stop it the usual way first, which
     * takes the int3 bytes out (and puts rip back on a hit) */
    if (!g_ours && g_pid > 0 && g_state == DBG_RUNNING) dbg_interrupt();
    if (g_pid > 0 && (g_state == DBG_STOPPED || g_state == DBG_RUNNING)) {
        if (g_ours) kill_and_reap();
        else let_go();
    }
    reset();
}

void dbg_kill(void) {
    if (g_pid > 0 && (g_state == DBG_STOPPED || g_state == DBG_RUNNING))
        kill_and_reap();
    reset();
}

/* ---- state, status, pid ------------------------------------------------ */

DbgState dbg_state(void) {
    /* killed or ended from outside: its handle is signalled */
    if ((g_state == DBG_STOPPED || g_state == DBG_RUNNING) && g_hproc
        && WaitForSingleObject(g_hproc, 0) == WAIT_OBJECT_0) {
        DWORD pid = (DWORD)g_pid;
        continue_pending();                  /* lets its EXIT_PROCESS come */
        note_exit(NULL);
        drain_to_exit(pid, 0);               /* answer its EXIT_PROCESS if queued */
    }
    return g_state;
}

DbgStop dbg_stop_reason(void) {
    return dbg_state() == DBG_STOPPED ? g_stop : DBG_STOP_NONE;
}

int dbg_pid(void) {
    DbgState s = dbg_state();
    return s == DBG_STOPPED || s == DBG_RUNNING ? g_pid : 0;
}

/* Name of a usual NTSTATUS a crashed program exits with (NULL: none). */
static const char *ntstatus_name(DWORD c) {
    switch (c) {
    case 0xC0000005: return "access violation";
    case 0xC0000017: return "out of memory";
    case 0xC000001D: return "illegal instruction";
    case 0xC0000025: return "noncontinuable exception";
    case 0xC000008C: return "array bounds exceeded";
    case 0xC000008E: return "float divide by zero";
    case 0xC0000090: return "float invalid operation";
    case 0xC0000094: return "integer divide by zero";
    case 0xC0000095: return "integer overflow";
    case 0xC0000096: return "privileged instruction";
    case 0xC00000FD: return "stack overflow";
    case 0xC0000135: return "DLL not found";
    case 0xC0000139: return "entry point not found";
    case 0xC0000142: return "DLL initialization failed";
    case 0xC000013A: return "Ctrl-C";
    case 0xC0000374: return "heap corruption";
    case 0xC0000409: return "stack buffer overrun / fail fast";
    case 0xC0000417: return "invalid CRT parameter";
    case 0x40010004: return "terminated by the debugger";
    case 0x80000003: return "breakpoint";
    default:         return NULL;
    }
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
    case DBG_EXITED: {
        const char *name = g_exit_ok ? ntstatus_name(g_exit) : NULL;
        if (!g_exit_ok)
            snprintf(out, sz, "exited (pid %d)", g_lastpid);
        else if (name)
            snprintf(out, sz, "exited with code 0x%08lX (%s)", (unsigned long)g_exit, name);
        else if (g_exit >= 0x80000000u)
            snprintf(out, sz, "exited with code 0x%08lX", (unsigned long)g_exit);
        else
            snprintf(out, sz, "exited with code %lu", (unsigned long)g_exit);
        break;
    }
    case DBG_STOPPED:
        switch (g_stop) {
        case DBG_STOP_EXEC:
            snprintf(out, sz, "stopped at start (pid %d)", g_pid);
            break;
        case DBG_STOP_INTERRUPT:
            snprintf(out, sz, g_ours ? "interrupted (pid %d)" : "attached, stopped (pid %d)", g_pid);
            break;
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

/* ---- events, resume ---------------------------------------------------- */

/* Every stop reported to the caller: event `ev` stays pending (the
 * process frozen), the int3 bytes go out, a step in progress and a
 * dbg_run_to are over. */
static void stop_on(const DEBUG_EVENT *ev, DbgStop why) {
    if (g_step_tid && !(why == DBG_STOP_STEP && ev->dwThreadId == g_step_tid))
        g_late_tid = g_step_tid;              /* its trap may be queued already */
    end_step();
    bp_remove_all();
    g_tmp_on = false;
    g_ev_pending = true;
    g_ev_pid = ev->dwProcessId;
    g_ev_tid = ev->dwThreadId;
    /* the break-in thread of dbg_interrupt is of no interest: the first
     * thread instead, while it lives */
    g_cur_tid = why == DBG_STOP_INTERRUPT && g_main_tid ? g_main_tid : ev->dwThreadId;
    g_state = DBG_STOPPED;
    g_stop = why;
    CONTEXT c;
    if (why == DBG_STOP_BP)                   /* the int3, rip is one past it */
        g_stop_rip = (uint64_t)(uintptr_t)ev->u.Exception.ExceptionRecord.ExceptionAddress;
    else if (g_wow64)                         /* eip, the 32-bit context (0: unread) */
        ip_wow64(g_cur_tid, &g_stop_rip);
    else
        g_stop_rip = get_ctx(g_cur_tid, &c, CONTEXT_CONTROL) ? c.Rip : 0;
}

static void regs_from(const CONTEXT *c, DbgRegs *r) {
    r->rip = c->Rip;  r->rsp = c->Rsp;  r->rbp = c->Rbp;
    r->rax = c->Rax;  r->rbx = c->Rbx;  r->rcx = c->Rcx;  r->rdx = c->Rdx;
    r->rsi = c->Rsi;  r->rdi = c->Rdi;  r->rflags = c->EFlags;
    r->r8  = c->R8;   r->r9  = c->R9;   r->r10 = c->R10;  r->r11 = c->R11;
    r->r12 = c->R12;  r->r13 = c->R13;  r->r14 = c->R14;  r->r15 = c->R15;
}

/* the neutral context -> DbgRegs (dbg_get_regs of a WOW64 debuggee: ctx_get
 * zero-extended the 32-bit registers and set r8..r15 to 0, as dbg.c's
 * registers of a 32-bit process) */
static void regs_from_ctx(const DbgCtx *x, DbgRegs *r) {
    r->rip = x->ip;   r->rsp = x->sp;   r->rbp = x->bp;
    r->rax = x->ax;   r->rbx = x->bx;   r->rcx = x->cx;   r->rdx = x->dx;
    r->rsi = x->si;   r->rdi = x->di;   r->rflags = x->flags;
    r->r8  = x->r8;   r->r9  = x->r9;   r->r10 = x->r10;  r->r11 = x->r11;
    r->r12 = x->r12;  r->r13 = x->r13;  r->r14 = x->r14;  r->r15 = x->r15;
}

/* An int3 trap of thread ev: one of ours (written now, or stale)? Then
 * rip goes back onto it, a pass is counted, and the stop is reported (1),
 * or, for the dbg_run_to target in a deeper frame or another thread or a
 * false condition, the thread steps over it with no int3 written and goes
 * on (2). 0: not ours. */
static int bp_hit(const DEBUG_EVENT *ev) {
    uint64_t at = (uint64_t)(uintptr_t)ev->u.Exception.ExceptionRecord.ExceptionAddress;
    DWORD tid = ev->dwThreadId;
    if (ins_index(at) < 0 && !bp_stale(at)) return 0;
    CONTEXT c;
    DbgCtx x;                                 /* WOW64: the 32-bit context (esp, the condition's registers) */
    if (!set_rip(tid, at) || (g_wow64 ? !ctx_get(tid, &x) : !get_ctx(tid, &c, CONTEXT_FULL))) return 0;
    uint64_t sp = g_wow64 ? x.sp : c.Rsp;
    bool dep = tid == g_dep_tid && at == g_dep_at;   /* its departure (hold_back_in): no pass */
    if (dep) g_dep_tid = 0;
    int i = bpm_at_rt(at);
    if (i >= 0 && !dep) g_bp[i].hits++;
    if (!dep && g_tmp_on && to_rt(g_tmp) == at && tid == g_tmp_tid && sp >= g_tmp_rsp) {
        g_last_bp = i;
        stop_on(ev, DBG_STOP_TEMP);
        return 1;
    }
    if (i >= 0 && !dep) {
        DbgRegs r;
        if (g_wow64) regs_from_ctx(&x, &r);   /* zero-extended, r8..r15 0 */
        else regs_from(&c, &r);
        if (cond_true(&g_bp[i], &r)) {
            g_last_bp = i;
            stop_on(ev, DBG_STOP_BP);
            return 1;
        }
    }
    bp_remove_all();                          /* not this frame, or the condition is false */
    if (!g_step_tid) {                        /* else the bytes come back after that step */
        char err[sizeof g_bp_news];
        err[0] = '\0';
        if (!hold_others(tid, err, sizeof err) || !set_tf(tid, true)) {
            unhold_all();
            if (err[0] && !g_bp_news[0]) snprintf(g_bp_news, sizeof g_bp_news, "%s", err);
            stop_on(ev, DBG_STOP_TEMP);
            return 1;
        }
        g_step_tid = tid;
        g_stepover = true;
        g_step_from = at;
    }
    g_pass = true;
    ContinueDebugEvent(ev->dwProcessId, tid, DBG_CONTINUE);
    return 2;
}

/* One debug event of the running debuggee. true: it stopped on it (left
 * pending) or it is gone; false: answered, it goes on. */
static bool on_event(DEBUG_EVENT *ev) {
    close_event_files(ev);
    if (ev->dwProcessId != (DWORD)g_pid) { continue_event(ev); return false; }
    switch (ev->dwDebugEventCode) {
    case EXIT_PROCESS_DEBUG_EVENT: {
        DWORD code = ev->u.ExitProcess.dwExitCode;
        ContinueDebugEvent(ev->dwProcessId, ev->dwThreadId, DBG_CONTINUE);
        note_exit(&code);
        return true;
    }
    case CREATE_THREAD_DEBUG_EVENT: {
        DbgThr *t = thr_add(ev->dwThreadId);
        DWORD e = 0;
        if (g_hold && (!t || !thr_hold(t, &e)) && !g_bp_news[0]) {   /* held from its start */
            char msg[96];
            win_error(t ? e : ERROR_NOT_ENOUGH_MEMORY, msg, sizeof msg);
            snprintf(g_bp_news, sizeof g_bp_news, "SuspendThread failed (new thread %lu, it runs during a step over): %.60s",
                     (unsigned long)ev->dwThreadId, msg);
        }
        break;
    }
    case EXIT_THREAD_DEBUG_EVENT:
        thr_del(ev->dwThreadId);
        if (ev->dwThreadId == g_main_tid) g_main_tid = 0;
        if (ev->dwThreadId == g_late_tid) g_late_tid = 0;
        if (ev->dwThreadId == g_step_tid) {   /* its step (over) ends with it: the bytes back, then the others */
            bp_insert_all();
            uint64_t bad = bp_missing();
            g_step_tid = 0;
            g_stepover = false;
            if (bad) {                        /* released, they could pass it: stopped here, none held */
                stop_on(ev, DBG_STOP_INTERRUPT);
                if (g_cur_tid == ev->dwThreadId && g_nthr) {   /* a live thread's registers */
                    CONTEXT c;
                    g_cur_tid = g_thr[0].tid;
                    if (g_wow64) ip_wow64(g_cur_tid, &g_stop_rip);   /* eip, the 32-bit context */
                    else g_stop_rip = get_ctx(g_cur_tid, &c, CONTEXT_CONTROL) ? c.Rip : 0;
                }
                snprintf(g_bp_news, sizeof g_bp_news, "Stopped: int3 at 0x%llx not written back (thread %lu ended during "
                         "its step): the other threads would pass it", (unsigned long long)bad, (unsigned long)ev->dwThreadId);
                return true;
            }
            unhold_all();
        }
        break;
    case EXCEPTION_DEBUG_EVENT: {
        /* a WOW64 debuggee (g_wow64): Windows raises its int3 / single
         * step as STATUS_WX86_BREAKPOINT / STATUS_WX86_SINGLE_STEP, taken
         * like EXCEPTION_BREAKPOINT / EXCEPTION_SINGLE_STEP (Wine raises
         * the usual two); an x64 one: those two only, as before WOW64 */
        const DWORD wx86_step = 0x4000001Eu;  /* STATUS_WX86_SINGLE_STEP */
        DWORD code = ev->u.Exception.ExceptionRecord.ExceptionCode;
        DWORD tid = ev->dwThreadId;
        bool brk = code == EXCEPTION_BREAKPOINT || (g_wow64 && code == DBG_WX86_BREAKPOINT);
        bool step = code == EXCEPTION_SINGLE_STEP || (g_wow64 && code == wx86_step);
        if (step) {
            if (g_stepover && tid == g_step_tid) {
                /* past the breakpoint it resumed on: write them all, the
                 * others resumed (everything is frozen until the answer) */
                bp_insert_all();
                end_step();
                g_pass = true;
                break;
            }
            if (tid == g_late_tid && tid != g_step_tid) {   /* a step cut short, done now */
                g_late_tid = 0;
                break;
            }
            {   /* a pass is an arrival, by a step too (same rule as dbg.c) */
                CONTEXT c;
                uint64_t ip;
                if (g_wow64) {                /* eip, the 32-bit context */
                    if (ip_wow64(tid, &ip) && ip != g_step_from) {
                        int i = bpm_at_rt(ip);
                        if (i >= 0) g_bp[i].hits++;
                    }
                } else if (get_ctx(tid, &c, CONTEXT_FULL) && c.Rip != g_step_from) {
                    int i = bpm_at_rt(c.Rip);
                    if (i >= 0) g_bp[i].hits++;
                }
            }
            stop_on(ev, DBG_STOP_STEP);
            return true;
        }
        if (brk) {
            uint64_t at = (uint64_t)(uintptr_t)ev->u.Exception.ExceptionRecord.ExceptionAddress;
            if (g_hold && tid != g_step_tid && bp_stale(at) && set_rip(tid, at)) {
                /* hit before the bytes went out, during a hold: back on the
                 * int3 and held, it traps again once they are in */
                DbgThr *t = thr_add(tid);
                DWORD e = 0;
                if (t && thr_hold(t, &e)) { g_pass = true; break; }
            }
            int ours = bp_hit(ev);
            if (ours) return ours == 1;
            int sys = sys_bp(ev);
            if (sys == 0 || (sys == 2 && g_intr)) {
                stop_on(ev, sys == 0 ? DBG_STOP_BP : DBG_STOP_INTERRUPT);
                return true;
            }
            break;                            /* the system's: DBG_CONTINUE */
        }
        if (code == DBG_WX86_BREAKPOINT) break;   /* x64: unseen, as before (WOW64: taken above) */
        ContinueDebugEvent(ev->dwProcessId, ev->dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
        return false;
    }
    default:        /* LOAD_DLL, UNLOAD_DLL, OUTPUT_DEBUG_STRING, RIP */
        break;
    }
    ContinueDebugEvent(ev->dwProcessId, ev->dwThreadId, DBG_CONTINUE);
    return false;
}

/* Answers the events of the running debuggee until it stops or ends,
 * waiting `ms` at most (0: only the ones already queued). Past that time
 * DBG_SETTLE_EXTRA more queued events are still taken, no more: a program
 * that floods OutputDebugString cannot hold the UI. */
static void settle(DWORD ms) {
    DWORD t0 = GetTickCount();
    int extra = 0;
    while (g_state == DBG_RUNNING) {
        DWORD used = GetTickCount() - t0;
        if (used >= ms && extra++ >= DBG_SETTLE_EXTRA) return;
        DEBUG_EVENT ev;
        /* after a silent pass the next one comes soon: a short wait, or a
         * poll would take one pass each DBG_POLL_MS */
        if (!WaitForDebugEvent(&ev, used >= ms ? (g_pass ? DBG_PASS_MS : 0) : ms - used)) { g_pass = false; return; }
        g_pass = false;
        on_event(&ev);
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

/* Continues the event the debuggee is stopped on, then settles. */
static bool resume(char *err, size_t esz) {
    if (!ContinueDebugEvent(g_ev_pid, g_ev_tid, DBG_CONTINUE)) {
        char msg[256];
        win_error(GetLastError(), msg, sizeof msg);
        snprintf(err, esz, "ContinueDebugEvent: %s", msg);
        dbg_state();                          /* killed from outside? */
        return false;
    }
    g_ev_pending = false;
    g_state = DBG_RUNNING;
    g_stop = DBG_STOP_NONE;
    settle(DBG_SETTLE_MS);
    return true;
}

bool dbg_poll(void) {
    DbgState before = g_state;
    if (g_state == DBG_RUNNING) settle(0);
    dbg_state();                              /* ended from outside */
    return g_state != before;
}

int dbg_ui_timeout(void) {
    return g_state == DBG_RUNNING ? DBG_POLL_MS : -1;
}

/* dbg_step (`step`), or dbg_cont / dbg_run_to: the int3 bytes go in,
 * unless the thread is on one of them: it single-steps past it first. */
static bool start(bool step, char *err, size_t esz) {
    if (!need_stopped(err, esz)) return false;
    g_last_bp = -1;
    if (g_dep_tid == g_cur_tid) g_dep_tid = 0;   /* resumed from its breakpoint below */
    bool over = !step && on_bp(g_cur_tid);
    if (step || over) {
        if (!hold_others(g_cur_tid, err, esz)) return false;   /* a dbg_step too (top of the file) */
        if (!set_tf(g_cur_tid, true)) {
            char msg[256];
            win_error(GetLastError(), msg, sizeof msg);
            unhold_all();
            snprintf(err, esz, "SetThreadContext (thread %lu): %s", (unsigned long)g_cur_tid, msg);
            return false;
        }
        g_step_tid = g_cur_tid;
        g_stepover = over;
        CONTEXT c;
        if (g_wow64) ip_wow64(g_cur_tid, &g_step_from);   /* eip, the 32-bit context */
        else g_step_from = get_ctx(g_cur_tid, &c, CONTEXT_FULL) ? c.Rip : 0;
    } else {
        bp_insert_all();
        if (g_dep_tid && ins_index(g_dep_at) < 0) g_dep_tid = 0;   /* no int3 there: no trap to take */
    }
    if (!resume(err, esz)) {
        end_step();
        bp_remove_all();
        return false;
    }
    return true;
}

bool dbg_cont(char *err, size_t esz) {
    err[0] = '\0';
    return start(false, err, esz);
}

bool dbg_step(char *err, size_t esz) {           /* writes no int3 */
    err[0] = '\0';
    return start(true, err, esz);
}

/* dbg_interrupt during a step that holds the others (its instruction
 * waits): the stepping thread is held too, the int3 bytes go back, then
 * the caller releases everyone (see the top of the file). true: done, or
 * no step holds anything. false: nothing changed (bytes out again, the
 * stepping thread resumed, the others still held), why in g_bp_news. */
static bool hold_back_in(void) {
    if (!g_hold || !g_step_tid) return true;
    DWORD tid = g_step_tid, e = ERROR_NOT_ENOUGH_MEMORY;
    DbgThr *t = thr_add(tid);
    char msg[96];
    const char *why = "SuspendThread";
    bool rf = false;
    if (!t || !thr_hold(t, &e))
        win_error(e, msg, sizeof msg);
    else {
        CONTEXT c;
        uint64_t ip = 0;                      /* its ip (WOW64: eip, the 32-bit context) */
        bool ended = !t->h;                   /* nothing to hold, no trap to come */
        if (!ended && (g_wow64 ? !ip_wow64(tid, &ip) : !get_ctx(tid, &c, CONTEXT_CONTROL))) {
            win_error(GetLastError(), msg, sizeof msg);
            why = g_wow64 ? "Wow64GetThreadContext" : "GetThreadContext";
        } else {
            if (!ended && !g_wow64) ip = c.Rip;
            bp_insert_all();
            uint64_t bad = 0;
            for (int i = 0; i < g_nbp && !bad; i++) {
                uint64_t at = bpm_rt(&g_bp[i]);
                if (g_bp[i].enabled && ins_index(at) < 0 && mem_state(at) == DBG_BPS_OK) bad = at;
            }
            if (!bad && g_tmp_on && ins_index(to_rt(g_tmp)) < 0 && mem_state(to_rt(g_tmp)) == DBG_BPS_OK) bad = to_rt(g_tmp);
            if (!bad) {
                if (!ended && ip == g_step_from && ins_index(ip) >= 0) { g_dep_tid = tid; g_dep_at = ip; }
                return true;
            }
            bp_remove_all();
            snprintf(msg, sizeof msg, "0x%llx not written back", (unsigned long long)bad);
            why = "int3";
        }
        rf = !thr_unhold(t, &e);
    }
    snprintf(g_bp_news, sizeof g_bp_news, "Not interrupted: %s%s (thread %lu, stepping): %.40s; step goes on, others held",
             why, rf ? " + ResumeThread failed" : "", (unsigned long)tid, msg);
    return false;
}

/* true when the debuggee is stopped on return */
bool dbg_interrupt(void) {
    if (dbg_state() == DBG_STOPPED) return true;
    if (g_state != DBG_RUNNING) return false;
    settle(0);                                /* a stop already waiting */
    if (g_state != DBG_RUNNING) return g_state == DBG_STOPPED;
    if (!hold_back_in()) return false;        /* no thread released with an int3 out */
    unhold_all();                             /* the break-in thread must run */
    if (g_brk_pending == 0) {                 /* not one still on its way */
        if (!DebugBreakProcess(g_hproc)) { settle(0); dbg_state(); return g_state == DBG_STOPPED; }
        g_brk_pending++;
    }
    g_intr = true;
    settle(DBG_INTR_MS);
    g_intr = false;
    return g_state == DBG_STOPPED;
}

bool dbg_get_regs(DbgRegs *r) {
    if (!r || dbg_state() != DBG_STOPPED) return false;
    if (g_wow64) {                            /* the 32-bit registers (Wow64GetThreadContext) */
        DbgCtx x;
        if (!ctx_get(g_cur_tid, &x)) return false;
        regs_from_ctx(&x, r);
        return true;
    }
    CONTEXT c;
    if (!get_ctx(g_cur_tid, &c, CONTEXT_FULL)) return false;
    regs_from(&c, r);
    return true;
}

/* ---- breakpoints, run to ----------------------------------------------- */

/* hooks of dbg_bp.h */

static bool bp_hook_can_change(char *err, size_t esz) {
    if (dbg_state() != DBG_RUNNING) return true;
    snprintf(err, esz, "The program is running (interrupt it first)");
    return false;
}

static bool bp_hook_stopped(void) {
    return dbg_state() == DBG_STOPPED;
}

/* `at` must be code of the stopped debuggee: committed memory with an
 * execute permission, not a mapped file view, readable */
static bool bp_hook_check_code(uint64_t at, uint64_t shown, char *err, size_t esz) {
    uint8_t b;
    switch (mem_state(at)) {
        case DBG_BPS_UNMAPPED:
            snprintf(err, esz, "0x%llx (0x%llx in the process) is not mapped in pid %d",
                     (unsigned long long)shown, (unsigned long long)at, g_pid);
            return false;
        case DBG_BPS_NOEXEC:
            snprintf(err, esz, "0x%llx is not code (no exec permission)", (unsigned long long)shown);
            return false;
        case DBG_BPS_SHARED:
            snprintf(err, esz, "0x%llx is in a mapped file view: a breakpoint could be written to the file", (unsigned long long)shown);
            return false;
        default:
            break;
    }
    if (!mem_read(at, &b, 1)) {
        char msg[256];
        win_error(GetLastError(), msg, sizeof msg);
        snprintf(err, esz, "ReadProcessMemory(0x%llx): %s", (unsigned long long)at, msg);
        return false;
    }
    return true;
}

static bool bp_hook_module_ok(char *err, size_t esz) {
    snprintf(err, esz, "breakpoints in another module are not handled on Windows, only in the program");
    return false;
}

static bool bp_hook_hw_ok(char *err, size_t esz) {
    snprintf(err, esz, "hardware breakpoints (DR0-DR3) are not handled on Windows");
    return false;
}

static bool bp_hook_module_rt(const char *module, uint64_t rva, uint64_t *rt) {
    (void)module; (void)rva; (void)rt;
    return false;
}

void dbg_bp_image(const char *path) {
    const char *sl = path ? strrchr(path, '/') : NULL, *bs = path ? strrchr(path, '\\') : NULL;
    if (bs && (!sl || bs > sl)) sl = bs;
    snprintf(g_prog, sizeof g_prog, "%.*s", DBG_MOD_MAX - 1, sl ? sl + 1 : path ? path : "");
    uint64_t ib = 0;
    uint32_t size;
    int bits = 0;
    if (path && pe_header_path(path, &ib, &size, &bits)) { g_bits = bits; bpm_rebase(ib); }
    else { g_bits = 0; bpm_rebase(0); }
}

/* ---- memory ------------------------------------------------------------ */

void dbg_mask_int3(int pid, uint64_t rt, void *buf, size_t n) {
    if (pid != g_pid || pid <= 0) return;
    for (int i = 0; i < g_nins; i++)
        if (g_ins[i] >= rt && g_ins[i] - rt < n) ((uint8_t *)buf)[g_ins[i] - rt] = g_orig[i];
}

bool dbg_read_mem(uint64_t rt, void *buf, size_t n) {
    if (!buf || !n || g_pid <= 0 || !(g_state == DBG_STOPPED || g_state == DBG_RUNNING)) return false;
    if (!mem_read(rt, buf, n)) return false;
    dbg_mask_int3(g_pid, rt, buf, n);
    return true;
}

bool dbg_run_to(uint64_t addr, char *err, size_t esz) {
    err[0] = '\0';
    if (!need_stopped(err, esz)) return false;
    if (!bp_hook_check_code(to_rt(addr), addr, err, esz)) return false;
    CONTEXT c;
    DbgCtx x;                                 /* WOW64: esp, the 32-bit context */
    if (g_wow64 ? !ctx_get(g_cur_tid, &x) : !get_ctx(g_cur_tid, &c, CONTEXT_CONTROL)) {
        char msg[256];
        win_error(GetLastError(), msg, sizeof msg);
        snprintf(err, esz, "%s (thread %lu): %s", g_wow64 ? "Wow64GetThreadContext" : "GetThreadContext",
                 (unsigned long)g_cur_tid, msg);
        return false;
    }
    g_tmp = addr;
    g_tmp_rsp = g_wow64 ? x.sp : c.Rsp;
    g_tmp_tid = g_cur_tid;
    g_tmp_on = true;
    if (!start(false, err, esz)) { g_tmp_on = false; return false; }
    return true;
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

/* ---- not done yet on Windows ------------------------------------------- */

long dbg_console_read(char *buf, size_t sz)        { (void)buf; (void)sz; return -1; }
long dbg_console_write(const char *buf, size_t n)  { (void)buf; (void)n;  return -1; }

bool dbg_map_name(uint64_t rt, char *out, size_t sz) {
    (void)rt; (void)out; (void)sz;
    return false;
}

#ifdef DBG_WIN_TEST
/* ---- test access (tests/win/t_dbg.c scenarios U, T; mock build only) ----
 * Compiled only with -DDBG_WIN_TEST: never in Abyss, not in dbg.h, so the
 * symbol set of a normal dbg_win.o stays that of dbg.h. The test declares
 * these twenty itself. dbg_win_test_wow64(on): on 0 / 1 sets g_wow64, -1 only
 * reads it; returns the value before. The context goes through DbgRegs
 * (dbg.h) field by field: rip = ip, rsp = sp, rflags = flags, rax..r15 =
 * ax..r15; the DbgCtx handed to ctx_get is filled with 0x5a first.
 * dbg_win_test_set_tf(tid, on) is set_tf (scenario T), dbg_win_test_set_rip
 * set_rip (scenario R). dbg_win_test_main(tid, h): main's thread as
 * dbg_launch records it (g_main_tid, g_hthread; 0, NULL: none), so that
 * thread_handle hands back h for tid; h stays the caller's: put 0, NULL back
 * before dbg_kill (reset closes g_hthread). dbg_win_test_stopped(tid): a stop
 * on thread tid as dbg_get_regs sees it (g_state DBG_STOPPED, g_cur_tid; no
 * process handle, so dbg_state does not look further); 0: DBG_NONE again
 * (scenario G).
 * Scenario P (the ip readers), each one on a frozen thread of the mock:
 * dbg_win_test_session(pid, hproc, base): the debuggee as dbg_launch records
 * it (g_pid, g_hproc, g_base_addr = base - the link base of dbg_bp_image);
 * hproc stays the caller's: put 0, NULL, 0 back before dbg_kill.
 * dbg_win_test_on_bp(tid, rt): on_bp(tid) with the run_to target at process
 * address rt for that call. dbg_win_test_stop_on(ev, why): stop_on(ev, why),
 * returns the stop's rip, then the stop is dropped (state DBG_NONE, no event
 * pending: the caller answers ev). dbg_win_test_step_trap(ev, from, *rip):
 * on_event(ev) (a SINGLE_STEP, no step in progress) after its step began at
 * `from`; *rip the stop's, stop dropped. dbg_win_test_exit_thread(ev, live,
 * *rip, *cur): on_event(ev), the EXIT_THREAD of the stepping thread
 * ev->dwThreadId, thread `live` the only one known; *rip, *cur: the stop's
 * rip and current thread; the list emptied, stop dropped.
 * dbg_win_test_hold_back_in(tid, from, *dep): hold_back_in() with tid
 * stepping from `from` during a hold; *dep the departure noted (0: none);
 * then the int3 out, tid resumed, no step, nothing noted. dbg_win_test_start(
 * ev, *from, err, esz): start(step) as dbg_step calls it, stopped on ev
 * (pending, main's thread unknown); *from the rip before the step; it
 * answers ev itself; then no step, none held, the stop dropped (the trap
 * flag stays).
 * Scenario Q (bp_hit, dbg_run_to): dbg_win_test_run_to(ev, addr, *sp, *tid,
 * err, esz): dbg_run_to(addr) on a stop on ev (pending, as in _start);
 * *sp, *tid: the frame and thread it recorded (whatever it returned); then
 * no target, no step, the stop dropped. dbg_win_test_bp_hit(ev, rt, sp,
 * *why, *rip): bp_hit(ev) with, if rt, the run_to target at process address
 * rt on ev's thread with frame sp (none if rt is 0); returns bp_hit's
 * value, *why / *rip the stop's (1) or 0 / its last rip; then no target, the
 * stop dropped, and for 2 (bp_hit answered ev, its step over begun) no step
 * noted, none held: the trap flag stays, the single step is the caller's.
 * Scenario L (let_go): dbg_win_test_let_go(): the session running (no
 * event pending), the int3 of every breakpoint written (bp_insert_all),
 * then let_go() as dbg_detach calls it; returns the int3 count written
 * before; then the session dropped (state DBG_NONE, as test_drop).
 * Scenario S (sys_bp): dbg_win_test_sys_bp(sys, brk): sys 0 / 1 sets g_sys_bp
 * (and clears g_sys_wx86: the state dbg_launch leaves), brk >= 0 sets
 * g_brk_pending, -1 leaves either; returns the state before, g_sys_bp
 * (bit 0) | g_brk_pending << 1.
 * Scenario M (module_base, load_base): dbg_win_test_module_base(exe, esz,
 * *base) is module_base as dbg_attach calls it, dbg_win_test_load_base(hfile,
 * path, base) load_base as dbg_launch calls it (g_hproc: dbg_win_test_session). */
static void test_drop(void) {             /* the stop is the caller's again */
    g_ev_pending = false;
    g_state = DBG_NONE;
    g_stop = DBG_STOP_NONE;
    g_cur_tid = 0;
}

int dbg_win_test_wow64(int on) {
    int was = g_wow64;
    if (on >= 0) g_wow64 = on != 0;
    return was;
}

bool dbg_win_test_ctx_get(unsigned long tid, DbgRegs *r) {
    DbgCtx x;
    memset(&x, 0x5a, sizeof x);            /* a field ctx_get leaves unset shows */
    bool ok = ctx_get((DWORD)tid, &x);
    r->rip = x.ip;  r->rsp = x.sp;  r->rflags = x.flags;
    r->rax = x.ax;  r->rbx = x.bx;  r->rcx = x.cx;  r->rdx = x.dx;
    r->rsi = x.si;  r->rdi = x.di;  r->rbp = x.bp;
    r->r8  = x.r8;  r->r9  = x.r9;  r->r10 = x.r10; r->r11 = x.r11;
    r->r12 = x.r12; r->r13 = x.r13; r->r14 = x.r14; r->r15 = x.r15;
    return ok;
}

bool dbg_win_test_ctx_set(unsigned long tid, const DbgRegs *r) {
    DbgCtx x;
    x.ip = r->rip;  x.sp = r->rsp;  x.flags = r->rflags;
    x.ax = r->rax;  x.bx = r->rbx;  x.cx = r->rcx;  x.dx = r->rdx;
    x.si = r->rsi;  x.di = r->rdi;  x.bp = r->rbp;
    x.r8  = r->r8;  x.r9  = r->r9;  x.r10 = r->r10; x.r11 = r->r11;
    x.r12 = r->r12; x.r13 = r->r13; x.r14 = r->r14; x.r15 = r->r15;
    return ctx_set((DWORD)tid, &x);
}

bool dbg_win_test_set_tf(unsigned long tid, bool on) {
    return set_tf((DWORD)tid, on);
}

bool dbg_win_test_set_rip(unsigned long tid, uint64_t rip) {
    return set_rip((DWORD)tid, rip);
}

void dbg_win_test_main(unsigned long tid, void *h) {
    g_main_tid = (DWORD)tid;
    g_hthread = (HANDLE)h;
}

void dbg_win_test_stopped(unsigned long tid) {
    g_state = tid ? DBG_STOPPED : DBG_NONE;
    g_cur_tid = (DWORD)tid;
}

void dbg_win_test_session(unsigned long pid, void *hproc, uint64_t base) {
    g_pid = (int)pid;
    g_hproc = (HANDLE)hproc;
    g_base_addr = base ? base - g_link_lo : 0;
}

bool dbg_win_test_on_bp(unsigned long tid, uint64_t rt) {
    g_tmp = rt - g_base_addr;
    g_tmp_on = true;
    bool r = on_bp((DWORD)tid);
    g_tmp_on = false;
    return r;
}

uint64_t dbg_win_test_stop_on(const DEBUG_EVENT *ev, int why) {
    stop_on(ev, (DbgStop)why);
    uint64_t r = g_stop_rip;
    test_drop();
    return r;
}

bool dbg_win_test_step_trap(DEBUG_EVENT *ev, uint64_t step_from, uint64_t *stop_rip) {
    g_step_from = step_from;
    bool r = on_event(ev);
    *stop_rip = g_stop_rip;
    test_drop();
    return r;
}

bool dbg_win_test_exit_thread(DEBUG_EVENT *ev, unsigned long live_tid, uint64_t *stop_rip, unsigned long *cur_tid) {
    thr_add((DWORD)live_tid);
    g_step_tid = ev->dwThreadId;
    bool r = on_event(ev);
    *stop_rip = g_stop_rip;
    *cur_tid = g_cur_tid;
    thr_clear();
    test_drop();
    return r;
}

bool dbg_win_test_hold_back_in(unsigned long tid, uint64_t step_from, uint64_t *dep_at) {
    g_hold = true;
    g_step_tid = (DWORD)tid;
    g_step_from = step_from;
    bool r = hold_back_in();
    *dep_at = g_dep_tid == (DWORD)tid ? g_dep_at : 0;
    bp_remove_all();
    thr_clear();
    g_step_tid = 0;
    g_dep_tid = 0;
    return r;
}

bool dbg_win_test_start(const DEBUG_EVENT *ev, uint64_t *step_from, char *err, size_t esz) {
    g_state = DBG_STOPPED;
    g_ev_pending = true;
    g_ev_pid = ev->dwProcessId;
    g_ev_tid = ev->dwThreadId;
    g_cur_tid = ev->dwThreadId;
    bool r = start(true, err, esz);
    *step_from = g_step_from;
    g_step_tid = 0;
    g_stepover = false;
    unhold_all();
    test_drop();
    return r;
}

bool dbg_win_test_run_to(const DEBUG_EVENT *ev, uint64_t addr, uint64_t *tmp_sp, unsigned long *tmp_tid,
                         char *err, size_t esz) {
    g_state = DBG_STOPPED;
    g_ev_pending = true;
    g_ev_pid = ev->dwProcessId;
    g_ev_tid = ev->dwThreadId;
    g_cur_tid = ev->dwThreadId;
    g_tmp_rsp = 0;
    g_tmp_tid = 0;
    bool r = dbg_run_to(addr, err, esz);
    *tmp_sp = g_tmp_rsp;
    *tmp_tid = g_tmp_tid;
    g_tmp_on = false;
    g_step_tid = 0;
    g_stepover = false;
    unhold_all();
    test_drop();
    return r;
}

int dbg_win_test_bp_hit(const DEBUG_EVENT *ev, uint64_t rt, uint64_t sp, int *why, uint64_t *stop_rip) {
    g_tmp_on = rt != 0;
    if (rt) {
        g_tmp = rt - g_base_addr;
        g_tmp_rsp = sp;
        g_tmp_tid = ev->dwThreadId;
    }
    g_stop = DBG_STOP_NONE;
    int r = bp_hit(ev);
    *why = r == 1 ? (int)g_stop : 0;
    *stop_rip = g_stop_rip;
    g_tmp_on = false;
    g_step_tid = 0;
    g_stepover = false;
    g_pass = false;
    unhold_all();
    test_drop();
    return r;
}

int dbg_win_test_let_go(void) {
    g_state = DBG_RUNNING;
    g_ev_pending = false;
    bp_insert_all();
    int n = g_nins;
    let_go();
    test_drop();
    return n;
}

int dbg_win_test_sys_bp(int sys, int brk) {
    int was = (g_sys_bp ? 1 : 0) | g_brk_pending << 1;
    if (sys >= 0) { g_sys_bp = sys != 0; g_sys_wx86 = false; }
    if (brk >= 0) g_brk_pending = brk;
    return was;
}

bool dbg_win_test_module_base(char *exe, unsigned long esz, uint64_t *base) {
    return module_base(exe, (DWORD)esz, base);
}

void dbg_win_test_load_base(void *hfile, const char *path, uint64_t base) {
    load_base((HANDLE)hfile, path, base);
}
#endif /* DBG_WIN_TEST */

#endif /* _WIN32 */
