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
 * whose path is the program's, from EnumProcessModules, that event as a
 * fallback). g_base_addr = that base - the ImageBase of the file, read in
 * the PE header of the hFile of the event (the path when there is none,
 * the header in memory as a last resort: the loader may have written the
 * real base there). g_img_lo / g_img_hi: ImageBase, + SizeOfImage, for
 * dbg_to_file.
 *
 * Breakpoints: the dbg.c model. g_bp is the sorted list of file
 * addresses (kept across launches: the base changes each time); the int3
 * bytes go in (ReadProcessMemory of the original byte, WriteProcessMemory
 * of 0xCC, FlushInstructionCache) just before a dbg_cont / dbg_run_to
 * resume and come out again at every reported stop (stop_on), so a
 * stopped process always shows its own code. g_ins records what is in
 * memory now. A hit (EXCEPTION_BREAKPOINT at an address of g_ins) puts
 * rip of that thread back onto the breakpoint (SetThreadContext, the
 * exception leaves it one past the int3). Resuming a thread whose rip is
 * on a breakpoint first single-steps it (trap flag) with nothing
 * written, then writes them all and goes on (g_stepover). dbg_step
 * writes none. The temporary breakpoint of dbg_run_to only stops in the
 * thread that asked, when rsp >= its value then (a deeper frame steps
 * over it and goes on); any reported stop ends it.
 *
 * Threads and breakpoints: every thread runs while one steps over a
 * breakpoint, with no int3 in memory (a breakpoint passed then is
 * missed). Two threads can hit int3 bytes at once: the second hit is
 * reported once the bytes are out; an int3 exception at a breakpoint
 * whose byte, back in memory, is not 0xCC is still ours (rip put back).
 * The single-step of a step that another stop cut short is swallowed
 * when it comes (g_late_tid).
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
 * first one), the break-in thread of an attach and of DebugBreakProcess
 * (at ntdll!DbgBreakPoint). Any other exception is passed on to the
 * program (DBG_EXCEPTION_NOT_HANDLED) without stopping: a crash ends as
 * DBG_EXITED with its NTSTATUS.
 *
 * Threads: the registers (and dbg_step) are those of the thread that
 * stopped; after dbg_interrupt (which stops in the injected break-in
 * thread) those of the first thread of the process, while it lives. Every
 * thread runs during a step, only the stepped one has the trap flag.
 * 32-bit (WOW64) programs are not handled: their registers are not read.
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

#define DBG_POLL_MS   50       /* wgetch timeout while the debuggee runs      */
#define DBG_START_MS  10000    /* launch / attach: longest wait, first event  */
#define DBG_KILL_MS   3000     /* kill: longest wait for the exit             */
#define DBG_INTR_MS   1000     /* dbg_interrupt: longest wait for the break-in */
#define DBG_TF        0x100    /* trap flag of EFlags                          */
#define DBG_WX86_BREAKPOINT 0x4000001Fu  /* loader breakpoint of a WOW64 program */
#define DBG_SETTLE_EXTRA 64    /* events still taken once the wait time is out */

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
static int      g_brk_pending = 0;     /* break-in breakpoints still to come       */
static bool     g_intr     = false;    /* dbg_interrupt waits for one              */
static uint64_t g_stop_rip = 0;        /* rip (or int3 address) of the last stop   */

/* load base (see the top of the file) */
static uint64_t g_base_addr = 0;       /* process addr - file addr             */
static uint64_t g_img_lo = 0;          /* file addresses of the image,         */
static uint64_t g_img_hi = 0;          /* [lo, hi); hi 0: unknown              */

/* breakpoints (see the top of the file) */
static uint64_t g_bp[DBG_MAX_BP];      /* file addresses, ascending            */
static int      g_nbp = 0;
static uint64_t g_ins[DBG_MAX_BP + 1]; /* int3 written there (process addr)    */
static uint8_t  g_orig[DBG_MAX_BP + 1];/* the byte it replaced                 */
static int      g_nins = 0;
static bool     g_tmp_on  = false;     /* dbg_run_to in progress               */
static uint64_t g_tmp     = 0;         /* its file address                     */
static uint64_t g_tmp_rsp = 0;         /* rsp when it was asked                */
static DWORD    g_tmp_tid = 0;         /* in that thread                       */
static bool     g_stepover = false;    /* g_step_tid only gets past a breakpoint */
static DWORD    g_late_tid = 0;        /* its step cut short: the trap may still come */

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

/* The handles an event hands to the debugger that it must close itself
 * (the hProcess / hThread of CREATE_PROCESS belong to the system). */
static void close_event_files(DEBUG_EVENT *ev) {
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

static void reset(void) {
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
    g_brk_pending = 0;
    g_intr = false;
    g_stop_rip = 0;
    g_nins = 0;                        /* the process they were in is gone */
    g_tmp_on = false;
    g_stepover = false;
    g_late_tid = 0;
    g_base_addr = 0;
    g_img_lo = g_img_hi = 0;
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
    g_brk_pending = 0;
    g_nins = 0;
    g_tmp_on = false;
    g_stepover = false;
    g_late_tid = 0;
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

/* Sets or clears the trap flag of thread `tid`. Suspended meanwhile: it
 * may be running (dbg_detach of a running process). */
static bool set_tf(DWORD tid, bool on) {
    bool own;
    HANDLE h = thread_handle(tid, &own);
    if (!h) return false;
    bool susp = SuspendThread(h) != (DWORD)-1;
    CONTEXT c;
    memset(&c, 0, sizeof c);
    c.ContextFlags = CONTEXT_CONTROL;
    bool ok = GetThreadContext(h, &c) != 0;
    if (ok) {
        if (on) c.EFlags |= DBG_TF; else c.EFlags &= ~(DWORD)DBG_TF;
        ok = SetThreadContext(h, &c) != 0;
    }
    if (susp) ResumeThread(h);
    if (own) CloseHandle(h);
    return ok;
}

/* A dbg_step is over (done or cut short by another stop): trap flag out. */
static void end_step(void) {
    if (g_step_tid) set_tf(g_step_tid, false);
    g_step_tid = 0;
    g_stepover = false;
}

/* rip of thread `tid` (stopped) := rip */
static bool set_rip(DWORD tid, uint64_t rip) {
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

/* ImageBase and SizeOfImage of a PE header (PE32+, PE32) */
static bool pe_header(ReadAt rd, void *src, uint64_t *image_base, uint32_t *size) {
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
    return true;
}

/* Base of the module of the stopped process whose path is the program's
 * (EnumProcessModules: an attach, the loader has run); `exe` gets that
 * path ("" if unknown). */
static bool module_base(char *exe, DWORD esz, uint64_t *base) {
    static HMODULE mods[1024];
    char name[MAX_PATH * 2];
    DWORD need = 0;
    if (!GetModuleFileNameExA(g_hproc, NULL, exe, esz)) { exe[0] = '\0'; return false; }
    if (!EnumProcessModules(g_hproc, mods, sizeof mods, &need)) return false;
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
static void load_base(HANDLE hfile, const char *path, uint64_t base) {
    g_base_addr = 0;
    g_img_lo = g_img_hi = 0;
    if (!base) return;
    uint64_t ib = 0;
    uint32_t size = 0;
    bool ok = hfile && pe_header(read_file_at, hfile, &ib, &size);
    if (!ok && path && *path) {
        HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            ok = pe_header(read_file_at, f, &ib, &size);
            CloseHandle(f);
        }
    }
    if (!ok) ok = pe_header(read_mem_at, (void *)(uintptr_t)base, &ib, &size);
    if (!ok) return;
    g_base_addr = base - ib;
    if (size && ib <= UINT64_MAX - size) { g_img_lo = ib; g_img_hi = ib + size; }
}

/* ---- breakpoint bytes ---- */

/* file address -> process address */
static uint64_t to_rt(uint64_t file_addr) { return file_addr + g_base_addr; }

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
    for (int i = 0; i < g_nbp; i++) ins_one(to_rt(g_bp[i]));
    if (g_tmp_on) ins_one(to_rt(g_tmp));
}

/* puts the original bytes back */
static void bp_remove_all(void) {
    for (int i = g_nins; i-- > 0; ) poke_byte(g_ins[i], g_orig[i], NULL);
    g_nins = 0;
}

/* is process address `at` the place of a breakpoint (or the run_to target)? */
static bool bp_at_rt(uint64_t at) {
    return (g_tmp_on && to_rt(g_tmp) == at) || bp_find(at - g_base_addr);
}

/* An int3 trap at a breakpoint that is no longer written (another thread
 * hit it before the bytes came out, see the top of the file)? */
static bool bp_stale(uint64_t at) {
    uint8_t b;
    return ins_index(at) < 0 && bp_at_rt(at) && mem_read(at, &b, 1) && b != 0xCC;
}

static bool on_bp(DWORD tid) {
    CONTEXT c;
    return get_ctx(tid, &c, CONTEXT_CONTROL) && bp_at_rt(c.Rip);
}

/* ntdll!DbgBreakPoint, where the break-in thread of DebugActiveProcess /
 * DebugBreakProcess stops (ntdll is at the same address in every 64-bit
 * process of a boot). 0: unknown. */
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

/* Is breakpoint event `ev` one the system raised for the debugger? 0:
 * no (the program's own), 1: the loader breakpoint of a launch, 2: a
 * break-in (attach, DebugBreakProcess). It is counted off. */
static int sys_bp(const DEBUG_EVENT *ev) {
    if (g_sys_bp) { g_sys_bp = false; return 1; }
    if (g_brk_pending > 0) {
        uint64_t at = (uint64_t)(uintptr_t)ev->u.Exception.ExceptionRecord.ExceptionAddress;
        uint64_t brk = break_addr();
        if (!brk || at == brk) { g_brk_pending--; return 2; }
    }
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
 * an int3 hit just before the bytes came out gets its rip put back. */
static void let_go(void) {
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
        if (ev.dwProcessId == pid && ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
            && (code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP)) {
            uint64_t at = (uint64_t)(uintptr_t)ev.u.Exception.ExceptionRecord.ExceptionAddress;
            if (code == EXCEPTION_BREAKPOINT && bp_stale(at)) set_rip(ev.dwThreadId, at);
            else if (code == EXCEPTION_BREAKPOINT) sys_bp(&ev);
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
    else
        g_stop_rip = get_ctx(g_cur_tid, &c, CONTEXT_CONTROL) ? c.Rip : 0;
}

/* An int3 trap of thread ev: one of ours (written now, or stale)? Then
 * rip goes back onto it, and the stop is reported (1), or, for the
 * dbg_run_to target in a deeper frame or another thread, the thread
 * steps over it with no int3 written and goes on (2). 0: not ours. */
static int bp_hit(const DEBUG_EVENT *ev) {
    uint64_t at = (uint64_t)(uintptr_t)ev->u.Exception.ExceptionRecord.ExceptionAddress;
    DWORD tid = ev->dwThreadId;
    if (ins_index(at) < 0 && !bp_stale(at)) return 0;
    CONTEXT c;
    if (!set_rip(tid, at) || !get_ctx(tid, &c, CONTEXT_CONTROL)) return 0;
    if (g_tmp_on && to_rt(g_tmp) == at && tid == g_tmp_tid && c.Rsp >= g_tmp_rsp) {
        stop_on(ev, DBG_STOP_TEMP);
        return 1;
    }
    if (bp_find(at - g_base_addr)) {
        stop_on(ev, DBG_STOP_BP);
        return 1;
    }
    bp_remove_all();                          /* a recursive call: not this frame */
    if (!g_step_tid) {                        /* else the bytes come back after that step */
        if (!set_tf(tid, true)) { stop_on(ev, DBG_STOP_TEMP); return 1; }
        g_step_tid = tid;
        g_stepover = true;
    }
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
    case EXIT_THREAD_DEBUG_EVENT:
        if (ev->dwThreadId == g_main_tid) g_main_tid = 0;
        if (ev->dwThreadId == g_step_tid) {   /* the bytes of a step over come back */
            if (g_stepover) bp_insert_all();
            g_step_tid = 0;
            g_stepover = false;
        }
        if (ev->dwThreadId == g_late_tid) g_late_tid = 0;
        break;
    case EXCEPTION_DEBUG_EVENT: {
        DWORD code = ev->u.Exception.ExceptionRecord.ExceptionCode;
        DWORD tid = ev->dwThreadId;
        if (code == EXCEPTION_SINGLE_STEP) {
            if (g_stepover && tid == g_step_tid) {
                /* past the breakpoint it resumed on: write them all, go on */
                end_step();
                bp_insert_all();
                break;
            }
            if (tid == g_late_tid && tid != g_step_tid) {   /* a step cut short, done now */
                g_late_tid = 0;
                break;
            }
            stop_on(ev, DBG_STOP_STEP);
            return true;
        }
        if (code == EXCEPTION_BREAKPOINT) {
            int ours = bp_hit(ev);
            if (ours) return ours == 1;
            int sys = sys_bp(ev);
            if (sys == 0 || (sys == 2 && g_intr)) {
                stop_on(ev, sys == 0 ? DBG_STOP_BP : DBG_STOP_INTERRUPT);
                return true;
            }
            break;                            /* the system's: DBG_CONTINUE */
        }
        if (code == DBG_WX86_BREAKPOINT) break;
        ContinueDebugEvent(ev->dwProcessId, ev->dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
        return false;
    }
    default:        /* CREATE_THREAD, LOAD_DLL, UNLOAD_DLL, OUTPUT_DEBUG_STRING, RIP */
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
        if (!WaitForDebugEvent(&ev, used >= ms ? 0 : ms - used)) return;
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
    bool over = !step && on_bp(g_cur_tid);
    if (step || over) {
        if (!set_tf(g_cur_tid, true)) {
            char msg[256];
            win_error(GetLastError(), msg, sizeof msg);
            snprintf(err, esz, "SetThreadContext (thread %lu): %s", (unsigned long)g_cur_tid, msg);
            return false;
        }
        g_step_tid = g_cur_tid;
        g_stepover = over;
    } else
        bp_insert_all();
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

/* true when the debuggee is stopped on return */
bool dbg_interrupt(void) {
    if (dbg_state() == DBG_STOPPED) return true;
    if (g_state != DBG_RUNNING) return false;
    settle(0);                                /* a stop already waiting */
    if (g_state != DBG_RUNNING) return g_state == DBG_STOPPED;
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
    CONTEXT c;
    if (!get_ctx(g_cur_tid, &c, CONTEXT_FULL)) return false;
    r->rip = c.Rip;  r->rsp = c.Rsp;  r->rbp = c.Rbp;
    r->rax = c.Rax;  r->rbx = c.Rbx;  r->rcx = c.Rcx;  r->rdx = c.Rdx;
    r->rsi = c.Rsi;  r->rdi = c.Rdi;  r->rflags = c.EFlags;
    return true;
}

/* ---- breakpoints, run to ----------------------------------------------- */

/* file address `file_addr` must be code of the stopped debuggee: committed
 * memory with an execute permission, readable */
static bool check_code(uint64_t file_addr, char *err, size_t esz) {
    uint64_t at = to_rt(file_addr);
    MEMORY_BASIC_INFORMATION mi;
    uint8_t b;
    if (!VirtualQueryEx(g_hproc, (LPCVOID)(uintptr_t)at, &mi, sizeof mi) || mi.State != MEM_COMMIT) {
        snprintf(err, esz, "0x%llx (0x%llx in the process) is not mapped in pid %d",
                 (unsigned long long)file_addr, (unsigned long long)at, g_pid);
        return false;
    }
    if (!(mi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
        || (mi.Protect & PAGE_GUARD)) {
        snprintf(err, esz, "0x%llx is not code (no exec permission)", (unsigned long long)file_addr);
        return false;
    }
    if (!mem_read(at, &b, 1)) {
        char msg[256];
        win_error(GetLastError(), msg, sizeof msg);
        snprintf(err, esz, "ReadProcessMemory(0x%llx): %s", (unsigned long long)at, msg);
        return false;
    }
    return true;
}

bool dbg_bp_add(uint64_t addr, char *err, size_t esz) {
    err[0] = '\0';
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
}

bool dbg_bp_remove(uint64_t addr, char *err, size_t esz) {
    err[0] = '\0';
    if (dbg_state() == DBG_RUNNING) { snprintf(err, esz, "The program is running (interrupt it first)"); return false; }
    int i = bp_index(addr);
    if (i >= g_nbp || g_bp[i] != addr) {
        snprintf(err, esz, "No breakpoint at 0x%llx", (unsigned long long)addr);
        return false;
    }
    /* the byte is already back while it is stopped; written all the same
     * (an int3 left behind would kill the program) */
    int k = ins_index(to_rt(addr));
    if (k >= 0 && !(g_tmp_on && g_tmp == addr)) {
        poke_byte(g_ins[k], g_orig[k], NULL);
        g_ins[k] = g_ins[g_nins - 1];
        g_orig[k] = g_orig[g_nins - 1];
        g_nins--;
    }
    memmove(g_bp + i, g_bp + i + 1, (size_t)(g_nbp - i - 1) * sizeof g_bp[0]);
    g_nbp--;
    return true;
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
    if (dbg_state() == DBG_RUNNING) return;
    g_nbp = 0;
}

bool dbg_run_to(uint64_t addr, char *err, size_t esz) {
    err[0] = '\0';
    if (!need_stopped(err, esz)) return false;
    if (!check_code(addr, err, esz)) return false;
    CONTEXT c;
    if (!get_ctx(g_cur_tid, &c, CONTEXT_CONTROL)) {
        char msg[256];
        win_error(GetLastError(), msg, sizeof msg);
        snprintf(err, esz, "GetThreadContext (thread %lu): %s", (unsigned long)g_cur_tid, msg);
        return false;
    }
    g_tmp = addr;
    g_tmp_rsp = c.Rsp;
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

#endif /* _WIN32 */
