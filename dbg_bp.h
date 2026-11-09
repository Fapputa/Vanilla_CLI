/* Breakpoint model shared by dbg.c (ptrace) and dbg_win.c (Win32): private
 * to those two files, each includes it once, after defining g_base_addr
 * and the hooks declared below. Only one of them is linked (see the
 * Makefiles), so the public dbg_bp_* functions here are not defined twice.
 *
 * The list (g_bp, at most DBG_MAX_BP): first the breakpoints of the program,
 * sorted by file address, then those of other modules, sorted by (module,
 * rva). A breakpoint of the program is known by its file address (va) and
 * by its offset in the image (rva = va - g_link_lo, g_link_lo: lowest
 * PT_LOAD page of the ELF, ImageBase of the PE). Its process address is
 * always computed from the rva and the load base of the current process:
 * g_link_lo + g_base_addr + rva. Nothing here touches the debuggee. */
#ifndef DBG_BP_H
#define DBG_BP_H

#include "dbg.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

/* platform side */
static bool bp_hook_can_change(char *err, size_t esz);          /* false: running   */
static bool bp_hook_stopped(void);                              /* a stopped debuggee */
/* `rt` holds code the debugger may write to; `shown`: the address for the message */
static bool bp_hook_check_code(uint64_t rt, uint64_t shown, char *err, size_t esz);
static bool bp_hook_module_ok(char *err, size_t esz);           /* other modules handled? */
static bool bp_hook_hw_ok(char *err, size_t esz);               /* DR0-DR3 handled?  */
/* process address of (module, rva) when that module is loaded now */
static bool bp_hook_module_rt(const char *module, uint64_t rva, uint64_t *rt);

static DbgBp    g_bp[DBG_MAX_BP];
static int      g_nbp = 0;
static int      g_nmain = 0;           /* g_bp[0 .. g_nmain): the program's     */
static char     g_prog[DBG_MOD_MAX];   /* its file name, "" until known         */
static uint64_t g_link_lo = 0;         /* its link base, 0 until known          */
static int      g_bits = 0;            /* 32 / 64, 0 until known                */
static int      g_last_bp = -1;        /* index of the breakpoint of the last stop */
static char     g_bp_news[160];        /* a problem not told yet, "" : none     */

static uint64_t g_base_addr;           /* process addr - file addr              */

static __attribute__((unused)) void bp_tell(const char *what, const DbgBp *b) {
    if (g_bp_news[0]) return;           /* the first one: the panel lists the rest */
    if (b->main)
        snprintf(g_bp_news, sizeof g_bp_news, "breakpoint 0x%llx %s", (unsigned long long)b->va, what);
    else
        snprintf(g_bp_news, sizeof g_bp_news, "breakpoint %s+0x%llx %s", b->module, (unsigned long long)b->rva, what);
}

static uint64_t bpm_rt(const DbgBp *b) {
    return b->main ? g_link_lo + g_base_addr + b->rva : b->rt;
}

/* insertion point of file address va among the program's breakpoints */
static int bpm_index(uint64_t va) {
    int lo = 0, hi = g_nmain;
    while (lo < hi) {
        int mid = (lo + hi) / 2;
        if (g_bp[mid].va < va) lo = mid + 1; else hi = mid;
    }
    return lo;
}

/* enabled breakpoint at process address `rt`, -1: none. Two breakpoints
 * cannot share an address of the program; a module mapped at the same place
 * as the program does not exist, the first one wins. */
static __attribute__((unused)) int bpm_at_rt(uint64_t rt) {
    for (int i = 0; i < g_nbp; i++)
        if (g_bp[i].enabled && g_bp[i].state != DBG_BPS_PENDING && bpm_rt(&g_bp[i]) == rt) return i;
    return -1;
}

/* the program's image is known: the rvas follow */
static __attribute__((unused)) void bpm_rebase(uint64_t link_lo) {
    g_link_lo = link_lo;
    for (int i = 0; i < g_nmain; i++) g_bp[i].rva = g_bp[i].va - link_lo;
}

/* a new process: counters and states start over, module addresses are lost */
static __attribute__((unused)) void bpm_new_session(void) {
    for (int i = 0; i < g_nbp; i++) {
        g_bp[i].hits = 0;
        g_bp[i].overwritten = false;
        g_bp[i].state = g_bp[i].main ? DBG_BPS_IDLE : DBG_BPS_PENDING;
        if (!g_bp[i].main) g_bp[i].rt = 0;
    }
    g_last_bp = -1;
    g_bp_news[0] = '\0';
}

/* the process is gone: nothing is written anywhere */
static void bpm_session_end(void) {
    for (int i = 0; i < g_nbp; i++) {
        g_bp[i].state = g_bp[i].main ? DBG_BPS_IDLE : DBG_BPS_PENDING;
        if (!g_bp[i].main) g_bp[i].rt = 0;
    }
}

/* ---- conditions ---- */

typedef struct { const char *name; uint8_t id; uint8_t width; } CondReg;   /* width: 32 only for the e* names */
enum { CR_RIP, CR_RSP, CR_RBP, CR_RAX, CR_RBX, CR_RCX, CR_RDX, CR_RSI, CR_RDI, CR_RFLAGS,
       CR_R8, CR_R9, CR_R10, CR_R11, CR_R12, CR_R13, CR_R14, CR_R15, CR_HITS };
enum { CO_EQ, CO_NE, CO_LT, CO_LE, CO_GT, CO_GE };

static const CondReg g_cond_regs[] = {
    { "rip", CR_RIP, 64 }, { "rsp", CR_RSP, 64 }, { "rbp", CR_RBP, 64 }, { "rax", CR_RAX, 64 },
    { "rbx", CR_RBX, 64 }, { "rcx", CR_RCX, 64 }, { "rdx", CR_RDX, 64 }, { "rsi", CR_RSI, 64 },
    { "rdi", CR_RDI, 64 }, { "rflags", CR_RFLAGS, 64 },
    { "r8", CR_R8, 64 }, { "r9", CR_R9, 64 }, { "r10", CR_R10, 64 }, { "r11", CR_R11, 64 },
    { "r12", CR_R12, 64 }, { "r13", CR_R13, 64 }, { "r14", CR_R14, 64 }, { "r15", CR_R15, 64 },
    { "eip", CR_RIP, 32 }, { "esp", CR_RSP, 32 }, { "ebp", CR_RBP, 32 }, { "eax", CR_RAX, 32 },
    { "ebx", CR_RBX, 32 }, { "ecx", CR_RCX, 32 }, { "edx", CR_RDX, 32 }, { "esi", CR_RSI, 32 },
    { "edi", CR_RDI, 32 }, { "eflags", CR_RFLAGS, 32 },
    { "hits", CR_HITS, 64 },
};

/* "<reg> <op> <number>": reg = rax... (the 32-bit names too: their low half),
 * or hits; op = == != < <= > >=; number = 0x.. or decimal, -n wraps to the
 * width. Comparisons are unsigned. */
static bool cond_parse(const char *s, DbgBp *b, char *err, size_t esz) {
    while (*s == ' ' || *s == '\t') s++;
    char name[12];
    size_t n = 0;
    while (isalnum((unsigned char)s[n])) {
        if (n + 1 >= sizeof name) { snprintf(err, esz, "condition: unknown register \"%.*s...\"", (int)n, s); return false; }
        name[n] = (char)tolower((unsigned char)s[n]);
        n++;
    }
    name[n] = '\0';
    if (!n) { snprintf(err, esz, "condition: expected <register> <op> <value>, like rax == 0x10 or hits >= 3"); return false; }
    const CondReg *r = NULL;
    for (size_t i = 0; i < sizeof g_cond_regs / sizeof g_cond_regs[0]; i++)
        if (!strcmp(g_cond_regs[i].name, name)) { r = &g_cond_regs[i]; break; }
    if (!r) { snprintf(err, esz, "condition: unknown register \"%s\"", name); return false; }
    if (g_bits == 32 && r->id != CR_HITS && r->width == 64) {
        snprintf(err, esz, "condition: no register %s in a 32-bit program", name);
        return false;
    }
    s += n;
    while (*s == ' ' || *s == '\t') s++;
    uint8_t op;
    if      (s[0] == '=' && s[1] == '=') { op = CO_EQ; s += 2; }
    else if (s[0] == '!' && s[1] == '=') { op = CO_NE; s += 2; }
    else if (s[0] == '<' && s[1] == '=') { op = CO_LE; s += 2; }
    else if (s[0] == '>' && s[1] == '=') { op = CO_GE; s += 2; }
    else if (s[0] == '<') { op = CO_LT; s++; }
    else if (s[0] == '>') { op = CO_GT; s++; }
    else { snprintf(err, esz, "condition: expected == != < <= > >= after %s", name); return false; }
    while (*s == ' ' || *s == '\t') s++;
    bool neg = *s == '-';
    if (neg) s++;
    bool hex = s[0] == '0' && (s[1] == 'x' || s[1] == 'X');
    const char *p = hex ? s + 2 : s;
    if (!(hex ? isxdigit((unsigned char)*p) : isdigit((unsigned char)*p))) {
        snprintf(err, esz, "condition: expected a number after the operator");
        return false;
    }
    errno = 0;
    char *end;
    unsigned long long v = strtoull(p, &end, hex ? 16 : 10);
    if (errno == ERANGE) { snprintf(err, esz, "condition: number too large"); return false; }
    while (*end == ' ' || *end == '\t') end++;
    if (*end) { snprintf(err, esz, "condition: unexpected \"%.20s\"", end); return false; }
    uint64_t mask = r->width == 32 ? 0xffffffffull : ~0ull;
    if (!neg && (uint64_t)v > mask) { snprintf(err, esz, "condition: 0x%llx does not fit %s", v, name); return false; }
    if (neg && (uint64_t)v > (mask >> 1) + 1) { snprintf(err, esz, "condition: -%llu does not fit %s", v, name); return false; }
    b->has_cond = true;
    b->creg = r->id;
    b->cwidth = r->width;
    b->cop = op;
    b->cval = (neg ? (uint64_t)0 - (uint64_t)v : (uint64_t)v) & mask;
    static const char *const ops[] = { "==", "!=", "<", "<=", ">", ">=" };
    snprintf(b->cond, sizeof b->cond, "%s %s 0x%llx", name, ops[op], (unsigned long long)b->cval);
    return true;
}

/* b's condition on registers r (its hit already counted) */
static __attribute__((unused)) bool cond_true(const DbgBp *b, const DbgRegs *r) {
    if (!b->has_cond) return true;
    uint64_t v;
    switch (b->creg) {
        case CR_RIP: v = r->rip; break;
        case CR_RSP: v = r->rsp; break;
        case CR_RBP: v = r->rbp; break;
        case CR_RAX: v = r->rax; break;
        case CR_RBX: v = r->rbx; break;
        case CR_RCX: v = r->rcx; break;
        case CR_RDX: v = r->rdx; break;
        case CR_RSI: v = r->rsi; break;
        case CR_RDI: v = r->rdi; break;
        case CR_RFLAGS: v = r->rflags; break;
        case CR_R8:  v = r->r8;  break;
        case CR_R9:  v = r->r9;  break;
        case CR_R10: v = r->r10; break;
        case CR_R11: v = r->r11; break;
        case CR_R12: v = r->r12; break;
        case CR_R13: v = r->r13; break;
        case CR_R14: v = r->r14; break;
        case CR_R15: v = r->r15; break;
        default:     v = b->hits; break;
    }
    if (b->cwidth == 32) v &= 0xffffffffull;
    switch (b->cop) {
        case CO_EQ: return v == b->cval;
        case CO_NE: return v != b->cval;
        case CO_LT: return v <  b->cval;
        case CO_LE: return v <= b->cval;
        case CO_GT: return v >  b->cval;
        default:    return v >= b->cval;
    }
}

/* ---- the public list ---- */

bool dbg_bp_add(uint64_t addr, char *err, size_t esz) {
    err[0] = '\0';
    if (!bp_hook_can_change(err, esz)) return false;
    int i = bpm_index(addr);
    if (i < g_nmain && g_bp[i].va == addr) return true;       /* already there */
    if (g_nbp >= DBG_MAX_BP) { snprintf(err, esz, "Too many breakpoints (%d)", DBG_MAX_BP); return false; }
    uint64_t rva = addr - g_link_lo;
    if (bp_hook_stopped() && !bp_hook_check_code(g_link_lo + g_base_addr + rva, addr, err, esz)) return false;
    memmove(g_bp + i + 1, g_bp + i, (size_t)(g_nbp - i) * sizeof g_bp[0]);
    DbgBp *b = &g_bp[i];
    memset(b, 0, sizeof *b);
    b->main = true;
    b->va = addr;
    b->rva = rva;
    b->enabled = true;
    b->state = DBG_BPS_IDLE;
    g_nmain++;
    g_nbp++;
    if (g_last_bp >= i) g_last_bp++;
    return true;
}

int dbg_bp_index(uint64_t addr) {
    int i = bpm_index(addr);
    return i < g_nmain && g_bp[i].va == addr ? i : -1;
}

int dbg_bp_index_module(const char *module, uint64_t rva) {
    if (!module) return -1;
    if (g_prog[0] && !strcmp(module, g_prog)) return dbg_bp_index(g_link_lo + rva);
    for (int i = g_nmain; i < g_nbp; i++)
        if (g_bp[i].rva == rva && !strcmp(g_bp[i].module, module)) return i;
    return -1;
}

bool dbg_bp_add_module(const char *module, uint64_t rva, char *err, size_t esz) {
    err[0] = '\0';
    if (!module || !*module) { snprintf(err, esz, "No module name"); return false; }
    if (g_prog[0] && !strcmp(module, g_prog)) return dbg_bp_add(g_link_lo + rva, err, esz);
    if (strlen(module) >= DBG_MOD_MAX) { snprintf(err, esz, "Module name too long"); return false; }
    if (!bp_hook_module_ok(err, esz)) return false;
    if (!bp_hook_can_change(err, esz)) return false;
    if (dbg_bp_index_module(module, rva) >= 0) return true;   /* already there */
    if (g_nbp >= DBG_MAX_BP) { snprintf(err, esz, "Too many breakpoints (%d)", DBG_MAX_BP); return false; }
    uint64_t rt = 0;
    bool loaded = bp_hook_stopped() && bp_hook_module_rt(module, rva, &rt);
    if (loaded && !bp_hook_check_code(rt, rva, err, esz)) return false;
    int i = g_nmain;
    while (i < g_nbp) {
        int c = strcmp(g_bp[i].module, module);
        if (c > 0 || (c == 0 && g_bp[i].rva > rva)) break;
        i++;
    }
    memmove(g_bp + i + 1, g_bp + i, (size_t)(g_nbp - i) * sizeof g_bp[0]);
    DbgBp *b = &g_bp[i];
    memset(b, 0, sizeof *b);
    snprintf(b->module, sizeof b->module, "%s", module);
    b->rva = rva;
    b->rt = rt;
    b->enabled = true;
    b->state = loaded ? DBG_BPS_IDLE : DBG_BPS_PENDING;
    g_nbp++;
    if (g_last_bp >= i) g_last_bp++;
    return true;
}

bool dbg_bp_remove_i(int i, char *err, size_t esz) {
    err[0] = '\0';
    if (!bp_hook_can_change(err, esz)) return false;
    if (i < 0 || i >= g_nbp) { snprintf(err, esz, "No such breakpoint"); return false; }
    if (g_bp[i].main) g_nmain--;
    memmove(g_bp + i, g_bp + i + 1, (size_t)(g_nbp - i - 1) * sizeof g_bp[0]);
    g_nbp--;
    if (g_last_bp == i) g_last_bp = -1;
    else if (g_last_bp > i) g_last_bp--;
    return true;
}

bool dbg_bp_remove(uint64_t addr, char *err, size_t esz) {
    err[0] = '\0';
    if (!bp_hook_can_change(err, esz)) return false;
    int i = dbg_bp_index(addr);
    if (i < 0) {
        snprintf(err, esz, "No breakpoint at 0x%llx", (unsigned long long)addr);
        return false;
    }
    return dbg_bp_remove_i(i, err, esz);
}

bool dbg_bp_enable_i(int i, bool on, char *err, size_t esz) {
    err[0] = '\0';
    if (!bp_hook_can_change(err, esz)) return false;
    if (i < 0 || i >= g_nbp) { snprintf(err, esz, "No such breakpoint"); return false; }
    g_bp[i].enabled = on;
    return true;
}

bool dbg_bp_cond_i(int i, const char *cond, char *err, size_t esz) {
    err[0] = '\0';
    if (!bp_hook_can_change(err, esz)) return false;
    if (i < 0 || i >= g_nbp) { snprintf(err, esz, "No such breakpoint"); return false; }
    if (!cond || !*cond) {
        g_bp[i].has_cond = false;
        g_bp[i].cond[0] = '\0';
        return true;
    }
    return cond_parse(cond, &g_bp[i], err, esz);
}

bool dbg_bp_hw_i(int i, bool on, char *err, size_t esz) {
    err[0] = '\0';
    if (!bp_hook_can_change(err, esz)) return false;
    if (i < 0 || i >= g_nbp) { snprintf(err, esz, "No such breakpoint"); return false; }
    if (on) {
        if (!bp_hook_hw_ok(err, esz)) return false;
        int n = 0;
        for (int k = 0; k < g_nbp; k++) if (g_bp[k].hw && k != i) n++;
        if (n >= DBG_MAX_HW) { snprintf(err, esz, "Only %d hardware breakpoints (DR0-DR3)", DBG_MAX_HW); return false; }
    }
    g_bp[i].hw = on;
    if (!on && g_bp[i].state == DBG_BPS_HWFAIL) g_bp[i].state = DBG_BPS_IDLE;
    return true;
}

bool dbg_bp_info(int i, DbgBp *out) {
    if (i < 0 || i >= g_nbp || !out) return false;
    *out = g_bp[i];
    if (out->main) {
        snprintf(out->module, sizeof out->module, "%s", g_prog);
        out->rt = bp_hook_stopped() ? bpm_rt(&g_bp[i]) : 0;
    }
    return true;
}

int dbg_bp_stopped_on(void) {
    return g_last_bp;
}

bool dbg_bp_take_news(char *out, size_t sz) {
    if (!g_bp_news[0]) return false;
    if (out && sz) snprintf(out, sz, "%s", g_bp_news);
    g_bp_news[0] = '\0';
    return true;
}

bool dbg_bp_has(uint64_t addr) {
    return dbg_bp_index(addr) >= 0;
}

/* copies min(n, max) addresses and returns that; out NULL: returns n */
int dbg_bp_list(uint64_t *out, int max) {
    if (!out) return g_nbp;
    int n = g_nbp < max ? g_nbp : max;
    if (n <= 0) return 0;
    for (int i = 0; i < n; i++) out[i] = g_bp[i].main ? g_bp[i].va : g_bp[i].rt;
    return n;
}

/* refused (does nothing) while the program runs, like dbg_bp_remove */
void dbg_bp_clear(void) {
    char e[64];
    if (!bp_hook_can_change(e, sizeof e)) return;
    g_nbp = g_nmain = 0;
    g_last_bp = -1;
    g_bp_news[0] = '\0';
}

int dbg_bits(void) {
    return g_bits;
}

uint64_t dbg_link_base(void) {
    return g_link_lo;
}

#endif
