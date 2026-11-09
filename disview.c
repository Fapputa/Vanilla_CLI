/* F9 — static analysis view (read-only), drawn in a pane.
 *
 * Three screens, Tab cycles info -> list -> disassembly -> info (the
 * disassembly only once a function has been opened):
 *  - information on the analysed ELF (type, architecture, entry point,
 *    protections, segments, sections, functions found, loader warnings).
 *    The text is built once when the file is opened and only clipped to
 *    the window when drawn, so a resize costs nothing;
 *  - the function list: address, size, callers, origin (FN_*), name;
 *    sorted by address / name / size / callers (s), filtered on the name
 *    (/, applied as it is typed), and a jump to a hex address (:). The
 *    sort order and the filtered rows are index arrays over d.fn, built
 *    again only when the sort or the filter changes; the geometry is
 *    taken from the window at each draw;
 *  - the disassembly of the function chosen with Enter: a linear sweep
 *    (da_linear) of [addr, addr + size), or up to the next function /
 *    the end of the section when the size is unknown, then, after a
 *    separator line, of its part laid out elsewhere (.cold) when the
 *    analysis found one. The lines are decoded once, when the function
 *    is opened; a line the recursive analysis did not decode is marked
 *    '!'. Esc goes back to the list.
 *
 * The binary is read by elfload.c (copied in memory) and analysed by
 * disasm.c: nothing here maps or writes it. Only the debugger keys of
 * the disassembly screen (b, F5, F6, F7) run it, through dbg.c. */
#include "disview.h"
#include "disasm.h"
#include "peload.h"
#include "utf8.h"
#include <stdarg.h>

extern char E_notify[256];

/* one line of the information screen: a label column, then a value */
typedef struct {
    char  *lbl;            /* NULL: the value takes the whole line      */
    char  *val;
    short  lp, vp;         /* colour pairs                              */
    bool   bold;
} InfoLine;

enum { SCR_INFO, SCR_FUNCS, SCR_DISASM, SCR_DATA, SCR_DUMP };   /* DisView.screen */

/* one data section (or, without a section table, one non-executable
 * mapping), for the data screens */
typedef struct {
    char        name[64];
    uint64_t    addr, size;
    uint64_t    filesz;            /* bytes from addr kept in the file    */
    char        perm[8];           /* "rw-"                               */
    const char *type;              /* PROGBITS, NOBITS, LOAD...           */
    const char *desc;              /* what such a section holds, or ""    */
    bool        bad;               /* its bytes lie outside the file      */
} DataSec;

/* one row of a section's contents */
enum { DT_HEX, DT_STR, DT_PTR, DT_ZERO };
typedef struct {
    uint64_t addr;
    uint64_t target;               /* DT_PTR: the address it holds        */
    uint32_t len;
    uint8_t  kind;                 /* DT_*                                */
} DataItem;

/* a place to come back to (Backspace) */
typedef struct {
    int      screen;
    long     obj;                  /* function (disassembly), section (dump) */
    size_t   sel, top;
} DisHist;

#define DIS_HIST 64
enum { SORT_ADDR, SORT_NAME, SORT_SIZE, SORT_CALLERS, SORT_COUNT };
enum { IN_NONE, IN_FILTER, IN_GOTO, IN_CONSOLE, IN_BREAK, IN_ARGS };   /* DisView.in_mode */

struct DisView {
    Disasm    d;
    char      path[4096];
    long long mtime, fsize;
    int       screen;

    InfoLine *ln;
    int       nln, cap;
    int       scroll;

    /* function list: `ord` holds every index of d.fn in the sort order,
     * `vis` the ones whose name matches the filter, in the same order.
     * sel / top are positions in vis. */
    uint32_t *ord, *vis;
    size_t    nvis;
    bool      list_ok;             /* false: out of memory, list unusable */
    int       sort;                /* SORT_*                              */
    size_t    sel, top;
    int       aw;                  /* hex digits of the address column    */
    char      filter[128];
    int       in_mode;             /* IN_*: a prompt replaces the bar     */
    char      in_buf[512], in_save[128];
    char      args[512];           /* a: arguments of F5 / F6 / F7 launches, as typed */
    char      msg[256];            /* shown in the bar until the next key */
    short     msg_pair;

    /* disassembly screen: the lines of function dfn (index in d.fn),
     * decoded from dva over dlen bytes: dl[0 .. dmain); when dmain < ndl,
     * dl[dmain] is a separator (len 0) and the lines of its .cold part
     * follow. dsel / dtop are line indexes. */
    DisLine  *dl;
    uint64_t *dref;                /* per line: the address its operands hold
                                      (data or code, followable), 0: none   */
    /* Enter / click on a line that leads to several places (a call and
     * the addresses it is given): the choice, drawn over the lines */
    int       npick, pick_sel, pick_y, pick_x, pick_w;
    uint64_t  pick_t[8];
    char      pick_s[8][160];
    size_t    ndl, dmain;
    long      dfn;                 /* -1: nothing opened yet              */
    uint64_t  dva, dlen;
    bool      dguess;              /* size unknown: range up to the next start */
    bool      dtrunc;              /* range cut to DA_LINEAR_MAX / DIS_GUESS_MAX */
    bool      dclip;               /* size runs past its section / mapping */
    size_t    doff;                /* lines the analysis did not decode   */
    size_t    dsel, dtop;

    /* debugger, when the debuggee runs this file: dbg_seen is the last
     * stop shown here (g_dbg_gen), drip the file address of rip while it
     * is stopped (drip_ok), dpanel the first column of the register
     * panel at the last draw (0: none). wait_seen: the last wait for
     * input seen (g_wait_gen); con_auto: the console was entered for it */
    unsigned  dbg_seen, wait_seen;
    uint64_t  drip;
    bool      drip_ok;
    int       dpanel;
    bool      con_auto;
    bool      bp_panel;            /* L: the panel lists the breakpoints  */
    /* the panel's [esp+4] / [esp+8] ([rsp+8] / [rsp+16]): rows sarg_y0 ..
     * sarg_y1 of each at the last draw (0: not drawn), clickable; peek:
     * the bytes at the value of slot peek_k shown under it, while that
     * slot still holds peek_a (peek_k 0 / 1: the stack slots, 2 + i:
     * register i of reg_val). reg_y / reg_x0 .. reg_x1: the row and the
     * columns of each register at the last draw (row 0: not drawn), clickable */
    int       sarg_y0[2], sarg_y1[2];
    int       reg_y[18], reg_x0[18], reg_x1[18];
    bool      peek_on;
    int       peek_k;
    uint64_t  peek_a;

    /* data screens: the sections (ds, by address), then the rows of
     * section xsec (xi). data_back: screen to go back to (d / Esc). */
    DataSec  *ds;
    size_t    nds, dssel, dstop;
    DataItem *xi;
    size_t    nxi, xsel, xtop;
    long      xsec;                /* -1: no section opened yet           */
    bool      xtrunc;              /* section cut to DATA_MAX / DATA_MAX_ITEMS */
    int       xsymw;               /* width of the SYMBOL column of xi, 0: none */
    /* the data screens are column blocks (as the table view): column 0
     * stays, the others scroll whole with Left / Right. dscol / xcol: the
     * first one shown after column 0; *_more: some on the right are hidden
     * (as drawn last) */
    int       dscol, xcol;
    bool      ds_more, x_more;
    int       data_back;

    DisHist   hist[DIS_HIST];      /* followed links, last one on top     */
    int       nhist;
};

#define LBL_W 14

/* longest range shown for a function of unknown size */
#define DIS_GUESS_MAX  (64u << 10)
/* instruction bytes shown before "…" (wide windows only) */
#define DIS_BYTES      10

/* ─── Drawing helpers ──────────────────────────────────────────── */

/* writes s from column x, clipped to column w; returns the next column */
static int put_clip(WINDOW *win, int y, int x, const char *s, int w) {
    if (!s || x >= w) return x;
    size_t n = strlen(s), i = 0;
    wmove(win, y, x);
    while (i < n) {
        uint32_t cp;
        int k = utf8_decode(s + i, n - i, &cp);
        if (k < 1) k = 1;
        int cw = utf8_cp_width(cp);
        if (cw < 0) cw = 0;
        if (x + cw > w) break;
        waddnstr(win, s + i, k);
        x += cw;
        i += (size_t)k;
    }
    return x;
}

static void bar(WINDOW *win, int y, int w, int pair, attr_t a, const char *s) {
    wattron(win, COLOR_PAIR(pair) | a);
    mvwhline(win, y, 0, ' ', w);
    put_clip(win, y, 0, s, w);
    wattroff(win, COLOR_PAIR(pair) | a);
}

static const char *base_name(const char *p) {
    const char *s = strrchr(p, '/');
#ifdef _WIN32
    const char *b = strrchr(p, '\\');
    if (b && (!s || b > s)) s = b;
#endif
    return s ? s + 1 : p;
}

static void human_size(unsigned long long n, char *out, size_t sz) {
    if (n >= 1024ull * 1024 * 1024) snprintf(out, sz, "%.1f GB", n / 1073741824.0);
    else if (n >= 1024ull * 1024)   snprintf(out, sz, "%.1f MB", n / 1048576.0);
    else if (n >= 1024)             snprintf(out, sz, "%.1f KB", n / 1024.0);
    else                            snprintf(out, sz, "%llu B", n);
}

/* ─── Information screen ───────────────────────────────────────── */

static void lines_free(DisView *v) {
    for (int i = 0; i < v->nln; i++) { free(v->ln[i].lbl); free(v->ln[i].val); }
    free(v->ln);
    v->ln = NULL;
    v->nln = v->cap = 0;
}

static InfoLine *push_line(DisView *v) {
    if (v->nln == v->cap) {
        int nc = v->cap ? v->cap * 2 : 64;
        InfoLine *n = realloc(v->ln, (size_t)nc * sizeof *n);
        if (!n) return NULL;                 /* line dropped, view still usable */
        v->ln = n;
        v->cap = nc;
    }
    InfoLine *l = &v->ln[v->nln++];
    memset(l, 0, sizeof *l);
    l->lp = COLOR_PAIR_TYPE;
    l->vp = COLOR_PAIR_NORMAL;
    return l;
}

static void add_kv(DisView *v, short vp, const char *lbl, const char *fmt, ...)
    __attribute__((format(gnu_printf, 4, 5)));
static void add_kv(DisView *v, short vp, const char *lbl, const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    InfoLine *l = push_line(v);
    if (!l) return;
    l->lbl = lbl ? strdup(lbl) : NULL;
    l->val = strdup(buf);
    l->vp  = vp;
}

#define add_text(v, vp, ...) add_kv(v, vp, NULL, __VA_ARGS__)

static void add_title(DisView *v, const char *fmt, ...) __attribute__((format(gnu_printf, 2, 3)));
static void add_title(DisView *v, const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (v->nln) add_text(v, COLOR_PAIR_NORMAL, "%s", "");
    InfoLine *l = push_line(v);
    if (!l) return;
    l->val  = strdup(buf);
    l->vp   = COLOR_PAIR_KEYWORD;
    l->bold = true;
}

static uint64_t rd64(const uint8_t *p) {
    uint64_t r = 0;
    for (int i = 7; i >= 0; i--) r = (r << 8) | p[i];
    return r;
}

/* BIND_NOW from the dynamic table (DT_BIND_NOW, DF_BIND_NOW, DF_1_NOW);
 * the table is read straight from the file copy, bounds checked */
static bool bind_now(const ElfFile *ef) {
    for (int i = 0; i < ef->nseg; i++) {
        const ElfSegment *s = &ef->seg[i];
        if (s->type != 2 || s->off > ef->size || s->filesz > ef->size - s->off) continue;
        const uint8_t *p = ef->data + s->off;
        for (uint64_t k = 0; k + 16 <= s->filesz; k += 16) {
            uint64_t tag = rd64(p + k), val = rd64(p + k + 8);
            if (tag == 0) break;                                  /* DT_NULL     */
            if (tag == 24) return true;                           /* DT_BIND_NOW */
            if (tag == 30 && (val & 0x8)) return true;            /* DF_BIND_NOW */
            if (tag == 0x6ffffffb && (val & 0x1)) return true;    /* DF_1_NOW    */
        }
    }
    return false;
}

static const ElfSegment *seg_of_type(const ElfFile *ef, uint32_t t) {
    for (int i = 0; i < ef->nseg; i++) if (ef->seg[i].type == t) return &ef->seg[i];
    return NULL;
}

/* an import or a symbol with this exact name */
static bool has_name(const ElfFile *ef, const char *name) {
    for (int i = 0; i < ef->nimp; i++) if (ef->imp[i].name && !strcmp(ef->imp[i].name, name)) return true;
    for (int i = 0; i < ef->nsym; i++) if (ef->sym[i].name && !strcmp(ef->sym[i].name, name)) return true;
    return false;
}

static bool is_chk(const char *n) {
    size_t l = n ? strlen(n) : 0;
    return l > 6 && !strncmp(n, "__", 2) && !strcmp(n + l - 4, "_chk") && strcmp(n, "__stack_chk_fail");
}

/* fortified calls (__printf_chk...): count, and the first names */
static int fortify_calls(const ElfFile *ef, char *names, size_t sz) {
    int n = 0;
    size_t used = 0;
    names[0] = '\0';
    for (int i = 0; i < ef->nimp; i++) {
        const char *nm = ef->imp[i].name;
        if (!is_chk(nm)) continue;
        bool dup = false;                       /* GOT + PLT entries of one import */
        for (int j = 0; j < i; j++) if (ef->imp[j].name && !strcmp(ef->imp[j].name, nm)) { dup = true; break; }
        if (dup) continue;
        if (n < 4 && used + strlen(nm) + 3 < sz) used += (size_t)snprintf(names + used, sz - used, "%s%s", n ? ", " : "", nm);
        n++;
    }
    if (!ef->nimp)                              /* static: the symbols, if any */
        for (int i = 0; i < ef->nsym; i++) {
            const char *nm = ef->sym[i].name;
            if (ef->sym[i].kind != ELF_SYM_FUNC || !is_chk(nm)) continue;
            if (n < 4 && used + strlen(nm) + 3 < sz) used += (size_t)snprintf(names + used, sz - used, "%s%s", n ? ", " : "", nm);
            n++;
        }
    return n;
}

/* PE: the DllCharacteristics flags (DYNAMIC_BASE 0x40, HIGH_ENTROPY_VA
 * 0x20, FORCE_INTEGRITY 0x80, NX_COMPAT 0x100, NO_ISOLATION 0x200,
 * NO_SEH 0x400, APPCONTAINER 0x1000, GUARD_CF 0x4000), the load config
 * (SecurityCookie, SafeSEH table, CFG table and GuardFlags), the
 * relocations, the certificate table, W+X sections: what the file
 * declares, not checked further */
static void build_protections_pe(DisView *v) {
    const ElfFile *ef = &v->d.elf;
    const PeInfo *pe = &ef->pe;
    const short GOOD = COLOR_PAIR_STRING, BAD = COLOR_PAIR_KEYWORD, MEH = COLOR_PAIR_NUMBER, NOTE = COLOR_PAIR_COMMENT;
    uint16_t dc = pe->dllchars;
    bool b64 = ef->bits == 64;
    PeLoadConfig lc;
    bool haslc = pe_load_config(ef, &lc);
    const char *rel = pe->relocs ? "relocations present"
                    : (pe->chars & 1) ? "relocations stripped (RELOCS_STRIPPED)" : "no relocation table";
    const char *he = (dc & 0x20) ? (b64 ? ", HIGH_ENTROPY_VA" : ", HIGH_ENTROPY_VA (no effect in 32-bit)")
                                 : (b64 ? ", no HIGH_ENTROPY_VA (low entropy)" : "");
    if (!(dc & 0x40))            add_kv(v, BAD, "ASLR", "no (DYNAMIC_BASE not set: loaded at its base)  ·  %s", rel);
    else if (!pe->relocs)        add_kv(v, MEH, "ASLR", "DYNAMIC_BASE set but %s: loaded at its base%s", rel, he);
    else                         add_kv(v, (dc & 0x20) || !b64 ? GOOD : MEH, "ASLR", "yes (DYNAMIC_BASE, %d relocations)%s", ef->nrel, he);
    if (dc & 0x100)              add_kv(v, GOOD, "DEP / NX", "yes (NX_COMPAT)");
    else                         add_kv(v, BAD, "DEP / NX", "no NX_COMPAT flag");
    if (dc & 0x400)              add_kv(v, NOTE, "SEH", "NO_SEH: no structured exception handler in the image");
    else if (b64) {
        PePdata pd;
        if (pe_pdata(ef, &pd)) add_kv(v, NOTE, "SEH", "table-based (x64 .pdata, SafeSEH does not apply): %u functions, %u with a handler", pd.nfunc, pd.nhandler);
        else                   add_kv(v, NOTE, "SEH", "table-based (x64), no .pdata");
        pe_pdata_free(&pd);
    } else {
        PeTable t;
        bool ok = pe_safeseh(ef, &t);
        if (ok)                add_kv(v, GOOD, "SEH", "SafeSEH: %u registered handler%s%s", t.n, t.n == 1 ? "" : "s",
                                      t.nout ? " (some entries outside the code)" : "");
        else if (t.present)    add_kv(v, BAD, "SEH", "SafeSEH table unusable (%s)", t.err);
        else                   add_kv(v, BAD, "SEH", "no SafeSEH table (any handler accepted)%s", haslc ? "" : ", no load config");
        pe_table_free(&t);
    }
    if (dc & 0x4000) {
        PeTable t;
        bool ok = pe_guard_cf(ef, &t);
        if (ok)                add_kv(v, GOOD, "CFG", "yes (GUARD_CF, %u functions in the table, GuardFlags 0x%x)", t.n, lc.guard_flags);
        else if (t.present)    add_kv(v, MEH, "CFG", "GUARD_CF set, function table unusable (%s)", t.err);
        else if (lc.has_gflags) add_kv(v, MEH, "CFG", "GUARD_CF set, no function table (GuardFlags 0x%x)", lc.guard_flags);
        else                   add_kv(v, MEH, "CFG", "GUARD_CF set but no load config guard fields");
        pe_table_free(&t);
    } else if (lc.has_gflags && (lc.guard_flags & PE_GUARD_CF_INSTRUMENTED))
                                 add_kv(v, NOTE, "CFG", "no (code instrumented, GUARD_CF not set in DllCharacteristics)");
    else                         add_kv(v, NOTE, "CFG", "no");
    bool gs = pe->cookie || has_name(ef, "__security_check_cookie") || has_name(ef, "__security_init_cookie");
    bool ssp = has_name(ef, "__stack_chk_fail") || has_name(ef, "__stack_chk_guard");
    if (gs)                      add_kv(v, GOOD, "Canary", "yes (/GS security cookie%s)", pe->cookie ? " in the load config" : "");
    else if (ssp)                add_kv(v, GOOD, "Canary", "yes (__stack_chk_fail)");
    else                         add_kv(v, BAD, "Canary", "not found");
    add_kv(v, dc & 0x80 ? GOOD : NOTE, "Integrity", "%s", dc & 0x80 ? "FORCE_INTEGRITY (signature checked at load)" : "no FORCE_INTEGRITY");
    add_kv(v, NOTE, "Isolation", "%s", dc & 0x200 ? "NO_ISOLATION (manifest ignored)" : "manifest isolation allowed");
    add_kv(v, dc & 0x1000 ? GOOD : NOTE, "AppContainer", "%s", dc & 0x1000 ? "yes (APPCONTAINER: runs in an app container)" : "no");
    if (pe->signature)           add_kv(v, GOOD, "Signature", "Authenticode certificate present (not verified here)");
    else                         add_kv(v, NOTE, "Signature", "not signed");
    int nrwx = 0;
    for (int i = 0; i < ef->nsec; i++)
        if ((ef->sec[i].flags & 5) == 5) {
            if (!nrwx) add_kv(v, BAD, "W+X section", "%s at 0x%llx: writable and executable", ef->sec[i].name,
                              (unsigned long long)ef->sec[i].addr);
            nrwx++;
        }
    if (nrwx > 1)                add_kv(v, BAD, "", "%d writable + executable sections in all", nrwx);
    else if (!nrwx)              add_kv(v, GOOD, "W+X section", "none");
}

static void build_protections(DisView *v) {
    const ElfFile *ef = &v->d.elf;
    const short GOOD = COLOR_PAIR_STRING, BAD = COLOR_PAIR_KEYWORD, MEH = COLOR_PAIR_NUMBER;
    add_title(v, "PROTECTIONS");
    if (ef->fmt == ELF_FMT_PE) { build_protections_pe(v); return; }

    if (ef->type == 1) { add_text(v, COLOR_PAIR_COMMENT, "   object file (.o): decided at link time"); return; }

    if (ef->pie)                 add_kv(v, GOOD,  "PIE", "yes (position independent)");
    else if (ef->type == 3)      add_kv(v, MEH, "PIE", "shared object (relocatable, not a PIE executable)");
    else                         add_kv(v, BAD, "PIE", "no (fixed load address)");

    const ElfSegment *st = seg_of_type(ef, 0x6474e551);
    if (!st)                     add_kv(v, BAD, "NX", "no PT_GNU_STACK: stack executable by default");
    else if (st->flags & 1)      add_kv(v, BAD, "NX", "no (stack marked executable)");
    else                         add_kv(v, GOOD,  "NX", "yes (non-executable stack)");

    bool relro = seg_of_type(ef, 0x6474e552) != NULL, now = bind_now(ef);
    if (relro && now)            add_kv(v, GOOD,  "RELRO", "full (GNU_RELRO + BIND_NOW)");
    else if (relro)              add_kv(v, MEH, "RELRO", "partial (GNU_RELRO, lazy binding)");
    else                         add_kv(v, BAD, "RELRO", "none");

    bool canary = has_name(ef, "__stack_chk_fail") || has_name(ef, "__stack_chk_guard");
    if (canary)                  add_kv(v, GOOD,  "Canary", "yes (__stack_chk_fail)");
    else if (ef->stripped && !ef->nimp) add_kv(v, COLOR_PAIR_COMMENT, "Canary", "unknown (static and stripped)");
    else                         add_kv(v, BAD, "Canary", "not found");

    char names[200];
    int nf = fortify_calls(ef, names, sizeof names);
    if (nf)                      add_kv(v, GOOD,  "FORTIFY", "yes, %d fortified function%s (%s%s)", nf, nf > 1 ? "s" : "", names, nf > 4 ? ", ..." : "");
    else if (ef->stripped && !ef->nimp) add_kv(v, COLOR_PAIR_COMMENT, "FORTIFY", "unknown (static and stripped)");
    else                         add_kv(v, COLOR_PAIR_COMMENT, "FORTIFY", "not found");

    int nrwx = 0;
    for (int i = 0; i < ef->nseg; i++)
        if (ef->seg[i].type == 1 && (ef->seg[i].flags & 3) == 3) {
            if (!nrwx) add_kv(v, BAD, "RWX segment", "LOAD at 0x%llx, %llu bytes: writable and executable",
                              (unsigned long long)ef->seg[i].vaddr, (unsigned long long)ef->seg[i].memsz);
            nrwx++;
        }
    if (nrwx > 1)                add_kv(v, BAD, "", "%d writable + executable LOAD segments in all", nrwx);
    else if (!nrwx)              add_kv(v, GOOD,  "RWX segment", "none");
}

static const char *fn_kind_name(int k) {
    static const char *n[] = { "symtab", "dynsym", "plt", "entry", "main", "ctor", "pdata",
                               "call", "codeptr", "dataptr", "prologue", "seh", "cfg" };
    return k >= 0 && k < (int)(sizeof n / sizeof *n) ? n[k] : "?";
}

static void build_analysis(DisView *v) {
    const Disasm *d = &v->d;
    add_title(v, "ANALYSIS");
    int cnt[16] = { 0 };
    for (size_t i = 0; i < d->nfn; i++) if (d->fn[i].kind < 16) cnt[d->fn[i].kind]++;
    char by[400] = "";
    size_t u = 0;
    static const uint8_t order[] = { FN_SYMTAB, FN_DYNSYM, FN_PLT, FN_ENTRY, FN_MAIN, FN_CTOR, FN_PDATA,
                                     FN_SEH, FN_GUARD, FN_CALL, FN_CODEPTR, FN_DATAPTR, FN_PROLOGUE };
    for (size_t j = 0; j < sizeof order && u < sizeof by; j++)
        if (cnt[order[j]]) u += (size_t)snprintf(by + u, sizeof by - u, "%s%s %d", u ? ", " : "", fn_kind_name(order[j]), cnt[order[j]]);
    add_kv(v, COLOR_PAIR_NUMBER, "Functions", "%zu", d->nfn);
    if (by[0]) add_kv(v, COLOR_PAIR_COMMENT, "", "%s", by);
    if (cnt[FN_DATAPTR] || cnt[FN_PROLOGUE])
        add_kv(v, COLOR_PAIR_COMMENT, "", "dataptr / prologue: guessed starts, less reliable");
    char cb[32];
    human_size(d->code_bytes, cb, sizeof cb);
    add_kv(v, COLOR_PAIR_NORMAL, "Instructions", "%zu decoded, %s of executable bytes", d->nins, cb);
    if (d->nbad) add_kv(v, COLOR_PAIR_NUMBER, "Undecodable", "%zu starts (bad or overlapping bytes)", d->nbad);
    if (d->capped)
        add_kv(v, COLOR_PAIR_KEYWORD, "Limits", "reached: partial result (trapped, packed or very large binary)");
    char cv[32];
    add_kv(v, COLOR_PAIR_COMMENT, "Engine", "capstone %s, %s syntax", da_capstone_version(cv, sizeof cv),
           d->att ? "AT&T" : "Intel");
}

/* PE: header, imports by DLL, exports, then the same sections table */
static void build_info_pe(DisView *v) {
    const Disasm *d = &v->d;
    const ElfFile *ef = &d->elf;
    const PeInfo *pe = &ef->pe;
    char tmp[256], sz[32];

    add_title(v, "FILE");
    add_kv(v, COLOR_PAIR_NORMAL, "Path", "%s", v->path);
    human_size(ef->size, sz, sizeof sz);
    add_kv(v, COLOR_PAIR_NORMAL, "Size", "%s (%zu bytes)", sz, ef->size);
    add_kv(v, COLOR_PAIR_NORMAL, "Type", "%s  ·  %s%s", pe->dll ? "DLL (dynamic-link library)" : "executable (.exe)",
           pe_subsystem_name(pe->subsystem), pe->dotnet ? "  ·  .NET assembly" : "");
    bool p32 = ef->bits == 32;
    add_kv(v, COLOR_PAIR_NORMAL, "Architecture", "%s  ·  %s", pe_machine_name(pe->machine), p32 ? "PE32 (32-bit)" : "PE32+ (64-bit)");
    if (p32)
        add_kv(v, COLOR_PAIR_NUMBER, "", "32-bit PE: debug directory and COFF symbols not read yet  ·  "
               "partial function discovery (no switch tables yet)");
    add_kv(v, COLOR_PAIR_NORMAL, "Image base", "0x%llx  ·  %u bytes in memory  ·  addresses = base + RVA",
           (unsigned long long)pe->image_base, pe->size_image);
    if (!ef->entry) add_kv(v, COLOR_PAIR_COMMENT, "Entry point", "none");
    else {
        const char *nm = da_name_for(d, ef->entry, tmp, sizeof tmp);
        const ElfSection *s = elf_section_at(ef, ef->entry);
        uint32_t rva = (uint32_t)(ef->entry - pe->image_base);
        uint64_t off = 0;
        char offs[40] = "";
        if (pe_rva_to_off(ef, rva, &off)) snprintf(offs, sizeof offs, ", offset 0x%llx", (unsigned long long)off);
        add_kv(v, elf_va_exec(ef, ef->entry) ? COLOR_PAIR_NUMBER : COLOR_PAIR_KEYWORD, "Entry point",
               "0x%llx  (RVA 0x%x%s)%s%s%s%s%s%s", (unsigned long long)ef->entry, rva, offs,
               nm ? "  " : "", nm ? nm : "",
               s ? "  (" : "", s ? s->name : "", s ? ")" : "", pe->dll ? "  ·  DllMain-style entry" : "");
    }
    long mi = da_func_named(d, "main");
    if (mi >= 0 && d->fn[mi].kind == FN_MAIN)
        add_kv(v, COLOR_PAIR_NUMBER, "main", "0x%llx  (called by the CRT start-up after argc / argv)", (unsigned long long)d->fn[mi].addr);
    add_kv(v, COLOR_PAIR_NORMAL, "Linker", "%u.%u  ·  OS %u.%u", pe->linker_major, pe->linker_minor, pe->os_major, pe->os_minor);
    if (pe->timestamp) add_kv(v, COLOR_PAIR_COMMENT, "Timestamp", "0x%08x (may be a build hash, not a date)", pe->timestamp);
    if (pe->pdb[0]) add_kv(v, COLOR_PAIR_STRING, "PDB", "%s", pe->pdb);
    if (ef->soname[0]) add_kv(v, COLOR_PAIR_NORMAL, "Export name", "%s", ef->soname);

    PeHeaders h;
    if (pe_read_headers(ef->data, ef->size, &h, NULL, 0)) {
        add_title(v, "HEADERS");
        add_kv(v, COLOR_PAIR_NORMAL, "Alignment", "sections 0x%x  ·  file 0x%x", h.sect_align, h.file_align);
        add_kv(v, COLOR_PAIR_NORMAL, "Headers", "0x%x bytes  ·  PE header at 0x%x  ·  section table at 0x%llx",
               h.size_headers, h.lfanew, (unsigned long long)h.sec_off);
        int nd = 0;
        for (unsigned i = 0; i < h.ndir; i++) if (h.dir[i].rva || h.dir[i].size) nd++;
        add_kv(v, COLOR_PAIR_NORMAL, "Directories", "%d data directories used of %u%s", nd, h.nrva,
               p32 && nd ? "  (32-bit PE: DEBUG not interpreted yet)" : "");
        for (unsigned i = 0; i < h.ndir; i++) {
            const PeDir *e = &h.dir[i];
            if (!e->rva && !e->size) continue;
            bool in = i == 4 ? e->rva <= ef->size && e->size <= ef->size - e->rva     /* a file offset */
                             : e->rva && (uint64_t)e->rva + e->size <= pe->size_image;
            const ElfSection *ds = i == 4 || !in ? NULL : elf_section_at(ef, pe_rva_to_va(ef, e->rva));
            add_kv(v, in ? COLOR_PAIR_COMMENT : COLOR_PAIR_KEYWORD, "", "%2u %-13s %s 0x%08x  0x%-8x %s", i, pe_dir_name(i),
                   i == 4 ? "offset" : "RVA   ", e->rva, e->size,
                   !in ? (i == 4 ? "outside the file: ignored" : "outside the image: ignored") : ds ? ds->name : "");
        }
        PeLoadConfig lc;
        if (pe_load_config(ef, &lc)) {
            add_kv(v, lc.err[0] ? COLOR_PAIR_KEYWORD : COLOR_PAIR_NORMAL, "Load config", "Size 0x%x (directory 0x%x)%s%s",
                   lc.size, lc.dirsize, lc.err[0] ? "  ·  " : "", lc.err);
            char b[200] = "";
            size_t u = 0;
            if (lc.has_cookie) u += (size_t)snprintf(b + u, sizeof b - u, "cookie 0x%llx", (unsigned long long)lc.cookie);
            if (lc.has_seh && u < sizeof b)
                u += (size_t)snprintf(b + u, sizeof b - u, "%sSEHandlerTable 0x%llx x %llu", u ? "  ·  " : "",
                                      (unsigned long long)lc.seh_table, (unsigned long long)lc.seh_count);
            if (lc.has_cf && u < sizeof b)
                u += (size_t)snprintf(b + u, sizeof b - u, "%sGuardCFFunctionTable 0x%llx x %llu", u ? "  ·  " : "",
                                      (unsigned long long)lc.cf_table, (unsigned long long)lc.cf_count);
            if (lc.has_gflags && u < sizeof b)
                snprintf(b + u, sizeof b - u, "%sGuardFlags 0x%x", u ? "  ·  " : "", lc.guard_flags);
            if (b[0]) add_kv(v, COLOR_PAIR_COMMENT, "", "%s", b);
        } else if (lc.err[0]) add_kv(v, COLOR_PAIR_KEYWORD, "Load config", "%s", lc.err);
        PePdata pd;
        if (pe_pdata(ef, &pd)) {
            bool bad = pd.rest || pd.capped || pd.nunsorted || pd.noverlap || pd.nempty || pd.nout ||
                       pd.nbadunw || pd.ncycle || pd.ndeep || pd.norphan || pd.nbadhandler;
            add_kv(v, COLOR_PAIR_NORMAL, ".pdata", "%u entries: %u functions, %u chained fragments, %u with a handler",
                   pd.nent, pd.nfunc, pd.nfrag, pd.nhandler);
            if (bad)
                add_kv(v, COLOR_PAIR_KEYWORD, "", "rejected: %u empty, %u outside the code, %u overlapping, %u bad unwind, %u cyclic, %u too deep, %u orphan%s%s",
                       pd.nempty, pd.nout, pd.noverlap, pd.nbadunw, pd.ncycle, pd.ndeep, pd.norphan,
                       pd.nunsorted ? "  ·  not sorted" : "", pd.rest ? "  ·  size not a multiple of 12" : "");
        } else if (pd.err[0]) add_kv(v, COLOR_PAIR_KEYWORD, ".pdata", "%s", pd.err);
        pe_pdata_free(&pd);
    }

    add_title(v, "IMPORTS (%d from %d DLL%s)", ef->nimp, ef->nneeded, ef->nneeded == 1 ? "" : "s");
    if (!ef->nneeded) add_text(v, COLOR_PAIR_COMMENT, "   none");
    for (int i = 0; i < ef->nneeded; i++) {
        char dll[128];
        snprintf(dll, sizeof dll, "%s", ef->needed[i]);
        char *sp = strstr(dll, " (delay-load)");
        if (sp) *sp = '\0';
        int n = 0;
        char first[200] = "";
        size_t u = 0;
        for (int k = 0; k < ef->nimp; k++) {
            if (strncmp(ef->imp[k].version, dll, sizeof ef->imp[k].version - 1)) continue;   /* version: cut at 31 */
            if (n < 6 && u + strlen(ef->imp[k].name) + 3 < sizeof first)
                u += (size_t)snprintf(first + u, sizeof first - u, "%s%s", n ? ", " : "", ef->imp[k].name);
            n++;
        }
        add_kv(v, COLOR_PAIR_STRING, i ? "" : "DLLs", "%-34s %4d  %s%s", ef->needed[i], n, first, n > 6 ? ", ..." : "");
    }
    if (pe->ndelay) add_kv(v, COLOR_PAIR_COMMENT, "Delay-load", "%d DLL%s loaded on first call", pe->ndelay, pe->ndelay > 1 ? "s" : "");
    PeBound bd;
    int nb = pe_bound_imports(ef, &bd);
    if (nb || bd.n) {
        char bl[200] = "";
        size_t bu = 0;
        for (int i = 0; i < bd.n && i < PE_BOUND_SHOW && bu < sizeof bl; i++)
            bu += (size_t)snprintf(bl + bu, sizeof bl - bu, "%s%s", i ? ", " : "", bd.name[i]);
        add_kv(v, nb < 0 ? COLOR_PAIR_KEYWORD : COLOR_PAIR_COMMENT, "Bound", "%d DLL%s%s: %s%s", bd.n, bd.n == 1 ? "" : "s",
               nb < 0 ? " (malformed table)" : "", bl, bd.n > PE_BOUND_SHOW ? ", ..." : "");
    }
    int nfs = 0;
    for (int i = 0; i < ef->nsym; i++) if (!ef->sym[i].dynamic) nfs++;
    add_title(v, "SYMBOLS");
    PeExports ex;
    if (pe_exports(ef, &ex)) {
        add_kv(v, COLOR_PAIR_NORMAL, "Exports", "%u  (%u code, %u data, %u forwarded)  ·  ordinal base %u  ·  %u names",
               ex.ncode + ex.ndata + ex.nfwd, ex.ncode, ex.ndata, ex.nfwd, ex.base, ex.nname);
        for (int i = 0; i < ex.nfwdshow; i++)
            add_kv(v, COLOR_PAIR_COMMENT, i ? "" : "Forwarders", "%s", ex.fwd[i]);
        if (ex.nfwd > (uint32_t)ex.nfwdshow) add_kv(v, COLOR_PAIR_COMMENT, "", "... %u more", ex.nfwd - (uint32_t)ex.nfwdshow);
    } else add_kv(v, ex.err[0] ? COLOR_PAIR_KEYWORD : COLOR_PAIR_NORMAL, "Exports", "%s", ex.err[0] ? ex.err : "none");
    uint32_t clr;
    if (pe->dotnet && pe_clr_flags(ef, &clr))
        add_kv(v, COLOR_PAIR_NUMBER, ".NET", "%s  (CLR flags 0x%x)", clr & PE_CLR_ILONLY
               ? "IL only: CIL bytecode, only the entry stub is native code (no guessed functions)"
               : "mixed-mode: native code analysed, CIL methods not disassembled", clr);
    if (p32) add_kv(v, COLOR_PAIR_COMMENT, "COFF symbols", "not read yet (32-bit PE)");
    else if (ef->stripped) add_kv(v, COLOR_PAIR_NUMBER, "COFF symbols", "none (stripped: names from exports and imports only)");
    else              add_kv(v, COLOR_PAIR_NORMAL, "COFF symbols", "%d (MinGW debug names)", nfs);
    if (ef->nfstart) add_kv(v, COLOR_PAIR_NORMAL, "Unwind table", "%d functions in .pdata (chained fragments go to their parent)", ef->nfstart);
    if (ef->nctors) add_kv(v, COLOR_PAIR_NUMBER, "TLS callbacks", "%d (run by the loader before the entry point)", ef->nctors);
    if (pe->overlay_size) {
        human_size(pe->overlay_size, sz, sizeof sz);
        add_kv(v, COLOR_PAIR_NUMBER, "Overlay", "%s after the sections (offset 0x%llx): appended data", sz, (unsigned long long)pe->overlay_off);
    }

    build_protections(v);
    build_analysis(v);

    add_title(v, "SECTIONS (%d)", ef->nsec);
    add_text(v, COLOR_PAIR_LINENUM, "   %3s  %-20s %-12s %18s %10s %10s  %s", "NR", "NAME", "TYPE", "ADDR", "OFFSET", "SIZE", "FLAGS");
    for (int i = 0; i < ef->nsec; i++) {
        const ElfSection *s = &ef->sec[i];
        char f[8];
        elf_sec_flags_str(s->flags, f);
        add_text(v, s->bad ? COLOR_PAIR_KEYWORD : (s->flags & 4) ? COLOR_PAIR_NUMBER : COLOR_PAIR_NORMAL,
                 "   %3d  %-20.20s %-12.12s %#18llx %#10llx %#10llx  %s%s", i, s->name[0] ? s->name : "-",
                 s->type == 8 ? "BSS" : (s->flags & 4) ? "CODE" : "DATA", (unsigned long long)s->addr,
                 (unsigned long long)s->off, (unsigned long long)s->size, f, s->bad ? "  outside the file" : "");
    }

    add_title(v, "LOADER WARNINGS (%d)", ef->nwarn);
    if (!ef->nwarn) add_text(v, COLOR_PAIR_COMMENT, "   none");
    for (int i = 0; i < ef->nwarn; i++) add_text(v, COLOR_PAIR_NUMBER, "   ! %s", ef->warn[i]);
}

static void build_info(DisView *v) {
    const Disasm *d = &v->d;
    const ElfFile *ef = &d->elf;
    char tmp[256], sz[32];
    if (ef->fmt == ELF_FMT_PE) { build_info_pe(v); return; }

    add_title(v, "FILE");
    add_kv(v, COLOR_PAIR_NORMAL, "Path", "%s", v->path);
    human_size(ef->size, sz, sizeof sz);
    add_kv(v, COLOR_PAIR_NORMAL, "Size", "%s (%zu bytes)", sz, ef->size);
    const char *what = ef->type == 1 ? "relocatable object"
                     : ef->type == 2 ? "executable"
                     : ef->type == 3 ? (ef->pie ? "PIE executable" : "shared object")
                     : ef->type == 4 ? "core dump" : "?";
    add_kv(v, COLOR_PAIR_NORMAL, "Type", "%s  ·  %s", elf_type_name(ef->type), what);
    add_kv(v, COLOR_PAIR_NORMAL, "Architecture", "%s  ·  ELF%u little endian  ·  OS/ABI %u%s",
           elf_machine_name(ef->machine), ef->bits == 32 ? 32u : 64u, ef->osabi,
           ef->osabi == 0 ? " (System V)" : ef->osabi == 3 ? " (GNU/Linux)" : "");
    if (ef->arch == ELF_ARCH_X86_32)
        add_kv(v, COLOR_PAIR_NUMBER, "", "32-bit: partial function discovery (no switch tables yet)");

    if (ef->type == 1 || !ef->entry) add_kv(v, COLOR_PAIR_COMMENT, "Entry point", "none");
    else {
        const char *nm = da_name_for(d, ef->entry, tmp, sizeof tmp);
        const ElfSection *s = elf_section_at(ef, ef->entry);
        add_kv(v, elf_va_exec(ef, ef->entry) ? COLOR_PAIR_NUMBER : COLOR_PAIR_KEYWORD, "Entry point",
               "0x%llx%s%s%s%s%s", (unsigned long long)ef->entry, nm ? "  " : "", nm ? nm : "",
               s ? "  (" : "", s ? s->name : "", s ? ")" : "");
    }
    long mi = da_func_named(d, "main");
    if (mi >= 0 && d->fn[mi].kind == FN_MAIN)
        add_kv(v, COLOR_PAIR_NUMBER, "main", "0x%llx  (from the __libc_start_main call)", (unsigned long long)d->fn[mi].addr);

    if (ef->type == 1)     add_kv(v, COLOR_PAIR_COMMENT, "Linking", "not linked yet (object file)");
    else if (ef->interp[0]) add_kv(v, COLOR_PAIR_NORMAL, "Linking", "dynamic  ·  interpreter %s", ef->interp);
    else if (ef->is_static) add_kv(v, COLOR_PAIR_NORMAL, "Linking", "static");
    else                   add_kv(v, COLOR_PAIR_NORMAL, "Linking", "dynamic");
    if (ef->soname[0])     add_kv(v, COLOR_PAIR_NORMAL, "Soname", "%s", ef->soname);
    for (int i = 0; i < ef->nneeded; i++)
        add_kv(v, COLOR_PAIR_STRING, i ? "" : "Libraries", "%s", ef->needed[i]);
    int nfs = 0;
    for (int i = 0; i < ef->nsym; i++) if (!ef->sym[i].dynamic) nfs++;
    if (ef->stripped) add_kv(v, COLOR_PAIR_NUMBER, "Symbols", "stripped (no .symtab)  ·  %d dynamic, %d imports", ef->nsym, ef->nimp);
    else              add_kv(v, COLOR_PAIR_NORMAL, "Symbols", "%d in .symtab, %d dynamic, %d imports", nfs, ef->nsym - nfs, ef->nimp);
    if (ef->nctors) add_kv(v, COLOR_PAIR_NORMAL, "Ctors/dtors", "%d (DT_INIT, DT_FINI, .init_array...)", ef->nctors);

    build_protections(v);
    build_analysis(v);

    add_title(v, "SEGMENTS (%d)", ef->nseg);
    if (!ef->nseg) add_text(v, COLOR_PAIR_COMMENT, "   none%s", ef->type == 1 ? " (object file: the sections are used)" : "");
    if (ef->nseg) add_text(v, COLOR_PAIR_LINENUM, "   %-14s %10s %18s %10s %10s  %s", "TYPE", "OFFSET", "VADDR", "FILESZ", "MEMSZ", "FLAGS");
    for (int i = 0; i < ef->nseg; i++) {
        const ElfSegment *s = &ef->seg[i];
        char f[4];
        elf_flags_str(s->flags, f);
        add_text(v, (s->type == 1 && (s->flags & 3) == 3) ? COLOR_PAIR_KEYWORD : COLOR_PAIR_NORMAL,
                 "   %-14s %#10llx %#18llx %#10llx %#10llx  %s", elf_seg_type_name(s->type),
                 (unsigned long long)s->off, (unsigned long long)s->vaddr,
                 (unsigned long long)s->filesz, (unsigned long long)s->memsz, f);
    }

    add_title(v, "SECTIONS (%d)", ef->nsec);
    if (!ef->nsec)
        add_text(v, COLOR_PAIR_NUMBER, "   no usable section table: the analysis relies on the segments");
    else
        add_text(v, COLOR_PAIR_LINENUM, "   %3s  %-20s %-12s %18s %10s %10s  %s", "NR", "NAME", "TYPE", "ADDR", "OFFSET", "SIZE", "FLAGS");
    for (int i = 0; i < ef->nsec; i++) {
        const ElfSection *s = &ef->sec[i];
        char f[8];
        elf_sec_flags_str(s->flags, f);
        add_text(v, s->bad ? COLOR_PAIR_KEYWORD : (s->flags & 4) ? COLOR_PAIR_NUMBER : COLOR_PAIR_NORMAL,
                 "   %3d  %-20.20s %-12.12s %#18llx %#10llx %#10llx  %s%s", i, s->name[0] ? s->name : "-",
                 elf_sec_type_name(s->type), (unsigned long long)s->addr, (unsigned long long)s->off,
                 (unsigned long long)s->size, f, s->bad ? "  outside the file" : "");
    }

    add_title(v, "LOADER WARNINGS (%d)", ef->nwarn);
    if (!ef->nwarn) add_text(v, COLOR_PAIR_COMMENT, "   none");
    for (int i = 0; i < ef->nwarn; i++) add_text(v, COLOR_PAIR_NUMBER, "   ! %s", ef->warn[i]);
}

/* ─── Function list: order and filter ──────────────────────────── */

static const char *sort_name(int s) {
    static const char *n[] = { "address", "name", "size", "callers" };
    return s >= 0 && s < SORT_COUNT ? n[s] : "?";
}

static bool fn_weak(const DisFunc *f) { return f->kind == FN_DATAPTR || f->kind == FN_PROLOGUE; }

static int lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

/* ASCII case-insensitive compare / substring (no strcasecmp, strcasestr:
 * the same code builds with MinGW) */
static int ci_cmp(const char *a, const char *b) {
    for (;; a++, b++) {
        int ca = lower((unsigned char)*a), cb = lower((unsigned char)*b);
        if (ca != cb || !ca) return ca - cb;
    }
}

static bool ci_contains(const char *s, const char *pat) {
    if (!pat[0]) return true;
    if (!s) return false;
    for (; *s; s++) {
        size_t k = 0;
        while (pat[k] && s[k] && lower((unsigned char)s[k]) == lower((unsigned char)pat[k])) k++;
        if (!pat[k]) return true;
        if (!s[k]) return false;
    }
    return false;
}

/* qsort has no context argument everywhere (qsort_r differs on Windows) */
static const DisFunc *sort_fn;
static int sort_key;

static int cmp_fn(const void *pa, const void *pb) {
    uint32_t a = *(const uint32_t *)pa, b = *(const uint32_t *)pb;
    const DisFunc *x = &sort_fn[a], *y = &sort_fn[b];
    int c = 0;
    switch (sort_key) {
        case SORT_NAME: {
            const char *p = x->name ? x->name : "", *q = y->name ? y->name : "";
            c = ci_cmp(p, q);
            if (!c) c = strcmp(p, q);
            break;
        }
        case SORT_SIZE:    c = x->size < y->size ? 1 : x->size > y->size ? -1 : 0;           break;
        case SORT_CALLERS: c = x->ncallers < y->ncallers ? 1 : x->ncallers > y->ncallers ? -1 : 0; break;
    }
    /* d.fn is sorted by address: ties keep the address order */
    return c ? c : (a > b) - (a < b);
}

/* position of function f in vis, -1 when hidden */
static long vis_pos(const DisView *v, long f) {
    for (size_t i = 0; i < v->nvis; i++) if ((long)v->vis[i] == f) return (long)i;
    return -1;
}

static long sel_fn(const DisView *v) {
    return v->list_ok && v->sel < v->nvis ? (long)v->vis[v->sel] : -1;
}

/* rebuilds vis from ord and the filter; the selection stays on function
 * `keep` when it is still shown, else goes back to the top */
static void list_filter(DisView *v, long keep) {
    if (!v->list_ok) return;
    v->nvis = 0;
    long at = -1;
    for (size_t i = 0; i < v->d.nfn; i++) {
        uint32_t f = v->ord[i];
        if (!ci_contains(v->d.fn[f].name, v->filter)) continue;
        if ((long)f == keep) at = (long)v->nvis;
        v->vis[v->nvis++] = f;
    }
    if (at >= 0) v->sel = (size_t)at;
    else v->sel = v->top = 0;
}

static void list_sort(DisView *v) {
    if (!v->list_ok) return;
    long keep = sel_fn(v);
    for (size_t i = 0; i < v->d.nfn; i++) v->ord[i] = (uint32_t)i;
    if (v->sort != SORT_ADDR && v->d.nfn > 1) {
        sort_fn  = v->d.fn;
        sort_key = v->sort;
        qsort(v->ord, v->d.nfn, sizeof *v->ord, cmp_fn);
    }
    list_filter(v, keep);
}

static bool list_init(DisView *v) {
    const Disasm *d = &v->d;
    v->aw = 6;
    if (d->nfn) {
        unsigned long long a = d->fn[d->nfn - 1].addr;   /* the highest */
        int n = 1;
        while (a >>= 4) n++;
        if (n > v->aw) v->aw = n;
    }
    if (d->nfn > UINT32_MAX) return false;
    if (d->nfn) {
        v->ord = malloc(d->nfn * sizeof *v->ord);
        v->vis = malloc(d->nfn * sizeof *v->vis);
        if (!v->ord || !v->vis) {
            free(v->ord); free(v->vis);
            v->ord = v->vis = NULL;
            return false;
        }
    }
    v->list_ok = true;
    list_sort(v);
    return true;
}

static void list_msg(DisView *v, short pair, const char *fmt, ...) __attribute__((format(gnu_printf, 3, 4)));
static void list_msg(DisView *v, short pair, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(v->msg, sizeof v->msg, fmt, ap);
    va_end(ap);
    v->msg_pair = pair;
}

/* "0x401000", "401000h", " 401000 ": 1 to 16 hex digits */
static bool parse_hex(const char *s, uint64_t *out) {
    while (*s == ' ' || *s == '\t') s++;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    uint64_t a = 0;
    int n = 0;
    for (; *s; s++, n++) {
        int c = lower((unsigned char)*s), dv;
        if (c >= '0' && c <= '9') dv = c - '0';
        else if (c >= 'a' && c <= 'f') dv = c - 'a' + 10;
        else break;
        if (n == 16) return false;
        a = a << 4 | (uint64_t)dv;
    }
    if (*s == 'h' || *s == 'H') s++;
    while (*s == ' ' || *s == '\t') s++;
    if (!n || *s) return false;
    *out = a;
    return true;
}

/* selects the function holding addr; outside every function, the
 * closest one below it in the list (else above) */
static void list_goto(DisView *v, const char *text) {
    uint64_t a;
    if (!parse_hex(text, &a)) {
        list_msg(v, COLOR_PAIR_KEYWORD, "not a hex address: \"%.60s\"", text);
        return;
    }
    const Disasm *d = &v->d;
    long f = da_func_containing(d, a);
    if (f >= 0) {
        long p = vis_pos(v, f);
        bool cleared = false;
        if (p < 0 && v->filter[0]) {          /* hidden by the filter: drop it */
            v->filter[0] = '\0';
            list_filter(v, f);
            p = vis_pos(v, f);
            cleared = true;
        }
        if (p < 0) { list_msg(v, COLOR_PAIR_KEYWORD, "0x%llx: in %s, not in the list", (unsigned long long)a, d->fn[f].name); return; }
        v->sel = (size_t)p;
        const DisFunc *fn = &d->fn[f];
        if (a == fn->addr) list_msg(v, COLOR_PAIR_STRING, "0x%llx: start of %s%s", (unsigned long long)a, fn->name, cleared ? "  (filter cleared)" : "");
        else if (a > fn->addr) list_msg(v, COLOR_PAIR_STRING, "0x%llx: %s+0x%llx%s", (unsigned long long)a, fn->name,
                                        (unsigned long long)(a - fn->addr), cleared ? "  (filter cleared)" : "");
        else list_msg(v, COLOR_PAIR_STRING, "0x%llx: code shared with %s%s", (unsigned long long)a, fn->name, cleared ? "  (filter cleared)" : "");
        return;
    }
    long below = -1, above = -1;
    for (size_t i = 0; i < v->nvis; i++) {
        uint64_t fa = d->fn[v->vis[i]].addr;
        if (fa <= a) { if (below < 0 || fa > d->fn[v->vis[below]].addr) below = (long)i; }
        else if (above < 0 || fa < d->fn[v->vis[above]].addr) above = (long)i;
    }
    long p = below >= 0 ? below : above;
    if (p < 0) { list_msg(v, COLOR_PAIR_NUMBER, "0x%llx: in no function (the list is empty)", (unsigned long long)a); return; }
    v->sel = (size_t)p;
    list_msg(v, COLOR_PAIR_NUMBER, "0x%llx is in no function: closest %s %s (0x%llx)", (unsigned long long)a,
             p == below ? "below," : "above,", d->fn[v->vis[p]].name, (unsigned long long)d->fn[v->vis[p]].addr);
}

/* The arguments typed after a (DisView.args), split as a shell would without
 * expanding anything: blanks separate them, '...' keeps everything as is,
 * "..." and a \ outside quotes keep the next character (\" \\ inside "...").
 * On Windows a \ is a path separator: it stays as typed, only \" gives a ".
 * The words go into buf (at least strlen(s) + 1 bytes), av[0 .. n) point
 * into it, av[n] = NULL. Returns n, or -1 (why in err): quote not closed,
 * more than max - 1 words. */
#ifdef _WIN32
#define BS_LITERAL 1
#else
#define BS_LITERAL 0
#endif
static int split_args(const char *s, char *buf, char **av, int max, char *err, size_t esz) {
    int n = 0;
    char *o = buf;
    while (*s) {
        while (*s == ' ' || *s == '\t') s++;
        if (!*s) break;
        if (n + 1 >= max) { snprintf(err, esz, "more than %d arguments", max - 1); return -1; }
        av[n++] = o;
        char q = 0;
        for (; *s; s++) {
            if (q == '\'') { if (*s == '\'') q = 0; else *o++ = *s; continue; }
            if (q == '"') {
                if (*s == '"') q = 0;
                else if (*s == '\\' && (s[1] == '"' || (!BS_LITERAL && s[1] == '\\'))) *o++ = *++s;
                else *o++ = *s;
                continue;
            }
            if (*s == ' ' || *s == '\t') break;
            if (*s == '\'' || *s == '"') q = *s;
            else if (*s == '\\' && (BS_LITERAL ? s[1] == '"' : s[1] != 0)) *o++ = *++s;
            else *o++ = *s;
        }
        if (q) { snprintf(err, esz, "%s quote not closed", q == '"' ? "double" : "single"); return -1; }
        *o++ = '\0';
    }
    av[n] = NULL;
    return n;
}

/* an unfinished prompt when the view is hidden: the old filter comes back */
static void cancel_input(DisView *v) {
    if (v->in_mode == IN_FILTER) {
        snprintf(v->filter, sizeof v->filter, "%s", v->in_save);
        list_filter(v, sel_fn(v));
    }
    v->in_mode = IN_NONE;
}

/* ─── Disassembly of one function ──────────────────────────────── */

/* bytes to sweep from the start of function f: its size, else up to the
 * next function start (at most DIS_GUESS_MAX: *trunc). Either way never
 * past the end of its section (without a section table: of its mapping),
 * so that a wrong symbol size does not show the following data as code
 * (*clip), and never more than DA_LINEAR_MAX (*trunc). 0: no byte there. */
static uint64_t func_range(const DisView *v, long f, bool *guess, bool *trunc, bool *clip) {
    const Disasm *d = &v->d;
    const DisFunc *fn = &d->fn[f];
    uint64_t a = fn->addr, n = fn->size;
    *guess = *trunc = *clip = false;
    size_t avail = 0;
    if (!elf_va_ptr(&d->elf, a, &avail) || !avail) return 0;
    uint64_t lim = avail;                                     /* rest of the mapping */
    const ElfSection *s = elf_section_at(&d->elf, a);        /* a - s->addr < s->size */
    if (s && s->size - (a - s->addr) < lim) lim = s->size - (a - s->addr);
    if (!n) {
        *guess = true;
        n = lim;
        for (size_t k = (size_t)f + 1; k < d->nfn; k++)       /* d.fn: by address */
            if (d->fn[k].addr > a) { if (d->fn[k].addr - a < n) n = d->fn[k].addr - a; break; }
        if (n > DIS_GUESS_MAX) { n = DIS_GUESS_MAX; *trunc = true; }
    } else if (n > lim) {
        n = lim;
        *clip = true;
    }
    if (n > DA_LINEAR_MAX) { n = DA_LINEAR_MAX; *trunc = true; }
    if (a > UINT64_MAX - n) n = UINT64_MAX - a;
    return n;
}

/* decodes function f into the disassembly screen; false + a message in
 * the list bar when it cannot be read (the old lines are kept) */
static void line_refs(DisView *v);

static bool disasm_open(DisView *v, long f) {
    if (f < 0) { list_msg(v, COLOR_PAIR_KEYWORD, "no function selected"); return false; }
    if (f == v->dfn && v->dl) { v->screen = SCR_DISASM; return true; }
    const Disasm *d = &v->d;
    const DisFunc *fn = &d->fn[f];
    bool guess, trunc, clip;
    uint64_t n = func_range(v, f, &guess, &trunc, &clip);
    if (!n) {
        list_msg(v, COLOR_PAIR_KEYWORD, "%.80s (0x%llx): no bytes in the file at this address",
                 fn->name ? fn->name : "?", (unsigned long long)fn->addr);
        return false;
    }
    DisLine *dl = NULL;
    size_t ndl = 0;
    char err[200];
    if (!da_linear(d, fn->addr, (size_t)n, &dl, &ndl, err, sizeof err)) {
        list_msg(v, COLOR_PAIR_KEYWORD, "%.80s: %s", fn->name ? fn->name : "?", err);
        return false;
    }
    size_t nmain = ndl;
    if (fn->cold_size) {                     /* separator, then the .cold part */
        DisLine *cl = NULL, *all;
        size_t ncl = 0;
        size_t cn = fn->cold_size < DA_LINEAR_MAX ? (size_t)fn->cold_size : DA_LINEAR_MAX;
        if (da_linear(d, fn->cold, cn, &cl, &ncl, err, sizeof err) && ncl &&
            ncl < SIZE_MAX / sizeof *all - ndl - 1 &&
            (all = realloc(dl, (ndl + 1 + ncl) * sizeof *all))) {   /* da_linear: one malloc block */
            dl = all;
            memset(&dl[ndl], 0, sizeof *dl);
            dl[ndl].addr = fn->cold;
            memcpy(&dl[ndl + 1], cl, ncl * sizeof *cl);
            ndl += 1 + ncl;
        }
        da_lines_free(cl);
    }
    da_lines_free(v->dl);
    v->dl = dl;
    v->ndl = ndl;
    v->dmain = nmain;
    line_refs(v);
    v->dfn = f;
    v->dva = fn->addr;
    v->dlen = n;
    v->dguess = guess;
    v->dtrunc = trunc;
    v->dclip = clip;
    v->doff = 0;
    if (d->nins)
        for (size_t i = 0; i < ndl; i++)
            if (dl[i].len && (dl[i].bad || da_insn_at(d, dl[i].addr) < 0)) v->doff++;
    v->dsel = v->dtop = 0;
    v->screen = SCR_DISASM;
    return true;
}

/* last word of a capstone mnemonic ("rep stosq", "notrack jmp", "bnd ret") */
static const char *mnem_base(const char *m) {
    const char *s = strrchr(m, ' ');
    return s ? s + 1 : m;
}

static bool mnem_flow(const char *m) {
    m = mnem_base(m);
    return m[0] == 'j' || !strncmp(m, "call", 4) || !strncmp(m, "ret", 3) || !strncmp(m, "loop", 4) ||
           !strcmp(m, "hlt") || !strcmp(m, "ud2") || !strcmp(m, "int3");
}

/* target of a direct branch ("0x401020") or of a rip-relative operand
 * ("[rip + 0x2edf]": next instruction + displacement); false if none */
static bool line_ref(const DisLine *l, uint64_t *t) {
    if (l->bad) return false;
    const char *m = mnem_base(l->mnem);
    char *end;
    if ((m[0] == 'j' || !strncmp(m, "call", 4) || !strncmp(m, "loop", 4)) &&
        l->ops[0] == '0' && l->ops[1] == 'x') {
        unsigned long long x = strtoull(l->ops, &end, 16);
        if (!*end) { *t = x; return true; }
    }
    const char *r = strstr(l->ops, "rip ");
    if (r && (r[4] == '+' || r[4] == '-') && r[5] == ' ' && r[6] == '0' && r[7] == 'x') {
        unsigned long long x = strtoull(r + 6, &end, 16);
        if (*end != ']') return false;
        uint64_t next = l->addr + l->len;
        *t = r[4] == '+' ? next + x : next - x;
        return true;
    }
    return false;
}

/* 32-bit PE: absolute memory operand `[0x402030]` (an IAT slot for
 * `call dword ptr [0x402030]`), no register in the brackets */
static bool abs_ref(const DisLine *l, uint64_t *t) {
    if (l->bad) return false;
    const char *r = strstr(l->ops, "[0x");
    if (!r) return false;
    char *end;
    unsigned long long x = strtoull(r + 1, &end, 16);
    if (*end != ']') return false;
    *t = x;
    return true;
}

/* ─── Data sections ────────────────────────────────────────────── */

#define DATA_MAX        (16u << 20)   /* bytes of one section shown          */
#define DATA_MAX_ITEMS  (1u << 20)    /* rows of one section                 */
#define DATA_STR_MAX    4096u         /* longest string taken as one row     */
#define DATA_ZERO_MIN   16u           /* zero bytes folded into one row      */
#define DATA_HEX        16u           /* bytes of a hex row                  */
#define D_SHF_WRITE     1u
#define D_SHF_ALLOC     2u
#define D_SHF_EXEC      4u
#define D_SHT_NOBITS    8u
#define D_PF_X          1u

/* what a usual section holds (prefix match when the name ends in '*') */
static const char *sec_desc(const char *n) {
    static const char *const t[][2] = {
        { ".rodata*",       "read-only data: strings, constants, switch tables" },
        { ".data.rel.ro*",  "read-only once relocated: vtables, tables of pointers" },
        { ".data*",         "initialised writable data (globals, statics)" },
        { ".bss*",          "globals set to zero at start (not in the file)" },
        { ".tdata",         "thread-local data, initial values" },
        { ".tbss",          "thread-local data set to zero" },
        { ".got.plt",       "addresses of the imported functions (PLT slots)" },
        { ".got",           "global offset table: addresses filled by the loader" },
        { ".init_array",    "constructors, run before main" },
        { ".preinit_array", "run before the constructors" },
        { ".fini_array",    "destructors, run at exit" },
        { ".dynamic",       "dynamic linking: libraries needed, tables" },
        { ".dynsym",        "dynamic symbols (imports, exports)" },
        { ".dynstr",        "names of the dynamic symbols and libraries" },
        { ".rela*",         "relocations applied by the loader" },
        { ".rel.*",         "relocations applied by the loader" },
        { ".relr*",         "relocations (compact form)" },
        { ".eh_frame_hdr",  "index of the unwind tables" },
        { ".eh_frame",      "unwind tables (exceptions, stack traces)" },
        { ".gcc_except_table", "exception handling tables (C++)" },
        { ".interp",        "path of the program interpreter" },
        { ".note*",         "notes: build id, ABI, properties" },
        { ".gnu.hash",      "hash table of the dynamic symbols" },
        { ".hash",          "hash table of the dynamic symbols" },
        { ".gnu.version*",  "versions of the dynamic symbols" },
        { ".go.buildinfo",  "Go build information (module, version)" },
        { ".gopclntab",     "Go function table (names, lines)" },
        { ".typelink",      "Go type table" },
        { ".itablink",      "Go interface table" },
        { ".noptrdata",     "Go data without pointers" },
        { ".noptrbss",      "Go zero data without pointers" },
        /* PE */
        { ".rdata",         "read-only data: strings, constants, import names" },
        { ".idata",         "imports: DLL names and the IAT (addresses filled by the loader)" },
        { ".edata",         "exports: the functions this DLL gives" },
        { ".pdata",         "unwind table: start and end of each function" },
        { ".xdata",         "unwind codes (exceptions, stack traces)" },
        { ".reloc",         "base relocations, applied when loaded elsewhere (ASLR)" },
        { ".rsrc",          "resources: icons, version info, dialogs, manifest" },
        { ".tls",           "thread-local data, initial values" },
        { ".CRT*",          "C runtime start-up tables (initialisers)" },
        { ".didat",         "delay-load import addresses" },
        { ".gfids",         "Control Flow Guard function table" },
        { ".debug_*",       "DWARF debug information (MinGW)" },
    };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        size_t k = strlen(t[i][0]);
        if (t[i][0][k - 1] == '*' ? !strncmp(n, t[i][0], k - 1) : !strcmp(n, t[i][0])) return t[i][1];
    }
    return "";
}

static int cmp_ds(const void *x, const void *y) {
    const DataSec *p = x, *q = y;
    return p->addr < q->addr ? -1 : p->addr > q->addr;
}

/* the data sections: allocated, not executable, not empty; without a
 * section table, the non-executable mappings. Widens v->aw to their
 * addresses. false: out of memory (the screen says so). */
static bool data_init(DisView *v) {
    const ElfFile *ef = &v->d.elf;
    size_t n = ef->nsec ? (size_t)ef->nsec : (size_t)ef->nmap;
    v->xsec = -1;
    if (!n) return true;
    v->ds = calloc(n, sizeof *v->ds);
    if (!v->ds) return false;
    for (int i = 0; i < ef->nsec; i++) {
        const ElfSection *s = &ef->sec[i];
        if (!(s->flags & D_SHF_ALLOC) || (s->flags & D_SHF_EXEC) || !s->size || !s->addr ||
            s->size > UINT64_MAX - s->addr)
            continue;
        DataSec *d = &v->ds[v->nds++];
        snprintf(d->name, sizeof d->name, "%s", s->name[0] ? s->name : "(no name)");
        d->addr   = s->addr;
        d->size   = s->size;
        d->filesz = s->type == D_SHT_NOBITS ? 0 : s->size;
        d->bad    = s->type != D_SHT_NOBITS && s->bad;
        snprintf(d->perm, sizeof d->perm, "r%c-", (s->flags & D_SHF_WRITE) ? 'w' : '-');
        d->type   = elf_sec_type_name(s->type);
        d->desc   = sec_desc(d->name);
    }
    if (!ef->nsec)
        for (int i = 0; i < ef->nmap; i++) {
            const ElfMap *m = &ef->map[i];
            if ((m->flags & D_PF_X) || !m->memsz || m->memsz > UINT64_MAX - m->va) continue;
            DataSec *d = &v->ds[v->nds++];
            snprintf(d->name, sizeof d->name, "segment %d", i);
            d->addr   = m->va;
            d->size   = m->memsz;
            d->filesz = m->filesz < m->memsz ? m->filesz : m->memsz;
            elf_flags_str(m->flags, d->perm);
            for (char *c = d->perm; *c; c++) if (*c >= 'A' && *c <= 'Z') *c = (char)(*c + 32);
            d->type   = "LOAD";
            d->desc   = d->filesz < d->size ? "data, then zero-filled memory (no section table)"
                                            : "data (no section table)";
        }
    if (v->nds) qsort(v->ds, v->nds, sizeof *v->ds, cmp_ds);
    for (size_t i = 0; i < v->nds; i++) {
        unsigned long long a = v->ds[i].addr + v->ds[i].size - 1;
        int k = 1;
        while (a >>= 4) k++;
        if (k > v->aw) v->aw = k;
    }
    return true;
}

/* section holding a, or -1 */
static long data_sec_at(const DisView *v, uint64_t a) {
    for (size_t i = 0; i < v->nds; i++)
        if (a >= v->ds[i].addr && a - v->ds[i].addr < v->ds[i].size) return (long)i;
    return -1;
}

static bool text_byte(uint8_t c) {
    return (c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r' || c >= 0x80;
}

/* Whether p[0 .. n) starts a string: 4 characters or more (ASCII,
 * \t \n \r, UTF-8) then a NUL, or DATA_STR_MAX bytes of them. *len: its
 * bytes with the NUL. On failure *stop is where the run of text bytes
 * ends: no string starts before it either. */
static bool str_run(const uint8_t *p, size_t n, size_t *len, size_t *stop) {
    size_t i = 0, chars = 0;
    while (i < n && i < DATA_STR_MAX && p[i]) {
        uint8_t c = p[i];
        if ((c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r') { i++; chars++; continue; }
        uint32_t cp;
        int k = c >= 0xc2 ? utf8_decode((const char *)p + i, n - i, &cp) : 0;
        if (k < 2 || cp < 0xa0) break;
        i += (size_t)k;
        chars++;
    }
    if (chars >= 4 && i < n && !p[i]) { *len = i + 1; return true; }
    if (chars >= 4 && i >= DATA_STR_MAX) { *len = i; return true; }
    *stop = i ? i : 1;
    return false;
}

static size_t zero_run(const uint8_t *p, size_t n) {
    size_t i = 0;
    while (i < n && !p[i]) i++;
    return i;
}

/* an address stored at s (8-aligned): an import's GOT slot, or a word
 * (relocations applied) pointing into the file's mappings */
static bool ptr_at(const ElfFile *ef, uint64_t s, uint64_t *t) {
    if (elf_import_got(ef, s)) {
        if (!elf_read_ptr(ef, s, t)) *t = 0;
        return true;
    }
    return elf_read_ptr(ef, s, t) && *t && elf_map_of(ef, *t);
}

/* first symbol start above a, or UINT64_MAX (ef->sym: by value) */
static uint64_t sym_next(const ElfFile *ef, uint64_t a) {
    size_t lo = 0, hi = (size_t)ef->nsym;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (ef->sym[mid].value <= a) lo = mid + 1; else hi = mid;
    }
    return lo < (size_t)ef->nsym ? ef->sym[lo].value : UINT64_MAX;
}

static bool item_push(DisView *v, size_t *cap, const DataItem *it) {
    if (v->nxi == *cap) {
        size_t nc = *cap ? *cap * 2 : 1024;
        DataItem *n = realloc(v->xi, nc * sizeof *n);
        if (!n) return false;
        v->xi = n;
        *cap = nc;
    }
    v->xi[v->nxi++] = *it;
    return true;
}

/* Rows of section ds[si], cut at each symbol start: an address (8-aligned
 * word pointing into the file, or a GOT slot), a string, a run of zero
 * bytes, else up to 16 bytes of hex. The bytes not in the file are one
 * zero row per symbol. Linear in the size (at most DATA_MAX bytes,
 * DATA_MAX_ITEMS rows). false: out of memory. */
static bool data_build(DisView *v, size_t si) {
    const ElfFile *ef = &v->d.elf;
    const DataSec *s = &v->ds[si];
    free(v->xi);
    v->xi = NULL;
    v->nxi = 0;
    v->xtrunc = false;
    size_t cap = 0;
    uint64_t size = s->size;
    if (size > DATA_MAX) { size = DATA_MAX; v->xtrunc = true; }
    uint64_t a = s->addr, end = a + size;
    size_t avail = 0;
    const uint8_t *p = s->filesz && !s->bad ? elf_va_ptr(ef, a, &avail) : NULL;
    uint64_t fsz = p ? s->filesz : 0;
    if (fsz > avail) fsz = avail;
    if (fsz > size) fsz = size;
    uint64_t fend = a + fsz, nostr = 0, cur = a;    /* no string starts before nostr */
    while (cur < end) {
        if (v->nxi >= DATA_MAX_ITEMS) { v->xtrunc = true; break; }
        uint64_t lim = sym_next(ef, cur);
        if (lim > end) lim = end;
        DataItem it = { cur, 0, 0, DT_HEX };
        if (cur >= fend) {
            it.kind = DT_ZERO;
            it.len  = (uint32_t)(lim - cur);
        } else {
            if (lim > fend) lim = fend;
            const uint8_t *q = p + (cur - a);
            size_t n = (size_t)(lim - cur), sl, stop;
            uint64_t t;
            if (!(cur & 7) && n >= 8 && ptr_at(ef, cur, &t)) {
                it.kind = DT_PTR; it.len = 8; it.target = t;
            } else if (cur >= nostr && str_run(q, n, &sl, &stop)) {
                it.kind = DT_STR; it.len = (uint32_t)sl;
            } else {
                if (cur >= nostr) nostr = cur + stop;   /* str_run ran: stop is set */
                if ((sl = zero_run(q, n)) >= DATA_ZERO_MIN) {
                    it.kind = DT_ZERO; it.len = (uint32_t)sl;
                } else {
                    size_t k = 1;
                    for (; k < n && k < DATA_HEX; k++) {
                        uint64_t c = cur + k;
                        if (!(c & 7) && n - k >= 8 && ptr_at(ef, c, &t)) break;
                        if (!q[k] && q[k - 1] && zero_run(q + k, n - k) >= DATA_ZERO_MIN) break;
                        if (c >= nostr && !text_byte(q[k - 1]) && text_byte(q[k])) {
                            if (str_run(q + k, n - k, &sl, &stop)) break;
                            nostr = c + stop;
                        }
                    }
                    it.len = (uint32_t)k;
                }
            }
        }
        if (!item_push(v, &cap, &it)) return false;
        cur += it.len;
    }
    return true;
}

/* row of the open section holding a */
static size_t item_at(const DisView *v, uint64_t a) {
    size_t lo = 0, hi = v->nxi;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (v->xi[mid].addr <= a) lo = mid + 1; else hi = mid;
    }
    return lo ? lo - 1 : 0;
}

/* where a row leads (what follow() can show): the address held, code
 * in a function found or data in a section of the list, or for an
 * import's GOT slot its PLT stub when it has one */
static bool item_link(const DisView *v, const DataItem *it, uint64_t *t) {
    if (it->kind != DT_PTR) return false;
    const ElfFile *ef = &v->d.elf;
    const ElfImport *im = elf_import_got(ef, it->addr);
    if (im) {
        if (im->plt && da_func_at(&v->d, im->plt) >= 0) { *t = im->plt; return true; }
        return false;
    }
    uint64_t a = it->target;
    if (!a || !elf_map_of(ef, a)) return false;
    if (elf_va_code(ef, a)) {                    /* code: in a function found */
        if (da_func_containing(&v->d, a) < 0) return false;
    } else {                                     /* data: in a section shown */
        long si = data_sec_at(v, a);
        if (si < 0 || v->ds[si].bad || a - v->ds[si].addr >= DATA_MAX) return false;
    }
    *t = a;
    return true;
}

/* ─── Addresses held by the operands of a line ────────────────── */

/* a is something follow() shows: code in a function found, or data in a
 * section of the list (within what its dump holds) */
static bool link_ok(const DisView *v, uint64_t a) {
    if (!a || !elf_map_of(&v->d.elf, a)) return false;
    if (elf_va_code(&v->d.elf, a)) return da_func_containing(&v->d, a) >= 0;
    long si = data_sec_at(v, a);
    return si >= 0 && !v->ds[si].bad && a - v->ds[si].addr < DATA_MAX;
}

/* No program is mapped in the first 64 KiB (Linux vm.mmap_min_addr,
 * Windows' null page area): a smaller constant is a size or an offset.
 * In a position-independent ELF (linked at 0) no constant is taken. */
#define REF_MIN 0x10000u

static const char *const g_r32[8] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };

static int r32_index(const char *s, size_t n) {
    for (int r = 0; r < 8; r++) if (n == 3 && !memcmp(s, g_r32[r], 3)) return r;
    return -1;
}

/* where a (link_ok) lies: "section+0x10", "function+0x10" */
static void ref_place(const DisView *v, uint64_t a, char *out, size_t sz) {
    long f = elf_va_code(&v->d.elf, a) ? da_func_containing(&v->d, a) : -1;
    long si = f < 0 ? data_sec_at(v, a) : -1;
    const char *n = f >= 0 ? v->d.fn[f].name : si >= 0 ? v->ds[si].name : NULL;
    uint64_t b = f >= 0 ? v->d.fn[f].addr : si >= 0 ? v->ds[si].addr : 0;
    if (!n || !n[0]) { snprintf(out, sz, "0x%llx", (unsigned long long)a); return; }
    if (a == b) snprintf(out, sz, "%s", n);
    else snprintf(out, sz, "%s+0x%llx", n, (unsigned long long)(a - b));
}

/* the x86-32 register written by a get-pc thunk at a (`mov r32, [esp]; ret`), -1: none */
static int thunk_reg(const ElfFile *ef, uint64_t a) {
    size_t av = 0;
    const uint8_t *p = elf_va_ptr(ef, a, &av);
    if (!p || av < 4 || p[0] != 0x8b || (p[1] & 0xc7) != 0x04 || p[2] != 0x24 || p[3] != 0xc3) return -1;
    return (p[1] >> 3) & 7;
}

static bool parse_num(const char *s, size_t n, uint64_t *out) {
    if (!n) return false;
    char tmp[24], *end;
    if (n >= sizeof tmp) return false;
    memcpy(tmp, s, n); tmp[n] = '\0';
    bool hex = n > 2 && tmp[0] == '0' && tmp[1] == 'x';
    if (!hex && (tmp[0] < '0' || tmp[0] > '9')) return false;
    *out = strtoull(tmp, &end, hex ? 16 : 10);
    return !*end;
}

/* The address a memory operand [ ... ] (body s, n bytes) designates, from
 * its constant and, in 32-bit code, a base register of known value
 * (val / known): [0x403014], [eax*4 + 0x403004] (the table), [ebx - 0x1fd8]
 * with ebx = the pc + a constant. rip is line_ref's. cst: a constant
 * alone may be an address (see ops_ref). false: none. */
static bool mem_addr(const char *s, size_t n, const uint64_t *val, const bool *known, uint64_t mask, bool cst, uint64_t *t) {
    uint64_t disp = 0, base = 0;
    int sign = 1, nbase = 0;
    bool index = false, other = false;
    size_t i = 0;
    while (i < n) {
        while (i < n && s[i] == ' ') i++;
        size_t j = i;
        while (j < n && s[j] != ' ') j++;
        if (j == i) break;
        const char *w = s + i;
        size_t wn = j - i;
        uint64_t x;
        if (wn == 1 && (*w == '+' || *w == '-')) sign = *w == '-' ? -1 : 1;
        else if (parse_num(w, wn, &x)) disp += sign < 0 ? (uint64_t)0 - x : x;
        else if (memchr(w, '*', wn)) index = true;          /* reg*scale */
        else {
            int r = val ? r32_index(w, wn) : -1;
            if (r >= 0 && known[r]) { base = val[r]; nbase++; }
            else other = true;                              /* rip, esp, an unknown register */
        }
        i = j;
    }
    if (other || nbase > 1) return false;
    if (nbase) { *t = (base + disp) & mask; return true; }
    if (!cst) return false;                                 /* a constant alone: not an address here */
    disp &= mask;
    (void)index;                                            /* [index*scale + table]: the table */
    if (disp < REF_MIN) return false;
    *t = disp;
    return true;
}

/* The address held by the operands of line l (memory operand first, then
 * an immediate), when link_ok; 0: none. Branch targets and rip-relative
 * operands stay line_ref's. */
static uint64_t ops_ref(const DisView *v, const DisLine *l, const uint64_t *val, const bool *known) {
    if (l->bad || !l->len) return 0;
    const char *m = mnem_base(l->mnem);
    if (m[0] == 'j' || !strncmp(m, "call", 4) || !strncmp(m, "loop", 4)) {
        if (l->ops[0] == '0' && l->ops[1] == 'x') return 0;   /* direct: line_ref */
    }
    uint64_t mask = v->d.elf.bits == 32 ? 0xffffffffu : ~(uint64_t)0, t;
    const char *o = l->ops;
    /* an ELF linked at 0 (PIE, shared object: ET_DYN) reaches its data
     * relative to the pc, its constants are no addresses; a PE image has
     * its ImageBase, and its absolute addresses are relocated */
    bool cst = v->d.elf.fmt == ELF_FMT_PE || v->d.elf.type != 3;
    for (const char *b = strchr(o, '['); b; b = strchr(b + 1, '[')) {
        const char *e = strchr(b, ']');
        if (!e) break;
        if (b > o + 1 && b[-1] == ':') continue;             /* fs:[...] gs:[...]: thread data */
        if (mem_addr(b + 1, (size_t)(e - b - 1), v->d.elf.bits == 32 ? val : NULL, known, mask, cst, &t) && link_ok(v, t)) return t;
    }
    /* immediates: an operand that is a number alone */
    for (const char *p = o; *p; ) {
        const char *q = strchr(p, ',');
        size_t n = q ? (size_t)(q - p) : strlen(p);
        while (n && *p == ' ') { p++; n--; }
        while (n && p[n - 1] == ' ') n--;
        if (cst && parse_num(p, n, &t) && (t &= mask) >= REF_MIN && link_ok(v, t)) return t;
        if (!q) break;
        p = q + 1;
    }
    return 0;
}

/* the register an instruction writes as its first operand (32-bit names,
 * or their 16 / 8-bit parts), -1: none / not a register */
static int dest_reg(const DisLine *l) {
    const char *m = mnem_base(l->mnem);
    if (!strncmp(m, "cmp", 3) || !strcmp(m, "test") || !strncmp(m, "push", 4) || !strncmp(m, "bt", 2) ||
        m[0] == 'j' || !strncmp(m, "call", 4) || !strncmp(m, "ret", 3)) return -1;
    static const char *const part[8][3] = {
        { "ax", "al", "ah" }, { "cx", "cl", "ch" }, { "dx", "dl", "dh" }, { "bx", "bl", "bh" },
        { "sp", "spl", "" },  { "bp", "bpl", "" },  { "si", "sil", "" }, { "di", "dil", "" } };
    size_t n = strcspn(l->ops, ", ");
    int r = r32_index(l->ops, n);
    if (r >= 0) return r;
    for (r = 0; r < 8; r++)
        for (int k = 0; k < 3; k++)
            if (part[r][k][0] && strlen(part[r][k]) == n && !memcmp(l->ops, part[r][k], n)) return r;
    return -1;
}

/* v->dref of the lines just opened. In 32-bit code a few registers are
 * followed down the lines: the pc from a get-pc thunk (`call thunk`) or
 * `call $+5; pop r`, then add / sub of a constant, `mov r2, r` and a
 * spill to / reload from [ebp ± X] (the GOT base of PIC code, used as
 * [ebx + X@GOTOFF]). Any other write
 * forgets a register, a call forgets eax ecx edx. The lines are in address
 * order, not along the jumps: after a ret / jmp (and at the .cold part),
 * the registers set from the pc and only lost to a restore (pop, mov from
 * the slot the caller's value was saved to) come back: the epilogue of an
 * early return does not end the function. */
static void line_refs(DisView *v) {
    v->npick = 0;                                    /* a choice among the old lines */
    free(v->dref);
    v->dref = v->ndl ? calloc(v->ndl, sizeof *v->dref) : NULL;
    if (!v->dref) return;
    const ElfFile *ef = &v->d.elf;
    bool x32 = ef->bits == 32;
    uint64_t val[8] = { 0 }, est[8] = { 0 };
    bool known[8] = { false }, kest[8] = { false };
    /* registers of known value spilled to [ebp ± X] (gcc -O3 keeps the GOT
     * base there): the operand text, its value */
    struct { char at[32]; uint64_t val; } spill[8];
    int nspill = 0;
    /* where the caller's value of each register was saved ([esp + X] /
     * [ebp - X] stored while the register was not known): a reload from
     * there is an epilogue's restore, from anywhere else a new value */
    char save[8][32] = { "" };
    for (size_t i = 0; i < v->ndl; i++) {
        const DisLine *l = &v->dl[i];
        if (!l->len) { memcpy(val, est, sizeof val); memcpy(known, kest, sizeof known); continue; }
        uint64_t t;
        if (!line_ref(l, &t)) v->dref[i] = ops_ref(v, l, val, known);
        if (!x32 || l->bad) continue;
        const char *m = mnem_base(l->mnem);
        int d = dest_reg(l);
        uint64_t next = (l->addr + l->len) & 0xffffffffu, x;
        /* mov dword ptr [ebp ± X], r: a spill (r known) or a save (r not
         * known yet); any other write there forgets the slot */
        bool sp_ = !strncmp(l->ops, "dword ptr [esp", 14), bp_ = !strncmp(l->ops, "dword ptr [ebp ", 15);
        if (sp_ || bp_) {
            const char *e = strchr(l->ops, ']');
            size_t an = e ? (size_t)(e - l->ops - 10 + 1) : 0;   /* "[ebp - 0x10]" */
            int k = 0;
            while (k < nspill && (strlen(spill[k].at) != an || memcmp(spill[k].at, l->ops + 10, an))) k++;
            int sr = e && e[1] == ',' && e[2] == ' ' && !strcmp(m, "mov") ? r32_index(e + 3, strlen(e + 3)) : -1;
            if (k < nspill) spill[k] = spill[--nspill];
            if (sr >= 0 && an < sizeof spill[0].at) {
                if (!known[sr]) { memcpy(save[sr], l->ops + 10, an); save[sr][an] = '\0'; }
                else if (bp_ && nspill < 8) {                /* esp moves with every push */
                    memcpy(spill[nspill].at, l->ops + 10, an); spill[nspill].at[an] = '\0';
                    spill[nspill++].val = val[sr];
                }
            }
        }
        if (!strncmp(m, "call", 4)) {
            known[0] = known[1] = known[2] = kest[0] = kest[1] = kest[2] = false;
            int r = line_ref(l, &t) ? thunk_reg(ef, t) : -1;
            if (r >= 0) { val[r] = next; known[r] = true; }
            else if (line_ref(l, &t) && t == next && i + 1 < v->ndl && !strcmp(v->dl[i + 1].mnem, "pop")) {
                int pr = r32_index(v->dl[i + 1].ops, strlen(v->dl[i + 1].ops));
                if (pr >= 0) { val[pr] = next; known[pr] = true; i++; }   /* the pop is taken here */
            }
        } else if (d >= 0 && (!strcmp(m, "add") || !strcmp(m, "sub")) && known[d] && l->ops[3] == ',' &&
                   r32_index(l->ops, 3) == d && parse_num(l->ops + 5, strlen(l->ops + 5), &x)) {
            val[d] = (m[0] == 'a' ? val[d] + x : val[d] - x) & 0xffffffffu;
        } else if (d >= 0 && !strcmp(m, "mov") && strlen(l->ops) == 8 && r32_index(l->ops + 5, 3) >= 0 &&
                   known[r32_index(l->ops + 5, 3)]) {
            val[d] = val[r32_index(l->ops + 5, 3)]; known[d] = true;
        } else if (d >= 0 && !strcmp(m, "mov") && l->ops[3] == ',' && r32_index(l->ops, 3) == d &&
                   (!strncmp(l->ops + 3, ", dword ptr [ebp ", 17) || !strncmp(l->ops + 3, ", dword ptr [esp", 16))) {
            const char *at = l->ops + 15;                    /* reload of a spill, of the save? */
            int k = 0;
            while (k < nspill && strcmp(spill[k].at, at)) k++;
            if (k < nspill) { val[d] = spill[k].val; known[d] = true; }
            else {
                known[d] = false;
                if (!save[d][0] || strcmp(save[d], at)) kest[d] = false;   /* not the restore: a new value */
            }
        } else if (d >= 0) {
            known[d] = false;
            if (strcmp(m, "pop")) kest[d] = false;           /* written for good (pop: the restore) */
        } else if (!strcmp(m, "xchg") || !strcmp(m, "cpuid") || !strncmp(m, "popa", 4) || !strcmp(m, "cmpxchg8b")) {
            memset(known, 0, sizeof known); memset(kest, 0, sizeof kest);
        }
        if (!strcmp(m, "mul") || !strcmp(m, "div") || !strcmp(m, "imul") || !strcmp(m, "idiv") ||
            !strcmp(m, "cdq") || !strcmp(m, "rdtsc"))
            known[0] = known[2] = kest[0] = kest[2] = false;
        for (int r = 0; r < 8; r++)                          /* from the pc, and still right */
            if (known[r]) { est[r] = val[r]; kest[r] = true; }
        if (!strncmp(m, "ret", 3) || !strcmp(m, "jmp")) { memcpy(val, est, sizeof val); memcpy(known, kest, sizeof known); }
    }
}

/* ─── Arguments of a call ──────────────────────────────────────── */

/* 0-15 for rax .. r15 and their 32 / 16 / 8-bit parts, -1: not a register */
static int reg_id(const char *s, size_t n) {
    static const char *const nm[16][4] = {
        { "rax", "eax", "ax", "al" },     { "rcx", "ecx", "cx", "cl" },     { "rdx", "edx", "dx", "dl" },
        { "rbx", "ebx", "bx", "bl" },     { "rsp", "esp", "sp", "spl" },    { "rbp", "ebp", "bp", "bpl" },
        { "rsi", "esi", "si", "sil" },    { "rdi", "edi", "di", "dil" },    { "r8", "r8d", "r8w", "r8b" },
        { "r9", "r9d", "r9w", "r9b" },    { "r10", "r10d", "r10w", "r10b" }, { "r11", "r11d", "r11w", "r11b" },
        { "r12", "r12d", "r12w", "r12b" }, { "r13", "r13d", "r13w", "r13b" }, { "r14", "r14d", "r14w", "r14b" },
        { "r15", "r15d", "r15w", "r15b" } };
    for (int r = 0; r < 16; r++)
        for (int k = 0; k < 4; k++)
            if (strlen(nm[r][k]) == n && !memcmp(s, nm[r][k], n)) return r;
    return -1;
}

/* the address line j puts somewhere (not a branch): rip-relative operand,
 * the operands' address (dref), a PE32 [abs] */
static bool line_value(const DisView *v, size_t j, uint64_t *t) {
    const DisLine *l = &v->dl[j];
    const char *m = mnem_base(l->mnem);
    if (l->bad || !l->len || m[0] == 'j' || !strncmp(m, "call", 4) || !strncmp(m, "loop", 4)) return false;
    if (line_ref(l, t)) return true;
    if (v->dref && v->dref[j]) { *t = v->dref[j]; return true; }
    return v->d.elf.fmt == ELF_FMT_PE && v->d.elf.bits == 32 && abs_ref(l, t);
}

/* the address register r holds at line j: its last write in the 16
 * lines before (not past a call, ret, jmp) when that is a mov / lea of an
 * address; false: not known */
static bool reg_value(const DisView *v, size_t j, int r, uint64_t *t) {
    for (size_t i = j; i-- > 0 && j - i <= 16; ) {
        const DisLine *l = &v->dl[i];
        if (!l->len || l->bad) return false;
        const char *m = mnem_base(l->mnem);
        if (!strncmp(m, "call", 4) || !strncmp(m, "ret", 3) || !strcmp(m, "jmp")) return false;
        if (!strncmp(m, "cmp", 3) || !strcmp(m, "test") || !strncmp(m, "push", 4) || m[0] == 'j') continue;
        if (reg_id(l->ops, strcspn(l->ops, ", ")) != r) continue;
        return (!strcmp(m, "mov") || !strcmp(m, "lea") || !strcmp(m, "movabs")) && line_value(v, i, t);
    }
    return false;
}

/* [ebp - X] / [rbp - X] in operand s (a local of the frame): its
 * brackets, into slot; false: another operand */
static bool frame_slot(const char *s, char *slot, size_t sz) {
    const char *b = strchr(s, '['), *e = b ? strchr(b, ']') : NULL;
    if (!b || !e || (strncmp(b + 1, "ebp ", 4) && strncmp(b + 1, "rbp ", 4)) || (size_t)(e - b + 1) >= sz) return false;
    memcpy(slot, b, (size_t)(e - b + 1));
    slot[e - b + 1] = '\0';
    return true;
}

/* The address the local `slot` holds at line j: its last store before
 * j in the function, `mov <size> ptr [ebp - X], <address>` (or from a
 * register set just before). The lines are taken in address order, past
 * calls (a callee does not write the caller's locals, unless their
 * address was taken: a `lea r, [ebp - X]` of it ends the search). */
static bool slot_value(const DisView *v, size_t j, const char *slot, uint64_t *t) {
    size_t sl = strlen(slot);
    for (size_t i = j; i-- > 0 && j - i <= 400; ) {
        const DisLine *l = &v->dl[i];
        if (!l->len || l->bad) continue;
        const char *m = mnem_base(l->mnem);
        const char *b = strchr(l->ops, '['), *c = strchr(l->ops, ',');
        bool here = b && !strncmp(b, slot, sl);
        if (!here) continue;
        if (!strcmp(m, "lea")) return false;             /* its address goes elsewhere */
        if (c && b > c) continue;                        /* read, not written */
        if (strcmp(m, "mov") || !c) return false;        /* add, inc, a pop...: changed */
        const char *src = c + 1;
        while (*src == ' ') src++;
        if (line_value(v, i, t)) return true;
        int r = reg_id(src, strcspn(src, " ,"));
        return r >= 0 && reg_value(v, i, r, t);
    }
    return false;
}

#define CALL_ARGS 6
typedef struct { uint64_t t; bool mem, idx; } CallArg;   /* mem: the value read at t, not t; idx: at t[index] */

/* The arguments of the call on line i that the lines just before it set
 * to an address: x86-64 registers (rdi rsi rdx rcx r8 r9, Windows: rcx
 * rdx r8 r9), x86-32 `push` and `mov dword ptr [esp + 4k], X`; a copy
 * from another register is followed back (`lea eax, [..]` then
 * `mov [esp], eax`). Up to 16 lines back, not past a call, ret, jmp.
 * Returns 1 + the last argument found, 0: none. */
static int call_args(const DisView *v, size_t i, CallArg *arg) {
    memset(arg, 0, sizeof *arg * CALL_ARGS);
    const ElfFile *ef = &v->d.elf;
    bool x32 = ef->bits == 32, done[CALL_ARGS] = { false };
    int pend[16];                                    /* register -> the argument it holds */
    for (int r = 0; r < 16; r++) pend[r] = -1;
    if (!x32) {
        static const int sysv[6] = { 7, 6, 2, 1, 8, 9 }, win[4] = { 1, 2, 8, 9 };
        if (ef->fmt == ELF_FMT_PE) for (int k = 0; k < 4; k++) pend[win[k]] = k;
        else                       for (int k = 0; k < 6; k++) pend[sysv[k]] = k;
    }
    int npush = 0, top = 0;
    for (size_t j = i; j-- > 0 && i - j <= 16; ) {
        const DisLine *l = &v->dl[j];
        if (!l->len || l->bad) break;
        const char *m = mnem_base(l->mnem);
        if (!strncmp(m, "call", 4) || !strncmp(m, "ret", 3) || !strcmp(m, "jmp")) break;
        int k = -1;
        const char *src = NULL;
        if (x32 && !strcmp(m, "push")) {
            k = npush++;
            src = l->ops;
            if (k < CALL_ARGS && done[k]) k = -1;
        } else if (x32 && !strcmp(m, "mov") && !strncmp(l->ops, "dword ptr [esp", 14)) {
            char *p = (char *)l->ops + 14;
            unsigned long off = 0;
            if (!strncmp(p, " + ", 3)) off = strtoul(p + 3, &p, 0);
            if (p[0] == ']' && p[1] == ',' && !(off & 3) && off / 4 < CALL_ARGS && !done[off / 4]) { k = (int)(off / 4); src = p + 2; }
        } else if (strncmp(m, "cmp", 3) && strcmp(m, "test") && strncmp(m, "push", 4) && strncmp(m, "bt", 2) && m[0] != 'j') {
            int d = reg_id(l->ops, strcspn(l->ops, ", "));
            if (d >= 0 && pend[d] >= 0) {            /* the closest write to it */
                k = pend[d];
                pend[d] = -1;
                src = strchr(l->ops, ',');
                src = src ? src + 1 : "";
                if (strcmp(m, "mov") && strcmp(m, "lea") && strcmp(m, "movabs")) continue;   /* xor edi, edi...: not an address */
            }
        }
        if (k < 0 || k >= CALL_ARGS) continue;
        done[k] = true;
        while (*src == ' ') src++;
        uint64_t t;
        if (line_value(v, j, &t)) {
            arg[k].t = t;
            arg[k].mem = strchr(src, '[') && strcmp(m, "lea");
            arg[k].idx = arg[k].mem && strchr(src, '*');
            if (k + 1 > top) top = k + 1;
        } else {
            int r = reg_id(src, strcspn(src, " ,"));
            char slot[40];
            if (r >= 0 && r != 4 && r != 5) pend[r] = k;   /* a copy: where that register was set */
            else if (r < 0 && (!strcmp(m, "mov") || !strcmp(m, "push")) && frame_slot(src, slot, sizeof slot) &&
                     slot_value(v, j, slot, &t)) {         /* a local: what was stored there */
                arg[k].t = t;
                if (k + 1 > top) top = k + 1;
            }
        }
    }
    return top;
}

/* what argument a is: a string, &name of data, name of a function, its
 * place; the value read at t: the name alone, name[…] when indexed */
static void arg_text(const DisView *v, const CallArg *a, char *out, size_t sz) {
    char nm[160];
    if (!a->mem && da_string_at(&v->d, a->t, nm, sizeof nm)) { snprintf(out, sz, "%s", nm); return; }
    if (!da_name_for(&v->d, a->t, nm, sizeof nm)) ref_place(v, a->t, nm, sizeof nm);
    snprintf(out, sz, "%s%s%s", !a->mem && !elf_va_code(&v->d.elf, a->t) ? "&" : "", nm, a->idx ? "[…]" : "");
}

/* "(a, ?, c)": the arguments of the call on line i, "" when none is known */
static void call_args_text(const DisView *v, size_t i, char *out, size_t sz) {
    CallArg arg[CALL_ARGS];
    int n = call_args(v, i, arg);
    size_t o = 0;
    out[0] = '\0';
    for (int k = 0; k < n && o + 2 < sz; k++) {
        char a[180] = "?";
        if (arg[k].t) arg_text(v, &arg[k], a, sizeof a);
        o += (size_t)snprintf(out + o, sz - o, "%s%s", k ? ", " : "(", a);
    }
    if (n && o + 1 < sz) snprintf(out + o, sz - o, ")");
}

/* The places line i leads to, for Enter / a click: the address of the
 * line (branch target, operand), then for a call each argument that is
 * an address. t[k] and a label lab[k] for each; returns how many. */
static int line_targets(const DisView *v, size_t i, uint64_t *t, char (*lab)[160], int max) {
    if (i >= v->ndl || !v->dl[i].len || max < 1) return 0;
    const DisLine *l = &v->dl[i];
    int n = 0;
    uint64_t a;
    char nm[160];
    if (line_ref(l, &a) || (v->dref && (a = v->dref[i])) ||
        (v->d.elf.fmt == ELF_FMT_PE && v->d.elf.bits == 32 && abs_ref(l, &a))) {
        if (!da_string_at(&v->d, a, nm, sizeof nm) && !da_name_for(&v->d, a, nm, sizeof nm)) ref_place(v, a, nm, sizeof nm);
        snprintf(lab[n], sizeof lab[n], "%.110s  ·  %s 0x%llx", nm, elf_va_code(&v->d.elf, a) ? "code" : "data",
                 (unsigned long long)a);
        t[n++] = a;
    }
    if (strncmp(mnem_base(l->mnem), "call", 4)) return n;
    CallArg arg[CALL_ARGS];
    int na = call_args(v, i, arg);
    for (int k = 0; k < na && n < max; k++) {
        if (!arg[k].t) continue;
        bool dup = false;
        for (int j = 0; j < n; j++) dup |= t[j] == arg[k].t;
        if (dup) continue;
        arg_text(v, &arg[k], nm, sizeof nm);
        snprintf(lab[n], sizeof lab[n], "argument %d: %.100s  ·  %s 0x%llx", k + 1, nm,
                 elf_va_code(&v->d.elf, arg[k].t) ? "code" : "data", (unsigned long long)arg[k].t);
        t[n++] = arg[k].t;
    }
    return n;
}

/* opens section si on the dump screen (its rows built once) */
static bool data_open(DisView *v, long si) {
    if (si < 0 || (size_t)si >= v->nds) { list_msg(v, COLOR_PAIR_KEYWORD, "no section selected"); return false; }
    const DataSec *s = &v->ds[si];
    if (s->bad) {
        list_msg(v, COLOR_PAIR_KEYWORD, "%.60s: its bytes lie outside the file", s->name);
        return false;
    }
    if (si != v->xsec || !v->xi) {
        if (!data_build(v, (size_t)si)) {
            free(v->xi);
            v->xi = NULL;
            v->nxi = 0;
            v->xsec = -1;
            list_msg(v, COLOR_PAIR_KEYWORD, "%.60s: out of memory", s->name);
            return false;
        }
        v->xsec = si;
        v->xsel = v->xtop = 0;
        v->xsymw = 0;
        for (size_t i = 0; i < v->nxi; i++) {
            const ElfSymbol *sy = elf_symbol_at(&v->d.elf, v->xi[i].addr);
            int n = sy && sy->name ? (int)strlen(sy->name) : 0;
            if (n > v->xsymw) v->xsymw = n > 32 ? 32 : n;
        }
        if (v->xsymw && v->xsymw < 6) v->xsymw = 6;      /* "SYMBOL" */
    }
    v->dssel = (size_t)si;
    v->screen = SCR_DUMP;
    return true;
}

/* ─── Links and history ────────────────────────────────────────── */

/* the place shown now, to come back to */
static void hist_push(DisView *v) {
    DisHist h = { v->screen, -1, 0, 0 };
    switch (v->screen) {
        case SCR_FUNCS:  h.sel = v->sel;   h.top = v->top;                     break;
        case SCR_DISASM: h.obj = v->dfn;   h.sel = v->dsel;  h.top = v->dtop;  break;
        case SCR_DATA:   h.sel = v->dssel; h.top = v->dstop;                   break;
        case SCR_DUMP:   h.obj = v->xsec;  h.sel = v->xsel;  h.top = v->xtop;  break;
        default:         h.top = (size_t)(v->scroll > 0 ? v->scroll : 0);      break;
    }
    if (v->nhist == DIS_HIST) {
        memmove(v->hist, v->hist + 1, (DIS_HIST - 1) * sizeof *v->hist);
        v->nhist--;
    }
    v->hist[v->nhist++] = h;
}

static void hist_back(DisView *v) {
    if (!v->nhist) { list_msg(v, COLOR_PAIR_NUMBER, "nothing to go back to"); return; }
    DisHist h = v->hist[--v->nhist];
    switch (h.screen) {
        case SCR_DISASM:
            if (!disasm_open(v, h.obj)) return;
            v->dsel = h.sel; v->dtop = h.top;
            break;
        case SCR_DUMP:
            if (!data_open(v, h.obj)) return;
            v->xsel = h.sel; v->xtop = h.top;
            break;
        case SCR_FUNCS: v->sel = h.sel;   v->top = h.top;   v->screen = h.screen; break;
        case SCR_DATA:  v->dssel = h.sel; v->dstop = h.top; v->screen = h.screen; break;
        default:        v->scroll = (int)h.top;             v->screen = h.screen; break;
    }
}

/* first rows above the selection when a link lands */
static size_t land_top(size_t sel) { return sel > 4 ? sel - 4 : 0; }

/* Shows address a: in code, the disassembly of the function holding it
 * on the line of a; in a data section, its row in the dump. The place
 * left goes on the history. false + a message when a is neither. */
static bool follow(DisView *v, uint64_t a) {
    const Disasm  *d  = &v->d;
    const ElfFile *ef = &d->elf;
    if (elf_va_code(ef, a)) {
        long f = da_func_containing(d, a);
        if (f < 0) {
            list_msg(v, COLOR_PAIR_KEYWORD, "0x%llx: code in no function found", (unsigned long long)a);
            return false;
        }
        int back = v->screen;
        hist_push(v);
        if (!disasm_open(v, f)) { v->nhist--; v->screen = back; return false; }
        long p = vis_pos(v, f);
        if (p >= 0) v->sel = (size_t)p;
        size_t best = SIZE_MAX;
        for (size_t i = 0; i < v->ndl; i++) {
            const DisLine *l = &v->dl[i];
            if (!l->len) continue;
            if (l->addr == a) { best = i; break; }
            if (best == SIZE_MAX && a > l->addr && a - l->addr < l->len) best = i;
        }
        const char *fn = d->fn[f].name ? d->fn[f].name : "?";
        if (best == SIZE_MAX) {
            v->dsel = v->dtop = 0;
            list_msg(v, COLOR_PAIR_NUMBER, "0x%llx: in %.80s, outside the lines shown", (unsigned long long)a, fn);
        } else {
            v->dsel = best;
            v->dtop = land_top(best);
            if (v->dl[best].addr != a)
                list_msg(v, COLOR_PAIR_NUMBER, "0x%llx: inside the instruction at 0x%llx",
                         (unsigned long long)a, (unsigned long long)v->dl[best].addr);
        }
        return true;
    }
    long si = data_sec_at(v, a);
    if (si < 0) {
        list_msg(v, COLOR_PAIR_KEYWORD, "0x%llx: not in a data section of the file", (unsigned long long)a);
        return false;
    }
    int back = v->screen;
    hist_push(v);
    if (!data_open(v, si)) { v->nhist--; v->screen = back; return false; }
    uint64_t shown = v->nxi ? v->xi[v->nxi - 1].addr + v->xi[v->nxi - 1].len : v->ds[si].addr;
    if (a >= shown) {
        list_msg(v, COLOR_PAIR_NUMBER, "0x%llx: past the part of %.60s shown", (unsigned long long)a, v->ds[si].name);
        v->xsel = v->xtop = 0;
        return true;
    }
    v->xsel = item_at(v, a);
    v->xtop = land_top(v->xsel);
    list_msg(v, COLOR_PAIR_STRING, "0x%llx: %.60s+0x%llx", (unsigned long long)a, v->ds[si].name,
             (unsigned long long)(a - v->ds[si].addr));
    return true;
}

/* ─── Debugger (dbg.c) ─────────────────────────────────────────── */

static int list_rows(int h);

/* dbg.c has one debuggee and one set of breakpoints: they belong to the
 * file g_dbg_file (path of the view that set them). g_dbg_gen counts the
 * stops / exits noticed; each view shows the latest one when drawn
 * (DisView.dbg_seen). g_regs: registers at the last stop, g_prev at the
 * one before (changed values are highlighted). */
static char     g_dbg_file[4096];
static unsigned g_dbg_gen;
static DbgRegs  g_regs, g_prev;
static bool     g_regs_ok, g_prev_ok;

/* Console of the debuggee (dbg_console_read): its output as plain text,
 * lines ended by '\n' ("\r\n" of the pty folded, a lone '\r' rewrites
 * the line, escape sequences and other control bytes dropped). Only the
 * end is kept (CON_MAX). Emptied at each launch. */
#define CON_MAX (64u << 10)
static char     g_con[CON_MAX];
static size_t   g_ncon;
static int      g_con_esc;         /* 0, 1: after ESC, 2: in CSI, 3: in OSC */
static bool     g_con_cr;          /* a '\r' not followed by '\n' yet       */

static void con_clear(void) { g_ncon = 0; g_con_esc = 0; g_con_cr = false; }

static void con_put(char c) {
    if (g_ncon == CON_MAX) {                         /* drop the older half, at a line end */
        char *nl = memchr(g_con + CON_MAX / 2, '\n', CON_MAX / 2);
        size_t cut = nl ? (size_t)(nl - g_con) + 1 : CON_MAX / 2;
        memmove(g_con, g_con + cut, CON_MAX - cut);
        g_ncon -= cut;
    }
    g_con[g_ncon++] = c;
}

/* start of the last line */
static size_t con_bol(void) {
    size_t i = g_ncon;
    while (i && g_con[i - 1] != '\n') i--;
    return i;
}

static void con_feed(const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)b[i];
        if (g_con_esc == 1) { g_con_esc = c == '[' ? 2 : c == ']' ? 3 : 0; continue; }
        if (g_con_esc == 2) { if (c >= 0x40 && c <= 0x7e) g_con_esc = 0; continue; }
        if (g_con_esc == 3) { if (c == 7) g_con_esc = 0; else if (c == 27) g_con_esc = 1; continue; }
        if (c == 27) { g_con_esc = 1; continue; }
        if (c == '\r') { g_con_cr = true; continue; }
        if (c == '\n') { g_con_cr = false; con_put('\n'); continue; }
        if (g_con_cr) { g_ncon = con_bol(); g_con_cr = false; }     /* "\r" alone: the line again */
        if (c == '\b') {
            size_t bol = con_bol();
            while (g_ncon > bol && ((unsigned char)g_con[g_ncon - 1] & 0xc0) == 0x80) g_ncon--;
            if (g_ncon > bol) g_ncon--;
            continue;
        }
        if (c == '\t') { do con_put(' '); while ((g_ncon - con_bol()) % 8); continue; }
        if (c < 0x20 || c == 0x7f) continue;
        con_put((char)c);
    }
}

/* takes what the debuggee wrote; true when something came */
static bool con_drain(void) {
    char b[4096];
    bool got = false;
    long n;
    for (int k = 0; k < 64 && (n = dbg_console_read(b, sizeof b)) > 0; k++) {
        con_feed(b, (size_t)n);
        got = true;
    }
    return got;
}

static bool dbg_mine(const DisView *v) { return g_dbg_file[0] && !strcmp(g_dbg_file, v->path); }

/* Input breakpoints: at the first launch of a file, one on every call to
 * an input function of the C library (scanf, fgets, getchar, read...) in
 * its own code, so the program stops before it waits for its input.
 * They are ordinary breakpoints (b removes one for good); g_auto keeps
 * their addresses to mark them. */
#define AUTO_MAX 64
static uint64_t g_auto[AUTO_MAX];
static int      g_nauto;
static bool     g_auto_done;               /* set for g_dbg_file already */

/* F6 / F7 with no process: a breakpoint of ours on main, taken out at
 * the first stop (the user's own one on main is left alone) */
static bool     g_main_tmp;
static uint64_t g_main_addr;

static void auto_reset(void) { g_nauto = 0; g_auto_done = false; g_main_tmp = false; }

static int auto_index(uint64_t a) {
    for (int i = 0; i < g_nauto; i++) if (g_auto[i] == a) return i;
    return -1;
}

static void auto_drop(uint64_t a) {
    int i = auto_index(a);
    if (i >= 0) g_auto[i] = g_auto[--g_nauto];
}

/* plain name of a C library input function as a call target shows it
 * ("__isoc23_scanf@plt", "__fgets_chk", "getchar"), NULL: not one */
static const char *input_fn(const char *nm) {
    static const char *const t[] = {
        "scanf", "vscanf", "fscanf", "vfscanf", "wscanf", "fwscanf",
        "getchar", "getchar_unlocked", "getc", "getc_unlocked", "_IO_getc", "fgetc", "fgetc_unlocked",
        "fgets", "fgets_unlocked", "gets", "getline", "getdelim", "read", "fread", "fread_unlocked",
        "getwchar", "getwc", "fgetwc", "fgetws", "readline",
        /* Windows: kernel32, the UCRT / msvcrt, MinGW */
        "ReadFile", "ReadConsoleA", "ReadConsoleW", "ReadConsoleInputA", "ReadConsoleInputW",
        "getch", "getche", "getwch", "getwche", "cgets", "cgetws", "gets_s", "getws",
        "scanf_s", "fscanf_s", "wscanf_s", "stdio_common_vfscanf", "stdio_common_vfwscanf", "fgetchar" };
    const char *bang = strchr(nm, '!');             /* PE IAT slot: "dll!function" */
    if (bang) nm = bang + 1;
    char b[64];
    size_t n = strcspn(nm, "@");
    if (n >= sizeof b) return NULL;
    memcpy(b, nm, n);
    b[n] = '\0';
    const char *s = b;
    if (!strncmp(s, "__imp_", 6)) s += 6;           /* PE: call through the IAT slot */
    if (!strncmp(s, "__isoc99_", 9) || !strncmp(s, "__isoc23_", 9)) s += 9;
    else if (!strncmp(s, "__mingw_", 8)) s += 8;    /* __mingw_scanf, __mingw_vfscanf */
    else if (!strncmp(s, "__", 2)) s += 2;          /* __fgets_chk, __getdelim, __stdio_common_vfscanf */
    for (int pass = 0; pass < 2; pass++) {          /* then _getch, _read, _fgetchar (Windows) */
        if (pass && (s[0] != '_' || s[1] == '_')) break;
        if (pass) s++;
        size_t m = strlen(s);
        if (m > 4 && !strcmp(s + m - 4, "_chk")) m -= 4;
        for (size_t k = 0; k < sizeof t / sizeof t[0]; k++)
            if (strlen(t[k]) == m && !strncmp(t[k], s, m)) return t[k];
    }
    return NULL;
}

/* the input function called by the instruction at a, NULL: none */
static const char *input_call_at(const DisView *v, uint64_t a) {
    const Disasm *d = &v->d;
    long i = d->nins ? da_insn_at(d, a) : -1;
    if (i < 0 || !(d->ins[i].flags & DI_CALL) || !d->ins[i].target) return NULL;
    char nb[256];
    const char *nm = da_name_for(d, d->ins[i].target, nb, sizeof nb);
    return nm ? input_fn(nm) : NULL;
}

/* sets the input breakpoints of v's file (the debuggee is stopped at its
 * exec); the number set */
static int auto_add(const DisView *v) {
    const Disasm *d = &v->d;
    char err[200];
    g_auto_done = true;
    for (size_t i = 0; i < d->nins && g_nauto < AUTO_MAX; i++) {
        const DisInsn *in = &d->ins[i];
        if (!(in->flags & DI_CALL) || !in->target || in->func == DA_NOFUNC) continue;
        const DisFunc *f = &d->fn[in->func];
        /* the program's code: not a stub, nor the start files / libc
         * internals of a static binary (_start, _IO_*, __libc_*) */
        if (f->kind == FN_PLT || !f->name || f->name[0] == '_' || input_fn(f->name)) continue;
        if (!input_call_at(v, in->addr) || dbg_bp_has(in->addr)) continue;
        if (dbg_bp_add(in->addr, err, sizeof err)) g_auto[g_nauto++] = in->addr;
    }
    return g_nauto;
}

/* The debuggee waits for its input: running, blocked in read() on its
 * console. g_wait_gen counts the waits (each view enters the console
 * once per wait). */
static bool     g_wait;
static unsigned g_wait_gen;
/* resumed onto a call to an input function (F7 over it, F5 from its
 * input breakpoint): where /proc/pid/syscall is missing (Windows), the
 * program is taken as waiting for its input until its next stop */
static bool     g_input_run;

static bool dbg_reading(void) {
#ifdef __linux__
    int pid = dbg_pid();
    if (dbg_state() != DBG_RUNNING || pid <= 0) return false;
    char p[64], b[256];
    snprintf(p, sizeof p, "/proc/%d/syscall", pid);
    FILE *f = fopen(p, "r");
    if (!f) return false;
    long nr = -1;
    unsigned long long fd = 0;
    bool in = fgets(b, sizeof b, f) && sscanf(b, "%ld %llx", &nr, &fd) == 2;
    fclose(f);
    bool rd = dbg_bits() == 32 ? nr == 3 || nr == 180 || nr == 145     /* i386: read, pread64, readv */
                               : nr == 0 || nr == 17 || nr == 19;     /* x86-64 */
    if (!in || !rd || fd > 1u << 20) return false;
    snprintf(p, sizeof p, "/proc/%d/fd/%llu", pid, fd);
    ssize_t n = readlink(p, b, sizeof b - 1);
    return n > 9 && !strncmp(b, "/dev/pts/", 9);
#else
    /* no console (dbg_console_read -1: dbg_win.c, whose program has its
     * own console window): nothing to type into here */
    return g_input_run && dbg_state() == DBG_RUNNING && dbg_console_read(NULL, 0) >= 0;
#endif
}

/* g_wait brought up to date; true when it changed */
static bool wait_check(void) {
    bool w = dbg_reading();
    if (w == g_wait) return false;
    g_wait = w;
    if (w) g_wait_gen++;
    return true;
}

/* F7 over a call that has not come back yet (dbg_run_to running): its
 * target, to go on with after b pauses the program */
static bool     g_runto_on;
static uint64_t g_runto;

static bool dbg_alive(void) {
    DbgState s = dbg_state();
    return s == DBG_STOPPED || s == DBG_RUNNING;
}

/* a stop, exit or launch happened: registers taken once here, every
 * view on the file jumps to it at its next draw */
static void dbg_changed(void) {
    g_dbg_gen++;
    g_runto_on = false;
    if (dbg_state() != DBG_RUNNING) g_input_run = false;
    if (g_main_tmp && dbg_state() != DBG_RUNNING) {
        char e[200];
        if (dbg_bp_remove(g_main_addr, e, sizeof e)) g_main_tmp = false;
    }
    if (g_regs_ok) { g_prev = g_regs; g_prev_ok = true; }
    g_regs_ok = dbg_state() == DBG_STOPPED && dbg_get_regs(&g_regs);
}

/* the debugger for v's file: free (no process for another file: its
 * breakpoints are dropped) or already v's. false + message otherwise. */
static bool dbg_claim(DisView *v) {
    if (dbg_mine(v)) return true;
    if (g_dbg_file[0] && dbg_alive()) {
        list_msg(v, COLOR_PAIR_KEYWORD, "the debugger is busy with %.100s (pid %d)", base_name(g_dbg_file), dbg_pid());
        return false;
    }
    if (dbg_state() != DBG_NONE) dbg_kill();
    dbg_bp_clear();
    auto_reset();
    g_regs_ok = g_prev_ok = false;
    snprintf(g_dbg_file, sizeof g_dbg_file, "%s", v->path);
    dbg_bp_image(v->path);
    v->dbg_seen = g_dbg_gen;                         /* the stops of the other file are not ours */
    return true;
}

/* rip of the stopped debuggee as a file address; false when it is not
 * stopped or rip is outside the program (*rt: rip in the process) */
static bool dbg_rip(uint64_t *fa, uint64_t *rt) {
    if (dbg_state() != DBG_STOPPED || !g_regs_ok) return false;
    if (rt) *rt = g_regs.rip;
    return dbg_to_file(g_regs.rip, fa);
}

/* line of address a in the disassembly shown (an instruction covering
 * it), SIZE_MAX when none */
static size_t dl_line_of(const DisView *v, uint64_t a) {
    for (size_t i = 0; i < v->ndl; i++)
        if (v->dl[i].len && a >= v->dl[i].addr && a - v->dl[i].addr < v->dl[i].len) return i;
    return SIZE_MAX;
}

/* name of the mapping / module of the debuggee holding address a
 * ("libc.so.6", "KERNEL32.DLL"), see dbg_map_name */
static bool map_name(int pid, uint64_t a, char *out, size_t sz) {
    (void)pid;
    char nm[4096];
    if (!dbg_map_name(a, nm, sizeof nm)) return false;
    snprintf(out, sz, "%.*s", (int)(sz ? sz - 1 : 0), nm[0] ? base_name(nm) : "anonymous memory");
    return true;
}

static const char *ip_name(void) { return dbg_bits() == 32 ? "eip" : "rip"; }

/* ─── Stack arguments in the panel: al, [esp+4], [esp+8] ───────── */

/* a C string of the debuggee at rt, quoted and escaped like da_string_at
 * ("..." when cut); false: under 2 printable ASCII characters */
static bool live_string(uint64_t rt, char *out, size_t osz) {
    uint8_t b[48];
    size_t n = sizeof b, page = 4096 - (size_t)(rt & 4095);
    if (n > page) n = page;
    if (osz < 8 || !dbg_read_mem(rt, b, n)) return false;
    size_t k = 0, o = 0;
    out[o++] = '"';
    for (; k < n && b[k]; k++) {
        uint8_t c = b[k];
        const char *e = c == '\n' ? "\\n" : c == '\t' ? "\\t" : c == '\r' ? "\\r" : c == '"' ? "\\\"" : c == '\\' ? "\\\\" : NULL;
        if (!e && (c < 0x20 || c > 0x7e)) return false;
        if (o + (e ? 2 : 1) + 5 > osz) break;
        if (e) { out[o++] = e[0]; out[o++] = e[1]; } else out[o++] = (char)c;
    }
    if (k < 2) return false;
    if (k == n || b[k]) { memcpy(out + o, "...", 3); o += 3; }
    out[o++] = '"';
    out[o] = '\0';
    return true;
}

/* slot k (0, 1) of the stack above the return address: [esp+4], [esp+8]
 * in 32-bit, [rsp+8], [rsp+16] in 64-bit. *lbl its name; false: not
 * stopped or not readable */
static bool stack_arg(int k, uint64_t *val, char *lbl, size_t lsz) {
    bool w32 = dbg_bits() == 32;
    unsigned slot = w32 ? 4 : 8;
    if (lbl) snprintf(lbl, lsz, "[%s+%u]", w32 ? "esp" : "rsp", slot * (unsigned)(k + 1));
    if (dbg_state() != DBG_STOPPED || !g_regs_ok) return false;
    uint8_t b[8];
    if (!dbg_read_mem(g_regs.rsp + slot * (uint64_t)(k + 1), b, slot)) return false;
    *val = 0;
    for (unsigned i = 0; i < slot; i++) *val |= (uint64_t)b[i] << (8 * i);
    return true;
}

/* what the value rt of a stack slot is, in a few words: the name of the
 * code it points to, the string there (live memory), the place in the
 * file, the stack (esp+X) and the slot found there, a mapping, a number */
static void ptr_note(const DisView *v, uint64_t rt, char *out, size_t sz) {
    bool w32 = dbg_bits() == 32;
    uint64_t fa, sp = g_regs.rsp;
    char nb[200];
    const char *nm;
    out[0] = '\0';
    bool in_file = dbg_to_file(rt, &fa);
    if (in_file && elf_va_code(&v->d.elf, fa)) {
        if ((nm = da_name_for(&v->d, fa, nb, sizeof nb))) snprintf(out, sz, "%s", nm);
        else ref_place(v, fa, out, sz);
        return;
    }
    if (live_string(rt, out, sz)) return;
    if (in_file) {
        if ((nm = da_name_for(&v->d, fa, nb, sizeof nb))) snprintf(out, sz, "%s", nm);
        else ref_place(v, fa, out, sz);
        return;
    }
    long long sv = w32 ? (long long)(int32_t)rt : (long long)rt;
    if (sv > -0x10000 && sv < 0x10000) { snprintf(out, sz, "= %lld", sv); return; }
    uint8_t b[8];
    unsigned slot = w32 ? 4 : 8;
    if (!dbg_read_mem(rt, b, slot)) {
        if (sv > -1000000000LL && sv < 1000000000LL) snprintf(out, sz, "= %lld, not an address", sv);
        else snprintf(out, sz, "not an address");
        return;
    }
    uint64_t at = 0;
    for (unsigned i = 0; i < slot; i++) at |= (uint64_t)b[i] << (8 * i);
    size_t u;
    if (rt >= sp - 0x10000 && rt < sp + 0x100000)
        u = (size_t)snprintf(out, sz, "stack %s%c0x%llx", w32 ? "esp" : "rsp", rt >= sp ? '+' : '-',
                             (unsigned long long)(rt >= sp ? rt - sp : sp - rt));
    else if (map_name(dbg_pid(), rt, nb, sizeof nb)) u = (size_t)snprintf(out, sz, "in %.100s", nb);
    else u = (size_t)snprintf(out, sz, "not in the file");
    if (u < sz) snprintf(out + u, sz - u, " → 0x%0*llx", w32 ? 8 : 16, (unsigned long long)at);
}

/* 1 / 2, a click on [esp+4] / [esp+8]: to what the slot points to in the
 * file (code: its disassembly, data: its row in the dump); elsewhere
 * (stack, heap, a library) its bytes shown / hidden under it */
static void value_go(DisView *v, int k, const char *lbl, uint64_t val);
static void stack_arg_go(DisView *v, int k) {
    char lbl[16];
    uint64_t val;
    if (!dbg_mine(v) || !stack_arg(k, &val, lbl, sizeof lbl)) {
        stack_arg(k, &val, lbl, sizeof lbl);
        list_msg(v, COLOR_PAIR_NUMBER, "%s: %s", lbl, dbg_mine(v) && dbg_state() == DBG_STOPPED
                 ? "not readable" : "only while the program is stopped (F5 / F6 / F7)");
        return;
    }
    value_go(v, k, lbl, val);
}

/* the registers of the panel: 0-9 rip rsp rbp rax rbx rcx rdx rsi rdi
 * rflags, 10-17 r8-r15 (64-bit only); their names in the program's mode */
static const char *reg_name(int i) {
    static const char *const rn[] = { "rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rflags",
                                      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
    static const char *const rn32[] = { "eip", "esp", "ebp", "eax", "ebx", "ecx", "edx", "esi", "edi", "eflags" };
    return dbg_bits() == 32 && i < 10 ? rn32[i] : i >= 0 && i < 18 ? rn[i] : "?";
}

static uint64_t reg_val(const DbgRegs *r, int i) {
    uint64_t c[18] = { r->rip, r->rsp, r->rbp, r->rax, r->rbx, r->rcx, r->rdx, r->rsi, r->rdi, r->rflags,
                       r->r8, r->r9, r->r10, r->r11, r->r12, r->r13, r->r14, r->r15 };
    uint64_t x = i >= 0 && i < 18 ? c[i] : 0;
    return dbg_bits() == 32 ? x & 0xffffffffu : x;
}

/* a click on register i: to what its value points to, as for [esp+4] */
static void reg_go(DisView *v, int i) {
    const char *nm = reg_name(i);
    if (!dbg_mine(v) || dbg_state() != DBG_STOPPED || !g_regs_ok) {
        list_msg(v, COLOR_PAIR_NUMBER, "%s: only while the program is stopped (F5 / F6 / F7)", nm);
        return;
    }
    if (i == 9) { list_msg(v, COLOR_PAIR_NUMBER, "%s: the flags, not an address", nm); return; }
    value_go(v, 2 + i, nm, reg_val(&g_regs, i));
}

/* what a value of the panel points to (slot k: see peek_k): in the file,
 * its code or data; elsewhere, its bytes shown / hidden under it */
static void value_go(DisView *v, int k, const char *lbl, uint64_t val) {
    uint64_t fa;
    if (dbg_to_file(val, &fa) && (elf_va_code(&v->d.elf, fa) || data_sec_at(v, fa) >= 0)) {
        v->peek_on = false;
        follow(v, fa);
        return;
    }
    uint8_t t;
    if (!dbg_read_mem(val, &t, 1)) {
        list_msg(v, COLOR_PAIR_NUMBER, "%s = 0x%llx: not an address of the program", lbl, (unsigned long long)val);
        return;
    }
    if (v->peek_on && v->peek_k == k && v->peek_a == val) { v->peek_on = false; return; }
    v->peek_on = true;
    v->peek_k = k;
    v->peek_a = val;
    if (k < 2)
        list_msg(v, COLOR_PAIR_STRING, "%s = 0x%llx: not in the file, its bytes are under it in the panel (%d again: hide)",
                 lbl, (unsigned long long)val, k + 1);
    else
        list_msg(v, COLOR_PAIR_STRING, "%s = 0x%llx: not in the file, its bytes are under it in the panel (click again: hide)",
                 lbl, (unsigned long long)val);
}

/* Shows the last stop of the debuggee in v, once per stop: the function
 * holding rip on the disassembly screen, its line selected (and brought
 * into view among `rows`), and the reason in the bar. Waits while a
 * filter / address is typed; leaves the console when nothing is typed
 * there (the keys go back to the disassembly). */
static void dbg_show_stop(DisView *v, int rows) {
    char st[160];
    dbg_status(st, sizeof st);
    DbgState s = dbg_state();
    if (s == DBG_RUNNING) { list_msg(v, COLOR_PAIR_STRING, "%s: %s", base_name(v->path), st); return; }
    if (v->in_mode == IN_CONSOLE && !v->in_buf[0])
        v->in_mode = IN_NONE;                        /* a stop: the keys come back to the disassembly */
    v->con_auto = false;
    if (s != DBG_STOPPED) {
        if (v->in_mode == IN_CONSOLE) v->in_mode = IN_NONE;     /* nobody to read it */
        list_msg(v, s == DBG_EXITED && strncmp(st, "exited", 6) ? COLOR_PAIR_KEYWORD : COLOR_PAIR_STRING,
                 "%s: %s", base_name(v->path), st);
        return;
    }
    uint64_t fa, rt = 0;
    if (!dbg_rip(&fa, &rt)) {
        char mp[200];
        if (map_name(dbg_pid(), rt, mp, sizeof mp))
            list_msg(v, COLOR_PAIR_NUMBER, "%s  ·  %s in %.80s, outside the file", st, ip_name(), mp);
        else
            list_msg(v, COLOR_PAIR_NUMBER, "%s  ·  %s outside the file", st, ip_name());
        return;
    }
    char nb[200];
    const char *nm = da_name_for(&v->d, fa, nb, sizeof nb), *in = input_call_at(v, fa);
    if (dbg_stop_reason() == DBG_STOP_BP && in)
        list_msg(v, COLOR_PAIR_NUMBER, "before %s (input) at 0x%llx  ·  F7: run it, then type the input in the console  ·  "
                 "F5: continue  ·  b: no breakpoint here", in, (unsigned long long)fa);
    else {
        DbgBp b;
        if (dbg_stop_reason() == DBG_STOP_BP && dbg_bp_info(dbg_bp_stopped_on(), &b))
            list_msg(v, COLOR_PAIR_STRING, "%s  ·  %.100s 0x%llx  ·  pass %llu%s%s", st, nm ? nm : "file address", (unsigned long long)fa,
                     (unsigned long long)b.hits, b.has_cond ? "  ·  if " : "", b.cond);
        else
            list_msg(v, COLOR_PAIR_STRING, "%s  ·  %.100s 0x%llx", st, nm ? nm : "file address", (unsigned long long)fa);
    }
    long f = da_func_containing(&v->d, fa);
    if (f < 0) return;
    if (!disasm_open(v, f)) return;
    long p = vis_pos(v, f);
    if (p >= 0) v->sel = (size_t)p;
    size_t li = dl_line_of(v, fa);
    if (li == SIZE_MAX) return;
    v->dsel = li;
    size_t r = rows > 0 ? (size_t)rows : 1;
    if (li < v->dtop || li >= v->dtop + r) v->dtop = land_top(li);
}

static void dbg_sync(DisView *v, int rows) {
    if (!dbg_mine(v) || v->dbg_seen == g_dbg_gen || v->in_mode == IN_FILTER || v->in_mode == IN_GOTO || v->in_mode == IN_BREAK ||
        v->in_mode == IN_ARGS) return;
    v->dbg_seen = g_dbg_gen;
    dbg_show_stop(v, rows);
    char news[160];                                  /* could not be placed, overwritten: said over the stop */
    if (dbg_bp_take_news(news, sizeof news)) list_msg(v, COLOR_PAIR_KEYWORD, "%s", news);
}

bool dis_ui_poll(void) {
    bool out = con_drain();                          /* output while it runs */
    if (dbg_state() == DBG_NONE || !dbg_poll()) return wait_check() || out;
    con_drain();                                     /* written just before the stop / exit */
    dbg_changed();
    wait_check();
    return true;
}

/* i (or a click on the panel): the keys go to the console of the program */
static void dbg_key_console(DisView *v) {
    if (!dbg_mine(v) || !dbg_alive()) {
        list_msg(v, COLOR_PAIR_NUMBER, "no process: F5 runs %s, then i types into its console", base_name(v->path));
        return;
    }
    if (dbg_console_read(NULL, 0) < 0) {
        list_msg(v, COLOR_PAIR_NUMBER, "%s has no console here: type its input in its own window", base_name(v->path));
        return;
    }
    v->in_mode = IN_CONSOLE;
    v->in_buf[0] = '\0';
    v->con_auto = false;
}

/* sends s (n bytes) to the console; false + message when it cannot */
static bool con_send(DisView *v, const char *s, size_t n) {
    if (dbg_console_write(s, n) == (long)n) return true;
    list_msg(v, COLOR_PAIR_KEYWORD, dbg_alive() ? "console: input not sent" : "console: the program is not running any more");
    return false;
}

/* The list of breakpoints cannot change while the program runs: it is paused
 * for that (dbg_hold) and let go again the same way (dbg_release). false:
 * nothing to do, the message is given. */
static bool dbg_hold(DisView *v, bool *resume) {
    *resume = false;
    if (dbg_state() != DBG_RUNNING) return true;
    if (!dbg_interrupt()) {
        dbg_changed();                           /* exited meanwhile, or stuck */
        if (dbg_state() == DBG_RUNNING) { list_msg(v, COLOR_PAIR_KEYWORD, "breakpoint: the program does not stop"); v->dbg_seen = g_dbg_gen; }
        return false;
    }
    *resume = dbg_stop_reason() == DBG_STOP_INTERRUPT;   /* else a stop of its own: shown */
    if (!*resume) dbg_changed();
    return true;
}

static bool dbg_release(DisView *v, bool resume) {
    if (!resume) return true;
    bool runto = g_runto_on;
    char e2[200];
    bool go = runto ? dbg_run_to(g_runto, e2, sizeof e2) : dbg_cont(e2, sizeof e2);
    con_drain();
    if (!go || dbg_state() != DBG_RUNNING) dbg_changed();       /* stopped again at once */
    else g_runto_on = runto;
    if (!go) { list_msg(v, COLOR_PAIR_KEYWORD, "breakpoint: cannot resume: %s", e2); v->dbg_seen = g_dbg_gen; }
    return go;
}

/* keeps the message just given over the "running" one of the next draw */
static void dbg_keep_msg(DisView *v) {
    if (v->dbg_seen != g_dbg_gen && dbg_state() == DBG_RUNNING) v->dbg_seen = g_dbg_gen;
}

/* b: breakpoint on the selected line, set or removed */
static void dbg_key_bp(DisView *v) {
    if (v->dsel >= v->ndl || !v->dl[v->dsel].len) { list_msg(v, COLOR_PAIR_NUMBER, "no instruction on this line"); return; }
    if (!dbg_claim(v)) return;
    uint64_t a = v->dl[v->dsel].addr;
    char err[200] = "", nb[200];
    bool resume;
    if (!dbg_hold(v, &resume)) return;
    bool had = dbg_bp_has(a), was_auto = auto_index(a) >= 0;
    bool ok = had ? dbg_bp_remove(a, err, sizeof err) : dbg_bp_add(a, err, sizeof err);
    if (ok && had) auto_drop(a);
    if (!dbg_release(v, resume)) return;
    if (!ok) {
        list_msg(v, COLOR_PAIR_KEYWORD, "breakpoint 0x%llx: %s", (unsigned long long)a, err);
        v->dbg_seen = g_dbg_gen;
        return;
    }
    const char *nm = da_name_for(&v->d, a, nb, sizeof nb);
    int n = dbg_bp_list(NULL, 0);
    list_msg(v, COLOR_PAIR_STRING, "%sbreakpoint %s at 0x%llx%s%.100s  ·  %d breakpoint%s",
             was_auto ? "input " : "", had ? "removed" : "set", (unsigned long long)a, nm ? " " : "", nm ? nm : "",
             n, n == 1 ? "" : "s");
    dbg_keep_msg(v);
}

/* e: the breakpoint of the selected line on / off, h: by debug register or
 * int3 (no breakpoint there: one is set) */
static void dbg_key_bp_flag(DisView *v, int key) {
    if (v->dsel >= v->ndl || !v->dl[v->dsel].len) { list_msg(v, COLOR_PAIR_NUMBER, "no instruction on this line"); return; }
    if (!dbg_claim(v)) return;
    uint64_t a = v->dl[v->dsel].addr;
    if (key == 'e' && !dbg_bp_has(a)) { list_msg(v, COLOR_PAIR_NUMBER, "no breakpoint on this line (b sets one)"); return; }
    char err[200] = "";
    bool resume;
    if (!dbg_hold(v, &resume)) return;
    bool isnew = !dbg_bp_has(a), ok = isnew ? dbg_bp_add(a, err, sizeof err) : true, on = false;
    int i = dbg_bp_index(a);
    DbgBp b;
    if (ok && dbg_bp_info(i, &b)) {
        on = key == 'e' ? !b.enabled : !b.hw;
        ok = key == 'e' ? dbg_bp_enable_i(i, on, err, sizeof err) : dbg_bp_hw_i(i, on, err, sizeof err);
        if (!ok && isnew) { char e2[64]; dbg_bp_remove_i(i, e2, sizeof e2); }
    }
    if (!dbg_release(v, resume)) return;
    if (!ok) {
        list_msg(v, COLOR_PAIR_KEYWORD, "breakpoint 0x%llx: %s", (unsigned long long)a, err);
        v->dbg_seen = g_dbg_gen;
        return;
    }
    list_msg(v, COLOR_PAIR_STRING, "breakpoint 0x%llx %s", (unsigned long long)a,
             key == 'e' ? (on ? "enabled" : "disabled") : (on ? "by debug register (no byte written)" : "by int3"));
    dbg_keep_msg(v);
}

/* L: the panel lists the breakpoints instead of the registers */
static void dbg_key_bp_panel(DisView *v) {
    if (!dbg_claim(v)) return;
    v->bp_panel = !v->bp_panel;
}

/* n: the next breakpoint of the program after the selected line (the first
 * one after the last) */
static void dbg_key_bp_next(DisView *v) {
    int n = dbg_mine(v) ? dbg_bp_list(NULL, 0) : 0;
    uint64_t cur = v->dsel < v->ndl ? v->dl[v->dsel].addr : 0, first = 0, next = 0;
    bool have_first = false, have_next = false;
    for (int i = 0; i < n; i++) {
        DbgBp b;
        if (!dbg_bp_info(i, &b) || !b.main) continue;
        if (!have_first) { first = b.va; have_first = true; }
        if (b.va > cur && !have_next) { next = b.va; have_next = true; }
    }
    if (!have_first) { list_msg(v, COLOR_PAIR_NUMBER, "no breakpoint in this file"); return; }
    follow(v, have_next ? next : first);
}

/* Where a breakpoint command points: an address of the file, or an offset
 * in another module. */
typedef struct { bool module; char mod[DBG_MOD_MAX]; uint64_t addr; } BpWhere;

/* "." (selected line), "main", "main+0x10", "sub_1149", "0x1149", "libc.so.6+0x2a1c0".
 * A name of the analysis wins over the same letters read as hex. */
static bool bp_where(const DisView *v, const char *text, BpWhere *w, char *err, size_t esz) {
    const Disasm *d = &v->d;
    const ElfFile *ef = &d->elf;
    char buf[128];
    snprintf(buf, sizeof buf, "%s", text);
    size_t n = strlen(buf);
    while (n && (buf[n - 1] == ' ' || buf[n - 1] == '\t')) buf[--n] = '\0';
    char *s = buf;
    while (*s == ' ' || *s == '\t') s++;
    if (!*s) { snprintf(err, esz, "expected a name or an address"); return false; }
    w->module = false;
    w->mod[0] = '\0';
    if (!strcmp(s, ".")) {
        if (v->dsel >= v->ndl || !v->dl[v->dsel].len) { snprintf(err, esz, "no instruction on this line"); return false; }
        w->addr = v->dl[v->dsel].addr;
        return true;
    }
    uint64_t off = 0, a = 0;
    bool has_off = false;
    long f = da_func_named(d, s);                    /* a name may hold a '+' */
    char *plus = f < 0 ? strrchr(s, '+') : NULL;
    if (plus) {
        *plus = '\0';
        if (!*s || !parse_hex(plus + 1, &off)) { *plus = '+'; snprintf(err, esz, "\"%.80s\": expected name+0xOFFSET", s); return false; }
        has_off = true;
        f = da_func_named(d, s);
    }
    if (f >= 0) {
        a = d->fn[f].addr + off;
        if (a < off) { snprintf(err, esz, "%.80s+0x%llx: past the end of the address space", s, (unsigned long long)off); return false; }
    } else if (!has_off && parse_hex(s, &a)) {
        /* an address */
    } else if (has_off) {
        if (strcspn(s, " \t/\\") != strlen(s)) { snprintf(err, esz, "\"%.80s\": a module is a file name, without a path", s); return false; }
        if (strlen(s) >= DBG_MOD_MAX) { snprintf(err, esz, "module name too long"); return false; }
        if (strcmp(s, base_name(v->path))) {
            if (!strchr(s, '.')) { snprintf(err, esz, "no function nor module named \"%.80s\"", s); return false; }
            w->module = true;
            snprintf(w->mod, sizeof w->mod, "%.*s", DBG_MOD_MAX - 1, s);
            w->addr = off;
            return true;
        }
        a = dbg_link_base() + off;                   /* the program by its name */
    } else {
        snprintf(err, esz, "no function named \"%.80s\", and not a hex address", s);
        return false;
    }
    if (!elf_va_exec(ef, a)) { snprintf(err, esz, "0x%llx is not code of %.60s", (unsigned long long)a, base_name(v->path)); return false; }
    long i = d->nins ? da_insn_floor(d, a) : -1;
    if (i >= 0 && a > d->ins[i].addr && a - d->ins[i].addr < d->ins[i].len) {
        snprintf(err, esz, "0x%llx is inside the instruction at 0x%llx", (unsigned long long)a, (unsigned long long)d->ins[i].addr);
        return false;
    }
    w->addr = a;
    return true;
}

static int bp_where_index(const BpWhere *w) {
    return w->module ? dbg_bp_index_module(w->mod, w->addr) : dbg_bp_index(w->addr);
}

static const char *bp_where_text(const BpWhere *w, char *out, size_t sz) {
    if (w->module) snprintf(out, sz, "%s+0x%llx", w->mod, (unsigned long long)w->addr);
    else snprintf(out, sz, "0x%llx", (unsigned long long)w->addr);
    return out;
}

/* One line typed after B:
 *   WHERE [hw] [if COND]   set (or change the one already there)
 *   -WHERE, -*             remove it, remove them all
 *   !WHERE                 on / off
 * false + err when nothing was done. *msg: what was done. */
static bool bp_apply(DisView *v, const char *line, char *msg, size_t msz, char *err, size_t esz) {
    char buf[sizeof v->in_buf];
    snprintf(buf, sizeof buf, "%s", line);
    char *s = buf;
    while (*s == ' ' || *s == '\t') s++;
    char what[128];
    BpWhere w;
    if (*s == '-' && !strcmp(s + 1 + strspn(s + 1, " \t"), "*")) {
        int n = dbg_bp_list(NULL, 0);
        dbg_bp_clear();
        g_nauto = 0;
        g_main_tmp = false;
        snprintf(msg, msz, "%d breakpoint%s removed", n, n == 1 ? "" : "s");
        return true;
    }
    if (*s == '-' || *s == '!') {
        if (!bp_where(v, s + 1, &w, err, esz)) return false;
        int i = bp_where_index(&w);
        bp_where_text(&w, what, sizeof what);
        if (i < 0) { snprintf(err, esz, "no breakpoint at %s", what); return false; }
        if (*s == '-') {
            if (!dbg_bp_remove_i(i, err, esz)) return false;
            if (!w.module) auto_drop(w.addr);
            snprintf(msg, msz, "breakpoint removed at %s", what);
            return true;
        }
        DbgBp b;
        if (!dbg_bp_info(i, &b) || !dbg_bp_enable_i(i, !b.enabled, err, esz)) return false;
        snprintf(msg, msz, "breakpoint %s at %s", b.enabled ? "disabled" : "enabled", what);
        return true;
    }
    /* set: [if COND], then a last word hw */
    const char *cond = NULL;
    for (char *p = s; (p = strstr(p, " if ")) != NULL; p++) { *p = '\0'; cond = p + 4; break; }
    if (!cond && !strncmp(s, "if ", 3)) { snprintf(err, esz, "expected a name or an address before if"); return false; }
    bool hw = false;
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t')) s[--n] = '\0';
    if (n > 3 && !strcmp(s + n - 3, " hw")) { hw = true; s[n - 3] = '\0'; }
    if (!bp_where(v, s, &w, err, esz)) return false;
    bp_where_text(&w, what, sizeof what);
    int i = bp_where_index(&w);
    bool isnew = i < 0;
    if (isnew) {
        bool ok = w.module ? dbg_bp_add_module(w.mod, w.addr, err, esz) : dbg_bp_add(w.addr, err, esz);
        if (!ok) return false;
        i = bp_where_index(&w);
    } else if (!hw && !cond) {
        snprintf(msg, msz, "already a breakpoint at %s", what);
        return true;
    }
    if ((cond && !dbg_bp_cond_i(i, cond, err, esz)) || (hw && !dbg_bp_hw_i(i, true, err, esz))) {
        char e2[64];
        if (isnew) dbg_bp_remove_i(i, e2, sizeof e2);
        return false;
    }
    DbgBp b;
    dbg_bp_info(i, &b);
    snprintf(msg, msz, "breakpoint %s at %s%s%s%s", isnew ? "set" : "changed", what, b.hw ? "  ·  debug register" : "",
             b.has_cond ? "  ·  if " : "", b.cond);
    return true;
}

static void dbg_bp_command(DisView *v, const char *line) {
    if (!line[strspn(line, " \t")]) return;
    if (!dbg_claim(v)) return;
    char err[240] = "", msg[240] = "";
    bool resume;
    if (!dbg_hold(v, &resume)) return;
    bool ok = bp_apply(v, line, msg, sizeof msg, err, sizeof err);
    if (!dbg_release(v, resume)) return;
    if (!ok) {
        list_msg(v, COLOR_PAIR_KEYWORD, "breakpoint: %s", err);
        v->dbg_seen = g_dbg_gen;
        return;
    }
    int n = dbg_bp_list(NULL, 0);
    list_msg(v, COLOR_PAIR_STRING, "%s  ·  %d breakpoint%s", msg, n, n == 1 ? "" : "s");
    dbg_keep_msg(v);
}

/* p: pauses the running program where it is */
static void dbg_key_pause(DisView *v) {
    if (!dbg_mine(v) || dbg_state() != DBG_RUNNING) {
        list_msg(v, COLOR_PAIR_NUMBER, "p pauses the program while it runs (F5 runs it)");
        return;
    }
    bool ok = dbg_interrupt();
    con_drain();
    dbg_changed();
    wait_check();
    if (!ok && dbg_state() == DBG_RUNNING) { list_msg(v, COLOR_PAIR_KEYWORD, "pause: the program does not stop"); v->dbg_seen = g_dbg_gen; }
}

/* Shift-F5 / K: kills the program */
static void dbg_key_kill(DisView *v) {
    if (!dbg_mine(v) || !dbg_alive()) { list_msg(v, COLOR_PAIR_NUMBER, "no program running"); return; }
    int pid = dbg_pid();
    con_drain();
    dbg_kill();
    dbg_changed();
    g_wait = false;
    if (v->in_mode == IN_CONSOLE) v->in_mode = IN_NONE;
    list_msg(v, COLOR_PAIR_STRING, "%s (pid %d) killed  ·  F5: run it again", base_name(v->path), pid);
    v->dbg_seen = g_dbg_gen;
}

/* F5 (run / continue), F6 (step), F7 (step over) */
static void dbg_key_run(DisView *v, int key, int win_h) {
    if (!dbg_claim(v)) return;
    if (v->dbg_seen != g_dbg_gen) { dbg_sync(v, list_rows(win_h)); return; }   /* show a new stop before resuming */
    char err[300] = "";
    bool ok, runto = false;
    DbgState s = dbg_state();
    if (s == DBG_RUNNING) {
        list_msg(v, COLOR_PAIR_NUMBER, "%s is running (pid %d): it stops at a breakpoint  ·  p: pause  ·  K: kill  ·  i: type its input",
                 base_name(v->path), dbg_pid());
        return;
    }
    if (s != DBG_STOPPED) {
        const ElfFile *ef = &v->d.elf;
#ifdef _WIN32
        if (ef->fmt != ELF_FMT_PE) {
            list_msg(v, COLOR_PAIR_NUMBER, "%s is a Linux program: the debugger (F5) runs Windows programs only, the analysis works here",
                     base_name(v->path));
            return;
        }
#else
        if (ef->fmt == ELF_FMT_PE) {
            list_msg(v, COLOR_PAIR_NUMBER, "%s is a Windows program: the debugger (F5) runs Linux programs only, the analysis works here",
                     base_name(v->path));
            return;
        }
#endif
        if (ef->fmt == ELF_FMT_PE && ef->pe.dll) {
            list_msg(v, COLOR_PAIR_NUMBER, "%s is a DLL: it does not run by itself (F5 on the .exe that loads it)", base_name(v->path));
            return;
        }
        /* F5 runs up to a breakpoint; F6 / F7 start it and stop at main,
         * to go through it from its first line (no main found: at the
         * entry point) */
        long mf = key != KEY_F(5) ? da_func_named(&v->d, "main") : -1;
        uint64_t first = 0;
        if (key != KEY_F(5)) {
            if (mf >= 0) first = v->d.fn[mf].addr;
            else if (ef->entry && elf_va_exec(ef, ef->entry)) first = ef->entry;
            else {
                list_msg(v, COLOR_PAIR_NUMBER, "no main nor entry point found: F5 runs %s up to a breakpoint", base_name(v->path));
                return;
            }
        }
        char abuf[sizeof v->args], *av[sizeof v->args / 2 + 2];
        int ac = split_args(v->args, abuf, av + 1, (int)(sizeof av / sizeof *av) - 1, err, sizeof err);
        if (ac < 0) {
            list_msg(v, COLOR_PAIR_KEYWORD, "F5: arguments: %s (a: change them)", err);
            return;
        }
        av[0] = v->path;
        g_regs_ok = g_prev_ok = false;
        con_clear();
        if (!dbg_launch(v->path, ac ? av : NULL, err, sizeof err)) {
            list_msg(v, COLOR_PAIR_KEYWORD, "F5: %s", err);
            dbg_changed();
            v->dbg_seen = g_dbg_gen;                 /* keep the message */
            return;
        }
        if (dbg_bits() && dbg_bits() != ef->bits) {      /* the file changed under the view? */
            int pb = dbg_bits();
            dbg_kill();
            dbg_changed();
            list_msg(v, COLOR_PAIR_KEYWORD, "F5: the process is %d-bit, the disassembly %d-bit: reopen the file", pb, ef->bits);
            v->dbg_seen = g_dbg_gen;
            return;
        }
        if (!g_auto_done) auto_add(v);
        if (first && !g_main_tmp && !dbg_bp_has(first)) {
            char e[200];
            g_main_addr = first;
            g_main_tmp = dbg_bp_add(g_main_addr, e, sizeof e);
        }
        ok = dbg_cont(err, sizeof err);
    } else if (key == KEY_F(5)) {
        uint64_t fa;
        bool in = dbg_rip(&fa, NULL) && input_call_at(v, fa);       /* from its input breakpoint */
        ok = dbg_cont(err, sizeof err);
        g_input_run = ok && in;
    } else if (key == KEY_F(6)) {
        ok = dbg_step(err, sizeof err);
    } else {
        /* step over: a call (or a rep string instruction) runs to the next
         * line; anything else is one step (a jump or ret may not come back
         * to the next line, and dbg_run_to only stops at a depth >= the
         * current one, so after a push it would never stop) */
        uint64_t fa;
        size_t li = dbg_rip(&fa, NULL) ? dl_line_of(v, fa) : SIZE_MAX;
        const DisLine *l = li != SIZE_MAX && v->dl[li].addr == fa && !v->dl[li].bad ? &v->dl[li] : NULL;
        if (l && (!strncmp(mnem_base(l->mnem), "call", 4) || !strncmp(l->mnem, "rep", 3))) {
            g_runto = l->addr + l->len;
            ok = runto = dbg_run_to(g_runto, err, sizeof err);
            g_input_run = ok && input_call_at(v, l->addr);
        } else
            ok = dbg_step(err, sizeof err);
    }
    con_drain();
    dbg_changed();
    g_runto_on = runto && dbg_state() == DBG_RUNNING;
    wait_check();
    if (!ok) {
        list_msg(v, COLOR_PAIR_KEYWORD, "%s: %s", key == KEY_F(5) ? "F5" : key == KEY_F(6) ? "F6" : "F7", err);
        v->dbg_seen = g_dbg_gen;
        return;
    }
    dbg_sync(v, list_rows(win_h));
}

/* ─── Opening ──────────────────────────────────────────────────── */

/* reads the ELF header for a clear message before the full load */
static bool check_header(const char *path, char *err, size_t esz) {
    FILE *f = fopen(path, "rb");
    if (!f) { snprintf(err, esz, "cannot open %s: %s", base_name(path), strerror(errno)); return false; }
    uint8_t h[20];
    size_t n = fread(h, 1, sizeof h, f);
    fclose(f);
    if (n >= 2 && h[0] == 'M' && h[1] == 'Z') return true;       /* PE: pe_parse checks the rest */
    if (n < 4 || memcmp(h, "\x7f" "ELF", 4)) { snprintf(err, esz, "%.200s is not an executable (ELF or PE)", base_name(path)); return false; }
    if (n < sizeof h) { snprintf(err, esz, "truncated ELF: %zu bytes, the header is incomplete", n); return false; }
    if (h[4] != 1 && h[4] != 2) { snprintf(err, esz, "ELF of unknown class %u", h[4]); return false; }
    if (h[5] != 1) { snprintf(err, esz, "big-endian ELF: only x86-64 (ELF64) and x86 (ELF32) are analysed"); return false; }
    unsigned m = h[18] | (unsigned)h[19] << 8;
    if (h[4] == 1) {                               /* ELF32: i386 only */
        if (m == 62) { snprintf(err, esz, "32-bit ELF for x86-64 (x32 ABI): not analysed"); return false; }
        if (m != 3) { snprintf(err, esz, "32-bit ELF for %s (machine %u): only x86 (i386) is analysed in 32 bits", elf_machine_name((uint16_t)m), m); return false; }
        return true;
    }
    if (m != 62) { snprintf(err, esz, "ELF for %s (machine %u): only x86-64 is analysed", elf_machine_name((uint16_t)m), m); return false; }
    return true;
}

bool dis_open(DisView **pv, const char *path, char *err, size_t esz) {
    struct stat st;
    if (!path || !path[0]) { snprintf(err, esz, "no file on disk for this buffer"); return false; }
    if (stat(path, &st) != 0) { snprintf(err, esz, "cannot read %s: %s", base_name(path), strerror(errno)); return false; }
    if (!S_ISREG(st.st_mode)) { snprintf(err, esz, "%s is not a regular file", base_name(path)); return false; }

    DisView *old = *pv;
    bool same = old && !strcmp(old->path, path);
    if (same && old->mtime == (long long)st.st_mtime && old->fsize == (long long)st.st_size) {
        cancel_input(old);
        old->msg[0] = '\0';
        return true;
    }
    bool dbg_reset = false;
    char args[sizeof old->args] = "";              /* the arguments outlive a rebuild of the file */
    if (same) {                                    /* changed on disk: analysed again */
        snprintf(args, sizeof args, "%s", old->args);
        if (dbg_mine(old)) {                       /* its debuggee / breakpoints are of the old file */
            dbg_reset = dbg_state() != DBG_NONE || dbg_bp_list(NULL, 0) > 0;
            if (dbg_state() != DBG_NONE) dbg_kill();
            dbg_bp_clear();
            auto_reset();
            g_regs_ok = g_prev_ok = false;
        }
        dis_free(old);
        *pv = NULL;
    }

    if (!check_header(path, err, esz)) return false;

    DisView *v = calloc(1, sizeof *v);
    if (!v) { snprintf(err, esz, "out of memory"); return false; }
    if (!da_analyze(&v->d, path, err, esz)) { free(v); return false; }
    snprintf(v->path, sizeof v->path, "%s", path);
    snprintf(v->args, sizeof v->args, "%s", args);
    v->mtime = (long long)st.st_mtime;
    v->fsize = (long long)st.st_size;
    v->dfn   = -1;
    build_info(v);
    if (!list_init(v))
        list_msg(v, COLOR_PAIR_KEYWORD, "function list unavailable: out of memory");
    if (!data_init(v))
        list_msg(v, COLOR_PAIR_KEYWORD, "data sections unavailable: out of memory");
    v->dbg_seen = g_dbg_gen;
    v->wait_seen = g_wait_gen;
    if (dbg_reset)
        list_msg(v, COLOR_PAIR_KEYWORD, "the file changed on disk: debuggee killed, breakpoints cleared");

    if (*pv) dis_free(*pv);
    *pv = v;
    return true;
}

void dis_free(DisView *v) {
    if (!v) return;
    da_free(&v->d);
    lines_free(v);
    free(v->ord);
    free(v->vis);
    da_lines_free(v->dl);
    free(v->dref);
    free(v->ds);
    free(v->xi);
    free(v);
}

/* ─── Drawing and keys ─────────────────────────────────────────── */

static int body_rows(int h) { return h >= 3 ? h - 2 : h - 1; }

static void clamp_scroll(DisView *v, int rows) {
    int max = v->nln - (rows > 0 ? rows : 1);
    if (v->scroll > max) v->scroll = max;
    if (v->scroll < 0) v->scroll = 0;
}

/* list: title bar, column header (h >= 4), rows, bottom bar (h >= 3) */
static int list_rows(int h) {
    int r = h - 1 - (h >= 3) - (h >= 4);
    return r > 0 ? r : 0;
}

/* a selection *sel among n rows, the first shown being *top */
static void keep_in_view(size_t *sel, size_t *top, size_t n, int rows) {
    if (!n) { *sel = *top = 0; return; }
    if (*sel >= n) *sel = n - 1;
    size_t r = rows > 0 ? (size_t)rows : 1;
    if (n <= r) *top = 0;
    else if (*top > n - r) *top = n - r;                    /* no blank rows after a resize */
    if (*sel < *top) *top = *sel;
    else if (*sel >= *top + r) *top = *sel - r + 1;
}

static void keep_visible(DisView *v, int rows) { keep_in_view(&v->sel, &v->top, v->nvis, rows); }

/* s from column x with attribute a, clipped to w; returns the next column */
static int piece(WINDOW *win, int y, int x, int w, attr_t a, const char *s) {
    wattrset(win, a);
    x = put_clip(win, y, x, s, w);
    wattrset(win, A_NORMAL);
    return x;
}

/* ─── Column blocks (data screens) ─────────────────────────────── */

/* display width of s (UTF-8) */
static int str_cols(const char *s) {
    int w = 0;
    for (size_t n = strlen(s), i = 0; i < n; ) {
        uint32_t cp;
        int k = utf8_decode(s + i, n - i, &cp);
        if (k < 1) k = 1;
        int cw = utf8_cp_width(cp);
        w += cw > 0 ? cw : 0;
        i += (size_t)k;
    }
    return w;
}

/* One row of column blocks, drawn cell by cell (blk_cell, in column
 * order): column 0 from x 0, then from column `first` on, each one as
 * "│ text " (cw[c] columns of text); columns 1 .. first-1 are skipped.
 * The last column gets what remains of the row. A text longer than its
 * cell ends with "…". */
typedef struct {
    WINDOW    *win;
    int        y, w, n, first, c;
    const int *cw;
    int        pos;                /* where the next separator goes        */
    int        x0, x, lim;         /* the current cell (x0 -1: not shown)  */
    attr_t     sep;
    bool      *cut;                /* set when the last column is cut      */
} Blk;

static void blk_text(Blk *b, attr_t a, const char *s) {
    if (b->x0 < 0 || b->x >= b->lim || !s || !*s) return;
    wattrset(b->win, a);
    if (b->x + str_cols(s) <= b->lim) b->x = put_clip(b->win, b->y, b->x, s, b->lim);
    else {
        put_clip(b->win, b->y, b->x, s, b->lim - 1);
        mvwaddstr(b->win, b->y, b->lim - 1, "…");
        b->x = b->lim;
        if (b->cut && b->c == b->n) *b->cut = true;
    }
    wattrset(b->win, A_NORMAL);
}

static void blk_cell(Blk *b, attr_t a, const char *s) {
    int c = b->c++;
    b->x0 = -1;
    if (c >= b->n || (c > 0 && c < b->first)) return;
    if (c == 0) { b->x0 = b->x = 0; b->lim = b->cw[0] < b->w ? b->cw[0] : b->w; b->pos = b->cw[0]; }
    else {
        if (b->pos >= b->w) return;
        wattrset(b->win, b->sep);
        mvwaddstr(b->win, b->y, b->pos, "│");
        wattrset(b->win, A_NORMAL);
        b->x0 = b->x = b->pos + 2;
        int end = c == b->n - 1 ? b->w : b->pos + 2 + b->cw[c];
        b->lim = end < b->w ? end : b->w;
        b->pos += b->cw[c] + 3;
    }
    blk_text(b, a, s);
}

/* more text in the current cell, from column `pad` of the cell, or `gap`
 * columns after what is there when it goes past */
static void blk_more(Blk *b, int pad, int gap, attr_t a, const char *s) {
    if (b->x0 < 0) return;
    b->x = b->x0 + pad > b->x + gap ? b->x0 + pad : b->x + gap;
    blk_text(b, a, s);
}

/* true: some column after `first` does not show whole in w (the last
 * one only counts here when it does not start on screen; Blk.cut tells
 * when its text is cut) */
static bool blk_more_right(const int *cw, int n, int first, int w) {
    int pos = cw[0];
    for (int c = first; c < n; c++) {
        if (c == n - 1) return pos + 2 >= w;
        if (pos + cw[c] + 3 > w) return true;
        pos += cw[c] + 3;
    }
    return false;
}

/* the header row of column blocks: the names, « / » when columns are
 * hidden on the left / right (not ◀ ▶: emoji, two cells wide in some
 * consoles, Wine's among them) */
static void blk_header(WINDOW *win, int y, int w, const int *cw, const char *const *name, int n, int first,
                       bool more) {
    Blk b = { win, y, w, n, first, 0, cw, 0, 0, 0, 0, COLOR_PAIR(COLOR_PAIR_INACTIVE_BORDER) | A_DIM, NULL };
    for (int c = 0; c < n; c++) blk_cell(&b, COLOR_PAIR(COLOR_PAIR_COMMENT) | A_BOLD, name[c]);
    wattrset(win, COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD);
    if (first > 1 && cw[0] < w) mvwaddstr(win, y, cw[0], "«");
    if (more && w > 1) mvwaddstr(win, y, w - 1, "»");
    wattrset(win, A_NORMAL);
}

/* Left / Right on a screen of column blocks; false: another key */
static bool blk_key(int key, int *first, int n, bool more) {
    if (key == KEY_LEFT)  { if (*first > 1) (*first)--; return true; }
    if (key == KEY_RIGHT) { if (more && *first < n - 1) (*first)++; return true; }
    return false;
}

static attr_t origin_attr(int kind) {
    if (kind == FN_DATAPTR || kind == FN_PROLOGUE) return COLOR_PAIR(COLOR_PAIR_NUMBER) | A_BOLD;
    if (kind == FN_CALL || kind == FN_CODEPTR)     return COLOR_PAIR(COLOR_PAIR_NORMAL);
    return COLOR_PAIR(COLOR_PAIR_STRING);                  /* symbol, plt, entry, main, ctor */
}

/* columns: mark, address, size, callers, origin, then the name, last so
 * that a long (C++) name never pushes the other columns off screen */
static void draw_fn_header(const DisView *v, WINDOW *win, int y, int w) {
    attr_t n = COLOR_PAIR(COLOR_PAIR_LINENUM), s = COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD;
    char a[24];
    snprintf(a, sizeof a, "%-*s", v->aw + 2, "ADDRESS");
    int x = 3;
    x = piece(win, y, x, w, v->sort == SORT_ADDR ? s : n, a) + 2;
    x = piece(win, y, x, w, v->sort == SORT_SIZE ? s : n, "    SIZE") + 2;
    x = piece(win, y, x, w, v->sort == SORT_CALLERS ? s : n, "CALLERS") + 2;
    x = piece(win, y, x, w, n, "ORIGIN  ") + 2;
    piece(win, y, x, w, v->sort == SORT_NAME ? s : n, "NAME");
}

static void draw_fn_row(const DisView *v, WINDOW *win, int y, int w, uint32_t fi, bool sel) {
    const DisFunc *f = &v->d.fn[fi];
    attr_t hs = COLOR_PAIR(COLOR_PAIR_SELECTION) | A_BOLD;
    if (sel) { wattrset(win, hs); mvwhline(win, y, 0, ' ', w); wattrset(win, A_NORMAL); }
    char a[24], sz[24], nc[16], org[16];
    snprintf(a, sizeof a, "0x%0*llx", v->aw, (unsigned long long)f->addr);
    if (f->size) snprintf(sz, sizeof sz, "%8llu", (unsigned long long)f->size);
    else         snprintf(sz, sizeof sz, "%8s", "-");
    snprintf(nc, sizeof nc, "%7u", f->ncallers);
    snprintf(org, sizeof org, "%-8s", fn_kind_name(f->kind));
    int x = 0;
    x = piece(win, y, x, w, sel ? hs : COLOR_PAIR(COLOR_PAIR_NUMBER) | A_BOLD, fn_weak(f) ? " ? " : "   ");
    x = piece(win, y, x, w, sel ? hs : COLOR_PAIR(COLOR_PAIR_LINENUM), a) + 2;
    x = piece(win, y, x, w, sel ? hs : COLOR_PAIR(f->size ? COLOR_PAIR_NORMAL : COLOR_PAIR_COMMENT), sz) + 2;
    x = piece(win, y, x, w, sel ? hs : COLOR_PAIR(f->ncallers ? COLOR_PAIR_NORMAL : COLOR_PAIR_COMMENT), nc) + 2;
    x = piece(win, y, x, w, sel ? hs : origin_attr(f->kind), org) + 2;
    piece(win, y, x, w, sel ? hs : COLOR_PAIR(COLOR_PAIR_NORMAL), f->name ? f->name : "?");
}

/* the prompt replaces the bottom bar while a filter / address is typed */
static void draw_prompt(const DisView *v, WINDOW *win, int y, int w) {
    bool flt = v->in_mode == IN_FILTER, con = v->in_mode == IN_CONSOLE, brk = v->in_mode == IN_BREAK, arg = v->in_mode == IN_ARGS;
    attr_t st = COLOR_PAIR(COLOR_PAIR_STATUS);
    bar(win, y, w, COLOR_PAIR_STATUS, 0, "");
    int x = piece(win, y, 0, w, st | A_BOLD, con ? " Console (stdin): " : flt ? " Filter (name): " : brk ? " Breakpoint: "
                                           : arg ? " Arguments: " : " Go to address (hex): ");
    int room = w - x - 1;                                   /* one cell for the cursor */
    size_t n = strlen(v->in_buf);
    const char *s = v->in_buf;                              /* ASCII only: bytes = cells */
    if (room < 0) room = 0;
    if (n > (size_t)room) s += n - (size_t)room;            /* the end stays visible */
    x = piece(win, y, x, w, st, s);
    if (x < w) x = piece(win, y, x, w, st | A_REVERSE, " ");
    piece(win, y, x, w, st, con ? (g_wait ? "   the program waits for this input  ·  Enter: send the line  ·  ^D: end of input  ·  "
                                            "↑↓ PgUp PgDn: move  ·  Esc: leave"
                                          : "   Enter: send the line  ·  ^D: end of input  ·  ^C: interrupt  ·  "
                                            "F5 F6 F7: run  ·  Shift-F5: kill  ·  ↑↓ PgUp PgDn: move  ·  Esc: leave")
                          : brk ? "   main, 0x1149, main+0x10, libc.so.6+0x2a1c0, . (this line)  [hw]  [if rax == 3 | hits >= 2]  ·  -x removes, -* all  ·  !x on/off  ·  Esc: cancel"
                          : arg ? (v->msg[0] ? v->msg : "   Enter: keep for the next F5 F6 F7 launches  ·  \"a b\" 'c d': one argument  ·  "
                                                        "empty: none  ·  Esc: cancel  ·  ^U: clear")
                          : flt ? "   Enter: keep  ·  Esc: cancel  ·  ^U: clear  ·  ↑↓: move"
                                : "   Enter: go  ·  Esc: cancel  ·  ^U: clear");
}

static void render_funcs(DisView *v, WINDOW *win, int h, int w) {
    int rows = list_rows(h), y0 = h >= 4 ? 2 : 1;
    if (h >= 4) draw_fn_header(v, win, 1, w);
    keep_visible(v, rows);
    if (v->list_ok)
        for (int r = 0; r < rows && v->top + (size_t)r < v->nvis; r++)
            draw_fn_row(v, win, y0 + r, w, v->vis[v->top + (size_t)r], v->top + (size_t)r == v->sel);

    char line[512];
    if (rows > 0 && !v->nvis) {
        if (!v->list_ok)      snprintf(line, sizeof line, "   Function list unavailable (out of memory)");
        else if (!v->d.nfn)   snprintf(line, sizeof line, "   No function found in this file");
        else                  snprintf(line, sizeof line, "   No function name contains \"%s\"  (/: change the filter, Esc: clear it)", v->filter);
        piece(win, y0, 0, w, COLOR_PAIR(COLOR_PAIR_COMMENT), line);
    }

    if (h < 3) return;
    if (v->in_mode != IN_NONE) { draw_prompt(v, win, h - 1, w); return; }
    char flt[200] = "";
    if (v->filter[0]) snprintf(flt, sizeof flt, "  ·  filter \"%.100s\" (%zu of %zu)", v->filter, v->nvis, v->d.nfn);
    snprintf(line, sizeof line, " %zu/%zu  ·  sort: %s%s  ·  ", v->nvis ? v->sel + 1 : 0, v->nvis, sort_name(v->sort), flt);
    bar(win, h - 1, w, COLOR_PAIR_LINENUM, 0, "");
    int x = piece(win, h - 1, 0, w, COLOR_PAIR(COLOR_PAIR_LINENUM), line);
    if (v->msg[0]) piece(win, h - 1, x, w, COLOR_PAIR(v->msg_pair) | A_BOLD, v->msg);
    else {
        snprintf(line, sizeof line, "Enter/click: disassemble  s: sort  /: filter  :: go to address  d: data sections  "
                 "? = guessed start (dataptr, prologue)  ·  Tab: %s  ·  F9/Esc: close", v->dl ? "disassembly" : "data");
        piece(win, h - 1, x, w, COLOR_PAIR(COLOR_PAIR_LINENUM), line);
    }
}

static void render_info(DisView *v, WINDOW *win, int h, int w) {
    char line[512];
    int rows = body_rows(h);
    clamp_scroll(v, rows);
    for (int r = 0; r < rows && v->scroll + r < v->nln; r++) {
        const InfoLine *l = &v->ln[v->scroll + r];
        int x = 0;
        if (l->lbl) {
            char lb[64];
            snprintf(lb, sizeof lb, "   %-*s", LBL_W, l->lbl);
            wattron(win, COLOR_PAIR(l->lp));
            x = put_clip(win, 1 + r, 0, lb, w);
            wattroff(win, COLOR_PAIR(l->lp));
            if (x < w) x++;
        }
        attr_t a = COLOR_PAIR(l->vp) | (l->bold ? A_BOLD : 0);
        wattron(win, a);
        put_clip(win, 1 + r, x, l->val, w);
        wattroff(win, a);
    }

    if (h >= 3) {
        int last = v->scroll + rows < v->nln ? v->scroll + rows : v->nln;
        if (v->in_mode != IN_NONE) { draw_prompt(v, win, h - 1, w); return; }
        snprintf(line, sizeof line, " %d-%d/%d  ·  ↑↓ PgUp/PgDn g/G: scroll  ·  d: data sections  ·  :: go to address  ·  "
                 "Tab: function list  ·  F9/Esc: close", v->nln ? v->scroll + 1 : 0, last, v->nln);
        bar(win, h - 1, w, COLOR_PAIR_LINENUM, 0, line);
    }
}

/* one disassembly line: mark ('!': not decoded by the analysis), address,
 * bytes (w >= 90), mnemonic, operands, then a comment (target name,
 * start of another function) */
/* x as a value of `bytes` bytes: unsigned, and signed (two's complement) */
static void num_split(uint64_t x, unsigned bytes, uint64_t *u, int64_t *sv) {
    unsigned bits = bytes >= 8 ? 64 : bytes * 8;
    *u = bits == 64 ? x : x & ((1ull << bits) - 1);
    *sv = bits == 64 || !((*u >> (bits - 1)) & 1) ? (int64_t)*u : (int64_t)(*u - (1ull << bits));
}

/* Decimal value of the hex numbers of a line, as "0x1c8 = 456": the
 * displacement of a memory operand ([rbp - 0x18]) then the immediate
 * (with its character for a byte). Numbers below 10 (capstone writes them
 * in decimal) and immediates that look like an address in the file are
 * left out. Returns the bytes written. */
static size_t num_note(const DisView *v, const DisLine *l, char *out, size_t sz) {
    size_t o = 0;
    if (!sz) return 0;
    out[0] = '\0';
    if (l->bad || !l->len) return 0;
    if (l->has_disp && (l->disp >= 10 || l->disp <= -10)) {
        uint64_t m = l->disp < 0 ? 0 - (uint64_t)l->disp : (uint64_t)l->disp;
        o += (size_t)snprintf(out + o, sz - o, "%s0x%llx = %lld", l->disp < 0 ? "-" : "",
                              (unsigned long long)m, (long long)l->disp);
    }
    if (l->imm_size && o < sz) {
        uint64_t u;
        int64_t sv;
        num_split((uint64_t)l->imm, l->imm_size, &u, &sv);
        bool addr = u >= 0x10000 && elf_map_of(&v->d.elf, u);
        if (!addr && (u >= 10 || sv <= -10 || sv < 0)) {
            char neg[32];
            uint64_t m = sv < 0 ? 0 - (uint64_t)sv : 0;
            snprintf(neg, sizeof neg, "-0x%llx", (unsigned long long)m);
            const char *sep = o ? ", " : "";
            if (sv < 0 && strstr(l->ops, neg))          /* written "-0x80" */
                o += (size_t)snprintf(out + o, sz - o, "%s%s = %lld", sep, neg, (long long)sv);
            else if (sv < 0)
                o += (size_t)snprintf(out + o, sz - o, "%s0x%llx = %lld", sep, (unsigned long long)u, (long long)sv);
            else
                o += (size_t)snprintf(out + o, sz - o, "%s0x%llx = %llu", sep, (unsigned long long)u, (unsigned long long)u);
            if (o < sz && l->imm_size == 1 && u >= 0x20 && u < 0x7f)
                o += (size_t)snprintf(out + o, sz - o, " '%c'", (char)u);
        }
    }
    return o < sz ? o : sz - 1;
}

static void draw_dl_row(const DisView *v, WINDOW *win, int y, int w, size_t i, bool sel) {
    const Disasm *d = &v->d;
    const DisLine *l = &v->dl[i];
    /* the line of rip (stopped debuggee): green, over the selection */
    bool rip = l->len && v->drip_ok && v->drip >= l->addr && v->drip - l->addr < l->len;
    bool bp  = l->len && dbg_mine(v) && dbg_bp_has(l->addr);
    attr_t hs = rip ? COLOR_PAIR(HEX_CP_CURSOR_A) | (sel ? A_BOLD : 0) : COLOR_PAIR(COLOR_PAIR_SELECTION) | A_BOLD;
    sel = sel || rip;
    if (sel) { wattrset(win, hs); mvwhline(win, y, 0, ' ', w); wattrset(win, A_NORMAL); }
    if (!l->len) {                           /* separator before the .cold part */
        const DisFunc *fn = &d->fn[v->dfn];
        char sep[400];
        snprintf(sep, sizeof sep, "   ── %.160s.cold  ·  0x%llx-0x%llx  ·  %llu bytes  ·  laid out apart from the body ──",
                 fn->name ? fn->name : "?", (unsigned long long)fn->cold,
                 (unsigned long long)(fn->cold + fn->cold_size), (unsigned long long)fn->cold_size);
        piece(win, y, 0, w, sel ? hs : COLOR_PAIR(COLOR_PAIR_COMMENT) | A_BOLD, sep);
        return;
    }
    long ai = d->nins && !l->bad ? da_insn_at(d, l->addr) : -1;
    bool off = d->nins && ai < 0;
    char a[24], by[DIS_BYTES * 3 + 8], mn[40], cmt[400] = "", nm[256];
    snprintf(a, sizeof a, "0x%0*llx", v->aw, (unsigned long long)l->addr);
    size_t u = 0;
    int nb = l->len > DIS_BYTES ? DIS_BYTES - 1 : l->len;
    for (int k = 0; k < nb; k++) u += (size_t)snprintf(by + u, sizeof by - u, "%02x ", l->bytes[k]);
    if (nb < l->len) u += (size_t)snprintf(by + u, sizeof by - u, "…");
    else if (u) by[--u] = '\0';                             /* trailing space */
    snprintf(mn, sizeof mn, "%-7s ", l->mnem);

    /* decoded by the analysis and not a branch: its comment (string, name
     * of the data pointed to); otherwise the name of the target */
    uint64_t t;
    u = 0;
    bool named = false;                         /* cmt ends with the name of the call's target */
    char dec[96];
    if (num_note(v, l, dec, sizeof dec)) u += (size_t)snprintf(cmt + u, sizeof cmt - u, "; %s", dec);
    if (ai >= 0 && d->ins[ai].target && !(d->ins[ai].flags & (DI_CALL | DI_JUMP | DI_COND))) {
        char m2[32], o2[160];
        nm[0] = '\0';
        da_format(d, (size_t)ai, m2, sizeof m2, o2, sizeof o2, nm, sizeof nm);
        if (nm[0]) u += (size_t)snprintf(cmt + u, sizeof cmt - u, "%s%s", u ? "  " : "; ", nm);
    } else if (!line_ref(l, &t) && v->dref && (t = v->dref[i])) {   /* an address in the operands */
        nm[0] = '\0';
        if (!da_string_at(d, t, nm, sizeof nm) && !da_name_for(d, t, nm, sizeof nm)) ref_place(v, t, nm, sizeof nm);
        if (nm[0]) u += (size_t)snprintf(cmt + u, sizeof cmt - u, "%s%s", u ? "  " : "; ", nm);
    } else if ((line_ref(l, &t) || (d->elf.fmt == ELF_FMT_PE && d->elf.bits == 32 && abs_ref(l, &t))) &&
               da_name_for(d, t, nm, sizeof nm)) {
        u += (size_t)snprintf(cmt + u, sizeof cmt - u, "%s%s", u ? "  " : "; ", nm);
        named = true;
    }
    if (!strncmp(mnem_base(l->mnem), "call", 4) && u < sizeof cmt) {   /* what it is given: printf("%d\n", ?) */
        char args[300];
        call_args_text(v, i, args, sizeof args);
        if (args[0] && u < sizeof cmt)
            u += (size_t)snprintf(cmt + u, sizeof cmt - u, "%s%s", named ? "" : u ? "  ?" : "; ?", args);
    }
    if (u >= sizeof cmt) u = sizeof cmt - 1;
    long fs = i ? da_func_at(d, l->addr) : -1;
    if (fs >= 0 && u < sizeof cmt)
        snprintf(cmt + u, sizeof cmt - u, "%s◂ start of %s", u ? "  " : "; ", d->fn[fs].name ? d->fn[fs].name : "?");

    attr_t mna = l->bad ? COLOR_PAIR(COLOR_PAIR_NUMBER) | A_BOLD
               : mnem_flow(l->mnem) ? COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD : COLOR_PAIR(COLOR_PAIR_NORMAL);
    /* margin: breakpoint, not decoded by the analysis, rip */
    int x = 0;
    DbgBp bi;
    bool bon = bp && dbg_bp_info(dbg_bp_index(l->addr), &bi);
    x = piece(win, y, x, w, sel ? hs : COLOR_PAIR(bp && auto_index(l->addr) >= 0 ? COLOR_PAIR_TYPE : HEX_CP_NONPRINT) | A_BOLD,
              !bon ? " " : !bi.enabled ? "○" : bi.hw ? "◆" : "•");
    x = piece(win, y, x, w, sel ? hs : COLOR_PAIR(COLOR_PAIR_NUMBER) | A_BOLD, off ? "!" : " ");
    x = piece(win, y, x, w, sel ? hs : COLOR_PAIR(COLOR_PAIR_NUMBER) | A_BOLD, rip ? "▶" : " ");
    x = piece(win, y, x, w, sel ? hs : COLOR_PAIR(COLOR_PAIR_LINENUM), a) + 2;
    if (w >= 90) {
        int bx = x;
        piece(win, y, x, w, sel ? hs : COLOR_PAIR(COLOR_PAIR_COMMENT), by);
        x = bx + DIS_BYTES * 3 + 1;
    }
    x = piece(win, y, x, w, sel ? hs : mna, mn);
    x = piece(win, y, x, w, sel ? hs : COLOR_PAIR(l->bad ? COLOR_PAIR_NUMBER : COLOR_PAIR_NORMAL), l->ops);
    if (cmt[0]) piece(win, y, x + 2, w, sel ? hs : COLOR_PAIR(COLOR_PAIR_COMMENT), cmt);
}

/* register panel of the debugger: right column of the disassembly, a
 * third of the width (DBG_PANEL_W to DBG_PANEL_MAX columns) */
#define DBG_PANEL_W   28
#define DBG_PANEL_MAX 60

/* s word-wrapped over rows y.. (< y1) from column x, clipped at w;
 * returns the next row */
static int put_wrap(WINDOW *win, int y, int y1, int x, int w, attr_t a, const char *s) {
    int width = w - x;
    if (width < 4) return y;
    while (*s && y < y1) {
        int n = (int)strlen(s);
        if (n > width) {
            n = width;
            while (n > 0 && s[n] != ' ') n--;
            if (!n) n = width;
        }
        char part[128];
        snprintf(part, sizeof part, "%.*s", n < (int)sizeof part ? n : (int)sizeof part - 1, s);
        piece(win, y++, x, w, a, part);
        s += n;
        while (*s == ' ') s++;
    }
    return y;
}

/* bytes of the first piece of s[0..n) that fits `width` cells (one
 * character at least) */
static size_t wrap_cut(const char *s, size_t n, int width) {
    size_t i = 0;
    int x = 0;
    while (i < n) {
        uint32_t cp;
        int k = utf8_decode(s + i, n - i, &cp);
        if (k < 1) k = 1;
        int cw = utf8_cp_width(cp);
        if (cw < 0) cw = 0;
        if (x + cw > width && i) break;
        x += cw;
        i += (size_t)k;
    }
    return i;
}

/* rows taken by a line of n bytes wrapped at `width` */
static int wrap_rows(const char *s, size_t n, int width) {
    int r = 0;
    do { size_t k = wrap_cut(s, n, width); s += k; n -= k; r++; } while (n);
    return r;
}

/* Console of the program, rows y .. y1-1 from column x (clipped at w):
 * title, the end of its output wrapped, the input line last. */
static void draw_console(const DisView *v, WINDOW *win, int y, int y1, int x, int w) {
    if (y1 - y < 2) return;
    int width = w - x;
    if (width < 4) return;
    bool typing = v->in_mode == IN_CONSOLE, alive = dbg_alive();
    int tx = piece(win, y++, x, w, COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD, "CONSOLE");
    piece(win, y - 1, tx + 2, w, COLOR_PAIR(COLOR_PAIR_LINENUM),
          typing ? "Enter: send  Esc: leave" : alive ? (g_wait ? "waits: i to type" : "i: type") : "");
    int out_rows = y1 - 1 - y;                       /* the last row: input */
    /* the lines that end the text, wrapped, bottom up */
    size_t end = g_ncon;
    if (end && g_con[end - 1] == '\n') end--;        /* no empty last line */
    int need = out_rows, yy = y1 - 1;
    if (!g_ncon && out_rows > 0)
        piece(win, y, x, w, COLOR_PAIR(COLOR_PAIR_COMMENT), alive ? "(no output yet)" : "(no output)");
    while (need > 0 && g_ncon) {
        size_t bol = end;
        while (bol && g_con[bol - 1] != '\n') bol--;
        const char *ln = g_con + bol;
        size_t n = end - bol;
        int r = wrap_rows(ln, n, width);
        int show = r < need ? r : need;              /* its last rows (the top may not fit) */
        yy -= show;
        for (int row = 0, yr = yy; row < r; row++) {
            size_t k = wrap_cut(ln, n, width);
            if (row >= r - show) {
                char part[512];
                size_t m = k < sizeof part - 1 ? k : sizeof part - 1;
                memcpy(part, ln, m);
                part[m] = '\0';
                piece(win, yr++, x, w, COLOR_PAIR(COLOR_PAIR_NORMAL), part);
            }
            ln += k;
            n -= k;
        }
        need -= show;
        if (!bol) break;
        end = bol - 1;
    }
    /* input line: what is being typed, its end visible */
    attr_t ia = typing ? COLOR_PAIR(COLOR_PAIR_STRING) | A_BOLD : COLOR_PAIR(COLOR_PAIR_LINENUM);
    int ix = piece(win, y1 - 1, x, w, ia, alive ? "> " : "(not running)");
    if (!alive) return;
    const char *b = typing ? v->in_buf : "";
    size_t bn = strlen(b);
    int room = w - ix - 1;
    if (room < 0) room = 0;
    if (bn > (size_t)room) b += bn - (size_t)room;   /* ASCII only: bytes = cells */
    ix = piece(win, y1 - 1, ix, w, ia, b);
    if (typing && ix < w) piece(win, y1 - 1, ix, w, COLOR_PAIR(COLOR_PAIR_STRING) | A_REVERSE, " ");
}

/* the bytes at val in the debuggee from (y, x): hex, then the characters,
 * 4 to 8 a row, two rows, not past its page. Returns the next row. */
static int draw_peek(WINDOW *win, int y, int y1, int x, int w, uint64_t val) {
    char line[96];
    int per = (w - x) / 4;
    if (per > 8) per = 8;
    if (per < 4) per = 4;
    uint8_t b[16];
    size_t n = (size_t)per * 2, page = 4096 - (size_t)(val & 4095);
    if (n > page) n = page;
    if (!dbg_read_mem(val, b, n)) n = 0;
    for (size_t o = 0; o < n && y < y1; o += (size_t)per) {
        size_t m = n - o < (size_t)per ? n - o : (size_t)per, q = 0;
        for (size_t i = 0; i < m; i++) q += (size_t)snprintf(line + q, sizeof line - q, "%02x ", b[o + i]);
        for (size_t i = m; i < (size_t)per; i++) q += (size_t)snprintf(line + q, sizeof line - q, "   ");
        for (size_t i = 0; i < m && q + 1 < sizeof line; i++)
            line[q++] = b[o + i] >= 0x20 && b[o + i] < 0x7f ? (char)b[o + i] : '.';
        line[q] = '\0';
        piece(win, y++, x, w, COLOR_PAIR(COLOR_PAIR_COMMENT), line);
    }
    return y;
}

/* al, then [esp+4] and [esp+8] with what they point to (and the bytes
 * there when peeked, see stack_arg_go); their rows go to v->sarg_y*.
 * Returns the next row. */
static int draw_stack_args(DisView *v, WINDOW *win, int x, int y, int y1, int w) {
    const DbgRegs *r = &g_regs, *p = &g_prev;
    bool w32 = dbg_bits() == 32;
    char line[96], note[200];
    unsigned al = (unsigned)(r->rax & 0xff);
    int u = snprintf(line, sizeof line, "0x%02x  %u", al, al);
    if (al > 127) u += snprintf(line + u, sizeof line - (size_t)u, " / %d", (int)(int8_t)al);
    if (al >= 0x20 && al < 0x7f) snprintf(line + u, sizeof line - (size_t)u, "  '%c'", (char)al);
    int xx = piece(win, y, x, w, COLOR_PAIR(COLOR_PAIR_TYPE), "al       ");
    piece(win, y++, xx, w, g_prev_ok && (p->rax & 0xff) != al ? COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD
                                                                : COLOR_PAIR(COLOR_PAIR_NORMAL), line);
    for (int k = 0; k < 2 && y < y1; k++) {
        char lbl[16];
        uint64_t val = 0;
        bool ok = stack_arg(k, &val, lbl, sizeof lbl);
        snprintf(line, sizeof line, "%-8s ", lbl);
        xx = piece(win, y, x, w, COLOR_PAIR(COLOR_PAIR_TYPE), line);
        if (!ok) { piece(win, y++, xx, w, COLOR_PAIR(COLOR_PAIR_COMMENT), "not readable"); continue; }
        v->sarg_y0[k] = y;
        bool peek = v->peek_on && v->peek_k == k && v->peek_a == val;
        snprintf(line, sizeof line, "0x%0*llx", w32 ? 8 : 16, (unsigned long long)val);
        xx = piece(win, y, xx, w, COLOR_PAIR(COLOR_PAIR_NORMAL) | A_UNDERLINE, line);
        piece(win, y++, xx, w, COLOR_PAIR(COLOR_PAIR_LINENUM), k ? " 2" : " 1");
        ptr_note(v, val, note, sizeof note);
        if (note[0] && y < y1) piece(win, y++, x + 9, w, COLOR_PAIR(COLOR_PAIR_STRING), note);
        if (peek) y = draw_peek(win, y, y1, x + 9, w, val);
        v->sarg_y1[k] = y;
    }
    return y;
}

/* under register i when it is peeked (see value_go): what its value
 * points to, then the bytes there. Returns the next row. */
static int draw_reg_peek(DisView *v, WINDOW *win, int i, int x, int y, int y1, int w) {
    uint64_t val = reg_val(&g_regs, i);
    if (!v->peek_on || v->peek_k != 2 + i || v->peek_a != val) return y;
    char note[200];
    ptr_note(v, val, note, sizeof note);
    if (note[0] && y < y1) piece(win, y++, x, w, COLOR_PAIR(COLOR_PAIR_STRING), note);
    return draw_peek(win, y, y1, x, w, val);
}

static void draw_regs(DisView *v, WINDOW *win, int x0, int y0, int y1, int w) {
    wattrset(win, COLOR_PAIR(COLOR_PAIR_INACTIVE_BORDER));
    for (int y = y0; y < y1; y++) mvwaddch(win, y, x0, ACS_VLINE);
    wattrset(win, A_NORMAL);
    int x = x0 + 2, y = y0;
    DbgState s = dbg_state();
    char st[200], line[96];
    dbg_status(st, sizeof st);
    if (s != DBG_EXITED) {                           /* short: the bar has the full text */
        static const char *const why[] = { "stopped", "at exec", "breakpoint", "reached", "step", NULL, "interrupted" };
        DbgStop r = dbg_stop_reason();
        const char *wd = s == DBG_RUNNING ? (g_wait ? "reads its input" : "running")
                       : (unsigned)r < sizeof why / sizeof why[0] ? why[r] : NULL;
        if (wd) snprintf(st, sizeof st, "%s  ·  pid %d", wd, dbg_pid());
    }
    piece(win, y++, x, w, COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD,
          s == DBG_STOPPED ? "REGISTERS" : s == DBG_RUNNING ? (g_wait ? "WAITING FOR INPUT" : "RUNNING") : "EXITED");
    y = put_wrap(win, y, y1 < y + 3 ? y1 : y + 3, x, w, COLOR_PAIR(COLOR_PAIR_COMMENT), st);
    y++;
    if (s == DBG_STOPPED && g_regs_ok) {
        bool w32 = dbg_bits() == 32;
        int dig = w32 ? 8 : 16;
        const DbgRegs *r = &g_regs, *p = &g_prev;
        for (int i = 0; i < 10 && y < y1; i++) {
            uint64_t cur = reg_val(r, i);
            bool chg = g_prev_ok && cur != reg_val(p, i);
            uint8_t t;
            attr_t ua = i != 9 && dbg_read_mem(cur, &t, 1) ? A_UNDERLINE : 0;   /* an address: clickable */
            snprintf(line, sizeof line, "%-6s ", reg_name(i));
            int xx = piece(win, y, x, w, COLOR_PAIR(COLOR_PAIR_TYPE), line);
            snprintf(line, sizeof line, "0x%0*llx", dig, (unsigned long long)cur);
            v->reg_y[i] = y; v->reg_x0[i] = x0 + 1; v->reg_x1[i] = w;
            piece(win, y++, xx, w, (chg ? COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD : COLOR_PAIR(COLOR_PAIR_NORMAL)) | ua, line);
            if (i == 0 && y < y1) {                  /* where rip is */
                char nb[200], where[120] = "";
                uint64_t fa;
                bool in_file = dbg_to_file(r->rip, &fa);
                const char *nm;
                if (in_file)
                    snprintf(where, sizeof where, "%.100s", (nm = da_name_for(&v->d, fa, nb, sizeof nb)) ? nm : "(no name)");
                else if (map_name(dbg_pid(), r->rip, nb, sizeof nb))
                    snprintf(where, sizeof where, "in %.100s", nb);
                if (where[0]) piece(win, y++, x + 7, w, COLOR_PAIR(COLOR_PAIR_COMMENT), where);
                uint8_t code[8];                     /* its bytes, as the program has them */
                if (y < y1 && dbg_read_mem(r->rip, code, sizeof code)) {
                    size_t avail = 0, u = 0;
                    const uint8_t *fp = in_file ? elf_va_ptr(&v->d.elf, fa, &avail) : NULL;
                    bool differs = fp && avail >= sizeof code && memcmp(fp, code, sizeof code);
                    line[0] = '\0';
                    for (size_t k = 0; k < sizeof code; k++) u += (size_t)snprintf(line + u, sizeof line - u, "%02x ", code[k]);
                    if (differs) snprintf(line + u, sizeof line - u, "≠ file");
                    piece(win, y++, x + 7, w, differs ? COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD : COLOR_PAIR(COLOR_PAIR_COMMENT), line);
                }
            }
            y = draw_reg_peek(v, win, i, x + 7, y, y1, w);
        }
        if (y < y1) {                                /* rflags, decoded */
            static const struct { int bit; const char *n; } fl[] = {
                { 0, "CF" }, { 2, "PF" }, { 4, "AF" }, { 6, "ZF" }, { 7, "SF" },
                { 8, "TF" }, { 9, "IF" }, { 10, "DF" }, { 11, "OF" } };
            size_t u = 0;
            line[0] = '\0';
            for (size_t k = 0; k < sizeof fl / sizeof fl[0]; k++)
                if (r->rflags >> fl[k].bit & 1)
                    u += (size_t)snprintf(line + u, sizeof line - u, "%s%s", u ? " " : "", fl[k].n);
            piece(win, y++, x + 7, w, COLOR_PAIR(COLOR_PAIR_COMMENT), line);
        }
        if (y < y1) y = draw_stack_args(v, win, x, y, y1, w);
        if (!w32 && w - x >= 46 && y1 - y >= 12) {   /* r8-r15, on two columns; a peeked one: under its row */
            for (int row = 0; row < 4 && y < y1; row++) {
                int pk = -1;
                for (int c = 0; c < 2; c++) {
                    int i = 10 + row * 2 + c, cx = x + c * 23;
                    uint64_t cur = reg_val(r, i);
                    uint8_t t;
                    attr_t ua = dbg_read_mem(cur, &t, 1) ? A_UNDERLINE : 0;
                    snprintf(line, sizeof line, "%-3s ", reg_name(i));
                    int xx = piece(win, y, cx, w, COLOR_PAIR(COLOR_PAIR_TYPE), line);
                    snprintf(line, sizeof line, "0x%016llx", (unsigned long long)cur);
                    piece(win, y, xx, w, (g_prev_ok && cur != reg_val(p, i) ? COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD
                                                                           : COLOR_PAIR(COLOR_PAIR_NORMAL)) | ua, line);
                    v->reg_y[i] = y; v->reg_x0[i] = c ? cx : x0 + 1; v->reg_x1[i] = c ? w : cx + 23;
                    if (v->peek_on && v->peek_k == 2 + i) pk = i;
                }
                y++;
                if (pk >= 0) y = draw_reg_peek(v, win, pk, x + 4, y, y1, w);
            }
        }
        y++;
    }
    if (y < y1) {
        int n = dbg_bp_list(NULL, 0);
        if (g_nauto) snprintf(line, sizeof line, "%d breakpoint%s (%d on input)", n, n == 1 ? "" : "s", g_nauto);
        else snprintf(line, sizeof line, "%d breakpoint%s", n, n == 1 ? "" : "s");
        piece(win, y++, x, w, COLOR_PAIR(COLOR_PAIR_NORMAL), line);
    }
    y++;
    draw_console(v, win, y, y1, x, w);
}

/* L: the breakpoints, in the panel: mark, address, name, passes, condition,
 * why it is not placed. The selected line's one first when they do not all
 * fit. */
static void draw_bps(const DisView *v, WINDOW *win, int x0, int y0, int y1, int w) {
    wattrset(win, COLOR_PAIR(COLOR_PAIR_INACTIVE_BORDER));
    for (int y = y0; y < y1; y++) mvwaddch(win, y, x0, ACS_VLINE);
    wattrset(win, A_NORMAL);
    int x = x0 + 2, y = y0, n = dbg_bp_list(NULL, 0);
    char line[200];
    snprintf(line, sizeof line, "BREAKPOINTS  %d/%d", n, DBG_MAX_BP);
    piece(win, y++, x, w, COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD, line);
    if (!n) { piece(win, y, x, w, COLOR_PAIR(COLOR_PAIR_COMMENT), "none  ·  b: this line  ·  B: by name"); return; }
    uint64_t cur = v->dsel < v->ndl ? v->dl[v->dsel].addr : 0;
    int rows = y1 - y, first = 0, on = dbg_bp_stopped_on();
    if (n > rows) {                                  /* around the selected line */
        int k = dbg_bp_index(cur);
        if (k > rows / 2) first = k - rows / 2;
        if (first > n - rows) first = n - rows;
        if (first < 0) first = 0;
    }
    for (int i = first; i < n && y < y1; i++) {
        DbgBp b;
        if (!dbg_bp_info(i, &b)) break;
        char nb[200], where[160], tail[120];
        const char *nm = b.main ? da_name_for(&v->d, b.va, nb, sizeof nb) : NULL;
        if (b.main) snprintf(where, sizeof where, "0x%llx %.60s", (unsigned long long)b.va, nm ? nm : "");
        else snprintf(where, sizeof where, "%.60s+0x%llx", b.module, (unsigned long long)b.rva);
        static const char *const st[] = { "", "", "pending", "not mapped", "not code", "shared", "hw refused" };
        size_t u = (size_t)snprintf(tail, sizeof tail, " ×%llu", (unsigned long long)b.hits);
        if (b.has_cond) u += (size_t)snprintf(tail + u, sizeof tail - u, " if %s", b.cond);
        if ((unsigned)b.state < sizeof st / sizeof st[0] && st[b.state][0])
            u += (size_t)snprintf(tail + u, sizeof tail - u, " [%s]", st[b.state]);
        if (b.overwritten) snprintf(tail + u, sizeof tail - u, " [overwritten]");
        bool bad = b.overwritten || (b.state >= DBG_BPS_UNMAPPED);
        attr_t a = i == on ? COLOR_PAIR(HEX_CP_CURSOR_A) | A_BOLD
                 : b.main && b.va == cur ? COLOR_PAIR(COLOR_PAIR_SELECTION) | A_BOLD
                 : !b.enabled ? COLOR_PAIR(COLOR_PAIR_COMMENT) : COLOR_PAIR(COLOR_PAIR_NORMAL);
        int xx = piece(win, y, x, w, a, !b.enabled ? "○ " : b.hw ? "◆ " : "• ");
        xx = piece(win, y, xx, w, a, where);
        piece(win, y++, xx, w, bad ? COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD : COLOR_PAIR(COLOR_PAIR_COMMENT), tail);
    }
}

/* title bar, function header (h >= 4), lines, bottom bar (h >= 3); the
 * register panel on the right while the debuggee of this file lives */
/* The choice of Enter (v->pick_*): a box under the line of the selection
 * (above it when there is no room), rows y0 .. y1 of the lines */
static void draw_pick(DisView *v, WINDOW *win, int row, int y0, int y1, int w) {
    int n = v->npick, lw = 0;
    char e[8][180];
    for (int k = 0; k < n; k++) {
        snprintf(e[k], sizeof e[k], " %d  %s ", k + 1, v->pick_s[k]);
        int c = str_cols(e[k]);
        if (c > lw) lw = c;
    }
    int bw = lw + 2, x = 8;
    if (bw > w - 2) bw = w - 2;
    if (x + bw > w) x = w - bw > 0 ? w - bw : 0;
    if (bw < 8) { v->npick = 0; return; }
    int y = row + 1;                                 /* the box: n rows + its two borders */
    if (y + n + 2 > y1) y = row - n - 2;
    if (y < y0 - 1) y = y0 - 1;
    attr_t box = COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD, hs = COLOR_PAIR(COLOR_PAIR_SELECTION) | A_BOLD;
    wattrset(win, box);
    mvwaddch(win, y, x, ACS_ULCORNER); mvwhline(win, y, x + 1, ACS_HLINE, bw - 2); mvwaddch(win, y, x + bw - 1, ACS_URCORNER);
    mvwaddstr(win, y, x + 2, " go to ");
    for (int k = 0; k < n; k++) {
        int ry = y + 1 + k;
        wattrset(win, box);
        mvwaddch(win, ry, x, ACS_VLINE); mvwaddch(win, ry, x + bw - 1, ACS_VLINE);
        wattrset(win, k == v->pick_sel ? hs : COLOR_PAIR(COLOR_PAIR_NORMAL));
        mvwhline(win, ry, x + 1, ' ', bw - 2);
        put_clip(win, ry, x + 1, e[k], x + bw - 1);
    }
    wattrset(win, box);
    mvwaddch(win, y + n + 1, x, ACS_LLCORNER); mvwhline(win, y + n + 1, x + 1, ACS_HLINE, bw - 2);
    mvwaddch(win, y + n + 1, x + bw - 1, ACS_LRCORNER);
    wattrset(win, A_NORMAL);
    v->pick_y = y + 1; v->pick_x = x + 1; v->pick_w = bw - 2;
}

static void render_disasm(DisView *v, WINDOW *win, int h, int w) {
    const Disasm *d = &v->d;
    int rows = list_rows(h), y0 = h >= 4 ? 2 : 1;
    char line[640];
    v->drip_ok = false;
    v->dpanel = 0;
    v->sarg_y0[0] = v->sarg_y0[1] = 0;               /* draw_stack_args sets them */
    memset(v->reg_y, 0, sizeof v->reg_y);            /* draw_regs too */
    if (v->dfn < 0 || (size_t)v->dfn >= d->nfn) return;
    const DisFunc *fn = &d->fn[v->dfn];
    v->drip_ok = dbg_mine(v) && dbg_rip(&v->drip, NULL);
    int full = w;
    if (dbg_mine(v) && (dbg_state() != DBG_NONE || v->bp_panel) && w >= 72 && h >= 4) {
        int pw = w / 3 < DBG_PANEL_W ? DBG_PANEL_W : w / 3 > DBG_PANEL_MAX ? DBG_PANEL_MAX : w / 3;
        v->dpanel = w - pw;
        w = v->dpanel;                               /* the lines stop before it */
    }
    if (h >= 4) {
        uint64_t end = v->dmain ? v->dl[v->dmain - 1].addr + v->dl[v->dmain - 1].len : v->dva;
        char extra[320] = "";
        size_t u = 0;
        if (v->dmain < v->ndl)
            u += (size_t)snprintf(extra + u, sizeof extra - u, "  ·  + .cold part at 0x%llx", (unsigned long long)fn->cold);
        if (v->dguess)
            u += (size_t)snprintf(extra + u, sizeof extra - u, "  ·  size unknown: up to the next function");
        if (v->dclip && u < sizeof extra) {
            const ElfSection *s = elf_section_at(&d->elf, v->dva);
            u += (size_t)snprintf(extra + u, sizeof extra - u, "  ·  size %llu runs past the end of %.40s: cut",
                                  (unsigned long long)fn->size, s ? s->name : "its segment");
        }
        if (v->dtrunc && u < sizeof extra)
            u += (size_t)snprintf(extra + u, sizeof extra - u, "  ·  cut to %llu KiB", (unsigned long long)(v->dlen >> 10));
        if (end < v->dva + v->dlen && u < sizeof extra)    /* da_linear stopped at bss / a gap */
            snprintf(extra + u, sizeof extra - u, "  ·  stops at 0x%llx (not in the file)", (unsigned long long)end);
        snprintf(line, sizeof line, "   %.160s  ·  0x%llx-0x%llx  ·  %llu bytes  ·  %zu lines  ·  %s%s",
                 fn->name ? fn->name : "?", (unsigned long long)v->dva, (unsigned long long)end,
                 (unsigned long long)(end - v->dva), v->ndl, fn_kind_name(fn->kind), extra);
        piece(win, 1, 0, w, COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD, line);
    }
    keep_in_view(&v->dsel, &v->dtop, v->ndl, rows);
    for (int r = 0; r < rows && v->dtop + (size_t)r < v->ndl; r++)
        draw_dl_row(v, win, y0 + r, w, v->dtop + (size_t)r, v->dtop + (size_t)r == v->dsel);
    if (v->dpanel) {
        if (v->bp_panel) draw_bps(v, win, v->dpanel, 1, h - 1, full);
        else draw_regs(v, win, v->dpanel, 1, h - 1, full);
    }
    if (v->npick) draw_pick(v, win, y0 + (int)(v->dsel - v->dtop), y0, y0 + rows, full);
    w = full;

    if (h < 3) return;
    if (v->in_mode != IN_NONE) { draw_prompt(v, win, h - 1, w); return; }
    char off[64] = "";
    if (v->doff) snprintf(off, sizeof off, "  ·  %zu ! (not decoded by the analysis)", v->doff);
    snprintf(line, sizeof line, " %zu/%zu%s  ·  ", v->ndl ? v->dsel + 1 : 0, v->ndl, off);
    bar(win, h - 1, w, COLOR_PAIR_LINENUM, 0, "");
    int x = piece(win, h - 1, 0, w, COLOR_PAIR(COLOR_PAIR_LINENUM), line);
    if (v->npick) piece(win, h - 1, x, w, COLOR_PAIR(COLOR_PAIR_LINENUM),
                        "↑/↓: choose  ·  Enter/click: go there  ·  1-9: that one  ·  Esc: cancel");
    else if (v->msg[0]) piece(win, h - 1, x, w, COLOR_PAIR(v->msg_pair) | A_BOLD, v->msg);
    else piece(win, h - 1, x, w, COLOR_PAIR(COLOR_PAIR_LINENUM),
               "b: breakpoint  ·  B: by name, condition  ·  e: on/off  ·  h: hardware  ·  L: list  ·  n: next  ·  a: arguments  ·  F5: run / continue  ·  F6: step this thread (from main)  ·  F7: step over  ·  p: pause  ·  1 / 2: follow [esp+4] / [esp+8]  ·  K / Shift-F5: kill  ·  i: console  ·  "
               "Enter/click: follow the address  ·  Backspace: back  ·  :: go to address  ·  d: data  ·  "
               "Esc: back to the list  ·  Tab: data  ·  F9: close");
}

/* ─── Data screens ─────────────────────────────────────────────── */

/* bottom bar of a screen: its position and keys, or the message, or the
 * prompt while an address is typed */
static void draw_bottom(const DisView *v, WINDOW *win, int h, int w, const char *pos, const char *keys) {
    if (h < 3) return;
    if (v->in_mode != IN_NONE) { draw_prompt(v, win, h - 1, w); return; }
    bar(win, h - 1, w, COLOR_PAIR_LINENUM, 0, "");
    int x = piece(win, h - 1, 0, w, COLOR_PAIR(COLOR_PAIR_LINENUM), pos);
    if (v->msg[0]) piece(win, h - 1, x, w, COLOR_PAIR(v->msg_pair) | A_BOLD, v->msg);
    else           piece(win, h - 1, x, w, COLOR_PAIR(COLOR_PAIR_LINENUM), keys);
}

/* the columns of the section list: SECTION (stays), ADDRESS, SIZE, RWX, TYPE, CONTENTS */
enum { DS_COLS = 6 };

static void draw_ds_row(const DisView *v, WINDOW *win, int y, int w, size_t i, bool sel, const int *cw, bool *cut) {
    const DataSec *s = &v->ds[i];
    attr_t hs = COLOR_PAIR(COLOR_PAIR_SELECTION) | A_BOLD;
    if (sel) { wattrset(win, hs); mvwhline(win, y, 0, ' ', w); wattrset(win, A_NORMAL); }
    char a[24], sz[24], hsz[16], nm[72];
    snprintf(a, sizeof a, "0x%0*llx", v->aw, (unsigned long long)s->addr);
    human_size(s->size, hsz, sizeof hsz);
    snprintf(sz, sizeof sz, "%10s", hsz);
    snprintf(nm, sizeof nm, "   %.60s", s->name);
    Blk b = { win, y, w, DS_COLS, v->dscol, 0, cw, 0, 0, 0, 0,
              sel ? hs : COLOR_PAIR(COLOR_PAIR_INACTIVE_BORDER) | A_DIM, cut };
    blk_cell(&b, sel ? hs : COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD, nm);
    blk_cell(&b, sel ? hs : COLOR_PAIR(COLOR_PAIR_LINENUM), a);
    blk_cell(&b, sel ? hs : COLOR_PAIR(COLOR_PAIR_NORMAL), sz);
    blk_cell(&b, sel ? hs : COLOR_PAIR(s->perm[1] == 'w' ? COLOR_PAIR_STRING : COLOR_PAIR_NORMAL), s->perm);
    blk_cell(&b, sel ? hs : COLOR_PAIR(COLOR_PAIR_COMMENT), s->type ? s->type : "?");
    const char *desc = s->bad ? "its bytes lie outside the file" : s->desc;
    blk_cell(&b, sel ? hs : COLOR_PAIR(s->bad ? COLOR_PAIR_NUMBER : COLOR_PAIR_COMMENT), desc);
}

static void render_data(DisView *v, WINDOW *win, int h, int w) {
    int rows = list_rows(h), y0 = h >= 4 ? 2 : 1;
    int nw = 7;                                       /* "SECTION" */
    for (size_t i = 0; i < v->nds; i++) {
        int n = str_cols(v->ds[i].name);
        if (n > nw) nw = n > 24 ? 24 : n;
    }
    const int cw[DS_COLS] = { 4 + nw, v->aw + 2, 10, 3, 10, 0 };
    static const char *const name[DS_COLS] = { "   SECTION", "ADDRESS", "      SIZE", "RWX", "TYPE", "CONTENTS" };
    if (v->dscol < 1) v->dscol = 1;
    bool cut = false;
    keep_in_view(&v->dssel, &v->dstop, v->nds, rows);
    for (int r = 0; r < rows && v->dstop + (size_t)r < v->nds; r++)
        draw_ds_row(v, win, y0 + r, w, v->dstop + (size_t)r, v->dstop + (size_t)r == v->dssel, cw, &cut);
    v->ds_more = blk_more_right(cw, DS_COLS, v->dscol, w) || (cut && v->dscol < DS_COLS - 1);
    if (h >= 4) blk_header(win, 1, w, cw, name, DS_COLS, v->dscol, v->ds_more);
    if (rows > 0 && !v->nds)
        piece(win, y0, 0, w, COLOR_PAIR(COLOR_PAIR_COMMENT),
              v->ds || !v->d.elf.nsec ? "   No data section in this file" : "   Section list unavailable (out of memory)");
    char pos[64];
    snprintf(pos, sizeof pos, " %zu/%zu  ·  ", v->nds ? v->dssel + 1 : 0, v->nds);
    bool cols = v->dscol > 1 || v->ds_more;
    draw_bottom(v, win, h, w, pos, cols ? "Enter/click: contents  ·  ←/→: columns  ·  :: go to address  ·  Backspace: back  ·  "
                                          "d/Esc: leave  ·  Tab: info  ·  F9: close"
                                        : "Enter/click: contents  ·  :: go to address  ·  Backspace: back  ·  "
                                          "d/Esc: leave  ·  Tab: info  ·  F9: close");
}

/* s[0 .. n) as a quoted C string, escaped, cut to the room in out */
static void quote(const uint8_t *s, size_t n, char *out, size_t osz) {
    size_t o = 0;
    if (osz < 8) { if (osz) *out = '\0'; return; }
    out[o++] = '"';
    size_t i = 0;
    for (; i < n && s[i]; ) {
        const char *e = s[i] == '\n' ? "\\n" : s[i] == '\t' ? "\\t" : s[i] == '\r' ? "\\r"
                      : s[i] == '"' ? "\\\"" : s[i] == '\\' ? "\\\\" : NULL;
        size_t k = 1;
        if (!e && s[i] >= 0x80) {
            uint32_t cp;
            int u = utf8_decode((const char *)s + i, n - i, &cp);
            k = u > 0 ? (size_t)u : 1;
        }
        size_t need = e ? 2 : k;
        if (o + need + 5 > osz) break;
        if (e) { out[o++] = e[0]; out[o++] = e[1]; }
        else for (size_t j = 0; j < k; j++) out[o++] = (s[i + j] < 0x20 || s[i + j] == 0x7f) ? '.' : (char)s[i + j];
        i += k;
    }
    if (i < n && s[i]) { memcpy(out + o, "...", 3); o += 3; }
    out[o++] = '"';
    out[o] = '\0';
}

/* what the address t held at slot means: import, function, string,
 * symbol, section */
static void ptr_text(const DisView *v, uint64_t slot, uint64_t t, char *out, size_t sz) {
    const Disasm  *d  = &v->d;
    const ElfFile *ef = &d->elf;
    char nb[200];
    const ElfImport *im = elf_import_got(ef, slot);
    if (im) {
        if (im->plt) snprintf(out, sz, "→ %s  (import, stub 0x%llx)", im->name, (unsigned long long)im->plt);
        else         snprintf(out, sz, "%s  (import, filled by the loader)", im->name);
        return;
    }
    if (elf_va_code(ef, t)) {
        snprintf(out, sz, "→ 0x%llx  %s", (unsigned long long)t, da_name_for(d, t, nb, sizeof nb) ? nb : "(code)");
        return;
    }
    size_t avail = 0;
    const uint8_t *p = elf_va_ptr(ef, t, &avail);
    size_t sl, stop;
    if (p && str_run(p, avail < 512 ? avail : 512, &sl, &stop)) {
        quote(p, sl, nb, sizeof nb > 90 ? 90 : sizeof nb);
        snprintf(out, sz, "→ 0x%llx  %s", (unsigned long long)t, nb);
        return;
    }
    uint64_t delta = 0;
    const ElfSymbol *sy = elf_symbol_near(ef, t, &delta);
    long si = data_sec_at(v, t);
    if (sy && delta < 0x10000) {
        if (delta) snprintf(out, sz, "→ 0x%llx  %s+0x%llx", (unsigned long long)t, sy->name, (unsigned long long)delta);
        else       snprintf(out, sz, "→ 0x%llx  %s", (unsigned long long)t, sy->name);
    } else if (si >= 0) {
        snprintf(out, sz, "→ 0x%llx  %s+0x%llx", (unsigned long long)t, v->ds[si].name,
                 (unsigned long long)(t - v->ds[si].addr));
    } else {
        snprintf(out, sz, "→ 0x%llx", (unsigned long long)t);
    }
}

/* Decimal value of a hex row, little-endian: one number of its symbol's
 * size (1, 2, 4 or 8 bytes: an int, a long...), else, when the row is
 * 4-aligned and made of whole 4-byte words, each word (int32) or a lone
 * 2-byte one. With the top bit set: signed, and for a lone value its
 * unsigned reading too. "" when none applies or all the bytes are 0. */
static void data_dec(const DisView *v, const DataItem *it, const uint8_t *p, size_t nb, char *out, size_t sz) {
    if (!sz) return;
    out[0] = '\0';
    if (!p || it->kind != DT_HEX) return;
    const ElfSymbol *sy = elf_symbol_at(&v->d.elf, it->addr);
    size_t ws = 0, nw = 0;
    if (sy && (sy->size == 1 || sy->size == 2 || sy->size == 4 || sy->size == 8) && nb >= sy->size) {
        ws = (size_t)sy->size; nw = 1;
    } else if (!(it->addr & 3) && nb >= 4 && !(nb & 3)) {
        ws = 4; nw = nb / 4;
    } else if (!(it->addr & 1) && nb == 2) {
        ws = 2; nw = 1;
    }
    size_t z = 0;
    while (z < nw * ws && !p[z]) z++;
    if (z == nw * ws) return;                    /* all zero: nothing to say */
    size_t o = 0;
    for (size_t k = 0; k < nw && o + 2 < sz; k++) {
        uint64_t x = 0, u;
        int64_t sv;
        for (size_t b = 0; b < ws; b++) x |= (uint64_t)p[k * ws + b] << (8 * b);
        num_split(x, (unsigned)ws, &u, &sv);
        const char *sep = k ? ", " : "; ";
        if (sv < 0 && nw == 1)   /* the file does not say if it is signed */
            o += (size_t)snprintf(out + o, sz - o, "%s%lld (unsigned %llu)", sep, (long long)sv, (unsigned long long)u);
        else if (sv < 0) o += (size_t)snprintf(out + o, sz - o, "%s%lld", sep, (long long)sv);
        else             o += (size_t)snprintf(out + o, sz - o, "%s%llu", sep, (unsigned long long)u);
    }
}

/* The columns of a section's rows: ADDRESS (with the link mark, stays),
 * SYMBOL (when one of the rows starts a symbol), BYTES, VALUE (ASCII,
 * string, target; the decimal value of a hex row after its ASCII). */
static int dump_cols(const DisView *v, int *cw, const char **name) {
    int n = 0;
    cw[n] = 3 + v->aw + 3;    name[n++] = "   ADDRESS";
    if (v->xsymw) { cw[n] = v->xsymw; name[n++] = "SYMBOL"; }
    cw[n] = (int)DATA_HEX * 3;     name[n++] = "BYTES";
    cw[n] = 0;                name[n++] = "VALUE";
    return n;
}

/* the dump shows the names of its columns under its title */
static int dump_hdr(int h) { return h >= 5; }

/* one row of a section: link mark, address, symbol starting there,
 * bytes, then the text (ASCII, string, target) */
static void draw_x_row(const DisView *v, WINDOW *win, int y, int w, size_t i, bool sel, const int *cw, int ncol,
                       bool *cut) {
    const ElfFile *ef = &v->d.elf;
    const DataItem *it = &v->xi[i];
    attr_t hs = COLOR_PAIR(COLOR_PAIR_SELECTION) | A_BOLD;
    if (sel) { wattrset(win, hs); mvwhline(win, y, 0, ' ', w); wattrset(win, A_NORMAL); }
    uint64_t t;
    bool link = item_link(v, it, &t);
    char a[24], hex[DATA_HEX * 3 + 8] = "", txt[400] = "", dec[128] = "";
    snprintf(a, sizeof a, "0x%0*llx", v->aw, (unsigned long long)it->addr);
    const ElfSymbol *sy = v->xsymw ? elf_symbol_at(ef, it->addr) : NULL;
    size_t avail = 0;
    const uint8_t *p = it->kind == DT_ZERO && it->addr >= v->ds[v->xsec].addr + v->ds[v->xsec].filesz
                     ? NULL : elf_va_ptr(ef, it->addr, &avail);
    size_t nb = p ? (it->len < avail ? it->len : avail) : 0;
    size_t u = 0, show = nb < DATA_HEX ? nb : DATA_HEX;
    if (it->kind == DT_ZERO) show = 0;
    for (size_t k = 0; k < show; k++) u += (size_t)snprintf(hex + u, sizeof hex - u, "%02x ", p[k]);
    if (u) hex[u - 1] = '\0';
    if (it->kind == DT_STR && nb > DATA_HEX && u >= 3) snprintf(hex + u - 1, sizeof hex - u + 1, "…");
    attr_t ta = COLOR_PAIR(COLOR_PAIR_NORMAL);
    switch (it->kind) {
        case DT_STR: {
            char q[300];
            quote(p, nb, q, sizeof q);
            snprintf(txt, sizeof txt, "%s", q);
            ta = COLOR_PAIR(COLOR_PAIR_STRING);
            break;
        }
        case DT_PTR:
            ptr_text(v, it->addr, it->target, txt, sizeof txt);
            ta = link ? COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD : COLOR_PAIR(COLOR_PAIR_COMMENT);
            break;
        case DT_ZERO:
            if (p) snprintf(hex, sizeof hex, "00 × %u", it->len);
            snprintf(txt, sizeof txt, p ? "%u zero bytes" : "%u bytes, zero at start (not in the file)", it->len);
            ta = COLOR_PAIR(COLOR_PAIR_COMMENT);
            break;
        default: {
            size_t o = 0;
            for (size_t k = 0; k < show && o + 1 < sizeof txt; k++)
                txt[o++] = p[k] >= 0x20 && p[k] < 0x7f ? (char)p[k] : '.';
            txt[o] = '\0';
            data_dec(v, it, p, show, dec, sizeof dec);
            break;
        }
    }
    Blk b = { win, y, w, ncol, v->xcol, 0, cw, 0, 0, 0, 0,
              sel ? hs : COLOR_PAIR(COLOR_PAIR_INACTIVE_BORDER) | A_DIM, cut };
    blk_cell(&b, sel ? hs : COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD, link ? " → " : "   ");
    blk_more(&b, 3, 0, sel ? hs : COLOR_PAIR(COLOR_PAIR_LINENUM), a);
    if (v->xsymw) blk_cell(&b, sel ? hs : COLOR_PAIR(COLOR_PAIR_KEYWORD), sy && sy->name ? sy->name : "");
    blk_cell(&b, sel ? hs : COLOR_PAIR(COLOR_PAIR_COMMENT), hex);
    blk_cell(&b, sel ? hs : ta, txt);
    if (dec[0]) blk_more(&b, (int)DATA_HEX + 2, 2, sel ? hs : COLOR_PAIR(COLOR_PAIR_NUMBER), dec);   /* "; 456" */
}

static void render_dump(DisView *v, WINDOW *win, int h, int w) {
    int hd = dump_hdr(h), rows = list_rows(h) - hd, y0 = (h >= 4 ? 2 : 1) + hd;
    if (v->xsec < 0 || (size_t)v->xsec >= v->nds) return;
    const DataSec *s = &v->ds[v->xsec];
    char line[512], hsz[16];
    if (h >= 4) {
        human_size(s->size, hsz, sizeof hsz);
        snprintf(line, sizeof line, "   %.60s  ·  0x%llx-0x%llx  ·  %s  ·  %s  ·  %zu rows%s%s%s",
                 s->name, (unsigned long long)s->addr, (unsigned long long)(s->addr + s->size), hsz, s->perm,
                 v->nxi, v->xtrunc ? "  ·  cut (too big)" : "", s->desc[0] ? "  ·  " : "", s->desc);
        piece(win, 1, 0, w, COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD, line);
    }
    int cw[4];
    const char *name[4];
    int n = dump_cols(v, cw, name);
    if (v->xcol < 1) v->xcol = 1;
    if (v->xcol > n - 1) v->xcol = n - 1;                 /* another section, no SYMBOL column */
    bool cut = false;
    keep_in_view(&v->xsel, &v->xtop, v->nxi, rows);
    for (int r = 0; r < rows && v->xtop + (size_t)r < v->nxi; r++)
        draw_x_row(v, win, y0 + r, w, v->xtop + (size_t)r, v->xtop + (size_t)r == v->xsel, cw, n, &cut);
    v->x_more = blk_more_right(cw, n, v->xcol, w) || (cut && v->xcol < n - 1);
    if (hd) blk_header(win, 2, w, cw, name, n, v->xcol, v->x_more);
    char pos[64];
    snprintf(pos, sizeof pos, " %zu/%zu  ·  ", v->nxi ? v->xsel + 1 : 0, v->nxi);
    bool cols = v->xcol > 1 || v->x_more;
    draw_bottom(v, win, h, w, pos, cols ? "→ Enter/click: follow  ·  ←/→: columns  ·  :: go to address  ·  Backspace: back  ·  "
                                          "Esc: sections  ·  d: leave  ·  F9: close"
                                        : "→ Enter/click: follow  ·  :: go to address  ·  Backspace: back  ·  "
                                          "Esc: sections  ·  d: leave  ·  F9: close");
}

void dis_render(DisView *v, WINDOW *win, int h, int w) {
    if (!v || !win || h < 1 || w < 4) return;
    dbg_sync(v, list_rows(h));                       /* a new stop of the debuggee: its rip line */
    if (v->wait_seen != g_wait_gen) {                /* it waits for its input: the keys go to it */
        v->wait_seen = g_wait_gen;
        if (g_wait && dbg_mine(v) && v->screen == SCR_DISASM && v->in_mode == IN_NONE) {
            v->in_mode = IN_CONSOLE;
            v->in_buf[0] = '\0';
            v->con_auto = true;
        }
    }
    if (v->con_auto && !g_wait && v->in_mode == IN_CONSOLE && !v->in_buf[0]) {
        v->in_mode = IN_NONE;                        /* its input read: the keys come back */
        v->con_auto = false;
    }
    werase(win);
    const ElfFile *ef = &v->d.elf;
    char line[512];
    static const char *const scr[] = { "INFO", "FUNCTIONS", "DISASSEMBLY", "DATA SECTIONS", "DATA" };
    snprintf(line, sizeof line, " DISASM  ·  %s  ·  %.200s  ·  %s %s  ·  %zu functions  ·  %zu data sections",
             scr[v->screen], base_name(v->path), elf_machine_name(ef->machine), elf_kind_name(ef),
             v->d.nfn, v->nds);
    bar(win, 0, w, HEX_CP_HEADER, A_BOLD, line);
    if (v->screen == SCR_FUNCS) render_funcs(v, win, h, w);
    else if (v->screen == SCR_DISASM) render_disasm(v, win, h, w);
    else if (v->screen == SCR_DATA) render_data(v, win, h, w);
    else if (v->screen == SCR_DUMP) render_dump(v, win, h, w);
    else render_info(v, win, h, w);
    wnoutrefresh(win);
}

static void move_sel(size_t *sel, size_t n, long delta) {
    if (!n) return;
    long s = (long)*sel + delta;
    if (s < 0) s = 0;
    if (s >= (long)n) s = (long)n - 1;
    *sel = (size_t)s;
}

/* moves a selection among n rows, `rows` of them shown; `letters`:
 * j k g G Space too (not while typing). false: not a move key */
static bool nav_key(int key, int rows, size_t *sel, size_t n, bool letters) {
    long page = rows > 1 ? rows - 1 : 1;
    if (letters)
        switch (key) {
            case 'k': key = KEY_UP;    break;
            case 'j': key = KEY_DOWN;  break;
            case ' ': key = KEY_NPAGE; break;
            case 'g': key = KEY_HOME;  break;
            case 'G': key = KEY_END;   break;
        }
    switch (key) {
        case KEY_UP:    move_sel(sel, n, -1);    break;
        case KEY_DOWN:  move_sel(sel, n, 1);     break;
        case KEY_PPAGE: move_sel(sel, n, -page); break;
        case KEY_NPAGE: move_sel(sel, n, page);  break;
        case KEY_HOME:  *sel = 0;                break;
        case KEY_END:   *sel = n ? n - 1 : 0;    break;
        default: return false;
    }
    return true;
}

static bool list_nav(DisView *v, int key, int win_h, bool letters) {
    int rows = list_rows(win_h);
    if (!nav_key(key, rows, &v->sel, v->nvis, letters)) return false;
    keep_visible(v, rows);
    return true;
}

/* keys while typing into the console of the debuggee: a line is sent
 * with Enter (the pty echoes it into the output); ^C / ^D go as they
 * are; F5 / F6 / F7 still drive the program */
static bool console_key(DisView *v, int key, int win_h) {
    size_t n = strlen(v->in_buf);
    switch (key) {
        case 27:
            v->in_mode = IN_NONE;
            v->con_auto = false;
            return true;
        case '\n': case '\r': case KEY_ENTER:      /* typing leaves room for one byte more */
        case 'd' & 0x1f:                             /* end of input, after the line typed */
            v->in_buf[n] = key == ('d' & 0x1f) ? '\x04' : '\n';
            if (con_send(v, v->in_buf, n + 1)) n = 0;
            v->in_buf[n] = '\0';
            break;
        case 'c' & 0x1f:                             /* SIGINT to the program */
            con_send(v, "\x03", 1);
            v->in_buf[0] = '\0';
            break;
        case KEY_BACKSPACE: case 127: case '\b':
            if (n) v->in_buf[n - 1] = '\0';
            break;
        case 'u' & 0x1f:
            v->in_buf[0] = '\0';
            break;
        default:
            if (key == KEY_F(5) || key == KEY_F(6) || key == KEY_F(7)) { dbg_key_run(v, key, win_h); break; }
            if (key == KEY_F(17)) { dbg_key_kill(v); return true; }
            if (key >= 32 && key < 127) {
                if (n + 2 < sizeof v->in_buf) {      /* room for "\n" */
                    v->in_buf[n] = (char)key;
                    v->in_buf[n + 1] = '\0';
                }
                break;
            }
            if (v->screen == SCR_DISASM) {           /* arrows, pages: the disassembly still moves */
                int rows = list_rows(win_h);
                if (nav_key(key, rows, &v->dsel, v->ndl, false)) keep_in_view(&v->dsel, &v->dtop, v->ndl, rows);
            }
            break;                                   /* anything else is swallowed */
    }
    con_drain();                                     /* the echo, an answer */
    return true;
}

static bool input_key(DisView *v, int key, int win_h) {
    if (v->in_mode == IN_CONSOLE) return console_key(v, key, win_h);
    if (v->in_mode == IN_ARGS) v->msg[0] = '\0';     /* the error of the last Enter */
    size_t n = strlen(v->in_buf);
    switch (key) {
        case 27:
            cancel_input(v);
            return true;
        case '\n': case '\r': case KEY_ENTER:
            if (v->in_mode == IN_ARGS) {
                char abuf[sizeof v->args], *av[sizeof v->args / 2 + 2], e[120];
                int ac = split_args(v->in_buf, abuf, av, (int)(sizeof av / sizeof *av) - 1, e, sizeof e);
                if (ac < 0) {                        /* the prompt stays, to fix it */
                    snprintf(v->msg, sizeof v->msg, "   %s: fix it, or Esc to keep the old arguments", e);
                    return true;
                }
                v->in_mode = IN_NONE;
                snprintf(v->args, sizeof v->args, "%s", v->in_buf);
                if (!ac) list_msg(v, COLOR_PAIR_STRING, "no arguments for the next launches");
                else list_msg(v, COLOR_PAIR_STRING, "%d argument%s for the next F5 F6 F7 launches%s: %.180s", ac, ac == 1 ? "" : "s",
                              dbg_mine(v) ? " (the running program keeps its own)" : "", v->args);
            } else if (v->in_mode == IN_BREAK) {
                char line[sizeof v->in_buf];
                snprintf(line, sizeof line, "%s", v->in_buf);
                v->in_mode = IN_NONE;
                dbg_bp_command(v, line);
            } else if (v->in_mode == IN_GOTO) {
                v->in_mode = IN_NONE;
                uint64_t a;
                if (!n) ;
                else if (v->screen == SCR_FUNCS) list_goto(v, v->in_buf);
                else if (!parse_hex(v->in_buf, &a))
                    list_msg(v, COLOR_PAIR_KEYWORD, "not a hex address: \"%.60s\"", v->in_buf);
                else follow(v, a);
            } else {
                v->in_mode = IN_NONE;
                if (v->filter[0] && !v->nvis)
                    list_msg(v, COLOR_PAIR_KEYWORD, "no function name contains \"%.100s\"", v->filter);
            }
            return true;
        case KEY_BACKSPACE: case 127: case '\b':
            if (n) v->in_buf[n - 1] = '\0';
            break;
        case 'u' & 0x1f:
            v->in_buf[0] = '\0';
            break;
        default:
            if (key >= 32 && key < 127) {
                size_t cap = v->in_mode == IN_FILTER ? sizeof v->filter : sizeof v->in_buf;
                if (n + 1 < cap) { v->in_buf[n] = (char)key; v->in_buf[n + 1] = '\0'; }
                break;
            }
            if (v->in_mode == IN_FILTER) list_nav(v, key, win_h, false);
            return true;                       /* anything else is swallowed */
    }
    if (v->in_mode == IN_FILTER) {             /* the filter applies as it is typed */
        snprintf(v->filter, sizeof v->filter, "%.*s", (int)sizeof v->filter - 1, v->in_buf);
        list_filter(v, sel_fn(v));
    }
    return true;
}

static bool funcs_key(DisView *v, int key, int win_h) {
    switch (key) {
        case 's':
            v->sort = (v->sort + 1) % SORT_COUNT;
            list_sort(v);
            keep_visible(v, list_rows(win_h));
            return true;
        case '/':
            v->in_mode = IN_FILTER;
            snprintf(v->in_save, sizeof v->in_save, "%s", v->filter);
            snprintf(v->in_buf, sizeof v->in_buf, "%s", v->filter);
            return true;
        case ':':
            v->in_mode = IN_GOTO;
            v->in_buf[0] = '\0';
            return true;
        case '\n': case '\r': case KEY_ENTER:
            disasm_open(v, sel_fn(v));
            return true;
        case 27:
            if (!v->filter[0]) return false;   /* Esc: the caller closes the view */
            v->filter[0] = '\0';
            list_filter(v, sel_fn(v));
            keep_visible(v, list_rows(win_h));
            list_msg(v, COLOR_PAIR_STRING, "filter cleared");
            return true;
    }
    return list_nav(v, key, win_h, true);
}

/* the choice of Enter on a line that leads to several places */
static void pick_go(DisView *v) {
    uint64_t a = v->pick_t[v->pick_sel];
    v->npick = 0;
    follow(v, a);
}

static bool pick_key(DisView *v, int key) {
    if (key == KEY_UP || key == 'k')        { if (v->pick_sel > 0) v->pick_sel--; }
    else if (key == KEY_DOWN || key == 'j') { if (v->pick_sel + 1 < v->npick) v->pick_sel++; }
    else if (key >= '1' && key < '1' + v->npick) { v->pick_sel = key - '1'; pick_go(v); }
    else if (key == '\n' || key == '\r' || key == KEY_ENTER) pick_go(v);
    else v->npick = 0;                               /* Esc, any other key: no choice */
    return true;
}

static bool disasm_key(DisView *v, int key, int win_h) {
    if (key == 27) { v->screen = SCR_FUNCS; return true; }   /* back to the list */
    if (key == 'b') { dbg_key_bp(v); return true; }
    if (key == 'B') { v->in_mode = IN_BREAK; v->in_buf[0] = '\0'; return true; }
    if (key == 'a') {                                 /* arguments, prefilled with the last ones */
        v->in_mode = IN_ARGS;
        snprintf(v->in_buf, sizeof v->in_buf, "%s", v->args);
        return true;
    }
    if (key == 'e' || key == 'h') { dbg_key_bp_flag(v, key); return true; }
    if (key == 'L') { dbg_key_bp_panel(v); return true; }
    if (key == 'n') { dbg_key_bp_next(v); return true; }
    if (key == 'i') { dbg_key_console(v); return true; }
    if (key == 'p') { dbg_key_pause(v); return true; }
    if (key == '1' || key == '2') { stack_arg_go(v, key - '1'); return true; }
    if (key == 'K' || key == KEY_F(17)) { dbg_key_kill(v); return true; }
    if (key == KEY_F(5) || key == KEY_F(6) || key == KEY_F(7)) { dbg_key_run(v, key, win_h); return true; }
    if (key == '\n' || key == '\r' || key == KEY_ENTER) {    /* follow the address of the line */
        int n = line_targets(v, v->dsel, v->pick_t, v->pick_s, (int)(sizeof v->pick_t / sizeof *v->pick_t));
        if (!n) list_msg(v, COLOR_PAIR_NUMBER, "no address to follow on this line");
        else if (n == 1) follow(v, v->pick_t[0]);
        else { v->npick = n; v->pick_sel = 0; }     /* several: the choice */
        return true;
    }
    int rows = list_rows(win_h);
    if (!nav_key(key, rows, &v->dsel, v->ndl, true)) return false;
    keep_in_view(&v->dsel, &v->dtop, v->ndl, rows);
    return true;
}

static bool data_key(DisView *v, int key, int win_h) {
    if (key == 27) { v->screen = v->data_back; return true; }
    if (key == '\n' || key == '\r' || key == KEY_ENTER) { data_open(v, (long)v->dssel); return true; }
    if (blk_key(key, &v->dscol, DS_COLS, v->ds_more)) return true;
    int rows = list_rows(win_h);
    if (!nav_key(key, rows, &v->dssel, v->nds, true)) return false;
    keep_in_view(&v->dssel, &v->dstop, v->nds, rows);
    return true;
}

static bool dump_key(DisView *v, int key, int win_h) {
    if (key == 27) { v->screen = SCR_DATA; return true; }
    if (key == '\n' || key == '\r' || key == KEY_ENTER) {
        uint64_t t;
        if (v->xsel < v->nxi && item_link(v, &v->xi[v->xsel], &t)) follow(v, t);
        else list_msg(v, COLOR_PAIR_NUMBER, "no address to follow on this row");
        return true;
    }
    int cw[4];
    const char *name[4];
    if (blk_key(key, &v->xcol, dump_cols(v, cw, name), v->x_more)) return true;
    int rows = list_rows(win_h) - dump_hdr(win_h);
    if (!nav_key(key, rows, &v->xsel, v->nxi, true)) return false;
    keep_in_view(&v->xsel, &v->xtop, v->nxi, rows);
    return true;
}

static bool info_key(DisView *v, int key, int win_h) {
    int rows = body_rows(win_h);
    int page = rows > 1 ? rows - 1 : 1;
    switch (key) {
        case KEY_UP:   case 'k': v->scroll--;           break;
        case KEY_DOWN: case 'j': v->scroll++;           break;
        case KEY_PPAGE:          v->scroll -= page;     break;
        case KEY_NPAGE: case ' ': v->scroll += page;    break;
        case KEY_HOME: case 'g': v->scroll = 0;         break;
        case KEY_END:  case 'G': v->scroll = v->nln;    break;
        default: return false;
    }
    clamp_scroll(v, rows);
    return true;
}

bool dis_key(DisView *v, int key, int win_h) {
    if (!v) return false;
    dis_ui_poll();                                   /* a stop not collected yet */
    if (v->in_mode != IN_NONE) return input_key(v, key, win_h);
    v->msg[0] = '\0';
    if (v->npick && v->screen == SCR_DISASM) return pick_key(v, key);
    v->npick = 0;
    switch (key) {
        case '\t':   /* info -> list -> disassembly -> data -> dump -> info (the
                       * disassembly / dump once a function / section is open) */
            switch (v->screen) {
                case SCR_INFO:   v->screen = SCR_FUNCS; break;
                case SCR_FUNCS:  v->data_back = SCR_FUNCS; v->screen = v->dl ? SCR_DISASM : SCR_DATA; break;
                case SCR_DISASM: v->data_back = SCR_DISASM; v->screen = SCR_DATA; break;
                case SCR_DATA:   v->screen = v->xi ? SCR_DUMP : SCR_INFO; break;
                default:         v->screen = SCR_INFO; break;
            }
            return true;
        case 'd':                                /* data sections, and back */
            if (v->screen == SCR_DATA || v->screen == SCR_DUMP) v->screen = v->data_back;
            else { v->data_back = v->screen; v->screen = SCR_DATA; }
            return true;
        case ':':
            if (v->screen == SCR_FUNCS) break;   /* funcs_key opens it */
            v->in_mode = IN_GOTO;
            v->in_buf[0] = '\0';
            return true;
        case KEY_BACKSPACE: case 127: case '\b':
            hist_back(v);
            return true;
    }
    if (v->screen == SCR_FUNCS)  return funcs_key(v, key, win_h);
    if (v->screen == SCR_DISASM) return disasm_key(v, key, win_h);
    if (v->screen == SCR_DATA)   return data_key(v, key, win_h);
    if (v->screen == SCR_DUMP)   return dump_key(v, key, win_h);
    return info_key(v, key, win_h);
}

/* Mouse, at (y, x) of the pane window: the wheel scrolls, a click on a
 * row selects it and acts as Enter on it (opens the function / section,
 * follows the address of a line or row). */
bool dis_mouse(DisView *v, int y, int x, unsigned long bstate, int win_h) {
    if (!v) return false;
    if (bstate & BUTTON4_PRESSED) { for (int i = 0; i < 3; i++) dis_key(v, KEY_UP, win_h); return true; }
#ifdef BUTTON5_PRESSED
    if (bstate & BUTTON5_PRESSED) { for (int i = 0; i < 3; i++) dis_key(v, KEY_DOWN, win_h); return true; }
#endif
    if (!(bstate & (BUTTON1_PRESSED | BUTTON1_CLICKED)) || v->in_mode != IN_NONE) return false;
    if (v->npick && v->screen == SCR_DISASM) {      /* the choice: a click on one, or elsewhere: none */
        if (y == win_h - 1) return false;           /* the bar: its hints (↑/↓, Esc) */
        if (y >= v->pick_y && y < v->pick_y + v->npick && x >= v->pick_x && x < v->pick_x + v->pick_w) {
            v->pick_sel = y - v->pick_y;
            v->msg[0] = '\0';
            pick_go(v);
        } else v->npick = 0;
        return true;
    }
    int hd = v->screen == SCR_DUMP ? dump_hdr(win_h) : 0;
    int y0 = (win_h >= 4 ? 2 : 1) + hd, rows = list_rows(win_h) - hd, r = y - y0;
    if (v->screen == SCR_DISASM && v->dpanel && x >= v->dpanel) {  /* a register: what its value points to */
        for (int i = 0; i < 18; i++)
            if (v->reg_y[i] && y == v->reg_y[i] && x >= v->reg_x0[i] && x < v->reg_x1[i]) {
                v->msg[0] = '\0';
                reg_go(v, i);
                return true;
            }
    }
    if (v->screen == SCR_DISASM && v->dpanel && x >= v->dpanel)    /* [esp+4] / [esp+8]: what they point to */
        for (int k = 0; k < 2; k++)
            if (v->sarg_y0[k] && y >= v->sarg_y0[k] && y < v->sarg_y1[k]) {
                v->msg[0] = '\0';
                stack_arg_go(v, k);
                return true;
            }
    if (v->screen == SCR_INFO || r < 0 || r >= rows) return false;
    if (v->screen == SCR_DISASM && v->dpanel && x >= v->dpanel) {   /* the panel: type into the console */
        v->msg[0] = '\0';
        dbg_key_console(v);
        return true;
    }
    size_t *sel, top, n;
    switch (v->screen) {
        case SCR_FUNCS:  sel = &v->sel;   top = v->top;   n = v->nvis; break;
        case SCR_DISASM: sel = &v->dsel;  top = v->dtop;  n = v->ndl;  break;
        case SCR_DATA:   sel = &v->dssel; top = v->dstop; n = v->nds;  break;
        default:         sel = &v->xsel;  top = v->xtop;  n = v->nxi;  break;
    }
    if (top + (size_t)r >= n) return false;
    *sel = top + (size_t)r;
    v->msg[0] = '\0';
    return dis_key(v, '\n', win_h);
}

void dis_status(const DisView *v, char *out, size_t sz) {
    if (!out || !sz) return;
    if (!v) { snprintf(out, sz, " [DISASM] "); return; }
    const ElfFile *ef = &v->d.elf;
    if (v->screen == SCR_DISASM && v->dfn >= 0 && (size_t)v->dfn < v->d.nfn) {
        const DisFunc *fn = &v->d.fn[v->dfn];
        if (!v->ndl) { snprintf(out, sz, " [DISASM]  %.120s  ·  no line ", fn->name ? fn->name : "?"); return; }
        size_t li = v->dsel < v->ndl ? v->dsel : v->ndl - 1;
        const DisLine *l = &v->dl[li];
        if (!l->len) {
            snprintf(out, sz, " [DISASM]  %.120s.cold  0x%llx  ·  %llu bytes apart from the body  ·  line %zu/%zu ",
                     fn->name ? fn->name : "?", (unsigned long long)fn->cold,
                     (unsigned long long)fn->cold_size, li + 1, v->ndl);
            return;
        }
        bool cold = li > v->dmain;
        bool off = v->d.nins && (l->bad || da_insn_at(&v->d, l->addr) < 0);
        snprintf(out, sz, " [DISASM]  %.120s%s+0x%llx  0x%llx  ·  %u byte%s%s  ·  line %zu/%zu ",
                 fn->name ? fn->name : "?", cold ? ".cold" : "",
                 (unsigned long long)(l->addr - (cold ? fn->cold : v->dva)), (unsigned long long)l->addr,
                 l->len, l->len == 1 ? "" : "s", l->bad ? "  ·  undecodable" : off ? "  ·  not decoded by the analysis" : "",
                 li + 1, v->ndl);
        return;
    }
    if (v->screen == SCR_DATA && v->dssel < v->nds) {
        const DataSec *d = &v->ds[v->dssel];
        snprintf(out, sz, " [DISASM]  %.60s  0x%llx-0x%llx  ·  %llu bytes%s  ·  %s  ·  section %zu/%zu ",
                 d->name, (unsigned long long)d->addr, (unsigned long long)(d->addr + d->size),
                 (unsigned long long)d->size, d->filesz < d->size ? " (zero-filled at start)" : "",
                 d->perm, v->dssel + 1, v->nds);
        return;
    }
    if (v->screen == SCR_DUMP && v->xsec >= 0 && v->xsel < v->nxi) {
        const DataSec  *d  = &v->ds[v->xsec];
        const DataItem *it = &v->xi[v->xsel];
        static const char *const kind[] = { "hex", "string", "address", "zeros" };
        char nb[160] = "", lk[200] = "";
        uint64_t t;
        if (item_link(v, it, &t))
            snprintf(lk, sizeof lk, "  ·  Enter: %s 0x%llx", elf_va_code(ef, t) ? "code" : "data", (unsigned long long)t);
        const char *nm = da_name_for(&v->d, it->addr, nb, sizeof nb);
        snprintf(out, sz, " [DISASM]  %.60s+0x%llx  0x%llx%s%.80s  ·  %s, %u byte%s%s  ·  row %zu/%zu ",
                 d->name, (unsigned long long)(it->addr - d->addr), (unsigned long long)it->addr,
                 nm ? "  " : "", nm ? nm : "", kind[it->kind], it->len, it->len == 1 ? "" : "s", lk,
                 v->xsel + 1, v->nxi);
        return;
    }
    if (v->screen == SCR_FUNCS) {
        char flt[200] = "";
        if (v->filter[0]) snprintf(flt, sizeof flt, "  ·  filter \"%.100s\": %zu of %zu", v->filter, v->nvis, v->d.nfn);
        long f = sel_fn(v);
        if (f < 0) {
            snprintf(out, sz, " [DISASM]  %s  ·  no function selected  ·  0/%zu%s ", base_name(v->path), v->nvis, flt);
            return;
        }
        const DisFunc *fn = &v->d.fn[f];
        char size[40];
        if (fn->size) snprintf(size, sizeof size, "%llu byte%s", (unsigned long long)fn->size, fn->size == 1 ? "" : "s");
        else          snprintf(size, sizeof size, "size unknown");
        snprintf(out, sz, " [DISASM]  %.120s  0x%llx  ·  %s  ·  %s%s  ·  %u caller%s  ·  %zu/%zu%s ",
                 fn->name ? fn->name : "?", (unsigned long long)fn->addr, size, fn_kind_name(fn->kind),
                 fn_weak(fn) ? " (guessed start)" : "", fn->ncallers, fn->ncallers == 1 ? "" : "s",
                 v->sel + 1, v->nvis, flt);
        return;
    }
    snprintf(out, sz, " [DISASM]  %s  ·  %s %s%s  ·  %zu functions  ·  %zu instructions%s  ·  %d warning%s ",
             base_name(v->path), elf_machine_name(ef->machine), elf_kind_name(ef),
             ef->stripped ? "  stripped" : "", v->d.nfn, v->d.nins, v->d.capped ? " (partial)" : "",
             ef->nwarn, ef->nwarn == 1 ? "" : "s");
}
