/* F8 — memory editor (Cheat Engine style), drawn in a pane.
 *
 *  1. Process list: newest first, type to filter, Enter attaches.
 *     ^O launches a program as a child of Abyss (on Linux a child can be
 *     inspected without root), ^R refreshes the list.
 *  2. Scanner: pick a type (t) and a scan mode (m), s scans: the first
 *     scan walks the process's writable memory, the next ones refine the
 *     results (changed, increased, decreased by 5...). Values are re-read
 *     live. Enter writes a new value, a / f save an address (f = frozen:
 *     its value is written back ten times a second), x shows the bytes
 *     around an address, g jumps to an address.
 *
 * The engine (memscan.c) does the process access and the scans. */
#include "abyss.h"
#include "utf8.h"
#include "memscan.h"
#include <stdarg.h>

extern char E_notify[256];

enum { MD_NONE, MD_SCAN, MD_EDIT_RESULT, MD_EDIT_ENTRY, MD_DESC, MD_GOTO, MD_LAUNCH };

typedef struct {
    char     desc[48];
    uint64_t addr;
    MemType  type;
    int      len;
    bool     frozen;
    uint8_t  fval[256];
} MemEntry;

#define MAX_ENTRIES 256

static struct {
    bool        open;              /* the view was entered at least once  */
    bool        picking;           /* process list on screen              */
    MemProc    *procs;
    int         nprocs;
    char        filter[64];
    int         psel, pscroll;

    MemType     type;
    MemScanMode mode;
    bool        aligned;
    MemResults  res;
    int         nscans;
    bool        snapshot;
    MemValue    lastv;
    char        last_text[128];
    int         rsel, rscroll;

    MemEntry    list[MAX_ENTRIES];
    int         nlist, lsel, lscroll;
    int         focus;             /* 0 results, 1 saved addresses */

    bool        hex;
    uint64_t    hex_addr;
    uint8_t     hex_prev[512];
    uint64_t    hex_prev_addr;
    int         hex_prev_n;

    int         pending;
    char        ptitle[200], pfill[256];
    long long   last_freeze;
    long long   last_render;       /* last draw of the F8 view (ms)       */
} M ={ .type = MT_I32, .mode = MS_EXACT, .aligned = true };

static void note(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void note(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(E_notify, sizeof E_notify, fmt, ap);
    va_end(ap);
}

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool first_phase(void) { return M.nscans == 0 && !M.snapshot; }

/* value length of the current results (text / bytes: the searched value) */
static int res_len(void) {
    int s = mem_type_size(M.type);
    return s ? s : (M.lastv.size > 0 ? M.lastv.size : 16);
}

/* ─── Process list ─────────────────────────────────────────────── */

static void procs_reload(void) {
    free(M.procs);
    M.nprocs = mem_list_procs(&M.procs);
    M.psel = M.pscroll = 0;
}

static bool has_ci(const char *s, const char *q) {
    size_t n = strlen(q);
    for (; *s; s++) {
        size_t i = 0;
        while (i < n && s[i] && tolower((unsigned char)s[i]) == tolower((unsigned char)q[i])) i++;
        if (i == n) return true;
    }
    return n == 0;
}

static bool proc_visible(const MemProc *p) {
    if (!M.filter[0]) return true;
    char pid[16];
    snprintf(pid, sizeof pid, "%d", p->pid);
    return has_ci(p->name, M.filter) || strstr(pid, M.filter);
}

static int visible_procs(int *idx, int max) {
    int n = 0;
    for (int i = 0; i < M.nprocs && n < max; i++) if (proc_visible(&M.procs[i])) idx[n++] = i;
    return n;
}

static void new_scan(void) {
    mem_results_free(&M.res);
    M.nscans = 0;
    M.snapshot = false;
    M.rsel = M.rscroll = 0;
    if (!mem_mode_first_ok(M.mode) || !mem_mode_ok_for(M.type, M.mode)) M.mode = MS_EXACT;
}

static void attach_to(const MemProc *p) {
    char err[300];
    if (!mem_attach(p->pid, p->name, err, sizeof err)) { note("%s", err); return; }
    new_scan();
    M.nlist = 0;
    M.hex = false;
    M.picking = false;
    note("Attached to %s (pid %d)", p->name, p->pid);
}

void mem_ui_enter(void) {
    if (!M.open) { M.open = true; M.type = MT_I32; M.mode = MS_EXACT; M.aligned = true; }
    if (!mem_attached() || !mem_alive()) {
        if (mem_attached()) mem_detach();
        M.picking = true;
        procs_reload();
    }
}

/* ─── Drawing helpers ──────────────────────────────────────────── */

/* writes s clipped to `w` columns */
static void put_clip(WINDOW *win, int y, int x, const char *s, int w) {
    if (w <= 0) return;
    size_t n = strlen(s), i = 0;
    int used = 0;
    wmove(win, y, x);
    while (i < n) {
        uint32_t cp;
        int k = utf8_decode(s + i, n - i, &cp);
        if (k < 1) k = 1;
        int cw = utf8_cp_width(cp);
        if (cw < 0) cw = 0;
        if (used + cw > w) break;
        waddnstr(win, s + i, k);
        used += cw;
        i += (size_t)k;
    }
}

static void bar(WINDOW *win, int y, int w, int pair, attr_t a, const char *s) {
    wattron(win, COLOR_PAIR(pair) | a);
    mvwhline(win, y, 0, ' ', w);
    put_clip(win, y, 0, s, w);
    wattroff(win, COLOR_PAIR(pair) | a);
}

static void keep_visible(int sel, int *scroll, int rows) {
    if (rows < 1) rows = 1;
    if (sel < *scroll) *scroll = sel;
    if (sel >= *scroll + rows) *scroll = sel - rows + 1;
    if (*scroll < 0) *scroll = 0;
}

/* ─── Process list screen ──────────────────────────────────────── */

static void render_picker(WINDOW *win, int h, int w) {
    bar(win, 0, w, HEX_CP_HEADER, A_BOLD, " MEMORY  ·  pick a process");
    char line[300];
    snprintf(line, sizeof line, " filter: %s▏", M.filter);
    wattron(win, COLOR_PAIR(COLOR_PAIR_STRING));
    put_clip(win, 1, 0, line, w);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_STRING));

    int idx[4096];
    int n = visible_procs(idx, 4096);
    if (M.psel >= n) M.psel = n ? n - 1 : 0;
    int top = 3, rows = h - top - 1;
    wattron(win, COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD);
    put_clip(win, 2, 0, "   PID      MEMORY  NAME", w);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD);
    keep_visible(M.psel, &M.pscroll, rows);
    for (int r = 0; r < rows && M.pscroll + r < n; r++) {
        const MemProc *p = &M.procs[idx[M.pscroll + r]];
        char mem[16] = "-";
        if (p->rss_kb >= 1024 * 1024) snprintf(mem, sizeof mem, "%.1f GB", p->rss_kb / 1048576.0);
        else if (p->rss_kb >= 1024)   snprintf(mem, sizeof mem, "%llu MB", p->rss_kb / 1024);
        else if (p->rss_kb)           snprintf(mem, sizeof mem, "%llu kB", p->rss_kb);
        snprintf(line, sizeof line, " %7d  %9s  %s", p->pid, mem, p->name);
        bool sel = M.pscroll + r == M.psel;
        if (sel) { wattron(win, COLOR_PAIR(COLOR_PAIR_SELECTION) | A_BOLD); mvwhline(win, top + r, 0, ' ', w); }
        put_clip(win, top + r, 0, line, w);
        if (sel) wattroff(win, COLOR_PAIR(COLOR_PAIR_SELECTION) | A_BOLD);
    }
    if (n == 0) {
        wattron(win, COLOR_PAIR(COLOR_PAIR_COMMENT));
        put_clip(win, top + 1, 2, M.nprocs ? "No process matches the filter" : "No process could be listed", w - 2);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_COMMENT));
    }
    snprintf(line, sizeof line, " %d/%d  ·  type to filter  ·  Enter: analyse  ·  ^O: launch a program  ·  ^R: refresh  ·  F8: close",
             n, M.nprocs);
    bar(win, h - 1, w, COLOR_PAIR_LINENUM, 0, line);
}

static bool picker_key(int key) {
    int idx[4096];
    int n = visible_procs(idx, 4096);
    size_t fl = strlen(M.filter);
    switch (key) {
        case KEY_UP:    if (M.psel > 0) M.psel--; return true;
        case KEY_DOWN:  if (M.psel + 1 < n) M.psel++; return true;
        case KEY_PPAGE: M.psel = M.psel > 10 ? M.psel - 10 : 0; return true;
        case KEY_NPAGE: M.psel = M.psel + 10 < n ? M.psel + 10 : (n ? n - 1 : 0); return true;
        case KEY_HOME:  M.psel = 0; return true;
        case KEY_END:   M.psel = n ? n - 1 : 0; return true;
        case '\n': case '\r': case KEY_ENTER:
            if (n) attach_to(&M.procs[idx[M.psel]]);
            return true;
        case 'r' & 0x1f: procs_reload(); return true;
        case 'o' & 0x1f:
            M.pending = MD_LAUNCH;
            snprintf(M.ptitle, sizeof M.ptitle, "Launch a program (it becomes a child of Abyss)");
            M.pfill[0] = '\0';
            return true;
        case KEY_BACKSPACE: case 127: case '\b':
            if (fl) M.filter[fl - 1] = '\0';
            M.psel = 0;
            return true;
        case 27:
            if (fl) { M.filter[0] = '\0'; M.psel = 0; return true; }
            if (mem_attached()) { M.picking = false; return true; }
            return false;                                  /* let F8/Esc close */
        default:
            if (key >= 32 && key < 127 && fl + 1 < sizeof M.filter) {
                M.filter[fl] = (char)key; M.filter[fl + 1] = '\0';
                M.psel = 0;
                return true;
            }
    }
    return false;
}

/* ─── Scanner screen ───────────────────────────────────────────── */

static void fmt_addr(uint64_t a, char *out, size_t sz) { snprintf(out, sz, "%012llX", (unsigned long long)a); }

static void read_fmt(uint64_t addr, MemType t, int len, char *out, size_t sz, uint8_t *raw) {
    uint8_t buf[256];
    if (len > (int)sizeof buf) len = (int)sizeof buf;
    size_t got = mem_read(addr, buf, (size_t)len);
    if ((int)got < len) { snprintf(out, sz, "??"); if (raw) memset(raw, 0, (size_t)len); return; }
    mem_format(t, buf, len, out, sz);
    if (raw) memcpy(raw, buf, (size_t)len);
}

static void render_hex(WINDOW *win, int y, int rows, int w) {
    int per = w >= 78 ? 16 : 8;
    uint64_t base = M.hex_addr & ~(uint64_t)(per - 1);
    char head[160], a[32];
    fmt_addr(M.hex_addr, a, sizeof a);
    snprintf(head, sizeof head, " Memory at %s  (g: go to address, x: hide)", a);
    bar(win, y, w, COLOR_PAIR_STATUS, 0, head);
    int n = per * (rows - 1);
    if (n > (int)sizeof M.hex_prev) n = (int)sizeof M.hex_prev;
    uint8_t buf[512];
    size_t got = mem_read(base, buf, (size_t)n);
    bool same = M.hex_prev_addr == base && M.hex_prev_n == n;
    for (int r = 0; r < rows - 1; r++) {
        int yy = y + 1 + r;
        uint64_t ra = base + (uint64_t)(r * per);
        fmt_addr(ra, a, sizeof a);
        wattron(win, COLOR_PAIR(COLOR_PAIR_LINENUM));
        mvwprintw(win, yy, 0, " %s ", a);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_LINENUM));
        int x = 15;
        for (int c = 0; c < per && x + 3 <= w; c++) {
            int k = r * per + c;
            bool cur = ra + (uint64_t)c == M.hex_addr;
            if ((size_t)k >= got) { mvwaddstr(win, yy, x, "?? "); x += 3; continue; }
            bool chg = same && M.hex_prev[k] != buf[k];
            int pair = cur ? COLOR_PAIR_SELECTION : chg ? COLOR_PAIR_KEYWORD : buf[k] ? COLOR_PAIR_NORMAL : COLOR_PAIR_COMMENT;
            wattron(win, COLOR_PAIR(pair) | (chg ? A_BOLD : 0));
            mvwprintw(win, yy, x, "%02X", buf[k]);
            wattroff(win, COLOR_PAIR(pair) | A_BOLD);
            x += 3;
        }
        x++;
        for (int c = 0; c < per && x < w; c++, x++) {
            int k = r * per + c;
            char ch = (size_t)k < got && buf[k] >= 32 && buf[k] < 127 ? (char)buf[k] : '.';
            wattron(win, COLOR_PAIR(COLOR_PAIR_STRING));
            mvwaddch(win, yy, x, (chtype)(unsigned char)ch);
            wattroff(win, COLOR_PAIR(COLOR_PAIR_STRING));
        }
    }
    memcpy(M.hex_prev, buf, got < (size_t)n ? got : (size_t)n);
    M.hex_prev_addr = base;
    M.hex_prev_n = n;
}

static void render_scanner(WINDOW *win, int h, int w) {
    char line[512], a[32], v[96], p[96];
    snprintf(line, sizeof line, " MEMORY  %s (pid %d)  ·  type: %s  ·  scan: %s%s",
             mem_pname(), mem_pid(), mem_type_name(M.type), mem_mode_name(M.mode),
             first_phase() ? (M.aligned ? "  ·  aligned" : "  ·  every byte") : "");
    bar(win, 0, w, HEX_CP_HEADER, A_BOLD, line);

    if (first_phase())
        snprintf(line, sizeof line, " New scan: t picks the type, m the mode, s scans");
    else if (M.snapshot)
        snprintf(line, sizeof line, " Memory copied. Change the value in the program, then pick increased / decreased / changed (m) and scan (s)");
    else
        snprintf(line, sizeof line, " Scan %d  ·  %zu result%s%s%s%s", M.nscans, M.res.n, M.res.n == 1 ? "" : "s",
                 M.res.overflow ? " (capped)" : "", M.last_text[0] ? "  ·  last value: " : "", M.last_text);
    wattron(win, COLOR_PAIR(COLOR_PAIR_COMMENT));
    put_clip(win, 1, 0, line, w);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_COMMENT));

    int top = 2, bottom = h - 1;                          /* last row: key help */
    int avail = bottom - top;
    int hex_rows = 0, list_rows = 0;
    if (M.hex && avail >= 8) { hex_rows = avail / 3 < 10 ? avail / 3 + 1 : 10; if (hex_rows < 4) hex_rows = 4; }
    if (M.nlist && avail - hex_rows >= 6) {
        list_rows = M.nlist + 1;
        if (list_rows > (avail - hex_rows) / 2) list_rows = (avail - hex_rows) / 2;
    }
    int res_rows = avail - hex_rows - list_rows;

    /* results */
    int vw = (w - 18) / 2 > 34 ? 34 : (w - 18) / 2;
    if (vw < 8) vw = 8;
    wattron(win, COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD);
    snprintf(line, sizeof line, " %-13s %-*s %s", "Address", vw, "Value", "Previous");
    put_clip(win, top, 0, line, w);
    wattroff(win, COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD);
    int rrows = res_rows - 1;
    if (M.rsel >= (int)M.res.n) M.rsel = M.res.n ? (int)M.res.n - 1 : 0;
    keep_visible(M.rsel, &M.rscroll, rrows);
    int len = res_len();
    for (int r = 0; r < rrows && (size_t)(M.rscroll + r) < M.res.n; r++) {
        size_t i = (size_t)(M.rscroll + r);
        uint8_t raw[256];
        fmt_addr(M.res.addr[i], a, sizeof a);
        read_fmt(M.res.addr[i], M.type, len, v, sizeof v, raw);
        mem_format(M.type, M.res.prev + i * MEM_PREV, len < MEM_PREV ? len : MEM_PREV, p, sizeof p);
        if (len > MEM_PREV) snprintf(p, sizeof p, "-");
        bool changed = len <= MEM_PREV && memcmp(raw, M.res.prev + i * MEM_PREV, (size_t)len) != 0;
        bool sel = (int)i == M.rsel && M.focus == 0;
        int y = top + 1 + r;
        if (sel) { wattron(win, COLOR_PAIR(COLOR_PAIR_SELECTION) | A_BOLD); mvwhline(win, y, 0, ' ', w); }
        else wattron(win, COLOR_PAIR(COLOR_PAIR_LINENUM));
        mvwprintw(win, y, 0, " %s ", a);
        if (!sel) { wattroff(win, COLOR_PAIR(COLOR_PAIR_LINENUM)); wattron(win, COLOR_PAIR(changed ? COLOR_PAIR_KEYWORD : COLOR_PAIR_NUMBER) | (changed ? A_BOLD : 0)); }
        put_clip(win, y, 15, v, vw);
        if (!sel) { wattroff(win, COLOR_PAIR(changed ? COLOR_PAIR_KEYWORD : COLOR_PAIR_NUMBER) | A_BOLD); wattron(win, COLOR_PAIR(COLOR_PAIR_COMMENT)); }
        put_clip(win, y, 16 + vw, p, w - 16 - vw);
        if (!sel) wattroff(win, COLOR_PAIR(COLOR_PAIR_COMMENT));
        else wattroff(win, COLOR_PAIR(COLOR_PAIR_SELECTION) | A_BOLD);
    }
    if (M.res.n == 0 && rrows > 1) {
        wattron(win, COLOR_PAIR(COLOR_PAIR_COMMENT));
        put_clip(win, top + 2, 2, first_phase() ? "(no scan yet)" : M.snapshot ? "(waiting for the next scan)" : "(no address matches: n starts over)", w - 2);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_COMMENT));
    }

    /* saved addresses */
    if (list_rows) {
        int y0 = top + res_rows;
        snprintf(line, sizeof line, " Saved addresses (%d)   Enter: edit  f: freeze  r: rename  d: delete", M.nlist);
        bar(win, y0, w, COLOR_PAIR_STATUS, 0, line);
        int lr = list_rows - 1;
        keep_visible(M.lsel, &M.lscroll, lr);
        for (int r = 0; r < lr && M.lscroll + r < M.nlist; r++) {
            MemEntry *e = &M.list[M.lscroll + r];
            fmt_addr(e->addr, a, sizeof a);
            read_fmt(e->addr, e->type, e->len, v, sizeof v, NULL);
            bool sel = M.lscroll + r == M.lsel && M.focus == 1;
            int y = y0 + 1 + r;
            snprintf(line, sizeof line, " %s %-16.16s %s  %-8s %s", e->frozen ? "*" : " ", e->desc, a,
                     mem_type_name(e->type), v);
            if (sel) { wattron(win, COLOR_PAIR(COLOR_PAIR_SELECTION) | A_BOLD); mvwhline(win, y, 0, ' ', w); }
            else wattron(win, COLOR_PAIR(e->frozen ? COLOR_PAIR_TYPE : COLOR_PAIR_NORMAL));
            put_clip(win, y, 0, line, w);
            if (sel) wattroff(win, COLOR_PAIR(COLOR_PAIR_SELECTION) | A_BOLD);
            else wattroff(win, COLOR_PAIR(e->frozen ? COLOR_PAIR_TYPE : COLOR_PAIR_NORMAL));
        }
    }
    if (hex_rows) render_hex(win, top + res_rows + list_rows, hex_rows, w);

    const char *help = M.focus == 1
        ? " Tab: results  ·  Enter: edit  ·  f: freeze  ·  r: rename  ·  d: delete  ·  x: hex  ·  p: process  ·  F8: close"
        : first_phase()
        ? " s: first scan  ·  t: type  ·  m: mode  ·  u: aligned  ·  g: go to address  ·  p: process  ·  F8: close"
        : " s: next scan  ·  m: mode  ·  n: new scan  ·  Enter: edit  ·  a: save  ·  f: freeze  ·  x: hex  ·  Tab: saved  ·  F8: close";
    bar(win, h - 1, w, COLOR_PAIR_LINENUM, 0, help);
}

void mem_ui_render(WINDOW *win, int h, int w) {
    if (!win || h < 1 || w < 4) return;
    werase(win);
    if (!M.open) mem_ui_enter();
    if (!M.picking && mem_attached() && !mem_alive()) {
        note("%s (pid %d) has exited", mem_pname(), mem_pid());
        mem_detach();
        new_scan();
        M.nlist = 0;
        M.picking = true;
        procs_reload();
    }
    if (M.picking || !mem_attached()) { M.picking = true; render_picker(win, h, w); }
    else render_scanner(win, h, w);
    wnoutrefresh(win);
    M.last_render = now_ms();
}

/* ─── Scanner actions ──────────────────────────────────────────── */

static void ask(int kind, const char *title, const char *fill) {
    M.pending = kind;
    snprintf(M.ptitle, sizeof M.ptitle, "%s", title);
    snprintf(M.pfill, sizeof M.pfill, "%s", fill ? fill : "");
}

static void do_scan(const char *text) {
    MemValue v;
    char err[300];
    if (!mem_parse(M.type, M.mode, text, &v, err, sizeof err)) { note("%s", err); return; }
    if (mem_mode_needs_value(M.mode)) {
        M.lastv = v;
        snprintf(M.last_text, sizeof M.last_text, "%s", text ? text : "");
    }
    bool ok;
    note("Scanning...");
    if (first_phase()) {
        ok = mem_first_scan(M.type, M.mode, &v, M.aligned, &M.res, err, sizeof err);
        if (ok && M.mode == MS_UNKNOWN) { M.snapshot = true; M.mode = MS_CHANGED; }
        else if (ok) M.nscans = 1;
    } else {
        ok = mem_next_scan(M.type, M.mode, &v, &M.res, err, sizeof err);
        if (ok) { M.nscans++; M.snapshot = false; }
    }
    M.rsel = M.rscroll = 0;
    if (!ok) note("%s", err);
    else if (err[0]) note("%s", err);
    else note("%zu result%s", M.res.n, M.res.n == 1 ? "" : "s");
}

static void cycle_mode(void) {
    for (int k = 1; k <= MS_COUNT; k++) {
        MemScanMode m = (MemScanMode)((M.mode + k) % MS_COUNT);
        if (!mem_mode_ok_for(M.type, m)) continue;
        if (first_phase() ? !mem_mode_first_ok(m) : m == MS_UNKNOWN) continue;
        M.mode = m;
        return;
    }
}

static bool write_value(uint64_t addr, MemType t, int old_len, const char *text, uint8_t *stored, int *stored_len) {
    MemValue v;
    char err[300];
    if (!mem_parse(t, MS_EXACT, text, &v, err, sizeof err)) { note("%s", err); return false; }
    uint8_t out[260];
    int n = v.size;
    memcpy(out, v.bytes, (size_t)n);
    /* shorter text: end it, so the program does not see the old tail */
    if (t == MT_STR   && n < old_len && n + 1 <= (int)sizeof out) out[n++] = 0;
    if (t == MT_STR16 && n < old_len && n + 2 <= (int)sizeof out) { out[n++] = 0; out[n++] = 0; }
    if (!mem_write(addr, out, (size_t)n)) { note("Write refused at %llX", (unsigned long long)addr); return false; }
    if (stored) { memcpy(stored, out, (size_t)n); if (stored_len) *stored_len = n; }
    note("Written");
    return true;
}

static void add_entry(uint64_t addr, bool frozen) {
    for (int i = 0; i < M.nlist; i++)
        if (M.list[i].addr == addr && M.list[i].type == M.type) {
            if (frozen) M.list[i].frozen = true;
            M.lsel = i;
            return;
        }
    if (M.nlist >= MAX_ENTRIES) { note("The saved list is full"); return; }
    MemEntry *e = &M.list[M.nlist];
    memset(e, 0, sizeof *e);
    snprintf(e->desc, sizeof e->desc, "value %d", M.nlist + 1);
    e->addr = addr;
    e->type = M.type;
    e->len  = res_len();
    if (e->len > (int)sizeof e->fval) e->len = (int)sizeof e->fval;
    e->frozen = frozen;
    mem_read(addr, e->fval, (size_t)e->len);
    M.lsel = M.nlist++;
    note(frozen ? "Saved and frozen" : "Saved");
}

static bool scanner_key(int key, int win_h) {
    int page = win_h > 8 ? win_h / 2 : 4;
    if (M.focus == 1 && M.nlist == 0) M.focus = 0;
    int *sel = M.focus ? &M.lsel : &M.rsel;
    int count = M.focus ? M.nlist : (int)M.res.n;
    char a[32];

    switch (key) {
        case KEY_UP:    if (*sel > 0) (*sel)--; return true;
        case KEY_DOWN:  if (*sel + 1 < count) (*sel)++; return true;
        case KEY_PPAGE: *sel = *sel > page ? *sel - page : 0; return true;
        case KEY_NPAGE: *sel = *sel + page < count ? *sel + page : (count ? count - 1 : 0); return true;
        case KEY_HOME:  *sel = 0; return true;
        case KEY_END:   *sel = count ? count - 1 : 0; return true;
        case '\t':      if (M.nlist) M.focus = !M.focus; return true;
        case 'p': case 'P':
            M.picking = true;
            M.filter[0] = '\0';
            procs_reload();
            return true;
        case 'x': case 'X': {
            uint64_t ad = M.focus ? (M.nlist ? M.list[M.lsel].addr : 0) : (M.res.n ? M.res.addr[M.rsel] : 0);
            if (M.hex && (!ad || ad == M.hex_addr)) { M.hex = false; return true; }
            if (ad) { M.hex = true; M.hex_addr = ad; }
            else if (M.hex_addr) M.hex = !M.hex;
            else note("Pick an address first, or g to go to one");
            return true;
        }
        case 'g': case 'G':
            fmt_addr(M.hex_addr, a, sizeof a);
            ask(MD_GOTO, "Go to address (hex)", M.hex_addr ? a : "");
            return true;
        default: break;
    }

    if (M.focus == 1) {                                   /* saved addresses */
        MemEntry *e = M.nlist ? &M.list[M.lsel] : NULL;
        if (!e) return false;
        char v[96];
        switch (key) {
            case '\n': case '\r': case KEY_ENTER: case 'e':
                read_fmt(e->addr, e->type, e->len, v, sizeof v, NULL);
                ask(MD_EDIT_ENTRY, "New value", v);
                return true;
            case 'f': case 'F':
                e->frozen = !e->frozen;
                if (e->frozen) mem_read(e->addr, e->fval, (size_t)e->len);
                note(e->frozen ? "Frozen: the value is written back continuously" : "Unfrozen");
                return true;
            case 'r': case 'R':
                ask(MD_DESC, "Name of this address", e->desc);
                return true;
            case 'd': case 'D': case KEY_DC:
                memmove(&M.list[M.lsel], &M.list[M.lsel + 1], (size_t)(M.nlist - M.lsel - 1) * sizeof *M.list);
                M.nlist--;
                if (M.lsel >= M.nlist) M.lsel = M.nlist ? M.nlist - 1 : 0;
                if (!M.nlist) M.focus = 0;
                return true;
        }
        return false;
    }

    switch (key) {
        case 's': case 'S':
            if (mem_mode_needs_value(M.mode)) {
                char t[200];
                snprintf(t, sizeof t, "%s scan  ·  %s  ·  %s%s", first_phase() ? "First" : "Next",
                         mem_type_name(M.type), mem_mode_name(M.mode),
                         M.mode == MS_BETWEEN ? "  (low..high)" : M.type == MT_BYTES ? "  (DE AD ?? EF)" : "");
                ask(MD_SCAN, t, M.last_text);
            } else do_scan(NULL);
            return true;
        case '\n': case '\r': case KEY_ENTER: case 'e':
            if (!M.res.n) {                               /* nothing to edit: scan */
                return scanner_key('s', win_h);
            } else {
                char v[96];
                read_fmt(M.res.addr[M.rsel], M.type, res_len(), v, sizeof v, NULL);
                ask(MD_EDIT_RESULT, "New value", v);
            }
            return true;
        case 'n': case 'N':
            new_scan();
            note("New scan");
            return true;
        case 't': case 'T':
            if (!first_phase()) { note("n starts a new scan, then t changes the type"); return true; }
            M.type = (MemType)((M.type + 1) % MT_COUNT);
            if (!mem_mode_ok_for(M.type, M.mode)) M.mode = MS_EXACT;
            return true;
        case 'm': case 'M':
            cycle_mode();
            return true;
        case 'u': case 'U':
            if (first_phase()) M.aligned = !M.aligned;
            return true;
        case 'a': case 'A': case '+':
            if (M.res.n) add_entry(M.res.addr[M.rsel], false);
            return true;
        case 'f': case 'F':
            if (M.res.n) add_entry(M.res.addr[M.rsel], true);
            return true;
    }
    return false;
}

bool mem_ui_key(int key, int win_h) {
    if (M.picking || !mem_attached()) { M.picking = true; return picker_key(key); }
    return scanner_key(key, win_h);
}

int mem_ui_dialog(char *title, size_t tsz, char *fill, size_t fsz) {
    int k = M.pending;
    if (!k) return 0;
    snprintf(title, tsz, "%s", M.ptitle);
    snprintf(fill, fsz, "%s", M.pfill);
    M.pending = MD_NONE;
    return k;
}

void mem_ui_dialog_done(int kind, const char *text) {
    char err[300];
    switch (kind) {
        case MD_SCAN:
            do_scan(text);
            break;
        case MD_EDIT_RESULT:
            if (M.res.n) write_value(M.res.addr[M.rsel], M.type, res_len(), text, NULL, NULL);
            break;
        case MD_EDIT_ENTRY:
            if (M.nlist) {
                MemEntry *e = &M.list[M.lsel];
                int n = e->len;
                write_value(e->addr, e->type, e->len, text, e->fval, &n);
            }
            break;
        case MD_DESC:
            if (M.nlist) snprintf(M.list[M.lsel].desc, sizeof M.list[M.lsel].desc, "%s", text);
            break;
        case MD_GOTO: {
            const char *s = text;
            while (*s == ' ') s++;
            if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
            char *end;
            unsigned long long ad = strtoull(s, &end, 16);
            if (end == s) { note("Not an address: %.60s", text); break; }
            M.hex = true;
            M.hex_addr = ad;
            break;
        }
        case MD_LAUNCH:
            if (mem_launch(text, err, sizeof err)) {
                new_scan();
                M.nlist = 0;
                M.hex = false;
                M.picking = false;
                note("Started and attached: %s (pid %d)", mem_pname(), mem_pid());
            } else note("%s", err);
            break;
    }
}

void mem_ui_status(char *out, size_t sz) {
    if (M.picking || !mem_attached())
        snprintf(out, sz, " [MEMORY]  pick a process  ·  %d listed ", M.nprocs);
    else
        snprintf(out, sz, " [MEMORY]  %s  pid %d  ·  %s  ·  %zu results  ·  %d saved ",
                 mem_pname(), mem_pid(), mem_type_name(M.type), M.res.n, M.nlist);
}

/* Frozen addresses are written back here; called from the main loop. */
void mem_ui_tick(void) {
    if (!mem_attached() || !M.nlist) return;
    long long t = now_ms();
    if (t - M.last_freeze < 90) return;
    M.last_freeze = t;
    for (int i = 0; i < M.nlist; i++)
        if (M.list[i].frozen) mem_write(M.list[i].addr, M.list[i].fval, (size_t)M.list[i].len);
}

#define MEM_REFRESH_MS 1000

/* How often the main loop should wake up: frozen values keep being
 * written even when the view is hidden (no redraw then); while the F8
 * view is the active pane, its values are redrawn once a second. */
int mem_ui_timeout(bool visible) {
    bool frozen = false;
    for (int i = 0; i < M.nlist; i++) if (M.list[i].frozen) { frozen = true; break; }
    if (frozen && mem_attached()) return 100;
    if (visible && mem_attached() && !M.picking) return MEM_REFRESH_MS;
    return -1;
}

bool mem_ui_refresh_due(void) {
    return mem_attached() && !M.picking && now_ms() - M.last_render >= MEM_REFRESH_MS;
}

bool mem_ui_picking(void) { return M.picking || !mem_attached(); }

void mem_ui_shutdown(void) {
    mem_results_free(&M.res);
    free(M.procs);
    M.procs = NULL;
    mem_detach();
}
