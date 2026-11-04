#include "abyss.h"
#include "utf8.h"
#include "memscan.h"

void ft_init_color_pairs(void);
#include <string.h>
#include <locale.h>
#include <time.h>
#ifdef _WIN32
int win_console_size(int *rows, int *cols);
#ifdef _WIN32
void win_init_utf8(void);
#endif
#  define IDLE_TMO 250
#else
#  define IDLE_TMO (-1)
#endif

Editor E;
char E_notify[256] = "";

/* ^B builds and runs; ^B pressed twice within BUILD_DOUBLE_TAP_MS opens the
 * build-options menu instead (F5 too). The first ^B only arms
 * `build_tap_pending`; the main loop then waits that long for the second
 * one, and falls back to a plain build & run on timeout or any other key. */
#define BUILD_DOUBLE_TAP_MS 350
static bool build_tap_pending = false;

/* The cell being edited held newlines: the dialog shows them as \n (and
 * backslashes as \\), and they are turned back on confirm. */
static bool edit_escaped = false;

/* the memory editor asked for a value: which one, and the dialog title */
static int  mem_dialog_kind = 0;
static char mem_dialog_title[200];

/* true only while the active pane shows the F8 memory editor: the live
 * refresh runs there and nowhere else */
static bool mem_visible(void) {
    return E.npanes > 0 && E.panes[E.active]->mem_mode;
}

static void handle_key_normal(int key);
static void handle_key_dialog(int key);
static void handle_key_build_menu(int key);
static void build_menu_open(void);
static void build_and_run(void);
static void full_redraw(bool force);

/* Deferred Smart Highlight rescan: on buffers larger than HL_DEFER_BYTES the
 * scan is postponed until the keyboard goes idle instead of running on every
 * keystroke. `pending` arms a short input timeout in the main loop; `forced`
 * lets the idle path run the scan through full_redraw. */
static bool hl_scan_pending = false;
static bool hl_scan_forced  = false;

/* Braille spinner shown in the top-right corner of the title bar while a
 * long-running scan (Smart Highlight) is in progress. Called from inside the
 * scan loop, so it draws and refreshes the title window directly; the next
 * full_redraw repaints the title bar and erases it. Throttled to ~80 ms. */
static void hl_spinner_tick(size_t done, size_t total) {
    (void)done; (void)total;
    static const char *frames[] = {"⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"};
    static int fi = 0;
    static struct timespec last;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long ms = (now.tv_sec - last.tv_sec) * 1000 + (now.tv_nsec - last.tv_nsec) / 1000000;
    if (last.tv_sec != 0 && ms < 80) return;
    last = now;

    if (!E.title_win) return;
    int w = getmaxx(E.title_win);
    mvwaddstr(E.title_win, 0, w - 3, frames[fi]);
    fi = (fi + 1) % 10;
    wrefresh(E.title_win);
}
static void layout_windows(void);
static void force_full_dirty(void);

/* Moves and resizes a window for a new layout. mvwin() refuses a spot
 * where the window, at its current size, would leave the screen (so after
 * the terminal shrank, a window stayed where it was): size first, then
 * move, and start over with a fresh window if curses still says no. */
static void place_win(WINDOW **w, int h, int ww, int y, int x) {
    if (h < 1) h = 1;
    if (ww < 1) ww = 1;
    if (*w) {
        int cy, cx, ch, cw;
        getbegyx(*w, cy, cx);
        getmaxyx(*w, ch, cw);
        if (cy == y && cx == x && ch == h && cw == ww) return;
        if (wresize(*w, h, ww) == OK && mvwin(*w, y, x) == OK) return;
        delwin(*w);
    }
    *w = newwin(h, ww, y, x);
}

static void layout_windows(void) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    int title_h  = 1;
    int status_h = 1;
    int out_h    = E.out_visible ? (rows / 3) : 0;
    int edit_h   = rows - title_h - status_h - out_h;
    if (edit_h < 1) edit_h = 1;

    

    int finfo_w = 0;
    if (E.finfo && E.finfo->visible) {
        finfo_w = E.finfo->width;
        if (finfo_w < FILEINFO_MIN_W) finfo_w = FILEINFO_MIN_W;
        if (finfo_w > cols / 2)       finfo_w = cols / 2;
        int fi_x = cols - finfo_w;
        place_win(&E.finfo->win, edit_h, finfo_w, title_h, fi_x);
    }

    int hl_w = 0;
    if (E.hl && E.hl->visible) {
        hl_w = HIGHLIGHT_DEFAULT_W;
        if (hl_w < HIGHLIGHT_MIN_W) hl_w = HIGHLIGHT_MIN_W;
        if (hl_w > (cols - finfo_w) / 2) hl_w = (cols - finfo_w) / 2;
        int hl_x = cols - finfo_w - hl_w;
        place_win(&E.hl->win, edit_h, hl_w, title_h, hl_x);
    }

    int tree_w = 0;
    if (E.tree && E.tree->visible) {
        tree_w = E.tree->width;
        if (tree_w < TREE_MIN_W) tree_w = TREE_MIN_W;
        if (tree_w > (cols - finfo_w - hl_w) / 2) tree_w = (cols - finfo_w - hl_w) / 2;
        int tree_x = cols - finfo_w - hl_w - tree_w;
        place_win(&E.tree->win, edit_h, tree_w, title_h, tree_x);
    }

    int edit_x    = 0;
    int edit_cols = cols - tree_w - hl_w - finfo_w;
    if (edit_cols < 1) edit_cols = 1;

    place_win(&E.title_win, title_h, cols, 0, 0);
    if (E.out_visible) place_win(&E.out_win, out_h, cols, title_h + edit_h, 0);
    place_win(&E.status_win, status_h, cols, rows - 1, 0);

    int npanes = E.npanes < 1 ? 1 : E.npanes;
    int pane_w = (edit_cols - (npanes - 1)) / npanes;

    for (int i = 0; i < E.npanes; i++) {
        Pane *p = E.panes[i];
        int px = edit_x + i * (pane_w + 1);
        int pw = (i == E.npanes - 1) ? (edit_cols - i * (pane_w + 1)) : pane_w;
        if (pw < 1) pw = 1;
        place_win(&p->win, edit_h, pw, title_h, px);
        pane_set_window(p, p->win, title_h, px, edit_h, pw);
        if (i < E.npanes - 1) place_win(&E.div_win[i], edit_h, 1, title_h, px + pw);
    }
    for (int i = E.npanes - 1; i < MAX_PANES; i++)
        if (i >= 0 && E.div_win[i]) { delwin(E.div_win[i]); E.div_win[i] = NULL; }
}

/* display columns of a UTF-8 string */
static int title_width(const char *s) {
    int w = 0;
    size_t n = strlen(s);
    for (size_t i = 0; i < n; ) {
        uint32_t cp;
        int k = utf8_decode(s + i, n - i, &cp);
        if (k < 1) k = 1;
        int cw = utf8_cp_width(cp);
        w += cw > 0 ? cw : 0;
        i += (size_t)k;
    }
    return w;
}

static void render_title(void) {
    wbkgdset(E.title_win, ' ' | COLOR_PAIR(COLOR_PAIR_TITLE));
    wmove(E.title_win, 0, 0);
    wattron(E.title_win, COLOR_PAIR(COLOR_PAIR_TITLE) | A_BOLD);
    Pane *ap = E.panes[E.active];

    if (E.show_shortcuts) {
        if (ap->mem_mode)
            wprintw(E.title_win,
                " [MEMORY] F8:Close  p:Process  t:Type  m:Mode  s:Scan  n:New  Enter:Edit  a:Save"
                "  f:Freeze  x:Hex  g:Goto  Tab:Saved  ^Q:Quit");
        else if (ap->img_mode)
            wprintw(E.title_win,
                " [IMAGE] d:Dither on/off  r:Reload  F2:Hex  F3:Info  F1:Tree  ^L:Split  ^Q:Quit");
        else if (ap->doc_mode)
            wprintw(E.title_win,
                " [DOC] Arrows/jk:Scroll  PgUp/PgDn/Space  g/G:Top/End  ^F:Find  ^N/^P:Next/Prev"
                "  %s  ^Q:Quit", ap->binary_view ? "F2:Hex" : "F7:Edit the text");
        else if (ap->table_mode)
            wprintw(E.title_win,
                " [TABLE] Arrows/hjkl:Move  Enter/e:Edit cell  s:Sort col (adds)  S:Unsort all  f:Filter col  F:Unfilter all  v:Show cell"
                "  Tab:Next table  ^F:Find  ^N/^P  ^Z/^Y:Undo/Redo  ^S:Save  F6:Exit  ^Q:Quit");
        else if (ap->hex_mode)
            wprintw(E.title_win,
                " [HEX] Tab:Switch  ^J:Jump  ^F:Search  ^N/^P:Next/Prev"
                "  ^S:Save  F2:Exit Hex  ^Q:Quit");
        else
            wprintw(E.title_win,
                " ^O:SaveAs  ^S:Save  ^K:Line  ^B:Run  ^B^B/F5:Build/Run opts  ^F:Find  ^Z:Undo"
                "  ^R:LN  ^W:Wipe  ^D:Fmt  F1:Tree  F2:Hex  F3:Info  F4:HL  F6:Table  F7:Doc  ^A:Help  ^Q:Quit");
    } else {
        bool mod         = ap->hex_mode ? (ap->hex && ap->hex->modified) : ap->modified;
        const char *hex_tag  = ap->mem_mode ? "  [MEMORY]" : ap->img_mode ? "  [IMAGE]" : ap->doc_mode ? "  [DOC]"
                             : ap->table_mode ? "  [TABLE]" : ap->hex_mode ? "  [HEX]" : "";
        const char *tree_tag = (E.tree && E.tree->visible && E.tree_focus) ? "  [TREE]" : "";
        const char *hl_tag   = (E.hl   && E.hl->visible)                  ? "  [HL]"   : "";
        static char srv_tag[128];
        srv_tag[0] = '\0';
        if (server_running()) snprintf(srv_tag, sizeof srv_tag, "  [SERVER %.80s]", server_url());
        /* left: the file name (always visible); right: its folder,
         * shortened from the left to whatever room is left */
        int tw = getmaxx(E.title_win);
        char base[512] = "[No File]", dir[4096] = "";
        if (ap->filename[0]) {
            const char *sl = strrchr(ap->filename, '/');
#ifdef _WIN32
            const char *bs = strrchr(ap->filename, '\\');
            if (bs && (!sl || bs > sl)) sl = bs;
#endif
            snprintf(base, sizeof base, "%s", sl ? sl + 1 : ap->filename);
            if (sl) {
                const char *home = home_dir();
                size_t hl = home ? strlen(home) : 0;
                if (hl && !strncmp(ap->filename, home, hl) && (ap->filename[hl] == '/' || ap->filename[hl] == '\\'))
                    snprintf(dir, sizeof dir, "~%.*s", (int)(sl - ap->filename - hl), ap->filename + hl);
                else
                    snprintf(dir, sizeof dir, "%.*s", (int)(sl - ap->filename), ap->filename);
                if (!dir[0]) snprintf(dir, sizeof dir, "/");
            }
        }
        char left[1024];
        snprintf(left, sizeof left, " Abyss  │  %s%s%s%s%s%s", base, mod ? " ●" : "",
                 hex_tag, tree_tag, hl_tag, srv_tag);
        int lw = title_width(left);
        const char *help = "  ^A: shortcuts ";
        int hw = title_width(help);
        wprintw(E.title_win, "%s", left);
        wclrtoeol(E.title_win);
        int room = tw - lw - 3;
        bool show_help = room - hw >= 8;
        if (show_help) room -= hw;
        if (dir[0] && room >= 6) {
            int dw = title_width(dir);
            const char *dp = dir;
            while (dw > room - 1 && *dp) {          /* cut whole characters from the left */
                dp++;
                while (*dp && ((unsigned char)*dp & 0xC0) == 0x80) dp++;
                dw = title_width(dp);
            }
            wattroff(E.title_win, A_BOLD);
            mvwprintw(E.title_win, 0, lw, "   %s%s", dp != dir ? "…" : "", dp);
            wattron(E.title_win, A_BOLD);
        }
        if (show_help) {
            wattroff(E.title_win, A_BOLD);
            mvwaddstr(E.title_win, 0, tw - hw, help);
            wattron(E.title_win, A_BOLD);
        }
    }
    wclrtoeol(E.title_win);
    wattroff(E.title_win, COLOR_PAIR(COLOR_PAIR_TITLE) | A_BOLD);
    wnoutrefresh(E.title_win);
}

static void render_status(void) {
    wbkgdset(E.status_win, ' ' | COLOR_PAIR(COLOR_PAIR_STATUS));
    wmove(E.status_win, 0, 0);
    wattron(E.status_win, COLOR_PAIR(COLOR_PAIR_STATUS));
    Pane *ap = E.panes[E.active];

    if (ap->mem_mode) {
        char info[512];
        mem_ui_status(info, sizeof info);
        waddstr(E.status_win, info);
    } else if (ap->img_mode && ap->img) {
        ImageView *iv = ap->img;
        if (iv->rgba)
            wprintw(E.status_win, " [IMAGE]  %dx%d  %s  ·  shown in %dx%d cells  ·  %s ",
                    iv->src_w, iv->src_h, iv->fmt, iv->img_w, iv->img_h,
                    iv->dither ? "dithered" : "smooth");
        else
            wprintw(E.status_win, " [IMAGE]  %s ", iv->use_chafa ? "drawn by chafa" : "not shown");
    } else if (ap->doc_mode && ap->doc) {
        char info[512];
        doc_status(ap->doc, info, sizeof info);
        waddstr(E.status_win, info);
    } else if (ap->table_mode && ap->table) {
        char info[512];
        tbl_status(ap->table, info, sizeof info);
        waddstr(E.status_win, info);
    } else if (ap->hex_mode && ap->hex) {
        HexPane *h = ap->hex;
        const char *panel = (h->focus == HEX_FOCUS_HEX) ? "HEX" : "ASCII";
        wprintw(E.status_win,
                " Offset 0x%07zx (%zu)  Row %zu  Col %zu  [%s]  %zu bytes%s ",
                h->cursor, h->cursor,
                h->cursor / 16, h->cursor % 16,
                panel, h->data_len,
                h->modified ? "  [modified]" : "");
    } else {
        size_t line, col;
        pane_cursor_line_col(ap, &line, &col);
        static const char *lang_names[] = {
            "C","C++","Python","Shell","JS","JSON","SQL","ASM",
            "HTML","CSS","PHP","C#","Rust","HEX","Plain"
        };
        const char *lname = lang_names[ap->lang <= LANG_NONE ? ap->lang : LANG_NONE];
        size_t nlines = li_line_count(ap->li);
        char search_info[512] = "";
        if (ap->search.query[0])
            snprintf(search_info, sizeof search_info, " | \"%s\" [%d/%zu]",
                     ap->search.query,
                     ap->search.current >= 0 ? ap->search.current + 1 : 0,
                     ap->search.count);
        bool readonly = ap->filename[0] && access(ap->filename, W_OK) != 0;
        wprintw(E.status_win, " Ln %zu/%zu  Col %zu  [%s]%s%s%s ",
                line + 1, nlines, col + 1, lname, search_info,
                ap->show_line_numbers ? "  [LN]" : "",
                readonly ? "  [RO]" : "");
    }
    wclrtoeol(E.status_win);

    if (E_notify[0]) {
        int rows, cols; getmaxyx(stdscr, rows, cols); (void)rows;
        int msglen = (int)strlen(E_notify);
        int nx = cols - msglen - 2;
        if (nx < 1) nx = 1;
        wattron(E.status_win, COLOR_PAIR(colors_notify_pair()) | A_BOLD);
        mvwprintw(E.status_win, 0, nx, " %s ", E_notify);
        wattroff(E.status_win, COLOR_PAIR(99) | A_BOLD);
    }
    wattroff(E.status_win, COLOR_PAIR(COLOR_PAIR_STATUS));
    wnoutrefresh(E.status_win);
}

/* memory scans can take a few seconds: show how far they are */
static void mem_scan_progress(uint64_t done, uint64_t total) {
    static long long last = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long long t = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    if (t - last < 100) return;
    last = t;
    snprintf(E_notify, sizeof E_notify, "Scanning... %d%%", total ? (int)(done * 100 / total) : 0);
    render_status();
    doupdate();
}

static void render_pane_borders(void) {
    for (int i = 0; i + 1 < E.npanes && i < MAX_PANES; i++) {
        WINDOW *w = E.div_win[i];
        if (!w) continue;
        int cp = (i == E.active || i + 1 == E.active)
                 ? COLOR_PAIR_ACTIVE_BORDER : COLOR_PAIR_INACTIVE_BORDER;
        werase(w);
        wattron(w, COLOR_PAIR(cp));
        mvwvline(w, 0, 0, ACS_VLINE, getmaxy(w));
        wattroff(w, COLOR_PAIR(cp));
        wnoutrefresh(w);
    }
}

/* Output of ^B, wrapped to the panel width (by display columns, so
 * accented compiler messages wrap where they should). */
static void render_output(void) {
    if (!E.out_visible || !E.out_win || !E.out_text) return;
    int h, w; getmaxyx(E.out_win, h, w);
    if (w < 1 || h < 1) return;
    werase(E.out_win);
    wattron(E.out_win, COLOR_PAIR(COLOR_PAIR_COMMENT));
    const char *ptr = E.out_text;
    int row = 0;
    size_t scroll = E.out_scroll;
    while (*ptr && row < h) {
        const char *nl  = strchr(ptr, '\n');
        size_t      len = nl ? (size_t)(nl - ptr) : strlen(ptr);
        if (len && ptr[len - 1] == '\r') len--;
        size_t off = 0;
        do {                                       /* one screen row */
            size_t end = off;
            int cols = 0;
            while (end < len) {
                uint32_t cp;
                int k = utf8_decode(ptr + end, len - end, &cp);
                if (k < 1) k = 1;
                int cw = cp == '\t' ? 4 : utf8_cp_width(cp) > 0 ? utf8_cp_width(cp) : (cp < 32 ? 0 : 1);
                if (cols + cw > w) break;
                cols += cw;
                end += (size_t)k;
            }
            if (end == off && off < len) end = off + 1;
            if (scroll > 0) scroll--;
            else {
                wmove(E.out_win, row, 0);
                for (size_t i = off; i < end; i++)
                    waddch(E.out_win, ptr[i] == '\t' ? ' ' : (chtype)(unsigned char)ptr[i]);
                row++;
            }
            off = end;
        } while (off < len && row < h);
        if (!nl) break;
        ptr = nl + 1;
    }
    wattroff(E.out_win, COLOR_PAIR(COLOR_PAIR_COMMENT));
    wnoutrefresh(E.out_win);
}

/* One-line input box. Wider for cell edits; the text scrolls sideways so
 * the cursor stays visible, and UTF-8 (accents...) is measured by display
 * columns, not bytes. */
static void render_dialog(const char *title) {
    int rows, cols; getmaxyx(stdscr, rows, cols);
    int dw = (E.mode == MODE_TABLE_EDIT || E.mode == MODE_MEM_INPUT) ? cols - 8 : 62;
    if (dw > 110) dw = 110;
    if (dw > cols) dw = cols;
    if (dw < 20) dw = cols;
    int dh = 3;
    int dy = rows / 2 - 1, dx = (cols - dw) / 2;
    if (dx < 0) dx = 0;
    WINDOW *dw2 = newwin(dh, dw, dy, dx);
    if (!dw2) return;
    wattron(dw2, COLOR_PAIR(COLOR_PAIR_STATUS) | A_BOLD);
    box(dw2, 0, 0);
    mvwprintw(dw2, 0, 2, " %.*s ", dw - 6, title);
    wattroff(dw2, A_BOLD | COLOR_PAIR(COLOR_PAIR_STATUS));

    const char *b = E.dialog_buf;
    size_t len = strlen(b);
    int inner = dw - 2;
    /* display column of the cursor */
    int ccol = 0;
    for (size_t i = 0; i < E.dialog_cursor && i < len; ) {
        uint32_t cp; int n = utf8_decode(b + i, len - i, &cp); if (n < 1) n = 1;
        ccol += utf8_cp_width(cp) > 0 ? utf8_cp_width(cp) : 1;
        i += (size_t)n;
    }
    int first = ccol >= inner - 1 ? ccol - inner + 2 : 0;    /* columns scrolled off */

    wattron(dw2, COLOR_PAIR(COLOR_PAIR_NORMAL));
    mvwhline(dw2, 1, 1, ' ', inner);
    int col = 0, x = 1;
    for (size_t i = 0; i <= len; ) {
        uint32_t cp = ' '; int n = 1;
        if (i < len) { n = utf8_decode(b + i, len - i, &cp); if (n < 1) n = 1; }
        int w = (i < len && utf8_cp_width(cp) > 0) ? utf8_cp_width(cp) : 1;
        if (col >= first) {
            if (x + w > dw - 1) break;
            bool at_cur = (i == E.dialog_cursor);
            if (at_cur) wattron(dw2, A_REVERSE);
            if (i < len) mvwaddnstr(dw2, 1, x, b + i, n);
            else         mvwaddch(dw2, 1, x, ' ');
            if (at_cur) wattroff(dw2, A_REVERSE);
            x += w;
        }
        col += w;
        if (i >= len) break;
        i += (size_t)n;
    }
    wattroff(dw2, COLOR_PAIR(COLOR_PAIR_NORMAL));
    wnoutrefresh(dw2);
    delwin(dw2);
}

/* ─── Build & run (^B) ────────────────────────────────────────────
 * Saves first — the compiler reads the file from disk, not the buffer. */
static void build_and_run(void) {
    Pane *ap = E.panes[E.active];
    if (!ap->filename[0]) return;
    if (ap->binary_view) {
        snprintf(E_notify, sizeof E_notify, "Nothing to run: this is a picture / document");
        return;
    }

    pane_save_file(ap, NULL);
    E.out_visible = true;
    E.out_scroll  = 0;
    layout_windows();
    free(E.out_text);
    E.out_text    = malloc(1 << 16);
    E.out_text[0] = '\0';

    if (build_has_menu(ap->lang)) {
        char flags[1024];
        build_flags_string(ap->lang, flags, sizeof flags);
        /* bounded: the notification area is one status-bar line */
        snprintf(E_notify, sizeof E_notify, "%.16s %.200s",
                 build_compiler_name(ap->lang), flags[0] ? flags : "...");
        render_status();
        doupdate();
    }
    char timing[128];
    run_file(ap->filename, ap->lang, E.out_text, 1 << 16, timing, sizeof timing);
    snprintf(E_notify, sizeof E_notify, "%s", timing);
}

static void build_menu_open(void) {
    Pane *ap = E.panes[E.active];
    if (ap->binary_view || !build_has_menu(ap->lang)) {
        snprintf(E_notify, sizeof E_notify,
                 "No build / run options for this file type");
        return;
    }
    E.mode         = MODE_BUILD_MENU;
    E.build_sel    = 0;
    E.build_scroll = 0;
}

/* Visible rows of the flag list, given the terminal height. */
static int build_menu_rows(int count) {
    int rows = getmaxy(stdscr);
    /* about two thirds of the screen; small terminals still get a usable
     * list (title, status, borders and preview take 6 rows) */
    int avail = rows * 2 / 3 - 4;
    if (avail > rows - 7) avail = rows - 7;
    if (avail < 3) avail = 3;
    return count < avail ? count : avail;
}

/* The dropdown itself: anchored at the bottom, just above the status bar. */
static void render_build_menu(void) {
    Pane *ap = E.panes[E.active];
    int count = 0;
    const BuildFlag *tbl = build_flag_table(ap->lang, &count);
    const bool *state    = build_flag_state(ap->lang);
    if (!tbl || !state) return;

    int rows, cols; getmaxyx(stdscr, rows, cols);
    int list_h = build_menu_rows(count);
    int mh = list_h + 4;                       /* borders + header + preview */
    int mw = cols;
    int my = rows - 1 - mh;
    if (my < 1) { my = 1; mh = rows - 2; if (mh < 4) return; list_h = mh - 4; }

    WINDOW *mwin = newwin(mh, mw, my, 0);
    wbkgd(mwin, ' ' | COLOR_PAIR(COLOR_PAIR_NORMAL));
    wattron(mwin, COLOR_PAIR(COLOR_PAIR_ACTIVE_BORDER));
    box(mwin, 0, 0);
    wattroff(mwin, COLOR_PAIR(COLOR_PAIR_ACTIVE_BORDER));

    static const char *lang_label[] = {
        "C","C++","Python","Shell","JS","JSON","SQL","ASM",
        "HTML","CSS","PHP","C#","Rust","HEX","Plain"
    };
    wattron(mwin, COLOR_PAIR(COLOR_PAIR_TITLE) | A_BOLD);
    mvwprintw(mwin, 0, 2, " %s options - %s (%s) ",
              build_is_compiled(ap->lang) ? "Build" : "Run",
              lang_label[ap->lang <= LANG_NONE ? ap->lang : LANG_NONE],
              build_compiler_name(ap->lang));
    wattroff(mwin, COLOR_PAIR(COLOR_PAIR_TITLE) | A_BOLD);
    if (server_running()) {
        wattron(mwin, COLOR_PAIR(COLOR_PAIR_PREPROC) | A_BOLD);
        wprintw(mwin, " server up: %.60s  (k: stop) ", server_url());
        wattroff(mwin, COLOR_PAIR(COLOR_PAIR_PREPROC) | A_BOLD);
    }

    wattron(mwin, COLOR_PAIR(COLOR_PAIR_COMMENT));
    const char *help = " Space:toggle  Up/Down:move  Enter:build & run  k:stop server  Esc:close ";
    int hx = mw - (int)strlen(help) - 3;
    if (hx > 2) mvwaddstr(mwin, mh - 1, hx, help);
    wattroff(mwin, COLOR_PAIR(COLOR_PAIR_COMMENT));

    /* keep the cursor inside the visible window */
    if (E.build_sel < E.build_scroll) E.build_scroll = E.build_sel;
    if (E.build_sel >= E.build_scroll + list_h) E.build_scroll = E.build_sel - list_h + 1;
    if (E.build_scroll < 0) E.build_scroll = 0;

    for (int r = 0; r < list_h; r++) {
        int i = E.build_scroll + r;
        if (i >= count) break;
        bool sel = (i == E.build_sel);
        /* radio (exclusive group) vs checkbox (independent) */
        const char *mark = tbl[i].group
                         ? (state[i] ? "(*)" : "( )")
                         : (state[i] ? "[x]" : "[ ]");

        bool avail = build_flag_available(ap->lang, i);
        /* a separator line before each new block (compilers, outputs...) */
        if (sel) wattron(mwin, A_REVERSE);
        mvwprintw(mwin, 1 + r, 2, "%-*s", mw - 4, "");
        wattron(mwin, state[i] ? A_BOLD : A_NORMAL);
        if (!avail && !sel) wattron(mwin, A_DIM);
        mvwprintw(mwin, 1 + r, 2, "%s %-22.22s", mark, tbl[i].label);
        wattroff(mwin, A_BOLD | A_DIM);
        if (!sel) wattron(mwin, COLOR_PAIR(COLOR_PAIR_TYPE));
        wprintw(mwin, "%-18.18s", tbl[i].flag);
        if (!sel) {
            wattroff(mwin, COLOR_PAIR(COLOR_PAIR_TYPE));
            wattron(mwin, COLOR_PAIR(COLOR_PAIR_COMMENT));
        }
        /* mark+label is 26 columns, the flag column 18; whatever is left
         * inside the box goes to the hint, so it never eats the border. */
        int left = mw - 4 - 26 - 18;
        char hint[160];
        snprintf(hint, sizeof hint, "%s%s", avail ? "" : "(not installed) ", tbl[i].hint);
        if (left > 2) wprintw(mwin, "%-*.*s", left, left, hint);
        if (!sel) wattroff(mwin, COLOR_PAIR(COLOR_PAIR_COMMENT));
        if (sel) wattroff(mwin, A_REVERSE);
    }

    /* live preview of the command ^B would run */
    char preview[4096];
    build_preview(ap->lang, ap->filename, preview, sizeof preview);
    wattron(mwin, COLOR_PAIR(COLOR_PAIR_STRING));
    mvwprintw(mwin, mh - 2, 2, "%-*.*s", mw - 4, mw - 4, preview[0] ? preview : "(nothing to run)");
    wattroff(mwin, COLOR_PAIR(COLOR_PAIR_STRING));

    if (count > list_h) {
        wattron(mwin, COLOR_PAIR(COLOR_PAIR_COMMENT));
        mvwprintw(mwin, 0, mw - 12, " %d/%d ", E.build_sel + 1, count);
        wattroff(mwin, COLOR_PAIR(COLOR_PAIR_COMMENT));
    }

    wnoutrefresh(mwin);
    delwin(mwin);
}

static void handle_key_build_menu(int key) {
    Pane *ap = E.panes[E.active];
    int count = 0;
    build_flag_table(ap->lang, &count);
    if (count <= 0) { E.mode = MODE_NORMAL; return; }

    switch (key) {
        case KEY_UP:   if (E.build_sel > 0) E.build_sel--; break;
        case KEY_DOWN: if (E.build_sel + 1 < count) E.build_sel++; break;
        case KEY_HOME: E.build_sel = 0; break;
        case KEY_END:  E.build_sel = count - 1; break;
        case KEY_PPAGE: E.build_sel -= 5; if (E.build_sel < 0) E.build_sel = 0; break;
        case KEY_NPAGE: E.build_sel += 5; if (E.build_sel >= count) E.build_sel = count - 1; break;

        case ' ':
        case 'x': case 'X':
            build_flag_toggle(ap->lang, E.build_sel);
            break;

        case '\n': case '\r':
            E.mode = MODE_NORMAL;
            build_and_run();
            break;

        case 'k': case 'K':
            if (server_running()) {
                server_stop();
    mem_ui_shutdown();
                snprintf(E_notify, sizeof E_notify, "Server stopped");
            } else {
                snprintf(E_notify, sizeof E_notify, "No server running");
            }
            break;

        case 27:
        case 'q' & 0x1f:
            E.mode = MODE_NORMAL;
            break;

        case KEY_F(5):
            E.mode = MODE_NORMAL;
            break;

        default: break;
    }
}

static void full_redraw(bool force) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    int title_h = 1, status_h = 1;
    int out_h   = E.out_visible ? (rows / 3) : 0;
    int edit_h  = rows - title_h - status_h - out_h;
    if (edit_h < 1) edit_h = 1;
    (void)cols;

    
    for (int i = 0; i < E.npanes; i++) {
        Pane *p = E.panes[i];
        if (p->mem_mode || p->img_mode || p->doc_mode)
            pane_render(p, force);                 /* these views take precedence */
        else if (p->table_mode && p->table)
            tbl_render(p->table, p->win, p->win_h, p->win_w);
        else if (p->hex_mode && p->hex)
            hex_render(p->hex, p->win, p->win_h, p->win_w);
        else
            pane_render(p, force);
    }

    
    if (E.tree && E.tree->visible && E.tree->win)
        ft_render(E.tree, E.tree->win, edit_h, E.tree->width, E.tree_focus);

    
    if (E.finfo && E.finfo->visible && E.finfo->win)
        fi_render(E.finfo, E.finfo->win, edit_h, E.finfo->width);

    
    if (E.hl && E.hl->visible && E.hl->win) {
        Pane *ap = E.panes[E.active];
        if (!ap->hex_mode && E.hl->dirty) {

            static size_t last_len  = (size_t)-1;
            static unsigned last_fp = 0;

            size_t len = gb_len(ap->buf);
            unsigned fp = (unsigned)len;
            if (len > 0) {
                fp ^= (unsigned char)gb_at(ap->buf, 0);
                fp ^= (unsigned char)gb_at(ap->buf, len / 2) << 8;
                fp ^= (unsigned char)gb_at(ap->buf, len - 1) << 16;
            }

            if (len != last_len || fp != last_fp) {
                if (len > HL_DEFER_BYTES && !hl_scan_forced) {
                    hl_scan_pending = true;
                } else {
                    hl_scan(E.hl, ap->buf);
                    last_len = len;
                    last_fp  = fp;
                    hl_scan_pending = false;
                }
            } else {
                E.hl->dirty = false;
                hl_scan_pending = false;
            }
            hl_scan_forced = false;
        } else if (ap->hex_mode) {
            hl_scan_pending = false;
        }
        int hl_w = getmaxx(E.hl->win);
        hl_render(E.hl, E.hl->win, edit_h, hl_w);
    } else {
        hl_scan_pending = false;
    }

    render_pane_borders();
    render_title();
    render_status();
    render_output();

    if (E.mode == MODE_BUILD_MENU) {
        render_build_menu();
    } else if (E.mode != MODE_NORMAL) {
        static const char *titles[] = {
            "",
            "Save As",
            "Search",
            "Open File",
            "Go to Line",
            "Jump to Offset  (decimal: 1024  or hex: 0x400)",
            "Search ASCII",
            "",
            "Search table",
            "Edit cell",
            "Search document"
        };
        if (E.mode == MODE_MEM_INPUT) {
            render_dialog(mem_dialog_title);
        } else if (E.mode == MODE_TABLE_EDIT) {
            Pane *ap = E.panes[E.active];
            char t[256];
            const TableView *tv = ap->table;
            const char *col = (tv && tv->cur < tv->nsheets && tv->col < tv->sheets[tv->cur].ncols)
                              ? tv->sheets[tv->cur].hdr[tv->col] : "";
            snprintf(t, sizeof t, "Edit  %.60s  [row %zu]   Enter:write  Esc:cancel  ^U:clear%s",
                     col, tv ? tv->row + 1 : 0, edit_escaped ? "  \\n=newline" : "");
            render_dialog(t);
        } else {
            render_dialog(titles[E.mode]);
        }
    }
    doupdate();
}

static void dialog_insert(char c) {
    size_t len = strlen(E.dialog_buf);
    if (len >= sizeof(E.dialog_buf) - 1) return;
    memmove(E.dialog_buf + E.dialog_cursor + 1,
            E.dialog_buf + E.dialog_cursor,
            len - E.dialog_cursor + 1);
    E.dialog_buf[E.dialog_cursor++] = c;
}

static void dialog_backspace(void) {
    if (!E.dialog_cursor) return;
    size_t len = strlen(E.dialog_buf);
    size_t back = 1;                      /* a whole UTF-8 character */
    while (back < E.dialog_cursor &&
           utf8_is_continuation((unsigned char)E.dialog_buf[E.dialog_cursor - back])) back++;
    memmove(E.dialog_buf + E.dialog_cursor - back,
            E.dialog_buf + E.dialog_cursor,
            len - E.dialog_cursor + 1);
    E.dialog_cursor -= back;
}

static void force_full_dirty(void) {
    for (int i = 0; i < E.npanes; i++)
        syn_mark_dirty_from(E.panes[i]->syn, 0);
}

static void open_dialog(EditorMode m, const char *prefill) {
    E.mode = m;
    if (prefill) snprintf(E.dialog_buf, sizeof(E.dialog_buf), "%s", prefill);
    else E.dialog_buf[0] = '\0';
    E.dialog_cursor = strlen(E.dialog_buf);
}

static void dialog_confirm(void) {
    Pane *ap = E.panes[E.active];
    switch (E.mode) {

        case MODE_HEX_JUMP: {
            if (ap->hex && E.dialog_buf[0]) {
                char *end;
                long off = strtol(E.dialog_buf, &end, 0);
                if (end != E.dialog_buf && off >= 0
                        && (size_t)off < ap->hex->data_len) {
                    ap->hex->cursor = (size_t)off;
                    ap->hex->nibble = 0;
                    hex_scroll_to_cursor(ap->hex, ap->win_h);
                }
            }
            E.mode = MODE_NORMAL;
            full_redraw(true);
            return;
        }

        case MODE_HEX_SEARCH: {
            if (!ap->hex) { E.mode = MODE_NORMAL; return; }
            HexPane *h = ap->hex;
            if (strcmp(E.dialog_buf, h->search_query) != 0) {
                hex_search_ascii(h, E.dialog_buf);
                if (h->search_count > 0) {
                    h->search_current = 0;
                    h->cursor = h->search_results[0];
                    hex_scroll_to_cursor(h, ap->win_h);
                }
            } else if (h->search_count > 0) {
                h->search_current = (h->search_current + 1) % h->search_count;
                h->cursor = h->search_results[h->search_current];
                hex_scroll_to_cursor(h, ap->win_h);
            }
            full_redraw(true);
            return;
        }

        case MODE_TABLE_SEARCH:
            if (ap->table && !tbl_search(ap->table, E.dialog_buf, true))
                snprintf(E_notify, sizeof E_notify, "Not found: %.200s", E.dialog_buf);
            break;

        case MODE_TABLE_EDIT:
            if (ap->table) {
                char val[sizeof E.dialog_buf];
                size_t o = 0;
                for (const char *c = E.dialog_buf; *c && o + 1 < sizeof val; c++) {
                    if (edit_escaped && c[0] == '\\' && c[1] == 'n')  { val[o++] = '\n'; c++; }
                    else if (edit_escaped && c[0] == '\\' && c[1] == '\\') { val[o++] = '\\'; c++; }
                    else val[o++] = *c;
                }
                val[o] = '\0';
                pane_table_edit(ap, val);
                if (E.hl && E.hl->visible) E.hl->dirty = true;
            }
            edit_escaped = false;
            break;

        case MODE_MEM_INPUT:
            E.mode = MODE_NORMAL;
            mem_ui_dialog_done(mem_dialog_kind, E.dialog_buf);
            return;

        case MODE_DOC_SEARCH:
            if (ap->doc && !doc_search(ap->doc, E.dialog_buf, true))
                snprintf(E_notify, sizeof E_notify, "Not found: %.200s", E.dialog_buf);
            break;

        case MODE_SAVE_DIALOG:
            pane_save_file(ap, E.dialog_buf);
            force_full_dirty();
            break;

        case MODE_OPEN_DIALOG:
            gb_free(ap->buf);  ap->buf = gb_new(GAP_DEFAULT);
            li_free(ap->li);   ap->li  = li_new();
            syn_free(ap->syn); ap->syn = syn_new(LANG_C);
            ap->cursor = 0;
            pane_open_file(ap, E.dialog_buf);
            if (E.finfo && E.finfo->visible)
                fi_analyze(E.finfo, ap->filename);
            if (E.hl && E.hl->visible)
                E.hl->dirty = true;
            layout_windows();
            force_full_dirty();
            break;

        case MODE_SEARCH_DIALOG:
            if (strcmp(E.dialog_buf, ap->search.query) != 0) {
                snprintf(ap->search.query,     sizeof ap->search.query,     "%s", E.dialog_buf);
                search_find(&ap->search, ap->buf);
                if (ap->search.count > 0) {
                    ap->search.current = 0;
                    ap->cursor = ap->search.matches[0];
                    li_rebuild(ap->li, ap->buf);
                    pane_move_cursor(ap, 0, 0);
                }
            } else {
                pane_search_next(ap);
            }
            
            snprintf(ap->syn->search_word, sizeof ap->syn->search_word, "%s", ap->search.query);
            syn_mark_dirty_from(ap->syn, 0);
            full_redraw(true);
            return;

        case MODE_GOTO_LINE: {
            long l = atol(E.dialog_buf);
            if (l > 0) pane_move_to_line_col(ap, (size_t)(l - 1), 0);
            break;
        }

        default: break;
    }
    E.mode = MODE_NORMAL;
}

static void handle_key_normal(int key) {

    
    if (key == KEY_F(1)) {
        if (E.tree) {
            E.tree->visible = !E.tree->visible;
            E.tree_focus    = E.tree->visible;
        }
        layout_windows();
        force_full_dirty();
        return;
    }

    
    static bool finfo_focus = false;
    if (key == KEY_F(3)) {
        if (E.finfo) {
            if (!E.finfo->visible) {
                E.finfo->visible = true;
                finfo_focus      = true;
                Pane *ap2  = E.panes[E.active];
                const char *fpath = ap2->hex_mode && ap2->hex
                                    ? ap2->hex->filename : ap2->filename;
                fi_analyze(E.finfo, fpath);
            } else {
                E.finfo->visible    = false;
                finfo_focus         = false;
                E.finfo->scroll_row = 0;
            }
        }
        layout_windows();
        force_full_dirty();
        return;
    }

    
    if (key == KEY_F(4)) {
        if (E.hl) {
            if (!E.hl->visible) {
                E.hl->visible = true;
                E.hl->dirty   = true;
                E.hl_focus    = true;
                Pane *ap2 = E.panes[E.active];
                if (!ap2->hex_mode)
                    hl_scan(E.hl, ap2->buf);
            } else {
                E.hl->visible = false;
                E.hl_focus    = false;
            }
        }
        layout_windows();
        force_full_dirty();
        return;
    }

    
    if (finfo_focus && E.finfo && E.finfo->visible) {
        if (key == KEY_DOWN || key == 'j') { E.finfo->scroll_row++;                        return; }
        if (key == KEY_UP   || key == 'k') { if (E.finfo->scroll_row > 0) E.finfo->scroll_row--; return; }
        if (key == '\t') { finfo_focus = false; return; }
    }
    if (!E.finfo || !E.finfo->visible) finfo_focus = false;

    
    if (E.hl_focus && E.hl && E.hl->visible) {
        if (key == KEY_DOWN || key == 'j') { E.hl->scroll++;                        return; }
        if (key == KEY_UP   || key == 'k') { if (E.hl->scroll > 0) E.hl->scroll--; return; }
        if (key == '\t') { E.hl_focus = false; return; }
        return;
    }
    if (!E.hl || !E.hl->visible) E.hl_focus = false;


    if (key == '\t' && E.hl && E.hl->visible && !E.hl_focus && !E.tree_focus) {
        E.hl_focus = true;
        return;
    }


    if (E.tree_focus && E.tree && E.tree->visible) {
        char open_path[4096] = "";
        bool consumed = ft_handle_key(E.tree, key, open_path, sizeof open_path);
        if (open_path[0]) {
            Pane *ap2 = E.panes[E.active];
            gb_free(ap2->buf);  ap2->buf = gb_new(GAP_DEFAULT);
            li_free(ap2->li);   ap2->li  = li_new();
            syn_free(ap2->syn); ap2->syn = syn_new(LANG_C);
            ap2->cursor = 0;
            pane_open_file(ap2, open_path);

            char tmp[4096];
            strncpy(tmp, open_path, sizeof tmp - 1);
            char *slash = strrchr(tmp, '/');
            if (slash && slash != tmp) {
                *slash = '\0';
                char resolved[4096];
                if (realpath(tmp, resolved))
                    strncpy(E.tree->cwd, resolved, sizeof E.tree->cwd - 1);
                ft_reload(E.tree);
            }

            if (E.finfo && E.finfo->visible)
                fi_analyze(E.finfo, open_path);
            if (E.hl && E.hl->visible)
                E.hl->dirty = true;

            E.tree_focus = false;
            layout_windows();
            force_full_dirty();
        }
        if (consumed) return;
    }

    Pane *ap = E.panes[E.active];

    /* Table view: read-only, so plain letters navigate. F2 drops to the
     * hex dump, F6 back to whatever was underneath. */
    /* F8: memory editor in this pane (process list, then scans) */
    if (key == KEY_F(8)) {
        ap->mem_mode = !ap->mem_mode;
        if (ap->mem_mode) mem_ui_enter();
        force_full_dirty();
        return;
    }
    if (ap->mem_mode) {
        if (key == ('q' & 0x1f)) { E.running = false; return; }
        if (key == ('a' & 0x1f)) { E.show_shortcuts = !E.show_shortcuts; return; }
        if (key == ('e' & 0x1f)) { editor_focus_next(); return; }
        if (!mem_ui_key(key, ap->win_h) && key == 27) {   /* Esc on an empty process list */
            ap->mem_mode = false;
            force_full_dirty();
            return;
        }
        char fill[256];
        int k = mem_ui_dialog(mem_dialog_title, sizeof mem_dialog_title, fill, sizeof fill);
        if (k) { mem_dialog_kind = k; open_dialog(MODE_MEM_INPUT, fill); }
        return;
    }

    /* Image view: nothing to edit; F2 opens the bytes in the hex view. */
    if (ap->img_mode && ap->img) {
        if (key == ('q' & 0x1f)) { E.running = false; return; }
        if (key == ('a' & 0x1f)) { E.show_shortcuts = !E.show_shortcuts; return; }
        if (key == 'r' || key == 'R') { img_reload(ap->img); return; }
        if (key == 'd' || key == 'D') { img_toggle_dither(ap->img); return; }
        if (key == ('l' & 0x1f)) { editor_split(); layout_windows(); return; }
        if (key == ('e' & 0x1f)) { editor_focus_next(); return; }
        if (key == KEY_F(2)) {
            if (!ap->hex) ap->hex = hex_new();
            hex_load(ap->hex, ap->filename);
            ap->img_mode = false;
            ap->hex_mode = true;
            force_full_dirty();
        }
        return;
    }

    /* Document view (Markdown preview, PDF, Word...). */
    if (ap->doc_mode && ap->doc) {
        DocView *dv = ap->doc;
        if (key == ('q' & 0x1f)) { E.running = false; return; }
        if (key == ('a' & 0x1f)) { E.show_shortcuts = !E.show_shortcuts; return; }
        if (key == ('l' & 0x1f)) { editor_split(); layout_windows(); return; }
        if (key == ('e' & 0x1f)) { editor_focus_next(); return; }
        if (key == KEY_F(7) && !ap->binary_view) { ap->doc_mode = false; force_full_dirty(); return; }
        if (key == ('s' & 0x1f) && !ap->binary_view) {      /* the Markdown text behind the view */
            if (ap->filename[0]) pane_save_file(ap, NULL);
            return;
        }
        if (key == KEY_F(2) && ap->binary_view) {
            if (!ap->hex) ap->hex = hex_new();
            hex_load(ap->hex, ap->filename);
            ap->doc_mode = false;
            ap->hex_mode = true;
            force_full_dirty();
            return;
        }
        if (key == ('f' & 0x1f)) {
            open_dialog(MODE_DOC_SEARCH, dv->search[0] ? dv->search : NULL);
            return;
        }
        if (key == ('n' & 0x1f) || key == ('p' & 0x1f)) {
            if (dv->search[0] && !doc_search(dv, dv->search, key == ('n' & 0x1f)))
                snprintf(E_notify, sizeof E_notify, "Not found: %.200s", dv->search);
            return;
        }
        if (key == KEY_MOUSE) {
            MEVENT ev;
            if (getmouse(&ev) == OK) {
                int step = (ev.bstate & BUTTON4_PRESSED) ? KEY_UP
                         : (ev.bstate & BUTTON5_PRESSED) ? KEY_DOWN : 0;
                for (int i = 0; step && i < 3; i++) doc_handle_key(dv, step, ap->win_h);
            }
            return;
        }
        doc_handle_key(dv, key, ap->win_h);
        return;
    }

    if (ap->table_mode && ap->table) {
        TableView *tv = ap->table;
        if (key == ('q' & 0x1f)) { E.running = false; return; }
        if (tv->menu.open) { tbl_filter_menu_key(tv, key, ap->win_h); return; }
        if (key == ('a' & 0x1f)) { E.show_shortcuts = !E.show_shortcuts; return; }
        if (key == KEY_F(6))     { ap->table_mode = false; force_full_dirty(); return; }
        if (key == KEY_F(2)) {
            ap->table_mode = false;
            if (ap->hex_mode) { force_full_dirty(); return; }
        } else {
            if (key == ('s' & 0x1f)) {
                if (ap->filename[0]) pane_save_file(ap, NULL);
                return;
            }
            if (key == ('f' & 0x1f)) {
                open_dialog(MODE_TABLE_SEARCH, tv->search[0] ? tv->search : NULL);
                return;
            }
            if (key == ('n' & 0x1f) || key == ('p' & 0x1f)) {
                if (tv->search[0] && !tbl_search(tv, tv->search, key == ('n' & 0x1f)))
                    snprintf(E_notify, sizeof E_notify, "Not found: %.200s", tv->search);
                return;
            }
            if (key == '\n' || key == '\r' || key == KEY_ENTER || key == 'e' || key == 'i') {
                char why[192];
                if (!tbl_cell_editable(tv, why, sizeof why)) {
                    snprintf(E_notify, sizeof E_notify, "%s", why);
                    return;
                }
                const char *c = tbl_cell(tv, tv->row, tv->col);
                if (!c) c = "";
                edit_escaped = strchr(c, '\n') != NULL;
                char pre[sizeof E.dialog_buf];
                size_t o = 0;
                for (const char *k = c; *k && o + 2 < sizeof pre; k++) {
                    if (edit_escaped && *k == '\n')      { pre[o++] = '\\'; pre[o++] = 'n'; }
                    else if (edit_escaped && *k == '\\') { pre[o++] = '\\'; pre[o++] = '\\'; }
                    else if (*k != '\r')                 pre[o++] = *k;
                }
                pre[o] = '\0';
                if (strlen(c) >= sizeof E.dialog_buf - 1) {
                    snprintf(E_notify, sizeof E_notify, "Cell too long to edit here (%zu bytes): edit it in the text", strlen(c));
                    return;
                }
                open_dialog(MODE_TABLE_EDIT, pre);
                return;
            }
            if (key == 'v' || key == ' ') {
                const char *c = tbl_cell(tv, tv->row, tv->col);
                snprintf(E_notify, sizeof E_notify, "%.250s", c ? c : "(empty)");
                for (char *q = E_notify; *q; q++) if (*q == '\n' || *q == '\t') *q = ' ';
                return;
            }
            if (key == ('z' & 0x1f) || key == ('y' & 0x1f)) {
                if (tv->sqlite || tv->from_hex) {
                    snprintf(E_notify, sizeof E_notify, "Nothing to undo here");
                    return;
                }
                if (key == ('z' & 0x1f)) pane_undo(ap); else pane_redo(ap);
                pane_table_enter(ap);
                return;
            }
            if (key == KEY_MOUSE) {
                MEVENT ev;
                if (getmouse(&ev) == OK) {
                    int step = (ev.bstate & BUTTON4_PRESSED) ? KEY_UP
                             : (ev.bstate & BUTTON5_PRESSED) ? KEY_DOWN : 0;
                    for (int i = 0; step && i < 3; i++) tbl_handle_key(tv, step, ap->win_h);
                }
                return;
            }
            tbl_handle_key(tv, key, ap->win_h);
            return;
        }
    }


    if (ap->hex_mode && ap->hex) {
        if (key == ('q' & 0x1f)) { E.running = false; return; }
        if (key == ('a' & 0x1f)) { E.show_shortcuts = !E.show_shortcuts; return; }
        if (key == KEY_F(2)) {
            ap->hex_mode = false;
            if (ap->binary_view) {               /* back to the picture / document */
                if (ap->img) { ap->img_mode = true; img_reload(ap->img); }
                else         pane_doc_enter(ap);
            }
            force_full_dirty();
            return;
        }
        if (key == KEY_F(6))     { pane_table_enter(ap); return; }
        if (key == ('s' & 0x1f)) { hex_save(ap->hex, NULL); return; }
        if (key == ('o' & 0x1f)) {
            open_dialog(MODE_SAVE_DIALOG, ap->hex->filename[0] ? ap->hex->filename : NULL);
            return;
        }
        if (key == ('j' & 0x1f)) { open_dialog(MODE_HEX_JUMP, NULL); return; }
        if (key == ('f' & 0x1f)) {
            open_dialog(MODE_HEX_SEARCH, ap->hex->search_query[0] ? ap->hex->search_query : NULL);
            return;
        }
        hex_handle_key(ap->hex, key, ap->win_h);
        return;
    }

    
    switch (key) {
        case KEY_UP:    pane_move_cursor(ap, -1,  0); break;
        case KEY_DOWN:  pane_move_cursor(ap,  1,  0); break;
        case KEY_LEFT:  pane_move_cursor(ap,  0, -1); break;
        case KEY_RIGHT: pane_move_cursor(ap,  0,  1); break;
        case KEY_PPAGE: pane_move_cursor(ap, -(ap->win_h > 2 ? ap->win_h - 1 : 1), 0); break;
        case KEY_NPAGE: pane_move_cursor(ap,  (ap->win_h > 2 ? ap->win_h - 1 : 1), 0); break;

        case KEY_HOME: {
            size_t ls = li_line_start(ap->li, ap->cursor_line);
            ap->cursor     = ls;
            ap->scroll_col = 0;
            pane_move_cursor(ap, 0, 0);
            break;
        }
        case KEY_END: {
            size_t nl = li_line_count(ap->li);
            size_t le = (ap->cursor_line + 1 < nl)
                        ? li_line_start(ap->li, ap->cursor_line + 1) - 1
                        : gb_len(ap->buf);
            ap->cursor = le;
            pane_move_cursor(ap, 0, 0);
            break;
        }

        case KEY_BACKSPACE: case 127: case '\b': pane_delete_char(ap);    break;
        case KEY_DC:
            if (ap->syn->search_word[0]) pane_search_prev(ap);
            else                         pane_delete_forward(ap);
            break;
        case '\n': case '\r':                    pane_insert_char(ap, '\n'); break;
        case '\t':                               pane_insert_str(ap, "    ", 4); break;

        case 'o' & 0x1f:
            open_dialog(MODE_SAVE_DIALOG, ap->filename[0] ? ap->filename : NULL);
            break;
        case 's' & 0x1f:
            if (ap->filename[0]) pane_save_file(ap, NULL);
            else open_dialog(MODE_SAVE_DIALOG, NULL);
            break;
        case 'z' & 0x1f: pane_undo(ap);  break;
        case 'y' & 0x1f: pane_redo(ap);  break;
        case 'c' & 0x1f: pane_copy(ap);  break;
        case 'x' & 0x1f: pane_cut(ap);   break;
        case 'v' & 0x1f: pane_paste(ap); break;
        case 'k' & 0x1f: pane_kill_whole_line(ap); break;
        case 't' & 0x1f: pane_kill_whole_line(ap); break;
        case 'f' & 0x1f:
            open_dialog(MODE_SEARCH_DIALOG, ap->search.query[0] ? ap->search.query : NULL);
            break;
        case 'n' & 0x1f: pane_search_next(ap); break;
        case 'p' & 0x1f: pane_search_prev(ap); break;
        case 'b' & 0x1f:
            build_tap_pending = true;          /* resolved by the main loop */
            break;

        case KEY_F(5):
            build_menu_open();
            break;
        case KEY_F(6):
            pane_table_enter(ap);
            break;
        case KEY_F(7):
            pane_doc_enter(ap);
            break;
        case 'r' & 0x1f:
            ap->show_line_numbers = !ap->show_line_numbers;
            pane_set_window(ap, ap->win, ap->win_y, ap->win_x, ap->win_h, ap->win_w);
            pane_scroll_to_cursor(ap);
            break;
        case 'w' & 0x1f:
            pane_wipe_file(ap);
            if (E.hl && E.hl->visible) E.hl->dirty = true;
            break;
        case 'l' & 0x1f: editor_split(); layout_windows(); break;
        case 'e' & 0x1f: editor_focus_next(); break;
        case 'g' & 0x1f: open_dialog(MODE_GOTO_LINE, NULL); break;
        case 'a' & 0x1f: E.show_shortcuts = !E.show_shortcuts; break;

        case 'd' & 0x1f:
            pane_beautify(ap);
            force_full_dirty();
            break;

        case KEY_F(2):
            if (!ap->hex) ap->hex = hex_new();
            if (ap->filename[0]) hex_load(ap->hex, ap->filename);
            ap->hex_mode = true;
            force_full_dirty();
            break;

        case 'q' & 0x1f: E.running = false; break;

        case KEY_SLEFT:
            if (!ap->sel_active) { ap->sel_active = true; ap->sel_anchor = ap->cursor; }
            pane_move_cursor(ap, 0, -1); break;
        case KEY_SRIGHT:
            if (!ap->sel_active) { ap->sel_active = true; ap->sel_anchor = ap->cursor; }
            pane_move_cursor(ap, 0,  1); break;
        case KEY_SR:
            if (!ap->sel_active) { ap->sel_active = true; ap->sel_anchor = ap->cursor; }
            pane_move_cursor(ap, -1, 0); break;
        case KEY_SF:
            if (!ap->sel_active) { ap->sel_active = true; ap->sel_anchor = ap->cursor; }
            pane_move_cursor(ap,  1, 0); break;

        case KEY_MOUSE: {
            MEVENT ev;
            if (getmouse(&ev) == OK) {
                if (ev.bstate & BUTTON4_PRESSED) {
                    if (E.tree_focus && E.tree && E.tree->visible) {
                        if (E.tree->selected > 0) E.tree->selected--;
                    } else if (E.hl_focus && E.hl && E.hl->visible) {
                        if (E.hl->scroll > 0) E.hl->scroll--;
                    } else if (E.finfo && E.finfo->visible) {
                        if (E.finfo->scroll_row > 0) E.finfo->scroll_row--;
                    } else {
                        pane_move_cursor(ap, -3, 0);
                    }
                } else if (ev.bstate & BUTTON5_PRESSED) {
                    if (E.tree_focus && E.tree && E.tree->visible) {
                        if (E.tree->selected + 1 < E.tree->count) E.tree->selected++;
                    } else if (E.hl_focus && E.hl && E.hl->visible) {
                        E.hl->scroll++;
                    } else if (E.finfo && E.finfo->visible) {
                        E.finfo->scroll_row++;
                    } else {
                        pane_move_cursor(ap, 3, 0);
                    }
                }
            }
            break;
        }

        case 27:
            ap->sel_active = false;
            if (ap->search.query[0]) {
                ap->syn->search_word[0] = '\0';
                syn_mark_dirty_from(ap->syn, 0);
            }
            break;

        default:
            if (key >= 32 && key < 127) pane_insert_char(ap, (char)key);
            else if (key >= 128)         pane_insert_char(ap, (char)key);
            
            if (E.hl && E.hl->visible) E.hl->dirty = true;
            break;
    }
}

static void handle_key_dialog(int key) {
    switch (key) {
        case '\n': case '\r': dialog_confirm(); break;
        case 27:
            if (E.mode == MODE_SEARCH_DIALOG) {
                Pane *ap = E.panes[E.active];
                ap->syn->search_word[0] = '\0';
                syn_mark_dirty_from(ap->syn, 0);
            }
            E.mode = MODE_NORMAL;
            break;
        case KEY_BACKSPACE: case 127: case '\b': dialog_backspace(); break;
        case KEY_DC:
            if (E.mode == MODE_SEARCH_DIALOG) {
                Pane *ap = E.panes[E.active];
                if (strcmp(E.dialog_buf, ap->search.query) != 0) {
                    snprintf(ap->search.query, sizeof ap->search.query, "%s", E.dialog_buf);
                    search_find(&ap->search, ap->buf);
                }
                snprintf(ap->syn->search_word, sizeof ap->syn->search_word, "%s", ap->search.query);
                syn_mark_dirty_from(ap->syn, 0);
                if (ap->search.count > 0) {
                    int idx = (int)ap->search.count - 1;
                    for (int i = (int)ap->search.count - 1; i >= 0; i--) {
                        if (ap->search.matches[i] < ap->cursor) { idx = i; break; }
                    }
                    ap->search.current = (idx + 1) % (int)ap->search.count;
                }
                pane_search_prev(ap);
                full_redraw(true);
            }
            break;
        case KEY_LEFT:
            if (E.dialog_cursor > 0) E.dialog_cursor--;
            while (E.dialog_cursor > 0 &&
                   utf8_is_continuation((unsigned char)E.dialog_buf[E.dialog_cursor])) E.dialog_cursor--;
            break;
        case KEY_RIGHT:
            if (E.dialog_cursor < strlen(E.dialog_buf)) E.dialog_cursor++;
            while (E.dialog_buf[E.dialog_cursor] &&
                   utf8_is_continuation((unsigned char)E.dialog_buf[E.dialog_cursor])) E.dialog_cursor++;
            break;
        case KEY_HOME:
            E.dialog_cursor = 0;
            break;
        case KEY_END:
            E.dialog_cursor = strlen(E.dialog_buf);
            break;
        case 'u' & 0x1f:                 /* clear the field */
            E.dialog_buf[0] = '\0';
            E.dialog_cursor = 0;
            break;
        case 'n' & 0x1f:
            if (E.mode == MODE_SEARCH_DIALOG) {
                dialog_confirm();
            }
            break;
        case 'p' & 0x1f:
            if (E.mode == MODE_SEARCH_DIALOG) {
                Pane *ap = E.panes[E.active];
                if (strcmp(E.dialog_buf, ap->search.query) != 0) {
                    snprintf(ap->search.query, sizeof ap->search.query, "%s", E.dialog_buf);
                    search_find(&ap->search, ap->buf);
                }
                snprintf(ap->syn->search_word, sizeof ap->syn->search_word, "%s", ap->search.query);
                syn_mark_dirty_from(ap->syn, 0);
                
                if (ap->search.count > 0) {
                    int idx = (int)ap->search.count - 1;
                    for (int i = (int)ap->search.count - 1; i >= 0; i--) {
                        if (ap->search.matches[i] < ap->cursor) { idx = i; break; }
                    }
                    

                    ap->search.current = (idx + 1) % (int)ap->search.count;
                }
                pane_search_prev(ap);
                full_redraw(true);
            }
            break;
        default:
            /* printable ASCII, and the bytes of UTF-8 characters */
            if ((key >= 32 && key < 127) || (key >= 128 && key < 256)) dialog_insert((char)key);
            break;
    }
}

void editor_init(void) {
    memset(&E, 0, sizeof E);
    pthread_mutex_init(&E.save_mutex, NULL);
    E.panes[0]   = pane_new();
    E.npanes     = 1;
    E.active     = 0;
    E.running    = true;
    E.tree       = ft_new();
    E.tree_focus = false;
    E.finfo      = fi_new();
    E.hl         = hl_new();
    E.hl_focus   = false;
    hl_progress_fn = hl_spinner_tick;
    mem_progress   = mem_scan_progress;
}

void editor_split(void) {
    if (E.npanes >= MAX_PANES) return;
    Pane *np = pane_new();
    Pane *ap = E.panes[E.active];
    if (ap->filename[0]) {
        pane_open_file(np, ap->filename);
        np->cursor      = ap->cursor;
        np->cursor_line = ap->cursor_line;
        np->cursor_col  = ap->cursor_col;
        np->scroll_line = ap->scroll_line;
    }
    E.panes[E.npanes++] = np;
    E.active = E.npanes - 1;
}

void editor_close_split(void) {
    if (E.npanes <= 1) return;
    if (E.panes[E.active]->win) {
        delwin(E.panes[E.active]->win);
        E.panes[E.active]->win = NULL;
    }
    pane_free(E.panes[E.active]);
    for (int i = E.active; i < E.npanes - 1; i++) E.panes[i] = E.panes[i + 1];
    E.npanes--;
    if (E.active >= E.npanes) E.active = E.npanes - 1;
}

void editor_focus_next(void)   { E.active = (E.active + 1) % E.npanes; }
void editor_resize_panes(void) { layout_windows(); }

void editor_cleanup(void) {
    for (int i = 0; i < E.npanes; i++) {
        if (E.panes[i]->win) delwin(E.panes[i]->win);
        pane_free(E.panes[i]);
    }
    if (E.title_win)  delwin(E.title_win);
    if (E.status_win) delwin(E.status_win);
    if (E.out_win)    delwin(E.out_win);
    if (E.tree) {
        if (E.tree->win) delwin(E.tree->win);
        ft_free(E.tree);
    }
    if (E.finfo) {
        if (E.finfo->win) delwin(E.finfo->win);
        fi_free(E.finfo);
    }
    if (E.hl) {
        if (E.hl->win) delwin(E.hl->win);
        hl_free(E.hl);
    }
    free(E.out_text);
    pthread_mutex_destroy(&E.save_mutex);
    server_stop();
    unlink("./temp_bin");
}

void editor_run(const char *initial_file) {
    #ifdef _WIN32
    win_init_utf8();
    setlocale(LC_ALL, ".UTF-8");   /* "" donnerait French_France.1252 → UTF-8 mal décodé */
#else
    setlocale(LC_ALL, "");
#endif
    initscr(); raw(); noecho();
    keypad(stdscr, TRUE);
    set_escdelay(25);
    curs_set(0);

    colors_init();
    use_default_colors();
    hex_colors_init();
    fi_colors_init();
    hl_colors_init();
    ft_init_color_pairs();          /* fixed pairs first: the image view allocates the rest */
    colors_win_polish();

    printf("\033[?2004h");  
    /* Kitty keyboard protocol, level 1 ("disambiguate escape codes"): makes
     * the terminal report modifiers for keys the legacy encoding folds
     * together (Ctrl+I vs Tab, Ctrl+M vs Enter, ...).
     * Only ambiguous keys change shape (plain text is untouched), and those
     * are decoded back below; terminals without support ignore the push. */
    printf("\033[>1u");
    fflush(stdout);
    layout_windows();

    if (initial_file) {
        pane_open_file(E.panes[0], initial_file);
        layout_windows();
    }
    full_redraw(true);

    {
#ifndef _WIN32
        struct termios t;
        tcgetattr(STDIN_FILENO, &t);
        t.c_iflag &= ~(IXON | IXOFF);
        tcsetattr(STDIN_FILENO, TCSANOW, &t);
#endif
        def_prog_mode();
    }

    bool in_paste   = false;
    char paste_batch[1 << 18];
    int  paste_len  = 0;

    while (E.running) {
#ifdef _WIN32
        {
            int nr, nc, cr, cc;
            getmaxyx(stdscr, cr, cc);
            if (win_console_size(&nr, &nc) && (nr != cr || nc != cc)) {
                resize_term(nr, nc);
                clearok(curscr, TRUE);
                layout_windows();
                full_redraw(true);
            }
        }
#endif
        WINDOW *iw  = E.panes[E.active]->win;
        WINDOW *kw  = iw ? iw : stdscr;

        int tmo = build_tap_pending ? BUILD_DOUBLE_TAP_MS
        	: hl_scan_pending   ? 300 : -1;
        {                                           /* memory editor: live values, freezes */
            int mt = mem_ui_timeout(mem_visible());
            if (mt > 0 && (tmo < 0 || mt < tmo)) tmo = mt;
        }
	#ifdef _WIN32
    		if (tmo < 0) tmo = 100;   /* pas de SIGWINCH sous Windows : on sonde la taille toutes les 100 ms */
	#endif
        if (tmo >= 0) wtimeout(kw, tmo);
        int key = wgetch(kw);
        if (tmo >= 0) wtimeout(kw, -1);
	        if (build_tap_pending && key == ERR) {      /* single ^B */
            build_tap_pending = false;
            build_and_run();
            full_redraw(true);
            continue;
        }
        if (hl_scan_pending) {
            if (key == ERR) {
                hl_scan_forced = true;
                full_redraw(false);
                continue;
            }
        }

        mem_ui_tick();                              /* frozen addresses */
        if (key == ERR && mem_visible()) {          /* live values: once a second, F8 only */
            if (mem_ui_refresh_due()) full_redraw(false);
            continue;
        }
        if (key == 0 || key == ERR || key == 0x16) continue;

        E_notify[0] = '\0';

        if (key == KEY_RESIZE) {
	#ifdef _WIN32
    		int nr = 0, nc = 0;
    		int ok = win_console_size(&nr, &nc);
    		if (ok) resize_term(nr, nc);   /* force la taille réelle de la fenêtre visible */
    		else    resize_term(0, 0);
    		clearok(curscr, TRUE);
	#else
    		endwin(); refresh();
	#endif
    		layout_windows(); full_redraw(true);
    		continue;
	}

        /* Enter closes the output panel (only outside dialogs and menus,
         * where Enter has its own meaning) */
        if (E.out_visible && E.mode == MODE_NORMAL &&
            (key == '\n' || key == '\r' || key == KEY_ENTER)) {
            E.out_visible = false;
            layout_windows();
            full_redraw(true);
            continue;
        }
        
        if (key == 27) {
            WINDOW *ew = iw ? iw : stdscr;
            wtimeout(ew, 5);
            int sq[16]; int sn = 0;
            for (; sn < 16; sn++) {
                sq[sn] = wgetch(ew);
                if (sq[sn] == ERR) { sn--; break; }
            }
            sn++; if (sn < 0) sn = 0;
            wtimeout(ew, -1);

            bool consumed = false;

            if (sn >= 1 && sq[0] == '[') {
                if (!consumed && sn >= 2 && sq[1] == 'Z') {
                    for (int si = sn - 1; si >= 2; si--)
                        if (sq[si] != ERR) ungetch(sq[si]);
                    key = KEY_BTAB; consumed = true;
                }
                
                if (!consumed && sn >= 6
                        && sq[1]=='2' && sq[2]=='7'
                        && sq[3]==';' && sq[4]=='5' && sq[5]==';') {
                    int n9 = (sn > 6) ? sq[6] : ERR, ntl = (sn > 7) ? sq[7] : ERR;
                    if (n9 == '9') {
                        if (ntl != '~' && ntl != ERR) ungetch(ntl);
                        key = KEY_BTAB; consumed = true;
                    }
                }
                
                if (!consumed && sn >= 5
                        && sq[1]=='1' && sq[2]==';' && sq[3]=='5' && sq[4]=='I') {
                    for (int si = sn - 1; si >= 5; si--)
                        if (sq[si] != ERR) ungetch(sq[si]);
                    key = KEY_BTAB; consumed = true;
                }
                
                if (!consumed && sn >= 5
                        && sq[1]=='9' && sq[2]==';' && sq[3]=='5' && sq[4]=='u') {
                    for (int si = sn - 1; si >= 5; si--)
                        if (sq[si] != ERR) ungetch(sq[si]);
                    key = KEY_BTAB; consumed = true;
                }
                
                if (!consumed && sn >= 5
                        && sq[1]=='2' && sq[2]=='0' && sq[3]=='0' && sq[4]=='~') {
                    in_paste = true; paste_len = 0;
                    if (sn > 5 && sq[5] != ERR && paste_len < (int)sizeof(paste_batch) - 1)
                        paste_batch[paste_len++] = (char)sq[5];
                    for (int si = sn - 1; si >= 6; si--)
                        if (sq[si] != ERR) ungetch(sq[si]);
                    consumed = true;
                    continue;
                }
                
                if (!consumed && sn >= 5
                        && sq[1]=='2' && sq[2]=='0' && sq[3]=='1' && sq[4]=='~') {
                    if (in_paste && paste_len > 0 && E.mode == MODE_NORMAL) {
                        paste_batch[paste_len] = '\0';
                        Pane *ap2 = E.panes[E.active];
                        if (!ap2->hex_mode && !ap2->table_mode && !ap2->mem_mode &&
                            !ap2->img_mode && !ap2->doc_mode) {
                            pane_insert_str(ap2, paste_batch, paste_len);
                            if (E.hl && E.hl->visible) E.hl->dirty = true;
                        }
                    }
                    in_paste = false; paste_len = 0;
                    for (int si = sn - 1; si >= 5; si--)
                        if (sq[si] != ERR) ungetch(sq[si]);
                    consumed = true;
                    full_redraw(true); continue;
                }
                /* F1-F4 under the keyboard protocol: CSI [1;<mod>] P/Q/R/S
                 * and CSI 13 [;<mod>] ~ for F3 — none of which match the
                 * terminfo SS3 forms ncurses would otherwise decode. */
                if (!consumed) {
                    int last = sn - 1;
                    while (last > 0 && sq[last] == ERR) last--;
                    int fk = 0, si = 1, num = 0;
                    while (si < last && (isdigit(sq[si]) || sq[si] == ';')) si++;
                    if (si == last) {
                        for (int di = 1; di < last && isdigit(sq[di]); di++)
                            num = num * 10 + (sq[di] - '0');
                        int c = sq[last];
                        if (c >= 'P' && c <= 'S' && (num == 0 || num == 1))
                            fk = c - 'P' + 1;
                        else if (c == '~' && num == 13)
                            fk = 3;
                        else if (c == '~' && num == 15)
                            fk = 5;
                        else if (c == '~' && num == 17)
                            fk = 6;
                    }
                    if (fk) { key = KEY_F(fk); consumed = true; }
                }
                /* CSI <codepoint> [;<modifiers>] u — the shape every
                 * ambiguous key takes once the protocol above is on.
                 * modifiers-1 is a bitmask: 1 shift, 2 alt, 4 ctrl. */
                if (!consumed) {
                    char seq[17]; int sl = 0;
                    for (int si = 0; si < sn && sq[si] != ERR; si++)
                        seq[sl++] = (char)sq[si];
                    seq[sl] = '\0';

                    if (sl >= 3 && seq[sl - 1] == 'u') {
                        const char *q = seq + 1;
                        int cp = 0, mod = 1;
                        bool has_cp = isdigit((unsigned char)*q);
                        while (isdigit((unsigned char)*q)) cp = cp * 10 + (*q++ - '0');
                        if (*q == ':')                       /* alternate key codes */
                            while (*q && *q != ';' && *q != 'u') q++;
                        if (*q == ';') {
                            q++; mod = 0;
                            while (isdigit((unsigned char)*q)) mod = mod * 10 + (*q++ - '0');
                            if (mod < 1) mod = 1;
                            if (*q == ':')                   /* event type (press/repeat) */
                                while (*q && *q != 'u') q++;
                        }
                        if (has_cp && *q == 'u') {
                            int  m     = mod - 1;
                            bool shift = (m & 1) != 0;
                            bool alt   = (m & 2) != 0;
                            bool ctrl  = (m & 4) != 0;
                            int  base  = cp;
                            int  mapped;

                            if (ctrl && isalpha(base))
                                mapped = tolower(base) & 0x1f;
                            else if (base == 13)  mapped = '\n';
                            else if (base == 9)   mapped = shift ? KEY_BTAB : '\t';
                            else if (base == 27)  mapped = 27;
                            else if (base == 127) mapped = KEY_BACKSPACE;
                            else if (!alt && base >= 32 && base < 127)
                                mapped = shift ? toupper(base) : base;
                            else
                                mapped = 0;

                            if (mapped) { key = mapped; consumed = true; }
                            else        { consumed = true; continue; }
                        }
                    }
                }

                if (!consumed) {
                    for (int si = sn - 1; si >= 0; si--)
                        if (sq[si] != ERR) ungetch(sq[si]);
                }
            } else {
                for (int si = sn - 1; si >= 0; si--)
                    if (sq[si] != ERR) ungetch(sq[si]);
            }
            (void)consumed;
        }

        if (build_tap_pending && !in_paste) {
            build_tap_pending = false;
            if (key == ('b' & 0x1f) && E.mode == MODE_NORMAL) {
                build_menu_open();                  /* ^B ^B */
                full_redraw(true);
                continue;
            }
            build_and_run();                        /* ^B then another key */
            full_redraw(true);
        }

        if (in_paste) {
            if (key != ERR && paste_len < (int)sizeof(paste_batch) - 1)
                paste_batch[paste_len++] = (char)key;
            continue;
        }

        EditorMode prev_mode = E.mode;
        if (E.mode == MODE_NORMAL)           handle_key_normal(key);
        else if (E.mode == MODE_BUILD_MENU)  handle_key_build_menu(key);
        else                                 handle_key_dialog(key);

        if (prev_mode == MODE_BUILD_MENU && E.mode == MODE_NORMAL) force_full_dirty();

        bool force = (prev_mode != MODE_NORMAL && E.mode == MODE_NORMAL);
        full_redraw(force);
    }

    printf("\033[?2004l");  
    printf("\033[<u");      /* pop the keyboard-protocol flags */
    fflush(stdout);
    endwin();
}

int main(int argc, char *argv[]) {
#ifdef _WIN32
    _fmode = _O_BINARY;
#endif
    /* ... le code existant continue ici ... */
    editor_init();
    editor_run(argc > 1 ? argv[1] : NULL);
    editor_cleanup();
    return 0;
}