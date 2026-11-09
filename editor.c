#include "abyss.h"
#include "utf8.h"
#include "memscan.h"
#include "disview.h"

void ft_init_color_pairs(void);
#include <string.h>
#include <locale.h>
#include <time.h>
#include <dirent.h>
#include <strings.h>
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

/* copies src into dst (size n), truncated and always NUL-terminated
 * (snprintf "%s" would do the same but warns -Wformat-truncation) */
static void str_copy(char *dst, size_t n, const char *src) {
    if (!n) return;
    size_t l = strlen(src);
    if (l >= n) l = n - 1;
    memmove(dst, src, l);
    dst[l] = '\0';
}

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
#ifdef BUTTON5_PRESSED
#  define MOUSE_WHEEL_DOWN BUTTON5_PRESSED
#else
#  define MOUSE_WHEEL_DOWN 0
#endif
static bool finfo_focus = false;    /* F3 panel: Up / Down scroll it (also set by a click) */

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
    if (E.out_visible && E.out_win && run_active())
        run_resize(getmaxx(E.out_win), getmaxy(E.out_win) - 1);
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
        if (ap->dis_mode)
            wprintw(E.title_win,
                " [DISASM] Tab:Info/Functions/Disasm  Enter:Disassemble  Arrows/jk  PgUp/PgDn/Space  g/G:Top/End  s:Sort"
                "  /:Filter  ':':Go to addr  Esc:Back/Close  F9:Close  ^E:Next pane  ^Q:Quit");
        else if (ap->mem_mode)
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
                " [TABLE] Arrows/hjkl:Move  Enter/e:Edit cell  s:Sort col (adds)  S:Unsort all  f:Filter col  F:Unfilter all  w:Save rows shown  v:Show cell"
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
        const char *hex_tag  = ap->dis_mode ? "  [DISASM]" : ap->mem_mode ? "  [MEMORY]" : ap->img_mode ? "  [IMAGE]" : ap->doc_mode ? "  [DOC]"
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
        if (ap->url[0]) {                 /* fetched page: its name, then the URL */
            snprintf(base, sizeof base, "%s  [URL]", ap->url_name);
            snprintf(dir, sizeof dir, "%s", ap->url);
        } else if (ap->filename[0]) {
            const char *sl = strrchr(ap->filename, '/');
#ifdef _WIN32
            const char *bs = strrchr(ap->filename, '\\');
            if (bs && (!sl || bs > sl)) sl = bs;
#endif
            str_copy(base, sizeof base, sl ? sl + 1 : ap->filename);
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

    if (ap->dis_mode && ap->dis) {
        char info[512];
        dis_status(ap->dis, info, sizeof info);
        waddstr(E.status_win, info);
    } else if (ap->mem_mode) {
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
 * accented compiler messages wrap where they should). Row 0 is a header
 * saying what runs and which keys do what; while the console follows
 * the output, the newest rows stay in view. */
static size_t out_total_rows = 0;   /* wrapped rows of the text, last render */
static int    out_text_rows  = 1;   /* rows the panel shows text on          */

/* Walks the text wrapped to `w` columns: returns how many rows it takes,
 * draws rows [first, first + h) from y0 when `win` is given, and tells
 * where the text ends (where the console cursor goes). */
static size_t out_layout(WINDOW *win, int y0, int w, size_t first, int h,
                         size_t *end_row, int *end_col) {
    const char *ptr = E.out_text;
    size_t row = 0;
    int last_cols = 0;
    while (*ptr) {
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
            if (win && row >= first && row < first + (size_t)h) {
                wmove(win, y0 + (int)(row - first), 0);
                for (size_t i = off; i < end; i++) {
                    if (ptr[i] == '\t') waddstr(win, "    ");
                    else if ((unsigned char)ptr[i] >= 32) waddch(win, (chtype)(unsigned char)ptr[i]);
                }
            }
            last_cols = cols;
            row++;
            off = end;
        } while (off < len);
        if (!nl) {                                 /* text ends mid-line */
            if (end_row) { *end_row = row - 1; *end_col = last_cols; }
            return row;
        }
        ptr = nl + 1;
    }
    if (end_row) { *end_row = row; *end_col = 0; } /* after a newline */
    return row;
}

static void render_output(void) {
    if (!E.out_visible || !E.out_win || !E.out_text) return;
    int h, w; getmaxyx(E.out_win, h, w);
    if (w < 1 || h < 1) return;
    werase(E.out_win);

    bool live    = run_active();
    bool console = live && E.out_focus;
    int  y0      = h >= 2 ? 1 : 0;
    int  th      = h - y0;
    if (y0) {
        char hdr[256];
        if (console)
            snprintf(hdr, sizeof hdr, " %s  |  type: input   Enter: send   ^D: end of input   ^C: stop   Esc: editor   PgUp/PgDn: scroll",
                     run_compiling() ? "Compiling..." : "Running");
        else if (live)
            snprintf(hdr, sizeof hdr, " %s in the background  |  ^B: back to the console",
                     run_compiling() ? "Compiling" : "Running");
        else
            snprintf(hdr, sizeof hdr, " Output  |  Enter: close   ^B: build & run again");
        wattron(E.out_win, COLOR_PAIR(COLOR_PAIR_TITLE) | A_BOLD | A_REVERSE);
        mvwhline(E.out_win, 0, 0, ' ', w);
        mvwaddnstr(E.out_win, 0, 0, hdr, w);
        wattroff(E.out_win, COLOR_PAIR(COLOR_PAIR_TITLE) | A_BOLD | A_REVERSE);
    }

    size_t end_row = 0; int end_col = 0;
    size_t total = out_layout(NULL, 0, w, 0, 0, &end_row, &end_col);
    size_t need  = (console && end_row >= total) ? end_row + 1 : total;
    size_t max_first = need > (size_t)th ? need - (size_t)th : 0;
    if (E.out_follow || E.out_scroll > max_first) E.out_scroll = max_first;
    if (E.out_scroll >= max_first) E.out_follow = true;
    out_total_rows = need;
    out_text_rows  = th;

    wattron(E.out_win, COLOR_PAIR(COLOR_PAIR_COMMENT));
    out_layout(E.out_win, y0, w, E.out_scroll, th, NULL, NULL);
    wattroff(E.out_win, COLOR_PAIR(COLOR_PAIR_COMMENT));

    if (console && end_row >= E.out_scroll && end_row < E.out_scroll + (size_t)th)
        mvwaddch(E.out_win, y0 + (int)(end_row - E.out_scroll),
                 end_col < w ? end_col : w - 1, ' ' | A_REVERSE);
    wnoutrefresh(E.out_win);
}

/* Scrolls the panel; reaching the bottom follows the output again. */
static void out_scroll_by(long d) {
    size_t max = out_total_rows > (size_t)out_text_rows ? out_total_rows - (size_t)out_text_rows : 0;
    long cur = E.out_follow ? (long)max : (long)E.out_scroll;
    cur += d;
    if (cur < 0) cur = 0;
    if ((size_t)cur >= max) { E.out_follow = true;  E.out_scroll = max; }
    else                    { E.out_follow = false; E.out_scroll = (size_t)cur; }
}

/* One-line input box. Wider for cell edits; the text scrolls sideways so
 * the cursor stays visible, and UTF-8 (accents...) is measured by display
 * columns, not bytes. */
static void render_dialog(const char *title) {
    int rows, cols; getmaxyx(stdscr, rows, cols);
    int dw = (E.mode == MODE_TABLE_EDIT || E.mode == MODE_MEM_INPUT) ? cols - 8
           : (E.mode == MODE_TABLE_EXPORT || E.mode == MODE_SAVE_DIALOG) ? 90 : 62;
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
 * Saves first — the compiler reads the file from disk, not the buffer —
 * and waits for that save to be on disk. The build and the program then
 * run in the live console below (run.c): the editor keeps drawing, the
 * output arrives as it is printed, and typed keys reach the program. */
static void build_and_run(void) {
    Pane *ap = E.panes[E.active];
    if (run_active()) {                     /* still running: back to its console */
        E.out_visible = true;
        E.out_focus   = true;
        E.out_follow  = true;
        layout_windows();
        force_full_dirty();
        return;
    }
    if (!ap->filename[0]) return;
    if (ap->binary_view) {
        snprintf(E_notify, sizeof E_notify, "Nothing to run: this is a picture / document");
        return;
    }

    if (!pane_save_file_sync(ap) && !ap->hex_mode) return;   /* E_notify says why */
    E.out_visible = true;
    E.out_scroll  = 0;
    E.out_follow  = true;
    layout_windows();
    free(E.out_text);
    E.out_text = malloc(RUN_OUT_CAP);
    if (!E.out_text) { E.out_visible = false; layout_windows(); return; }
    E.out_text[0] = '\0';

    if (build_has_menu(ap->lang)) {
        char flags[1024];
        build_flags_string(ap->lang, flags, sizeof flags);
        /* bounded: the notification area is one status-bar line */
        snprintf(E_notify, sizeof E_notify, "%.16s %.200s",
                 build_compiler_name(ap->lang), flags[0] ? flags : "...");
    }
    int ow = E.out_win ? getmaxx(E.out_win) : 80;
    int oh = E.out_win ? getmaxy(E.out_win) - 1 : 10;
    char msg[256];
    bool live = run_start(ap->filename, ap->lang, E.out_text, RUN_OUT_CAP, ow, oh, msg, sizeof msg);
    E.out_focus = live;
    if (!live && msg[0]) snprintf(E_notify, sizeof E_notify, "%s", msg);
}

/* Keys while the console has the focus: they go to the running program.
 * Esc gives the keys back to the editor (the program keeps running and
 * its output keeps coming), ^B returns to the console, ^Q still quits.
 * Returns false for keys the editor should handle itself. */
static bool console_key(int key) {
    if (!(E.out_focus && E.out_visible && run_active() && E.mode == MODE_NORMAL)) return false;
    switch (key) {
        case 27:
            E.out_focus = false;
            snprintf(E_notify, sizeof E_notify, "Program still running - ^B: back to its console");
            return true;
        case 'c' & 0x1f: run_interrupt();       return true;
        case 'd' & 0x1f: run_input_eof();       return true;
        case '\n': case '\r': case KEY_ENTER:
            E.out_follow = true;
            run_input_enter();
            return true;
        case KEY_BACKSPACE: case 127: case 8:
            run_input_backspace();
            return true;
        case KEY_UP:    out_scroll_by(-1);                  return true;
        case KEY_DOWN:  out_scroll_by(1);                   return true;
        case KEY_PPAGE: out_scroll_by(-(out_text_rows - 1)); return true;
        case KEY_NPAGE: out_scroll_by(out_text_rows - 1);   return true;
        case 'b' & 0x1f: case 'q' & 0x1f:
            return false;
        default:
            if (key == '\t' || (key >= 32 && key < 256)) {
                E.out_follow = true;
                run_input_char(key);
            }
            return true;                    /* other function keys: swallowed */
    }
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
/* the ^B^B menu at its last draw, for the mouse: first screen row, height,
 * rows of options (they start one row below the top border) */
static int g_bm_y = -1, g_bm_h, g_bm_rows;

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
    g_bm_y = my; g_bm_h = mh; g_bm_rows = list_h;

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
        if (p->dis_mode || p->mem_mode || p->img_mode || p->doc_mode)
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
        fi_render(E.finfo, E.finfo->win, edit_h, getmaxx(E.finfo->win));

    
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
        } else if (E.mode == MODE_TABLE_EXPORT) {
            Pane *ap = E.panes[E.active];
            const TableView *tv = ap->table;
            char t[200];
            size_t shown = (tv && tv->cur < tv->nsheets) ? tv->sheets[tv->cur].nview : 0;
            snprintf(t, sizeof t, "Save the %zu row%s shown%s as", shown, shown == 1 ? "" : "s",
                     tv && (tv->nsort || tv->nfilt) ? " (sorted / filtered)" : "");
            render_dialog(t);
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
    if (prefill) str_copy(E.dialog_buf, sizeof(E.dialog_buf), prefill);
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

        case MODE_SAVE_DIALOG: {
            bool was_url = ap->url[0] != '\0';
            bool ok = pane_save_file(ap, E.dialog_buf);
            if (ok && was_url) {          /* the fetched page now lives in that file */
                if (ap->hex_mode && ap->hex)
                    snprintf(ap->hex->filename, sizeof ap->hex->filename, "%s", E.dialog_buf);
                ap->url[0] = ap->url_name[0] = '\0';
                if (E.tree) ft_reload(E.tree);
                snprintf(E_notify, sizeof E_notify, "Saved to %.200s", E.dialog_buf);
            } else if (!ok && !E_notify[0]) {
                snprintf(E_notify, sizeof E_notify, "Could not save to %.200s", E.dialog_buf);
            }
            force_full_dirty();
            break;
        }

        case MODE_TABLE_EXPORT:
            if (ap->table) {
                char msg[256];
                pane_table_export(ap, E.dialog_buf, msg, sizeof msg);
                snprintf(E_notify, sizeof E_notify, "%s", msg);
                if (E.tree) ft_reload(E.tree);
            }
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
                str_copy(ap->search.query, sizeof ap->search.query,     E.dialog_buf);
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

/* ─── F1 field: open a path, fetch a URL ──────────────────────────
 * A URL is downloaded with curl into a private temporary folder, only so
 * that the usual detection (extension, table, image, document...) applies.
 * Text lands in the buffer and the temporary file is removed at once: the
 * page has no file until ^S saves it. Pictures, PDFs, databases and hex
 * views need their bytes on disk: those stay in the folder until exit. */

static char url_tmp_dir[4096];
static int  url_tmp_seq = 0;

static const char *url_tmpdir(void) {
    if (url_tmp_dir[0]) return url_tmp_dir;
#ifdef _WIN32
    char sub[32];                                   /* %LOCALAPPDATA%\abyss\url-PID */
    snprintf(sub, sizeof sub, "url-%d", (int)getpid());
    if (!win_apppath(url_tmp_dir, sizeof url_tmp_dir, sub)) return NULL;
    if (mkdir(url_tmp_dir) != 0 && errno != EEXIST) { url_tmp_dir[0] = '\0'; return NULL; }
#else
    const char *t = getenv("TMPDIR");
    if (!t || !*t) t = "/tmp";
    snprintf(url_tmp_dir, sizeof url_tmp_dir, "%s/abyss-url-XXXXXX", t);
    if (!mkdtemp(url_tmp_dir)) { url_tmp_dir[0] = '\0'; return NULL; }
#endif
    return url_tmp_dir;
}

static void url_tmp_cleanup(void) {
    if (!url_tmp_dir[0]) return;
    DIR *d = opendir(url_tmp_dir);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d))) {
            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
            char f[4600];
            snprintf(f, sizeof f, "%s/%s", url_tmp_dir, de->d_name);
            unlink(f);
        }
        closedir(d);
    }
    rmdir(url_tmp_dir);
    url_tmp_dir[0] = '\0';
}

/* extension for a Content-Type, when the URL itself gives none */
static const char *ctype_ext(const char *ct) {
    static const struct { const char *t, *e; } map[] = {
        { "text/html", ".html" }, { "application/xhtml", ".html" },
        { "application/json", ".json" }, { "+json", ".json" },
        { "application/x-ndjson", ".jsonl" },
        { "text/csv", ".csv" }, { "text/tab-separated", ".tsv" },
        { "javascript", ".js" }, { "text/css", ".css" },
        { "text/markdown", ".md" }, { "application/sql", ".sql" },
        { "image/svg", ".svg" }, { "xml", ".xml" },
        { "image/png", ".png" }, { "image/jpeg", ".jpg" }, { "image/gif", ".gif" },
        { "image/webp", ".webp" }, { "image/bmp", ".bmp" }, { "image/x-icon", ".ico" },
        { "application/pdf", ".pdf" }, { "sqlite", ".db" },
        { "x-python", ".py" }, { "x-sh", ".sh" }, { "x-c", ".c" },
        { "text/plain", ".txt" },
        { NULL, NULL }
    };
    if (!ct) return "";
    for (int i = 0; map[i].t; i++) {
        size_t n = strlen(map[i].t);
        for (const char *c = ct; *c; c++)
            if (!strncasecmp(c, map[i].t, n)) return map[i].e;
    }
    return "";
}

/* local name for a URL: the last part of its path, without ?query */
static void url_basename(const char *url, char *out, size_t sz) {
    const char *p = strstr(url, "://");
    p = p ? p + 3 : url;
    const char *path = strchr(p, '/');
    char name[256] = "";
    if (path) {
        size_t n = strcspn(path, "?#");
        const char *end = path + n;
        const char *b = end;
        while (b > path && b[-1] != '/') b--;
        snprintf(name, sizeof name, "%.*s", (int)(end - b), b);
    }
    for (char *c = name; *c; c++)
        if (*c == '\\' || *c == ':' || *c == '*' || *c == '"' || *c == '<' ||
            *c == '>' || *c == '|' || (unsigned char)*c < 32) *c = '_';
    if (!name[0] || !strcmp(name, ".") || !strcmp(name, "..")) snprintf(name, sizeof name, "index");
    snprintf(out, sz, "%s", name);
}

static void status_flash(const char *msg) {
    if (!E.status_win) return;
    wbkgdset(E.status_win, ' ' | COLOR_PAIR(COLOR_PAIR_STATUS));
    werase(E.status_win);
    wattron(E.status_win, COLOR_PAIR(COLOR_PAIR_STATUS) | A_BOLD);
    mvwaddnstr(E.status_win, 0, 1, msg, getmaxx(E.status_win) - 2);
    wattroff(E.status_win, COLOR_PAIR(COLOR_PAIR_STATUS) | A_BOLD);
    wrefresh(E.status_win);
}

static void pane_reset_for_open(Pane *p) {
    gb_free(p->buf);  p->buf = gb_new(GAP_DEFAULT);
    li_free(p->li);   p->li  = li_new();
    syn_free(p->syn); p->syn = syn_new(LANG_C);
    p->cursor = 0;
}

static void after_open(const char *path) {
    if (E.finfo && E.finfo->visible) fi_analyze(E.finfo, path);
    if (E.hl && E.hl->visible) E.hl->dirty = true;
    layout_windows();
    force_full_dirty();
}

static bool fetch_url(Pane *ap, const char *url_in) {
    char url[2048];
    if (!strncasecmp(url_in, "www.", 4)) snprintf(url, sizeof url, "https://%s", url_in);
    else                                 snprintf(url, sizeof url, "%s", url_in);

    if (!proc_have("curl")) {
        snprintf(E_notify, sizeof E_notify, "curl not found: install it to open URLs");
        return false;
    }
    const char *dir = url_tmpdir();
    if (!dir) {
        snprintf(E_notify, sizeof E_notify, "Cannot create a temporary folder: %.150s", strerror(errno));
        return false;
    }
    char tmp[4600];
    snprintf(tmp, sizeof tmp, "%s/%d.download", dir, ++url_tmp_seq);

    char flash[300];
    snprintf(flash, sizeof flash, "Fetching %.250s ...", url);
    status_flash(flash);

    char *argv[] = { "curl", "-sSL", "--max-time", "60", "-o", tmp,
                     "-w", "%{http_code} %{content_type}", url, NULL };
    char *out = NULL; size_t olen = 0;
    int rc = proc_capture(argv, &out, &olen);
    int http = 0;
    char ctype[200] = "";
    if (out) sscanf(out, "%d %199[^\n]", &http, ctype);
    free(out);
    if (rc != 0) {
        unlink(tmp);
        const char *why = rc == 6 ? "could not resolve the host" : rc == 7 ? "could not connect"
                        : rc == 28 ? "timed out" : rc == 35 || rc == 60 ? "SSL / certificate error"
                        : rc == 3 ? "malformed URL" : rc == 127 ? "curl could not start" : NULL;
        if (why) snprintf(E_notify, sizeof E_notify, "curl: %s (%.180s)", why, url);
        else     snprintf(E_notify, sizeof E_notify, "curl failed (code %d): %.180s", rc, url);
        return false;
    }

    /* the name decides the view: the URL's own, or one from the Content-Type */
    char name[256];
    url_basename(url, name, sizeof name);
    const char *dot = strrchr(name, '.');
    const char *ce  = ctype_ext(ctype);
    bool html = !strcmp(ce, ".html");
    if (*ce && (!dot || (html && strcasecmp(dot, ".html") && strcasecmp(dot, ".htm")))) {
        size_t l = strlen(name);
        snprintf(name + l, sizeof name - l, "%s", ce);
    }
    char local[4900];
    snprintf(local, sizeof local, "%s/%d_%s", dir, url_tmp_seq, name);
    if (rename(tmp, local) != 0) snprintf(local, sizeof local, "%s", tmp);

    pane_reset_for_open(ap);
    pane_open_file(ap, local);
    E_notify[0] = '\0';
    snprintf(ap->url, sizeof ap->url, "%s", url);
    snprintf(ap->url_name, sizeof ap->url_name, "%s", name);

    bool on_disk = ap->binary_view || ap->hex_mode || (ap->table && ap->table->sqlite);
    if (!on_disk) {                   /* text: in memory only, no file behind it */
        unlink(local);
        ap->filename[0] = '\0';
        ap->modified    = true;
    }
    if (http >= 400)
        snprintf(E_notify, sizeof E_notify, "HTTP %d — page shown anyway  (^S to save it)", http);
    else
        snprintf(E_notify, sizeof E_notify, "%s%.150s  (%s%s)", on_disk ? "" : "Fetched ", url,
                 ctype[0] ? ctype : "unknown type",
                 on_disk ? ", read-only temporary copy" : ", not saved: ^S to keep it");
    after_open(ap->filename[0] ? ap->filename : "");
    return true;
}

/* Opens `path` from the tree in the active pane; the tree follows its folder. */
static void tree_open_path(const char *open_path) {
    Pane *ap2 = E.panes[E.active];
    pane_reset_for_open(ap2);
    pane_open_file(ap2, open_path);

    char tmp[4096];
    snprintf(tmp, sizeof tmp, "%s", open_path);
    char *slash = strrchr(tmp, '/');
#ifdef _WIN32
    char *bslash = strrchr(tmp, '\\');          /* path typed as C:\dir\file */
    if (bslash && (!slash || bslash > slash)) slash = bslash;
    if (slash == tmp + 2 && tmp[1] == ':') slash++;   /* keep "C:\" whole */
#endif
    if (slash && slash != tmp) {
        *slash = '\0';
        char resolved[4096];
        if (realpath(tmp, resolved))
            snprintf(E.tree->cwd, sizeof E.tree->cwd, "%s", resolved);
        E.tree->query[0] = '\0';
        ft_reload(E.tree);
    }
    E.tree_focus = false;
    after_open(open_path);
}

/* Enter in the tree field */
static void tree_query_submit(void) {
    FileTree *ft = E.tree;
    char q[2048];
    const char *b = ft->query;
    while (*b == ' ') b++;
    snprintf(q, sizeof q, "%s", b);
    size_t n = strlen(q);
    while (n && (q[n - 1] == ' ' || q[n - 1] == '\n' || q[n - 1] == '\r')) q[--n] = '\0';
    /* pasted / dragged paths often come quoted */
    if (n >= 2 && (q[0] == '\'' || q[0] == '"') && q[n - 1] == q[0]) {
        memmove(q, q + 1, n - 2); q[n - 2] = '\0'; n -= 2;
    }
    if (!n) { ft_query_set(ft, ""); return; }

    if (!strncasecmp(q, "http://", 7) || !strncasecmp(q, "https://", 8) ||
        !strncasecmp(q, "ftp://", 6) || !strncasecmp(q, "ftps://", 7) ||
        !strncasecmp(q, "www.", 4)) {
        if (fetch_url(E.panes[E.active], q)) {
            ft_query_set(ft, "");
            E.tree_focus = false;
        }
        return;
    }

    if (ft_query_is_filter(q)) {          /* filter: open what is selected */
        if (!ft->count) { snprintf(E_notify, sizeof E_notify, "No name matches \"%.200s\"", q); return; }
        FTEntry *e = &ft->entries[ft->selected];
        char full[4400];
        snprintf(full, sizeof full, "%s/%s", ft->cwd, e->name);
        bool dir = e->is_dir;
        ft_query_set(ft, "");
        if (dir) {
            char r[4096];
            if (realpath(full, r)) snprintf(ft->cwd, sizeof ft->cwd, "%s", r);
            ft->selected = 0; ft->scroll = 0;
            ft_reload(ft);
        } else {
            tree_open_path(full);
        }
        return;
    }

    /* a path: absolute, ~, relative to the folder shown, or file:// */
    char path[4400];
    const char *home = home_dir();
    if (!strncasecmp(q, "file://", 7)) {
        const char *fp = q + 7;
#ifdef _WIN32
        if (fp[0] == '/' && isalpha((unsigned char)fp[1]) && fp[2] == ':') fp++;  /* file:///C:/x */
#endif
        snprintf(path, sizeof path, "%s", fp);
    }
    else if (q[0] == '~' && home)      snprintf(path, sizeof path, "%s%s", home, q + 1);
    else if (q[0] == '/' || q[0] == '\\' || (isalpha((unsigned char)q[0]) && q[1] == ':'))
        snprintf(path, sizeof path, "%s", q);
    else snprintf(path, sizeof path, "%s/%s", ft->cwd, q);

    struct stat st;
    if (stat(path, &st) != 0) {
        snprintf(E_notify, sizeof E_notify, "Not found: %.220s", path);
        return;
    }
    ft_query_set(ft, "");
    if (S_ISDIR(st.st_mode)) {
        char r[4096];
        if (realpath(path, r)) str_copy(ft->cwd, sizeof ft->cwd, r);
        else                   str_copy(ft->cwd, sizeof ft->cwd, path);
        ft->selected = 0; ft->scroll = 0;
        ft_reload(ft);
    } else {
        tree_open_path(path);
    }
}

/* Keys for the tree field; true when the key was used. */
static bool tree_query_key(int key) {
    FileTree *ft = E.tree;
    size_t len = strlen(ft->query);
    if ((key >= 32 && key < 127) || (key >= 128 && key < 256)) {
        if (len + 1 < sizeof ft->query) {
            char q[sizeof ft->query];
            snprintf(q, sizeof q, "%s%c", ft->query, (char)key);
            ft_query_set(ft, q);
        }
        return true;
    }
    if (key == '\t') {                        /* path completion */
        if (len) ft_query_complete(ft);
        return len > 0;
    }
    if (!len) return false;
    switch (key) {
        case KEY_BACKSPACE: case 127: case '\b': {
            char q[sizeof ft->query];
            snprintf(q, sizeof q, "%s", ft->query);
            size_t k = len;
            do k--; while (k > 0 && ((unsigned char)q[k] & 0xC0) == 0x80);
            q[k] = '\0';
            ft_query_set(ft, q);
            return true;
        }
        case 27: case 'u' & 0x1f:
            ft_query_set(ft, "");
            return true;
        case '\n': case '\r': case KEY_ENTER:
            tree_query_submit();
            return true;
        default:
            return false;
    }
}

/* ^S / ^O on a buffer with no file yet (a fetched page): a name to start from */
static const char *save_suggestion(const Pane *p, char *out, size_t sz) {
    if (p->filename[0]) return p->filename;
    if (!p->url_name[0]) return NULL;
    char cwd[4096] = ".";
    if (E.tree) snprintf(cwd, sizeof cwd, "%s", E.tree->cwd);
    else if (!getcwd(cwd, sizeof cwd)) snprintf(cwd, sizeof cwd, ".");
    snprintf(out, sz, "%s/%s", cwd, p->url_name);
    return out;
}

/* F9: opens the static analysis view on the file behind the pane (the
 * bytes on disk, never the unsaved buffer), or closes it. The analysis
 * is kept while hidden, so F9 again shows it at once unless the file
 * changed on disk. */
static void dis_toggle(Pane *ap) {
    if (ap->dis_mode) { ap->dis_mode = false; force_full_dirty(); return; }
    const char *path = ap->hex_mode && ap->hex && ap->hex->filename[0] ? ap->hex->filename : ap->filename;
    if (ap->url[0]) path = "";                     /* fetched page: nothing on disk */
    char err[300] = "";
#ifdef HAVE_CAPSTONE
    if (path[0] && !ap->dis) {                     /* first analysis: may take a moment */
        snprintf(E_notify, sizeof E_notify, "Analysing %.200s...", path);
        render_status();
        doupdate();
    }
#endif
    if (!dis_open(&ap->dis, path, err, sizeof err)) {
        snprintf(E_notify, sizeof E_notify, "F9: %.240s", err);
        return;
    }
    E_notify[0] = '\0';
    ap->dis_mode = true;
    ap->mem_mode = false;
    if (ap->modified) snprintf(E_notify, sizeof E_notify, "F9: the file on disk is analysed, not the unsaved changes");
    force_full_dirty();
}

/* F9 toggle and the keys of the F9 view in pane p; false when the key is
 * not for it (p not in the view, or F8, which switches to the memory
 * editor) */
static bool dis_pane_key(Pane *p, int key) {
    if (key == KEY_F(9)) { dis_toggle(p); return true; }
    if (!p->dis_mode || key == KEY_F(8)) return false;
    if (key == ('q' & 0x1f)) { E.running = false; return true; }
    if (key == ('a' & 0x1f)) { E.show_shortcuts = !E.show_shortcuts; return true; }
    if (key == ('e' & 0x1f)) { editor_focus_next(); return true; }
    if (!dis_key(p->dis, key, p->win_h) && key == 27) {
        p->dis_mode = false;
        force_full_dirty();
    }
    return true;
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

    /* F9: static analysis of the file behind this pane (read-only). Taken
     * before the F3 / F4 panels, which would otherwise swallow its keys
     * (Tab cycles the F9 screens, j/k move in them). The file tree keeps
     * the keys while it has the focus (F1). F8 falls through to the
     * memory editor below. */
    if (!(E.tree_focus && E.tree && E.tree->visible) && dis_pane_key(E.panes[E.active], key))
        return;

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
        if (tree_query_key(key)) return;
        char open_path[4096] = "";
        bool consumed = ft_handle_key(E.tree, key, open_path, sizeof open_path);
        if (open_path[0]) tree_open_path(open_path);
        if (consumed) return;
    }

    Pane *ap = E.panes[E.active];

    /* F9 while the file tree has the focus: once the tree passed the key on */
    if (dis_pane_key(ap, key)) return;

    /* F8: memory editor in this pane (process list, then scans) */
    if (key == KEY_F(8)) {
        ap->mem_mode = !ap->mem_mode;
        if (ap->mem_mode) { mem_ui_enter(); ap->dis_mode = false; }
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
                char sug[4400];
                if (ap->filename[0]) pane_save_file(ap, NULL);
                else if (!tv->sqlite) open_dialog(MODE_SAVE_DIALOG, save_suggestion(ap, sug, sizeof sug));
                return;
            }
            if (key == 'w') {                    /* the rows shown, as a new file */
                if (tv->nsheets == 0) return;
                char sug[4400];
                tbl_export_suggest(ap, E.tree ? E.tree->cwd : NULL, sug, sizeof sug);
                open_dialog(MODE_TABLE_EXPORT, sug);
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
        if (key == ('s' & 0x1f) && !ap->url[0]) { hex_save(ap->hex, NULL); return; }
        if (key == ('o' & 0x1f) || key == ('s' & 0x1f)) {
            char sug[4400];
            open_dialog(MODE_SAVE_DIALOG, ap->url[0] ? save_suggestion(ap, sug, sizeof sug)
                        : ap->hex->filename[0] ? ap->hex->filename : NULL);
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
        case '\t': {                     /* spaces up to the next INDENT_W stop */
            size_t n = INDENT_W - ap->cursor_col % INDENT_W;
            pane_insert_str(ap, "        ", n);
            break;
        }

        case 'o' & 0x1f: {
            char sug[4400];
            open_dialog(MODE_SAVE_DIALOG, save_suggestion(ap, sug, sizeof sug));
            break;
        }
        case 's' & 0x1f:
            if (ap->filename[0]) pane_save_file(ap, NULL);
            else {
                char sug[4400];
                open_dialog(MODE_SAVE_DIALOG, save_suggestion(ap, sug, sizeof sug));
            }
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
                    str_copy(ap->search.query, sizeof ap->search.query, E.dialog_buf);
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
    if (E.finfo) fi_free(E.finfo);         /* fi_free deletes its window */
    if (E.hl)    hl_free(E.hl);            /* hl_free too                */
    E.finfo = NULL;
    E.hl    = NULL;
    run_stop();
    free(E.out_text);
    E.out_text = NULL;
    pthread_mutex_destroy(&E.save_mutex);
    server_stop();
    mem_ui_shutdown();                     /* F8: detach, free the scans */
    url_tmp_cleanup();
}

#ifndef _WIN32
/* initscr() without its exit on a terminal it does not know. TERM unset, empty, or
 * found neither in the terminfo databases nor among the entries built into ncurses
 * (static build, static/build.sh): xterm-256color instead, said on stderr (seen after
 * the quit) and in the status bar, and passed on to the programs Abyss starts.
 * Otherwise exactly what initscr() does.
 * The entry is looked up with setupterm() first: a newterm() that fails loses the screen
 * it allocated (LeakSanitizer, ncurses 6.6). Declared here rather than through <term.h>,
 * whose capability macros (lines, columns...) would reach the whole file. */
struct term;
extern int setupterm(const char *, int, int *);
extern struct term *set_curterm(struct term *);
extern int del_curterm(struct term *);
static char term_note[96];            /* put in E_notify once the first file is open */
static void curses_start(void) {
    const char *t = getenv("TERM");
    int err = 0;
    bool known = t && *t && setupterm(t, fileno(stdout), &err) == OK;
    if (known) del_curterm(set_curterm(NULL));     /* only a lookup: newterm() reads it again */
    if (known && newterm(t, stdout, stdin)) { def_prog_mode(); return; }
    char was[64];
    snprintf(was, sizeof was, "%s", t && *t ? t : "(unset)");
    fprintf(stderr, "abyss: terminal type \"%s\" unknown (no terminfo entry): using xterm-256color\n", was);
    if (!newterm("xterm-256color", stdout, stdin)) {
        fprintf(stderr, "Error opening terminal: %s.\n", t && *t ? t : "unknown");
        exit(EXIT_FAILURE);
    }
    setenv("TERM", "xterm-256color", 1);
    def_prog_mode();
    snprintf(term_note, sizeof term_note, "Terminal \"%.40s\" unknown: shown as xterm-256color", was);
}
#endif

#ifdef _WIN32
/* wgetch() as on Linux: a typed character beyond ASCII comes as its UTF-8 bytes, one per
 * call (the console driver gives WIN_KEY_CHAR | its UTF-16 unit: winsize.c) */
static int key_read(WINDOW *w) {
    static unsigned char q[4];
    static int qn, qi;
    if (qi < qn) return q[qi++];
    for (;;) {
        int k = wgetch(w), n = win_key_utf8(k, q);
        if (n < 0) return k;
        if (n > 0) { qn = n; qi = 1; return q[0]; }
    }
}
#else
#  define key_read(w) wgetch(w)
#endif

/* ─── Mouse ────────────────────────────────────────────────────── */

/* The key a hint names: "F5", "Shift-F5", "^S", "Esc", "Tab", "Enter",
 * "Space", "Backspace", "PgUp" / "PgDn", "Home" / "End", "'x'" or one
 * character; 0: none. */
static int hint_key(const char *s, size_t n) {
    while (n && *s == ' ') { s++; n--; }
    while (n && s[n - 1] == ' ') n--;
    if (!n) return 0;
    if (n > 2 && (unsigned char)s[0] <= 6 && s[1] == ' ') { s += 2; n -= 2; }   /* a mark before the key: "→ Enter" */
    if (n == 3 && s[0] == '\'' && s[2] == '\'') return (unsigned char)s[1];
    if (n == 1 && s[0] == '\x03') return KEY_LEFT;
    if (n == 1 && s[0] == '\x04') return KEY_RIGHT;
    if (n == 1 && s[0] == '\x05') return KEY_UP;
    if (n == 1 && s[0] == '\x06') return KEY_DOWN;
    if (n == 1) return s[0] > 32 && s[0] < 127 ? (unsigned char)s[0] : 0;
    if (n == 2 && s[0] == '^' && ((s[1] >= '@' && s[1] <= '_') || (s[1] >= 'a' && s[1] <= 'z'))) return s[1] & 0x1f;
    int shift = 0;
    if (n > 6 && !strncmp(s, "Shift-", 6)) { shift = 12; s += 6; n -= 6; }
    if ((n == 2 || n == 3) && s[0] == 'F' && isdigit((unsigned char)s[1]) && (n == 2 || isdigit((unsigned char)s[2]))) {
        int k = s[1] - '0';
        if (n == 3) k = k * 10 + (s[2] - '0');
        return k >= 1 && k <= 12 ? KEY_F(k + shift) : 0;
    }
    if (shift) return 0;
    static const struct { const char *name; int key; } names[] = {
        { "Esc", 27 }, { "Tab", '\t' }, { "Enter", '\n' }, { "Space", ' ' }, { "Backspace", KEY_BACKSPACE },
        { "PgUp", KEY_PPAGE }, { "PgDn", KEY_NPAGE }, { "Home", KEY_HOME }, { "End", KEY_END } };
    for (size_t i = 0; i < sizeof names / sizeof *names; i++)
        if (strlen(names[i].name) == n && !strncmp(s, names[i].name, n)) return names[i].key;
    return 0;
}

/* The key of the hint under the screen cell (y, x), read back from the
 * screen: a hint is "KEY: what" or "KEY:What", hints are apart by a '·',
 * a '│' or two spaces, and "A / B: what" or "A/B:What" give the
 * alternative clicked, else the first one that names a key (← → ↑ ↓ are
 * the arrows; a mark and a blank before a key are skipped: "→ Enter"). printable: a key that types a character
 * is taken too (on a row that is only hints, not where a file name or a
 * command line shows). 0: none there. */
static int hint_at(int y, int x, bool printable) {
    int cols = getmaxx(curscr);
    if (y < 0 || y >= getmaxy(curscr) || x < 0 || x >= cols) return 0;
    char row[1024];
    int n = cols < (int)sizeof row - 1 ? cols : (int)sizeof row - 1;
    for (int i = 0; i < n; i++) {                    /* one byte per cell, other characters as marks */
        cchar_t cc;
        wchar_t wc[CCHARW_MAX + 1] = { 0 };
        attr_t at; short cp;
        row[i] = ' ';
        if (mvwin_wch(curscr, y, i, &cc) == ERR || getcchar(&cc, wc, &at, &cp, NULL) == ERR) continue;
        row[i] = wc[0] == 0xB7 || wc[0] == 0x2502 ? '\x01' : wc[0] == 0x2190 ? '\x03' : wc[0] == 0x2192 ? '\x04'
               : wc[0] == 0x2191 ? '\x05' : wc[0] == 0x2193 ? '\x06'
               : wc[0] >= 32 && wc[0] < 127 ? (char)wc[0] : wc[0] ? '\x02' : ' ';
    }
    row[n] = '\0';
    if (x >= n || row[x] == '\x01' || (row[x] == ' ' && (x == 0 || row[x - 1] == ' ' || row[x + 1] == ' '))) return 0;
    int l = x, r = x;
    while (l > 0 && row[l - 1] != '\x01' && !(row[l - 1] == ' ' && l >= 2 && row[l - 2] == ' ')) l--;
    while (r < n && row[r] != '\x01' && !(row[r] == ' ' && row[r + 1] == ' ')) r++;
    while (l < r && row[l] == ' ') l++;
    const char *s = row + l;
    size_t len = (size_t)(r - l);
    size_t c;                                        /* the colon after the key */
    if (len >= 2 && s[0] == ':' && s[1] == ':') c = 1;
    else if (len >= 4 && s[0] == '\'' && s[2] == '\'' && s[3] == ':') c = 3;
    else { const char *q = memchr(s, ':', len); if (!q || q == s) return 0; c = (size_t)(q - s); }
    int first = 0;                                   /* the alternatives, A / B: the one clicked, */
    for (size_t a = 0; a < c; ) {                    /* else the first that names a key */
        size_t b = a;
        while (b < c && s[b] != '/') b++;
        int k = c == 1 && s[0] == ':' ? ':' : hint_key(s + a, b - a);
        if (k && !(printable || k < 32 || k > 126)) k = 0;
        if (k && (size_t)(x - l) >= a && (size_t)(x - l) < b) return k;
        if (k && !first) first = k;
        a = b + 1;
    }
    return first;
}

static bool mouse_in(WINDOW *w, int y, int x, int *wy, int *wx) {
    if (!w || !wenclose(w, y, x)) return false;
    int by, bx;
    getbegyx(w, by, bx);
    *wy = y - by; *wx = x - bx;
    return true;
}

/* the key goes in as if typed: the main loop reads it next */
static void mouse_key(int k) { if (k) ungetch(k); }

static void focus_pane(int i) {
    E.active = i;
    E.tree_focus = E.hl_focus = finfo_focus = E.out_focus = false;
}

/* the wheel over pane p (focused or not): what Up / Down x3 do in its view */
static void pane_wheel(Pane *p, int dir, int wy, int wx, unsigned long b) {
    int key = dir < 0 ? KEY_UP : KEY_DOWN;
    if (p->dis_mode && p->dis)            dis_mouse(p->dis, wy, wx, b, p->win_h);
    else if (p->mem_mode)                 mem_ui_mouse(wy, wx, b, p->win_h);
    else if (p->img_mode)                 ;
    else if (p->doc_mode && p->doc)       for (int i = 0; i < 3; i++) doc_handle_key(p->doc, key, p->win_h);
    else if (p->table_mode && p->table && p->table->menu.open)   /* the f dropdown, over the grid */
        for (int i = 0; i < 3; i++) tbl_filter_menu_key(p->table, key, p->win_h);
    else if (p->table_mode && p->table)   for (int i = 0; i < 3; i++) tbl_handle_key(p->table, key, p->win_h);
    else if (p->hex_mode && p->hex)       for (int i = 0; i < 3; i++) hex_handle_key(p->hex, key, p->win_h);
    else if (!p->doc_mode && !p->table_mode && !p->hex_mode) pane_move_cursor(p, 3 * dir, 0);
}

/* A mouse event (KEY_MOUSE), by what lies under it: the wheel scrolls the
 * view or panel under the pointer, focused or not; a click gives it the
 * focus and acts on what it hits (text: the cursor, held and released
 * elsewhere: a selection; a row of the tree / F8 / F9 / table: selects it,
 * a second click on the selected one is Enter; a key named on a hint bar:
 * that key). Dialogs keep the keyboard only. */
static void mouse_event(void) {
    MEVENT ev;
    if (getmouse(&ev) != OK) return;
    static int press_pane = -1;                      /* text pane of the last press */
    unsigned long b = (unsigned long)ev.bstate;
    int dir = b & BUTTON4_PRESSED ? -1 : (b & MOUSE_WHEEL_DOWN) ? 1 : 0;
    bool click = b & BUTTON1_PRESSED, release = b & BUTTON1_RELEASED;
    int y = ev.y, x = ev.x, wy, wx;

    if (release) {                                   /* end of a drag in the text */
        int i = press_pane;
        press_pane = -1;
        if (i < 0 || i >= E.npanes || E.mode != MODE_NORMAL) return;
        Pane *p = E.panes[i];
        if (p->dis_mode || p->mem_mode || p->img_mode || p->doc_mode || p->table_mode || p->hex_mode || !p->win) return;
        int by, bx;
        getbegyx(p->win, by, bx);
        wy = y - by; wx = x - bx;                    /* past the edges: the nearest cell */
        if (wy < 0) wy = 0;
        if (wy >= p->win_h) wy = p->win_h - 1;
        if (wx < 0) wx = 0;
        if (wx >= p->win_w) wx = p->win_w - 1;
        size_t at = p->cursor;
        pane_click(p, wy, wx, true);
        if (p->cursor == at) p->sel_active = false;  /* released where pressed: a click */
        return;
    }
    if (!dir && !click) return;
    E_notify[0] = '\0';                             /* as a key does (not the release after it) */

    if (E.mode == MODE_BUILD_MENU) {
        if (g_bm_y < 0 || y < g_bm_y || y >= g_bm_y + g_bm_h) return;
        int count = 0;
        build_flag_table(E.panes[E.active]->lang, &count);
        if (dir) {
            E.build_sel += dir;
            if (E.build_sel >= count) E.build_sel = count - 1;
            if (E.build_sel < 0) E.build_sel = 0;
        } else if (y == g_bm_y + g_bm_h - 1) mouse_key(hint_at(y, x, true));
        else if (y > g_bm_y && y <= g_bm_y + g_bm_rows) {
            int i = E.build_scroll + (y - g_bm_y - 1);
            if (i < count) { E.build_sel = i; mouse_key(' '); }   /* a click ticks it */
        }
        return;
    }
    if (E.mode != MODE_NORMAL) return;

    if (mouse_in(E.title_win, y, x, &wy, &wx)) {    /* its hints: ^A, the shortcuts */
        if (click) mouse_key(hint_at(y, x, E.show_shortcuts));
        return;
    }
    if (E.out_visible && mouse_in(E.out_win, y, x, &wy, &wx)) {
        if (dir) out_scroll_by(3 * dir);
        else if (wy == 0) mouse_key(hint_at(y, x, false));      /* the header: what keys do */
        else if (run_active()) { focus_pane(E.active); E.out_focus = true; }
        return;
    }
    if (E.tree && E.tree->visible && mouse_in(E.tree->win, y, x, &wy, &wx)) {
        FileTree *ft = E.tree;
        if (dir) {
            for (int i = 0; i < 3; i++) {
                if (dir < 0 && ft->selected > 0) ft->selected--;
                if (dir > 0 && ft->selected + 1 < ft->count) ft->selected++;
            }
            return;
        }
        bool had = E.tree_focus;
        focus_pane(E.active);
        E.tree_focus = true;
        size_t idx = ft->scroll + (size_t)(wy - 2);
        if (wy < 2 || idx >= ft->count) return;    /* the folder, the field */
        if (had && idx == ft->selected) {            /* second click: open it */
            char open_path[4096] = "";
            ft_handle_key(ft, '\n', open_path, sizeof open_path);
            if (open_path[0]) tree_open_path(open_path);
        } else ft->selected = idx;
        return;
    }
    if (E.hl && E.hl->visible && mouse_in(E.hl->win, y, x, &wy, &wx)) {
        if (dir < 0) { E.hl->scroll -= 3; if (E.hl->scroll < 0) E.hl->scroll = 0; }
        else if (dir > 0) E.hl->scroll += 3;
        else { focus_pane(E.active); E.hl_focus = true; }
        return;
    }
    if (E.finfo && E.finfo->visible && mouse_in(E.finfo->win, y, x, &wy, &wx)) {
        if (dir < 0) { E.finfo->scroll_row -= 3; if (E.finfo->scroll_row < 0) E.finfo->scroll_row = 0; }
        else if (dir > 0) E.finfo->scroll_row += 3;
        else { focus_pane(E.active); finfo_focus = true; }
        return;
    }
    for (int i = 0; i < E.npanes; i++) {
        Pane *p = E.panes[i];
        if (!mouse_in(p->win, y, x, &wy, &wx)) continue;
        if (dir) { pane_wheel(p, dir, wy, wx, b); return; }
        bool was = E.active == i && !E.tree_focus && !E.hl_focus && !finfo_focus && !E.out_focus;
        focus_pane(i);
        if (p->dis_mode && p->dis) {
            if (!dis_mouse(p->dis, wy, wx, b, p->win_h) && wy == p->win_h - 1) mouse_key(hint_at(y, x, true));
        } else if (p->mem_mode) {
            if (!mem_ui_mouse(wy, wx, b, p->win_h) && wy == p->win_h - 1) mouse_key(hint_at(y, x, true));
        } else if (p->img_mode || p->doc_mode) {
            ;                                        /* the focus only */
        } else if (p->table_mode && p->table && p->table->menu.open) {
            ;                                        /* the f dropdown: keyboard */
        } else if (p->table_mode && p->table) {
            int r = tbl_click(p->table, wy, wx, p->win_h, p->win_w);
            if (r == 2 && was) mouse_key('\n');                         /* edit the cell */
            else if (!r && wy == p->win_h - 1) mouse_key(hint_at(y, x, true));   /* its legend */
        } else if (p->hex_mode && p->hex) {
            hex_click(p->hex, wy, wx);
        } else {
            pane_click(p, wy, wx, false);
            press_pane = i;
        }
        return;
    }
}

void editor_run(const char *initial_file) {
    #ifdef _WIN32
    win_init_utf8();
    setlocale(LC_ALL, ".UTF-8");   /* "" donnerait French_France.1252 → UTF-8 mal décodé */
    initscr();
#else
    setlocale(LC_ALL, "");
    curses_start();
#endif
    raw(); noecho();
    keypad(stdscr, TRUE);
    set_escdelay(25);
    mouseinterval(0);                       /* a press is a click, no wait */
    /* the mouse in every view (see mouse_event); the terminal's own
     * selection then takes Shift + drag */
    mousemask(BUTTON1_PRESSED | BUTTON1_RELEASED | BUTTON4_PRESSED | MOUSE_WHEEL_DOWN, NULL);
    curs_set(0);

    colors_init();
    use_default_colors();
    hex_colors_init();
    fi_colors_init();
    hl_colors_init();
    ft_init_color_pairs();          /* fixed pairs first: the image view allocates the rest */
    colors_win_polish();

#ifndef _WIN32
    /* (not on Windows: the console driver of ncurses reads key events, never these
     * sequences, and a terminal behind the console that took the kitty push would send
     * keys nothing there decodes) */
    printf("\033[?2004h");
    /* Kitty keyboard protocol, level 1 ("disambiguate escape codes"): makes
     * the terminal report modifiers for keys the legacy encoding folds
     * together (Ctrl+I vs Tab, Ctrl+M vs Enter, ...).
     * Only ambiguous keys change shape (plain text is untouched), and those
     * are decoded back below; terminals without support ignore the push. */
    printf("\033[>1u");
    fflush(stdout);
#endif
    layout_windows();

    if (initial_file) {
        pane_open_file(E.panes[0], initial_file);
        layout_windows();
    }
#ifndef _WIN32
    if (term_note[0] && !E_notify[0]) snprintf(E_notify, sizeof E_notify, "%s", term_note);
#else
    if (win_console_note() && !E_notify[0]) snprintf(E_notify, sizeof E_notify, "%s", win_console_note());
#endif
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
            int dt = dbg_ui_timeout();              /* F9 debugger: dbg_poll while it runs */
            if (dt > 0 && (tmo < 0 || dt < tmo)) tmo = dt;
        }
        if (run_active() && (tmo < 0 || tmo > 25)) tmo = 25;   /* live console */
	#ifdef _WIN32
    		if (tmo < 0) tmo = 100;   /* pas de SIGWINCH sous Windows : on sonde la taille toutes les 100 ms */
	#endif
        if (tmo >= 0) wtimeout(kw, tmo);
        int key = key_read(kw);
        if (tmo >= 0) wtimeout(kw, -1);
        {                                           /* live console: new output, end */
            int ev = run_poll();
            if (ev & RUN_EV_DONE) {
                E.out_focus = false;
                snprintf(E_notify, sizeof E_notify, "%s", run_timing());
            }
            if (ev) full_redraw(false);
        }
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
        if (key == ERR && dis_ui_poll()) { full_redraw(false); continue; }   /* F9 debuggee stopped */
        if (key == ERR && mem_visible()) {          /* live values: once a second, F8 only */
            if (mem_ui_refresh_due()) full_redraw(false);
            continue;
        }
        if (key == 0 || key == ERR || key == 0x16) continue;

        if (key == KEY_MOUSE && !in_paste) {       /* every view, see mouse_event */
            mouse_event();                          /* (it clears E_notify on a press only) */
            force_full_dirty();
            full_redraw(false);
            continue;
        }
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
        if (E.out_visible && E.mode == MODE_NORMAL && !(E.out_focus && run_active()) &&
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
            while (sn < 16) {
                int c = key_read(ew);
                if (c == ERR) break;
                sq[sn++] = c;
            }
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
                    if (in_paste && paste_len > 0 && E.mode == MODE_NORMAL &&
                        E.out_focus && run_active()) {
                        run_input_str(paste_batch, (size_t)paste_len);
                    } else if (in_paste && paste_len > 0 && E.mode == MODE_NORMAL &&
                               E.tree_focus && E.tree && E.tree->visible) {
                        /* a path / URL pasted into the tree field: one line */
                        paste_batch[paste_len] = '\0';
                        char q[sizeof E.tree->query];
                        size_t o = strlen(E.tree->query);
                        memcpy(q, E.tree->query, o);
                        for (int pi = 0; pi < paste_len && o + 1 < sizeof q; pi++) {
                            char c = paste_batch[pi];
                            if (c == '\n' || c == '\r') { if (o) break; continue; }
                            if (c == '\t') c = ' ';
                            q[o++] = c;
                        }
                        q[o] = '\0';
                        ft_query_set(E.tree, q);
                    } else if (in_paste && paste_len > 0 && E.mode == MODE_NORMAL) {
                        paste_batch[paste_len] = '\0';
                        Pane *ap2 = E.panes[E.active];
                        if (!ap2->hex_mode && !ap2->table_mode && !ap2->mem_mode && !ap2->dis_mode &&
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

        if (console_key(key)) { full_redraw(false); continue; }

        EditorMode prev_mode = E.mode;
        if (E.mode == MODE_NORMAL)           handle_key_normal(key);
        else if (E.mode == MODE_BUILD_MENU)  handle_key_build_menu(key);
        else                                 handle_key_dialog(key);

        if (prev_mode == MODE_BUILD_MENU && E.mode == MODE_NORMAL) force_full_dirty();

        bool force = (prev_mode != MODE_NORMAL && E.mode == MODE_NORMAL);
        full_redraw(force);
    }

    mousemask(0, NULL);
#ifndef _WIN32
    printf("\033[?2004l");
    printf("\033[<u");      /* pop the keyboard-protocol flags */
    fflush(stdout);
#endif
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