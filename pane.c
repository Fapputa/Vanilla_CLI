#include "abyss.h"
#include <string.h>

GapBuf *gb_clone(const GapBuf *g);

Pane *pane_new(void) {
    Pane *p = calloc(1, sizeof *p);
    p->buf  = gb_new(GAP_DEFAULT);
    p->li   = li_new();
    p->syn  = syn_new(LANG_C);
    p->undo = us_new();
    p->lang = LANG_C;
    p->show_line_numbers  = false;
    p->prev_render_rows   = 0;
    p->last_cursor_row    = 0;
    return p;
}

void pane_free(Pane *p) {
    if (!p) return;
    gb_free(p->buf);
    li_free(p->li);
    syn_free(p->syn);
    us_free(p->undo);
    free(p->clip.text);
    free(p->search.matches);
    if (p->line_dirty) free(p->line_dirty);
    if (p->prev_render) {
        for (int i = 0; i < p->prev_render_rows; i++) free(p->prev_render[i]);
        free(p->prev_render);
    }
    free(p);
}

void pane_open_file(Pane *p, const char *path) {
    /* Resolve to absolute path so the title always shows the full location */
    char resolved[4096];
    if (realpath(path, resolved))
        strncpy(p->filename, resolved, sizeof(p->filename)-1);
    else
        strncpy(p->filename, path, sizeof(p->filename)-1);
    p->filename[sizeof(p->filename)-1] = '\0';

    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    struct stat st; fstat(fd, &st);
    size_t sz = (size_t)st.st_size;
    if (sz > 0) {
        void *m = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
        if (m != MAP_FAILED) { gb_insert_str(p->buf, 0, (const char *)m, sz); munmap(m, sz); }
    }
    close(fd);
    const char *ext = strrchr(path, '.');
    p->lang = lang_from_ext(ext ? ext : "");
    syn_free(p->syn); p->syn = syn_new(p->lang);
    li_rebuild(p->li, p->buf);
    p->cursor = 0; p->cursor_line = 0; p->cursor_col = 0;
    p->modified = false;
    pane_push_undo(p);
}

typedef struct { char path[4096]; char *data; size_t len; } SaveArgs;
static void *save_thread_fn(void *arg) {
    SaveArgs *sa = arg;
    FILE *f = fopen(sa->path, "w");
    if (f) { fwrite(sa->data, 1, sa->len, f); fclose(f); }
    free(sa->data); free(sa);
    return NULL;
}

bool pane_save_file(Pane *p, const char *path) {
    if (path && path[0]) strncpy(p->filename, path, sizeof(p->filename)-1);
    if (!p->filename[0]) return false;
    char *s = gb_to_str(p->buf);
    SaveArgs *sa = malloc(sizeof *sa);
    strncpy(sa->path, p->filename, sizeof(sa->path)-1);
    sa->data = s; sa->len = strlen(s);
    pthread_t tid;
    pthread_create(&tid, NULL, save_thread_fn, sa);
    pthread_detach(tid);
    p->modified = false;
    const char *ext = strrchr(p->filename, '.');
    p->lang = lang_from_ext(ext ? ext : "");
    syn_free(p->syn); p->syn = syn_new(p->lang);
    syn_mark_dirty_from(p->syn, 0);
    return true;
}

void pane_set_window(Pane *p, WINDOW *w, int y, int x, int h, int ww) {
    if (p->prev_render) {
        for (int i = 0; i < p->prev_render_rows; i++) free(p->prev_render[i]);
        free(p->prev_render); p->prev_render = NULL;
    }
    if (p->line_dirty) { free(p->line_dirty); p->line_dirty = NULL; }
    p->win = w; p->win_y = y; p->win_x = x; p->win_h = h; p->win_w = ww;
    p->prev_render_rows = 0;
    keypad(w, TRUE);
}

static void cursor_update_line_col(Pane *p) {
    size_t lo = 0, hi = li_line_count(p->li);
    while (lo + 1 < hi) {
        size_t mid = (lo + hi) / 2;
        if (li_line_start(p->li, mid) <= p->cursor) lo = mid; else hi = mid;
    }
    p->cursor_line = lo;
    p->cursor_col  = p->cursor - li_line_start(p->li, lo);
}

void pane_scroll_to_cursor(Pane *p) {
    int margin = 3;
    int gutter = p->show_line_numbers ? 6 : 0;
    int text_w = p->win_w - gutter; if (text_w < 1) text_w = 1;
    if (p->win_h > 0) {
        if ((int)p->cursor_line < (int)p->scroll_line + margin)
            p->scroll_line = p->cursor_line > (size_t)margin ? p->cursor_line - margin : 0;
        if ((int)p->cursor_line >= (int)p->scroll_line + p->win_h - margin)
            p->scroll_line = p->cursor_line - p->win_h + margin + 1;
    }
    if ((int)p->cursor_col < (int)p->scroll_col)
        p->scroll_col = p->cursor_col;
    if ((int)p->cursor_col >= (int)p->scroll_col + text_w)
        p->scroll_col = p->cursor_col - text_w + 1;
}

void pane_render(Pane *p, bool force) {
    (void)force; /* always redraw — ncurses virtual screen handles actual terminal updates */
    if (!p->win || p->win_h < 1 || p->win_w < 1) return;
    if (p->li->dirty) li_rebuild(p->li, p->buf);

    int gutter = p->show_line_numbers ? 6 : 0;
    int text_w = p->win_w - gutter; if (text_w < 1) text_w = 1;
    size_t nlines = li_line_count(p->li);
    size_t buflen  = gb_len(p->buf);

    /* Pre-pass: propagate lex states for off-screen lines so block comments
       and strings are correct for the visible viewport */
    for (size_t i = 0; i < p->scroll_line && i < nlines; i++)
        syn_ensure_line(p->syn, i, p->buf, p->li);

    for (int row = 0; row < p->win_h; row++) {
        size_t lineno     = p->scroll_line + row;
        bool   is_cur_row = (lineno == p->cursor_line);

        wmove(p->win, row, 0);
        wstandend(p->win);

        if (lineno >= nlines) {
            wclrtoeol(p->win);
            continue;
        }

        syn_ensure_line(p->syn, lineno, p->buf, p->li);
        size_t line_start = li_line_start(p->li, lineno);
        size_t line_end   = (lineno + 1 < nlines) ? li_line_start(p->li, lineno+1)-1 : buflen;
        size_t line_len   = (line_end >= line_start) ? line_end - line_start : 0;

        /* gutter */
        if (p->show_line_numbers) {
            wattron(p->win, is_cur_row ? (A_BOLD|COLOR_PAIR(COLOR_PAIR_LINENUM))
                                       : COLOR_PAIR(COLOR_PAIR_LINENUM));
            wprintw(p->win, "%4zu ", lineno + 1);
            wattroff(p->win, A_BOLD|COLOR_PAIR(COLOR_PAIR_LINENUM));
            wattron(p->win, COLOR_PAIR(COLOR_PAIR_OPERATOR));
            waddch(p->win, '|');
            wattroff(p->win, COLOR_PAIR(COLOR_PAIR_OPERATOR));
        }

        /* text */
        LineAttr *la = &p->syn->lines[lineno];
        size_t ci = p->scroll_col;
        for (int col = 0; col < text_w; col++, ci++) {
            if (ci >= line_len) break;
            size_t abs = line_start + ci;
            char ch = gb_at(p->buf, abs); if (ch == '\t') ch = ' ';
            TokenType tok = (la->attrs && ci < la->len) ? la->attrs[ci] : TOK_NORMAL;
            bool sel = false;
            if (p->sel_active) {
                size_t s0 = min_sz(p->sel_anchor, p->cursor);
                size_t s1 = max_sz(p->sel_anchor, p->cursor);
                sel = (abs >= s0 && abs < s1);
            }
            bool cur = (abs == p->cursor);
            wstandend(p->win);
            if      (cur) wattron(p->win, A_REVERSE);
            else if (sel) wattron(p->win, COLOR_PAIR(COLOR_PAIR_SELECTION));
            else {
                int cp = tok_to_color_pair(tok);
                wattron(p->win, COLOR_PAIR(cp));
                if (tok == TOK_KEYWORD || tok == TOK_TYPE) wattron(p->win, A_BOLD);
            }
            waddch(p->win, ch);
        }
        /* cursor at EOL */
        wstandend(p->win);
        if (p->cursor == line_end && is_cur_row) {
            wattron(p->win, A_REVERSE); waddch(p->win, ' '); wstandend(p->win);
        }
        wclrtoeol(p->win);
    }
    if (p->cursor_line >= p->scroll_line &&
        (int)(p->cursor_line - p->scroll_line) < p->win_h)
        p->last_cursor_row = p->cursor_line - p->scroll_line;
    wnoutrefresh(p->win);
}

static void mark_dirty(Pane *p) {
    li_mark_dirty(p->li);
    syn_mark_dirty_from(p->syn, p->cursor_line > 0 ? p->cursor_line-1 : 0);
    p->modified = true;
}

static void auto_indent_newline(Pane *p) {
    if (p->li->dirty) li_rebuild(p->li, p->buf);
    size_t ls = li_line_start(p->li, p->cursor_line);
    size_t blen = gb_len(p->buf);
    size_t indent = 0;
    while (ls + indent < blen) {
        char c = gb_at(p->buf, ls + indent);
        if (c == ' ' || c == '\t') indent++; else break;
    }
    if (indent > 255) indent = 255;
    char spaces[256] = {0}; memset(spaces, ' ', indent);
    char prev_c = p->cursor > 0    ? gb_at(p->buf, p->cursor-1) : 0;
    char next_c = p->cursor < blen ? gb_at(p->buf, p->cursor)   : 0;
    pane_push_undo(p);
    if (prev_c == '{' && next_c == '}') {
        size_t n = 1 + indent + 4 + 1 + indent;
        char *ins = malloc(n+1); size_t pos = 0;
        ins[pos++] = '\n';
        memcpy(ins+pos, spaces, indent); pos += indent;
        memcpy(ins+pos, "    ", 4);      pos += 4;
        ins[pos++] = '\n';
        memcpy(ins+pos, spaces, indent); pos += indent;
        ins[pos] = '\0';
        gb_insert_str(p->buf, p->cursor, ins, n);
        p->cursor += 1 + indent + 4;
        free(ins);
    } else {
        bool extra = (prev_c == '{');
        gb_insert_char(p->buf, p->cursor, '\n'); p->cursor++;
        gb_insert_str(p->buf, p->cursor, spaces, indent); p->cursor += indent;
        if (extra) { gb_insert_str(p->buf, p->cursor, "    ", 4); p->cursor += 4; }
    }
    mark_dirty(p);
    li_rebuild(p->li, p->buf);
    cursor_update_line_col(p);
    pane_scroll_to_cursor(p);
}

void pane_push_undo(Pane *p) { us_push(p->undo, p->buf, p->cursor); }

void pane_insert_char(Pane *p, char c) {
    if (c == '\n') { auto_indent_newline(p); return; }
    pane_push_undo(p);
    const char *open = "{([\"'", *close = "})]\"'";
    const char *cp = strchr(open, c);
    if (cp) {
        char cl = close[cp-open];
        gb_insert_char(p->buf, p->cursor, c);
        gb_insert_char(p->buf, p->cursor+1, cl);
        p->cursor++;
    } else {
        const char *clp = strchr(close, c);
        if (clp && p->cursor < gb_len(p->buf) && gb_at(p->buf, p->cursor) == c)
            { p->cursor++; goto done; }
        gb_insert_char(p->buf, p->cursor, c); p->cursor++;
    }
done:
    mark_dirty(p);
    li_rebuild(p->li, p->buf);
    cursor_update_line_col(p);
    pane_scroll_to_cursor(p);
}

void pane_insert_str(Pane *p, const char *s, size_t n) {
    pane_push_undo(p);
    gb_insert_str(p->buf, p->cursor, s, n); p->cursor += n;
    mark_dirty(p); li_rebuild(p->li, p->buf);
    cursor_update_line_col(p); pane_scroll_to_cursor(p);
}

void pane_delete_char(Pane *p) {
    if (p->cursor == 0) return;
    pane_push_undo(p);
    char prev = gb_at(p->buf, p->cursor-1);
    size_t blen = gb_len(p->buf);
    const char *open = "{([\"'", *close = "})]\"'";
    const char *cp = strchr(open, prev);
    if (cp && p->cursor < blen && gb_at(p->buf, p->cursor) == close[cp-open]) {
        gb_delete(p->buf, p->cursor-1, 2); p->cursor--;
    } else { gb_delete(p->buf, p->cursor-1, 1); p->cursor--; }
    mark_dirty(p); li_rebuild(p->li, p->buf);
    cursor_update_line_col(p); pane_scroll_to_cursor(p);
}

void pane_delete_forward(Pane *p) {
    if (p->cursor >= gb_len(p->buf)) return;
    pane_push_undo(p);
    gb_delete(p->buf, p->cursor, 1);
    mark_dirty(p); li_rebuild(p->li, p->buf);
    cursor_update_line_col(p); pane_scroll_to_cursor(p);
}

void pane_move_cursor(Pane *p, int dy, int dx) {
    if (p->li->dirty) li_rebuild(p->li, p->buf);
    if (dy != 0) {
        size_t nl = li_line_count(p->li);
        long tl = (long)p->cursor_line + dy;
        if (tl < 0) tl = 0;
        if ((size_t)tl >= nl) tl = (long)nl-1;
        size_t ls  = li_line_start(p->li, (size_t)tl);
        size_t nls = ((size_t)tl+1 < nl) ? li_line_start(p->li,(size_t)tl+1)-1 : gb_len(p->buf);
        size_t ll  = nls >= ls ? nls-ls : 0;
        p->cursor  = ls + min_sz(p->cursor_col, ll);
    }
    if (dx > 0) { if (p->cursor < gb_len(p->buf)) p->cursor++; }
    else if (dx < 0) { if (p->cursor > 0) p->cursor--; }
    cursor_update_line_col(p); pane_scroll_to_cursor(p);
}

void pane_move_to_line_col(Pane *p, size_t line, size_t col) {
    if (p->li->dirty) li_rebuild(p->li, p->buf);
    size_t nl = li_line_count(p->li);
    if (line >= nl) line = nl > 0 ? nl-1 : 0;
    size_t ls = li_line_start(p->li, line);
    p->cursor = ls + col;
    size_t blen = gb_len(p->buf);
    if (p->cursor > blen) p->cursor = blen;
    cursor_update_line_col(p); pane_scroll_to_cursor(p);
}

void pane_kill_line(Pane *p) {
    /* Delete from cursor to end of line content; if at EOL, delete just the \n */
    if (p->li->dirty) li_rebuild(p->li, p->buf);
    size_t nl = li_line_count(p->li);
    size_t le = (p->cursor_line+1 < nl)
                ? li_line_start(p->li, p->cursor_line+1) - 1
                : gb_len(p->buf);
    size_t n = 0;
    if (p->cursor < le)             n = le - p->cursor;      /* delete to EOL content */
    else if (p->cursor < gb_len(p->buf)) n = 1;              /* delete the \n itself  */
    if (!n) return;
    pane_push_undo(p);
    gb_delete(p->buf, p->cursor, n);
    mark_dirty(p); li_rebuild(p->li, p->buf);
    cursor_update_line_col(p);
}

void pane_kill_whole_line(Pane *p) {
    if (p->li->dirty) li_rebuild(p->li, p->buf);
    size_t nl = li_line_count(p->li);
    size_t ls = li_line_start(p->li, p->cursor_line);
    size_t le = (p->cursor_line+1 < nl)
                ? li_line_start(p->li, p->cursor_line+1)
                : gb_len(p->buf);
    pane_push_undo(p);
    gb_delete(p->buf, ls, le-ls); p->cursor = ls;
    mark_dirty(p); li_rebuild(p->li, p->buf);
    cursor_update_line_col(p); pane_scroll_to_cursor(p);
}

void pane_undo(Pane *p) {
    GapBuf *nb = NULL; size_t nc = 0;
    if (us_undo(p->undo, &nb, &nc)) {
        gb_free(p->buf); p->buf = nb; p->cursor = nc;
        mark_dirty(p); li_rebuild(p->li, p->buf);
        cursor_update_line_col(p); pane_scroll_to_cursor(p);
    }
}
void pane_redo(Pane *p) {
    GapBuf *nb = NULL; size_t nc = 0;
    if (us_redo(p->undo, &nb, &nc)) {
        gb_free(p->buf); p->buf = nb; p->cursor = nc;
        mark_dirty(p); li_rebuild(p->li, p->buf);
        cursor_update_line_col(p); pane_scroll_to_cursor(p);
    }
}

void pane_copy(Pane *p) {
    if (!p->sel_active) return;
    size_t s0 = min_sz(p->sel_anchor, p->cursor);
    size_t s1 = max_sz(p->sel_anchor, p->cursor);
    size_t len = s1-s0;
    free(p->clip.text);
    p->clip.text = malloc(len+1);
    gb_get_range(p->buf, s0, len, p->clip.text);
    p->clip.text[len] = '\0'; p->clip.len = len;
    p->sel_active = false;
}

void pane_cut(Pane *p) {
    if (!p->sel_active) return;
    pane_copy(p);
    size_t s0 = min_sz(p->sel_anchor, p->cursor);
    size_t s1 = max_sz(p->sel_anchor, p->cursor);
    pane_push_undo(p);
    gb_delete(p->buf, s0, s1-s0); p->cursor = s0;
    mark_dirty(p); li_rebuild(p->li, p->buf);
    cursor_update_line_col(p);
}

void pane_paste(Pane *p) {
    if (!p->clip.text || !p->clip.len) return;
    pane_push_undo(p);
    gb_insert_str(p->buf, p->cursor, p->clip.text, p->clip.len);
    p->cursor += p->clip.len;
    mark_dirty(p); li_rebuild(p->li, p->buf);
    cursor_update_line_col(p); pane_scroll_to_cursor(p);
}

void pane_search_next(Pane *p) {
    if (!p->search.count) return;
    p->search.current = (p->search.current + 1) % (int)p->search.count;
    p->cursor = p->search.matches[p->search.current];
    li_rebuild(p->li, p->buf); cursor_update_line_col(p); pane_scroll_to_cursor(p);
}
void pane_search_prev(Pane *p) {
    if (!p->search.count) return;
    p->search.current = (p->search.current - 1 + (int)p->search.count) % (int)p->search.count;
    p->cursor = p->search.matches[p->search.current];
    li_rebuild(p->li, p->buf); cursor_update_line_col(p); pane_scroll_to_cursor(p);
}

void pane_wipe_file(Pane *p) {
    if (!p->filename[0]) return;
    char cmd[4200];
    snprintf(cmd, sizeof cmd, "shred -uz \"%s\" 2>&1", p->filename);
    int _r = system(cmd); (void)_r;
    gb_free(p->buf); p->buf = gb_new(GAP_DEFAULT);
    li_free(p->li);  p->li  = li_new();
    syn_free(p->syn); p->syn = syn_new(p->lang);
    int fd = open(p->filename, O_RDONLY);
    if (fd >= 0) {
        struct stat st; fstat(fd, &st);
        size_t sz = (size_t)st.st_size;
        if (sz > 0) {
            void *m = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
            if (m != MAP_FAILED) { gb_insert_str(p->buf, 0, (const char*)m, sz); munmap(m,sz); }
        }
        close(fd);
    }
    li_rebuild(p->li, p->buf);
    p->cursor = 0; p->cursor_line = 0; p->cursor_col = 0; p->modified = false;
    pane_push_undo(p); mark_dirty(p);
}

void pane_cursor_line_col(const Pane *p, size_t *line, size_t *col) {
    *line = p->cursor_line; *col = p->cursor_col;
}