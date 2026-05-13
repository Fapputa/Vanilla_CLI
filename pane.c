#include "abyss.h"
#include "utf8.h"
#include <string.h>

GapBuf *gb_clone(const GapBuf *g);

/* ── UTF-8 helpers on GapBuf ──────────────────────────────────────── */

/* Read up to 4 bytes from GapBuf at byte offset pos into tmp[], decode. */
static int gb_decode_cp(const GapBuf *g, size_t pos, uint32_t *cp) {
    size_t len = gb_len(g);
    if (pos >= len) { *cp = 0; return 0; }
    char tmp[4];
    int n = utf8_byte_len((unsigned char)gb_at(g, pos));
    if ((size_t)n > len - pos) n = (int)(len - pos);
    for (int i = 0; i < n; i++) tmp[i] = gb_at(g, pos + i);
    return utf8_decode(tmp, (size_t)n, cp);
}

/* Visual width of the character at byte offset pos in GapBuf. */
static int gb_char_vis_width(const GapBuf *g, size_t pos) {
    uint32_t cp; gb_decode_cp(g, pos, &cp);
    if (cp == '\t') return 4; /* treat tab as 4 spaces */
    return utf8_cp_width(cp);
}

/* Move one codepoint forward (returns bytes advanced). */
static size_t gb_next_cp(const GapBuf *g, size_t pos) {
    size_t len = gb_len(g);
    if (pos >= len) return 0;
    int n = utf8_byte_len((unsigned char)gb_at(g, pos));
    if (pos + (size_t)n > len) n = (int)(len - pos);
    return (size_t)n;
}

/* Move one codepoint backward (returns bytes retreated). */
static size_t gb_prev_cp(const GapBuf *g, size_t pos) {
    if (pos == 0) return 0;
    size_t back = 1;
    /* skip continuation bytes */
    while (back < 4 && back < pos &&
           utf8_is_continuation((unsigned char)gb_at(g, pos - back - 1)))
        back++;
    return back;
}

/* Compute visual column of byte offset within a line (line_start in bytes). */
static size_t byte_offset_to_vis_col(const GapBuf *g, size_t line_start, size_t byte_offset) {
    size_t vis = 0;
    size_t pos = line_start;
    while (pos < byte_offset) {
        uint32_t cp; int n = gb_decode_cp(g, pos, &cp);
        if (n <= 0) break;
        if (cp == '\t') vis = (vis / 4 + 1) * 4;
        else vis += (size_t)utf8_cp_width(cp);
        pos += (size_t)n;
    }
    return vis;
}

/* Find the byte offset whose visual column is >= target_vis_col.
   Returns byte offset from line_start. line_len is in bytes. */
static size_t vis_col_to_byte_offset(const GapBuf *g, size_t line_start,
                                      size_t line_len, size_t target_vis) {
    size_t vis = 0, pos = 0;
    while (pos < line_len) {
        if (vis >= target_vis) break;
        uint32_t cp; int n = gb_decode_cp(g, line_start + pos, &cp);
        if (n <= 0) break;
        int w = (cp == '\t') ? (int)(((vis/4)+1)*4 - vis) : utf8_cp_width(cp);
        if (vis + (size_t)w > target_vis) break;
        vis += (size_t)w;
        pos += (size_t)n;
    }
    return pos;
}

Pane *pane_new(void) {
    Pane *p = calloc(1, sizeof *p);
    p->buf  = gb_new(GAP_DEFAULT);
    p->li   = li_new();
    p->syn  = syn_new(LANG_C);
    p->undo = us_new();
    p->lang = LANG_C;
    p->show_line_numbers = false;
    p->prev_render_rows  = 0;
    p->last_cursor_row   = 0;
    p->hex_mode          = false;
    p->hex               = NULL;
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
    hex_free(p->hex);
    free(p);
}

void pane_open_file(Pane *p, const char *path) {
    char resolved[4096];
    if (realpath(path, resolved))
        strncpy(p->filename, resolved, sizeof(p->filename)-1);
    else
        strncpy(p->filename, path, sizeof(p->filename)-1);
    p->filename[sizeof(p->filename)-1] = '\0';

    /* Vider le buffer précédent avant de charger */
    gb_free(p->buf); p->buf = gb_new(GAP_DEFAULT);
    p->cursor = 0; p->cursor_line = 0; p->cursor_col = 0;
    p->scroll_line = 0; p->scroll_col = 0; p->preferred_col = 0;
    p->sel_active = false;
    p->modified = false;
    us_free(p->undo); p->undo = us_new();

    const char *ext = strrchr(path, '.');
    p->lang = lang_from_ext(ext ? ext : "");

    /* Binary file → hex mode, don't load into GapBuf */
    if (p->lang == LANG_HEX) {
        if (!p->hex) p->hex = hex_new();
        hex_load(p->hex, p->filename);
        p->hex_mode = true;
        syn_free(p->syn); p->syn = syn_new(LANG_NONE);
    } else {
        p->hex_mode = false;
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            struct stat st; fstat(fd, &st);
            size_t sz = (size_t)st.st_size;
            if (sz > 0) {
                void *m = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
                if (m != MAP_FAILED) {
                    const char *src = (const char *)m;
                    /* Detect and strip \r\n → \n (CRLF files) */
                    p->crlf = false;
                    for (size_t i = 0; i + 1 < sz; i++) {
                        if (src[i] == '\r' && src[i+1] == '\n') { p->crlf = true; break; }
                    }
                    if (p->crlf) {
                        char *buf = malloc(sz);
                        size_t j = 0;
                        for (size_t i = 0; i < sz; i++) {
                            if (src[i] == '\r' && i + 1 < sz && src[i+1] == '\n') continue;
                            buf[j++] = src[i];
                        }
                        gb_insert_str(p->buf, 0, buf, j);
                        free(buf);
                    } else {
                        gb_insert_str(p->buf, 0, src, sz);
                    }
                    munmap(m, sz);
                }
            }
            close(fd);
        }
        syn_free(p->syn); p->syn = syn_new(p->lang);
    }

    li_rebuild(p->li, p->buf);
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
    /* In hex mode, delegate to hex_save */
    if (p->hex_mode && p->hex)
        return hex_save(p->hex, path);

    if (path && path[0]) strncpy(p->filename, path, sizeof(p->filename)-1);
    if (!p->filename[0]) return false;
    char *s = gb_to_str(p->buf);
    size_t slen = strlen(s);

    /* Re-add \r\n if file originally used CRLF */
    char *out = s; size_t outlen = slen;
    if (p->crlf) {
        /* Count \n to know how much space we need */
        size_t newlines = 0;
        for (size_t i = 0; i < slen; i++) if (s[i] == '\n') newlines++;
        out = malloc(slen + newlines + 1);
        size_t j = 0;
        for (size_t i = 0; i < slen; i++) {
            if (s[i] == '\n') out[j++] = '\r';
            out[j++] = s[i];
        }
        out[j] = '\0'; outlen = j;
        free(s);
    }

    SaveArgs *sa = malloc(sizeof *sa);
    snprintf(sa->path, sizeof(sa->path), "%s", p->filename);
    sa->data = out; sa->len = outlen;
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
    /* Prevent ncurses from wrapping long lines onto the next row,
       which would shift all subsequent lines and cause them to disappear */
    scrollok(w, FALSE);
    idlok(w, FALSE);
}

static void cursor_update_line_col(Pane *p) {
    size_t lo = 0, hi = li_line_count(p->li);
    while (lo + 1 < hi) {
        size_t mid = (lo + hi) / 2;
        if (li_line_start(p->li, mid) <= p->cursor) lo = mid; else hi = mid;
    }
    p->cursor_line = lo;
    /* cursor_col = visual column, not byte offset */
    size_t line_start = li_line_start(p->li, lo);
    p->cursor_col = byte_offset_to_vis_col(p->buf, line_start, p->cursor);
}

void pane_scroll_to_cursor(Pane *p) {
    int margin = 3;
    int gutter = p->show_line_numbers ? 6 : 0;
    int text_w = p->win_w - gutter; if (text_w < 1) text_w = 1;

    /* Vertical scroll */
    if (p->win_h > 0) {
        long cl = (long)p->cursor_line;
        long sl = (long)p->scroll_line;
        if (cl < sl + margin)
            p->scroll_line = cl > margin ? (size_t)(cl - margin) : 0;
        if (cl >= sl + p->win_h - margin)
            p->scroll_line = (size_t)(cl - p->win_h + margin + 1);
    }

    /* Horizontal scroll — use signed arithmetic to avoid size_t wrap bugs */
    long cc = (long)p->cursor_col;
    long sc = (long)p->scroll_col;
    if (cc < sc)
        p->scroll_col = (size_t)cc;
    else if (cc >= sc + text_w)
        p->scroll_col = (size_t)(cc - text_w + 1);
}

void pane_render(Pane *p, bool force) {
    /* If hex mode is active, delegate entirely to hex_render */
    if (p->hex_mode && p->hex) {
        hex_render(p->hex, p->win, p->win_h, p->win_w);
        return;
    }

    (void)force;
    if (!p->win || p->win_h < 1 || p->win_w < 1) return;
    if (p->li->dirty) li_rebuild(p->li, p->buf);

    int gutter = p->show_line_numbers ? 6 : 0;
    int text_w = p->win_w - gutter; if (text_w < 1) text_w = 1;
    size_t nlines = li_line_count(p->li);
    size_t buflen  = gb_len(p->buf);

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

        if (p->show_line_numbers) {
            wattron(p->win, is_cur_row ? (A_BOLD|COLOR_PAIR(COLOR_PAIR_LINENUM))
                                       : COLOR_PAIR(COLOR_PAIR_LINENUM));
            wprintw(p->win, "%4zu ", lineno + 1);
            wattroff(p->win, A_BOLD|COLOR_PAIR(COLOR_PAIR_LINENUM));
            wattron(p->win, COLOR_PAIR(COLOR_PAIR_OPERATOR));
            waddch(p->win, '|');
            wattroff(p->win, COLOR_PAIR(COLOR_PAIR_OPERATOR));
        }

        LineAttr *la = &p->syn->lines[lineno];

        /* UTF-8 aware rendering:
           - iterate by codepoint (byte pos), track visual column
           - scroll_col and text_w are in visual columns */
        size_t byte_pos = line_start; /* current byte position in buffer */
        size_t vis_col  = 0;          /* current visual column on this line */

        /* Skip characters that are scrolled off to the left */
        while (byte_pos < line_start + line_len) {
            uint32_t cp; char tmp[4];
            int blen_cp = utf8_byte_len((unsigned char)gb_at(p->buf, byte_pos));
            int avail = (int)(line_start + line_len - byte_pos);
            if (blen_cp > avail) blen_cp = avail;
            for (int i = 0; i < blen_cp; i++) tmp[i] = gb_at(p->buf, byte_pos + i);
            utf8_decode(tmp, (size_t)blen_cp, &cp);
            int w = (cp == '\t') ? (int)(((vis_col/4)+1)*4 - vis_col) : utf8_cp_width(cp);
            if (vis_col + (size_t)w > p->scroll_col) break;
            vis_col += (size_t)w;
            byte_pos += (size_t)blen_cp;
        }

        /* Render visible characters */
        int screen_col = 0; /* columns written to screen so far */
        while (byte_pos < line_start + line_len && screen_col < text_w - 1) {
            /* Decode codepoint */
            char tmp[4]; uint32_t cp;
            int blen_cp = utf8_byte_len((unsigned char)gb_at(p->buf, byte_pos));
            int avail = (int)(line_start + line_len - byte_pos);
            if (blen_cp > avail) blen_cp = avail;
            for (int i = 0; i < blen_cp; i++) tmp[i] = gb_at(p->buf, byte_pos + i);
            utf8_decode(tmp, (size_t)blen_cp, &cp);

            int w; /* visual width of this char */
            if (cp == '\t') {
                /* Compute actual tab width from absolute visual col */
                size_t abs_vis = vis_col;
                w = (int)(((abs_vis/4)+1)*4 - abs_vis);
                if (screen_col + w > text_w) w = text_w - screen_col;
            } else {
                w = utf8_cp_width(cp);
            }

            /* Don't overflow the line width */
            if (screen_col + w > text_w) break;

            /* Determine token type using byte offset into line attrs */
            size_t ci = byte_pos - line_start; /* byte offset within line */
            TokenType tok = (la->attrs && ci < la->len) ? la->attrs[ci] : TOK_NORMAL;

            bool sel = false;
            if (p->sel_active) {
                size_t s0 = min_sz(p->sel_anchor, p->cursor);
                size_t s1 = max_sz(p->sel_anchor, p->cursor);
                sel = (byte_pos >= s0 && byte_pos < s1);
            }
            bool cur = (byte_pos == p->cursor);

            wstandend(p->win);
            if      (cur) wattron(p->win, A_REVERSE);
            else if (sel) wattron(p->win, COLOR_PAIR(COLOR_PAIR_SELECTION));
            else {
                int color_pair = tok_to_color_pair(tok);
                wattron(p->win, COLOR_PAIR(color_pair));
                if (tok == TOK_KEYWORD || tok == TOK_TYPE) wattron(p->win, A_BOLD);
            }

            if (cp == '\t') {
                for (int i = 0; i < w; i++) waddch(p->win, ' ');
            } else if (cp < 0x80) {
                waddch(p->win, (chtype)cp);
            } else {
                /* Multi-byte: write raw UTF-8 bytes */
                tmp[blen_cp] = '\0';
                waddstr(p->win, tmp);
            }

            vis_col    += (size_t)w;
            screen_col += w;
            byte_pos   += (size_t)blen_cp;
        }
        wstandend(p->win);
        /* Cursor at end of line */
        if (byte_pos == p->cursor && is_cur_row && screen_col < text_w) {
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
    p->preferred_col = p->cursor_col;
    pane_scroll_to_cursor(p);
}

void pane_push_undo(Pane *p) { us_push(p->undo, p->buf, p->cursor); }

void pane_insert_char(Pane *p, char c) {
    if (c == '\n') { auto_indent_newline(p); return; }
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
    pane_push_undo(p); /* push APRÈS insertion avec curseur correct */
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
    cursor_update_line_col(p); p->preferred_col = p->cursor_col; pane_scroll_to_cursor(p);
}

void pane_delete_char(Pane *p) {
    if (p->cursor == 0) return;
    size_t blen = gb_len(p->buf);
    /* Find start of previous codepoint */
    size_t back = gb_prev_cp(p->buf, p->cursor);
    size_t prev_pos = p->cursor - back;
    char prev = gb_at(p->buf, prev_pos);
    const char *open = "{([\"'", *close = "})]\"'";
    const char *cp = strchr(open, prev);
    if (back == 1 && cp && p->cursor < blen && gb_at(p->buf, p->cursor) == close[cp-open]) {
        gb_delete(p->buf, prev_pos, 2); p->cursor = prev_pos;
    } else {
        gb_delete(p->buf, prev_pos, back); p->cursor = prev_pos;
    }
    pane_push_undo(p);
    mark_dirty(p); li_rebuild(p->li, p->buf);
    cursor_update_line_col(p); p->preferred_col = p->cursor_col; pane_scroll_to_cursor(p);
}

void pane_delete_forward(Pane *p) {
    size_t len = gb_len(p->buf);
    if (p->cursor >= len) return;
    pane_push_undo(p);
    size_t adv = gb_next_cp(p->buf, p->cursor);
    if (adv == 0) adv = 1;
    gb_delete(p->buf, p->cursor, adv);
    mark_dirty(p); li_rebuild(p->li, p->buf);
    cursor_update_line_col(p); p->preferred_col = p->cursor_col; pane_scroll_to_cursor(p);
}

void pane_move_cursor(Pane *p, int dy, int dx) {
    if (p->li->dirty) li_rebuild(p->li, p->buf);
    if (dy != 0) {
        /* Vertical: use preferred_col (visual), find closest byte offset */
        size_t nl = li_line_count(p->li);
        long tl = (long)p->cursor_line + dy;
        if (tl < 0) tl = 0;
        if ((size_t)tl >= nl) tl = (long)nl - 1;
        size_t ls  = li_line_start(p->li, (size_t)tl);
        size_t nls = ((size_t)tl+1 < nl)
                     ? li_line_start(p->li, (size_t)tl+1) - 1
                     : gb_len(p->buf);
        size_t ll  = nls >= ls ? nls - ls : 0;
        size_t byte_off = vis_col_to_byte_offset(p->buf, ls, ll, p->preferred_col);
        p->cursor = ls + byte_off;
    }
    if (dx > 0) {
        size_t adv = gb_next_cp(p->buf, p->cursor);
        if (adv > 0) p->cursor += adv;
        cursor_update_line_col(p);
        p->preferred_col = p->cursor_col;
        pane_scroll_to_cursor(p);
        return;
    } else if (dx < 0) {
        size_t back = gb_prev_cp(p->buf, p->cursor);
        if (back > 0) p->cursor -= back;
        cursor_update_line_col(p);
        p->preferred_col = p->cursor_col;
        pane_scroll_to_cursor(p);
        return;
    }
    cursor_update_line_col(p); p->preferred_col = p->cursor_col; pane_scroll_to_cursor(p);
}

void pane_move_to_line_col(Pane *p, size_t line, size_t col) {
    if (p->li->dirty) li_rebuild(p->li, p->buf);
    size_t nl = li_line_count(p->li);
    if (line >= nl) line = nl > 0 ? nl-1 : 0;
    size_t ls = li_line_start(p->li, line);
    p->cursor = ls + col;
    size_t blen = gb_len(p->buf);
    if (p->cursor > blen) p->cursor = blen;
    cursor_update_line_col(p); p->preferred_col = p->cursor_col; pane_scroll_to_cursor(p);
}

void pane_kill_line(Pane *p) {
    if (p->li->dirty) li_rebuild(p->li, p->buf);
    size_t nl = li_line_count(p->li);
    size_t le = (p->cursor_line+1 < nl)
                ? li_line_start(p->li, p->cursor_line+1) - 1
                : gb_len(p->buf);
    size_t n = 0;
    if (p->cursor < le)                  n = le - p->cursor;
    else if (p->cursor < gb_len(p->buf)) n = 1;
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
    cursor_update_line_col(p); p->preferred_col = p->cursor_col; pane_scroll_to_cursor(p);
}

void pane_undo(Pane *p) {
    GapBuf *nb = NULL; size_t nc = 0;
    if (us_undo(p->undo, &nb, &nc)) {
        gb_free(p->buf); p->buf = nb; p->cursor = nc;
        mark_dirty(p); li_rebuild(p->li, p->buf);
        cursor_update_line_col(p); p->preferred_col = p->cursor_col; pane_scroll_to_cursor(p);
    }
}
void pane_redo(Pane *p) {
    GapBuf *nb = NULL; size_t nc = 0;
    if (us_redo(p->undo, &nb, &nc)) {
        gb_free(p->buf); p->buf = nb; p->cursor = nc;
        mark_dirty(p); li_rebuild(p->li, p->buf);
        cursor_update_line_col(p); p->preferred_col = p->cursor_col; pane_scroll_to_cursor(p);
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
    cursor_update_line_col(p); p->preferred_col = p->cursor_col; pane_scroll_to_cursor(p);
}

void pane_search_next(Pane *p) {
    if (!p->search.count) return;
    p->search.current = (p->search.current + 1) % (int)p->search.count;
    p->cursor = p->search.matches[p->search.current];
    mark_dirty(p); li_rebuild(p->li, p->buf); cursor_update_line_col(p); p->preferred_col = p->cursor_col; pane_scroll_to_cursor(p);
}

void pane_search_prev(Pane *p) {
    if (!p->search.count) return;
    p->search.current = (p->search.current - 1 + (int)p->search.count) % (int)p->search.count;
    p->cursor = p->search.matches[p->search.current];
    mark_dirty(p); li_rebuild(p->li, p->buf); cursor_update_line_col(p); p->preferred_col = p->cursor_col; pane_scroll_to_cursor(p);
}

void pane_wipe_file(Pane *p) {
    struct stat _st;
    bool file_exists = p->filename[0] && stat(p->filename, &_st) == 0;

    if (file_exists) {
        /* Fichier sur disque : shred puis vider */
        char cmd[4200];
        snprintf(cmd, sizeof cmd, "shred -uz \"%s\" 2>&1", p->filename);
        int _r = system(cmd); (void)_r;
        p->filename[0] = '\0';
    }
    /* Dans tous les cas : vider le buffer éditeur */
    gb_free(p->buf); p->buf = gb_new(GAP_DEFAULT);
    li_free(p->li);  p->li  = li_new();
    syn_free(p->syn); p->syn = syn_new(p->lang);
    li_rebuild(p->li, p->buf);
    p->cursor = 0; p->cursor_line = 0; p->cursor_col = 0;
    p->scroll_line = 0; p->scroll_col = 0; p->preferred_col = 0;
    p->modified = false;
    pane_push_undo(p); mark_dirty(p);
}

void pane_cursor_line_col(const Pane *p, size_t *line, size_t *col) {
    *line = p->cursor_line; *col = p->cursor_col;
}