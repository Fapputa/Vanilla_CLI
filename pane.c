#include "abyss.h"
#include "disview.h"

extern char E_notify[256];
#include "utf8.h"
#include <string.h>

GapBuf *gb_clone(const GapBuf *g);

static int gb_decode_cp(const GapBuf *g, size_t pos, uint32_t *cp) {
    size_t len = gb_len(g);
    if (pos >= len) { *cp = 0; return 0; }
    char tmp[4];
    int n = utf8_byte_len((unsigned char)gb_at(g, pos));
    if ((size_t)n > len - pos) n = (int)(len - pos);
    for (int i = 0; i < n; i++) tmp[i] = gb_at(g, pos + i);
    return utf8_decode(tmp, (size_t)n, cp);
}

static int gb_char_vis_width(const GapBuf *g, size_t pos) {
    uint32_t cp; gb_decode_cp(g, pos, &cp);
    if (cp == '\t') return 4; 
    return utf8_cp_width(cp);
}

static size_t gb_next_cp(const GapBuf *g, size_t pos) {
    size_t len = gb_len(g);
    if (pos >= len) return 0;
    int n = utf8_byte_len((unsigned char)gb_at(g, pos));
    if (pos + (size_t)n > len) n = (int)(len - pos);
    return (size_t)n;
}

static size_t gb_prev_cp(const GapBuf *g, size_t pos) {
    if (pos == 0) return 0;
    size_t back = 1;
    
    while (back < 4 && back < pos &&
           utf8_is_continuation((unsigned char)gb_at(g, pos - back - 1)))
        back++;
    return back;
}

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
    p->table_mode        = false;
    p->table             = NULL;
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
    tbl_free(p->table);
    img_free(p->img);
    doc_free(p->doc);
    dis_free(p->dis);
    free(p);
}

/* After the buffer was rewritten from outside the usual editing calls
 * (table edits...): indexes, highlighting and cursor are refreshed. */
void pane_text_changed(Pane *p) {
    size_t len = gb_len(p->buf);
    if (p->cursor > len) p->cursor = len;
    p->modified = true;
    li_rebuild(p->li, p->buf);
    syn_mark_dirty_from(p->syn, 0);
    p->sel_active = false;
}

/* Markdown preview of the buffer, or the rendering of a binary document
 * (PDF, docx...) read from the file itself. */
bool pane_doc_enter(Pane *p) {
    if (!p->doc) p->doc = doc_new();
    bool ok;
    if (p->binary_view || !doc_is_markdown(p->filename)) {
        ok = doc_load_file(p->doc, p->filename);
    } else {
        char *s = gb_to_str(p->buf);
        ok = doc_load_markdown(p->doc, p->filename, s, gb_len(p->buf));
        free(s);
    }
    if (!ok && !p->binary_view) {
        snprintf(E_notify, sizeof E_notify, "Document view: %.200s", p->doc->err);
        return false;
    }
    p->doc_mode = true;          /* binary docs show their error in the pane */
    return ok;
}

extern char E_notify[256];

void pane_open_file(Pane *p, const char *path) {
    p->url[0] = p->url_name[0] = '\0';
    char resolved[4096];
    if (realpath(path, resolved))
        strncpy(p->filename, resolved, sizeof(p->filename)-1);
    else
        strncpy(p->filename, path, sizeof(p->filename)-1);
    p->filename[sizeof(p->filename)-1] = '\0';

    
    E_notify[0] = '\0';
    bool can_read  = (access(p->filename, R_OK) == 0);
    bool can_write = (access(p->filename, W_OK) == 0);
    if (!can_read && !can_write)
        snprintf(E_notify, sizeof E_notify, "Cannot read or write: %s", p->filename);
    else if (!can_read)
        snprintf(E_notify, sizeof E_notify, "Cannot read: %s", p->filename);
    else if (!can_write)
        snprintf(E_notify, sizeof E_notify, "Cannot write: %s (read-only)", p->filename);

    
    gb_free(p->buf); p->buf = gb_new(GAP_DEFAULT);
    p->cursor = 0; p->cursor_line = 0; p->cursor_col = 0;
    p->scroll_line = 0; p->scroll_col = 0; p->preferred_col = 0;
    p->sel_active = false;
    p->modified = false;
    us_free(p->undo); p->undo = us_new();

    const char *ext = strrchr(path, '.');
    p->lang = lang_from_ext(ext ? ext : "");

    /* pictures and binary documents (PDF, Word...) are shown, not loaded
     * as text: the buffer stays empty and saving is disabled */
    p->img_mode = p->doc_mode = p->binary_view = false;
    p->dis_mode = false;                   /* the F9 view belongs to the old file */
    dis_free(p->dis); p->dis = NULL;
    if (p->img) { img_free(p->img); p->img = NULL; }
    if (p->doc) { doc_free(p->doc); p->doc = NULL; }
    if (img_is_image(p->filename) || doc_is_binary_doc(p->filename)) {
        p->hex_mode    = false;
        p->table_mode  = false;
        if (p->table) { tbl_free(p->table); p->table = NULL; }
        p->binary_view = true;
        p->lang        = LANG_NONE;
        syn_free(p->syn); p->syn = syn_new(LANG_NONE);
        li_rebuild(p->li, p->buf);
        if (img_is_image(p->filename)) {
            p->img = img_new(p->filename);
            p->img_mode = true;
        } else {
            pane_doc_enter(p);
        }
        return;
    }

    
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

    /* data files (and SQLite databases, whatever their name) open
     * straight into the table view; F6 goes back to text / hex */
    p->table_mode = false;
    if (p->table) { tbl_free(p->table); p->table = NULL; }
    /* documents open rendered; F7 goes to the text to edit it */
    p->doc_mode = false;
    if (doc_is_markdown(p->filename) && gb_len(p->buf) > 0) {
        char keep[256];
        snprintf(keep, sizeof keep, "%s", E_notify);
        if (pane_doc_enter(p) && keep[0]) snprintf(E_notify, sizeof E_notify, "%s", keep);
        return;
    }

    bool sqlite = p->hex_mode && p->hex && tbl_is_sqlite(p->hex->data, p->hex->data_len);
    if (sqlite || tbl_auto_ext(p->filename)) {
        char keep[256];
        snprintf(keep, sizeof keep, "%s", E_notify);
        if (!pane_table_enter(p)) snprintf(E_notify, sizeof E_notify, "%s", keep);
        else if (keep[0])         snprintf(E_notify, sizeof E_notify, "%s", keep);
    }
}

typedef struct { char path[4096]; char *data; size_t len; } SaveArgs;

/* saves still being written by a background thread */
static int saves_in_flight = 0;

static bool write_file(const char *path, const char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fwrite(data, 1, len, f) == len;
    if (fclose(f) != 0) ok = false;
    return ok;
}

static void *save_thread_fn(void *arg) {
    SaveArgs *sa = arg;
    write_file(sa->path, sa->data, sa->len);
    free(sa->data); free(sa);
    __atomic_sub_fetch(&saves_in_flight, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

static bool pane_save_impl(Pane *p, const char *path, bool sync);

bool pane_save_file(Pane *p, const char *path) { return pane_save_impl(p, path, false); }

/* ^B: the compiler reads the file from disk, so the save must be on
 * disk before it starts — written here, after any background save of
 * the same file has landed (it would otherwise overwrite it late). */
bool pane_save_file_sync(Pane *p) {
    for (int i = 0; i < 2000 && __atomic_load_n(&saves_in_flight, __ATOMIC_SEQ_CST) > 0; i++) {
        struct timespec ts = { 0, 1000000L };
        nanosleep(&ts, NULL);
    }
    return pane_save_impl(p, NULL, true);
}

static bool pane_save_impl(Pane *p, const char *path, bool sync) {
    
    if (p->hex_mode && p->hex)
        return hex_save(p->hex, path);

    /* never write the (empty) text buffer over a picture or a PDF */
    if (p->binary_view) {
        snprintf(E_notify, sizeof E_notify, "Read-only view: use F2 (hex) to modify this file");
        return false;
    }

    if (path && path[0]) strncpy(p->filename, path, sizeof(p->filename)-1);
    if (!p->filename[0]) return false;
    char *s = gb_to_str(p->buf);
    size_t slen = strlen(s);

    
    char *out = s; size_t outlen = slen;
    if (p->crlf) {
        
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

    if (sync) {
        bool ok = write_file(p->filename, out, outlen);
        free(out);
        if (!ok) {
            snprintf(E_notify, sizeof E_notify, "Save failed: %.200s", strerror(errno));
            return false;
        }
    } else {
        SaveArgs *sa = malloc(sizeof *sa);
        snprintf(sa->path, sizeof(sa->path), "%s", p->filename);
        sa->data = out; sa->len = outlen;
        __atomic_add_fetch(&saves_in_flight, 1, __ATOMIC_SEQ_CST);
        pthread_t tid;
        if (pthread_create(&tid, NULL, save_thread_fn, sa) == 0) {
            pthread_detach(tid);
        } else {                       /* no thread: write it right here */
            save_thread_fn(sa);
        }
    }
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
    
    size_t line_start = li_line_start(p->li, lo);
    p->cursor_col = byte_offset_to_vis_col(p->buf, line_start, p->cursor);
}

void pane_scroll_to_cursor(Pane *p) {
    int margin = 3;
    int gutter = p->show_line_numbers ? 6 : 0;
    int text_w = p->win_w - gutter; if (text_w < 1) text_w = 1;

    
    if (p->win_h > 0) {
        long cl = (long)p->cursor_line;
        long sl = (long)p->scroll_line;
        if (cl < sl + margin)
            p->scroll_line = cl > margin ? (size_t)(cl - margin) : 0;
        if (cl >= sl + p->win_h - margin)
            p->scroll_line = (size_t)(cl - p->win_h + margin + 1);
    }

    
    long cc = (long)p->cursor_col;
    long sc = (long)p->scroll_col;
    if (cc < sc)
        p->scroll_col = (size_t)cc;
    else if (cc >= sc + text_w)
        p->scroll_col = (size_t)(cc - text_w + 1);
}

static int hex_digit_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static bool is_word_byte(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') || c == '_';
}

/* Detect a color literal starting at byte `pos` (bounded by [start,end)):
 *   #rgb   #rrggbb   0xRRGGBB   0XRRGGBB
 * On success fills *rgb (24-bit) and returns the literal's byte length; else 0.
 * Rejects word-char neighbours so "#define" / an identifier isn't a color. */
static int hex_color_at(const GapBuf *g, size_t pos, size_t start, size_t end,
                        unsigned *rgb) {
    if (pos >= end) return 0;
    if (pos > start && is_word_byte(gb_at(g, pos - 1))) return 0;

    char c0 = gb_at(g, pos);
    size_t p;
    bool zerox = false;

    if (c0 == '#') {
        p = pos + 1;
    } else if (c0 == '0' && pos + 1 < end &&
               (gb_at(g, pos + 1) == 'x' || gb_at(g, pos + 1) == 'X')) {
        p = pos + 2;
        zerox = true;                    /* 0x form: require exactly 6 digits */
    } else {
        return 0;
    }

    int d[6], n = 0;
    while (p < end && n < 6) {
        int v = hex_digit_val(gb_at(g, p));
        if (v < 0) break;
        d[n++] = v; p++;
    }
    if (zerox ? (n != 6) : (n != 3 && n != 6)) return 0;
    if (p < end) {
        char nc = gb_at(g, p);
        if (hex_digit_val(nc) >= 0 || is_word_byte(nc)) return 0;
    }
    if (n == 3)
        *rgb = ((unsigned)(d[0] * 17) << 16) |
               ((unsigned)(d[1] * 17) <<  8) |  (unsigned)(d[2] * 17);
    else
        *rgb = ((unsigned)((d[0] << 4) | d[1]) << 16) |
               ((unsigned)((d[2] << 4) | d[3]) <<  8) |
                (unsigned)((d[4] << 4) | d[5]);
    return (int)(p - pos);
}

void pane_render(Pane *p, bool force) {

    if (p->dis_mode && p->dis) {
        dis_render(p->dis, p->win, p->win_h, p->win_w);
        return;
    }

    if (p->mem_mode) {
        mem_ui_render(p->win, p->win_h, p->win_w);
        return;
    }

    if (p->img_mode && p->img) {
        img_render(p->img, p->win, p->win_h, p->win_w);
        return;
    }

    if (p->doc_mode && p->doc) {
        doc_render(p->doc, p->win, p->win_h, p->win_w);
        return;
    }

    if (p->table_mode && p->table) {
        tbl_render(p->table, p->win, p->win_h, p->win_w);
        return;
    }

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

    /* Prime lexer state up to the viewport. Start at the valid watermark so we
     * don't re-walk already-computed lines every frame (crucial on huge files). */
    for (size_t i = p->syn->valid_upto; i < p->scroll_line && i < nlines; i++)
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

        

        size_t byte_pos = line_start; 
        size_t vis_col  = 0;          

        
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

        
        int screen_col = 0;
        while (byte_pos < line_start + line_len && screen_col < text_w - 1) {

            /* Inline color swatch (VSCode-style): purely a rendered decoration,
             * never stored in the buffer — so it can't be deleted and is never
             * saved. Drawn just before the color literal, tinted with its RGB. */
            if (screen_col + 2 <= text_w) {
                unsigned rgb;
                if (hex_color_at(p->buf, byte_pos, line_start,
                                 line_start + line_len, &rgb)) {
                    int sp = colors_swatch_pair(rgb);
                    if (sp) {
                        wstandend(p->win);
                        wattron(p->win, COLOR_PAIR(sp) | A_BOLD);
                        waddstr(p->win, "▣");   /* ▣ */
                        wstandend(p->win);
                        waddch(p->win, ' ');
                        screen_col += 2;
                        vis_col    += 2;
                        if (screen_col >= text_w - 1) break;
                    }
                }
            }

            char tmp[5]; uint32_t cp;           /* 4 bytes + the NUL added below */
            int blen_cp = utf8_byte_len((unsigned char)gb_at(p->buf, byte_pos));
            int avail = (int)(line_start + line_len - byte_pos);
            if (blen_cp > avail) blen_cp = avail;
            for (int i = 0; i < blen_cp; i++) tmp[i] = gb_at(p->buf, byte_pos + i);
            utf8_decode(tmp, (size_t)blen_cp, &cp);

            int w; 
            if (cp == '\t') {
                
                size_t abs_vis = vis_col;
                w = (int)(((abs_vis/4)+1)*4 - abs_vis);
                if (screen_col + w > text_w) w = text_w - screen_col;
            } else {
                w = utf8_cp_width(cp);
            }

            
            if (screen_col + w > text_w) break;

            
            size_t ci = byte_pos - line_start; 
            TokenType tok = (la->attrs && ci < la->len) ? la->attrs[ci] : TOK_NORMAL;

            bool sel = false;
            if (p->sel_active) {
                size_t s0 = min_sz(p->sel_anchor, p->cursor);
                size_t s1 = max_sz(p->sel_anchor, p->cursor);
                sel = (byte_pos >= s0 && byte_pos < s1);
            }
            bool cur = (byte_pos == p->cursor);

            wstandend(p->win);
            if (cur) {
                wattron(p->win, A_REVERSE);
            } else if (sel) {
                wattron(p->win, COLOR_PAIR(COLOR_PAIR_SELECTION));
            } else {
                
                extern Editor E;
                const HLMatch *hlm = (E.hl && E.hl->visible)
                                     ? hl_match_at(E.hl, byte_pos) : NULL;
                if (hlm) {
                    wattron(p->win, COLOR_PAIR(hlm->cp) | A_BOLD);
                } else {
                    int color_pair = tok_to_color_pair(tok);
                    wattron(p->win, COLOR_PAIR(color_pair));
                    if (tok == TOK_KEYWORD || tok == TOK_TYPE) wattron(p->win, A_BOLD);
                }
            }

            if (cp == '\t') {
                for (int i = 0; i < w; i++) waddch(p->win, ' ');
            } else if (cp < 0x80) {
                waddch(p->win, (chtype)cp);
            } else {
                
                tmp[blen_cp] = '\0';
                waddstr(p->win, tmp);
            }

            vis_col    += (size_t)w;
            screen_col += w;
            byte_pos   += (size_t)blen_cp;
        }
        wstandend(p->win);
        
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

/* true si [ls, end) ne contient que des blancs */
static bool line_all_blank(const GapBuf *g, size_t ls, size_t end) {
    for (size_t i = ls; i < end; i++) {
        char c = gb_at(g, i);
        if (c != ' ' && c != '\t' && c != '\r') return false;
    }
    return true;
}

/* true si la ligne [ls, end) se termine par ':' (hors chaine et hors commentaire) */
static bool py_opens_block(const GapBuf *g, size_t ls, size_t end) {
    char quote = 0, last = 0;
    bool esc = false;
    for (size_t i = ls; i < end; i++) {
        char c = gb_at(g, i);
        if (quote) {
            if (esc)                 esc = false;
            else if (c == '\\')      esc = true;
            else if (c == quote)     quote = 0;
            last = c;
            continue;
        }
        if (c == '#') break;
        if (c == '"' || c == '\'') { quote = c; last = c; continue; }
        if (c != ' ' && c != '\t' && c != '\r') last = c;
    }
    return last == ':';
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
    char prev_c = p->cursor > 0    ? gb_at(p->buf, p->cursor-1) : 0;
    char next_c = p->cursor < blen ? gb_at(p->buf, p->cursor)   : 0;

    /* Python : deuxieme Entree sur une ligne vide -> on repart sans indentation */
    if (p->lang == LANG_PY && indent > 0 && line_all_blank(p->buf, ls, p->cursor)) {
        pane_push_undo(p);
        gb_delete(p->buf, ls, indent);          /* efface l'indentation orpheline */
        p->cursor = ls;
        gb_insert_char(p->buf, p->cursor, '\n');
        p->cursor++;
        mark_dirty(p);
        li_rebuild(p->li, p->buf);
        cursor_update_line_col(p);
        p->preferred_col = p->cursor_col;
        pane_scroll_to_cursor(p);
        return;
    }

    if (indent > 251) indent = 251;
    char spaces[256] = {0}; memset(spaces, ' ', indent);
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
        bool extra = (prev_c == '{') ||
                     (p->lang == LANG_PY && py_opens_block(p->buf, ls, p->cursor));
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
    /* the closer already under the cursor (the one auto-inserted): step over it.
     * Checked first, a quote being both an opener and a closer. */
    if (strchr(close, c) && p->cursor < gb_len(p->buf) && gb_at(p->buf, p->cursor) == c)
        { p->cursor++; goto done; }
    /* no pair for a quote right after a letter or digit (it's, don't) */
    char before = p->cursor > 0 ? gb_at(p->buf, p->cursor - 1) : ' ';
    if (cp && (c == '"' || c == '\'') && (isalnum((unsigned char)before) || before == '_'))
        cp = NULL;
    if (cp) {
        char cl = close[cp-open];
        gb_insert_char(p->buf, p->cursor, c);
        gb_insert_char(p->buf, p->cursor+1, cl);
        p->cursor++;
    } else {
        gb_insert_char(p->buf, p->cursor, c); p->cursor++;
    }
    pane_push_undo(p); 
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
    pane_push_undo(p);
    gb_free(p->buf); p->buf = gb_new(GAP_DEFAULT);
    li_free(p->li);  p->li  = li_new();
    syn_free(p->syn); p->syn = syn_new(p->lang);
    li_rebuild(p->li, p->buf);
    p->cursor = 0; p->cursor_line = 0; p->cursor_col = 0;
    p->scroll_line = 0; p->scroll_col = 0; p->preferred_col = 0;
    p->modified = true;
    mark_dirty(p);
}

void pane_cursor_line_col(const Pane *p, size_t *line, size_t *col) {
    *line = p->cursor_line; *col = p->cursor_col;
}