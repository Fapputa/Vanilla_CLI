#include "abyss.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define HEX_BYTES_PER_ROW 16

/* ------------------------------------------------------------------ */
void hex_colors_init(void) {
    init_pair(HEX_CP_OFFSET,   COLOR_CYAN,    -1);
    init_pair(HEX_CP_ZERO,     COLOR_WHITE,   -1);
    init_pair(HEX_CP_PRINT,    COLOR_GREEN,   -1);
    init_pair(HEX_CP_NONPRINT, COLOR_RED,     -1);
    init_pair(HEX_CP_CURSOR_H, COLOR_BLACK,   COLOR_CYAN);
    init_pair(HEX_CP_CURSOR_A, COLOR_BLACK,   COLOR_GREEN);
    init_pair(HEX_CP_PEER,     COLOR_BLACK,   COLOR_YELLOW);
    init_pair(HEX_CP_MODIFIED, COLOR_YELLOW,  -1);
    init_pair(HEX_CP_HEADER,   COLOR_WHITE,   COLOR_BLUE);
}

HexPane *hex_new(void) {
    HexPane *h = calloc(1, sizeof *h);
    h->data_cap = 4096;
    h->data     = malloc(h->data_cap);
    return h;
}

void hex_free(HexPane *h) {
    if (!h) return;
    free(h->data);
    free(h->search_results);
    free(h);
}

bool hex_load(HexPane *h, const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    struct stat st; fstat(fd, &st);
    size_t sz = (size_t)st.st_size;
    if (sz > h->data_cap) {
        free(h->data);
        h->data     = malloc(sz + 1);
        h->data_cap = sz + 1;
    }
    h->data_len = 0;
    if (sz > 0) {
        void *m = mmap(NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
        if (m != MAP_FAILED) { memcpy(h->data, m, sz); munmap(m, sz); h->data_len = sz; }
    }
    close(fd);
    char resolved[4096];
    strncpy(h->filename, realpath(path, resolved) ? resolved : path,
            sizeof(h->filename) - 1);
    h->cursor = 0; h->nibble = 0;
    h->focus  = HEX_FOCUS_HEX; h->scroll_row = 0; h->modified = false;
    return true;
}

bool hex_save(HexPane *h, const char *path) {
    const char *dst = (path && path[0]) ? path : h->filename;
    if (!dst[0]) return false;
    FILE *f = fopen(dst, "wb");
    if (!f) return false;
    fwrite(h->data, 1, h->data_len, f);
    fclose(f);
    if (dst != h->filename) strncpy(h->filename, dst, sizeof(h->filename)-1);
    h->modified = false;
    return true;
}

void hex_search_ascii(HexPane *h, const char *query) {
    free(h->search_results); h->search_results = NULL;
    h->search_count = 0; h->search_current = 0;
    if (!query || !query[0]) return;
    size_t qlen = strlen(query);
    if (qlen > h->data_len) return;
    size_t cap = 64;
    h->search_results = malloc(cap * sizeof(size_t));
    for (size_t i = 0; i <= h->data_len - qlen; i++) {
        if (memcmp(h->data + i, query, qlen) == 0) {
            if (h->search_count >= cap) {
                cap *= 2;
                h->search_results = realloc(h->search_results, cap * sizeof(size_t));
            }
            h->search_results[h->search_count++] = i;
        }
    }
    strncpy(h->search_query, query, sizeof(h->search_query)-1);
}

/* ------------------------------------------------------------------ */
void hex_scroll_to_cursor(HexPane *h, int win_h) {
    size_t cur_row   = h->cursor / HEX_BYTES_PER_ROW;
    int    text_rows = win_h - 1; if (text_rows < 1) text_rows = 1;
    int    margin    = 2;
    if (cur_row < h->scroll_row + (size_t)margin)
        h->scroll_row = cur_row > (size_t)margin ? cur_row - margin : 0;
    if (cur_row >= h->scroll_row + (size_t)(text_rows - margin))
        h->scroll_row = cur_row - (size_t)text_rows + (size_t)margin + 1;
}

/* ------------------------------------------------------------------ */
void hex_render(HexPane *h, WINDOW *win, int win_h, int win_w) {
    if (!win || win_h < 3 || win_w < 10) return;
    werase(win);
    int text_rows = win_h - 1;

    /* Header */
    wattron(win, COLOR_PAIR(HEX_CP_HEADER) | A_BOLD);
    wmove(win, 0, 0);
    wprintw(win, " Offset   ");
    for (int b = 0; b < HEX_BYTES_PER_ROW; b++) {
        if (b == 8) waddch(win, ' ');
        wprintw(win, "%02X ", b);
    }
    waddstr(win, " ASCII           ");
    if (h->search_count > 0)
        wprintw(win, "[%zu/%zu] \"%s\"",
                h->search_current + 1, h->search_count, h->search_query);
    wclrtoeol(win);
    wattroff(win, COLOR_PAIR(HEX_CP_HEADER) | A_BOLD);

    size_t total_rows = h->data_len > 0
                      ? (h->data_len + HEX_BYTES_PER_ROW - 1) / HEX_BYTES_PER_ROW : 1;
    size_t cur_row = h->cursor / HEX_BYTES_PER_ROW;
    size_t cur_col = h->cursor % HEX_BYTES_PER_ROW;
    size_t qlen    = h->search_query[0] ? strlen(h->search_query) : 0;

    for (int row = 0; row < text_rows; row++) {
        size_t vrow = h->scroll_row + (size_t)row;
        wmove(win, row + 1, 0); wstandend(win);
        if (vrow >= total_rows) { wclrtoeol(win); continue; }

        size_t rs  = vrow * HEX_BYTES_PER_ROW;
        size_t re  = rs + HEX_BYTES_PER_ROW; if (re > h->data_len) re = h->data_len;
        size_t rlen = re - rs;

        wattron(win, COLOR_PAIR(HEX_CP_OFFSET));
        wprintw(win, " %07zx  ", rs);
        wattroff(win, COLOR_PAIR(HEX_CP_OFFSET));

        /* Hex */
        for (size_t b = 0; b < (size_t)HEX_BYTES_PER_ROW; b++) {
            if (b == 8) waddch(win, ' ');
            if (b >= rlen) { waddstr(win, "   "); continue; }
            size_t  ap2    = rs + b;
            uint8_t byte   = h->data[ap2];
            bool    is_cur = (vrow == cur_row && b == cur_col);
            bool    is_srch = qlen > 0 && h->search_count > 0 &&
                              ap2 >= h->search_results[h->search_current] &&
                              ap2 <  h->search_results[h->search_current] + qlen;

            if      (is_cur && h->focus == HEX_FOCUS_HEX)   wattron(win, COLOR_PAIR(HEX_CP_CURSOR_H)|A_BOLD);
            else if (is_cur && h->focus == HEX_FOCUS_ASCII)  wattron(win, COLOR_PAIR(HEX_CP_PEER));
            else if (is_srch)                                 wattron(win, COLOR_PAIR(COLOR_PAIR_SEARCH)|A_BOLD);
            else if (byte == 0x00)                            wattron(win, COLOR_PAIR(HEX_CP_ZERO)|A_DIM);
            else if (isprint(byte))                           wattron(win, COLOR_PAIR(HEX_CP_PRINT));
            else                                              wattron(win, COLOR_PAIR(HEX_CP_NONPRINT));

            if (is_cur && h->focus == HEX_FOCUS_HEX && h->nibble == 1)
                wprintw(win, "%X_", (byte >> 4) & 0xF);
            else
                wprintw(win, "%02X", byte);
            wstandend(win); waddch(win, ' ');
        }

        wattron(win, COLOR_PAIR(HEX_CP_OFFSET));
        waddstr(win, " |");
        wattroff(win, COLOR_PAIR(HEX_CP_OFFSET));

        /* ASCII */
        for (size_t b = 0; b < rlen; b++) {
            size_t  ap2    = rs + b;
            uint8_t byte   = h->data[ap2];
            bool    is_cur = (vrow == cur_row && b == cur_col);
            bool    is_srch = qlen > 0 && h->search_count > 0 &&
                              ap2 >= h->search_results[h->search_current] &&
                              ap2 <  h->search_results[h->search_current] + qlen;
            char disp = isprint(byte) ? (char)byte : '.';

            if      (is_cur && h->focus == HEX_FOCUS_ASCII) wattron(win, COLOR_PAIR(HEX_CP_CURSOR_A)|A_BOLD);
            else if (is_cur && h->focus == HEX_FOCUS_HEX)   wattron(win, COLOR_PAIR(HEX_CP_PEER));
            else if (is_srch)                                wattron(win, COLOR_PAIR(COLOR_PAIR_SEARCH)|A_BOLD);
            else if (byte == 0x00)                           wattron(win, COLOR_PAIR(HEX_CP_ZERO)|A_DIM);
            else if (isprint(byte))                          wattron(win, COLOR_PAIR(HEX_CP_PRINT));
            else                                             wattron(win, COLOR_PAIR(HEX_CP_NONPRINT));
            waddch(win, disp); wstandend(win);
        }
        wattron(win, COLOR_PAIR(HEX_CP_OFFSET)); waddch(win, '|'); wattroff(win, COLOR_PAIR(HEX_CP_OFFSET));
        wclrtoeol(win);
    }
    wnoutrefresh(win);
}

/* ------------------------------------------------------------------ */
static void hex_move(HexPane *h, int dy, int dx, int win_h) {
    if (!h->data_len) return;
    long pos = (long)h->cursor + dy * HEX_BYTES_PER_ROW + dx;
    if (pos < 0) pos = 0;
    if ((size_t)pos >= h->data_len) pos = (long)(h->data_len - 1);
    h->cursor = (size_t)pos; h->nibble = 0;
    hex_scroll_to_cursor(h, win_h);
}

bool hex_handle_key(HexPane *h, int key, int win_h) {
    switch (key) {
        case KEY_UP:    hex_move(h, -1,  0, win_h); return true;
        case KEY_DOWN:  hex_move(h,  1,  0, win_h); return true;
        case KEY_LEFT:  hex_move(h,  0, -1, win_h); return true;
        case KEY_RIGHT: hex_move(h,  0,  1, win_h); return true;
        case KEY_PPAGE: hex_move(h, -(win_h-2), 0, win_h); return true;
        case KEY_NPAGE: hex_move(h,   win_h-2,  0, win_h); return true;
        case KEY_HOME:
            h->cursor = (h->cursor / HEX_BYTES_PER_ROW) * HEX_BYTES_PER_ROW;
            h->nibble = 0; hex_scroll_to_cursor(h, win_h); return true;
        case KEY_END: {
            size_t e = (h->cursor / HEX_BYTES_PER_ROW) * HEX_BYTES_PER_ROW + HEX_BYTES_PER_ROW - 1;
            if (e >= h->data_len) e = h->data_len > 0 ? h->data_len - 1 : 0;
            h->cursor = e; h->nibble = 0; hex_scroll_to_cursor(h, win_h); return true;
        }
        case '\t':
            h->focus  = (h->focus == HEX_FOCUS_HEX) ? HEX_FOCUS_ASCII : HEX_FOCUS_HEX;
            h->nibble = 0; return true;

        /* Ctrl+N / Ctrl+P — résultat suivant / précédent */
        case 'n'&0x1f:
            if (h->search_count > 0) {
                h->search_current = (h->search_current + 1) % h->search_count;
                h->cursor = h->search_results[h->search_current];
                hex_scroll_to_cursor(h, win_h);
            }
            return true;
        case 'p'&0x1f:
            if (h->search_count > 0) {
                h->search_current = (h->search_current + h->search_count - 1) % h->search_count;
                h->cursor = h->search_results[h->search_current];
                hex_scroll_to_cursor(h, win_h);
            }
            return true;

        default:
            /* ASCII panel */
            if (h->focus == HEX_FOCUS_ASCII && h->data_len > 0 && key >= 32 && key < 127) {
                h->data[h->cursor] = (uint8_t)key; h->modified = true;
                if (h->cursor + 1 < h->data_len) h->cursor++;
                hex_scroll_to_cursor(h, win_h); return true;
            }
            /* Hex panel nibble */
            if (h->focus == HEX_FOCUS_HEX && h->data_len > 0) {
                int nv = -1;
                if (key >= '0' && key <= '9') nv = key - '0';
                else if (key >= 'a' && key <= 'f') nv = key - 'a' + 10;
                else if (key >= 'A' && key <= 'F') nv = key - 'A' + 10;
                if (nv >= 0) {
                    uint8_t b = h->data[h->cursor];
                    if (h->nibble == 0) {
                        h->data[h->cursor] = (uint8_t)((nv << 4) | (b & 0x0F));
                        h->nibble = 1;
                    } else {
                        h->data[h->cursor] = (uint8_t)((b & 0xF0) | nv);
                        h->nibble = 0; h->modified = true;
                        if (h->cursor + 1 < h->data_len) h->cursor++;
                        hex_scroll_to_cursor(h, win_h);
                    }
                    return true;
                }
            }
            return false;
    }
}