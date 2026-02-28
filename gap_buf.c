#include "abyss.h"

GapBuf *gb_new(size_t cap) {
    if (cap < GAP_DEFAULT) cap = GAP_DEFAULT;
    GapBuf *g = malloc(sizeof *g);
    g->buf = malloc(cap);
    g->gap_start = 0;
    g->gap_end = cap;
    g->cap = cap;
    return g;
}

void gb_free(GapBuf *g) {
    if (!g) return;
    free(g->buf);
    free(g);
}

size_t gb_len(const GapBuf *g) {
    return g->cap - (g->gap_end - g->gap_start);
}

static size_t gap_size(const GapBuf *g) {
    return g->gap_end - g->gap_start;
}

char gb_at(const GapBuf *g, size_t i) {
    if (i < g->gap_start) return g->buf[i];
    return g->buf[i + (g->gap_end - g->gap_start)];
}

void gb_move_gap(GapBuf *g, size_t pos) {
    if (pos == g->gap_start) return;
    size_t gs = gap_size(g);
    if (pos < g->gap_start) {
        /* move text right */
        size_t n = g->gap_start - pos;
        memmove(g->buf + pos + gs, g->buf + pos, n);
        g->gap_start = pos;
        g->gap_end   = pos + gs;
    } else {
        /* move text left */
        size_t n = pos - g->gap_start;
        memmove(g->buf + g->gap_start, g->buf + g->gap_end, n);
        g->gap_start = pos;
        g->gap_end   = pos + gs;
    }
}

static void gb_ensure_gap(GapBuf *g, size_t needed) {
    if (gap_size(g) >= needed) return;
    size_t new_cap = g->cap + needed + GAP_GROW;
    char *new_buf = malloc(new_cap);
    /* copy pre-gap */
    memcpy(new_buf, g->buf, g->gap_start);
    /* copy post-gap with new gap size */
    size_t new_gap_end = new_cap - (g->cap - g->gap_end);
    memcpy(new_buf + new_gap_end, g->buf + g->gap_end, g->cap - g->gap_end);
    free(g->buf);
    g->buf = new_buf;
    g->gap_end = new_gap_end;
    g->cap = new_cap;
}

void gb_insert_char(GapBuf *g, size_t pos, char c) {
    gb_ensure_gap(g, 1);
    gb_move_gap(g, pos);
    g->buf[g->gap_start++] = c;
}

void gb_insert_str(GapBuf *g, size_t pos, const char *s, size_t n) {
    gb_ensure_gap(g, n);
    gb_move_gap(g, pos);
    memcpy(g->buf + g->gap_start, s, n);
    g->gap_start += n;
}

void gb_delete(GapBuf *g, size_t pos, size_t n) {
    size_t len = gb_len(g);
    if (pos >= len) return;
    if (pos + n > len) n = len - pos;
    gb_move_gap(g, pos);
    g->gap_end += n;
}

char *gb_to_str(const GapBuf *g) {
    size_t len = gb_len(g);
    char *s = malloc(len + 1);
    if (g->gap_start > 0)
        memcpy(s, g->buf, g->gap_start);
    size_t post = g->cap - g->gap_end;
    if (post > 0)
        memcpy(s + g->gap_start, g->buf + g->gap_end, post);
    s[len] = '\0';
    return s;
}

void gb_get_range(const GapBuf *g, size_t start, size_t len, char *out) {
    for (size_t i = 0; i < len; i++)
        out[i] = gb_at(g, start + i);
}

/* ─── Clone a gap buffer (for undo snapshots) ─────────────────── */
GapBuf *gb_clone(const GapBuf *g) {
    GapBuf *n = malloc(sizeof *n);
    n->cap = g->cap;
    n->gap_start = g->gap_start;
    n->gap_end   = g->gap_end;
    n->buf = malloc(g->cap);
    memcpy(n->buf, g->buf, g->cap);
    return n;
}
