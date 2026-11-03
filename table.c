#include "abyss.h"
#include "utf8.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <strings.h>

extern char E_notify[256];

/* ─── Loading ──────────────────────────────────────────────────────
 * Parsers feed rows of arena strings into per-sheet builders; once the
 * whole source is read, tbl_finish packs each builder into a dense
 * row-major TblSheet and measures its columns. Builders are looked up by
 * name, so a SQL dump spreading one table over many INSERTs still lands
 * in one sheet. */

typedef struct {
    char     name[128];
    char   **hdr;
    int      nhdr;
    char  ***rows;
    int     *rlen;
    size_t   n, cap;
    bool     truncated;
} Build;

typedef struct {
    TableView *tv;
    Build      b[TABLE_MAX_SHEETS];
    int        nb;
} Loader;

typedef struct { char **v; int n, cap; } Row;

static void row_push(Row *r, char *s) {
    if (r->n >= r->cap) {
        r->cap = r->cap ? r->cap * 2 : 16;
        r->v   = realloc(r->v, (size_t)r->cap * sizeof *r->v);
    }
    r->v[r->n++] = s;
}

/* Growable scratch string, for fields that need unescaping. */
typedef struct { char *s; size_t n, cap; } Str;

static void str_putc(Str *b, char c) {
    if (b->n + 1 >= b->cap) {
        b->cap = b->cap ? b->cap * 2 : 64;
        b->s   = realloc(b->s, b->cap);
    }
    b->s[b->n++] = c;
}

static char *adup(Loader *L, const char *s, size_t n) {
    char *d = arena_alloc(L->tv->arena, n + 1);
    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

static char *adupz(Loader *L, const char *s) { return adup(L, s, strlen(s)); }

static Build *ld_sheet(Loader *L, const char *name) {
    for (int i = 0; i < L->nb; i++)
        if (strcmp(L->b[i].name, name) == 0) return &L->b[i];
    if (L->nb >= TABLE_MAX_SHEETS) return NULL;
    Build *b = &L->b[L->nb++];
    memset(b, 0, sizeof *b);
    snprintf(b->name, sizeof b->name, "%s", name);
    return b;
}

static char **acopy_vec(Loader *L, char **v, int n) {
    char **d = arena_alloc(L->tv->arena, (size_t)(n ? n : 1) * sizeof *d);
    if (n) memcpy(d, v, (size_t)n * sizeof *d);
    return d;
}

static void b_set_header(Loader *L, Build *b, char **h, int n) {
    if (!b) return;
    b->hdr  = acopy_vec(L, h, n);
    b->nhdr = n;
}

static void b_add_row(Loader *L, Build *b, char **v, int n) {
    if (!b) return;
    if (b->n >= TABLE_MAX_ROWS) { b->truncated = true; return; }
    if (b->n >= b->cap) {
        b->cap  = b->cap ? b->cap * 2 : 256;
        b->rows = realloc(b->rows, b->cap * sizeof *b->rows);
        b->rlen = realloc(b->rlen, b->cap * sizeof *b->rlen);
    }
    b->rows[b->n] = acopy_vec(L, v, n);
    b->rlen[b->n] = n;
    b->n++;
}

static void ld_free(Loader *L) {
    for (int i = 0; i < L->nb; i++) { free(L->b[i].rows); free(L->b[i].rlen); }
    L->nb = 0;
}

/* Display width of a cell as drawn: newlines become a one-column "↵". */
static int disp_width(const char *s) {
    int w = 0;
    size_t len = strlen(s);
    for (size_t i = 0; i < len; ) {
        uint32_t cp;
        int n = utf8_decode(s + i, len - i, &cp);
        i += (size_t)n;
        w += (cp < 32 || cp == 127) ? 1 : utf8_cp_width(cp);
    }
    return w;
}

static bool looks_numeric(const char *s) {
    while (*s == ' ') s++;
    if (!*s) return false;
    char *end;
    strtod(s, &end);
    if (end == s) return false;
    while (*end == ' ') end++;
    return *end == '\0';
}

static void tbl_clear(TableView *tv) {
    for (int i = 0; i < tv->nsheets; i++) {
        free(tv->sheets[i].cells);
        free(tv->sheets[i].colw);
        free(tv->sheets[i].numeric);
    }
    free(tv->sheets);
    tv->sheets  = NULL;
    tv->nsheets = 0;
    if (tv->arena) arena_free(tv->arena);
    tv->arena = arena_new(1 << 16);
    tv->err[0] = '\0';
}

static void tbl_finish(Loader *L) {
    TableView *tv = L->tv;
    tv->sheets  = calloc((size_t)(L->nb ? L->nb : 1), sizeof *tv->sheets);
    tv->nsheets = 0;

    for (int i = 0; i < L->nb; i++) {
        Build *b = &L->b[i];
        int ncols = b->nhdr;
        for (size_t r = 0; r < b->n; r++) if (b->rlen[r] > ncols) ncols = b->rlen[r];
        if (ncols == 0) continue;

        TblSheet *t = &tv->sheets[tv->nsheets++];
        snprintf(t->name, sizeof t->name, "%s", b->name);
        t->ncols     = ncols;
        t->nrows     = b->n;
        t->truncated = b->truncated;
        t->hdr       = arena_alloc(tv->arena, (size_t)ncols * sizeof *t->hdr);
        for (int c = 0; c < ncols; c++) {
            if (c < b->nhdr && b->hdr[c]) { t->hdr[c] = b->hdr[c]; continue; }
            char tmp[32];
            snprintf(tmp, sizeof tmp, "col%d", c + 1);
            t->hdr[c] = adupz(L, tmp);
        }
        t->cells = calloc(t->nrows * (size_t)ncols + 1, sizeof *t->cells);
        for (size_t r = 0; r < b->n; r++)
            memcpy(t->cells + r * (size_t)ncols, b->rows[r],
                   (size_t)b->rlen[r] * sizeof *t->cells);

        t->colw    = calloc((size_t)ncols, sizeof *t->colw);
        t->numeric = calloc((size_t)ncols, sizeof *t->numeric);
        for (int c = 0; c < ncols; c++) {
            int w = disp_width(t->hdr[c]);
            size_t nums = 0, filled = 0;
            for (size_t r = 0; r < t->nrows; r++) {
                const char *s = t->cells[r * (size_t)ncols + (size_t)c];
                if (!s) continue;
                if (w < TABLE_MAX_COLW) {
                    int cw = disp_width(s);
                    if (cw > w) w = cw;
                }
                if (r < 5000 && *s && strcmp(s, "NULL") != 0 && strcmp(s, "null") != 0) {
                    filled++;
                    if (looks_numeric(s)) nums++;
                }
            }
            if (w < 1) w = 1;
            if (w > TABLE_MAX_COLW) w = TABLE_MAX_COLW;
            t->colw[c]    = w;
            t->numeric[c] = filled > 0 && nums * 10 >= filled * 9;
        }
    }
    ld_free(L);
}

/* ─── CSV / TSV / PSV ───────────────────────────────────────────── */

/* Pick the separator that splits the first lines into the most columns,
 * consistently. Returns 0 when nothing looks delimited. */
static char csv_sniff(const char *s, size_t len, bool need_multi) {
    static const char cand[] = { ',', ';', '\t', '|' };
    char best = 0; int best_score = 0;
    for (size_t k = 0; k < sizeof cand; k++) {
        int mn = -1, mx = 0, lines = 0, cnt = 0;
        bool inq = false;
        for (size_t i = 0; i < len && lines < 20; i++) {
            char c = s[i];
            if (c == '"') inq = !inq;
            else if (!inq && c == cand[k]) cnt++;
            else if (!inq && c == '\n') {
                if (cnt || (i > 0 && s[i - 1] != '\n')) {
                    if (mn < 0 || cnt < mn) mn = cnt;
                    if (cnt > mx) mx = cnt;
                    lines++;
                }
                cnt = 0;
            }
        }
        if (cnt) { if (mn < 0 || cnt < mn) mn = cnt; if (cnt > mx) mx = cnt; lines++; }
        if (mn <= 0) continue;
        if (need_multi && (lines < 2 || mn != mx)) continue;
        int score = mn * 2 + (mn == mx);
        if (score > best_score) { best_score = score; best = cand[k]; }
    }
    return best;
}

static void parse_csv(Loader *L, const char *s, size_t len, char delim,
                      const char *name, bool header) {
    Build *b = ld_sheet(L, name);
    Row row = {0};
    Str f   = {0};
    size_t i = 0;
    bool have_hdr = !header;

    while (i < len) {
        row.n = 0;
        for (;;) {                                   /* one record */
            f.n = 0;
            if (i < len && s[i] == '"') {
                i++;
                while (i < len) {
                    if (s[i] == '"') {
                        if (i + 1 < len && s[i + 1] == '"') { str_putc(&f, '"'); i += 2; continue; }
                        i++;
                        break;
                    }
                    if (s[i] != '\r') str_putc(&f, s[i]);
                    i++;
                }
            }
            while (i < len && s[i] != delim && s[i] != '\n') {
                if (s[i] != '\r') str_putc(&f, s[i]);
                i++;
            }
            row_push(&row, adup(L, f.s ? f.s : "", f.n));
            if (i < len && s[i] == delim) { i++; continue; }
            if (i < len) i++;                        /* the newline */
            break;
        }
        if (row.n == 1 && !row.v[0][0]) continue;   /* blank line */
        if (!have_hdr) { b_set_header(L, b, row.v, row.n); have_hdr = true; }
        else           b_add_row(L, b, row.v, row.n);
    }
    free(row.v);
    free(f.s);
}

/* ─── JSON ──────────────────────────────────────────────────────── */

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } JType;

typedef struct JVal {
    JType         t;
    char         *s;       /* decoded string, or the literal's text */
    const char   *raw;     /* source span, for nested cells          */
    size_t        rawlen;
    struct JVal **kids;
    char        **keys;
    int           n;
} JVal;

typedef struct {
    Loader     *L;
    const char *s;
    size_t      i, len;
    int         depth;
    bool        err;
} JP;

static void jp_ws(JP *p) {
    while (p->i < p->len && isspace((unsigned char)p->s[p->i])) p->i++;
}

static JVal *jp_value(JP *p);

static char *jp_string(JP *p) {
    p->i++;                                          /* opening quote */
    size_t start = p->i;
    size_t end   = start;
    while (end < p->len && p->s[end] != '"') end += (p->s[end] == '\\') ? 2 : 1;
    if (end >= p->len) { p->err = true; p->i = p->len; return NULL; }

    char *out = arena_alloc(p->L->tv->arena, end - start + 1);
    size_t o = 0;
    for (size_t i = start; i < end; i++) {
        char c = p->s[i];
        if (c != '\\') { out[o++] = c; continue; }
        c = p->s[++i];
        switch (c) {
            case 'n': out[o++] = '\n'; break;
            case 't': out[o++] = '\t'; break;
            case 'r': out[o++] = '\r'; break;
            case 'b': out[o++] = '\b'; break;
            case 'f': out[o++] = '\f'; break;
            case 'u': {
                uint32_t cp = 0;
                if (i + 4 >= end) { p->err = true; p->i = i; return NULL; }
                for (int k = 1; k <= 4; k++) {
                    char h = p->s[i + k];
                    if (!isxdigit((unsigned char)h)) { p->err = true; p->i = i; return NULL; }
                    cp = cp * 16 + (uint32_t)(isdigit((unsigned char)h) ? h - '0'
                                             : (tolower((unsigned char)h) - 'a' + 10));
                }
                i += 4;
                if (cp >= 0xD800 && cp < 0xDC00 && i + 6 < end
                        && p->s[i + 1] == '\\' && p->s[i + 2] == 'u') {
                    uint32_t lo = (uint32_t)strtoul((char[5]){ p->s[i+3], p->s[i+4],
                                                               p->s[i+5], p->s[i+6], 0 }, NULL, 16);
                    if (lo >= 0xDC00 && lo < 0xE000) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        i += 6;
                    }
                }
                /* \uXXXX encodes to at most 3 bytes, a surrogate pair (12
                 * source bytes) to 4: the output never outgrows the input. */
                o += (size_t)utf8_encode(cp, out + o);
                break;
            }
            default: out[o++] = c; break;
        }
    }
    out[o] = '\0';
    p->i = end + 1;
    return out;
}

static JVal *jp_new(JP *p, JType t, size_t start) {
    JVal *v = arena_alloc(p->L->tv->arena, sizeof *v);
    memset(v, 0, sizeof *v);
    v->t   = t;
    v->raw = p->s + start;
    return v;
}

static JVal *jp_container(JP *p, bool obj) {
    size_t start = p->i++;
    if (++p->depth > 256) { p->err = true; return NULL; }
    JVal *v = jp_new(p, obj ? J_OBJ : J_ARR, start);
    char close = obj ? '}' : ']';
    JVal **kids = NULL; char **keys = NULL; int n = 0, cap = 0;

    jp_ws(p);
    if (p->i < p->len && p->s[p->i] == close) p->i++;
    else for (;;) {
        char *key = NULL;
        if (obj) {
            jp_ws(p);
            if (p->i >= p->len || p->s[p->i] != '"') { p->err = true; break; }
            key = jp_string(p);
            if (p->err) break;
            jp_ws(p);
            if (p->i >= p->len || p->s[p->i] != ':') { p->err = true; break; }
            p->i++;
        }
        JVal *kid = jp_value(p);
        if (p->err) break;
        if (n >= cap) {
            cap  = cap ? cap * 2 : 8;
            kids = realloc(kids, (size_t)cap * sizeof *kids);
            keys = realloc(keys, (size_t)cap * sizeof *keys);
        }
        kids[n] = kid; keys[n] = key; n++;
        jp_ws(p);
        if (p->i < p->len && p->s[p->i] == ',') { p->i++; continue; }
        if (p->i < p->len && p->s[p->i] == close) { p->i++; break; }
        p->err = true;
        break;
    }
    if (!p->err) {
        v->n    = n;
        v->kids = (JVal **)acopy_vec(p->L, (char **)kids, n);
        v->keys = obj ? acopy_vec(p->L, keys, n) : NULL;
    }
    free(kids); free(keys);
    p->depth--;
    v->rawlen = p->i - start;
    return v;
}

static JVal *jp_value(JP *p) {
    jp_ws(p);
    if (p->i >= p->len) { p->err = true; return NULL; }
    size_t start = p->i;
    char c = p->s[p->i];
    if (c == '{') return jp_container(p, true);
    if (c == '[') return jp_container(p, false);
    if (c == '"') {
        JVal *v = jp_new(p, J_STR, start);
        v->s = jp_string(p);
        v->rawlen = p->i - start;
        return v;
    }
    JType t;
    if (c == '-' || isdigit((unsigned char)c)) {
        t = J_NUM;
        while (p->i < p->len && strchr("+-0123456789.eE", p->s[p->i])) p->i++;
    } else if (!strncmp(p->s + p->i, "true", 4) || !strncmp(p->s + p->i, "false", 5)) {
        t = J_BOOL;
        p->i += (c == 't') ? 4 : 5;
    } else if (!strncmp(p->s + p->i, "null", 4)) {
        t = J_NULL;
        p->i += 4;
    } else { p->err = true; return NULL; }
    JVal *v = jp_new(p, t, start);
    v->rawlen = p->i - start;
    v->s = adup(p->L, v->raw, v->rawlen);
    return v;
}

/* Nested values are shown as compact JSON (whitespace dropped). */
static char *j_cell(Loader *L, const JVal *v) {
    if (v->t != J_ARR && v->t != J_OBJ) return v->s;
    size_t cap = v->rawlen < 1024 ? v->rawlen : 1024;
    char *out = arena_alloc(L->tv->arena, cap + 4);
    size_t o = 0; bool inq = false;
    for (size_t i = 0; i < v->rawlen && o < cap; i++) {
        char c = v->raw[i];
        if (inq) {
            out[o++] = c;
            if (c == '\\' && i + 1 < v->rawlen && o < cap) out[o++] = v->raw[++i];
            else if (c == '"') inq = false;
        } else if (!isspace((unsigned char)c)) {
            out[o++] = c;
            if (c == '"') inq = true;
        }
    }
    if (o >= cap && cap < v->rawlen) { memcpy(out + o, "…", 3); o += 3; }
    out[o] = '\0';
    return out;
}

static int hdr_index(char ***hdr, int *nh, int *cap, const char *key, int hint) {
    if (hint >= 0 && hint < *nh && strcmp((*hdr)[hint], key) == 0) return hint;
    for (int i = 0; i < *nh; i++) if (strcmp((*hdr)[i], key) == 0) return i;
    if (*nh >= 512) return -1;
    if (*nh >= *cap) {
        *cap = *cap ? *cap * 2 : 16;
        *hdr = realloc(*hdr, (size_t)*cap * sizeof **hdr);
    }
    (*hdr)[*nh] = (char *)key;
    return (*nh)++;
}

/* An array (or an object whose members are all objects, with `keycol`
 * naming the column for their keys) becomes one sheet. */
static void j_sheet_from(Loader *L, const char *name, const JVal *arr, const char *keycol) {
    Build *b = ld_sheet(L, name);
    if (!b) return;

    int nobj = 0, narr = 0;
    for (int i = 0; i < arr->n; i++) {
        if (arr->kids[i]->t == J_OBJ) nobj++;
        else if (arr->kids[i]->t == J_ARR) narr++;
    }

    Row row = {0};
    if (nobj > 0) {
        char **hdr = NULL; int nh = 0, hcap = 0;
        if (keycol) hdr_index(&hdr, &nh, &hcap, keycol, -1);
        int base = nh;
        for (int i = 0; i < arr->n; i++) {
            const JVal *o = arr->kids[i];
            if (o->t != J_OBJ) continue;
            for (int k = 0; k < o->n; k++) hdr_index(&hdr, &nh, &hcap, o->keys[k], base + k);
        }
        if (nh == 0) hdr_index(&hdr, &nh, &hcap, "value", -1);
        b_set_header(L, b, hdr, nh);

        char **cells = calloc((size_t)nh, sizeof *cells);
        for (int i = 0; i < arr->n; i++) {
            const JVal *o = arr->kids[i];
            memset(cells, 0, (size_t)nh * sizeof *cells);
            if (keycol) cells[0] = arr->keys[i];
            if (o->t == J_OBJ) {
                for (int k = 0; k < o->n; k++) {
                    int c = hdr_index(&hdr, &nh, &hcap, o->keys[k], base + k);
                    if (c >= 0) cells[c] = j_cell(L, o->kids[k]);
                }
            } else {
                cells[base < nh ? base : 0] = j_cell(L, o);
            }
            b_add_row(L, b, cells, nh);
        }
        free(cells);
        free(hdr);
    } else if (narr == arr->n && arr->n > 0) {
        /* [["name","age"],["bob",3]]: the first row is a header when it is
         * all strings and some later row is not. */
        const JVal *first = arr->kids[0];
        bool str_first = first->n > 0, later_mixed = false;
        for (int k = 0; k < first->n; k++) if (first->kids[k]->t != J_STR) str_first = false;
        for (int i = 1; i < arr->n && !later_mixed; i++)
            for (int k = 0; k < arr->kids[i]->n; k++)
                if (arr->kids[i]->kids[k]->t != J_STR) { later_mixed = true; break; }
        int start = (str_first && later_mixed) ? 1 : 0;
        for (int i = 0; i < arr->n; i++) {
            const JVal *a = arr->kids[i];
            row.n = 0;
            for (int k = 0; k < a->n; k++) row_push(&row, j_cell(L, a->kids[k]));
            if (i < start) b_set_header(L, b, row.v, row.n);
            else           b_add_row(L, b, row.v, row.n);
        }
    } else {
        char *h = keycol ? (char *)keycol : "value";
        if (keycol) {
            char *hh[2] = { h, "value" };
            b_set_header(L, b, hh, 2);
        } else {
            b_set_header(L, b, &h, 1);
        }
        for (int i = 0; i < arr->n; i++) {
            row.n = 0;
            if (keycol) row_push(&row, arr->keys[i]);
            row_push(&row, j_cell(L, arr->kids[i]));
            b_add_row(L, b, row.v, row.n);
        }
    }
    free(row.v);
}

static void j_tabularize(Loader *L, const JVal *v, const char *name, int depth) {
    if (v->t == J_ARR) { j_sheet_from(L, name, v, NULL); return; }
    if (v->t != J_OBJ) {
        Build *b = ld_sheet(L, name);
        char *h = "value", *c = j_cell(L, v);
        b_set_header(L, b, &h, 1);
        b_add_row(L, b, &c, 1);
        return;
    }

    bool all_obj = v->n > 0;
    for (int i = 0; i < v->n; i++) if (v->kids[i]->t != J_OBJ) all_obj = false;
    if (all_obj) {
        /* {"alice": {...}, "bob": {...}}: one row per member */
        bool nested = false;
        for (int i = 0; i < v->n && !nested; i++)
            for (int k = 0; k < v->kids[i]->n; k++)
                if (v->kids[i]->kids[k]->t == J_ARR) { nested = true; break; }
        if (!nested || depth > 0) { j_sheet_from(L, name, v, "key"); return; }
    }

    /* Mixed object: every array member gets its own sheet, sub-objects
     * are explored a couple of levels down, and what is left is shown
     * as a key | value sheet. */
    int before = L->nb;
    int scalars = 0;
    for (int i = 0; i < v->n; i++) {
        const JVal *k = v->kids[i];
        char sub[128];
        if (depth == 0) snprintf(sub, sizeof sub, "%s", v->keys[i]);
        else            snprintf(sub, sizeof sub, "%s.%s", name, v->keys[i]);
        if (k->t == J_ARR && k->n > 0)              j_tabularize(L, k, sub, depth + 1);
        else if (k->t == J_OBJ && depth < 2 && k->n) j_tabularize(L, k, sub, depth + 1);
        else scalars++;
    }
    if (scalars > 0 || L->nb == before) {
        Build *b = ld_sheet(L, depth == 0 ? "(root)" : name);
        char *h[2] = { "key", "value" };
        b_set_header(L, b, h, 2);
        for (int i = 0; i < v->n; i++) {
            const JVal *k = v->kids[i];
            bool own = (k->t == J_ARR && k->n > 0) || (k->t == J_OBJ && depth < 2 && k->n);
            if (own && L->nb != before) continue;
            char *r[2] = { v->keys[i], j_cell(L, k) };
            b_add_row(L, b, r, 2);
        }
    }
}

static void json_error(TableView *tv, const char *what, const char *s, size_t at) {
    size_t line = 1, col = 1;
    for (size_t i = 0; i < at; i++) { if (s[i] == '\n') { line++; col = 1; } else col++; }
    snprintf(tv->err, sizeof tv->err, "%s: parse error at line %zu, col %zu", what, line, col);
}

static bool parse_json(Loader *L, const char *s, size_t len, const char *name) {
    JP p = { .L = L, .s = s, .len = len };
    JVal *root = jp_value(&p);
    jp_ws(&p);
    if (p.err || !root || p.i < len) { json_error(L->tv, "JSON", s, p.i); return false; }
    j_tabularize(L, root, name, 0);
    return true;
}

static bool parse_jsonl(Loader *L, const char *s, size_t len, const char *name) {
    JVal arr = { .t = J_ARR };
    int cap = 0;
    size_t i = 0;
    while (i < len) {
        size_t e = i;
        while (e < len && s[e] != '\n') e++;
        JP p = { .L = L, .s = s, .i = i, .len = e };
        jp_ws(&p);
        if (p.i < e) {
            JVal *v = jp_value(&p);
            jp_ws(&p);
            if (p.err || p.i < e) {
                free(arr.kids);
                json_error(L->tv, "JSON Lines", s, p.i);
                return false;
            }
            if (arr.n >= cap) {
                cap = cap ? cap * 2 : 256;
                arr.kids = realloc(arr.kids, (size_t)cap * sizeof *arr.kids);
            }
            arr.kids[arr.n++] = v;
        }
        i = e + 1;
    }
    if (arr.n > 0) j_sheet_from(L, name, &arr, NULL);
    free(arr.kids);
    return arr.n > 0;
}

/* ─── SQL dumps ────────────────────────────────────────────────────
 * Not a SQL parser: a tokenizer plus just enough grammar to lift
 * CREATE TABLE column lists, INSERT ... VALUES tuples and pg_dump's
 * COPY ... FROM stdin blocks into sheets. */

typedef enum { T_EOF, T_WORD, T_QIDENT, T_STR, T_NUM, T_PUNCT } TokT;

typedef struct {
    TokT        t;
    const char *p;      /* source span */
    size_t      len;
    char        c;      /* T_PUNCT */
} Tok;

typedef struct {
    Loader     *L;
    const char *s;
    size_t      i, len;
    Tok         tok;
} SqlLex;

static void sql_next(SqlLex *x) {
    const char *s = x->s;
    for (;;) {
        while (x->i < x->len && isspace((unsigned char)s[x->i])) x->i++;
        if (x->i + 1 < x->len && s[x->i] == '-' && s[x->i + 1] == '-') {
            while (x->i < x->len && s[x->i] != '\n') x->i++;
            continue;
        }
        if (x->i < x->len && s[x->i] == '#') {
            while (x->i < x->len && s[x->i] != '\n') x->i++;
            continue;
        }
        if (x->i + 1 < x->len && s[x->i] == '/' && s[x->i + 1] == '*') {
            x->i += 2;
            while (x->i + 1 < x->len && !(s[x->i] == '*' && s[x->i + 1] == '/')) x->i++;
            x->i += 2;
            continue;
        }
        break;
    }
    Tok *t = &x->tok;
    t->p = s + x->i; t->len = 0;
    if (x->i >= x->len) { t->t = T_EOF; return; }

    char c = s[x->i];
    size_t st = x->i;
    if (c == '\'' || c == '"' || c == '`' || c == '[') {
        char close = (c == '[') ? ']' : c;
        x->i++;
        while (x->i < x->len) {
            if (s[x->i] == '\\' && c == '\'') { x->i += 2; continue; }
            if (s[x->i] == close) {
                if (close != ']' && x->i + 1 < x->len && s[x->i + 1] == close) { x->i += 2; continue; }
                x->i++;
                break;
            }
            x->i++;
        }
        if (x->i > x->len) x->i = x->len;
        t->t = (c == '\'') ? T_STR : T_QIDENT;
    } else if (isdigit((unsigned char)c) ||
               (c == '.' && x->i + 1 < x->len && isdigit((unsigned char)s[x->i + 1]))) {
        while (x->i < x->len && (isalnum((unsigned char)s[x->i]) || s[x->i] == '.' ||
               ((s[x->i] == '-' || s[x->i] == '+') && tolower((unsigned char)s[x->i - 1]) == 'e')))
            x->i++;
        t->t = T_NUM;
    } else if (isalpha((unsigned char)c) || c == '_' || (unsigned char)c >= 0x80) {
        while (x->i < x->len && (isalnum((unsigned char)s[x->i]) || s[x->i] == '_' ||
                                 s[x->i] == '$' || (unsigned char)s[x->i] >= 0x80))
            x->i++;
        t->t = T_WORD;
    } else {
        x->i++;
        t->t = T_PUNCT;
        t->c = c;
    }
    t->len = x->i - st;
}

static bool tok_kw(const Tok *t, const char *kw) {
    return t->t == T_WORD && strlen(kw) == t->len && strncasecmp(t->p, kw, t->len) == 0;
}

static bool tok_is(const Tok *t, char c) { return t->t == T_PUNCT && t->c == c; }

/* Unquote a string literal or quoted identifier into the arena. */
static char *tok_text(SqlLex *x, const Tok *t) {
    if (t->t != T_STR && t->t != T_QIDENT) return adup(x->L, t->p, t->len);
    char q = t->p[0], close = (q == '[') ? ']' : q;
    size_t n = t->len >= 2 ? t->len - 2 : 0;
    char *out = arena_alloc(x->L->tv->arena, n + 1);
    size_t o = 0;
    for (size_t i = 1; i <= n; i++) {
        char c = t->p[i];
        if (c == close && i + 1 <= n && t->p[i + 1] == close) { out[o++] = c; i++; continue; }
        if (c == '\\' && q == '\'' && i + 1 <= n) {
            c = t->p[++i];
            switch (c) {
                case 'n': out[o++] = '\n'; break;
                case 't': out[o++] = '\t'; break;
                case 'r': out[o++] = '\r'; break;
                case '0': out[o++] = '0';  break;
                default:  out[o++] = c;    break;
            }
            continue;
        }
        out[o++] = c;
    }
    out[o] = '\0';
    return out;
}

/* Table name, possibly schema-qualified: keeps the last part. */
static bool sql_name(SqlLex *x, char *out, size_t out_sz) {
    if (x->tok.t != T_WORD && x->tok.t != T_QIDENT) return false;
    for (;;) {
        char *n = tok_text(x, &x->tok);
        snprintf(out, out_sz, "%s", n);
        sql_next(x);
        if (!tok_is(&x->tok, '.')) return true;
        sql_next(x);
        if (x->tok.t != T_WORD && x->tok.t != T_QIDENT) return true;
    }
}

static void sql_skip_stmt(SqlLex *x) {
    int depth = 0;
    while (x->tok.t != T_EOF) {
        if (tok_is(&x->tok, '(')) depth++;
        else if (tok_is(&x->tok, ')')) depth--;
        else if (tok_is(&x->tok, ';') && depth <= 0) { sql_next(x); return; }
        sql_next(x);
    }
}

/* Parenthesised, comma-separated list. Single-token items are unquoted;
 * anything longer (function calls, casts, negative numbers) keeps its
 * source text. */
static bool sql_list(SqlLex *x, Row *row, bool names_only) {
    if (!tok_is(&x->tok, '(')) return false;
    sql_next(x);
    row->n = 0;
    while (x->tok.t != T_EOF) {
        Tok first = x->tok;
        const char *end = first.p;
        int ntok = 0, depth = 0;
        while (x->tok.t != T_EOF) {
            if (depth == 0 && (tok_is(&x->tok, ',') || tok_is(&x->tok, ')'))) break;
            if (tok_is(&x->tok, '(')) depth++;
            if (tok_is(&x->tok, ')')) depth--;
            end = x->tok.p + x->tok.len;
            ntok++;
            sql_next(x);
        }
        char *v;
        if (ntok == 0)                          v = adupz(x->L, "");
        else if (ntok == 1 || names_only)       v = tok_text(x, &first);
        else                                    v = adup(x->L, first.p, (size_t)(end - first.p));
        row_push(row, v);
        if (tok_is(&x->tok, ',')) { sql_next(x); continue; }
        if (tok_is(&x->tok, ')')) { sql_next(x); return true; }
    }
    return false;
}

static void sql_create(SqlLex *x) {
    sql_next(x);
    while (tok_kw(&x->tok, "TEMP") || tok_kw(&x->tok, "TEMPORARY") ||
           tok_kw(&x->tok, "UNLOGGED") || tok_kw(&x->tok, "GLOBAL") || tok_kw(&x->tok, "LOCAL"))
        sql_next(x);
    if (!tok_kw(&x->tok, "TABLE")) { sql_skip_stmt(x); return; }
    sql_next(x);
    if (tok_kw(&x->tok, "IF")) { sql_next(x); sql_next(x); sql_next(x); }   /* IF NOT EXISTS */
    char name[128];
    if (!sql_name(x, name, sizeof name) || !tok_is(&x->tok, '(')) { sql_skip_stmt(x); return; }

    static const char *constraint_kw[] = {
        "PRIMARY","UNIQUE","FOREIGN","CONSTRAINT","CHECK","KEY","INDEX",
        "FULLTEXT","SPATIAL","EXCLUDE","PERIOD",NULL
    };
    Row cols = {0};
    sql_next(x);
    while (x->tok.t != T_EOF) {
        bool skip = false;
        for (int k = 0; constraint_kw[k]; k++) if (tok_kw(&x->tok, constraint_kw[k])) skip = true;
        if (!skip && (x->tok.t == T_WORD || x->tok.t == T_QIDENT))
            row_push(&cols, tok_text(x, &x->tok));
        int depth = 0;
        while (x->tok.t != T_EOF) {
            if (depth == 0 && (tok_is(&x->tok, ',') || tok_is(&x->tok, ')'))) break;
            if (tok_is(&x->tok, '(')) depth++;
            if (tok_is(&x->tok, ')')) depth--;
            sql_next(x);
        }
        if (tok_is(&x->tok, ',')) { sql_next(x); continue; }
        break;
    }
    Build *b = ld_sheet(x->L, name);
    if (b && cols.n) b_set_header(x->L, b, cols.v, cols.n);
    free(cols.v);
    sql_skip_stmt(x);
}

static int name_index(const Build *b, const char *col) {
    for (int i = 0; i < b->nhdr; i++) if (strcasecmp(b->hdr[i], col) == 0) return i;
    return -1;
}

static void sql_insert(SqlLex *x) {
    sql_next(x);
    while (tok_kw(&x->tok, "OR") || tok_kw(&x->tok, "REPLACE") || tok_kw(&x->tok, "IGNORE") ||
           tok_kw(&x->tok, "ROLLBACK") || tok_kw(&x->tok, "ABORT") || tok_kw(&x->tok, "FAIL") ||
           tok_kw(&x->tok, "LOW_PRIORITY") || tok_kw(&x->tok, "DELAYED") ||
           tok_kw(&x->tok, "HIGH_PRIORITY"))
        sql_next(x);
    if (tok_kw(&x->tok, "INTO")) sql_next(x);
    char name[128];
    if (!sql_name(x, name, sizeof name)) { sql_skip_stmt(x); return; }
    Build *b = ld_sheet(x->L, name);

    Row cols = {0}, vals = {0};
    int *map = NULL;
    if (tok_is(&x->tok, '(')) {
        sql_list(x, &cols, true);
        if (b && b->nhdr == 0) b_set_header(x->L, b, cols.v, cols.n);
        else if (b) {
            map = malloc((size_t)cols.n * sizeof *map);
            for (int i = 0; i < cols.n; i++) {
                map[i] = name_index(b, cols.v[i]);
                if (map[i] < 0) { free(map); map = NULL; break; }
            }
        }
    }
    if (!tok_kw(&x->tok, "VALUES") && !tok_kw(&x->tok, "VALUE")) {
        free(cols.v); free(map); sql_skip_stmt(x); return;
    }
    sql_next(x);
    char **mapped = NULL;
    while (sql_list(x, &vals, false)) {
        if (map && b) {
            mapped = realloc(mapped, (size_t)b->nhdr * sizeof *mapped);
            memset(mapped, 0, (size_t)b->nhdr * sizeof *mapped);
            for (int i = 0; i < vals.n && i < cols.n; i++) mapped[map[i]] = vals.v[i];
            b_add_row(x->L, b, mapped, b->nhdr);
        } else {
            b_add_row(x->L, b, vals.v, vals.n);
        }
        if (!tok_is(&x->tok, ',')) break;
        sql_next(x);
    }
    free(mapped); free(map); free(cols.v); free(vals.v);
    sql_skip_stmt(x);
}

/* pg_dump: COPY t (a, b) FROM stdin;  then tab-separated lines up to "\." */
static void sql_copy(SqlLex *x) {
    sql_next(x);
    char name[128];
    if (!sql_name(x, name, sizeof name)) { sql_skip_stmt(x); return; }
    Build *b = ld_sheet(x->L, name);
    Row cols = {0};
    if (tok_is(&x->tok, '(')) {
        sql_list(x, &cols, true);
        if (b && b->nhdr == 0) b_set_header(x->L, b, cols.v, cols.n);
    }
    free(cols.v);
    bool stdin_src = false;
    while (x->tok.t != T_EOF && !tok_is(&x->tok, ';')) {
        if (tok_kw(&x->tok, "STDIN")) stdin_src = true;
        sql_next(x);
    }
    if (!stdin_src || x->tok.t == T_EOF) { sql_next(x); return; }

    /* raw data starts on the line after the ';' */
    size_t i = x->i;
    while (i < x->len && x->s[i] != '\n') i++;
    i++;
    Row row = {0};
    Str f = {0};
    while (i < x->len) {
        size_t e = i;
        while (e < x->len && x->s[e] != '\n') e++;
        if (e - i == 2 && x->s[i] == '\\' && x->s[i + 1] == '.') { i = e + 1; break; }
        row.n = 0;
        size_t j = i;
        for (;;) {
            f.n = 0;
            while (j < e && x->s[j] != '\t') {
                char c = x->s[j++];
                if (c == '\\' && j < e) {
                    c = x->s[j++];
                    if (c == 'N') {
                        f.n = 0;
                        for (const char *k = "NULL"; *k; k++) str_putc(&f, *k);
                        continue;
                    }
                    c = (c == 'n') ? '\n' : (c == 't') ? '\t' : (c == 'r') ? '\r' : c;
                }
                str_putc(&f, c);
            }
            row_push(&row, adup(x->L, f.s ? f.s : "", f.n));
            if (j < e) { j++; continue; }
            break;
        }
        b_add_row(x->L, b, row.v, row.n);
        i = e + 1;
    }
    free(row.v); free(f.s);
    x->i = i;
    sql_next(x);
}

static bool parse_sql(Loader *L, const char *s, size_t len) {
    SqlLex x = { .L = L, .s = s, .len = len };
    sql_next(&x);
    while (x.tok.t != T_EOF) {
        if      (tok_kw(&x.tok, "CREATE"))  sql_create(&x);
        else if (tok_kw(&x.tok, "INSERT") || tok_kw(&x.tok, "REPLACE")) sql_insert(&x);
        else if (tok_kw(&x.tok, "COPY"))    sql_copy(&x);
        else                                sql_skip_stmt(&x);
    }
    return L->nb > 0;
}

/* ─── Markdown / psql / ASCII-art tables ───────────────────────── */

static bool is_sep_line(const char *s, size_t n) {
    bool dash = false;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '-' || s[i] == '=') dash = true;
        else if (!strchr("|+: \t\r", s[i])) return false;
    }
    return dash;
}

static bool has_pipe(const char *s, size_t n) { return memchr(s, '|', n) != NULL; }

static void split_pipes(Loader *L, const char *s, size_t n, Row *row) {
    row->n = 0;
    while (n && isspace((unsigned char)s[n - 1])) n--;
    while (n && isspace((unsigned char)*s)) { s++; n--; }
    if (n && *s == '|') { s++; n--; }
    if (n && s[n - 1] == '|' && !(n >= 2 && s[n - 2] == '\\')) n--;
    Str f = {0};
    for (size_t i = 0; i <= n; i++) {
        if (i == n || s[i] == '|') {
            size_t a = 0, z = f.n;
            while (a < z && isspace((unsigned char)f.s[a])) a++;
            while (z > a && isspace((unsigned char)f.s[z - 1])) z--;
            row_push(row, adup(L, f.s ? f.s + a : "", z - a));
            f.n = 0;
            continue;
        }
        if (s[i] == '\\' && i + 1 < n && s[i + 1] == '|') { str_putc(&f, '|'); i++; continue; }
        str_putc(&f, s[i]);
    }
    free(f.s);
}

static bool parse_markdown(Loader *L, const char *s, size_t len) {
    Row row = {0};
    int ntab = 0;
    Build *b = NULL;
    bool have_hdr = false;
    size_t i = 0;
    while (i < len) {
        size_t e = i;
        while (e < len && s[e] != '\n') e++;
        const char *ln = s + i;
        size_t n = e - i;
        size_t a = 0;
        while (a < n && (ln[a] == ' ' || ln[a] == '\t')) a++;

        /* next line, for "a | b" headers underlined by "---|---" */
        size_t ne = e + 1 < len ? e + 1 : len, nn = ne;
        while (nn < len && s[nn] != '\n') nn++;
        bool next_sep = ne < len && is_sep_line(s + ne, nn - ne);

        bool starts = a < n && (ln[a] == '|' || (ln[a] == '+' && is_sep_line(ln, n)));
        bool tline  = starts || (b && (has_pipe(ln, n) || is_sep_line(ln, n)))
                   || (!b && has_pipe(ln, n) && next_sep);

        if (!tline) { b = NULL; i = e + 1; continue; }
        if (is_sep_line(ln, n)) { i = e + 1; continue; }
        if (!b) {
            char name[32];
            snprintf(name, sizeof name, "table %d", ++ntab);
            b = ld_sheet(L, name);
            have_hdr = false;
            if (!b) break;
        }
        split_pipes(L, ln, n, &row);
        if (!have_hdr) { b_set_header(L, b, row.v, row.n); have_hdr = true; }
        else           b_add_row(L, b, row.v, row.n);
        i = e + 1;
    }
    free(row.v);
    int k = 0;
    for (int j = 0; j < L->nb; j++) {
        if (L->b[j].n == 0) { free(L->b[j].rows); free(L->b[j].rlen); continue; }
        L->b[k++] = L->b[j];
    }
    L->nb = k;
    return L->nb > 0;
}

/* ─── SQLite (through the sqlite3 CLI) ─────────────────────────── */

bool tbl_is_sqlite(const unsigned char *data, size_t len) {
    return data && len >= 16 && memcmp(data, "SQLite format 3", 16) == 0;
}

/* fork/exec rather than popen: the path never goes through a shell. */
static int run_capture(char *const argv[], char **out, size_t *out_len) {
    int fd[2];
    if (pipe(fd) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(fd[0]); close(fd[1]); return -1; }
    if (pid == 0) {
        dup2(fd[1], STDOUT_FILENO);
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) { dup2(dn, STDERR_FILENO); dup2(dn, STDIN_FILENO); }
        close(fd[0]); close(fd[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fd[1]);
    size_t cap = 1 << 16, n = 0;
    char *buf = malloc(cap);
    for (;;) {
        if (n + 4096 > cap) {
            if (cap >= (256u << 20)) break;
            cap *= 2;
            buf = realloc(buf, cap);
        }
        ssize_t r = read(fd[0], buf + n, cap - n - 1);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        n += (size_t)r;
    }
    close(fd[0]);
    if (n + 4096 > cap && cap >= (256u << 20)) kill(pid, SIGTERM);
    buf[n] = '\0';
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    *out = buf; *out_len = n;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void sql_quote(char *out, size_t sz, const char *name, char q) {
    size_t o = 0;
    if (o + 1 < sz) out[o++] = q;
    for (const char *p = name; *p && o + 3 < sz; p++) {
        if (*p == q) out[o++] = q;
        out[o++] = *p;
    }
    if (o + 1 < sz) out[o++] = q;
    out[o] = '\0';
}

bool tbl_load_sqlite(TableView *tv, const char *path) {
    tbl_clear(tv);
    tv->fmt = "SQLite";
    Loader L = { .tv = tv };

    char *list; size_t llen;
    char *argv[] = { "sqlite3", "-readonly", "-batch", "-noheader", "-list", (char *)path,
        "SELECT name FROM sqlite_master WHERE type IN ('table','view') "
        "AND name NOT LIKE 'sqlite_%' ORDER BY type, name;", NULL };
    int rc = run_capture(argv, &list, &llen);
    if (rc == 127) {
        free(list);
        snprintf(tv->err, sizeof tv->err, "sqlite3 not found: install it to browse databases");
        return false;
    }
    if (rc != 0) {
        free(list);
        snprintf(tv->err, sizeof tv->err, "sqlite3 could not read this database");
        return false;
    }

    char limit[32];
    snprintf(limit, sizeof limit, "%d", TABLE_MAX_ROWS + 1);
    Row names = {0};
    for (char *ln = list, *nl; ln < list + llen; ln = nl + 1) {
        nl = strchr(ln, '\n');
        if (!nl) nl = list + llen;
        *nl = '\0';
        if (*ln) row_push(&names, ln);
    }
    for (int ti = 0; ti < names.n; ti++) {
        char *ln = names.v[ti];
        char qn[512], query[700];
        sql_quote(qn, sizeof qn, ln, '"');
        snprintf(query, sizeof query, "SELECT * FROM %s LIMIT %s;", qn, limit);
        char *qa[] = { "sqlite3", "-readonly", "-batch", "-csv", "-header",
                       (char *)path, query, NULL };
        char *csv; size_t clen;
        run_capture(qa, &csv, &clen);
        parse_csv(&L, csv, clen, ',', ln, true);
        free(csv);

        Build *b = ld_sheet(&L, ln);
        if (b && b->nhdr == 0) {                 /* empty table: no CSV header */
            char lit[512];
            sql_quote(lit, sizeof lit, ln, '\'');
            snprintf(query, sizeof query, "SELECT name FROM pragma_table_info(%s);", lit);
            char *pa[] = { "sqlite3", "-readonly", "-batch", "-noheader", "-list",
                           (char *)path, query, NULL };
            char *cols; size_t cl;
            run_capture(pa, &cols, &cl);
            Row r = {0};
            for (char *c = strtok(cols, "\n"); c; c = strtok(NULL, "\n"))
                row_push(&r, adupz(&L, c));
            b_set_header(&L, b, r.v, r.n);
            free(r.v); free(cols);
        }
    }
    free(names.v);
    free(list);
    tbl_finish(&L);
    if (tv->nsheets == 0) {
        snprintf(tv->err, sizeof tv->err, "No tables in this database");
        return false;
    }
    return true;
}

/* ─── Format detection ─────────────────────────────────────────── */

static const char *path_ext(const char *path) {
    if (!path) return "";
    const char *slash = strrchr(path, '/');
    const char *dot   = strrchr(slash ? slash : path, '.');
    return dot ? dot : "";
}

static const char *path_base(const char *path) {
    if (!path || !*path) return "data";
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* Extensions whose whole point is tabular data: they open in the table
 * view directly (F6 goes back to the text). */
bool tbl_auto_ext(const char *path) {
    static const char *ext[] = { ".csv", ".tsv", ".tab", ".psv", ".jsonl", ".ndjson",
                                 ".db", ".sqlite", ".sqlite3", ".db3", NULL };
    const char *e = path_ext(path);
    for (int i = 0; ext[i]; i++) if (strcasecmp(e, ext[i]) == 0) return true;
    return false;
}

static bool contains_ci(const char *s, size_t len, const char *needle) {
    size_t n = strlen(needle);
    size_t lim = len < (1u << 20) ? len : (1u << 20);
    for (size_t i = 0; i + n <= lim; i++)
        if (strncasecmp(s + i, needle, n) == 0) return true;
    return false;
}

bool tbl_load_text(TableView *tv, const char *path, const char *s, size_t len, Language lang) {
    tbl_clear(tv);
    Loader L = { .tv = tv };
    if (len >= 3 && memcmp(s, "\xEF\xBB\xBF", 3) == 0) { s += 3; len -= 3; }

    const char *e    = path_ext(path);
    const char *name = path_base(path);
    bool ok = false;

    if (!strcasecmp(e, ".csv")) {
        char d = csv_sniff(s, len, false);
        tv->fmt = "CSV";
        parse_csv(&L, s, len, d ? d : ',', name, true);
        ok = true;
    } else if (!strcasecmp(e, ".tsv") || !strcasecmp(e, ".tab")) {
        tv->fmt = "TSV";
        parse_csv(&L, s, len, '\t', name, true);
        ok = true;
    } else if (!strcasecmp(e, ".psv")) {
        tv->fmt = "PSV";
        parse_csv(&L, s, len, '|', name, true);
        ok = true;
    } else if (!strcasecmp(e, ".jsonl") || !strcasecmp(e, ".ndjson")) {
        tv->fmt = "JSONL";
        ok = parse_jsonl(&L, s, len, name);
    } else if (lang == LANG_JSON || !strcasecmp(e, ".json")) {
        tv->fmt = "JSON";
        ok = parse_json(&L, s, len, name);
        if (!ok) {                         /* .json files are often JSON Lines */
            char saved[sizeof tv->err];
            memcpy(saved, tv->err, sizeof saved);
            ld_free(&L);
            tv->fmt = "JSONL";
            ok = parse_jsonl(&L, s, len, name);
            if (!ok) { memcpy(tv->err, saved, sizeof saved); tv->fmt = "JSON"; }
        }
    } else if (lang == LANG_SQL || !strcasecmp(e, ".sql")) {
        tv->fmt = "SQL";
        ok = parse_sql(&L, s, len);
        if (!ok) snprintf(tv->err, sizeof tv->err,
                          "No CREATE TABLE / INSERT / COPY statement found");
    } else if (!strcasecmp(e, ".md") || !strcasecmp(e, ".markdown")) {
        tv->fmt = "Markdown";
        ok = parse_markdown(&L, s, len);
        if (!ok) snprintf(tv->err, sizeof tv->err, "No table found in this document");
    } else {
        /* unknown extension: sniff the content */
        size_t k = 0;
        while (k < len && isspace((unsigned char)s[k])) k++;
        if (k < len && (s[k] == '[' || s[k] == '{')) {
            tv->fmt = "JSON";
            ok = parse_json(&L, s, len, name);
            if (!ok) { ld_free(&L); tv->fmt = "JSONL"; ok = parse_jsonl(&L, s, len, name); }
            if (!ok) ld_free(&L);
        }
        if (!ok && (contains_ci(s, len, "INSERT INTO") || contains_ci(s, len, "CREATE TABLE"))) {
            tv->fmt = "SQL";
            ok = parse_sql(&L, s, len);
            if (!ok) ld_free(&L);
        }
        if (!ok) { tv->fmt = "Table"; ok = parse_markdown(&L, s, len); if (!ok) ld_free(&L); }
        if (!ok) {
            char d = csv_sniff(s, len, true);
            if (d) {
                tv->fmt = d == '\t' ? "TSV" : d == '|' ? "PSV" : "CSV";
                parse_csv(&L, s, len, d, name, true);
                ok = true;
            }
        }
        if (!ok) snprintf(tv->err, sizeof tv->err, "No tabular structure found");
    }

    if (!ok) { ld_free(&L); return false; }
    tbl_finish(&L);
    if (tv->nsheets == 0) {
        snprintf(tv->err, sizeof tv->err, "%s: no rows to show", tv->fmt);
        return false;
    }
    return true;
}

TableView *tbl_new(void) {
    TableView *tv = calloc(1, sizeof *tv);
    tv->fmt = "Table";
    return tv;
}

void tbl_free(TableView *tv) {
    if (!tv) return;
    tbl_clear(tv);
    arena_free(tv->arena);
    free(tv);
}

/* ─── Pane glue ────────────────────────────────────────────────── */

/* Builds the table from what the pane currently holds (unsaved edits
 * included) and switches the pane to it, keeping the previous position
 * when the same data is shown again. */
bool pane_table_enter(Pane *p) {
    if (!p->table) p->table = tbl_new();
    TableView *tv = p->table;
    int    cur = tv->cur, col = tv->col;
    size_t row = tv->row;
    bool ok;

    if (p->hex_mode && p->hex) {
        if (tbl_is_sqlite(p->hex->data, p->hex->data_len))
            ok = tbl_load_sqlite(tv, p->hex->filename);
        else
            ok = tbl_load_text(tv, p->hex->filename, (const char *)p->hex->data,
                               p->hex->data_len, LANG_NONE);
    } else {
        unsigned char magic[16];
        size_t blen = gb_len(p->buf);
        for (size_t i = 0; i < 16 && i < blen; i++) magic[i] = (unsigned char)gb_at(p->buf, i);
        if (p->filename[0] && !p->modified && tbl_is_sqlite(magic, blen)) {
            ok = tbl_load_sqlite(tv, p->filename);
        } else {
            char *s = gb_to_str(p->buf);
            ok = tbl_load_text(tv, p->filename, s, blen, p->lang);
            free(s);
        }
    }
    if (!ok) {
        snprintf(E_notify, sizeof E_notify, "Table view: %s", tv->err);
        return false;
    }
    if (cur < tv->nsheets) {
        tv->cur = cur;
        const TblSheet *t = &tv->sheets[cur];
        tv->row = t->nrows ? (row < t->nrows ? row : t->nrows - 1) : 0;
        tv->col = col < t->ncols ? col : t->ncols - 1;
    } else {
        tv->cur = 0; tv->row = 0; tv->col = 0;
    }
    tv->scroll_row = 0; tv->scroll_col = 0;
    p->table_mode = true;
    return true;
}

/* ─── Rendering ────────────────────────────────────────────────── */

const char *tbl_cell(const TableView *tv, size_t row, int col) {
    if (!tv || tv->cur >= tv->nsheets) return NULL;
    const TblSheet *t = &tv->sheets[tv->cur];
    if (row >= t->nrows || col < 0 || col >= t->ncols) return NULL;
    return t->cells[row * (size_t)t->ncols + (size_t)col];
}

static void put_ch(WINDOW *w, int y, int x, chtype c) {
    if (x >= 0 && x < getmaxx(w)) mvwaddch(w, y, x, c);
}

/* Draws `s` into exactly `width` columns (clipped at the window edge),
 * with an ellipsis when it does not fit. */
static void draw_text(WINDOW *win, int y, int x, const char *s, int width, bool right) {
    int maxx = getmaxx(win);
    if (width > maxx - x) width = maxx - x;
    if (width <= 0) return;
    int dw = disp_width(s);
    bool cut = dw > width;
    int avail = cut ? width - 1 : width;
    int pad   = (!cut && right) ? width - dw : 0;

    wmove(win, y, x);
    for (int i = 0; i < pad; i++) waddch(win, ' ');
    int used = 0;
    size_t len = strlen(s);
    for (size_t i = 0; i < len; ) {
        uint32_t cp;
        int n = utf8_decode(s + i, len - i, &cp);
        int cw = (cp < 32 || cp == 127) ? 1 : utf8_cp_width(cp);
        if (used + cw > avail) break;
        if (cp == '\n')                  waddstr(win, "↵");
        else if (cp < 32 || cp == 127)   waddch(win, cp == '\t' ? ' ' : '.');
        else                             waddnstr(win, s + i, n);
        used += cw;
        i += (size_t)n;
    }
    if (cut) { waddstr(win, "…"); used++; }
    for (int i = pad + used; i < width; i++) waddch(win, ' ');
}

static int cell_pair(const char *s, bool numeric_col) {
    if (!s) return COLOR_PAIR_COMMENT;
    if (!strcmp(s, "NULL") || !strcmp(s, "null")) return COLOR_PAIR_COMMENT;
    if (!strcasecmp(s, "true") || !strcasecmp(s, "false")) return COLOR_PAIR_KEYWORD;
    if (numeric_col && looks_numeric(s)) return COLOR_PAIR_NUMBER;
    if (s[0] == '{' || s[0] == '[') return COLOR_PAIR_TYPE;
    return COLOR_PAIR_NORMAL;
}

static int data_rows(int win_h) {
    int r = win_h - 5;          /* tab bar, top border, header, separator, bottom */
    return r < 1 ? 1 : r;
}

static int gutter_w(const TblSheet *t) {
    int g = 1;
    for (size_t n = t->nrows; n >= 10; n /= 10) g++;
    return g + 1;
}

/* Keeps the current column on screen, scrolling whole columns. */
static void fit_cols(TableView *tv, const TblSheet *t, int win_w) {
    if (tv->col < tv->scroll_col) tv->scroll_col = tv->col;
    int avail = win_w - gutter_w(t) - 1;
    while (tv->scroll_col < tv->col) {
        int x = 0;
        for (int c = tv->scroll_col; c <= tv->col; c++) x += t->colw[c] + 3;
        if (x <= avail) break;
        tv->scroll_col++;
    }
}

void tbl_render(TableView *tv, WINDOW *win, int win_h, int win_w) {
    if (!win || win_h < 1 || win_w < 4) return;
    werase(win);

    /* tab bar: format, then one tab per sheet */
    wattron(win, COLOR_PAIR(HEX_CP_HEADER));
    mvwhline(win, 0, 0, ' ', win_w);
    char tab[192];
    int x = 0;
    snprintf(tab, sizeof tab, " %s ", tv->fmt ? tv->fmt : "Table");
    wattron(win, A_BOLD);
    mvwaddnstr(win, 0, x, tab, win_w - x);
    wattroff(win, A_BOLD);
    x += disp_width(tab);
    for (int i = 0; i < tv->nsheets && x < win_w; i++) {
        const TblSheet *s = &tv->sheets[i];
        snprintf(tab, sizeof tab, " %s (%zu%s) ", s->name, s->nrows, s->truncated ? "+" : "");
        if (i == tv->cur) wattron(win, A_REVERSE | A_BOLD);
        draw_text(win, 0, x, tab, disp_width(tab), false);
        if (i == tv->cur) wattroff(win, A_REVERSE | A_BOLD);
        x += disp_width(tab);
    }
    wattroff(win, COLOR_PAIR(HEX_CP_HEADER));

    if (tv->nsheets == 0) {
        wattron(win, COLOR_PAIR(COLOR_PAIR_COMMENT));
        mvwaddnstr(win, win_h / 2, 2, tv->err[0] ? tv->err : "No data", win_w - 4);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_COMMENT));
        wnoutrefresh(win);
        return;
    }

    const TblSheet *t = &tv->sheets[tv->cur];
    int nr = data_rows(win_h);
    if (t->nrows) {
        if (tv->row >= t->nrows) tv->row = t->nrows - 1;
        if (tv->row < tv->scroll_row) tv->scroll_row = tv->row;
        if (tv->row >= tv->scroll_row + (size_t)nr) tv->scroll_row = tv->row - (size_t)nr + 1;
    }
    fit_cols(tv, t, win_w);

    int gw = gutter_w(t);
    int last_c = tv->scroll_col;
    {
        int x = gw;
        for (int c = tv->scroll_col; c < t->ncols && x < win_w; c++) { x += t->colw[c] + 3; last_c = c; }
    }

    size_t shown = t->nrows - tv->scroll_row < (size_t)nr ? t->nrows - tv->scroll_row : (size_t)nr;

    /* horizontal rules: top, below the header, bottom */
    int rule_y[3] = { 1, 3, 4 + (int)shown };
    chtype left[3]  = { ACS_ULCORNER, ACS_LTEE, ACS_LLCORNER };
    chtype mid[3]   = { ACS_TTEE,     ACS_PLUS, ACS_BTEE     };
    chtype right[3] = { ACS_URCORNER, ACS_RTEE, ACS_LRCORNER };
    wattron(win, COLOR_PAIR(COLOR_PAIR_INACTIVE_BORDER) | A_DIM);
    for (int k = 0; k < 3; k++) {
        int y = rule_y[k];
        if (y >= win_h) continue;
        int x = gw;
        put_ch(win, y, x - 1 >= 0 ? x - 1 : 0, ' ');
        put_ch(win, y, x, left[k]);
        for (int c = tv->scroll_col; c <= last_c; c++) {
            for (int i = 0; i < t->colw[c] + 2; i++) put_ch(win, y, x + 1 + i, ACS_HLINE);
            x += t->colw[c] + 3;
            put_ch(win, y, x, c == last_c ? right[k] : mid[k]);
        }
    }
    wattroff(win, A_DIM);

    /* header + data rows */
    for (int r = -1; r < (int)shown; r++) {
        int y = r < 0 ? 2 : 4 + r;
        if (y >= win_h) break;
        size_t row = tv->scroll_row + (size_t)(r < 0 ? 0 : r);
        bool cur_row = r >= 0 && row == tv->row;

        if (r >= 0) {
            wattron(win, COLOR_PAIR(COLOR_PAIR_LINENUM) | (cur_row ? A_REVERSE | A_BOLD : 0));
            mvwprintw(win, y, 0, "%*zu", gw - 1, row + 1);
            wattroff(win, COLOR_PAIR(COLOR_PAIR_LINENUM) | A_REVERSE | A_BOLD);
            waddch(win, ' ');
        }
        int x = gw;
        wattron(win, COLOR_PAIR(COLOR_PAIR_INACTIVE_BORDER) | A_DIM);
        put_ch(win, y, x, ACS_VLINE);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_INACTIVE_BORDER) | A_DIM);
        for (int c = tv->scroll_col; c <= last_c; c++) {
            const char *s;
            int attr;
            bool right_al = t->numeric[c];
            if (r < 0) {
                s    = t->hdr[c];
                attr = COLOR_PAIR(c == tv->col ? COLOR_PAIR_SELECTION : COLOR_PAIR_KEYWORD) | A_BOLD;
                right_al = false;
            } else {
                s = t->cells[row * (size_t)t->ncols + (size_t)c];
                if (cur_row && c == tv->col) attr = COLOR_PAIR(COLOR_PAIR_SELECTION) | A_BOLD;
                else attr = COLOR_PAIR(cell_pair(s, t->numeric[c])) | (cur_row ? A_BOLD | A_UNDERLINE : 0);
                if (s && !strcmp(s, "NULL")) right_al = false;
            }
            wattron(win, attr);
            put_ch(win, y, x + 1, ' ');
            draw_text(win, y, x + 2, s ? s : "", t->colw[c], right_al);
            put_ch(win, y, x + 2 + t->colw[c], ' ');
            wattroff(win, attr);
            x += t->colw[c] + 3;
            wattron(win, COLOR_PAIR(COLOR_PAIR_INACTIVE_BORDER) | A_DIM);
            put_ch(win, y, x, ACS_VLINE);
            wattroff(win, COLOR_PAIR(COLOR_PAIR_INACTIVE_BORDER) | A_DIM);
        }
    }

    if (t->nrows == 0 && 4 < win_h) {
        wattron(win, COLOR_PAIR(COLOR_PAIR_COMMENT));
        mvwaddnstr(win, 5 < win_h ? 5 : 4, gw + 2, "(no rows)", win_w - gw - 2);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_COMMENT));
    }
    wnoutrefresh(win);
}

void tbl_status(const TableView *tv, char *out, size_t out_sz) {
    if (!tv || tv->nsheets == 0) { snprintf(out, out_sz, " [TABLE] no data "); return; }
    const TblSheet *t = &tv->sheets[tv->cur];
    snprintf(out, out_sz, " Row %zu/%zu%s  Col %d/%d  [%s]  %.60s  |  %.40s ",
             t->nrows ? tv->row + 1 : 0, t->nrows, t->truncated ? "+" : "",
             tv->col + 1, t->ncols, tv->fmt, t->name, t->hdr[tv->col]);
}

/* ─── Keys & search ────────────────────────────────────────────── */

static void sheet_switch(TableView *tv, int d) {
    if (tv->nsheets < 2) return;
    tv->cur = (tv->cur + d + tv->nsheets) % tv->nsheets;
    tv->row = tv->scroll_row = 0;
    tv->col = tv->scroll_col = 0;
}

bool tbl_handle_key(TableView *tv, int key, int win_h) {
    if (!tv || tv->nsheets == 0) return false;
    const TblSheet *t = &tv->sheets[tv->cur];
    size_t page = (size_t)data_rows(win_h);
    size_t last = t->nrows ? t->nrows - 1 : 0;

    switch (key) {
        case KEY_UP:   case 'k': if (tv->row > 0) tv->row--; break;
        case KEY_DOWN: case 'j': if (tv->row < last) tv->row++; break;
        case KEY_LEFT: case 'h': if (tv->col > 0) tv->col--; break;
        case KEY_RIGHT:case 'l': if (tv->col + 1 < t->ncols) tv->col++; break;
        case KEY_PPAGE: tv->row = tv->row > page ? tv->row - page : 0; break;
        case KEY_NPAGE: tv->row = tv->row + page < last ? tv->row + page : last; break;
        case KEY_HOME: case '0': tv->col = 0; break;
        case KEY_END:  case '$': tv->col = t->ncols - 1; break;
        case 'g': tv->row = 0; break;
        case 'G': tv->row = last; break;
        case '\t': case ']': sheet_switch(tv, 1); break;
        case KEY_BTAB: case '[': sheet_switch(tv, -1); break;
        default: return false;
    }
    return true;
}

bool tbl_search(TableView *tv, const char *q, bool forward) {
    if (!tv || !q || !q[0] || tv->nsheets == 0) return false;
    snprintf(tv->search, sizeof tv->search, "%s", q);
    const TblSheet *t = &tv->sheets[tv->cur];
    size_t total = t->nrows * (size_t)t->ncols;
    if (total == 0) return false;
    size_t at = tv->row * (size_t)t->ncols + (size_t)tv->col;
    for (size_t k = 1; k <= total; k++) {
        size_t i = forward ? (at + k) % total : (at + total - k % total) % total;
        const char *s = t->cells[i];
        if (s && strcasestr(s, q)) {
            tv->row = i / (size_t)t->ncols;
            tv->col = (int)(i % (size_t)t->ncols);
            return true;
        }
    }
    return false;
}
