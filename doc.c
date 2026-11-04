/* Document view: read-only, word-wrapped rendering of documents.
 *
 *   Markdown   parsed here (headings, lists, quotes, code, tables, inline
 *              bold / italic / code / links), straight from the buffer
 *   PDF        text through pdftotext, mutool or Python's pypdf
 *   .docx      word/document.xml read out of the zip (unzip, bsdtar or
 *              Python's zipfile) and walked here: headings, lists, bold,
 *              italic, tables
 *   .odt       content.xml, same idea
 *   .doc       antiword / catdoc
 *   others     pandoc, converted to Markdown, when it is installed
 *
 * Every loader produces a flat list of paragraphs (text + one style byte
 * per text byte); the layout wraps them to the pane width and is rebuilt
 * when the width changes. */
#include "abyss.h"
#include "utf8.h"
#include <strings.h>

/* inline styles (bitmask, one byte per text byte) */
enum { ST_BOLD = 1, ST_ITALIC = 2, ST_CODE = 4, ST_LINK = 8, ST_STRIKE = 16 };

typedef enum {
    PK_TEXT, PK_H1, PK_H2, PK_H3, PK_CODE, PK_QUOTE, PK_BULLET,
    PK_HR, PK_TABLE, PK_PAGE, PK_BLANK
} ParaKind;

struct DocPara {
    ParaKind kind;
    int      indent;        /* list nesting                         */
    char     bullet[16];    /* "• ", "1. "...                       */
    char    *text;
    uint8_t *sty;
    size_t   len;
};

typedef struct DocLine {
    int    para;
    size_t start, end;      /* byte range of the paragraph text     */
    bool   first;           /* first line of its paragraph          */
    int    rule;            /* 1: heading underline ═, 2: ─         */
} DocLine;

/* ─── Building paragraphs ──────────────────────────────────────── */

typedef struct {
    char    *s;
    uint8_t *st;
    size_t   n, cap;
} SBuf;

static void sb_putc(SBuf *b, char c, uint8_t style) {
    if (b->n + 1 >= b->cap) {
        b->cap = b->cap ? b->cap * 2 : 128;
        b->s   = realloc(b->s, b->cap);
        b->st  = realloc(b->st, b->cap);
    }
    b->s[b->n] = c;
    b->st[b->n] = style;
    b->n++;
}

static void sb_puts(SBuf *b, const char *s, uint8_t style) { while (*s) sb_putc(b, *s++, style); }
static void sb_putn(SBuf *b, const char *s, size_t n, uint8_t style) {
    for (size_t i = 0; i < n; i++) sb_putc(b, s[i], style);
}
static void sb_free(SBuf *b) { free(b->s); free(b->st); b->s = NULL; b->st = NULL; b->n = b->cap = 0; }

static DocPara *dv_push(DocView *dv, ParaKind k) {
    if (dv->npara >= dv->cap) {
        dv->cap   = dv->cap ? dv->cap * 2 : 256;
        dv->paras = realloc(dv->paras, (size_t)dv->cap * sizeof *dv->paras);
    }
    DocPara *p = &dv->paras[dv->npara++];
    memset(p, 0, sizeof *p);
    p->kind = k;
    return p;
}

/* Adds a paragraph from a buffer (copied); trims trailing blanks. */
static void dv_add(DocView *dv, ParaKind k, const SBuf *b, int indent, const char *bullet) {
    size_t n = b ? b->n : 0;
    while (n && (b->s[n - 1] == ' ' || b->s[n - 1] == '\t')) n--;
    DocPara *p = dv_push(dv, k);
    p->indent = indent;
    if (bullet) snprintf(p->bullet, sizeof p->bullet, "%s", bullet);
    p->text = malloc(n + 1);
    p->sty  = malloc(n + 1);
    if (n) { memcpy(p->text, b->s, n); memcpy(p->sty, b->st, n); }
    p->text[n] = '\0';
    p->len = n;
}

static void dv_blank(DocView *dv) {
    if (dv->npara == 0 || dv->paras[dv->npara - 1].kind == PK_BLANK) return;
    dv_add(dv, PK_BLANK, NULL, 0, NULL);
}

static void dv_clear(DocView *dv) {
    for (int i = 0; i < dv->npara; i++) { free(dv->paras[i].text); free(dv->paras[i].sty); }
    dv->npara = 0;
    dv->nlines = 0;
    dv->wrap_w = 0;
    dv->scroll = 0;
    dv->err[0] = '\0';
}

DocView *doc_new(void) {
    DocView *dv = calloc(1, sizeof *dv);
    dv->fmt = "Document";
    return dv;
}

void doc_free(DocView *dv) {
    if (!dv) return;
    dv_clear(dv);
    free(dv->paras);
    free(dv->lines);
    free(dv);
}

/* ─── File type ────────────────────────────────────────────────── */

static const char *ext_of(const char *path) {
    const char *slash = strrchr(path, '/');
#ifdef _WIN32
    const char *bs = strrchr(path, '\\');
    if (bs && (!slash || bs > slash)) slash = bs;
#endif
    const char *dot = strrchr(slash ? slash + 1 : path, '.');
    return dot ? dot : "";
}

static bool ext_in(const char *path, const char *const *list) {
    const char *e = ext_of(path);
    for (int i = 0; list[i]; i++) if (strcasecmp(e, list[i]) == 0) return true;
    return false;
}

bool doc_is_binary_doc(const char *path) {
    static const char *const l[] = { ".pdf", ".docx", ".docm", ".dotx", ".odt", ".ott",
                                     ".doc", ".rtf", ".epub", NULL };
    return path && ext_in(path, l);
}

bool doc_is_markdown(const char *path) {
    static const char *const l[] = { ".md", ".markdown", ".mdown", ".mkd", ".mkdn", NULL };
    return path && ext_in(path, l);
}

/* ─── Markdown ─────────────────────────────────────────────────── */

static bool is_punct(char c) { return c && strchr("\\`*_{}[]()#+-.!|~<>\"'", c) != NULL; }

/* Inline markup of one paragraph's raw text into styled text. */
static void md_inline(SBuf *o, const char *s, size_t n, uint8_t base) {
    uint8_t st = base;
    for (size_t i = 0; i < n; ) {
        char c = s[i];
        if (c == '\\' && i + 1 < n && is_punct(s[i + 1])) { sb_putc(o, s[i + 1], st); i += 2; continue; }
        if (c == '`') {
            size_t run = 0;
            while (i + run < n && s[i + run] == '`') run++;
            size_t j = i + run;
            while (j < n) {                              /* matching closing run */
                if (s[j] == '`') {
                    size_t r2 = 0;
                    while (j + r2 < n && s[j + r2] == '`') r2++;
                    if (r2 == run) break;
                    j += r2;
                } else j++;
            }
            if (j < n) {
                size_t a = i + run, z = j;
                if (z > a + 1 && s[a] == ' ' && s[z - 1] == ' ') { a++; z--; }
                sb_putn(o, s + a, z - a, (uint8_t)(st | ST_CODE));
                i = j + run;
                continue;
            }
            sb_putn(o, s + i, run, st);
            i += run;
            continue;
        }
        if ((c == '*' || c == '_') && i + 1 < n && s[i + 1] == c) {          /* bold */
            bool word_in = c == '_' && i > 0 && isalnum((unsigned char)s[i - 1]);
            const char *close = NULL;
            if (!word_in) {
                for (size_t j = i + 2; j + 1 < n; j++)
                    if (s[j] == c && s[j + 1] == c) { close = s + j; break; }
            }
            if ((st & ST_BOLD) || close) { st ^= ST_BOLD; i += 2; continue; }
        }
        if (c == '~' && i + 1 < n && s[i + 1] == '~') { st ^= ST_STRIKE; i += 2; continue; }
        if (c == '*' || c == '_') {                                          /* italic */
            bool open_ok = i + 1 < n && !isspace((unsigned char)s[i + 1]);
            bool word_in = c == '_' && i > 0 && isalnum((unsigned char)s[i - 1])
                           && i + 1 < n && isalnum((unsigned char)s[i + 1]);
            if (!word_in) {
                if (st & ST_ITALIC) { st &= (uint8_t)~ST_ITALIC; i++; continue; }
                if (open_ok && memchr(s + i + 1, c, n - i - 1)) { st |= ST_ITALIC; i++; continue; }
            }
        }
        if ((c == '[' || (c == '!' && i + 1 < n && s[i + 1] == '['))) {     /* link / image */
            size_t a = i + (c == '!' ? 2 : 1);
            size_t j = a; int depth = 1;
            while (j < n && depth) { if (s[j] == '[') depth++; else if (s[j] == ']') depth--; if (depth) j++; }
            if (j < n && j + 1 < n && s[j + 1] == '(') {
                size_t k = j + 2;
                while (k < n && s[k] != ')') k++;
                if (k < n) {
                    if (c == '!') {
                        sb_puts(o, "[image: ", (uint8_t)(st | ST_LINK));
                        sb_putn(o, s + a, j - a, (uint8_t)(st | ST_LINK));
                        sb_putc(o, ']', (uint8_t)(st | ST_LINK));
                    } else {
                        md_inline(o, s + a, j - a, (uint8_t)(st | ST_LINK));
                    }
                    i = k + 1;
                    continue;
                }
            }
        }
        if (c == '<' && i + 1 < n) {                         /* <http://...> and <br> */
            size_t k = i + 1;
            while (k < n && s[k] != '>' && s[k] != ' ') k++;
            if (k < n && s[k] == '>') {
                if (!strncasecmp(s + i, "<br", 3)) { sb_putc(o, '\n', st); i = k + 1; continue; }
                if (!strncmp(s + i + 1, "http", 4) || memchr(s + i + 1, '@', k - i - 1)) {
                    sb_putn(o, s + i + 1, k - i - 1, (uint8_t)(st | ST_LINK));
                    i = k + 1;
                    continue;
                }
            }
        }
        sb_putc(o, c, st);
        i++;
    }
}

static size_t lead_ws(const char *s, size_t n) {
    size_t w = 0, i = 0;
    for (; i < n && (s[i] == ' ' || s[i] == '\t'); i++) w += s[i] == '\t' ? 4 : 1;
    return w;
}

static bool md_hr(const char *s, size_t n) {
    char m = 0; int cnt = 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c == ' ' || c == '\t' || c == '\r') continue;
        if (c != '-' && c != '*' && c != '_') return false;
        if (m && c != m) return false;
        m = c; cnt++;
    }
    return cnt >= 3;
}

/* "1. ", "- ", "* ", "+ " list markers. Returns the marker length. */
static size_t md_list_marker(const char *s, size_t n, char *bullet, size_t bsz, int indent) {
    size_t i = 0;
    while (i < n && (s[i] == ' ' || s[i] == '\t')) i++;
    if (i < n && (s[i] == '-' || s[i] == '*' || s[i] == '+') && i + 1 < n && s[i + 1] == ' ') {
        static const char *dots[] = { "• ", "◦ ", "▪ " };
        snprintf(bullet, bsz, "%s", dots[indent % 3]);
        i += 2;
    } else {
        size_t d = i;
        while (d < n && isdigit((unsigned char)s[d]) && d - i < 9) d++;
        if (d == i || d >= n || (s[d] != '.' && s[d] != ')') || d + 1 >= n || s[d + 1] != ' ') return 0;
        snprintf(bullet, bsz, "%.*s. ", (int)(d - i), s + i);
        i = d + 2;
    }
    /* task lists */
    if (i + 3 < n && s[i] == '[' && s[i + 2] == ']' && s[i + 3] == ' ') {
        if (s[i + 1] == ' ')                            { snprintf(bullet, bsz, "☐ "); i += 4; }
        else if (s[i + 1] == 'x' || s[i + 1] == 'X')   { snprintf(bullet, bsz, "☑ "); i += 4; }
    }
    return i;
}

static bool md_table_sep(const char *s, size_t n) {
    bool dash = false, pipe = false;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '-') dash = true;
        else if (s[i] == '|') pipe = true;
        else if (!strchr(": \t\r", s[i])) return false;
    }
    return dash && pipe;
}

typedef struct { char *v[64]; int n; } MdRow;

static void md_split_row(const char *s, size_t n, MdRow *r) {
    r->n = 0;
    while (n && isspace((unsigned char)s[n - 1])) n--;
    while (n && isspace((unsigned char)*s)) { s++; n--; }
    if (n && *s == '|') { s++; n--; }
    if (n && s[n - 1] == '|') n--;
    size_t st = 0;
    for (size_t i = 0; i <= n && r->n < 64; i++) {
        if (i == n || (s[i] == '|' && (i == 0 || s[i - 1] != '\\'))) {
            size_t a = st, z = i;
            while (a < z && isspace((unsigned char)s[a])) a++;
            while (z > a && isspace((unsigned char)s[z - 1])) z--;
            SBuf b = {0};
            md_inline(&b, s + a, z - a, 0);
            sb_putc(&b, '\0', 0);
            r->v[r->n++] = b.s;
            free(b.st);
            st = i + 1;
        }
    }
}

static int text_width(const char *s) {
    int w = 0;
    size_t n = strlen(s);
    for (size_t i = 0; i < n; ) {
        uint32_t cp;
        int k = utf8_decode(s + i, n - i, &cp);
        if (k < 1) k = 1;
        w += cp < 32 ? 1 : utf8_cp_width(cp);
        i += (size_t)k;
    }
    return w;
}

/* A Markdown table block becomes aligned PK_TABLE rows. */
static void md_table(DocView *dv, MdRow *rows, int nr) {
    int ncol = 0;
    for (int r = 0; r < nr; r++) if (rows[r].n > ncol) ncol = rows[r].n;
    int w[64] = {0};
    for (int r = 0; r < nr; r++)
        for (int c = 0; c < rows[r].n; c++) {
            int tw = text_width(rows[r].v[c]);
            if (tw > w[c]) w[c] = tw;
        }
    for (int c = 0; c < ncol; c++) if (w[c] > 40) w[c] = 40;
    for (int r = 0; r < nr; r++) {
        SBuf b = {0};
        for (int c = 0; c < ncol; c++) {
            const char *v = c < rows[r].n ? rows[r].v[c] : "";
            if (c) sb_puts(&b, " │ ", 0);
            int tw = text_width(v);
            sb_puts(&b, v, r == 0 ? ST_BOLD : 0);
            for (int k = tw; k < w[c]; k++) sb_putc(&b, ' ', 0);
        }
        dv_add(dv, PK_TABLE, &b, 0, NULL);
        sb_free(&b);
        if (r == 0) {
            SBuf sep = {0};
            for (int c = 0; c < ncol; c++) {
                if (c) sb_puts(&sep, "─┼─", 0);
                for (int k = 0; k < w[c]; k++) sb_puts(&sep, "─", 0);
            }
            dv_add(dv, PK_TABLE, &sep, 0, NULL);
            sb_free(&sep);
        }
    }
    dv_blank(dv);
}

bool doc_load_markdown(DocView *dv, const char *path, const char *s, size_t len) {
    dv_clear(dv);
    snprintf(dv->path, sizeof dv->path, "%s", path ? path : "");
    dv->fmt = "Markdown";

    SBuf raw = {0};                 /* current paragraph, raw markdown */
    ParaKind pk = PK_TEXT;
    int  p_indent = 0;
    char p_bullet[16] = "";
    bool in_code = false;
    char fence = 0;

#define FLUSH() do {                                                     \
        if (raw.n) {                                                     \
            SBuf o = {0};                                                \
            md_inline(&o, raw.s, raw.n, 0);                              \
            dv_add(dv, pk, &o, p_indent, pk == PK_BULLET ? p_bullet : NULL); \
            sb_free(&o);                                                 \
            raw.n = 0;                                                   \
        }                                                                \
        pk = PK_TEXT; p_indent = 0; p_bullet[0] = '\0';                  \
    } while (0)

    size_t i = 0;
    while (i < len) {
        size_t e = i;
        while (e < len && s[e] != '\n') e++;
        const char *ln = s + i;
        size_t n = e - i;
        if (n && ln[n - 1] == '\r') n--;
        size_t next = e + 1;

        size_t ws = lead_ws(ln, n);
        size_t a = 0;
        while (a < n && (ln[a] == ' ' || ln[a] == '\t')) a++;
        const char *t = ln + a;
        size_t tn = n - a;

        /* fenced code */
        if (tn >= 3 && (!strncmp(t, "```", 3) || !strncmp(t, "~~~", 3)) && (!in_code || t[0] == fence)) {
            FLUSH();
            if (!in_code) {
                in_code = true; fence = t[0];
                size_t k = 3;
                while (k < tn && t[k] == fence) k++;
                while (k < tn && t[k] == ' ') k++;
                if (k < tn) {                                   /* language label */
                    SBuf lb = {0};
                    sb_putn(&lb, t + k, tn - k, ST_ITALIC);
                    dv_add(dv, PK_CODE, &lb, 0, NULL);
                    dv->paras[dv->npara - 1].indent = -1;       /* marks a label */
                    sb_free(&lb);
                }
            } else {
                in_code = false;
                dv_blank(dv);
            }
            i = next; continue;
        }
        if (in_code) {
            SBuf c = {0};
            sb_putn(&c, ln, n, 0);
            dv_add(dv, PK_CODE, &c, 0, NULL);
            sb_free(&c);
            i = next; continue;
        }

        if (tn == 0) {                                         /* blank line */
            FLUSH();
            dv_blank(dv);
            i = next; continue;
        }

        /* tables: header row followed by |---|---| */
        if (memchr(t, '|', tn) && next < len) {
            size_t ne = next;
            while (ne < len && s[ne] != '\n') ne++;
            if (md_table_sep(s + next, ne - next)) {
                FLUSH();
                MdRow rows[512];
                int nr = 0;
                md_split_row(t, tn, &rows[nr++]);
                size_t j = ne + 1;
                while (j < len && nr < 512) {
                    size_t je = j;
                    while (je < len && s[je] != '\n') je++;
                    if (!memchr(s + j, '|', je - j)) break;
                    md_split_row(s + j, je - j, &rows[nr++]);
                    j = je + 1;
                }
                md_table(dv, rows, nr);
                for (int r = 0; r < nr; r++) for (int c = 0; c < rows[r].n; c++) free(rows[r].v[c]);
                i = j; continue;
            }
        }

        /* ATX headings */
        if (t[0] == '#') {
            size_t h = 0;
            while (h < tn && t[h] == '#') h++;
            if (h <= 6 && (h == tn || t[h] == ' ')) {
                FLUSH();
                size_t z = tn;
                while (z > h && (t[z - 1] == '#' || t[z - 1] == ' ')) z--;
                size_t st = h;
                while (st < z && t[st] == ' ') st++;
                SBuf o = {0};
                md_inline(&o, t + st, z > st ? z - st : 0, 0);
                dv_add(dv, h == 1 ? PK_H1 : h == 2 ? PK_H2 : PK_H3, &o, 0, NULL);
                sb_free(&o);
                dv_blank(dv);
                i = next; continue;
            }
        }

        /* setext underline of the pending paragraph */
        if (raw.n && pk == PK_TEXT && tn >= 2) {
            bool eq = true, da = true;
            for (size_t k = 0; k < tn; k++) {
                if (t[k] != '=' && t[k] != ' ') eq = false;
                if (t[k] != '-' && t[k] != ' ') da = false;
            }
            if (eq || da) {
                pk = eq ? PK_H1 : PK_H2;
                FLUSH();
                dv_blank(dv);
                i = next; continue;
            }
        }

        if (md_hr(t, tn)) {
            FLUSH();
            dv_add(dv, PK_HR, NULL, 0, NULL);
            i = next; continue;
        }

        if (t[0] == '>') {                                     /* blockquote */
            if (pk != PK_QUOTE) FLUSH();
            pk = PK_QUOTE;
            size_t k = 1;
            while (k < tn && t[k] == '>') k++;
            if (k < tn && t[k] == ' ') k++;
            if (k >= tn) { FLUSH(); i = next; continue; }
            if (raw.n) sb_putc(&raw, ' ', 0);
            sb_putn(&raw, t + k, tn - k, 0);
            i = next; continue;
        }

        char bullet[16];
        int  ind = (int)(ws / 2);
        size_t mk = md_list_marker(ln, n, bullet, sizeof bullet, ind);
        if (mk) {
            FLUSH();
            pk = PK_BULLET;
            p_indent = ind;
            snprintf(p_bullet, sizeof p_bullet, "%s", bullet);
            sb_putn(&raw, ln + mk, n - mk, 0);
            i = next; continue;
        }

        if (ws >= 4 && !raw.n && (dv->npara == 0 || dv->paras[dv->npara - 1].kind == PK_BLANK
                                  || dv->paras[dv->npara - 1].kind == PK_CODE)) {
            SBuf c = {0};                                       /* indented code */
            size_t k = 0, col = 0;
            while (k < n && col < 4) { col += ln[k] == '\t' ? 4 : 1; k++; }
            sb_putn(&c, ln + k, n - k, 0);
            dv_add(dv, PK_CODE, &c, 0, NULL);
            sb_free(&c);
            i = next; continue;
        }

        /* paragraph text (or a list item / quote continuation) */
        bool hard = n >= 2 && ln[n - 1] == ' ' && ln[n - 2] == ' ';
        if (raw.n && raw.s[raw.n - 1] != '\n') sb_putc(&raw, ' ', 0);
        size_t z = tn;
        while (z && t[z - 1] == ' ') z--;
        if (z && t[z - 1] == '\\') { z--; hard = true; }
        sb_putn(&raw, t, z, 0);
        if (hard) sb_putc(&raw, '\n', 0);
        i = next;
    }
    FLUSH();
#undef FLUSH
    sb_free(&raw);
    if (dv->npara == 0) { snprintf(dv->err, sizeof dv->err, "Empty document"); return false; }
    return true;
}

/* Plain text: every source paragraph (blank-line separated) is kept,
 * lines inside it are joined unless the line looks like a list item. */
static void load_plain(DocView *dv, const char *s, size_t len, bool pages) {
    SBuf b = {0};
    int page = 1;
    size_t i = 0;
    while (i <= len) {
        size_t e = i;
        while (e < len && s[e] != '\n' && s[e] != '\f') e++;
        const char *ln = s + i;
        size_t n = e - i;
        if (n && ln[n - 1] == '\r') n--;
        size_t a = 0;
        while (a < n && (ln[a] == ' ' || ln[a] == '\t')) a++;
        bool blank = a == n;
        bool listy = !blank && (ln[a] == '-' || ln[a] == '*' || !strncmp(ln + a, "•", 3) ||
                                (isdigit((unsigned char)ln[a]) && a + 1 < n &&
                                 (ln[a + 1] == '.' || ln[a + 1] == ')')));
        if (blank || listy) {
            if (b.n) { dv_add(dv, PK_TEXT, &b, 0, NULL); b.n = 0; }
            if (blank) dv_blank(dv);
        }
        if (!blank) {
            if (b.n) {
                /* de-hyphenate words split at the end of a line */
                if (b.s[b.n - 1] == '-' && b.n > 1 && isalpha((unsigned char)b.s[b.n - 2]) &&
                    islower((unsigned char)ln[a])) b.n--;
                else sb_putc(&b, ' ', 0);
            }
            sb_putn(&b, ln + a, n - a, 0);
        }
        if (e < len && s[e] == '\f') {
            if (b.n) { dv_add(dv, PK_TEXT, &b, 0, NULL); b.n = 0; }
            if (pages && e + 1 < len) {
                char pg[48];
                snprintf(pg, sizeof pg, "page %d", ++page);
                SBuf pb = {0};
                sb_puts(&pb, pg, 0);
                dv_blank(dv);
                dv_add(dv, PK_PAGE, &pb, 0, NULL);
                dv_blank(dv);
                sb_free(&pb);
            }
        }
        if (e >= len) break;
        i = e + 1;
    }
    if (b.n) dv_add(dv, PK_TEXT, &b, 0, NULL);
    sb_free(&b);
}

/* ─── XML documents (docx / odt) ───────────────────────────────── */

static bool xattr(const char *a, size_t an, const char *name, char *out, size_t out_sz) {
    size_t nl = strlen(name);
    for (size_t i = 0; i + nl + 2 <= an; i++) {
        if (strncmp(a + i, name, nl) == 0 && a[i + nl] == '=' &&
            (a[i + nl + 1] == '"' || a[i + nl + 1] == '\'') && (i == 0 || isspace((unsigned char)a[i - 1]))) {
            char q = a[i + nl + 1];
            size_t j = i + nl + 2, k = 0;
            while (j < an && a[j] != q && k + 1 < out_sz) out[k++] = a[j++];
            out[k] = '\0';
            return true;
        }
    }
    return false;
}

/* XML text with entities decoded */
static void xml_text(SBuf *b, const char *s, size_t n, uint8_t st) {
    for (size_t i = 0; i < n; i++) {
        if (s[i] != '&') { if (s[i] != '\r' && s[i] != '\n') sb_putc(b, s[i], st); continue; }
        const char *semi = memchr(s + i, ';', n - i < 12 ? n - i : 12);
        if (!semi) { sb_putc(b, '&', st); continue; }
        size_t el = (size_t)(semi - (s + i));
        const char *e = s + i + 1;
        uint32_t cp = 0;
        if (!strncmp(e, "amp;", 4)) cp = '&';
        else if (!strncmp(e, "lt;", 3)) cp = '<';
        else if (!strncmp(e, "gt;", 3)) cp = '>';
        else if (!strncmp(e, "quot;", 5)) cp = '"';
        else if (!strncmp(e, "apos;", 5)) cp = '\'';
        else if (e[0] == '#') cp = (uint32_t)strtoul(e + 1 + (e[1] == 'x'), NULL, e[1] == 'x' ? 16 : 10);
        if (!cp) { sb_putc(b, '&', st); continue; }
        char u[4];
        int k = utf8_encode(cp, u);
        sb_putn(b, u, (size_t)k, st);
        i += el;
    }
}


static ParaKind style_kind(const char *st, int *level) {
    char low[64];
    size_t i = 0;
    for (; st[i] && i + 1 < sizeof low; i++) low[i] = (char)tolower((unsigned char)st[i]);
    low[i] = '\0';
    const char *h = strstr(low, "heading");
    if (!h) h = strstr(low, "titre");
    if (h) {
        const char *d = h;
        while (*d && !isdigit((unsigned char)*d)) d++;
        int lv = *d ? atoi(d) : 1;
        *level = lv;
        return lv <= 1 ? PK_H1 : lv == 2 ? PK_H2 : PK_H3;
    }
    if (!strcmp(low, "title")) { *level = 1; return PK_H1; }
    if (!strcmp(low, "subtitle") || !strcmp(low, "sous-titre")) { *level = 3; return PK_H3; }
    if (strstr(low, "quote") || strstr(low, "citation")) return PK_QUOTE;
    if (strstr(low, "listparagraph") || strstr(low, "paragraphedeliste")) return PK_BULLET;
    return PK_TEXT;
}

static const char *const bullets[] = { "• ", "◦ ", "▪ " };

typedef struct {
    DocView *dv;
    bool     odt;
    /* paragraph */
    SBuf     p;
    bool     in_p;
    char     pstyle[64];
    int      head_level;     /* odt text:h, docx outline level        */
    bool     list;
    int      ilvl;
    int      list_depth;     /* odt list nesting                      */
    /* run */
    bool     bold, italic, in_t, link;
    int      skip;           /* inside deleted text / notes           */
    /* tables */
    int      tbl_depth;
    SBuf     row, cell;
    int      tbl_row;
    bool     in_cell;
} XWalk;

static uint8_t xw_style(const XWalk *w) {
    return (uint8_t)((w->bold ? ST_BOLD : 0) | (w->italic ? ST_ITALIC : 0) | (w->link ? ST_LINK : 0));
}

static void sb_append(SBuf *dst, const SBuf *src, uint8_t extra) {
    for (size_t i = 0; i < src->n; i++) sb_putc(dst, src->s[i], (uint8_t)(src->st[i] | extra));
}

static void xw_begin_para(XWalk *w) {
    w->in_p = true;
    w->p.n = 0;
    w->pstyle[0] = '\0';
    w->head_level = 0;
    w->list = w->odt && w->list_depth > 0;
    w->ilvl = w->list_depth > 0 ? w->list_depth - 1 : 0;
}

static void xw_end_para(XWalk *w) {
    if (!w->in_p) return;
    w->in_p = false;
    if (w->tbl_depth > 0 && w->in_cell) {              /* text of a table cell */
        if (w->cell.n && w->p.n) sb_putc(&w->cell, ' ', 0);
        sb_append(&w->cell, &w->p, 0);
        w->p.n = 0;
        return;
    }
    int lv = 0;
    ParaKind k = PK_TEXT;
    if (w->head_level > 0)  k = w->head_level <= 1 ? PK_H1 : w->head_level == 2 ? PK_H2 : PK_H3;
    else if (w->pstyle[0])  k = style_kind(w->pstyle, &lv);
    if (w->list && (k == PK_TEXT || k == PK_BULLET)) k = PK_BULLET;
    if (k == PK_BULLET) {
        int ind = w->ilvl < 0 ? 0 : w->ilvl;
        if (w->p.n) dv_add(w->dv, PK_BULLET, &w->p, ind, bullets[ind % 3]);
    } else if (w->p.n == 0) {
        dv_blank(w->dv);
    } else {
        if (w->dv->npara && w->dv->paras[w->dv->npara - 1].kind == PK_BULLET) dv_blank(w->dv);
        dv_add(w->dv, k, &w->p, 0, NULL);
        dv_blank(w->dv);
    }
    w->p.n = 0;
}

static bool tag_is(const char *name, const char *want) { return strcmp(name, want) == 0; }

static void xw_tag(XWalk *w, const char *name, bool close, bool selfc, const char *a, size_t an) {
    char v[64];
    if (!w->odt) {
        /* WordprocessingML */
        if (tag_is(name, "w:p")) {
            if (close) xw_end_para(w);
            else { xw_begin_para(w); if (selfc) xw_end_para(w); }
        } else if (tag_is(name, "w:r")) {
            if (!close) { w->bold = w->italic = false; }
        } else if (tag_is(name, "w:t")) {
            w->in_t = !close && !selfc;
        } else if (tag_is(name, "w:tab") && !close) {
            if (w->in_p && !w->skip) sb_putc(&w->p, ' ', xw_style(w));
        } else if ((tag_is(name, "w:br") || tag_is(name, "w:cr")) && !close) {
            if (w->in_p && !w->skip) sb_putc(&w->p, '\n', 0);
        } else if ((tag_is(name, "w:b") || tag_is(name, "w:bCs")) && !close) {
            w->bold = !(xattr(a, an, "w:val", v, sizeof v) && (!strcmp(v, "0") || !strcmp(v, "false")));
        } else if ((tag_is(name, "w:i") || tag_is(name, "w:iCs")) && !close) {
            w->italic = !(xattr(a, an, "w:val", v, sizeof v) && (!strcmp(v, "0") || !strcmp(v, "false")));
        } else if (tag_is(name, "w:pStyle") && !close) {
            if (xattr(a, an, "w:val", v, sizeof v)) snprintf(w->pstyle, sizeof w->pstyle, "%s", v);
        } else if (tag_is(name, "w:outlineLvl") && !close) {
            if (xattr(a, an, "w:val", v, sizeof v) && atoi(v) < 9) w->head_level = atoi(v) + 1;
        } else if (tag_is(name, "w:numPr")) {
            if (!close) w->list = true;
        } else if (tag_is(name, "w:ilvl") && !close) {
            if (xattr(a, an, "w:val", v, sizeof v)) w->ilvl = atoi(v);
        } else if (tag_is(name, "w:hyperlink")) {
            w->link = !close && !selfc;
        } else if (tag_is(name, "w:del") || tag_is(name, "w:footnoteReference")) {
            if (!selfc) w->skip += close ? -1 : 1;
            if (w->skip < 0) w->skip = 0;
        } else if (tag_is(name, "w:tbl")) {
            if (!close) { if (++w->tbl_depth == 1) w->tbl_row = 0; dv_blank(w->dv); }
            else if (w->tbl_depth > 0 && --w->tbl_depth == 0) dv_blank(w->dv);
        } else if (tag_is(name, "w:tr")) {
            if (!close) w->row.n = 0;
            else if (w->tbl_depth == 1) {
                if (w->row.n) dv_add(w->dv, PK_TABLE, &w->row, 0, NULL);
                if (w->tbl_row == 0 && w->dv->npara) {
                    DocPara *dp = &w->dv->paras[w->dv->npara - 1];
                    for (size_t k = 0; k < dp->len; k++) dp->sty[k] |= ST_BOLD;
                }
                w->tbl_row++;
                w->row.n = 0;
            }
        } else if (tag_is(name, "w:tc")) {
            if (!close) { w->in_cell = true; w->cell.n = 0; }
            else if (w->tbl_depth == 1) {
                if (w->row.n) sb_puts(&w->row, " │ ", 0);
                sb_append(&w->row, &w->cell, 0);
                w->cell.n = 0;
                w->in_cell = false;
            }
        }
        return;
    }

    /* OpenDocument */
    if (tag_is(name, "text:p") || tag_is(name, "text:h")) {
        if (close) xw_end_para(w);
        else {
            xw_begin_para(w);
            if (tag_is(name, "text:h"))
                w->head_level = xattr(a, an, "text:outline-level", v, sizeof v) ? atoi(v) : 1;
            if (w->head_level == 0 && tag_is(name, "text:h")) w->head_level = 1;
            if (selfc) xw_end_para(w);
        }
    } else if (tag_is(name, "text:list")) {
        if (!selfc) w->list_depth += close ? -1 : 1;
        if (w->list_depth < 0) w->list_depth = 0;
    } else if (tag_is(name, "text:tab") && !close) {
        if (w->in_p && !w->skip) sb_putc(&w->p, ' ', 0);
    } else if (tag_is(name, "text:line-break") && !close) {
        if (w->in_p && !w->skip) sb_putc(&w->p, '\n', 0);
    } else if (tag_is(name, "text:s") && !close) {
        int c = xattr(a, an, "text:c", v, sizeof v) ? atoi(v) : 1;
        for (int k = 0; k < c && k < 64 && w->in_p; k++) sb_putc(&w->p, ' ', 0);
    } else if (tag_is(name, "text:a")) {
        w->link = !close && !selfc;
    } else if (tag_is(name, "text:note") || tag_is(name, "office:annotation") ||
               tag_is(name, "text:tracked-changes")) {
        if (!selfc) w->skip += close ? -1 : 1;
        if (w->skip < 0) w->skip = 0;
    } else if (tag_is(name, "table:table")) {
        if (!close) { if (++w->tbl_depth == 1) w->tbl_row = 0; dv_blank(w->dv); }
        else if (w->tbl_depth > 0 && --w->tbl_depth == 0) dv_blank(w->dv);
    } else if (tag_is(name, "table:table-row")) {
        if (!close) w->row.n = 0;
        else if (w->tbl_depth == 1) {
            if (w->row.n) dv_add(w->dv, PK_TABLE, &w->row, 0, NULL);
            if (w->tbl_row == 0 && w->dv->npara) {
                DocPara *dp = &w->dv->paras[w->dv->npara - 1];
                for (size_t k = 0; k < dp->len; k++) dp->sty[k] |= ST_BOLD;
            }
            w->tbl_row++;
        }
    } else if (tag_is(name, "table:table-cell")) {
        if (!close && !selfc) { w->in_cell = true; w->cell.n = 0; }
        else if (w->tbl_depth == 1) {
            if (w->row.n) sb_puts(&w->row, " │ ", 0);
            sb_append(&w->row, &w->cell, 0);
            w->cell.n = 0;
            w->in_cell = false;
        }
    }
}

static void xml_walk(XWalk *w, const char *s, size_t n) {
    size_t i = 0;
    while (i < n) {
        if (s[i] != '<') {
            size_t j = i;
            while (j < n && s[j] != '<') j++;
            bool capture = w->odt ? w->in_p : (w->in_t && w->in_p);
            if (capture && !w->skip) xml_text(&w->p, s + i, j - i, xw_style(w));
            i = j;
            continue;
        }
        if (i + 3 < n && !strncmp(s + i, "<!--", 4)) {
            const char *e = strstr(s + i + 4, "-->");
            i = e ? (size_t)(e - s) + 3 : n;
            continue;
        }
        if (i + 1 < n && (s[i + 1] == '?' || s[i + 1] == '!')) {
            while (i < n && s[i] != '>') i++;
            i++;
            continue;
        }
        size_t j = i + 1;
        bool close = false;
        if (j < n && s[j] == '/') { close = true; j++; }
        size_t ns = j;
        while (j < n && !isspace((unsigned char)s[j]) && s[j] != '>' && s[j] != '/') j++;
        char name[64];
        size_t nl = j - ns < sizeof name - 1 ? j - ns : sizeof name - 1;
        memcpy(name, s + ns, nl);
        name[nl] = '\0';
        size_t as = j;
        char q = 0;
        while (j < n && (q || s[j] != '>')) {
            if (q) { if (s[j] == q) q = 0; }
            else if (s[j] == '"' || s[j] == '\'') q = s[j];
            j++;
        }
        bool selfc = j > as && s[j - 1] == '/';
        xw_tag(w, name, close, selfc, s + as, j - as);
        i = j + 1;
    }
    xw_end_para(w);
    sb_free(&w->p); sb_free(&w->row); sb_free(&w->cell);
}

/* ─── External tools ───────────────────────────────────────────── */

#ifdef _WIN32
#  define PY1 "python"
#  define PY2 "py"
#else
#  define PY1 "python3"
#  define PY2 "python"
#endif

static bool run_ok(char *const argv[], char **out, size_t *len) {
    int rc = proc_capture(argv, out, len);
    if (rc == 0 && *len > 0) return true;
    free(*out); *out = NULL; *len = 0;
    return false;
}

/* One member of a zip archive (docx / odt are zips). */
static bool zip_member(const char *path, const char *member, char **out, size_t *len) {
    char *u[] = { "unzip", "-p", (char *)path, (char *)member, NULL };
    if (run_ok(u, out, len)) return true;
    char *t[] = { "tar", "-xOf", (char *)path, (char *)member, NULL };   /* bsdtar, tar.exe */
    if (run_ok(t, out, len)) return true;
    static const char code[] =
        "import sys,zipfile;sys.stdout.buffer.write(zipfile.ZipFile(sys.argv[1]).read(sys.argv[2]))";
    char *p1[] = { PY1, "-c", (char *)code, (char *)path, (char *)member, NULL };
    if (run_ok(p1, out, len)) return true;
    char *p2[] = { PY2, "-c", (char *)code, (char *)path, (char *)member, NULL };
    return run_ok(p2, out, len);
}

static bool load_pdf(DocView *dv, const char *path) {
    char *out; size_t len;
    char *a[] = { "pdftotext", "-enc", "UTF-8", (char *)path, "-", NULL };
    char *b[] = { "mutool", "draw", "-q", "-F", "txt", "-o", "-", (char *)path, NULL };
    static const char code[] =
        "import sys\n"
        "try:\n from pypdf import PdfReader\n"
        "except ImportError:\n from PyPDF2 import PdfReader\n"
        "sys.stdout.write('\\f'.join((p.extract_text() or '') for p in PdfReader(sys.argv[1]).pages))";
    char *c[] = { PY1, "-c", (char *)code, (char *)path, NULL };
    if (run_ok(a, &out, &len) || run_ok(b, &out, &len) || run_ok(c, &out, &len)) {
        load_plain(dv, out, len, true);
        free(out);
        return true;
    }
    snprintf(dv->err, sizeof dv->err,
             "Cannot read PDF: install poppler (pdftotext), mupdf (mutool) or pip install pypdf");
    return false;
}

static bool load_pandoc(DocView *dv, const char *path) {
    char *out; size_t len;
    char *a[] = { "pandoc", "-t", "gfm", "--wrap=none", (char *)path, NULL };
    if (!run_ok(a, &out, &len)) return false;
    const char *fmt = dv->fmt;
    doc_load_markdown(dv, path, out, len);
    dv->fmt = fmt;
    free(out);
    return dv->npara > 0;
}

bool doc_load_file(DocView *dv, const char *path) {
    dv_clear(dv);
    snprintf(dv->path, sizeof dv->path, "%s", path);
    const char *e = ext_of(path);
    bool ok = false;

    if (!strcasecmp(e, ".pdf")) {
        dv->fmt = "PDF";
        ok = load_pdf(dv, path);
    } else if (!strcasecmp(e, ".docx") || !strcasecmp(e, ".docm") || !strcasecmp(e, ".dotx") ||
               !strcasecmp(e, ".odt")  || !strcasecmp(e, ".ott")) {
        bool odt = tolower((unsigned char)e[1]) == 'o';
        dv->fmt = odt ? "OpenDocument" : "Word";
        char *xml; size_t len;
        if (zip_member(path, odt ? "content.xml" : "word/document.xml", &xml, &len)) {
            XWalk w = { .dv = dv, .odt = odt };
            xml_walk(&w, xml, len);
            free(xml);
            ok = true;
        } else if (load_pandoc(dv, path)) {
            ok = true;
        } else {
            snprintf(dv->err, sizeof dv->err,
                     "Cannot open the archive: needs unzip, tar (bsdtar) or Python");
        }
    } else if (!strcasecmp(e, ".doc")) {
        dv->fmt = "Word 97";
        char *out; size_t len;
        char *a[] = { "antiword", "-w", "0", (char *)path, NULL };
        char *b[] = { "catdoc", "-w", (char *)path, NULL };
        if (run_ok(a, &out, &len) || run_ok(b, &out, &len)) {
            load_plain(dv, out, len, false);
            free(out);
            ok = true;
        } else snprintf(dv->err, sizeof dv->err, "Old .doc files need antiword or catdoc");
    } else {
        dv->fmt = !strcasecmp(e, ".rtf") ? "RTF" : !strcasecmp(e, ".epub") ? "EPUB" : "Document";
        ok = load_pandoc(dv, path);
        if (!ok) snprintf(dv->err, sizeof dv->err, "%s files need pandoc", dv->fmt);
    }
    while (dv->npara && dv->paras[dv->npara - 1].kind == PK_BLANK) {
        dv->npara--;
        free(dv->paras[dv->npara].text); free(dv->paras[dv->npara].sty);
    }
    if (ok && dv->npara == 0) {
        snprintf(dv->err, sizeof dv->err, "No text in this document (scanned images?)");
        ok = false;
    }
    return ok;
}

/* ─── Layout ───────────────────────────────────────────────────── */

static int para_prefix(const DocPara *p) {
    switch (p->kind) {
        case PK_BULLET: return p->indent * 2 + text_width(p->bullet);
        case PK_QUOTE:  return 2;
        case PK_CODE:   return 2;
        case PK_TABLE:  return 1;
        default:        return 0;
    }
}

static void push_line(DocView *dv, int para, size_t a, size_t z, bool first, int rule) {
    if (dv->nlines >= dv->lcap) {
        dv->lcap  = dv->lcap ? dv->lcap * 2 : 1024;
        dv->lines = realloc(dv->lines, dv->lcap * sizeof *dv->lines);
    }
    dv->lines[dv->nlines++] = (DocLine){ para, a, z, first, rule };
}

static void dv_layout(DocView *dv, int width) {
    dv->nlines = 0;
    dv->wrap_w = width;
    for (int k = 0; k < dv->npara; k++) {
        const DocPara *p = &dv->paras[k];
        if (p->kind == PK_BLANK || p->kind == PK_HR || p->kind == PK_PAGE) {
            push_line(dv, k, 0, p->len, true, 0);
            continue;
        }
        bool pre = p->kind == PK_CODE || p->kind == PK_TABLE;
        int avail = width - para_prefix(p);
        if (avail < 8) avail = 8;
        size_t pos = 0;
        int widest = 0;
        do {
            size_t i = pos, last_sp = (size_t)-1;
            int w = 0;
            while (i < p->len && p->text[i] != '\n') {
                uint32_t cp;
                int n = utf8_decode(p->text + i, p->len - i, &cp);
                if (n < 1) n = 1;
                int cw = cp < 32 ? 1 : utf8_cp_width(cp);
                if (w + cw > avail) break;
                if (p->text[i] == ' ') last_sp = i;
                w += cw;
                i += (size_t)n;
            }
            size_t end, next;
            if (i >= p->len || p->text[i] == '\n') { end = i; next = i < p->len ? i + 1 : p->len; }
            else if (!pre && last_sp != (size_t)-1 && last_sp > pos) { end = last_sp; next = last_sp + 1; }
            else { end = i; next = i; }
            if (next == pos) {                      /* always make progress */
                uint32_t cp;
                int n = utf8_decode(p->text + pos, p->len - pos, &cp);
                end = next = pos + (size_t)(n < 1 ? 1 : n);
            }
            if (w > widest) widest = w;
            push_line(dv, k, pos, end, pos == 0, 0);
            pos = next;
        } while (pos < p->len);
        if (p->kind == PK_H1 || p->kind == PK_H2)
            push_line(dv, k, (size_t)widest, 0, false, p->kind == PK_H1 ? 1 : 2);
    }
}

/* ─── Rendering ────────────────────────────────────────────────── */

static attr_t base_attr(const DocPara *p) {
    switch (p->kind) {
        case PK_H1:    return COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD;
        case PK_H2:    return COLOR_PAIR(COLOR_PAIR_TYPE)    | A_BOLD;
        case PK_H3:    return COLOR_PAIR(COLOR_PAIR_PREPROC) | A_BOLD;
        case PK_CODE:  return COLOR_PAIR(COLOR_PAIR_STRING);
        case PK_QUOTE: return COLOR_PAIR(COLOR_PAIR_COMMENT) | A_ITALIC;
        default:       return COLOR_PAIR(COLOR_PAIR_NORMAL);
    }
}

static attr_t with_pair(attr_t a, int pair) { return (a & ~A_COLOR) | COLOR_PAIR(pair); }

static const char *ci_find(const char *s, size_t n, const char *q) {
    size_t qn = strlen(q);
    if (!qn || qn > n) return NULL;
    for (size_t i = 0; i + qn <= n; i++)
        if (strncasecmp(s + i, q, qn) == 0) return s + i;
    return NULL;
}

/* One wrapped line, drawn in the text column [x0, x0 + w). */
static void draw_line(const DocView *dv, WINDOW *win, int y, int x0, int w, const DocLine *ln) {
    const DocPara *p = &dv->paras[ln->para];
    attr_t base = base_attr(p);
    int x = 0;

    if (ln->rule) {
        int n = (int)ln->start;
        if (n > w) n = w;
        wattron(win, base);
        for (int i = 0; i < n; i++) mvwaddstr(win, y, x0 + i, ln->rule == 1 ? "═" : "─");
        wattroff(win, base);
        return;
    }
    switch (p->kind) {
        case PK_BLANK: return;
        case PK_HR:
            wattron(win, COLOR_PAIR(COLOR_PAIR_LINENUM));
            mvwhline(win, y, x0, ACS_HLINE, w > 0 ? w : 1);
            wattroff(win, COLOR_PAIR(COLOR_PAIR_LINENUM));
            return;
        case PK_PAGE: {
            char lab[64];
            snprintf(lab, sizeof lab, " %s ", p->text);
            int lw = text_width(lab);
            wattron(win, COLOR_PAIR(COLOR_PAIR_LINENUM));
            mvwhline(win, y, x0, ACS_HLINE, w);
            mvwaddstr(win, y, x0 + ((w - lw) / 2 > 0 ? (w - lw) / 2 : 0), lab);
            wattroff(win, COLOR_PAIR(COLOR_PAIR_LINENUM));
            return;
        }
        case PK_BULLET:
            x = p->indent * 2;
            if (ln->first) {
                wattron(win, COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD);
                mvwaddstr(win, y, x0 + x, p->bullet);
                wattroff(win, COLOR_PAIR(COLOR_PAIR_KEYWORD) | A_BOLD);
            }
            x += text_width(p->bullet);
            break;
        case PK_QUOTE:
            wattron(win, COLOR_PAIR(COLOR_PAIR_TYPE));
            mvwaddstr(win, y, x0, "│ ");
            wattroff(win, COLOR_PAIR(COLOR_PAIR_TYPE));
            x = 2;
            break;
        case PK_CODE:
            wattron(win, COLOR_PAIR(COLOR_PAIR_LINENUM));
            mvwaddstr(win, y, x0, "▏ ");
            wattroff(win, COLOR_PAIR(COLOR_PAIR_LINENUM));
            x = 2;
            if (p->indent < 0) base = COLOR_PAIR(COLOR_PAIR_COMMENT) | A_ITALIC;
            break;
        case PK_TABLE: x = 1; break;
        default: break;
    }

    /* search hits on this line */
    size_t n = ln->end > ln->start ? ln->end - ln->start : 0;
    const char *t = p->text + ln->start;
    uint8_t hit[1024];
    size_t hn = n < sizeof hit ? n : sizeof hit;
    memset(hit, 0, hn);
    if (dv->search[0]) {
        size_t qn = strlen(dv->search);
        for (const char *m = ci_find(t, n, dv->search); m; m = ci_find(m + 1, n - (size_t)(m + 1 - t), dv->search))
            for (size_t k = (size_t)(m - t); k < (size_t)(m - t) + qn && k < hn; k++) hit[k] = 1;
    }

    wmove(win, y, x0 + x);
    for (size_t i = 0; i < n; ) {
        uint32_t cp;
        int len = utf8_decode(t + i, n - i, &cp);
        if (len < 1) len = 1;
        int cw = cp < 32 ? 1 : utf8_cp_width(cp);
        if (x + cw > w) break;
        uint8_t st = p->sty[ln->start + i];
        attr_t a = base;
        if (st & ST_BOLD)   a |= A_BOLD;
        if (st & ST_ITALIC) a |= A_ITALIC;
        if (st & ST_STRIKE) a |= A_DIM;
        if (st & ST_CODE)   a = with_pair(a, COLOR_PAIR_STRING);
        if (st & ST_LINK)   a = with_pair(a, COLOR_PAIR_TYPE) | A_UNDERLINE;
        if (i < hn && hit[i]) a = with_pair(a, COLOR_PAIR_SEARCH);
        wattron(win, a);
        if (cp < 32) waddch(win, ' ');
        else         waddnstr(win, t + i, len);
        wattroff(win, a);
        x += cw;
        i += (size_t)len;
    }
}

static int body_rows(int win_h) { return win_h > 1 ? win_h : 1; }

/* Text column: small margins, at most 100 columns, centered when the pane
 * is wider (long lines are hard to read). */
static void text_column(int win_w, int *x0, int *tw) {
    int margin = win_w >= 60 ? 3 : win_w >= 30 ? 1 : 0;
    int avail = win_w - 2 * margin - 1;              /* last column: scrollbar */
    if (avail < 8) avail = win_w > 8 ? win_w - 1 : win_w;
    int w = avail > 100 ? 100 : avail;
    *tw = w;
    *x0 = margin + (avail - w) / 2;
}

void doc_render(DocView *dv, WINDOW *win, int win_h, int win_w) {
    if (!dv || !win || win_h < 1 || win_w < 4) return;
    werase(win);
    int x0, tw;
    text_column(win_w, &x0, &tw);

    if (dv->npara && dv->wrap_w != tw) {
        /* re-wrap, keeping the paragraph at the top of the screen */
        int top_para = (dv->nlines && dv->scroll < dv->nlines) ? dv->lines[dv->scroll].para : 0;
        dv_layout(dv, tw);
        dv->scroll = 0;
        for (size_t i = 0; i < dv->nlines; i++) if (dv->lines[i].para >= top_para) { dv->scroll = i; break; }
    }
    int body = body_rows(win_h);
    size_t max_scroll = dv->nlines > (size_t)body ? dv->nlines - (size_t)body : 0;
    if (dv->scroll > max_scroll) dv->scroll = max_scroll;
    dv->view_rows = body;

    if (dv->npara == 0) {
        const char *msg = dv->err[0] ? dv->err : "Empty document";
        int len = text_width(msg);
        wattron(win, COLOR_PAIR(COLOR_PAIR_COMMENT));
        mvwaddnstr(win, win_h / 2, len < win_w ? (win_w - len) / 2 : 0, msg, win_w);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_COMMENT));
        wnoutrefresh(win);
        return;
    }
    for (int r = 0; r < body; r++) {
        size_t li = dv->scroll + (size_t)r;
        if (li >= dv->nlines) break;
        draw_line(dv, win, r, x0, tw, &dv->lines[li]);
    }
    /* scroll thumb on the right edge */
    if (dv->nlines > (size_t)body && body > 2) {
        int th = body * body / (int)dv->nlines;
        if (th < 1) th = 1;
        int ty = (int)((double)dv->scroll / (double)max_scroll * (body - th));
        wattron(win, COLOR_PAIR(COLOR_PAIR_LINENUM));
        for (int r = 0; r < body; r++) mvwaddstr(win, r, win_w - 1, r >= ty && r < ty + th ? "┃" : "│");
        wattroff(win, COLOR_PAIR(COLOR_PAIR_LINENUM));
    }
    wnoutrefresh(win);
}

/* ─── Keys & search ────────────────────────────────────────────── */

bool doc_handle_key(DocView *dv, int key, int win_h) {
    if (!dv) return false;
    size_t body = (size_t)body_rows(win_h);
    size_t page = body > 1 ? body - 1 : 1;
    size_t max = dv->nlines > body ? dv->nlines - body : 0;
    switch (key) {
        case KEY_UP: case 'k':    if (dv->scroll) dv->scroll--; break;
        case KEY_DOWN: case 'j':  if (dv->scroll < max) dv->scroll++; break;
        case KEY_PPAGE: case 'b': dv->scroll = dv->scroll > page ? dv->scroll - page : 0; break;
        case KEY_NPAGE: case ' ': dv->scroll = dv->scroll + page < max ? dv->scroll + page : max; break;
        case KEY_HOME: case 'g':  dv->scroll = 0; break;
        case KEY_END:  case 'G':  dv->scroll = max; break;
        default: return false;
    }
    return true;
}

bool doc_search(DocView *dv, const char *query, bool forward) {
    if (!dv || !query || !query[0] || dv->nlines == 0) return false;
    char q[sizeof dv->search];                 /* query may be dv->search itself */
    snprintf(q, sizeof q, "%s", query);
    bool same = strcmp(dv->search, q) == 0 && dv->match_line < dv->nlines;
    memcpy(dv->search, q, sizeof q);
    size_t n = dv->nlines;
    size_t start = same ? dv->match_line : (dv->scroll ? dv->scroll - 1 : n - 1);
    for (size_t k = 1; k <= n; k++) {
        size_t i = forward ? (start + k) % n : (start + n - k % n) % n;
        const DocLine *ln = &dv->lines[i];
        if (ln->rule) continue;
        const DocPara *p = &dv->paras[ln->para];
        if (ln->end > ln->start && ci_find(p->text + ln->start, ln->end - ln->start, q)) {
            dv->match_line = i;
            dv->scroll = i > 2 ? i - 2 : 0;
            return true;
        }
    }
    return false;
}

void doc_status(const DocView *dv, char *out, size_t out_sz) {
    if (!dv) { snprintf(out, out_sz, " [DOC] "); return; }
    size_t bottom = dv->scroll + (size_t)(dv->view_rows > 0 ? dv->view_rows : 1);
    int pct = dv->nlines ? (int)((bottom >= dv->nlines ? dv->nlines : bottom) * 100 / dv->nlines) : 100;
    snprintf(out, out_sz, " %s  ·  line %zu/%zu  ·  %d%%%s%.60s%s ",
             dv->fmt ? dv->fmt : "Document", dv->nlines ? dv->scroll + 1 : 0, dv->nlines, pct,
             dv->search[0] ? "  ·  find \"" : "", dv->search, dv->search[0] ? "\"" : "");
}
