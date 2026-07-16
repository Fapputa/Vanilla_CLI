#include "abyss.h"

/* Custom RGB palette (Monokai-inspired, high contrast). Used when the terminal
 * can redefine colors; otherwise we fall back to bright ANSI. Indices 16..31
 * are reserved here so they never collide with the dynamic swatch pool. */
enum {
    SC_FG = 16, SC_KEYWORD, SC_TYPE, SC_PREPROC, SC_STRING,
    SC_CHAR, SC_COMMENT, SC_NUMBER, SC_OPERATOR, SC_LINENUM, SC_ACCENT
};

static void set_rgb(short idx, unsigned rgb) {
    init_color(idx,
               (int)(((rgb >> 16) & 0xFF) * 1000 / 255),
               (int)(((rgb >>  8) & 0xFF) * 1000 / 255),
               (int)(( rgb        & 0xFF) * 1000 / 255));
}

void colors_init(void) {
    start_color();
    use_default_colors();

    bool truecolor = has_colors() && can_change_color() && COLORS >= 32;

    /* Foreground color index chosen per token, resolved from the palette below. */
    short fg_norm, fg_kw, fg_type, fg_prep, fg_str, fg_char,
          fg_cmt, fg_num, fg_op, fg_lnum, fg_accent;

    if (truecolor) {
        set_rgb(SC_FG,       0xF8F8F2);  /* soft white   */
        set_rgb(SC_KEYWORD,  0xF92672);  /* vivid pink   – if/for/return */
        set_rgb(SC_TYPE,     0x66D9EF);  /* cyan         – int/class     */
        set_rgb(SC_PREPROC,  0xA6E22E);  /* green        – #include      */
        set_rgb(SC_STRING,   0xE6DB74);  /* warm yellow  */
        set_rgb(SC_CHAR,     0xFFB86C);  /* orange       */
        set_rgb(SC_COMMENT,  0x9A8F7A);  /* readable gray*/
        set_rgb(SC_NUMBER,   0xAE81FF);  /* purple       */
        set_rgb(SC_OPERATOR, 0xF92672);  /* pink accent  */
        set_rgb(SC_LINENUM,  0x5C6370);  /* dim gutter   */
        set_rgb(SC_ACCENT,   0x66D9EF);  /* cyan accent  */
        fg_norm=SC_FG; fg_kw=SC_KEYWORD; fg_type=SC_TYPE; fg_prep=SC_PREPROC;
        fg_str=SC_STRING; fg_char=SC_CHAR; fg_cmt=SC_COMMENT; fg_num=SC_NUMBER;
        fg_op=SC_OPERATOR; fg_lnum=SC_LINENUM; fg_accent=SC_ACCENT;
    } else if (COLORS >= 16) {
        /* Bright ANSI (indices 8..15) — much punchier than the dim 0..7. */
        fg_norm=15; fg_kw=13; fg_type=14; fg_prep=10; fg_str=11;
        fg_char=11; fg_cmt=8; fg_num=13; fg_op=13; fg_lnum=8; fg_accent=14;
    } else {
        fg_norm=COLOR_WHITE; fg_kw=COLOR_CYAN; fg_type=COLOR_GREEN;
        fg_prep=COLOR_MAGENTA; fg_str=COLOR_YELLOW; fg_char=COLOR_YELLOW;
        fg_cmt=COLOR_BLUE; fg_num=COLOR_RED; fg_op=COLOR_WHITE;
        fg_lnum=COLOR_CYAN; fg_accent=COLOR_CYAN;
    }

    init_pair(COLOR_PAIR_NORMAL,    fg_norm,   -1);
    init_pair(COLOR_PAIR_KEYWORD,   fg_kw,     -1);
    init_pair(COLOR_PAIR_TYPE,      fg_type,   -1);
    init_pair(COLOR_PAIR_PREPROC,   fg_prep,   -1);
    init_pair(COLOR_PAIR_STRING,    fg_str,    -1);
    init_pair(COLOR_PAIR_COMMENT,   fg_cmt,    -1);
    init_pair(COLOR_PAIR_NUMBER,    fg_num,    -1);
    init_pair(COLOR_PAIR_IDENT,     fg_norm,   -1);
    init_pair(COLOR_PAIR_SEARCH,    COLOR_BLACK,   COLOR_YELLOW);
    init_pair(COLOR_PAIR_TITLE,     COLOR_WHITE,   COLOR_RED);
    init_pair(COLOR_PAIR_STATUS,    COLOR_BLACK,   COLOR_WHITE);
    init_pair(COLOR_PAIR_LINENUM,   fg_lnum,   -1);
    init_pair(COLOR_PAIR_CURSOR,    COLOR_WHITE,   COLOR_BLACK);
    init_pair(COLOR_PAIR_OPERATOR,  fg_op,     -1);
    init_pair(COLOR_PAIR_ACTIVE_BORDER,   fg_accent, -1);
    init_pair(COLOR_PAIR_INACTIVE_BORDER, COLOR_WHITE, -1);
    init_pair(COLOR_PAIR_SELECTION, COLOR_BLACK,   COLOR_CYAN);
    init_pair(COLOR_PAIR_CHAR,      fg_char,   -1);

    colors_swatch_init();
}

/* ---- inline RGB color swatches ------------------------------------------ */

static struct { unsigned rgb; short pair; } swatch_cache[SWATCH_MAX];
static int   swatch_n     = 0;
static short swatch_color = 0;      /* next free custom color slot */
static bool  swatch_ok    = false;

void colors_swatch_init(void) {
    swatch_n     = 0;
    swatch_color = 32;              /* 0-15 ANSI, 16-31 reserved for syntax */
    swatch_ok    = has_colors() && can_change_color() &&
                   COLORS >= 48 && COLOR_PAIRS > SWATCH_PAIR_BASE + SWATCH_MAX;
}

int colors_swatch_pair(unsigned rgb) {
    if (!swatch_ok) return 0;
    rgb &= 0xFFFFFFu;
    for (int i = 0; i < swatch_n; i++)
        if (swatch_cache[i].rgb == rgb) return swatch_cache[i].pair;
    if (swatch_n >= SWATCH_MAX || swatch_color >= (short)COLORS)
        return swatch_n ? swatch_cache[swatch_n - 1].pair : 0;  /* pool full */

    short cidx = swatch_color++;
    int r = (int)((rgb >> 16) & 0xFF);
    int g = (int)((rgb >>  8) & 0xFF);
    int b = (int)( rgb        & 0xFF);
    init_color(cidx, r * 1000 / 255, g * 1000 / 255, b * 1000 / 255);

    short pair = (short)(SWATCH_PAIR_BASE + swatch_n);
    init_pair(pair, cidx, -1);
    swatch_cache[swatch_n].rgb  = rgb;
    swatch_cache[swatch_n].pair = pair;
    swatch_n++;
    return pair;
}

int tok_to_color_pair(TokenType t) {
    switch (t) {
        case TOK_KEYWORD:  return COLOR_PAIR_KEYWORD;
        case TOK_TYPE:     return COLOR_PAIR_TYPE;
        case TOK_PREPROC:  return COLOR_PAIR_PREPROC;
        case TOK_STRING:   return COLOR_PAIR_STRING;
        case TOK_CHAR:     return COLOR_PAIR_CHAR;
        case TOK_COMMENT:  return COLOR_PAIR_COMMENT;
        case TOK_NUMBER:   return COLOR_PAIR_NUMBER;
        case TOK_SEARCH:   return COLOR_PAIR_SEARCH;
        case TOK_OPERATOR: return COLOR_PAIR_OPERATOR;
        default:           return COLOR_PAIR_NORMAL;
    }
}

#define ARENA_BLOCK_SIZE 65536

Arena *arena_new(size_t block_size) {
    if (block_size < 4096) block_size = 4096;
    Arena *a = malloc(sizeof *a);
    a->head = malloc(sizeof(ArenaBlock) + block_size);
    a->head->next = NULL;
    a->head->used = 0;
    a->head->cap  = block_size;
    return a;
}

void *arena_alloc(Arena *a, size_t n) {
    n = (n + 7) & ~(size_t)7; 
    if (a->head->used + n > a->head->cap) {
        size_t bsz = n > ARENA_BLOCK_SIZE ? n : ARENA_BLOCK_SIZE;
        ArenaBlock *b = malloc(sizeof(ArenaBlock) + bsz);
        b->next = a->head;
        b->used = 0;
        b->cap  = bsz;
        a->head = b;
    }
    void *ptr = a->head->data + a->head->used;
    a->head->used += n;
    return ptr;
}

void arena_free(Arena *a) {
    ArenaBlock *b = a->head;
    while (b) { ArenaBlock *n = b->next; free(b); b = n; }
    free(a);
}
