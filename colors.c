#include "abyss.h"

/* Custom RGB palette (Monokai-inspired, high contrast). Used when the terminal
 * can redefine colors; otherwise we fall back to bright ANSI. Indices 16..31
 * are reserved here so they never collide with the dynamic swatch pool. */
enum {
    SC_FG = 16, SC_KEYWORD, SC_TYPE, SC_PREPROC, SC_STRING,
    SC_CHAR, SC_COMMENT, SC_NUMBER, SC_OPERATOR, SC_LINENUM, SC_ACCENT
};

static short g_bg = -1;   /* fond des pairs de texte */

static void set_rgb(short idx, unsigned rgb) {
    init_color(idx,
               (int)(((rgb >> 16) & 0xFF) * 1000 / 255),
               (int)(((rgb >>  8) & 0xFF) * 1000 / 255),
               (int)(( rgb        & 0xFF) * 1000 / 255));
}

/* ─── Windows theme ─────────────────────────────────────────────
 * The Windows console cannot redefine colors reliably and has no usable
 * "default" background, so the editor uses a fixed xterm-256 theme
 * there: a dark Monokai-like syntax palette, a deep red title bar, a
 * slate status bar, blue selections. colors_win_polish() then brings
 * the other panels (tree, inspector, hex, smart highlight), which ask
 * for the 8 basic colors on a -1 background, onto the same theme. */

static bool g_theme256 = false;

/* basic color -> theme color, as a foreground / as a background */
static const short fg_map[8] = { 16, 203, 114, 221, 75, 176, 80, 252 };
static const short bg_map[8] = { 0,  124, 29,  178, 25, 97,  31, 250 };

static short polish_fg(short f, bool on_color) {
    if (f < 0)  return on_color ? 231 : 252;
    if (f < 8)  return (on_color && f == COLOR_BLACK) ? 16 : (on_color && f == COLOR_WHITE) ? 231 : fg_map[f];
    if (f < 16) return fg_map[f - 8];
    return f;
}

void colors_win_polish(void) {
    if (!g_theme256) {
        /* 16-color console: at least never ask for the -1 background */
        for (short p = 1; p < 200 && p < COLOR_PAIRS; p++) {
            short f, b;
            if (pair_content(p, &f, &b) != OK) continue;
            if (b == -1 || f == -1)
                init_pair(p, f == -1 ? COLOR_WHITE : f, b == -1 ? g_bg : b);
        }
        return;
    }
    /* core editor pairs (1..18) are set by colors_init; swatches live at 200+ */
    for (short p = 19; p < SWATCH_PAIR_BASE && p < COLOR_PAIRS; p++) {
        short f, b;
        if (pair_content(p, &f, &b) != OK) continue;
        if (f == 0 && b == 0) continue;                 /* never initialised */
        bool colored_bg = b > 0 && b != COLOR_BLACK;
        short nb = (b < 0 || b == COLOR_BLACK) ? g_bg : (b < 8 ? bg_map[b] : b);
        short nf = polish_fg(f, colored_bg);
        if (nf != f || nb != b) init_pair(p, nf, nb);
    }
}

/* Pair 99: notifications on the right of the status bar. */
int colors_notify_pair(void) {
    static bool done = false;
    if (!done) {
        if (g_theme256) init_pair(99, 231, 161);
        else            init_pair(99, COLOR_WHITE, COLOR_RED);
        done = true;
    }
    return 99;
}

void colors_init(void) {
    start_color();
    g_bg = (use_default_colors() == OK) ? -1 : COLOR_BLACK;
#ifdef _WIN32
    g_bg = COLOR_BLACK;   /* le fond -1 ne marche pas avec la console Windows */
#endif

    bool truecolor = has_colors() && can_change_color() && COLORS >= 32;
#ifdef _WIN32
    truecolor = false;   /* init_color n'est pas fiable sous Windows : on utilise la palette xterm-256 */
#endif
    g_theme256 = !truecolor && COLORS >= 256;

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
    } else if (g_theme256) {
        /* Monokai on the fixed xterm-256 palette */
        fg_norm=253;              /* #dadada text             */
        fg_kw=204;                /* #ff5f87 keywords         */
        fg_type=81;               /* #5fd7ff types            */
        fg_prep=149;              /* #afd75f #include         */
        fg_str=222;               /* #ffd787 strings          */
        fg_char=215;              /* #ffaf5f chars            */
        fg_cmt=244;               /* #808080 comments         */
        fg_num=141;               /* #af87ff numbers          */
        fg_op=211;                /* #ff87af operators        */
        fg_lnum=239;              /* #4e4e4e gutter           */
        fg_accent=81;
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

    init_pair(COLOR_PAIR_NORMAL,    fg_norm,   g_bg);
    init_pair(COLOR_PAIR_KEYWORD,   fg_kw,     g_bg);
    init_pair(COLOR_PAIR_TYPE,      fg_type,   g_bg);
    init_pair(COLOR_PAIR_PREPROC,   fg_prep,   g_bg);
    init_pair(COLOR_PAIR_STRING,    fg_str,    g_bg);
    init_pair(COLOR_PAIR_COMMENT,   fg_cmt,    g_bg);
    init_pair(COLOR_PAIR_NUMBER,    fg_num,    g_bg);
    init_pair(COLOR_PAIR_IDENT,     fg_norm,   g_bg);
    init_pair(COLOR_PAIR_LINENUM,   fg_lnum,   g_bg);
    init_pair(COLOR_PAIR_OPERATOR,  fg_op,     g_bg);
    init_pair(COLOR_PAIR_ACTIVE_BORDER,   fg_accent, g_bg);
    init_pair(COLOR_PAIR_CHAR,      fg_char,   g_bg);
    if (g_theme256) {
        init_pair(COLOR_PAIR_SEARCH,    16,  220);   /* black on amber            */
        init_pair(COLOR_PAIR_TITLE,     231, 88);    /* white on deep red         */
        init_pair(COLOR_PAIR_STATUS,    252, 237);   /* light gray on slate       */
        init_pair(COLOR_PAIR_CURSOR,    231, 238);
        init_pair(COLOR_PAIR_INACTIVE_BORDER, 240, g_bg);
        init_pair(COLOR_PAIR_SELECTION, 231, 25);    /* white on blue             */
    } else {
        init_pair(COLOR_PAIR_SEARCH,    COLOR_BLACK,   COLOR_YELLOW);
        init_pair(COLOR_PAIR_TITLE,     COLOR_WHITE,   COLOR_RED);
        init_pair(COLOR_PAIR_STATUS,    COLOR_BLACK,   COLOR_WHITE);
        init_pair(COLOR_PAIR_CURSOR,    COLOR_WHITE,   COLOR_BLACK);
        init_pair(COLOR_PAIR_INACTIVE_BORDER, COLOR_WHITE, g_bg);
        init_pair(COLOR_PAIR_SELECTION, COLOR_BLACK,   COLOR_CYAN);
    }

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
#ifdef _WIN32
    swatch_ok = false;   /* init_color peu fiable sous Windows */
#endif
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
    init_pair(pair, cidx, g_bg);
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
