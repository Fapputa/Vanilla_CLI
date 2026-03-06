#ifndef ABYSS_H
#define ABYSS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ncurses.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <signal.h>
#include <termios.h>
#include <ctype.h>
#include <time.h>

/* ─── Gap Buffer ─────────────────────────────────────────────── */
#define GAP_DEFAULT   4096
#define GAP_GROW      8192

typedef struct {
    char   *buf;
    size_t  gap_start;
    size_t  gap_end;
    size_t  cap;
} GapBuf;

GapBuf *gb_new(size_t cap);
void    gb_free(GapBuf *g);
size_t  gb_len(const GapBuf *g);
char    gb_at(const GapBuf *g, size_t i);
void    gb_move_gap(GapBuf *g, size_t pos);
void    gb_insert_char(GapBuf *g, size_t pos, char c);
void    gb_insert_str(GapBuf *g, size_t pos, const char *s, size_t n);
void    gb_delete(GapBuf *g, size_t pos, size_t n);
char   *gb_to_str(const GapBuf *g);
void    gb_get_range(const GapBuf *g, size_t start, size_t len, char *out);

/* ─── Line Index ─────────────────────────────────────────────── */
#define LINE_IDX_CHUNK 1024

typedef struct {
    size_t *offsets;
    size_t  count;
    size_t  cap;
    bool    dirty;
} LineIdx;

LineIdx *li_new(void);
void     li_free(LineIdx *li);
void     li_rebuild(LineIdx *li, const GapBuf *g);
size_t   li_line_start(const LineIdx *li, size_t line);
size_t   li_line_count(const LineIdx *li);
void     li_mark_dirty(LineIdx *li);

/* ─── Undo/Redo ──────────────────────────────────────────────── */
typedef enum { PIECE_ORIG, PIECE_ADD } PieceSource;

typedef struct {
    PieceSource src;
    size_t      start;
    size_t      len;
} Piece;

typedef struct UndoAction {
    GapBuf             *snapshot_buf;
    size_t              cursor_pos;
    struct UndoAction  *prev;
    struct UndoAction  *next;
} UndoAction;

typedef struct {
    UndoAction *head;
    UndoAction *current;
    int         depth;
} UndoStack;

UndoStack *us_new(void);
void       us_free(UndoStack *us);
void       us_push(UndoStack *us, const GapBuf *g, size_t cursor);
bool       us_undo(UndoStack *us, GapBuf **g_out, size_t *cursor_out);
bool       us_redo(UndoStack *us, GapBuf **g_out, size_t *cursor_out);

/* ─── Syntax / Lexer ─────────────────────────────────────────── */
typedef enum {
    TOK_NORMAL = 0,
    TOK_KEYWORD,
    TOK_TYPE,
    TOK_PREPROC,
    TOK_STRING,
    TOK_CHAR,
    TOK_COMMENT,
    TOK_NUMBER,
    TOK_IDENT,
    TOK_SEARCH,
    TOK_OPERATOR,
    _TOK_COUNT
} TokenType;

typedef enum {
    LANG_C, LANG_CPP, LANG_PY, LANG_SH,
    LANG_JS, LANG_JSON, LANG_SQL, LANG_ASM,
    LANG_HTML, LANG_CSS, LANG_PHP, LANG_CS,
    LANG_HEX,
    LANG_NONE
} Language;

typedef struct {
    TokenType *attrs;
    size_t     len;
    bool       dirty;
    int        lex_state_start;
    int        lex_state_end;
} LineAttr;

typedef struct {
    LineAttr  *lines;
    size_t     count;
    size_t     cap;
    Language   lang;
    char       search_word[256];
} SynCtx;

SynCtx  *syn_new(Language lang);
void     syn_free(SynCtx *s);
void     syn_mark_dirty_from(SynCtx *s, size_t line);
void     syn_ensure_line(SynCtx *s, size_t line, const GapBuf *g,
                         const LineIdx *li);
Language lang_from_ext(const char *ext);
TokenType syn_search_tok(TokenType base);

/* ─── Search ─────────────────────────────────────────────────── */
typedef struct {
    char    query[256];
    size_t *matches;
    size_t  count;
    size_t  cap;
    int     current;
} SearchCtx;

void search_find(SearchCtx *sc, const GapBuf *g);
void search_clear(SearchCtx *sc);

/* ─── Clipboard ──────────────────────────────────────────────── */
typedef struct {
    char  *text;
    size_t len;
} Clipboard;

typedef enum { HEX_FOCUS_HEX, HEX_FOCUS_ASCII } HexFocus;

typedef struct {
    uint8_t  *data;
    size_t    data_len;
    size_t    data_cap;
    size_t    cursor;
    int       nibble;
    HexFocus  focus;
    size_t    scroll_row;
    char      filename[4096];
    bool      modified;
    /* Recherche ASCII */
    char      search_query[256];
    size_t   *search_results;
    size_t    search_count;
    size_t    search_current;
} HexPane;

HexPane *hex_new(void);
void     hex_free(HexPane *h);
bool     hex_load(HexPane *h, const char *path);
bool     hex_save(HexPane *h, const char *path);
void     hex_scroll_to_cursor(HexPane *h, int win_h);
void     hex_search_ascii(HexPane *h, const char *query);
void     hex_render(HexPane *h, WINDOW *win, int win_h, int win_w);
bool     hex_handle_key(HexPane *h, int key, int win_h);
void     hex_colors_init(void);

/* ─── Pane ───────────────────────────────────────────────────── */
typedef struct {
    GapBuf    *buf;
    LineIdx   *li;
    SynCtx    *syn;
    UndoStack *undo;
    SearchCtx  search;
    Clipboard  clip;

    char    filename[4096];
    bool    modified;
    bool    crlf;         /* file used CRLF line endings */
    Language lang;

    size_t  cursor;
    size_t  cursor_line;
    size_t  cursor_col;
    size_t  preferred_col;   /* sticky column for vertical navigation */

    size_t  scroll_line;
    size_t  scroll_col;

    bool    sel_active;
    size_t  sel_anchor;

    WINDOW *win;
    int     win_y, win_x, win_h, win_w;

    bool   *line_dirty;
    char  **prev_render;
    int     prev_render_rows;
    size_t  last_cursor_row;

    bool    show_line_numbers;

    /* Hex mode */
    bool      hex_mode;
    HexPane  *hex;
} Pane;

Pane *pane_new(void);
void  pane_free(Pane *p);
void  pane_open_file(Pane *p, const char *path);
bool  pane_save_file(Pane *p, const char *path);
void  pane_set_window(Pane *p, WINDOW *w, int y, int x, int h, int ww);
void  pane_render(Pane *p, bool force);
void  pane_insert_char(Pane *p, char c);
void  pane_insert_str(Pane *p, const char *s, size_t n);
void  pane_delete_char(Pane *p);
void  pane_delete_forward(Pane *p);
void  pane_move_cursor(Pane *p, int dy, int dx);
void  pane_move_to_line_col(Pane *p, size_t line, size_t col);
void  pane_scroll_to_cursor(Pane *p);
void  pane_kill_line(Pane *p);
void  pane_kill_whole_line(Pane *p);
void  pane_undo(Pane *p);
void  pane_redo(Pane *p);
void  pane_copy(Pane *p);
void  pane_cut(Pane *p);
void  pane_paste(Pane *p);
void  pane_search_next(Pane *p);
void  pane_search_prev(Pane *p);
void  pane_cursor_line_col(const Pane *p, size_t *line, size_t *col);
void  pane_push_undo(Pane *p);
void  pane_wipe_file(Pane *p);

/* ─── Editor (global state) ──────────────────────────────────── */
#define MAX_PANES 4

typedef enum {
    MODE_NORMAL,
    MODE_SAVE_DIALOG,
    MODE_SEARCH_DIALOG,
    MODE_OPEN_DIALOG,
    MODE_GOTO_LINE,
    MODE_HEX_JUMP,
    MODE_HEX_SEARCH,
} EditorMode;

typedef struct {
    Pane      *panes[MAX_PANES];
    int        npanes;
    int        active;
    EditorMode mode;

    char       dialog_buf[4096];
    size_t     dialog_cursor;
    int        dialog_action;

    WINDOW    *out_win;
    char      *out_text;
    size_t     out_scroll;
    bool       out_visible;

    WINDOW    *status_win;
    WINDOW    *title_win;

    pid_t      run_pid;
    char       run_output[1<<16];

    bool       running;
    bool       show_shortcuts;

    pthread_t  save_thread;
    bool       save_pending;
    char       save_path[4096];
    char      *save_buf;
    size_t     save_len;
    pthread_mutex_t save_mutex;
} Editor;

extern Editor E;

void editor_init(void);
void editor_run(const char *initial_file);
void editor_cleanup(void);
void editor_split(void);
void editor_close_split(void);
void editor_focus_next(void);
void editor_resize_panes(void);

/* ─── Run / Build ────────────────────────────────────────────── */
void run_file(const char *path, Language lang, char *out_buf, size_t out_max);
void run_async(const char *path, Language lang);

/* ─── Colour pairs ───────────────────────────────────────────── */
#define COLOR_PAIR_NORMAL          1
#define COLOR_PAIR_KEYWORD         2
#define COLOR_PAIR_TYPE            3
#define COLOR_PAIR_PREPROC         4
#define COLOR_PAIR_STRING          5
#define COLOR_PAIR_COMMENT         6
#define COLOR_PAIR_NUMBER          7
#define COLOR_PAIR_IDENT           8
#define COLOR_PAIR_SEARCH          9
#define COLOR_PAIR_TITLE          10
#define COLOR_PAIR_STATUS         11
#define COLOR_PAIR_LINENUM        12
#define COLOR_PAIR_CURSOR         13
#define COLOR_PAIR_OPERATOR       14
#define COLOR_PAIR_ACTIVE_BORDER  15
#define COLOR_PAIR_INACTIVE_BORDER 16
#define COLOR_PAIR_SELECTION      17
#define COLOR_PAIR_CHAR           18
/* Hex editor colour pairs */
#define HEX_CP_OFFSET             19
#define HEX_CP_ZERO               20
#define HEX_CP_PRINT              21
#define HEX_CP_NONPRINT           22
#define HEX_CP_CURSOR_H           23
#define HEX_CP_CURSOR_A           24
#define HEX_CP_PEER               25
#define HEX_CP_MODIFIED           26
#define HEX_CP_HEADER             27

void colors_init(void);
int  tok_to_color_pair(TokenType t);

/* ─── Arena Allocator ────────────────────────────────────────── */
typedef struct ArenaBlock {
    struct ArenaBlock *next;
    size_t used;
    size_t cap;
    char   data[];
} ArenaBlock;

typedef struct { ArenaBlock *head; } Arena;

Arena *arena_new(size_t block_size);
void  *arena_alloc(Arena *a, size_t n);
void   arena_free(Arena *a);

/* ─── Utilities ──────────────────────────────────────────────── */
static inline size_t min_sz(size_t a, size_t b) { return a < b ? a : b; }
static inline size_t max_sz(size_t a, size_t b) { return a > b ? a : b; }

#endif /* ABYSS_H */