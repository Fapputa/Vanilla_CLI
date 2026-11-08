#ifndef ABYSS_H
#define ABYSS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef _WIN32
/* ncurses formats printw() & co with the C99 vsnprintf of UCRT: checked as such (the
 * "printf" archetype of MinGW's GCC is the old msvcrt one, which knows no %zu) */
#  ifndef GCC_PRINTFLIKE
#    define GCC_PRINTFLIKE(fmt, var) __attribute__((format(gnu_printf, fmt, var)))
#  endif
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
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>

#ifdef _WIN32
#  include <io.h>
#  include <limits.h>
#  ifndef PATH_MAX
#    define PATH_MAX 260
#  endif
#  define realpath(p, r) _fullpath((r), (p), PATH_MAX)
#  define PROT_READ    1
#  define MAP_PRIVATE  2
#  define MAP_FAILED   ((void *)-1)
#  define lstat        stat
#  ifndef S_ISLNK
#    define S_ISLNK(m) 0
#  endif

/* mmap en lecture seule émulé : on lit le fichier dans un buffer */
static inline void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
    (void)addr; (void)prot; (void)flags;
    void *p = malloc(len ? len : 1);
    if (!p) return MAP_FAILED;
    off_t saved = lseek(fd, 0, SEEK_CUR);
    _setmode(fd, _O_BINARY);
    if (lseek(fd, off, SEEK_SET) < 0) { free(p); return MAP_FAILED; }
    size_t got = 0;
    while (got < len) {
        int r = read(fd, (char *)p + got, (unsigned)(len - got));
        if (r <= 0) break;
        got += (size_t)r;
    }
    lseek(fd, saved, SEEK_SET);
    if (got != len) { free(p); return MAP_FAILED; }
    return p;
}
static inline int munmap(void *p, size_t len) { (void)len; free(p); return 0; }

/* winsize.c: the console (before initscr) and Abyss's own folder, %LOCALAPPDATA%\abyss */
int  win_console_size(int *rows, int *cols);
void win_init_utf8(void);                       /* console checked, VT + UTF-8, or exit 1 */
const char *win_console_note(void);             /* for the status bar, NULL if none */
const char *win_appdir(void);                   /* created if missing; NULL, errno set */
int  win_apppath(char *out, size_t sz, const char *name);   /* <appdir>\name; 0, errno set */
#define WIN_KEY_CHAR 0x40000000                  /* | a typed UTF-16 unit, from winsize.c */
int  win_key_utf8(int key, unsigned char b[4]);  /* its UTF-8 bytes; 0 half a pair; -1 not one */
#else
#  include <sys/mman.h>
#  include <sys/wait.h>
#  include <termios.h>
#endif

#ifdef _WIN32
static inline const char *home_dir(void) {
    const char *h = getenv("USERPROFILE");
    return h ? h : getenv("HOME");
}
#else
static inline const char *home_dir(void) { return getenv("HOME"); }
#endif

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
    LANG_RUST,
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
    size_t     valid_upto;   /* lines [0, valid_upto) are computed & up to date */
    Language   lang;
    char       search_word[256];
} SynCtx;

SynCtx   *syn_new(Language lang);
void      syn_free(SynCtx *s);
void      syn_mark_dirty_from(SynCtx *s, size_t line);
void      syn_ensure_line(SynCtx *s, size_t line, const GapBuf *g,
                          const LineIdx *li);
Language  lang_from_ext(const char *ext);
TokenType syn_search_tok(TokenType base);

typedef struct {
    char    query[256];
    size_t *matches;
    size_t  count;
    size_t  cap;
    int     current;
} SearchCtx;

void search_find(SearchCtx *sc, const GapBuf *g);
void search_clear(SearchCtx *sc);

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

typedef enum {
    HLCAT_HTTP = 0,
    HLCAT_SENSITIVE,
    HLCAT_IP,
    HLCAT_DATE,
    HLCAT_WORD,
    HLCAT_COUNT
} HLCat;

typedef struct {
    size_t  offset;
    size_t  len;
    HLCat   cat;
    int     cp;
    char    text[64];
} HLMatch;

#define HL_MAX_MATCHES 524288
#define HL_TOP_WORDS   40

typedef struct {
    char   word[64];
    size_t count;
    HLCat  cat;
} HLWordCount;

#define HL_KW_MAX  128
#define HL_IP_MAX  4096
#define HL_DT_MAX  2048

typedef struct {
    const char *word;
    size_t      count;
} HLKwCount;

typedef struct { char ip[64]; size_t cnt; } HLIPEntry;
typedef struct { char dt[64]; size_t cnt; } HLDTEntry;

typedef struct HLCtx {
    HLMatch    *matches;       
    size_t      nmatch;

    HLWordCount top[HL_TOP_WORDS];
    int         ntop;

    size_t      cat_count[HLCAT_COUNT];

    HLKwCount   http_kw[HL_KW_MAX];
    int         http_nkw;
    HLKwCount   sens_kw[HL_KW_MAX];
    int         sens_nkw;

    
    HLIPEntry   ips[HL_IP_MAX];
    int         nips;
    HLDTEntry   dts[HL_DT_MAX];
    int         ndts;

    bool        dirty;
    bool        visible;
    int         width;
    int         scroll;
    WINDOW     *win;
} HLCtx;

/* Above this buffer size, Smart Highlight rescans triggered by edits are
 * deferred until the keyboard goes idle, so typing never blocks on a scan. */
#define HL_DEFER_BYTES  (4u * 1024u * 1024u)

extern void (*hl_progress_fn)(size_t done, size_t total);

HLCtx      *hl_new(void);
void        hl_free(HLCtx *h);
void        hl_scan(HLCtx *h, const GapBuf *g);
void        hl_render(HLCtx *h, WINDOW *win, int win_h, int win_w);
void        hl_colors_init(void);
const HLMatch *hl_match_at(const HLCtx *h, size_t byte_off);

/* ─── Memory editor (F8, memview.c + memscan.c) ──────────
 * Process list first, then Cheat Engine style scans of the chosen
 * process's memory, live values, writes, frozen addresses, hex view. */
void mem_ui_enter(void);
void mem_ui_render(WINDOW *win, int h, int w);
bool mem_ui_key(int key, int win_h);
void mem_ui_status(char *out, size_t sz);
int  mem_ui_dialog(char *title, size_t tsz, char *fill, size_t fsz);   /* pending input */
void mem_ui_dialog_done(int kind, const char *text);
void mem_ui_tick(void);
int  mem_ui_timeout(bool visible);
bool mem_ui_refresh_due(void);       /* a second since the last F8 draw */
bool mem_ui_picking(void);
void mem_ui_shutdown(void);

#define HIGHLIGHT_DEFAULT_W  34
#define HIGHLIGHT_MIN_W      28
#define HIGHLIGHT_MAX_W      52

/* ─── Table view (F6) ──────────────────────────────────────
 * Read-only grid over structured data: CSV/TSV/PSV, JSON, JSON Lines,
 * SQL dumps (CREATE TABLE / INSERT / COPY), Markdown & psql tables and
 * SQLite databases (through the sqlite3 CLI). A source may hold several
 * tables ("sheets"); Tab cycles them. Data-only formats open in it
 * automatically, everything else toggles with F6. */

#define TABLE_MAX_ROWS   200000
#define TABLE_MAX_COLW   40
#define TABLE_MAX_SHEETS 64

typedef struct Arena Arena;

/* F9 static analysis view (disview.c / disview.h) */
typedef struct DisView DisView;

/* Where a cell came from in the source text, so an edit made in the grid
 * can be written back in place (keeping the rest of the file untouched).
 * `kind` says how the new value must be encoded (CSV quoting, JSON string,
 * SQL literal...); 0 means the cell has no editable source. */
enum { SPK_NONE = 0, SPK_CSV, SPK_JSTR, SPK_JRAW, SPK_SQL, SPK_COPY, SPK_MD };

typedef struct {
    size_t   off;
    uint32_t len;
    uint8_t  kind;
} TblSpan;

typedef struct {
    char    name[128];
    char  **hdr;        /* ncols headers                            */
    char  **cells;      /* nrows * ncols, row-major; NULL = missing */
    size_t  nrows;
    int     ncols;
    int    *colw;       /* display width of each column             */
    bool   *numeric;    /* mostly numbers: right-aligned            */
    bool    truncated;  /* stopped at TABLE_MAX_ROWS                */
    TblSpan   *span;    /* nrows * ncols source positions, or NULL  */
    long long *rowid;   /* SQLite rowid of each row, or NULL        */
    size_t    *perm;    /* display order (sort / filter), NULL = as is */
    size_t     nview;   /* rows shown: nrows, or fewer when filtered  */
} TblSheet;

/* One entry of the column filter dropdown ('f'): a distinct value of the
 * column and how many rows hold it. val NULL = the cell is missing. */
typedef struct {
    const char *val;
    size_t      count;
} TblValue;

/* A column filter ('f'): the rows whose cell in `col` is one of `vals`
 * (or missing, when `missing`) are kept. Filters on several columns
 * combine: a row is shown when it passes them all. */
#define TABLE_MAX_FILT 16

typedef struct {
    int    col;
    char **vals;                   /* kept values, malloc'd, strcmp order */
    int    nvals;
    bool   missing;                /* missing cells are kept too        */
} TblFilter;

typedef struct {
    bool      open;
    int       col;
    bool      touched;             /* a box was ticked / unticked       */
    size_t    total;               /* rows the other filters leave      */
    bool     *on;                  /* nvals: the value is ticked        */
    TblValue *vals;  int nvals;    /* values of those rows, sorted      */
    int      *idx;   int nidx;     /* entries shown: -1 = "(all)"       */
    int       sel, scroll;
    int       width;               /* widest value, display columns     */
    char      q[64];               /* typed text narrowing the list     */
} TblMenu;

/* One key of the sort ('s'): keys combine, the first one counts most and
 * the next ones order the rows it leaves equal. */
#define TABLE_MAX_SORT 8

typedef struct {
    int col;
    int dir;                       /* 1 ascending, -1 descending        */
} TblSortKey;

typedef struct {
    Arena      *arena;
    TblSheet   *sheets;
    int         nsheets;
    int         cur;
    const char *fmt;
    size_t      row, scroll_row;   /* row = display row (after sorting) */
    int         col, scroll_col;
    char        err[192];
    char        search[256];
    TblSortKey  sort[TABLE_MAX_SORT]; /* sort keys, main one first      */
    int         nsort;             /* 0 = unsorted                      */
    char        delim;            /* CSV-like sources: the separator   */
    bool        from_hex;          /* built from the hex buffer         */
    bool        sqlite;
    char        path[4096];        /* SQLite database (for UPDATEs)     */
    TblFilter   filt[TABLE_MAX_FILT]; /* column filters, all must pass  */
    int         nfilt;             /* 0 = not filtered                  */
    TblMenu     menu;              /* 'f': dropdown of a column's values */
} TableView;

TableView  *tbl_new(void);
void        tbl_free(TableView *tv);
bool        tbl_load_text(TableView *tv, const char *path, const char *text,
                          size_t len, Language lang);
bool        tbl_load_sqlite(TableView *tv, const char *path);
bool        tbl_is_sqlite(const unsigned char *data, size_t len);
bool        tbl_auto_ext(const char *path);
void        tbl_render(TableView *tv, WINDOW *win, int win_h, int win_w);
bool        tbl_handle_key(TableView *tv, int key, int win_h);
bool        tbl_search(TableView *tv, const char *query, bool forward);
const char *tbl_cell(const TableView *tv, size_t row, int col);
void        tbl_status(const TableView *tv, char *out, size_t out_sz);
size_t      tbl_phys_row(const TblSheet *t, size_t display_row);
/* Sets the direction of `col` among the sort keys (a new column becomes
 * the last key, dir 0 drops it); col -1 removes every key. */
void        tbl_sort(TableView *tv, int col, int dir);
void        tbl_sort_cycle(TableView *tv);
/* Index of `col` among the sort keys, -1 when it is not sorted. */
int         tbl_sort_key(const TableView *tv, int col);
/* Column filter: only the rows whose cell in `col` is one of `vals` (or
 * missing, when `missing`) are shown, together with the other columns'
 * filters. No value and not `missing` drops the column's filter; col -1
 * drops every filter. */
void        tbl_filter(TableView *tv, int col, const char *const *vals, int nvals, bool missing);
/* Index of `col` among the filters, -1 when it is not filtered. */
int         tbl_filter_index(const TableView *tv, int col);
void        tbl_filter_menu_open(TableView *tv);
bool        tbl_filter_menu_key(TableView *tv, int key, int win_h);
bool        tbl_cell_editable(const TableView *tv, char *why, size_t why_sz);
/* 'w': writes the rows the grid shows (sort and filters applied, in that
 * order) of the current table to `path`, in the format of the source
 * (CSV stays CSV, SQL dump stays SQL, SQLite gives a new database...). */
struct Pane;
bool        pane_table_export(struct Pane *p, const char *path, char *msg, size_t msg_sz);
/* Default name for that copy: next to the source, "<name>_view.<ext>". */
void        tbl_export_suggest(const struct Pane *p, const char *fallback_dir,
                               char *out, size_t out_sz);

/* Runs argv[0] (no shell) and captures its stdout; stderr is dropped.
 * Returns the exit code, 127 when the program could not be started. */
int         proc_capture(char *const argv[], char **out, size_t *out_len);
/* true when `prog` can be found on PATH */
bool        proc_have(const char *prog);

/* ─── Image view ───────────────────────────────────────────
 * Pictures are decoded by the built-in decoders (imgdecode.c: PNG,
 * JPEG, GIF, BMP, ICO, PNM, TGA, QOI) and drawn with half-block
 * characters, two pixels per cell, dithered to the 256-color palette.
 * Re-laid out whenever the pane changes size. chafa, when installed, is
 * only used for the formats the decoders do not read (WebP, SVG...). */
typedef struct {
    char     path[4096];
    bool     loaded;           /* decoding attempted                      */
    int      bw, bh;           /* working bitmap (shrunk to <= 1024 px)  */
    uint8_t *rgba;
    int      src_w, src_h;     /* size in the file                        */
    char     fmt[32];
    bool     dither;
    int      req_w, req_h;     /* pane size the cells were built for      */
    int      cols, rows;       /* cell grid                               */
    short   *top, *bot;        /* color of each half cell, -1 = background */
    bool     half;             /* two pixels per cell (else one)          */
    int      img_x, img_y, img_w, img_h;   /* picture area, in cells      */
    bool     use_chafa;        /* fallback for unsupported formats        */
    char    *art;
    size_t   art_len;
    char     err[256];
} ImageView;

bool        img_is_image(const char *path);
ImageView  *img_new(const char *path);
void        img_free(ImageView *iv);
void        img_reload(ImageView *iv);
void        img_toggle_dither(ImageView *iv);
void        img_render(ImageView *iv, WINDOW *win, int win_h, int win_w);

/* ─── Document view ────────────────────────────────────────
 * Read-only, word-wrapped rendering of documents: Markdown (from the
 * buffer), PDF (pdftotext / mutool), Word .docx, OpenDocument .odt,
 * and anything pandoc can read. */
typedef struct DocPara DocPara;

typedef struct {
    char     path[4096];
    const char *fmt;
    DocPara *paras;
    int      npara, cap;
    /* wrapped layout, rebuilt when the width changes */
    struct DocLine *lines;
    size_t   nlines, lcap;
    int      wrap_w;
    int      view_rows;   /* rows shown at the last render */
    size_t   scroll;
    char     search[256];
    size_t   match_line;
    char     err[256];
} DocView;

bool        doc_is_binary_doc(const char *path);   /* pdf, docx, odt... */
bool        doc_is_markdown(const char *path);
DocView    *doc_new(void);
void        doc_free(DocView *dv);
bool        doc_load_file(DocView *dv, const char *path);
bool        doc_load_markdown(DocView *dv, const char *path, const char *text, size_t len);
void        doc_render(DocView *dv, WINDOW *win, int win_h, int win_w);
bool        doc_handle_key(DocView *dv, int key, int win_h);
bool        doc_search(DocView *dv, const char *q, bool forward);
void        doc_status(const DocView *dv, char *out, size_t out_sz);

typedef struct Pane {
    GapBuf    *buf;
    LineIdx   *li;
    SynCtx    *syn;
    UndoStack *undo;
    SearchCtx  search;
    Clipboard  clip;

    char     filename[4096];
    bool     modified;
    bool     crlf;
    Language lang;

    size_t   cursor;
    size_t   cursor_line;
    size_t   cursor_col;
    size_t   preferred_col;

    size_t   scroll_line;
    size_t   scroll_col;

    bool     sel_active;
    size_t   sel_anchor;

    WINDOW  *win;
    int      win_y, win_x, win_h, win_w;

    bool    *line_dirty;
    char   **prev_render;
    int      prev_render_rows;
    size_t   last_cursor_row;

    bool     show_line_numbers;

    bool     hex_mode;
    HexPane *hex;

    bool       table_mode;
    TableView *table;

    bool       img_mode;
    ImageView *img;

    bool       doc_mode;
    DocView   *doc;

    /* the file is an image / binary document: the text buffer is empty
     * and must never be written over it */
    bool       binary_view;

    bool       mem_mode;          /* F8 memory editor shown in this pane */

    bool       dis_mode;          /* F9 static analysis shown in this pane */
    DisView   *dis;               /* kept when hidden: F9 reopens it at once */

    /* page fetched from the F1 field (curl): shown without a file on
     * disk until it is saved; url_name is the local name it would get */
    char       url[2048];
    char       url_name[256];
} Pane;

Pane *pane_new(void);
void  pane_free(Pane *p);
void  pane_open_file(Pane *p, const char *path);
bool  pane_save_file(Pane *p, const char *path);
bool  pane_save_file_sync(Pane *p);
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
void  pane_beautify(Pane *p);
bool  pane_table_enter(Pane *p);
bool  pane_table_edit(Pane *p, const char *value);
bool  pane_doc_enter(Pane *p);
void  pane_text_changed(Pane *p);

#define TREE_DEFAULT_W  26
#define TREE_MIN_W      18
#define TREE_MAX_W      48

typedef struct {
    char   name[256];
    bool   is_dir;
    bool   is_lnk;
    bool   is_exe;
    size_t size;
} FTEntry;

typedef struct {
    char     cwd[4096];
    /* field at the top of the tree: a path, a URL, or (plain text) a
     * filter on the names of the folder */
    char     query[2048];
    FTEntry *entries;
    size_t   count;
    size_t   cap;
    size_t   selected;
    size_t   scroll;
    bool     visible;
    int      width;
    WINDOW  *win;
} FileTree;

FileTree   *ft_new(void);
void        ft_free(FileTree *ft);
void        ft_reload(FileTree *ft);
void        ft_enter(FileTree *ft);
void        ft_go_up(FileTree *ft);
const char *ft_selected_path(FileTree *ft, char *buf, size_t bufsz);
void        ft_render(FileTree *ft, WINDOW *win, int win_h, int win_w, bool is_active);
bool        ft_handle_key(FileTree *ft, int key, char *open_path, size_t path_sz);
/* the field holds a filter (not a path nor a URL) */
bool        ft_query_is_filter(const char *q);
void        ft_query_set(FileTree *ft, const char *q);
/* Tab: completes the path typed in the field */
bool        ft_query_complete(FileTree *ft);

#define FILEINFO_DEFAULT_W  36
#define FILEINFO_MIN_W      28
#define FILEINFO_MAX_W      56

typedef struct {
    char    path[4096];
    bool    has_data;
    bool    visible;
    int     width;
    int     scroll_row;
    WINDOW *win;
} FileInfo;

FileInfo *fi_new(void);
void      fi_free(FileInfo *fi);
void      fi_analyze(FileInfo *fi, const char *path);
void      fi_render(FileInfo *fi, WINDOW *win, int win_h, int win_w);
void      fi_colors_init(void);

#define MAX_PANES 4

typedef enum {
    MODE_NORMAL,
    MODE_SAVE_DIALOG,
    MODE_SEARCH_DIALOG,
    MODE_OPEN_DIALOG,
    MODE_GOTO_LINE,
    MODE_HEX_JUMP,
    MODE_HEX_SEARCH,
    MODE_BUILD_MENU,
    MODE_TABLE_SEARCH,
    MODE_TABLE_EDIT,
    MODE_DOC_SEARCH,
    MODE_MEM_INPUT,
    MODE_TABLE_EXPORT,
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
    bool       out_focus;     /* keys go to the running program   */
    bool       out_follow;    /* panel sticks to the newest output */

    WINDOW    *status_win;
    WINDOW    *title_win;
    WINDOW    *div_win[MAX_PANES];   /* vertical rules between split panes */

    pid_t      run_pid;
    char       run_output[1<<16];

    bool       running;
    bool       show_shortcuts;

    /* ^B ^B build-options menu */
    int        build_sel;
    int        build_scroll;

    bool       tree_focus;
    FileTree  *tree;

    FileInfo  *finfo;

    
    HLCtx     *hl;
    bool       hl_focus;

    pthread_t       save_thread;
    bool            save_pending;
    char            save_path[4096];
    char           *save_buf;
    size_t          save_len;
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

/* ^B: build + run in a live console (run.c). run_start launches the
 * child and returns at once (false when nothing keeps running: server,
 * browser, error — `msg` then holds the outcome); the main loop calls
 * run_poll, which streams the output into `buf` and reports
 * RUN_EV_OUTPUT / RUN_EV_DONE. The run_input_* calls feed its stdin. */
#define RUN_OUT_CAP   (1 << 18)
#define RUN_EV_OUTPUT 1
#define RUN_EV_DONE   2
bool        run_start(const char *path, Language lang, char *buf, size_t cap,
                      int cols, int rows, char *msg, size_t msg_sz);
int         run_poll(void);
bool        run_active(void);
bool        run_compiling(void);
const char *run_timing(void);
void        run_resize(int cols, int rows);
void        run_stop(void);
void        run_interrupt(void);
void        run_input_char(int c);
void        run_input_enter(void);
void        run_input_backspace(void);
void        run_input_eof(void);
void        run_input_str(const char *s, size_t n);

/* ─── Build options (^B ^B menu) ───────────────────────────
 * Compiled languages get a per-language table of toggleable compiler
 * flags (optimisation level, SIMD/vector ISA, LTO, sanitizers...).
 * Flags sharing a non-zero `group` are mutually exclusive: selecting
 * one clears the others, the way -O2/-O3/-Ofast would fight. */

#define BUILD_MAX_FLAGS 48

/* What a menu entry stands for. Plain flags land on the compiler command
 * line; the other kinds are choices the build itself is shaped by. */
enum {
    BK_FLAG = 0,   /* compiler flag                                    */
    BK_CC,         /* compiler to use      (flag = its command)         */
    BK_OUT,        /* output kind          (flag = run|exe|dll|lib|obj) */
    BK_ALLSRC,     /* build every source of the folder into one output  */
    BK_SERVER,     /* web: how to serve    (flag = auto|script|flask|http|php|node|file) */
    BK_PORT,       /* web: port            (flag = the number)          */
    BK_BROWSER,    /* web: open the browser once the server is up       */
};

typedef struct {
    const char *label;   /* menu entry                      */
    const char *flag;    /* what lands on the command line  */
    const char *hint;    /* short explanation, shown inline */
    int         group;   /* 0 = independent, >0 = radio group */
    bool        on;      /* default state                   */
    int         kind;    /* BK_*                            */
} BuildFlag;

bool             build_is_compiled(Language lang);
bool             build_has_menu(Language lang);
const BuildFlag *build_flag_table(Language lang, int *count);
bool            *build_flag_state(Language lang);
void             build_flag_toggle(Language lang, int idx);
bool             build_flag_available(Language lang, int idx);
void             build_flags_string(Language lang, char *out, size_t out_sz);
const char      *build_compiler_name(Language lang);
void             build_preview(Language lang, const char *path, char *out, size_t out_sz);

/* Background web server started by ^B on web files (php -S, flask,
 * python -m http.server...). One at a time; stopped on exit. */
bool             server_running(void);
void             server_stop(void);
const char      *server_url(void);

#define COLOR_PAIR_NORMAL           1
#define COLOR_PAIR_KEYWORD          2
#define COLOR_PAIR_TYPE             3
#define COLOR_PAIR_PREPROC          4
#define COLOR_PAIR_STRING           5
#define COLOR_PAIR_COMMENT          6
#define COLOR_PAIR_NUMBER           7
#define COLOR_PAIR_IDENT            8
#define COLOR_PAIR_SEARCH           9
#define COLOR_PAIR_TITLE           10
#define COLOR_PAIR_STATUS          11
#define COLOR_PAIR_LINENUM         12
#define COLOR_PAIR_CURSOR          13
#define COLOR_PAIR_OPERATOR        14
#define COLOR_PAIR_ACTIVE_BORDER   15
#define COLOR_PAIR_INACTIVE_BORDER 16
#define COLOR_PAIR_SELECTION       17
#define COLOR_PAIR_CHAR            18

#define HEX_CP_OFFSET              19
#define HEX_CP_ZERO                20
#define HEX_CP_PRINT               21
#define HEX_CP_NONPRINT            22
#define HEX_CP_CURSOR_H            23
#define HEX_CP_CURSOR_A            24
#define HEX_CP_PEER                25
#define HEX_CP_MODIFIED            26
#define HEX_CP_HEADER              27

void colors_init(void);
int  tok_to_color_pair(TokenType t);
/* Windows: brings every panel's color pairs onto the editor theme */
void colors_win_polish(void);
int  colors_notify_pair(void);

/* Inline color swatches (VSCode-style): map a 24-bit RGB to an ncurses color
 * pair whose foreground is that color. Returns 0 when unsupported/exhausted. */
#define SWATCH_PAIR_BASE 200
#define SWATCH_MAX       48
void colors_swatch_init(void);
int  colors_swatch_pair(unsigned rgb);

typedef struct ArenaBlock {
    struct ArenaBlock *next;
    size_t used;
    size_t cap;
    char   data[];
} ArenaBlock;

struct Arena { ArenaBlock *head; };

Arena *arena_new(size_t block_size);
void  *arena_alloc(Arena *a, size_t n);
void   arena_free(Arena *a);

static inline size_t min_sz(size_t a, size_t b) { return a < b ? a : b; }
static inline size_t max_sz(size_t a, size_t b) { return a > b ? a : b; }

#endif