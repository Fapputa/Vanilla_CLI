#include "abyss.h"

void colors_init(void) {
    start_color();
    use_default_colors();
    
    
    init_pair(COLOR_PAIR_NORMAL,    COLOR_WHITE,   -1);
    
    init_pair(COLOR_PAIR_KEYWORD,   COLOR_CYAN,    -1);
    
    init_pair(COLOR_PAIR_TYPE,      COLOR_GREEN,   -1);
    
    init_pair(COLOR_PAIR_PREPROC,   COLOR_MAGENTA, -1);
    
    init_pair(COLOR_PAIR_STRING,    COLOR_YELLOW,  -1);
    
    init_pair(COLOR_PAIR_COMMENT,   COLOR_BLUE,    -1);
    
    init_pair(COLOR_PAIR_NUMBER,    COLOR_RED,     -1);
    
    init_pair(COLOR_PAIR_IDENT,     COLOR_WHITE,   -1);
    
    init_pair(COLOR_PAIR_SEARCH,    COLOR_BLACK,   COLOR_YELLOW);
    
    init_pair(COLOR_PAIR_TITLE,     COLOR_WHITE,   COLOR_RED);
    
    init_pair(COLOR_PAIR_STATUS,    COLOR_BLACK,   COLOR_WHITE);
    
    init_pair(COLOR_PAIR_LINENUM,   COLOR_CYAN,    -1);
    
    init_pair(COLOR_PAIR_CURSOR,    COLOR_WHITE,   COLOR_BLACK);
    
    init_pair(COLOR_PAIR_OPERATOR,  COLOR_WHITE,   -1);
    
    init_pair(COLOR_PAIR_ACTIVE_BORDER,   COLOR_CYAN,  -1);
    
    init_pair(COLOR_PAIR_INACTIVE_BORDER, COLOR_WHITE, -1);
    
    init_pair(COLOR_PAIR_SELECTION, COLOR_BLACK,   COLOR_CYAN);
    
    init_pair(COLOR_PAIR_CHAR,      COLOR_YELLOW,  -1);
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
