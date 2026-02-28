#include "abyss.h"

LineIdx *li_new(void) {
    LineIdx *li = calloc(1, sizeof *li);
    li->cap = LINE_IDX_CHUNK;
    li->offsets = malloc(li->cap * sizeof(size_t));
    li->offsets[0] = 0;
    li->count = 1;
    li->dirty = true;
    return li;
}

void li_free(LineIdx *li) {
    if (!li) return;
    free(li->offsets);
    free(li);
}

void li_rebuild(LineIdx *li, const GapBuf *g) {
    li->count = 0;
    size_t len = gb_len(g);

    /* ensure capacity */
    if (li->cap < 2) {
        li->cap = LINE_IDX_CHUNK;
        li->offsets = realloc(li->offsets, li->cap * sizeof(size_t));
    }

    li->offsets[li->count++] = 0;

    for (size_t i = 0; i < len; i++) {
        if (gb_at(g, i) == '\n') {
            if (li->count >= li->cap) {
                li->cap *= 2;
                li->offsets = realloc(li->offsets, li->cap * sizeof(size_t));
            }
            li->offsets[li->count++] = i + 1;
        }
    }
    li->dirty = false;
}

void li_mark_dirty(LineIdx *li) { li->dirty = true; }

size_t li_line_count(const LineIdx *li) { return li->count; }

size_t li_line_start(const LineIdx *li, size_t line) {
    if (line >= li->count) return 0;
    return li->offsets[line];
}
