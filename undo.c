#include "abyss.h"

/* Forward-declare clone (defined in gap_buf.c) */
GapBuf *gb_clone(const GapBuf *g);

#define MAX_UNDO_DEPTH 512

UndoStack *us_new(void) {
    UndoStack *us = calloc(1, sizeof *us);
    return us;
}

static void ua_free(UndoAction *a) {
    if (!a) return;
    gb_free(a->snapshot_buf);
    free(a);
}

void us_free(UndoStack *us) {
    if (!us) return;
    UndoAction *a = us->head;
    while (a) {
        UndoAction *n = a->next;
        ua_free(a);
        a = n;
    }
    free(us);
}

void us_push(UndoStack *us, const GapBuf *g, size_t cursor) {
    /* Discard redo history */
    if (us->current) {
        UndoAction *a = us->current->next;
        while (a) {
            UndoAction *n = a->next;
            ua_free(a);
            a = n;
        }
        us->current->next = NULL;
    }

    UndoAction *ua = calloc(1, sizeof *ua);
    ua->snapshot_buf = gb_clone(g);
    ua->cursor_pos = cursor;
    ua->prev = us->current;
    if (us->current) us->current->next = ua;
    else us->head = ua;
    us->current = ua;

    us->depth++;
    /* Trim oldest entries if too deep */
    if (us->depth > MAX_UNDO_DEPTH) {
        UndoAction *old = us->head;
        us->head = old->next;
        if (us->head) us->head->prev = NULL;
        ua_free(old);
        us->depth--;
    }
}

bool us_undo(UndoStack *us, GapBuf **g_out, size_t *cursor_out) {
    if (!us->current || !us->current->prev) return false;
    us->current = us->current->prev;
    *g_out = gb_clone(us->current->snapshot_buf);
    *cursor_out = us->current->cursor_pos;
    return true;
}

bool us_redo(UndoStack *us, GapBuf **g_out, size_t *cursor_out) {
    if (!us->current || !us->current->next) return false;
    us->current = us->current->next;
    *g_out = gb_clone(us->current->snapshot_buf);
    *cursor_out = us->current->cursor_pos;
    return true;
}
