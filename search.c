#include "abyss.h"
#include <string.h>

/* Simple Boyer-Moore-Horspool for text search */
static void bmh_build(const char *pat, int plen, int *skip) {
    for (int i = 0; i < 256; i++) skip[i] = plen;
    for (int i = 0; i < plen - 1; i++)
        skip[(unsigned char)pat[i]] = plen - 1 - i;
}

void search_find(SearchCtx *sc, const GapBuf *g) {
    sc->count = 0;
    sc->current = -1;
    if (!sc->query[0]) return;

    int plen = (int)strlen(sc->query);
    size_t tlen = gb_len(g);
    if ((size_t)plen > tlen) return;

    /* Materialise buffer for BMH */
    char *text = gb_to_str(g);

    int skip[256];
    bmh_build(sc->query, plen, skip);

    size_t i = plen - 1;
    while (i < tlen) {
        int j = plen - 1;
        size_t k = i;
        while (j >= 0 && text[k] == sc->query[j]) { j--; k--; }
        if (j < 0) {
            /* match at k+1 */
            if (sc->count >= sc->cap) {
                sc->cap = sc->cap ? sc->cap * 2 : 64;
                sc->matches = realloc(sc->matches, sc->cap * sizeof(size_t));
            }
            sc->matches[sc->count++] = k + 1;
            i += plen;
        } else {
            i += skip[(unsigned char)text[i]];
        }
    }
    free(text);
    if (sc->count > 0) sc->current = 0;
}

void search_clear(SearchCtx *sc) {
    sc->query[0] = '\0';
    sc->count = 0;
    sc->current = -1;
}
