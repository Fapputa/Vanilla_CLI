#include "abyss.h"
#include "utf8.h"
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

/*
 * beautify.c  --  Shift+Tab / Ctrl+Tab "beautify" action
 *
 * Performs two passes on the active pane buffer:
 *   1. Strip Unicode emoji codepoints.
 *   2. Strip comments, language-aware:
 *        C / C++ / JS / CSS / C#  ->  // line comments and block comments
 *        Python / Shell            ->  # line comments
 *        SQL                       ->  -- line comments
 *        HTML                      ->  block comments
 *        ASM                       ->  ; line comments
 *        PHP                       ->  #, //, and block comments
 *        JSON / Plain / unknown    ->  nothing stripped
 *
 * An undo snapshot is pushed before the transform so ^Z can revert it.
 */

/* ------------------------------------------------------------------
 * 1.  Emoji detection
 * ------------------------------------------------------------------ */

static bool is_emoji(uint32_t cp)
{
    if (cp >= 0x1F300 && cp <= 0x1F5FF) return true;  /* Misc Symbols & Pictographs  */
    if (cp >= 0x1F600 && cp <= 0x1F64F) return true;  /* Emoticons                   */
    if (cp >= 0x1F680 && cp <= 0x1F6FF) return true;  /* Transport & Map             */
    if (cp >= 0x1F700 && cp <= 0x1F77F) return true;  /* Alchemical Symbols          */
    if (cp >= 0x1F780 && cp <= 0x1F7FF) return true;  /* Geometric Shapes Extended   */
    if (cp >= 0x1F800 && cp <= 0x1F8FF) return true;  /* Supplemental Arrows-C       */
    if (cp >= 0x1F900 && cp <= 0x1F9FF) return true;  /* Supplemental Symbols        */
    if (cp >= 0x1FA00 && cp <= 0x1FAFF) return true;  /* Symbols & Pictographs Ext-A */
    if (cp >= 0x2600  && cp <= 0x26FF)  return true;  /* Miscellaneous Symbols       */
    if (cp >= 0x2700  && cp <= 0x27BF)  return true;  /* Dingbats                    */
    if (cp >= 0x1F100 && cp <= 0x1F2FF) return true;  /* Enclosed Alphanum/Ideograph */
    if (cp >= 0xFE00  && cp <= 0xFE0F)  return true;  /* Variation selectors         */
    if (cp == 0x200D  || cp == 0x20E3)  return true;  /* ZWJ / enclosing keycap      */
    return false;
}

/* ------------------------------------------------------------------
 * 2.  Comment style per language
 * ------------------------------------------------------------------ */

typedef enum {
    CMT_NONE,   /* no comment stripping                              */
    CMT_C,      /* // line  +  slash-star block                      */
    CMT_HASH,   /* # line                                            */
    CMT_SQL,    /* -- line                                           */
    CMT_HTML,   /* angle-bang-dash-dash  ...  dash-dash-angle block  */
    CMT_ASM,    /* ; line                                            */
    CMT_PHP     /* # line  +  // line  +  slash-star block           */
} CommentStyle;

static CommentStyle style_for_lang(Language lang)
{
    switch (lang) {
        case LANG_C:
        case LANG_CPP:
        case LANG_JS:
        case LANG_CS:
        case LANG_CSS:  return CMT_C;
        case LANG_PY:
        case LANG_SH:   return CMT_HASH;
        case LANG_SQL:  return CMT_SQL;
        case LANG_HTML: return CMT_HTML;
        case LANG_ASM:  return CMT_ASM;
        case LANG_PHP:  return CMT_PHP;
        default:        return CMT_NONE;
    }
}

/* ------------------------------------------------------------------
 * 3.  Core transform
 *
 * Reads src[0..slen), writes beautified text into a freshly malloc'd
 * buffer returned via *out / *out_len.  Caller must free(*out).
 * ------------------------------------------------------------------ */

static void beautify_buf(const char *src, size_t slen,
                         CommentStyle cs,
                         char **out, size_t *out_len)
{
    char  *dst = malloc(slen + 1);  /* worst case: same size */
    size_t di  = 0;
    size_t i   = 0;

    bool in_dq    = false;  /* inside "..."        */
    bool in_sq    = false;  /* inside '...'        */
    bool in_block = false;  /* inside block comment */
    bool in_html  = false;  /* inside HTML comment  */
    bool in_line  = false;  /* inside line comment  */
    bool in_tqdq  = false;  /* inside """..."""     */
    bool in_tqsq  = false;  /* inside '''...'''     */

    /* ---- Preserve shebang line (#!) verbatim ---- */
    if (slen >= 2 && src[0] == '#' && src[1] == '!') {
        while (i < slen && src[i] != '\n') dst[di++] = src[i++];
        if (i < slen) dst[di++] = src[i++]; /* '\n' */
    }

    while (i < slen) {

        /* Decode one UTF-8 codepoint */
        uint32_t cp;
        int blen = utf8_decode(src + i, slen - i, &cp);

        char c = src[i];

        /* Newline: always emit, always ends a line comment */
        if (c == '\n') {
            in_line = false;
            dst[di++] = '\n';
            i++;
            continue;
        }

        /* Skip remaining chars on a line comment */
        if (in_line) {
            i += (size_t)blen;
            continue;
        }

        /* ---- Python triple-quote strings: """...""" and '''...'''
         * Docstrings are preserved entirely -- never stripped.        ---- */
        if (cs == CMT_HASH) {
            if (in_tqdq) {
                if (c == '"' && i+2 < slen && src[i+1]=='"' && src[i+2]=='"') {
                    dst[di++]='"'; dst[di++]='"'; dst[di++]='"';
                    i += 3; in_tqdq = false;
                } else { dst[di++] = src[i++]; }
                continue;
            }
            if (in_tqsq) {
                if (c=='\'' && i+2 < slen && src[i+1]=='\'' && src[i+2]=='\'') {
                    dst[di++]='\''; dst[di++]='\''; dst[di++]='\'';
                    i += 3; in_tqsq = false;
                } else { dst[di++] = src[i++]; }
                continue;
            }
            if (!in_dq && !in_sq) {
                if (c=='"' && i+2 < slen && src[i+1]=='"' && src[i+2]=='"') {
                    dst[di++]='"'; dst[di++]='"'; dst[di++]='"';
                    i += 3; in_tqdq = true; continue;
                }
                if (c=='\'' && i+2 < slen && src[i+1]=='\'' && src[i+2]=='\'') {
                    dst[di++]='\''; dst[di++]='\''; dst[di++]='\'';
                    i += 3; in_tqsq = true; continue;
                }
            }
        }

        /* Strip emoji only outside strings */
        if (is_emoji(cp) && !in_dq && !in_sq && !in_tqdq && !in_tqsq) {
            i += (size_t)blen;
            continue;
        }

        /* ---- HTML block comment:  opening is <! followed by two dashes ---- */
        if (cs == CMT_HTML) {
            if (in_html) {
                /* close on two dashes followed by > */
                if (c == '-' && i + 2 < slen
                        && src[i+1] == '-' && src[i+2] == '>') {
                    in_html = false;
                    i += 3;
                } else {
                    i++;
                }
                continue;
            }
            if (!in_dq && !in_sq
                    && c == '<' && i + 3 < slen
                    && src[i+1] == '!'
                    && src[i+2] == '-'
                    && src[i+3] == '-') {
                in_html = true;
                i += 4;
                continue;
            }
        }

        /* ---- C-style block comment:  slash+star  ...  star+slash ---- */
        if (cs == CMT_C || cs == CMT_PHP) {
            if (in_block) {
                if (c == '*' && i + 1 < slen && src[i+1] == '/') {
                    in_block = false;
                    i += 2;
                } else {
                    i++;
                }
                continue;
            }
            if (!in_dq && !in_sq
                    && c == '/' && i + 1 < slen && src[i+1] == '*') {
                in_block = true;
                i += 2;
                continue;
            }
        }

        /* ---- String literal tracking (prevents false comment matches) ---- */
        if (!in_block && !in_html && !in_tqdq && !in_tqsq) {
            bool esc = (i > 0 && src[i-1] == '\\');
            if (!in_dq && !in_sq) {
                if (c == '"')  in_dq = true;
                if (c == '\'') in_sq = true;
            } else {
                if (in_dq && c == '"'  && !esc) in_dq = false;
                if (in_sq && c == '\'' && !esc) in_sq = false;
            }
        }

        bool in_str = in_dq || in_sq || in_tqdq || in_tqsq;

        /* ---- Line comment openers ---- */
        if (!in_str && !in_block && !in_html) {
            switch (cs) {
                case CMT_C:
                    if (c == '/' && i + 1 < slen && src[i+1] == '/') {
                        in_line = true; i += 2; continue;
                    }
                    break;
                case CMT_PHP:
                    if (c == '/' && i + 1 < slen && src[i+1] == '/') {
                        in_line = true; i += 2; continue;
                    }
                    if (c == '#') { in_line = true; i++; continue; }
                    break;
                case CMT_HASH:
                    if (c == '#') { in_line = true; i++; continue; }
                    break;
                case CMT_SQL:
                    if (c == '-' && i + 1 < slen && src[i+1] == '-') {
                        in_line = true; i += 2; continue;
                    }
                    break;
                case CMT_ASM:
                    if (c == ';') { in_line = true; i++; continue; }
                    break;
                default:
                    break;
            }
        }

        /* Copy bytes verbatim */
        for (int b = 0; b < blen; b++)
            dst[di++] = src[i + b];
        i += (size_t)blen;
    }

    /* Collapse runs of more than two blank lines */
    char  *out2 = malloc(di + 1);
    size_t oi   = 0;
    size_t nl   = 0;
    for (size_t k = 0; k < di; k++) {
        if (dst[k] == '\n') {
            nl++;
            if (nl <= 2) out2[oi++] = '\n';
        } else {
            nl = 0;
            out2[oi++] = dst[k];
        }
    }
    free(dst);

    out2[oi] = '\0';
    *out     = out2;
    *out_len = oi;
}

/* ------------------------------------------------------------------
 * 4.  Public entry point (called from editor.c)
 * ------------------------------------------------------------------ */

void pane_beautify(Pane *p)
{
    if (!p || p->hex_mode) return;

    char  *src  = gb_to_str(p->buf);
    size_t slen = gb_len(p->buf);

    char  *dst  = NULL;
    size_t dlen = 0;
    beautify_buf(src, slen, style_for_lang(p->lang), &dst, &dlen);
    free(src);

    /* Replace the gap buffer */
    gb_free(p->buf);
    p->buf = gb_new(dlen + GAP_DEFAULT);
    if (dlen > 0)
        gb_insert_str(p->buf, 0, dst, dlen);
    free(dst);

    if (p->cursor > dlen) p->cursor = dlen;

    li_rebuild(p->li, p->buf);
    syn_mark_dirty_from(p->syn, 0);
    p->modified = true;

    pane_push_undo(p);
}
