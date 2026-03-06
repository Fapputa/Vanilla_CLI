#ifndef UTF8_H
#define UTF8_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Decode one UTF-8 codepoint at buf[0..len).
   Returns number of bytes consumed (1-4), or 1 on invalid byte.
   *cp receives the codepoint (U+FFFD on error). */
static inline int utf8_decode(const char *buf, size_t len, uint32_t *cp) {
    unsigned char c = (unsigned char)buf[0];
    if (c < 0x80) { *cp = c; return 1; }
    int n; uint32_t min;
    if      ((c & 0xE0) == 0xC0) { n = 2; *cp = c & 0x1F; min = 0x80;   }
    else if ((c & 0xF0) == 0xE0) { n = 3; *cp = c & 0x0F; min = 0x800;  }
    else if ((c & 0xF8) == 0xF0) { n = 4; *cp = c & 0x07; min = 0x10000;}
    else { *cp = 0xFFFD; return 1; } /* invalid leading byte */
    if ((size_t)n > len) { *cp = 0xFFFD; return 1; }
    for (int i = 1; i < n; i++) {
        unsigned char cc = (unsigned char)buf[i];
        if ((cc & 0xC0) != 0x80) { *cp = 0xFFFD; return 1; }
        *cp = (*cp << 6) | (cc & 0x3F);
    }
    if (*cp < min) { *cp = 0xFFFD; return 1; } /* overlong */
    return n;
}

/* Visual column width of a codepoint (0 for combining, 2 for wide, 1 otherwise).
   Uses wcwidth() logic without linking wchar for simple cases. */
static inline int utf8_cp_width(uint32_t cp) {
    if (cp == 0) return 0;
    /* Combining / zero-width ranges */
    if ((cp >= 0x0300 && cp <= 0x036F) ||   /* Combining diacriticals */
        (cp >= 0x1DC0 && cp <= 0x1DFF) ||
        (cp >= 0x20D0 && cp <= 0x20FF) ||
        (cp >= 0xFE20 && cp <= 0xFE2F))
        return 0;
    /* Wide (East Asian) ranges */
    if ((cp >= 0x1100 && cp <= 0x115F)  ||
        (cp >= 0x2E80 && cp <= 0x303E)  ||
        (cp >= 0x3040 && cp <= 0xA4CF)  ||
        (cp >= 0xAC00 && cp <= 0xD7AF)  ||
        (cp >= 0xF900 && cp <= 0xFAFF)  ||
        (cp >= 0xFE10 && cp <= 0xFE19)  ||
        (cp >= 0xFE30 && cp <= 0xFE6F)  ||
        (cp >= 0xFF00 && cp <= 0xFF60)  ||
        (cp >= 0xFFE0 && cp <= 0xFFE6)  ||
        (cp >= 0x1B000 && cp <= 0x1B0FF)||
        (cp >= 0x1F300 && cp <= 0x1F9FF)||
        (cp >= 0x20000 && cp <= 0x2FFFD)||
        (cp >= 0x30000 && cp <= 0x3FFFD))
        return 2;
    /* Box-drawing & block elements (U+2500–U+259F) — 1 wide in most terminals */
    return 1;
}

/* Encode codepoint cp into buf (must have at least 4 bytes).
   Returns number of bytes written. */
static inline int utf8_encode(uint32_t cp, char *buf) {
    if (cp < 0x80)   { buf[0] = (char)cp; return 1; }
    if (cp < 0x800)  { buf[0] = (char)(0xC0|(cp>>6)); buf[1]=(char)(0x80|(cp&0x3F)); return 2; }
    if (cp < 0x10000){ buf[0]=(char)(0xE0|(cp>>12)); buf[1]=(char)(0x80|((cp>>6)&0x3F)); buf[2]=(char)(0x80|(cp&0x3F)); return 3; }
    buf[0]=(char)(0xF0|(cp>>18)); buf[1]=(char)(0x80|((cp>>12)&0x3F)); buf[2]=(char)(0x80|((cp>>6)&0x3F)); buf[3]=(char)(0x80|(cp&0x3F)); return 4;
}

/* Number of bytes in the UTF-8 character starting at byte c */
static inline int utf8_byte_len(unsigned char c) {
    if (c < 0x80) return 1;
    if ((c & 0xE0) == 0xC0) return 2;
    if ((c & 0xF0) == 0xE0) return 3;
    if ((c & 0xF8) == 0xF0) return 4;
    return 1; /* continuation or invalid → treat as 1 */
}

/* Is this byte a UTF-8 continuation byte? */
static inline bool utf8_is_continuation(unsigned char c) {
    return (c & 0xC0) == 0x80;
}

#endif /* UTF8_H */
