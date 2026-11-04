/* Built-in image decoders for the image view — no library, no external
 * program, so pictures work the same on Linux and Windows.
 *
 *   PNG    every color type and bit depth, palette + tRNS, Adam7; with
 *          its own inflate (RFC 1951)
 *   JPEG   baseline and progressive Huffman, any chroma subsampling,
 *          restart markers, Adobe CMYK/YCCK, EXIF orientation; photos
 *          bigger than ~2 megapixels decode at 1/8 scale (DC only), which
 *          is still far more than a terminal can show
 *   GIF    first frame, interlacing, transparency
 *   BMP    1/4/8/16/24/32 bpp, bitfields;  ICO (BMP or PNG entries)
 *   PNM    P1-P6;  TGA  (raw / RLE, true-color, gray, color-mapped);  QOI
 *
 * Everything decodes to 8-bit RGBA. Damaged files decode as far as they
 * can (missing parts stay black) instead of failing outright. */
#include "imgdecode.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <math.h>

#define MAX_PIXELS (48u * 1024u * 1024u)

static int fail(char *err, size_t sz, const char *msg) {
    snprintf(err, sz, "%s", msg);
    return 0;
}

static bool bm_alloc(Bitmap *b, int w, int h) {
    if (w <= 0 || h <= 0 || (uint64_t)w * (uint64_t)h > MAX_PIXELS) return false;
    b->px = calloc((size_t)w * (size_t)h, 4);
    if (!b->px) return false;
    b->w = b->src_w = w;
    b->h = b->src_h = h;
    return true;
}

void bitmap_free(Bitmap *b) {
    if (!b) return;
    free(b->px);
    b->px = NULL;
    b->w = b->h = 0;
}

static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static uint32_t be16(const uint8_t *p) { return (uint32_t)p[0] << 8 | p[1]; }
static uint32_t le32(const uint8_t *p) { return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0]; }
static uint32_t le16(const uint8_t *p) { return (uint32_t)p[1] << 8 | p[0]; }

static inline uint8_t clamp8(int v) { return v < 0 ? 0 : v > 255 ? 255 : (uint8_t)v; }

/* ═══ inflate ═══════════════════════════════════════════════════════ */

typedef struct {
    const uint8_t *in;
    size_t         inlen, pos;
    uint32_t       bitbuf;
    int            bitcnt;
    uint8_t       *out;
    size_t         outlen, outcap;
    bool           err;
} Inf;

typedef struct { short count[16]; short symbol[320]; } Huf;

static inline int inf_bits(Inf *s, int need) {
    uint32_t val = s->bitbuf;
    while (s->bitcnt < need) {
        if (s->pos >= s->inlen) { s->err = true; return 0; }
        val |= (uint32_t)s->in[s->pos++] << s->bitcnt;
        s->bitcnt += 8;
    }
    s->bitbuf = val >> need;
    s->bitcnt -= need;
    return (int)(val & ((1u << need) - 1));
}

static int huf_build(Huf *h, const short *len, int n) {
    short offs[16];
    memset(h->count, 0, sizeof h->count);
    for (int s = 0; s < n; s++) h->count[len[s]]++;
    if (h->count[0] == n) return 0;
    int left = 1;
    for (int l = 1; l < 16; l++) {
        left <<= 1;
        left -= h->count[l];
        if (left < 0) return -1;
    }
    offs[1] = 0;
    for (int l = 1; l < 15; l++) offs[l + 1] = (short)(offs[l] + h->count[l]);
    for (int s = 0; s < n; s++) if (len[s]) h->symbol[offs[len[s]]++] = (short)s;
    return left;
}

static int huf_decode(Inf *s, const Huf *h) {
    int code = 0, first = 0, index = 0;
    for (int l = 1; l < 16; l++) {
        code |= inf_bits(s, 1);
        if (s->err) return -1;
        int count = h->count[l];
        if (code - count < first) return h->symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -1;
}

static bool inf_put(Inf *s, uint8_t c) {
    if (s->outlen >= s->outcap) return false;      /* got everything we want */
    s->out[s->outlen++] = c;
    return true;
}

static const short lbase[29] = { 3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258 };
static const short lext[29]  = { 0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0 };
static const short dbase[30] = { 1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577 };
static const short dext[30]  = { 0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13 };

/* returns false when the output is full (stop) or on error */
static bool inf_codes(Inf *s, const Huf *lc, const Huf *dc) {
    for (;;) {
        int sym = huf_decode(s, lc);
        if (sym < 0) { s->err = true; return false; }
        if (sym < 256) { if (!inf_put(s, (uint8_t)sym)) return false; continue; }
        if (sym == 256) return true;
        sym -= 257;
        if (sym >= 29) { s->err = true; return false; }
        int len = lbase[sym] + inf_bits(s, lext[sym]);
        int ds = huf_decode(s, dc);
        if (ds < 0 || ds >= 30) { s->err = true; return false; }
        size_t dist = (size_t)(dbase[ds] + inf_bits(s, dext[ds]));
        if (s->err || dist > s->outlen) { s->err = true; return false; }
        for (int i = 0; i < len; i++)
            if (!inf_put(s, s->out[s->outlen - dist])) return false;
    }
}

static Huf fixed_l, fixed_d;
static bool fixed_ready = false;

static void inf_fixed_init(void) {
    if (fixed_ready) return;
    short len[288];
    int i = 0;
    for (; i < 144; i++) len[i] = 8;
    for (; i < 256; i++) len[i] = 9;
    for (; i < 280; i++) len[i] = 7;
    for (; i < 288; i++) len[i] = 8;
    huf_build(&fixed_l, len, 288);
    for (i = 0; i < 30; i++) len[i] = 5;
    huf_build(&fixed_d, len, 30);
    fixed_ready = true;
}

static bool inf_dynamic(Inf *s) {
    static const short order[19] = { 16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15 };
    short len[320];
    Huf lc, dc;
    int nlen = inf_bits(s, 5) + 257, ndist = inf_bits(s, 5) + 1, ncode = inf_bits(s, 4) + 4;
    if (s->err || nlen > 286 || ndist > 30) { s->err = true; return false; }
    int i;
    for (i = 0; i < ncode; i++) len[order[i]] = (short)inf_bits(s, 3);
    for (; i < 19; i++) len[order[i]] = 0;
    if (huf_build(&lc, len, 19) != 0) { s->err = true; return false; }
    for (i = 0; i < nlen + ndist; ) {
        int sym = huf_decode(s, &lc);
        if (sym < 0) { s->err = true; return false; }
        if (sym < 16) { len[i++] = (short)sym; continue; }
        int rep, val = 0;
        if (sym == 16) {
            if (i == 0) { s->err = true; return false; }
            val = len[i - 1];
            rep = 3 + inf_bits(s, 2);
        } else if (sym == 17) rep = 3 + inf_bits(s, 3);
        else                  rep = 11 + inf_bits(s, 7);
        if (i + rep > nlen + ndist) { s->err = true; return false; }
        while (rep--) len[i++] = (short)val;
    }
    if (len[256] == 0) { s->err = true; return false; }
    int e = huf_build(&lc, len, nlen);
    if (e < 0 || (e > 0 && nlen - lc.count[0] != 1)) { s->err = true; return false; }
    e = huf_build(&dc, len + nlen, ndist);
    if (e < 0 || (e > 0 && ndist - dc.count[0] != 1)) { s->err = true; return false; }
    return inf_codes(s, &lc, &dc);
}

/* zlib stream -> out (at most cap bytes). Returns the bytes produced. */
static size_t zlib_inflate(const uint8_t *in, size_t inlen, uint8_t *out, size_t cap) {
    if (inlen < 2 || (in[0] & 0x0F) != 8 || ((in[0] << 8) | in[1]) % 31 != 0 || (in[1] & 0x20))
        return 0;
    Inf s = { .in = in, .inlen = inlen, .pos = 2, .out = out, .outcap = cap };
    inf_fixed_init();
    int last;
    do {
        last = inf_bits(&s, 1);
        int type = inf_bits(&s, 2);
        if (s.err) break;
        if (type == 0) {
            s.bitbuf = 0; s.bitcnt = 0;
            if (s.pos + 4 > s.inlen) break;
            unsigned len = le16(s.in + s.pos);
            unsigned nlen = le16(s.in + s.pos + 2);
            s.pos += 4;
            if ((len ^ 0xFFFF) != nlen || s.pos + len > s.inlen) break;
            bool full = false;
            for (unsigned k = 0; k < len; k++) if (!inf_put(&s, s.in[s.pos + k])) { full = true; break; }
            s.pos += len;
            if (full) break;
        } else if (type == 1) {
            if (!inf_codes(&s, &fixed_l, &fixed_d)) break;
        } else if (type == 2) {
            if (!inf_dynamic(&s)) break;
        } else break;
    } while (!last);
    return s.outlen;
}

/* ═══ PNG ═══════════════════════════════════════════════════════════ */

static inline int paeth(int a, int b, int c) {
    int p = a + b - c, pa = abs(p - a), pb = abs(p - b), pc = abs(p - c);
    return (pa <= pb && pa <= pc) ? a : (pb <= pc) ? b : c;
}

static int decode_png(const uint8_t *d, size_t n, Bitmap *bm, char *err, size_t esz) {
    if (n < 33) return fail(err, esz, "PNG: file too short");
    size_t pos = 8;
    int w = 0, h = 0, depth = 0, ctype = -1, interlace = 0;
    uint8_t pal[256][4];
    int npal = 0;
    for (int i = 0; i < 256; i++) { pal[i][0] = pal[i][1] = pal[i][2] = 0; pal[i][3] = 255; }
    int trns[3] = { -1, -1, -1 };
    uint8_t *idat = NULL;
    size_t idat_n = 0, idat_cap = 0;

    while (pos + 8 <= n) {
        uint32_t len = be32(d + pos);
        const uint8_t *type = d + pos + 4;
        const uint8_t *body = d + pos + 8;
        if (len > n - pos - 8) len = (uint32_t)(n - pos - 8);       /* truncated file */
        if (!memcmp(type, "IHDR", 4) && len >= 13) {
            w = (int)be32(body); h = (int)be32(body + 4);
            depth = body[8]; ctype = body[9]; interlace = body[12];
        } else if (!memcmp(type, "PLTE", 4)) {
            npal = (int)(len / 3) > 256 ? 256 : (int)(len / 3);
            for (int i = 0; i < npal; i++) { pal[i][0] = body[3*i]; pal[i][1] = body[3*i+1]; pal[i][2] = body[3*i+2]; }
        } else if (!memcmp(type, "tRNS", 4)) {
            if (ctype == 3) for (uint32_t i = 0; i < len && i < 256; i++) pal[i][3] = body[i];
            else if (ctype == 0 && len >= 2) trns[0] = (int)be16(body);
            else if (ctype == 2 && len >= 6) { trns[0] = (int)be16(body); trns[1] = (int)be16(body + 2); trns[2] = (int)be16(body + 4); }
        } else if (!memcmp(type, "IDAT", 4)) {
            if (idat_n + len > idat_cap) {
                idat_cap = (idat_n + len) * 2;
                uint8_t *nb = realloc(idat, idat_cap);
                if (!nb) { free(idat); return fail(err, esz, "PNG: out of memory"); }
                idat = nb;
            }
            memcpy(idat + idat_n, body, len);
            idat_n += len;
        } else if (!memcmp(type, "IEND", 4)) break;
        pos += 12 + (size_t)len;
    }

    int ch;
    switch (ctype) {
        case 0: ch = 1; break;
        case 2: ch = 3; break;
        case 3: ch = 1; break;
        case 4: ch = 2; break;
        case 6: ch = 4; break;
        default: free(idat); return fail(err, esz, "PNG: unknown color type");
    }
    if (!(depth == 1 || depth == 2 || depth == 4 || depth == 8 || depth == 16) ||
        (ctype == 3 && depth > 8) || ((ctype == 2 || ctype == 4 || ctype == 6) && depth < 8)) {
        free(idat); return fail(err, esz, "PNG: invalid bit depth");
    }
    if (!idat_n) { free(idat); return fail(err, esz, "PNG: no image data"); }
    if (!bm_alloc(bm, w, h)) { free(idat); return fail(err, esz, "PNG: image too large"); }

    int bits = ch * depth;
    int bpp  = bits >= 8 ? bits / 8 : 1;
    static const int sx[7] = { 0, 4, 0, 2, 0, 1, 0 }, sy[7] = { 0, 0, 4, 0, 2, 0, 1 };
    static const int dx[7] = { 8, 8, 4, 4, 2, 2, 1 }, dy[7] = { 8, 8, 8, 4, 4, 2, 2 };
    int npass = interlace ? 7 : 1;

    size_t total = 0;
    for (int p = 0; p < npass; p++) {
        int pw = interlace ? (w - sx[p] + dx[p] - 1) / dx[p] : w;
        int ph = interlace ? (h - sy[p] + dy[p] - 1) / dy[p] : h;
        if (pw <= 0 || ph <= 0) continue;
        total += (size_t)ph * (1 + ((size_t)pw * (size_t)bits + 7) / 8);
    }
    uint8_t *raw = calloc(total ? total : 1, 1);
    if (!raw) { free(idat); bitmap_free(bm); return fail(err, esz, "PNG: out of memory"); }
    zlib_inflate(idat, idat_n, raw, total);       /* short data: the rest stays 0 */
    free(idat);

    uint8_t *prev = calloc(((size_t)w * (size_t)bits + 7) / 8 + 8, 1);
    size_t off = 0;
    int maxv = (1 << depth) - 1;
    for (int p = 0; p < npass; p++) {
        int pw = interlace ? (w - sx[p] + dx[p] - 1) / dx[p] : w;
        int ph = interlace ? (h - sy[p] + dy[p] - 1) / dy[p] : h;
        if (pw <= 0 || ph <= 0) continue;
        size_t stride = ((size_t)pw * (size_t)bits + 7) / 8;
        memset(prev, 0, stride);
        for (int y = 0; y < ph; y++) {
            uint8_t ft = raw[off];
            uint8_t *row = raw + off + 1;
            off += 1 + stride;
            for (size_t i = 0; i < stride; i++) {
                int a = i >= (size_t)bpp ? row[i - (size_t)bpp] : 0;
                int b = prev[i];
                int c = i >= (size_t)bpp ? prev[i - (size_t)bpp] : 0;
                int x = row[i];
                switch (ft) {
                    case 1: x += a; break;
                    case 2: x += b; break;
                    case 3: x += (a + b) >> 1; break;
                    case 4: x += paeth(a, b, c); break;
                    default: break;
                }
                row[i] = (uint8_t)x;
            }
            memcpy(prev, row, stride);

            int oy = interlace ? sy[p] + y * dy[p] : y;
            for (int x = 0; x < pw; x++) {
                int ox = interlace ? sx[p] + x * dx[p] : x;
                uint8_t *o = bm->px + ((size_t)oy * (size_t)w + (size_t)ox) * 4;
                int v[4] = { 0, 0, 0, 0 }, raw16[4] = { 0, 0, 0, 0 };
                for (int k = 0; k < ch; k++) {
                    if (depth == 16) {
                        const uint8_t *q = row + ((size_t)x * (size_t)ch + (size_t)k) * 2;
                        raw16[k] = (q[0] << 8) | q[1];
                        v[k] = q[0];
                    } else if (depth == 8) {
                        v[k] = raw16[k] = row[(size_t)x * (size_t)ch + (size_t)k];
                    } else {
                        size_t bit = (size_t)x * (size_t)depth;
                        int s = 8 - depth - (int)(bit & 7);
                        raw16[k] = (row[bit >> 3] >> s) & maxv;
                        v[k] = ctype == 3 ? raw16[k] : raw16[k] * 255 / maxv;
                    }
                }
                switch (ctype) {
                    case 0:
                        o[0] = o[1] = o[2] = (uint8_t)v[0];
                        o[3] = (trns[0] >= 0 && raw16[0] == trns[0]) ? 0 : 255;
                        break;
                    case 2:
                        o[0] = (uint8_t)v[0]; o[1] = (uint8_t)v[1]; o[2] = (uint8_t)v[2];
                        o[3] = (trns[0] >= 0 && raw16[0] == trns[0] && raw16[1] == trns[1] && raw16[2] == trns[2]) ? 0 : 255;
                        break;
                    case 3: {
                        int idx = v[0] & 255;
                        memcpy(o, pal[idx], 4);
                        break;
                    }
                    case 4:
                        o[0] = o[1] = o[2] = (uint8_t)v[0];
                        o[3] = (uint8_t)v[1];
                        break;
                    default:
                        o[0] = (uint8_t)v[0]; o[1] = (uint8_t)v[1]; o[2] = (uint8_t)v[2]; o[3] = (uint8_t)v[3];
                }
            }
        }
    }
    free(prev);
    free(raw);
    bm->fmt = "PNG";
    return 1;
}

/* ═══ JPEG ══════════════════════════════════════════════════════════ */

static const uint8_t zz[64] = {
     0,  1,  8, 16,  9,  2,  3, 10, 17, 24, 32, 25, 18, 11,  4,  5,
    12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13,  6,  7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63
};

typedef struct {
    uint8_t bits[17];
    uint8_t vals[256];
    int     mincode[17], maxcode[18], valptr[17];
} JHuff;

typedef struct {
    int    id, h, v, tq;
    int    bpl, bpc;           /* blocks per line / column covering the component */
    int    bplm, bpcm;         /* same, rounded up to whole MCUs                  */
    short *coef;               /* bpcm * bplm * 64, natural order                 */
    int    td, ta;
    int    pred;
    uint8_t *plane;
    int    pw, ph;
} JComp;

typedef struct {
    const uint8_t *d;
    size_t   n, pos;
    uint32_t bitbuf;
    int      bitcnt;
    uint16_t qt[4][64];
    JHuff    dc[4], ac[4];
    JComp    comp[4];
    int      ncomp;
    int      w, h, hmax, vmax, mcux, mcuy;
    bool     progressive, have_frame, dc_only;
    int      restart;
    int      eobrun, ac_state, ac_next, ac_r;
    int      ss, se, ah, al;
    bool     adobe;
    int      transform;
    int      orientation;
} Jpg;

static void jh_build(JHuff *h) {
    int code = 0, k = 0;
    for (int l = 1; l <= 16; l++) {
        h->valptr[l]  = k;
        h->mincode[l] = code;
        code += h->bits[l];
        k    += h->bits[l];
        h->maxcode[l] = h->bits[l] ? code - 1 : -1;
        code <<= 1;
    }
    h->maxcode[17] = INT_MAX;
}

static inline int jbit(Jpg *j) {
    if (j->bitcnt == 0) {
        uint8_t c = 0;
        if (j->pos < j->n) {
            c = j->d[j->pos];
            if (c == 0xFF) {
                uint8_t nx = j->pos + 1 < j->n ? j->d[j->pos + 1] : 0;
                if (nx == 0x00) j->pos += 2;
                else c = 0;                  /* a marker: feed zeros, stay on it */
            } else j->pos++;
        }
        j->bitbuf = c;
        j->bitcnt = 8;
    }
    j->bitcnt--;
    return (int)((j->bitbuf >> j->bitcnt) & 1);
}

static inline int jreceive(Jpg *j, int n) {
    int v = 0;
    while (n--) v = (v << 1) | jbit(j);
    return v;
}

static inline int jextend(Jpg *j, int s) {
    if (s == 0) return 0;
    if (s > 16) s = 16;
    int v = jreceive(j, s);
    return v < (1 << (s - 1)) ? v - (1 << s) + 1 : v;
}

static inline int jdecode(Jpg *j, const JHuff *h) {
    int code = 0;
    for (int l = 1; l <= 16; l++) {
        code = (code << 1) | jbit(j);
        if (code <= h->maxcode[l]) {
            int idx = h->valptr[l] + code - h->mincode[l];
            return (idx >= 0 && idx < 256) ? h->vals[idx] : 0;
        }
    }
    return 0;
}

static void jblock_baseline(Jpg *j, JComp *c, short *z) {
    int t = jdecode(j, &j->dc[c->td]);
    c->pred += jextend(j, t);
    z[0] = (short)c->pred;
    for (int k = 1; k < 64; ) {
        int rs = jdecode(j, &j->ac[c->ta]);
        int s = rs & 15, r = rs >> 4;
        if (s == 0) {
            if (r < 15) break;
            k += 16;
            continue;
        }
        k += r;
        if (k > 63) break;
        z[zz[k]] = (short)jextend(j, s);
        k++;
    }
}

static void jblock_dc_first(Jpg *j, JComp *c, short *z) {
    int t = jdecode(j, &j->dc[c->td]);
    c->pred += jextend(j, t) * (1 << j->al);
    z[0] = (short)c->pred;
}

static void jblock_dc_refine(Jpg *j, JComp *c, short *z) {
    (void)c;
    if (jbit(j)) z[0] = (short)(z[0] | (1 << j->al));
}

static void jblock_ac_first(Jpg *j, JComp *c, short *z) {
    if (j->eobrun > 0) { j->eobrun--; return; }
    for (int k = j->ss; k <= j->se; ) {
        int rs = jdecode(j, &j->ac[c->ta]);
        int s = rs & 15, r = rs >> 4;
        if (s == 0) {
            if (r < 15) { j->eobrun = jreceive(j, r) + (1 << r) - 1; break; }
            k += 16;
            continue;
        }
        k += r;
        if (k > 63) break;
        z[zz[k]] = (short)(jextend(j, s) * (1 << j->al));
        k++;
    }
}

static void jblock_ac_refine(Jpg *j, JComp *c, short *z) {
    int p1 = 1 << j->al;
    int r = j->ac_r;
    for (int k = j->ss; k <= j->se; k++) {
        short *zc = &z[zz[k]];
        int sign = *zc < 0 ? -1 : 1;
        switch (j->ac_state) {
            case 0: {
                int rs = jdecode(j, &j->ac[c->ta]);
                int s = rs & 15;
                r = rs >> 4;
                if (s == 0) {
                    if (r < 15) { j->eobrun = jreceive(j, r) + (1 << r); j->ac_state = 4; }
                    else        { r = 16; j->ac_state = 1; }
                } else {
                    j->ac_next = jextend(j, s);
                    j->ac_state = r ? 2 : 3;
                }
                k--;                       /* the same coefficient, in the new state */
                continue;
            }
            case 1:
            case 2:
                if (*zc) *zc = (short)(*zc + sign * (jbit(j) * p1));
                else if (--r == 0) j->ac_state = j->ac_state == 2 ? 3 : 0;
                break;
            case 3:
                if (*zc) *zc = (short)(*zc + sign * (jbit(j) * p1));
                else { *zc = (short)(j->ac_next * p1); j->ac_state = 0; }
                break;
            case 4:
                if (*zc) *zc = (short)(*zc + sign * (jbit(j) * p1));
                break;
        }
    }
    if (j->ac_state == 4 && --j->eobrun <= 0) { j->eobrun = 0; j->ac_state = 0; }
    j->ac_r = r;
}

static bool jnext_rst(Jpg *j) {
    j->bitcnt = 0;
    while (j->pos + 1 < j->n) {
        if (j->d[j->pos] == 0xFF) {
            uint8_t m = j->d[j->pos + 1];
            if (m >= 0xD0 && m <= 0xD7) { j->pos += 2; return true; }
            if (m != 0x00 && m != 0xFF) return false;
        }
        j->pos++;
    }
    return false;
}

static void jscan(Jpg *j, JComp **sc, int ns) {
    void (*fn)(Jpg *, JComp *, short *);
    if (!j->progressive)  fn = jblock_baseline;
    else if (j->ss == 0)  fn = j->ah == 0 ? jblock_dc_first : jblock_dc_refine;
    else                  fn = j->ah == 0 ? jblock_ac_first : jblock_ac_refine;

    j->bitcnt = 0; j->eobrun = 0; j->ac_state = 0;
    for (int i = 0; i < ns; i++) sc[i]->pred = 0;

    long mcus = ns == 1 ? (long)sc[0]->bpl * sc[0]->bpc : (long)j->mcux * j->mcuy;
    long interval = j->restart ? j->restart : mcus;
    long m = 0;
    while (m < mcus) {
        for (long r = 0; r < interval && m < mcus; r++, m++) {
            if (ns == 1) {
                JComp *c = sc[0];
                int row = (int)(m / c->bpl), col = (int)(m % c->bpl);
                fn(j, c, c->coef + ((size_t)row * (size_t)c->bplm + (size_t)col) * 64);
            } else {
                int mrow = (int)(m / j->mcux), mcol = (int)(m % j->mcux);
                for (int i = 0; i < ns; i++) {
                    JComp *c = sc[i];
                    for (int v = 0; v < c->v; v++)
                        for (int h = 0; h < c->h; h++) {
                            int row = mrow * c->v + v, col = mcol * c->h + h;
                            fn(j, c, c->coef + ((size_t)row * (size_t)c->bplm + (size_t)col) * 64);
                        }
                }
            }
            if (j->pos >= j->n) return;
        }
        if (m < mcus) {
            if (!jnext_rst(j)) return;
            j->eobrun = 0; j->ac_state = 0;
            for (int i = 0; i < ns; i++) sc[i]->pred = 0;
        }
    }
}

static float idct_t[8][8];
static bool  idct_ready = false;

static void idct_init(void) {
    if (idct_ready) return;
    for (int x = 0; x < 8; x++)
        for (int u = 0; u < 8; u++) {
            double cu = u == 0 ? 0.70710678118654752 : 1.0;
            idct_t[x][u] = (float)(cu * 0.5 * cos((2 * x + 1) * u * 3.14159265358979323846 / 16.0));
        }
    idct_ready = true;
}

static void idct_block(const short *coef, const uint16_t *q, uint8_t *out, int stride) {
    float in[64], tmp[64];
    for (int i = 0; i < 64; i++) in[i] = (float)coef[i] * (float)q[i];
    for (int y = 0; y < 8; y++)
        for (int x = 0; x < 8; x++) {
            float s = 0;
            for (int u = 0; u < 8; u++) s += in[y * 8 + u] * idct_t[x][u];
            tmp[y * 8 + x] = s;
        }
    for (int x = 0; x < 8; x++)
        for (int y = 0; y < 8; y++) {
            float s = 0;
            for (int v = 0; v < 8; v++) s += tmp[v * 8 + x] * idct_t[y][v];
            int px = (int)(s + 128.5f);
            out[y * stride + x] = clamp8(px);
        }
}

static void exif_orientation(Jpg *j, const uint8_t *s, size_t n) {
    if (n < 14 || memcmp(s, "Exif\0\0", 6)) return;
    const uint8_t *t = s + 6;
    size_t tn = n - 6;
    bool le = t[0] == 'I';
    #define R16(p) (le ? le16(p) : be16(p))
    #define R32(p) (le ? le32(p) : be32(p))
    uint32_t ifd = R32(t + 4);
    if (ifd + 2 > tn) return;
    unsigned cnt = R16(t + ifd);
    for (unsigned i = 0; i < cnt; i++) {
        size_t e = ifd + 2 + (size_t)i * 12;
        if (e + 12 > tn) return;
        if (R16(t + e) == 0x0112) { j->orientation = (int)R16(t + e + 8); return; }
    }
    #undef R16
    #undef R32
}

static void apply_orientation(Bitmap *b, int o) {
    if (o < 2 || o > 8) return;
    int W = b->w, H = b->h;
    bool swap = o >= 5;
    int nw = swap ? H : W, nh = swap ? W : H;
    uint8_t *np = malloc((size_t)nw * (size_t)nh * 4);
    if (!np) return;
    for (int y = 0; y < nh; y++)
        for (int x = 0; x < nw; x++) {
            int sx, sy;
            switch (o) {
                case 2: sx = W - 1 - x; sy = y;         break;
                case 3: sx = W - 1 - x; sy = H - 1 - y; break;
                case 4: sx = x;         sy = H - 1 - y; break;
                case 5: sx = y;         sy = x;         break;
                case 6: sx = y;         sy = H - 1 - x; break;
                case 7: sx = W - 1 - y; sy = H - 1 - x; break;
                default: sx = W - 1 - y; sy = x;        break;   /* 8 */
            }
            memcpy(np + ((size_t)y * nw + x) * 4, b->px + ((size_t)sy * W + sx) * 4, 4);
        }
    free(b->px);
    b->px = np;
    b->w = nw; b->h = nh;
    if (swap) { int t = b->src_w; b->src_w = b->src_h; b->src_h = t; }
}

static void jfree(Jpg *j) {
    for (int i = 0; i < 4; i++) { free(j->comp[i].coef); free(j->comp[i].plane); }
}

static int decode_jpeg(const uint8_t *d, size_t n, Bitmap *bm, char *err, size_t esz) {
    Jpg *j = calloc(1, sizeof *j);
    if (!j) return fail(err, esz, "JPEG: out of memory");
    j->d = d; j->n = n;
    j->transform = -1;
    size_t pos = 2;
    int rc = 0;

    while (pos + 4 <= n) {
        if (d[pos] != 0xFF) { pos++; continue; }
        uint8_t m = d[pos + 1];
        if (m == 0xFF) { pos++; continue; }
        pos += 2;
        if (m == 0x00 || m == 0x01 || m == 0xD8 || (m >= 0xD0 && m <= 0xD7)) continue;
        if (m == 0xD9) break;
        if (pos + 2 > n) break;
        size_t len = be16(d + pos);
        if (len < 2 || pos + len > n) break;
        const uint8_t *s = d + pos + 2;
        size_t sl = len - 2;

        if (m == 0xDB) {                                   /* quantisation tables */
            for (size_t o = 0; o < sl; ) {
                int pq = s[o] >> 4, tq = s[o] & 3;
                o++;
                for (int k = 0; k < 64; k++) {
                    if (o + (pq ? 2 : 1) > sl) break;
                    j->qt[tq][zz[k]] = (uint16_t)(pq ? be16(s + o) : s[o]);
                    o += pq ? 2 : 1;
                }
            }
        } else if (m == 0xC4) {                            /* Huffman tables */
            for (size_t o = 0; o + 17 <= sl; ) {
                int tc = s[o] >> 4, th = s[o] & 3;
                JHuff *h = tc ? &j->ac[th] : &j->dc[th];
                int total = 0;
                memset(h, 0, sizeof *h);
                for (int l = 1; l <= 16; l++) { h->bits[l] = s[o + (size_t)l]; total += h->bits[l]; }
                o += 17;
                if (total > 256 || o + (size_t)total > sl) break;
                memcpy(h->vals, s + o, (size_t)total);
                o += (size_t)total;
                jh_build(h);
            }
        } else if (m == 0xC0 || m == 0xC1 || m == 0xC2) {  /* frame */
            if (sl < 6 || s[0] != 8) { rc = fail(err, esz, "JPEG: only 8-bit images are supported"); goto done; }
            j->progressive = m == 0xC2;
            j->h = (int)be16(s + 1); j->w = (int)be16(s + 3);
            j->ncomp = s[5];
            if (j->ncomp < 1 || j->ncomp > 4 || sl < 6 + (size_t)j->ncomp * 3 || j->w <= 0 || j->h <= 0) {
                rc = fail(err, esz, "JPEG: bad frame header"); goto done;
            }
            if ((uint64_t)j->w * (uint64_t)j->h > 4u * MAX_PIXELS) { rc = fail(err, esz, "JPEG: image too large"); goto done; }
            j->hmax = j->vmax = 1;
            for (int i = 0; i < j->ncomp; i++) {
                JComp *c = &j->comp[i];
                c->id = s[6 + i * 3];
                c->h  = s[7 + i * 3] >> 4;
                c->v  = s[7 + i * 3] & 15;
                c->tq = s[8 + i * 3] & 3;
                if (c->h < 1 || c->h > 4 || c->v < 1 || c->v > 4) { rc = fail(err, esz, "JPEG: bad sampling"); goto done; }
                if (c->h > j->hmax) j->hmax = c->h;
                if (c->v > j->vmax) j->vmax = c->v;
            }
            j->mcux = (j->w + 8 * j->hmax - 1) / (8 * j->hmax);
            j->mcuy = (j->h + 8 * j->vmax - 1) / (8 * j->vmax);
            for (int i = 0; i < j->ncomp; i++) {
                JComp *c = &j->comp[i];
                int cw = (j->w * c->h + j->hmax - 1) / j->hmax;
                int chh = (j->h * c->v + j->vmax - 1) / j->vmax;
                c->bpl  = (cw + 7) / 8;
                c->bpc  = (chh + 7) / 8;
                c->bplm = j->mcux * c->h;
                c->bpcm = j->mcuy * c->v;
                c->coef = calloc((size_t)c->bplm * (size_t)c->bpcm * 64, sizeof *c->coef);
                if (!c->coef) { rc = fail(err, esz, "JPEG: out of memory"); goto done; }
            }
            /* photos far bigger than any terminal: keep only the DC
             * coefficients, i.e. decode at 1/8 scale */
            j->dc_only = (uint64_t)j->w * (uint64_t)j->h > 2200000u && j->w >= 1600;
            j->have_frame = true;
        } else if ((m >= 0xC3 && m <= 0xCF) && m != 0xC4 && m != 0xC8 && m != 0xCC) {
            rc = fail(err, esz, "JPEG: lossless / arithmetic-coded JPEG is not supported");
            goto done;
        } else if (m == 0xDD) {
            if (sl >= 2) j->restart = (int)be16(s);
        } else if (m == 0xE1) {
            exif_orientation(j, s, sl);
        } else if (m == 0xEE) {
            if (sl >= 12 && !memcmp(s, "Adobe", 5)) { j->adobe = true; j->transform = s[11]; }
        } else if (m == 0xDA) {                            /* scan */
            if (!j->have_frame || sl < 1) { rc = fail(err, esz, "JPEG: scan before frame"); goto done; }
            int ns = s[0];
            if (ns < 1 || ns > 4 || sl < 1 + (size_t)ns * 2 + 3) { rc = fail(err, esz, "JPEG: bad scan header"); goto done; }
            JComp *sc[4];
            int got = 0;
            for (int i = 0; i < ns; i++) {
                int cid = s[1 + i * 2], tabs = s[2 + i * 2];
                for (int k = 0; k < j->ncomp; k++)
                    if (j->comp[k].id == cid) {
                        sc[got] = &j->comp[k];
                        sc[got]->td = (tabs >> 4) & 3;
                        sc[got]->ta = tabs & 3;
                        got++;
                        break;
                    }
            }
            const uint8_t *t = s + 1 + ns * 2;
            j->ss = t[0]; j->se = t[1] > 63 ? 63 : t[1];
            j->ah = t[2] >> 4; j->al = t[2] & 15;
            j->pos = pos + len;
            if (got == ns && !(j->dc_only && j->progressive && j->ss > 0))
                jscan(j, sc, ns);
            pos = j->pos;
            continue;
        }
        pos += len;
    }

    if (!j->have_frame) { rc = fail(err, esz, "JPEG: no image frame"); goto done; }

    /* samples of every component */
    idct_init();
    int scale = j->dc_only ? 8 : 1;
    for (int i = 0; i < j->ncomp; i++) {
        JComp *c = &j->comp[i];
        c->pw = c->bplm * 8 / scale;
        c->ph = c->bpcm * 8 / scale;
        c->plane = malloc((size_t)c->pw * (size_t)c->ph);
        if (!c->plane) { rc = fail(err, esz, "JPEG: out of memory"); goto done; }
        const uint16_t *q = j->qt[c->tq];
        for (int by = 0; by < c->bpcm; by++)
            for (int bx = 0; bx < c->bplm; bx++) {
                const short *z = c->coef + ((size_t)by * (size_t)c->bplm + (size_t)bx) * 64;
                if (j->dc_only)
                    c->plane[(size_t)by * (size_t)c->pw + (size_t)bx] = clamp8((int)((float)z[0] * q[0] / 8.0f + 128.5f));
                else
                    idct_block(z, q, c->plane + ((size_t)by * 8) * (size_t)c->pw + (size_t)bx * 8, c->pw);
            }
        free(c->coef);
        c->coef = NULL;
    }

    int ow = (j->w + scale - 1) / scale, oh = (j->h + scale - 1) / scale;
    if (!bm_alloc(bm, ow, oh)) { rc = fail(err, esz, "JPEG: image too large"); goto done; }
    bm->src_w = j->w; bm->src_h = j->h;
    bool ycc = j->ncomp >= 3 && !(j->adobe && j->transform == 0 && j->ncomp == 3);
    for (int y = 0; y < oh; y++)
        for (int x = 0; x < ow; x++) {
            int v[4] = { 0, 0, 0, 0 };
            for (int i = 0; i < j->ncomp; i++) {
                JComp *c = &j->comp[i];
                int sx = x * c->h / j->hmax, sy = y * c->v / j->vmax;
                if (sx >= c->pw) sx = c->pw - 1;
                if (sy >= c->ph) sy = c->ph - 1;
                v[i] = c->plane[(size_t)sy * (size_t)c->pw + (size_t)sx];
            }
            uint8_t *o = bm->px + ((size_t)y * (size_t)ow + (size_t)x) * 4;
            int r, g, b;
            if (j->ncomp == 1) {
                r = g = b = v[0];
            } else if (ycc && (j->ncomp == 3 || j->transform == 2)) {
                float Y = (float)v[0], cb = (float)v[1] - 128.f, cr = (float)v[2] - 128.f;
                r = (int)(Y + 1.402f * cr + 0.5f);
                g = (int)(Y - 0.344136f * cb - 0.714136f * cr + 0.5f);
                b = (int)(Y + 1.772f * cb + 0.5f);
            } else {
                r = v[0]; g = v[1]; b = v[2];
            }
            if (j->ncomp == 4) {               /* Adobe CMYK is stored inverted */
                int k = v[3];
                r = clamp8(r) * k / 255; g = clamp8(g) * k / 255; b = clamp8(b) * k / 255;
            }
            o[0] = clamp8(r); o[1] = clamp8(g); o[2] = clamp8(b); o[3] = 255;
        }
    apply_orientation(bm, j->orientation);
    bm->fmt = j->progressive ? "JPEG (progressive)" : "JPEG";
    rc = 1;
done:
    jfree(j);
    free(j);
    if (rc != 1) bitmap_free(bm);
    return rc;
}

/* ═══ GIF ═══════════════════════════════════════════════════════════ */

static size_t lzw_decode(const uint8_t *in, size_t n, int minsize, uint8_t *out, size_t outn) {
    if (minsize < 1 || minsize > 11) return 0;
    static uint16_t prefix[4096];
    static uint8_t  suffix[4096], stack[4097];
    int clear = 1 << minsize, eoi = clear + 1;
    int next = clear + 2, size = minsize + 1;
    for (int i = 0; i < clear && i < 4096; i++) { prefix[i] = 0; suffix[i] = (uint8_t)i; }
    size_t o = 0, bitpos = 0, nbits = n * 8;
    int prev = -1, firstch = 0;
    while (o < outn && bitpos + (size_t)size <= nbits) {
        int code = 0;
        for (int b = 0; b < size; b++, bitpos++)
            code |= ((in[bitpos >> 3] >> (bitpos & 7)) & 1) << b;
        if (code == clear) { size = minsize + 1; next = clear + 2; prev = -1; continue; }
        if (code == eoi) break;
        if (prev < 0) {
            if (code >= clear) break;
            out[o++] = (uint8_t)code;
            prev = firstch = code;
            continue;
        }
        int c = code, sp = 0;
        if (code >= next) {
            if (code > next) break;               /* corrupt */
            stack[sp++] = (uint8_t)firstch;
            c = prev;
        }
        while (c >= clear && sp < 4096) { stack[sp++] = suffix[c]; c = prefix[c]; }
        stack[sp++] = (uint8_t)c;
        firstch = c;
        while (sp && o < outn) out[o++] = stack[--sp];
        if (next < 4096) {
            prefix[next] = (uint16_t)prev;
            suffix[next] = (uint8_t)firstch;
            next++;
            if (next == (1 << size) && size < 12) size++;
        }
        prev = code;
    }
    return o;
}

static int decode_gif(const uint8_t *d, size_t n, Bitmap *bm, char *err, size_t esz) {
    if (n < 13) return fail(err, esz, "GIF: file too short");
    int sw = (int)le16(d + 6), sh = (int)le16(d + 8);
    uint8_t flags = d[10];
    size_t pos = 13;
    const uint8_t *gct = NULL;
    int gct_n = 0;
    if (flags & 0x80) {
        gct_n = 1 << ((flags & 7) + 1);
        gct = d + pos;
        pos += (size_t)gct_n * 3;
    }
    if (!bm_alloc(bm, sw, sh)) return fail(err, esz, "GIF: bad size");
    int trans = -1;
    while (pos < n) {
        uint8_t b = d[pos++];
        if (b == 0x21) {                                   /* extension */
            if (pos >= n) break;
            uint8_t label = d[pos++];
            if (label == 0xF9 && pos + 5 <= n && d[pos] == 4) {
                if (d[pos + 1] & 1) trans = d[pos + 4];
            }
            while (pos < n && d[pos]) pos += 1 + d[pos];
            pos++;
        } else if (b == 0x2C) {                            /* image */
            if (pos + 9 > n) break;
            int ix = (int)le16(d + pos), iy = (int)le16(d + pos + 2);
            int iw = (int)le16(d + pos + 4), ih = (int)le16(d + pos + 6);
            uint8_t pf = d[pos + 8];
            pos += 9;
            const uint8_t *pal = gct;
            int pal_n = gct_n;
            if (pf & 0x80) {
                pal_n = 1 << ((pf & 7) + 1);
                pal = d + pos;
                pos += (size_t)pal_n * 3;
            }
            if (pos >= n || iw <= 0 || ih <= 0) break;
            int minsize = d[pos++];
            uint8_t *buf = malloc(n - pos + 1);
            size_t bn = 0;
            while (pos < n && d[pos]) {
                size_t l = d[pos++];
                if (pos + l > n) l = n - pos;
                memcpy(buf + bn, d + pos, l);
                bn += l;
                pos += l;
            }
            size_t npx = (size_t)iw * (size_t)ih;
            uint8_t *idx = calloc(npx ? npx : 1, 1);
            if (!idx) { free(buf); break; }
            size_t got = lzw_decode(buf, bn, minsize, idx, npx);
            free(buf);
            bool inter = (pf & 0x40) != 0;
            static const int start[4] = { 0, 4, 2, 1 }, step[4] = { 8, 8, 4, 2 };
            int row = 0, pass = 0, prow = 0;
            for (int r = 0; r < ih; r++) {
                if (inter) {
                    while (pass < 4 && prow >= ih) { pass++; if (pass < 4) prow = start[pass]; }
                    if (pass >= 4) break;
                    row = prow;
                    prow += step[pass];
                } else row = r;
                int y = iy + row;
                if (y < 0 || y >= sh) continue;
                for (int x = 0; x < iw; x++) {
                    size_t k = (size_t)r * (size_t)iw + (size_t)x;
                    if (k >= got) break;
                    int c = idx[k];
                    int X = ix + x;
                    if (X < 0 || X >= sw || c == trans || !pal || c >= pal_n) continue;
                    uint8_t *o = bm->px + ((size_t)y * (size_t)sw + (size_t)X) * 4;
                    o[0] = pal[c * 3]; o[1] = pal[c * 3 + 1]; o[2] = pal[c * 3 + 2]; o[3] = 255;
                }
            }
            free(idx);
            bm->fmt = "GIF";
            return 1;                                      /* first frame only */
        } else break;
    }
    bitmap_free(bm);
    return fail(err, esz, "GIF: no image in the file");
}

/* ═══ BMP / ICO ═════════════════════════════════════════════════════ */

static int mask_shift(uint32_t m) { int s = 0; if (!m) return 0; while (!(m & 1)) { m >>= 1; s++; } return s; }
static int mask_bits(uint32_t m)  { int b = 0; while (m) { b += m & 1; m >>= 1; } return b; }
static uint8_t mask_get(uint32_t v, uint32_t m) {
    if (!m) return 0;
    int s = mask_shift(m), b = mask_bits(m);
    uint32_t x = (v & m) >> s;
    if (b >= 8) return (uint8_t)(x >> (b - 8));
    uint32_t max = (1u << b) - 1;
    return (uint8_t)(x * 255 / max);
}

/* A DIB (BMP without its file header). `pix` is where the pixels start;
 * an icon DIB stores twice its height (image + AND transparency mask). */
static int decode_dib(const uint8_t *dib, size_t n, size_t pix, bool icon, Bitmap *bm,
                      char *err, size_t esz) {
    if (n < 12) return fail(err, esz, "BMP: header too short");
    uint32_t hs = le32(dib);
    int w, h, bpp;
    uint32_t comp = 0, clrused = 0;
    uint32_t rm = 0, gm = 0, bmk = 0, am = 0;
    int pal_entry = 4;
    if (hs == 12) {
        w = (int)le16(dib + 4); h = (int16_t)le16(dib + 6); bpp = (int)le16(dib + 10);
        pal_entry = 3;
    } else {
        if (n < 40) return fail(err, esz, "BMP: header too short");
        w = (int32_t)le32(dib + 4); h = (int32_t)le32(dib + 8);
        bpp = (int)le16(dib + 14); comp = le32(dib + 16); clrused = le32(dib + 32);
        if ((comp == 3 || comp == 6) && n >= 52) {        /* masks: in or right after the header */
            rm = le32(dib + 40); gm = le32(dib + 44); bmk = le32(dib + 48);
            if ((hs >= 56 || comp == 6) && n >= 56) am = le32(dib + 52);
        }
    }
    if (comp == 1 || comp == 2) return fail(err, esz, "BMP: RLE-compressed bitmaps are not supported");
    if (comp == 4 || comp == 5) return fail(err, esz, "BMP: embedded JPEG/PNG bitmaps are not supported");
    bool topdown = h < 0;
    if (topdown) h = -h;
    if (icon) h /= 2;
    if (!bm_alloc(bm, w, h)) return fail(err, esz, "BMP: bad size");

    size_t pal_off = hs + ((comp == 3 && hs == 40) ? 12 : 0);
    int npal = bpp <= 8 ? (clrused ? (int)clrused : 1 << bpp) : 0;
    if (npal > 256) npal = 256;
    if (pix == 0) pix = pal_off + (size_t)npal * (size_t)pal_entry;
    if (bpp == 16 && !rm) { rm = 0x7C00; gm = 0x03E0; bmk = 0x001F; }
    if (bpp == 32 && !rm) { rm = 0x00FF0000; gm = 0x0000FF00; bmk = 0x000000FF; }
    size_t stride = (((size_t)w * (size_t)bpp + 31) / 32) * 4;
    bool any_alpha = false;

    for (int y = 0; y < h; y++) {
        size_t ro = pix + (size_t)y * stride;
        if (ro + stride > n) break;
        const uint8_t *r = dib + ro;
        int oy = topdown ? y : h - 1 - y;
        for (int x = 0; x < w; x++) {
            uint8_t *o = bm->px + ((size_t)oy * (size_t)w + (size_t)x) * 4;
            o[3] = 255;
            if (bpp <= 8) {
                size_t bit = (size_t)x * (size_t)bpp;
                int idx = (r[bit >> 3] >> (8 - bpp - (int)(bit & 7))) & ((1 << bpp) - 1);
                if (idx < npal && pal_off + (size_t)idx * pal_entry + 3 <= n) {
                    const uint8_t *p = dib + pal_off + (size_t)idx * (size_t)pal_entry;
                    o[0] = p[2]; o[1] = p[1]; o[2] = p[0];
                }
            } else if (bpp == 24) {
                o[0] = r[x * 3 + 2]; o[1] = r[x * 3 + 1]; o[2] = r[x * 3];
            } else if (bpp == 16) {
                uint32_t v = le16(r + x * 2);
                o[0] = mask_get(v, rm); o[1] = mask_get(v, gm); o[2] = mask_get(v, bmk);
                if (am) o[3] = mask_get(v, am);
            } else if (bpp == 32) {
                uint32_t v = le32(r + x * 4);
                o[0] = mask_get(v, rm); o[1] = mask_get(v, gm); o[2] = mask_get(v, bmk);
                /* BI_RGB: the top byte is unused in a .bmp, but is the alpha
                 * channel of a 32-bit icon */
                uint8_t a = am ? mask_get(v, am) : icon ? (uint8_t)(v >> 24) : 255;
                if (a) any_alpha = true;
                o[3] = a;
            }
        }
    }
    /* 32-bit bitmaps very often leave the alpha byte at 0: then it means
     * nothing and the picture is opaque */
    if (bpp == 32 && !any_alpha && !am)
        for (size_t k = 0; k < (size_t)w * (size_t)h; k++) bm->px[k * 4 + 3] = 255;
    if (icon && (bpp < 32 || !any_alpha)) {                 /* AND mask */
        size_t mo = pix + (size_t)h * stride;
        size_t ms = (((size_t)w + 31) / 32) * 4;
        for (int y = 0; y < h; y++) {
            if (mo + (size_t)(y + 1) * ms > n) break;
            const uint8_t *r = dib + mo + (size_t)y * ms;
            int oy = topdown ? y : h - 1 - y;
            for (int x = 0; x < w; x++)
                if ((r[x >> 3] >> (7 - (x & 7))) & 1) bm->px[((size_t)oy * (size_t)w + (size_t)x) * 4 + 3] = 0;
        }
    }
    bm->fmt = icon ? "ICO" : "BMP";
    return 1;
}

static int decode_bmp(const uint8_t *d, size_t n, Bitmap *bm, char *err, size_t esz) {
    if (n < 26) return fail(err, esz, "BMP: file too short");
    size_t off = le32(d + 10);
    if (off < 14 || off >= n) return fail(err, esz, "BMP: bad pixel offset");
    return decode_dib(d + 14, n - 14, off - 14, false, bm, err, esz);
}

static int decode_ico(const uint8_t *d, size_t n, Bitmap *bm, char *err, size_t esz) {
    int count = (int)le16(d + 4);
    int best = -1;
    long best_score = -1;
    for (int i = 0; i < count; i++) {
        size_t e = 6 + (size_t)i * 16;
        if (e + 16 > n) break;
        int w = d[e] ? d[e] : 256, h = d[e + 1] ? d[e + 1] : 256;
        long score = (long)w * h * 64 + le16(d + e + 6);
        if (score > best_score) { best_score = score; best = i; }
    }
    if (best < 0) return fail(err, esz, "ICO: no image in the file");
    size_t e = 6 + (size_t)best * 16;
    size_t sz = le32(d + e + 8), off = le32(d + e + 12);
    if (off >= n) return fail(err, esz, "ICO: bad offset");
    if (sz > n - off) sz = n - off;
    if (sz >= 8 && !memcmp(d + off, "\x89PNG", 4)) {
        int r = decode_png(d + off, sz, bm, err, esz);
        if (r == 1) bm->fmt = "ICO";
        return r;
    }
    return decode_dib(d + off, sz, 0, true, bm, err, esz);
}

/* ═══ PNM ═══════════════════════════════════════════════════════════ */

static bool pnm_int(const uint8_t *d, size_t n, size_t *pos, int *out) {
    while (*pos < n) {
        if (d[*pos] == '#') { while (*pos < n && d[*pos] != '\n') (*pos)++; }
        else if (d[*pos] == ' ' || d[*pos] == '\t' || d[*pos] == '\r' || d[*pos] == '\n') (*pos)++;
        else break;
    }
    if (*pos >= n || d[*pos] < '0' || d[*pos] > '9') return false;
    long v = 0;
    while (*pos < n && d[*pos] >= '0' && d[*pos] <= '9') { v = v * 10 + (d[*pos] - '0'); if (v > 1 << 24) return false; (*pos)++; }
    *out = (int)v;
    return true;
}

static int decode_pnm(const uint8_t *d, size_t n, Bitmap *bm, char *err, size_t esz) {
    int kind = d[1] - '0';
    size_t pos = 2;
    int w, h, maxv = 1;
    if (!pnm_int(d, n, &pos, &w) || !pnm_int(d, n, &pos, &h)) return fail(err, esz, "PNM: bad header");
    if (kind != 1 && kind != 4 && !pnm_int(d, n, &pos, &maxv)) return fail(err, esz, "PNM: bad header");
    if (maxv < 1 || maxv > 65535) return fail(err, esz, "PNM: bad maximum value");
    if (!bm_alloc(bm, w, h)) return fail(err, esz, "PNM: bad size");
    if (kind >= 4) pos++;                                 /* the single whitespace */
    int ch = (kind == 3 || kind == 6) ? 3 : 1;
    int bytes = maxv > 255 ? 2 : 1;
    size_t rowbits = (size_t)w;
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            int v[3] = { 0, 0, 0 };
            if (kind == 4) {
                size_t bi = (size_t)y * ((rowbits + 7) / 8) * 8 + (size_t)x;
                size_t byte = pos + bi / 8;
                v[0] = (byte < n && ((d[byte] >> (7 - (bi & 7))) & 1)) ? 0 : 255;
            } else if (kind == 1) {
                int t = 0;
                while (pos < n && (d[pos] == ' ' || d[pos] == '\n' || d[pos] == '\r' || d[pos] == '\t')) pos++;
                if (pos < n) { t = d[pos] == '1'; pos++; }
                v[0] = t ? 0 : 255;
            } else {
                for (int k = 0; k < ch; k++) {
                    int s = 0;
                    if (kind == 2 || kind == 3) { if (!pnm_int(d, n, &pos, &s)) s = 0; }
                    else if (pos + (size_t)bytes <= n) { s = bytes == 2 ? (int)be16(d + pos) : d[pos]; pos += (size_t)bytes; }
                    v[k] = s * 255 / maxv;
                }
            }
            uint8_t *o = bm->px + ((size_t)y * (size_t)w + (size_t)x) * 4;
            o[0] = (uint8_t)v[0];
            o[1] = (uint8_t)(ch == 3 ? v[1] : v[0]);
            o[2] = (uint8_t)(ch == 3 ? v[2] : v[0]);
            o[3] = 255;
        }
    bm->fmt = "PNM";
    return 1;
}

/* ═══ TGA ═══════════════════════════════════════════════════════════ */

static bool tga_plausible(const uint8_t *d, size_t n) {
    if (n < 18) return false;
    int cmt = d[1], it = d[2], bpp = d[16];
    if (cmt > 1) return false;
    if (!(it == 1 || it == 2 || it == 3 || it == 9 || it == 10 || it == 11)) return false;
    if (!(bpp == 8 || bpp == 15 || bpp == 16 || bpp == 24 || bpp == 32)) return false;
    if ((it == 1 || it == 9) && cmt != 1) return false;
    return le16(d + 12) > 0 && le16(d + 14) > 0;
}

static void tga_px(const uint8_t *p, int bpp, uint8_t *o) {
    if (bpp == 8)  { o[0] = o[1] = o[2] = p[0]; o[3] = 255; }
    else if (bpp == 15 || bpp == 16) {
        uint32_t v = le16(p);
        o[0] = (uint8_t)(((v >> 10) & 31) * 255 / 31); o[1] = (uint8_t)(((v >> 5) & 31) * 255 / 31);
        o[2] = (uint8_t)((v & 31) * 255 / 31); o[3] = 255;
    } else { o[0] = p[2]; o[1] = p[1]; o[2] = p[0]; o[3] = bpp == 32 ? p[3] : 255; }
}

static int decode_tga(const uint8_t *d, size_t n, Bitmap *bm, char *err, size_t esz) {
    int idlen = d[0], it = d[2];
    int cmfirst = (int)le16(d + 3), cmlen = (int)le16(d + 5), cmbpp = d[7];
    int w = (int)le16(d + 12), h = (int)le16(d + 14), bpp = d[16], desc = d[17];
    size_t pos = 18 + (size_t)idlen;
    const uint8_t *cmap = d + pos;
    int cmbytes = (cmbpp + 7) / 8;
    if (d[1]) pos += (size_t)cmlen * (size_t)cmbytes;
    if (!bm_alloc(bm, w, h)) return fail(err, esz, "TGA: bad size");
    int pb = (bpp + 7) / 8;
    bool rle = it >= 9, mapped = it == 1 || it == 9;
    bool top = (desc & 0x20) != 0;
    size_t total = (size_t)w * (size_t)h, k = 0;
    while (k < total && pos < n) {
        int cnt = 1;
        bool rep = false;
        if (rle) { uint8_t hd = d[pos++]; cnt = (hd & 0x7F) + 1; rep = hd & 0x80; }
        for (int i = 0; i < cnt && k < total; i++, k++) {
            const uint8_t *p = d + pos;
            if (pos + (size_t)pb > n) { k = total; break; }
            int x = (int)(k % (size_t)w), y = (int)(k / (size_t)w);
            int oy = top ? y : h - 1 - y;
            uint8_t *o = bm->px + ((size_t)oy * (size_t)w + (size_t)x) * 4;
            if (mapped) {
                int idx = (pb == 2 ? (int)le16(p) : p[0]) - cmfirst;
                if (idx >= 0 && idx < cmlen && cmap + (size_t)(idx + 1) * (size_t)cmbytes <= d + n)
                    tga_px(cmap + (size_t)idx * (size_t)cmbytes, cmbpp, o);
            } else tga_px(p, bpp, o);
            if (!rep) pos += (size_t)pb;
        }
        if (rep) pos += (size_t)pb;
    }
    bm->fmt = "TGA";
    return 1;
}

/* ═══ QOI ═══════════════════════════════════════════════════════════ */

static int decode_qoi(const uint8_t *d, size_t n, Bitmap *bm, char *err, size_t esz) {
    if (n < 22) return fail(err, esz, "QOI: file too short");
    int w = (int)be32(d + 4), h = (int)be32(d + 8);
    if (!bm_alloc(bm, w, h)) return fail(err, esz, "QOI: bad size");
    uint8_t idx[64][4];
    memset(idx, 0, sizeof idx);
    uint8_t px[4] = { 0, 0, 0, 255 };
    size_t p = 14, total = (size_t)w * (size_t)h;
    int run = 0;
    for (size_t k = 0; k < total; k++) {
        if (run > 0) run--;
        else if (p < n) {
            uint8_t b1 = d[p++];
            if (b1 == 0xFE && p + 3 <= n)      { px[0] = d[p]; px[1] = d[p + 1]; px[2] = d[p + 2]; p += 3; }
            else if (b1 == 0xFF && p + 4 <= n) { memcpy(px, d + p, 4); p += 4; }
            else if ((b1 & 0xC0) == 0x00)      memcpy(px, idx[b1], 4);
            else if ((b1 & 0xC0) == 0x40) {
                px[0] = (uint8_t)(px[0] + ((b1 >> 4) & 3) - 2);
                px[1] = (uint8_t)(px[1] + ((b1 >> 2) & 3) - 2);
                px[2] = (uint8_t)(px[2] + (b1 & 3) - 2);
            } else if ((b1 & 0xC0) == 0x80 && p < n) {
                uint8_t b2 = d[p++];
                int vg = (b1 & 0x3F) - 32;
                px[0] = (uint8_t)(px[0] + vg - 8 + ((b2 >> 4) & 15));
                px[1] = (uint8_t)(px[1] + vg);
                px[2] = (uint8_t)(px[2] + vg - 8 + (b2 & 15));
            } else if ((b1 & 0xC0) == 0xC0) run = b1 & 0x3F;
            memcpy(idx[(px[0] * 3 + px[1] * 5 + px[2] * 7 + px[3] * 11) % 64], px, 4);
        }
        memcpy(bm->px + k * 4, px, 4);
    }
    bm->fmt = "QOI";
    return 1;
}

/* ICO and TGA headers can both start 00 00 01/02 00: an icon also needs a
 * sane directory (entry count, reserved byte, offset inside the file). */
static bool ico_plausible(const uint8_t *d, size_t n) {
    if (n < 22 || d[0] || d[1] || (d[2] != 1 && d[2] != 2) || d[3]) return false;
    unsigned count = le16(d + 4);
    if (count == 0 || count > 256 || 6 + (size_t)count * 16 > n) return false;
    uint32_t sz = le32(d + 6 + 8), off = le32(d + 6 + 12);
    return d[6 + 3] == 0 && sz > 0 && off >= 6 + count * 16 && off < n;
}

/* ═══ dispatch ══════════════════════════════════════════════════════ */

int img_decode(const uint8_t *d, size_t n, Bitmap *out, char *err, size_t esz) {
    memset(out, 0, sizeof *out);
    err[0] = '\0';
    if (!d || n < 4) return fail(err, esz, "Empty file");
    if (n >= 8 && !memcmp(d, "\x89PNG\r\n\x1a\n", 8))         return decode_png(d, n, out, err, esz);
    if (d[0] == 0xFF && d[1] == 0xD8)                          return decode_jpeg(d, n, out, err, esz);
    if (n >= 6 && (!memcmp(d, "GIF87a", 6) || !memcmp(d, "GIF89a", 6))) return decode_gif(d, n, out, err, esz);
    if (d[0] == 'B' && d[1] == 'M')                            return decode_bmp(d, n, out, err, esz);
    if (ico_plausible(d, n))                                   return decode_ico(d, n, out, err, esz);
    if (!memcmp(d, "qoif", 4))                                 return decode_qoi(d, n, out, err, esz);
    if (d[0] == 'P' && d[1] >= '1' && d[1] <= '6')             return decode_pnm(d, n, out, err, esz);

    const char *other = NULL;
    if (n >= 12 && !memcmp(d, "RIFF", 4) && !memcmp(d + 8, "WEBP", 4)) other = "WebP";
    else if (n >= 12 && !memcmp(d + 4, "ftyp", 4))             other = "HEIF / AVIF";
    else if (!memcmp(d, "II*\0", 4) || !memcmp(d, "MM\0*", 4)) other = "TIFF";
    else if ((n >= 2 && d[0] == 0xFF && d[1] == 0x0A) || (n >= 12 && !memcmp(d, "\0\0\0\x0cJXL ", 8)))
                                                               other = "JPEG XL";
    else {
        size_t k = 0;
        while (k < n && k < 512 && (d[k] == ' ' || d[k] == '\n' || d[k] == '\r' || d[k] == '\t' || d[k] == 0xEF || d[k] == 0xBB || d[k] == 0xBF)) k++;
        if (k < n && d[k] == '<') other = "SVG";
        else if (n >= 9 && !memcmp(d, "/* XPM */", 9)) other = "XPM";
    }
    if (other) { snprintf(err, esz, "%s is not supported by the built-in decoders", other); return -1; }
    if (tga_plausible(d, n)) return decode_tga(d, n, out, err, esz);
    snprintf(err, esz, "Unknown image format");
    return -1;
}
