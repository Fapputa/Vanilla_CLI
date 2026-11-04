/* Built-in image decoders: no library, no external program.
 * PNG, JPEG (baseline + progressive), GIF (first frame), BMP, ICO,
 * PNM (P1-P6), TGA and QOI, decoded to 8-bit RGBA. */
#ifndef IMGDECODE_H
#define IMGDECODE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    int         w, h;
    uint8_t    *px;          /* w * h * 4 bytes, RGBA, row-major          */
    const char *fmt;         /* "PNG", "JPEG"...                          */
    int         src_w, src_h;/* size in the file (JPEGs may decode at 1/8) */
} Bitmap;

/* 1 = decoded, 0 = damaged / not decodable, -1 = a format the built-in
 * decoders do not handle (WebP, SVG, HEIC...). `err` says why. */
int  img_decode(const uint8_t *data, size_t len, Bitmap *out, char *err, size_t err_sz);
void bitmap_free(Bitmap *b);

#endif
