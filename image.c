/* Image view: pictures drawn in the pane, with no external program.
 *
 * The file is decoded by the built-in decoders (imgdecode.c), shrunk once
 * to at most 1024 px, then for every pane size:
 *   1. scaled with an area average to fit the pane (cells are about twice
 *      as tall as wide, so a cell holds two square pixels: '▀' with the
 *      top pixel as foreground and the bottom one as background),
 *   2. dithered (Floyd–Steinberg) to the 240 fixed colors of the xterm-256
 *      palette — 16..255, the same on every terminal, unlike 0..15 which
 *      follow the terminal theme,
 *   3. centered; transparent pixels show the terminal background.
 * When the terminal cannot hold that many color pairs, each cell shows a
 * single pixel instead (a colored space).
 *
 * Formats the decoders do not read (WebP, SVG, HEIC...) fall back to
 * chafa when it happens to be installed; it is never required. */
#include "abyss.h"
#include "utf8.h"
#include "imgdecode.h"
#include <strings.h>

static const char *img_exts[] = {
    ".png", ".jpg", ".jpeg", ".jpe", ".jfif", ".gif", ".bmp", ".dib", ".ico", ".cur",
    ".ppm", ".pgm", ".pbm", ".pnm", ".tga", ".qoi",
    /* through chafa only, when installed */
    ".webp", ".svg", ".tif", ".tiff", ".avif", ".heic", ".heif", ".jxl", ".xpm", NULL
};

static const char *file_ext(const char *path) {
    const char *slash = strrchr(path, '/');
#ifdef _WIN32
    const char *bs = strrchr(path, '\\');
    if (bs && (!slash || bs > slash)) slash = bs;
#endif
    const char *dot = strrchr(slash ? slash + 1 : path, '.');
    return dot ? dot : "";
}

static const char *file_base(const char *path) {
    const char *slash = strrchr(path, '/');
#ifdef _WIN32
    const char *bs = strrchr(path, '\\');
    if (bs && (!slash || bs > slash)) slash = bs;
#endif
    return slash ? slash + 1 : path;
}

bool img_is_image(const char *path) {
    if (!path || !*path) return false;
    const char *e = file_ext(path);
    for (int i = 0; img_exts[i]; i++) if (strcasecmp(e, img_exts[i]) == 0) return true;
    return false;
}

ImageView *img_new(const char *path) {
    ImageView *iv = calloc(1, sizeof *iv);
    snprintf(iv->path, sizeof iv->path, "%s", path);
    iv->dither = false;              /* cleaner at terminal resolutions; d toggles */
    return iv;
}

static void img_drop_cells(ImageView *iv) {
    free(iv->top); free(iv->bot);
    iv->top = iv->bot = NULL;
    iv->req_w = iv->req_h = 0;
}

static void img_drop(ImageView *iv) {
    free(iv->rgba); iv->rgba = NULL;
    free(iv->art);  iv->art = NULL; iv->art_len = 0;
    img_drop_cells(iv);
    iv->loaded = false;
    iv->use_chafa = false;
    iv->err[0] = '\0';
}

void img_free(ImageView *iv) {
    if (!iv) return;
    img_drop(iv);
    free(iv);
}

void img_reload(ImageView *iv)        { if (iv) img_drop(iv); }
void img_toggle_dither(ImageView *iv) { if (iv) { iv->dither = !iv->dither; img_drop_cells(iv); } }

/* ─── Resampling ───────────────────────────────────────────────── */

/* Area-average of the source rectangle that lands on each target pixel
 * (plain sampling when enlarging). Output: premultiplied RGB + alpha. */
static void resample(const uint8_t *src, int sw, int sh, float *dst, int tw, int th) {
    for (int ty = 0; ty < th; ty++) {
        int y0 = (int)((int64_t)ty * sh / th), y1 = (int)((int64_t)(ty + 1) * sh / th);
        if (y1 <= y0) y1 = y0 + 1;
        if (y1 > sh) y1 = sh;
        for (int tx = 0; tx < tw; tx++) {
            int x0 = (int)((int64_t)tx * sw / tw), x1 = (int)((int64_t)(tx + 1) * sw / tw);
            if (x1 <= x0) x1 = x0 + 1;
            if (x1 > sw) x1 = sw;
            float r = 0, g = 0, b = 0, a = 0;
            for (int y = y0; y < y1; y++) {
                const uint8_t *p = src + ((size_t)y * (size_t)sw + (size_t)x0) * 4;
                for (int x = x0; x < x1; x++, p += 4) {
                    float al = p[3];
                    r += p[0] * al; g += p[1] * al; b += p[2] * al; a += al;
                }
            }
            float cnt = (float)((y1 - y0) * (x1 - x0));
            float *o = dst + ((size_t)ty * (size_t)tw + (size_t)tx) * 4;
            if (a > 0) { o[0] = r / a; o[1] = g / a; o[2] = b / a; }
            else       { o[0] = o[1] = o[2] = 0; }
            o[3] = a / cnt;
        }
    }
}

/* The bitmap is shrunk once so later re-layouts stay instant. */
static void shrink_bitmap(Bitmap *b, int max_side) {
    if (b->w <= max_side && b->h <= max_side) return;
    double s = (double)max_side / (b->w > b->h ? b->w : b->h);
    int nw = (int)(b->w * s + 0.5), nh = (int)(b->h * s + 0.5);
    if (nw < 1) nw = 1;
    if (nh < 1) nh = 1;
    float *tmp = malloc((size_t)nw * (size_t)nh * 4 * sizeof *tmp);
    uint8_t *np = malloc((size_t)nw * (size_t)nh * 4);
    if (!tmp || !np) { free(tmp); free(np); return; }
    resample(b->px, b->w, b->h, tmp, nw, nh);
    for (size_t i = 0; i < (size_t)nw * (size_t)nh * 4; i++) {
        float v = tmp[i] + 0.5f;
        np[i] = (uint8_t)(v < 0 ? 0 : v > 255 ? 255 : v);
    }
    free(tmp);
    free(b->px);
    b->px = np; b->w = nw; b->h = nh;
}

/* ─── Palette ──────────────────────────────────────────────────── */

static uint8_t pal[256][3];
static bool    pal_ready = false;

static void pal_init(void) {
    if (pal_ready) return;
    static const uint8_t ansi[16][3] = {
        {0,0,0},{205,0,0},{0,205,0},{205,205,0},{0,0,238},{205,0,205},{0,205,205},{229,229,229},
        {127,127,127},{255,0,0},{0,255,0},{255,255,0},{92,92,255},{255,0,255},{0,255,255},{255,255,255}
    };
    for (int i = 0; i < 16; i++) memcpy(pal[i], ansi[i], 3);
    static const uint8_t lv[6] = { 0, 95, 135, 175, 215, 255 };
    for (int i = 0; i < 216; i++) {
        pal[16 + i][0] = lv[i / 36]; pal[16 + i][1] = lv[(i / 6) % 6]; pal[16 + i][2] = lv[i % 6];
    }
    for (int i = 0; i < 24; i++) pal[232 + i][0] = pal[232 + i][1] = pal[232 + i][2] = (uint8_t)(8 + i * 10);
    pal_ready = true;
}

static inline int cube_level(float v) {
    if (v < 48)  return 0;
    if (v < 115) return 1;
    int l = (int)((v - 35) / 40);
    return l > 5 ? 5 : l;
}

static inline float dist2(const float *c, const uint8_t *p) {
    float dr = c[0] - p[0], dg = c[1] - p[1], db = c[2] - p[2];
    return dr * dr * 0.30f + dg * dg * 0.59f + db * db * 0.11f;   /* luma-weighted */
}

/* nearest fixed color: best cube entry vs best gray */
static int nearest256(const float *c) {
    int ci = 16 + 36 * cube_level(c[0]) + 6 * cube_level(c[1]) + cube_level(c[2]);
    float avg = (c[0] + c[1] + c[2]) / 3.0f;
    int gi = (int)((avg - 3.0f) / 10.0f + 0.5f);
    if (gi < 0) gi = 0;
    if (gi > 23) gi = 23;
    gi += 232;
    return dist2(c, pal[gi]) < dist2(c, pal[ci]) ? gi : ci;
}

static int nearest_small(const float *c, int n) {
    int best = 0; float bd = 1e30f;
    for (int i = 0; i < n; i++) { float d = dist2(c, pal[i]); if (d < bd) { bd = d; best = i; } }
    return best;
}

/* Quantises a premultiplied RGBA float image (in place) to palette
 * indices; transparent pixels become -1. */
static void quantise(float *img, int w, int h, short *out, bool dither) {
    int ncolors = COLORS >= 256 ? 256 : COLORS >= 16 ? 16 : 8;
    for (int y = 0; y < h; y++) {
        bool rtl = dither && (y & 1);                      /* serpentine */
        for (int k = 0; k < w; k++) {
            int x = rtl ? w - 1 - k : k;
            float *p = img + ((size_t)y * (size_t)w + (size_t)x) * 4;
            if (p[3] < 24.0f) { out[(size_t)y * (size_t)w + (size_t)x] = -1; continue; }
            float c[3];
            float a = p[3] / 255.0f;                       /* partial alpha over black */
            for (int i = 0; i < 3; i++) {
                c[i] = p[i] * (a > 1 ? 1 : a);
                if (c[i] < 0) c[i] = 0;
                if (c[i] > 255) c[i] = 255;
            }
            int idx = ncolors == 256 ? nearest256(c) : nearest_small(c, ncolors);
            out[(size_t)y * (size_t)w + (size_t)x] = (short)idx;
            if (!dither) continue;
            float e[3] = { c[0] - pal[idx][0], c[1] - pal[idx][1], c[2] - pal[idx][2] };
            int dir = rtl ? -1 : 1;
            struct { int dx, dy; float f; } nb[4] = { { dir, 0, 7 / 16.f }, { -dir, 1, 3 / 16.f },
                                                      { 0, 1, 5 / 16.f }, { dir, 1, 1 / 16.f } };
            for (int n = 0; n < 4; n++) {
                int nx = x + nb[n].dx, ny = y + nb[n].dy;
                if (nx < 0 || nx >= w || ny >= h) continue;
                float *q = img + ((size_t)ny * (size_t)w + (size_t)nx) * 4;
                if (q[3] < 24.0f) continue;
                for (int i = 0; i < 3; i++) q[i] += e[i] * nb[n].f;
            }
        }
    }
}

/* ─── Loading & layout ─────────────────────────────────────────── */

static void img_load(ImageView *iv) {
    iv->loaded = true;
    FILE *f = fopen(iv->path, "rb");
    if (!f) { snprintf(iv->err, sizeof iv->err, "Cannot open: %s", strerror(errno)); return; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0 || n > (256L << 20)) {
        fclose(f);
        snprintf(iv->err, sizeof iv->err, n <= 0 ? "Empty file" : "File too large for the image view");
        return;
    }
    uint8_t *data = malloc((size_t)n);
    size_t got = data ? fread(data, 1, (size_t)n, f) : 0;
    fclose(f);
    Bitmap bm;
    char err[200];
    int rc = img_decode(data, got, &bm, err, sizeof err);
    free(data);
    if (rc == 1) {
        iv->src_w = bm.src_w; iv->src_h = bm.src_h;
        snprintf(iv->fmt, sizeof iv->fmt, "%s", bm.fmt ? bm.fmt : "image");
        shrink_bitmap(&bm, 1024);
        iv->rgba = bm.px; iv->bw = bm.w; iv->bh = bm.h;
        return;
    }
    if (rc < 0 && proc_have("chafa")) { iv->use_chafa = true; return; }
    if (rc < 0) snprintf(iv->err, sizeof iv->err, "%s (install chafa to view it)", err);
    else        snprintf(iv->err, sizeof iv->err, "%s", err);
}

static void img_layout(ImageView *iv, int cols, int rows) {
    img_drop_cells(iv);
    iv->req_w = cols; iv->req_h = rows;
    iv->cols = cols; iv->rows = rows;
    if (!iv->rgba || cols < 1 || rows < 1) return;
    pal_init();

    /* half blocks need one color pair per (top, bottom) couple seen */
    iv->half = COLOR_PAIRS >= 4096;
    for (int attempt = 0; attempt < 2; attempt++) {
        int pw = cols, ph = iv->half ? rows * 2 : rows;
        /* pixels are square in half mode, twice as tall as wide otherwise */
        double sx = (double)pw / iv->bw;
        double sy = iv->half ? (double)ph / iv->bh : (double)ph * 2.0 / iv->bh;
        double s  = sx < sy ? sx : sy;
        int tw = (int)(iv->bw * s + 0.5);
        int th = (int)(iv->bh * s * (iv->half ? 1.0 : 0.5) + 0.5);
        if (tw < 1) tw = 1;
        if (th < 1) th = 1;
        if (tw > pw) tw = pw;
        if (th > ph) th = ph;

        float *buf = malloc((size_t)tw * (size_t)th * 4 * sizeof *buf);
        short *q   = malloc((size_t)tw * (size_t)th * sizeof *q);
        iv->top = malloc((size_t)cols * (size_t)rows * sizeof *iv->top);
        iv->bot = malloc((size_t)cols * (size_t)rows * sizeof *iv->bot);
        if (!buf || !q || !iv->top || !iv->bot) { free(buf); free(q); img_drop_cells(iv); return; }
        resample(iv->rgba, iv->bw, iv->bh, buf, tw, th);
        quantise(buf, tw, th, q, iv->dither);
        free(buf);

        for (size_t i = 0; i < (size_t)cols * (size_t)rows; i++) iv->top[i] = iv->bot[i] = -1;
        int ox = (pw - tw) / 2, oy = (ph - th) / 2;
        for (int y = 0; y < th; y++)
            for (int x = 0; x < tw; x++) {
                int py = oy + y, cx = ox + x;
                int cy = iv->half ? py / 2 : py;
                if (cx < 0 || cx >= cols || cy < 0 || cy >= rows) continue;
                short v = q[(size_t)y * (size_t)tw + (size_t)x];
                size_t k = (size_t)cy * (size_t)cols + (size_t)cx;
                if (!iv->half)        iv->top[k] = iv->bot[k] = v;
                else if (py % 2 == 0) iv->top[k] = v;
                else                  iv->bot[k] = v;
            }
        free(q);
        iv->img_x = ox; iv->img_w = tw;
        iv->img_y = iv->half ? oy / 2 : oy;
        iv->img_h = iv->half ? (oy + th + 1) / 2 - oy / 2 : th;
        if (!iv->half) return;

        /* would the picture need more pairs than the terminal has? */
        static uint8_t seen[65536 / 8];
        memset(seen, 0, sizeof seen);
        int distinct = 0;
        for (size_t i = 0; i < (size_t)cols * (size_t)rows; i++) {
            int t = iv->top[i] & 0xFF, b = iv->bot[i] & 0xFF;
            unsigned key = (unsigned)t << 8 | (unsigned)b;
            if (!(seen[key >> 3] & (1 << (key & 7)))) { seen[key >> 3] |= (uint8_t)(1 << (key & 7)); distinct++; }
        }
        if (distinct + 400 < COLOR_PAIRS) return;
        free(iv->top); free(iv->bot);
        iv->top = iv->bot = NULL;
        iv->half = false;                                  /* retry, one pixel per cell */
    }
}

/* ─── Drawing ──────────────────────────────────────────────────── */

static int pair_for(int fg, int bg) {
#ifdef _WIN32
    if (bg < 0) bg = COLOR_BLACK;         /* default bg is unreliable on the console */
    if (fg < 0) fg = COLOR_WHITE;
#endif
    if (fg >= COLORS) fg = -1;
    if (bg >= COLORS) bg = -1;
    int p = alloc_pair(fg, bg);
    return p < 0 ? 0 : p;
}

static void put_cell(WINDOW *win, int y, int x, int fg, int bg, const char *glyph) {
    int pr = pair_for(fg, bg);
    wattr_set(win, A_NORMAL, (short)pr, &pr);
    mvwaddstr(win, y, x, glyph);
}

static void draw_cells(const ImageView *iv, WINDOW *win) {
    for (int r = 0; r < iv->rows; r++)
        for (int c = 0; c < iv->cols; c++) {
            size_t k = (size_t)r * (size_t)iv->cols + (size_t)c;
            int t = iv->top[k], b = iv->bot[k];
            if (t < 0 && b < 0) continue;                  /* background */
            if (t == b)       put_cell(win, r, c, t, t, " ");
            else if (b < 0)   put_cell(win, r, c, t, -1, "▀");
            else if (t < 0)   put_cell(win, r, c, b, -1, "▄");
            else              put_cell(win, r, c, t, b, "▀");
        }
    wattr_set(win, A_NORMAL, 0, NULL);
}

/* ─── chafa fallback (WebP, SVG...) ────────────────────────────── */

static void chafa_produce(ImageView *iv, int w, int h) {
    free(iv->art);
    iv->art = NULL; iv->art_len = 0;
    iv->req_w = w; iv->req_h = h;
    char size[32], col_opt[32], size_opt[48];
    snprintf(size, sizeof size, "%dx%d", w, h);
    const char *colors = COLORS >= 256 ? "256" : COLORS >= 16 ? "16" : "8";
    snprintf(col_opt, sizeof col_opt, "--colors=%s", colors);
    snprintf(size_opt, sizeof size_opt, "--size=%s", size);
    char *full[] = { "chafa", "--format=symbols", col_opt, size_opt, "--animate=off",
                     "--optimize=0", "--polite=on", iv->path, NULL };
    char *mini[] = { "chafa", "-c", (char *)colors, "-s", size, iv->path, NULL };
    int rc = proc_capture(full, &iv->art, &iv->art_len);
    if (rc != 0 || iv->art_len == 0) { free(iv->art); rc = proc_capture(mini, &iv->art, &iv->art_len); }
    if (rc != 0 || iv->art_len == 0) {
        free(iv->art); iv->art = NULL; iv->art_len = 0;
        snprintf(iv->err, sizeof iv->err, "chafa could not read this image");
    }
}

/* Replays chafa's ANSI output: SGR colors and text, nothing else. */
static void chafa_play(const ImageView *iv, WINDOW *win, int max_h, int max_w) {
    const char *s = iv->art;
    size_t n = iv->art_len;
    int fg = -1, bg = -1, row = 0, col = 0;
    for (size_t i = 0; i < n; ) {
        unsigned char c = (unsigned char)s[i];
        if (c == 0x1b && i + 1 < n && s[i + 1] == '[') {
            size_t j = i + 2;
            while (j < n && ((unsigned char)s[j] < 0x40 || (unsigned char)s[j] > 0x7e)) j++;
            if (j >= n) break;
            if (s[j] == 'm') {
                int v[16], nv = 0, cur = 0;
                for (size_t k = i + 2; k <= j && nv < 16; k++) {
                    if (k == j || s[k] == ';') { v[nv++] = cur; cur = 0; }
                    else if (isdigit((unsigned char)s[k])) cur = cur * 10 + (s[k] - '0');
                }
                for (int k = 0; k < nv; k++) {
                    if (v[k] == 0) fg = bg = -1;
                    else if ((v[k] == 38 || v[k] == 48) && k + 2 < nv && v[k + 1] == 5) {
                        if (v[k] == 38) fg = v[k + 2]; else bg = v[k + 2];
                        k += 2;
                    } else if (v[k] == 39) fg = -1;
                    else if (v[k] == 49) bg = -1;
                }
            }
            i = j + 1;
            continue;
        }
        if (c == 0x1b) { i += 2; continue; }
        if (c == '\n') { row++; col = 0; i++; continue; }
        if (c < 0x20) { i++; continue; }
        uint32_t cp;
        int len = utf8_decode(s + i, n - i, &cp);
        if (len < 1) len = 1;
        int w = utf8_cp_width(cp) > 0 ? utf8_cp_width(cp) : 1;
        if (row < max_h && col + w <= max_w) {
            int pr = pair_for(fg, bg);
            wattr_set(win, A_NORMAL, (short)pr, &pr);
            mvwaddnstr(win, row, col, s + i, len);
        }
        col += w;
        i += (size_t)len;
    }
    wattr_set(win, A_NORMAL, 0, NULL);
}

/* ─── Render ───────────────────────────────────────────────────── */

void img_render(ImageView *iv, WINDOW *win, int win_h, int win_w) {
    if (!iv || !win || win_h < 1 || win_w < 1) return;
    werase(win);
    if (!iv->loaded) img_load(iv);

    bool caption = win_h >= 3;
    int art_h = caption ? win_h - 1 : win_h;

    if (iv->rgba) {
        if (iv->req_w != win_w || iv->req_h != art_h || !iv->top) img_layout(iv, win_w, art_h);
        if (iv->top) draw_cells(iv, win);
    } else if (iv->use_chafa) {
        if (iv->req_w != win_w || iv->req_h != art_h || (!iv->art && !iv->err[0])) chafa_produce(iv, win_w, art_h);
        if (iv->art) chafa_play(iv, win, art_h, win_w);
    }
    if (iv->err[0] && !iv->rgba && !iv->art) {
        wattron(win, COLOR_PAIR(COLOR_PAIR_COMMENT));
        int len = (int)strlen(iv->err);
        int x = len < win_w - 2 ? (win_w - len) / 2 : 1;
        mvwaddnstr(win, art_h / 2, x > 0 ? x : 0, iv->err, win_w > 2 ? win_w - 2 : win_w);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_COMMENT));
    }

    if (caption) {
        char info[160] = "";
        if (iv->rgba)
            snprintf(info, sizeof info, "%dx%d", iv->src_w, iv->src_h);
        else if (iv->use_chafa)
            snprintf(info, sizeof info, "via chafa");
        char keys[96];
        snprintf(keys, sizeof keys, " d:%s  r:reload  F2:hex ", iv->dither ? "smooth" : "dither");
        /* name on the left, details and keys on the right, never overlapping */
        wattron(win, COLOR_PAIR(COLOR_PAIR_STATUS));
        mvwhline(win, win_h - 1, 0, ' ', win_w);
        char left[600];
        snprintf(left, sizeof left, " %s  %s", file_base(iv->path), info);
        int kw = (int)strlen(keys);
        int room = win_w - (kw < win_w / 2 ? kw + 1 : 0);
        mvwaddnstr(win, win_h - 1, 0, left, room > 0 ? room : 0);
        if (kw < win_w / 2) mvwaddstr(win, win_h - 1, win_w - kw, keys);
        wattroff(win, COLOR_PAIR(COLOR_PAIR_STATUS));
    }
    wnoutrefresh(win);
}
