#include "abyss.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

#define HL_CP_BASE        130
#define HL_CP_BORDER      (HL_CP_BASE + 0)
#define HL_CP_HEADER      (HL_CP_BASE + 1)
#define HL_CP_SECTION     (HL_CP_BASE + 2)
#define HL_CP_HTTP        (HL_CP_BASE + 3)
#define HL_CP_SENSITIVE   (HL_CP_BASE + 4)
#define HL_CP_IP          (HL_CP_BASE + 5)
#define HL_CP_DATE        (HL_CP_BASE + 6)
#define HL_CP_WORD        (HL_CP_BASE + 7)
#define HL_CP_COUNT       (HL_CP_BASE + 8)
#define HL_CP_MATCH_HTTP  (HL_CP_BASE + 9)
#define HL_CP_MATCH_SENS  (HL_CP_BASE + 10)
#define HL_CP_MATCH_IP    (HL_CP_BASE + 11)
#define HL_CP_MATCH_DATE  (HL_CP_BASE + 12)
#define HL_CP_MATCH_WORD  (HL_CP_BASE + 13)

void hl_colors_init(void) {
    init_pair(HL_CP_BORDER,     COLOR_CYAN,    -1);
    init_pair(HL_CP_HEADER,     COLOR_BLACK,   COLOR_CYAN);
    init_pair(HL_CP_SECTION,    COLOR_CYAN,    -1);
    init_pair(HL_CP_HTTP,       COLOR_CYAN,    -1);
    init_pair(HL_CP_SENSITIVE,  COLOR_RED,     -1);
    init_pair(HL_CP_IP,         COLOR_MAGENTA, -1);
    init_pair(HL_CP_DATE,       COLOR_YELLOW,  -1);
    init_pair(HL_CP_WORD,       COLOR_WHITE,   -1);
    init_pair(HL_CP_COUNT,      COLOR_GREEN,   -1);
    init_pair(HL_CP_MATCH_HTTP, COLOR_BLACK,   COLOR_CYAN);
    init_pair(HL_CP_MATCH_SENS, COLOR_WHITE,   COLOR_RED);
    init_pair(HL_CP_MATCH_IP,   COLOR_BLACK,   COLOR_MAGENTA);
    init_pair(HL_CP_MATCH_DATE, COLOR_BLACK,   COLOR_YELLOW);
    init_pair(HL_CP_MATCH_WORD, COLOR_BLACK,   COLOR_WHITE);
}

typedef struct { const char *w; size_t len; } KW;

static KW HTTP_KW[16];
static int HTTP_KW_N = 0;
static KW SENS_KW[128];
static int SENS_KW_N = 0;
static KW MONTH_KW[32];
static int MONTH_KW_N = 0;

static const char *HTTP_METHODS[] = {
    "GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS","CONNECT","TRACE", NULL
};
static const char *SENSITIVE_WORDS[] = {
    "user","username","password","passwd","pass","token","key","secret",
    "auth","bearer","api_key","apikey","session","cookie","jwt","hash",
    "salt","credential","credentials","login","email","phone","ssn",
    "credit_card","cvv","pin","otp","mfa","2fa","private_key","public_key",
    "host","hostname","port","proxy","gateway","firewall","subnet","dns",
    "ssl","tls","cert","certificate","cipher","handshake","vpn","tunnel",
    "error","err","errno","exception","fatal","panic","crash","segfault",
    "debug","trace","warn","warning","critical","alert","failure","timeout",
    "database","db","query","sql","injection","payload","schema","table",
    "root","admin","sudo","superuser","privilege","escalation","exploit",
    "header","referer","origin","cors","xss","csrf","redirect","callback",
    "endpoint","webhook","request","response","status","code", NULL
};
static const char *MONTH_NAMES[] = {
    "jan","feb","mar","apr","may","jun",
    "jul","aug","sep","oct","nov","dec",
    "january","february","march","april","june","july",
    "august","september","october","november","december", NULL
};

static void kw_tables_init(void) {
    if (HTTP_KW_N) return; 
    for (int i = 0; HTTP_METHODS[i]; i++)
        HTTP_KW[HTTP_KW_N++] = (KW){ HTTP_METHODS[i], strlen(HTTP_METHODS[i]) };
    for (int i = 0; SENSITIVE_WORDS[i]; i++)
        SENS_KW[SENS_KW_N++] = (KW){ SENSITIVE_WORDS[i], strlen(SENSITIVE_WORDS[i]) };
    for (int i = 0; MONTH_NAMES[i]; i++)
        MONTH_KW[MONTH_KW_N++] = (KW){ MONTH_NAMES[i], strlen(MONTH_NAMES[i]) };
}

#define STOP_HT_SIZE 256
static const char *STOP_WORDS[] = {
    "the","a","an","is","it","in","of","to","and","or","for",
    "if","do","int","char","void","return","true","false","null",
    "NULL","new","this","self","else","then","end","not","be",
    "at","by","on","as","so","no","up","my","we","our","its",
    "with","from","that","have","had","has","was","were","are",
    "been","but","also","when","who","they","their","than","can",
    "will","more","some","into","over","out","get","set","use",
    "var","let","def","fn","pub","mod","type","size", NULL
};

static uint8_t stop_ht[STOP_HT_SIZE]; 
static char    stop_ht_keys[STOP_HT_SIZE][16];

static unsigned stop_hash(const char *s) {
    unsigned h = 2166136261u;
    while (*s) h = (h ^ (unsigned char)*s++) * 16777619u;
    return h & (STOP_HT_SIZE - 1);
}

static void stop_ht_init(void) {
    for (int i = 0; STOP_WORDS[i]; i++) {
        unsigned slot = stop_hash(STOP_WORDS[i]);
        
        while (stop_ht[slot] && strcmp(stop_ht_keys[slot], STOP_WORDS[i]) != 0)
            slot = (slot + 1) & (STOP_HT_SIZE - 1);
        stop_ht[slot] = 1;
        strncpy(stop_ht_keys[slot], STOP_WORDS[i], 15);
    }
}

static bool is_stop(const char *w) {
    unsigned slot = stop_hash(w);
    while (stop_ht[slot]) {
        if (strcmp(stop_ht_keys[slot], w) == 0) return true;
        slot = (slot + 1) & (STOP_HT_SIZE - 1);
    }
    return false;
}

HLCtx *hl_new(void) {
    kw_tables_init();
    stop_ht_init();
    HLCtx *h = calloc(1, sizeof *h);
    if (!h) return NULL;
    h->matches = calloc(HL_MAX_MATCHES, sizeof(HLMatch));
    if (!h->matches) { free(h); return NULL; }
    h->dirty   = true;
    h->visible = false;
    h->width   = HIGHLIGHT_DEFAULT_W;
    return h;
}

void hl_free(HLCtx *h) {
    if (!h) return;
    if (h->win) delwin(h->win);
    free(h->matches);
    free(h);
}

/* Optional hook called periodically during hl_scan so the UI can animate a
 * busy indicator while a large file is being aggregated. */
void (*hl_progress_fn)(size_t done, size_t total) = NULL;

static inline bool is_word_char(char c) {
    return isalnum((unsigned char)c) || c == '_';
}

static bool scan_ipv4(const char *buf, size_t off, size_t buflen, size_t *out_len) {
    if (off > 0 && is_word_char(buf[off - 1])) return false;
    size_t pos = off;
    for (int oct = 0; oct < 4; oct++) {
        if (pos >= buflen || !isdigit((unsigned char)buf[pos])) return false;
        int digits = 0, val = 0;
        while (pos < buflen && isdigit((unsigned char)buf[pos])) {
            val = val * 10 + (buf[pos] - '0');
            pos++; digits++;
            if (digits > 3) return false;
        }
        if (val > 255) return false;
        if (oct < 3) {
            if (pos >= buflen || buf[pos] != '.') return false;
            pos++;
        }
    }
    if (pos < buflen && (buf[pos] == '.' || isalpha((unsigned char)buf[pos]))) return false;
    *out_len = pos - off;
    return true;
}

static bool month3_ok(const char *p) {
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    for (int m = 0; m < 12; m++)
        if (memcmp(p, months + 3 * m, 3) == 0) return true;
    return false;
}

static bool scan_date(const char *buf, size_t off, size_t buflen, size_t *out_len) {
    if (off > 0 && isdigit((unsigned char)buf[off - 1])) return false;
    if (off + 8 > buflen) return false;

    /* Apache/CLF: dd/Mon/yyyy[:hh:mm:ss] */
    if (off + 11 <= buflen
        && isdigit((unsigned char)buf[off]) && isdigit((unsigned char)buf[off + 1])
        && buf[off + 2] == '/' && month3_ok(buf + off + 3) && buf[off + 6] == '/'
        && isdigit((unsigned char)buf[off + 7])  && isdigit((unsigned char)buf[off + 8])
        && isdigit((unsigned char)buf[off + 9])  && isdigit((unsigned char)buf[off + 10])) {
        size_t len = 11;
        if (off + 20 <= buflen && buf[off + 11] == ':'
            && isdigit((unsigned char)buf[off + 12]) && isdigit((unsigned char)buf[off + 13])
            && buf[off + 14] == ':'
            && isdigit((unsigned char)buf[off + 15]) && isdigit((unsigned char)buf[off + 16])
            && buf[off + 17] == ':'
            && isdigit((unsigned char)buf[off + 18]) && isdigit((unsigned char)buf[off + 19]))
            len = 20;
        *out_len = len;
        return true;
    }

    char tmp[20]; size_t n = 0, pos = off;
    while (pos < buflen && n < 19) {
        char c = buf[pos];
        if (isdigit((unsigned char)c) || c == '/' || c == '-' || c == ':')
            { tmp[n++] = c; pos++; }
        else break;
    }
    tmp[n] = '\0';
    if (n >= 10 && tmp[2]=='/' && tmp[5]=='/' && isdigit((unsigned char)tmp[6])) { *out_len=10; return true; }
    if (n >= 10 && tmp[4]=='-' && tmp[7]=='-')                                    { *out_len=10; return true; }
    if (n >= 10 && tmp[2]=='-' && tmp[5]=='-' && isdigit((unsigned char)tmp[6])) { *out_len=10; return true; }
    if (n >= 8  && tmp[2]==':' && tmp[5]==':')                                    { *out_len=8;  return true; }
    if (n >= 5  && tmp[2]==':' && isdigit((unsigned char)tmp[3]))                 { *out_len=5;  return true; }
    return false;
}

#define FREQ_BUCKETS 4096   
typedef struct FreqNode { char word[64]; size_t count; struct FreqNode *next; } FreqNode;

#define FREQ_POOL_SIZE 65536
typedef struct FreqPool { FreqNode nodes[FREQ_POOL_SIZE]; size_t used; } FreqPool;

static unsigned str_hash(const char *s) {
    unsigned h = 2166136261u;
    while (*s) h = (h ^ (unsigned char)*s++) * 16777619u;
    return h & (FREQ_BUCKETS - 1);
}

#define IP_DEDUP_BUCKETS  2048
#define DT_DEDUP_BUCKETS  512

typedef struct IPNode { char ip[64]; size_t cnt; struct IPNode *next; } IPNode;
typedef struct DTNode { char dt[64]; size_t cnt; struct DTNode *next; } DTNode;

static inline void add_match_fast(HLCtx *h, size_t off, size_t len, HLCat cat, int cp,
                                   const char *text)
{
    h->cat_count[cat]++;
    if (h->nmatch >= HL_MAX_MATCHES) return;
    HLMatch *m = &h->matches[h->nmatch++];
    m->offset = off;
    m->len    = len;
    m->cat    = cat;
    m->cp     = cp;
    size_t n  = len < 63 ? len : 63;
    memcpy(m->text, text, n);
    m->text[n] = '\0';
}

void hl_scan(HLCtx *h, const GapBuf *g) {
    h->nmatch   = 0;
    h->ntop     = 0;
    h->http_nkw = 0;
    h->sens_nkw = 0;
    memset(h->cat_count, 0, sizeof h->cat_count);

    size_t total = gb_len(g);
    if (total == 0) { h->dirty = false; return; }

    size_t buflen = total;

    char *buf = malloc(buflen + 1);
    if (!buf) { h->dirty = false; return; }
    gb_get_range(g, 0, buflen, buf);
    buf[buflen] = '\0';

    
    FreqNode *buckets[FREQ_BUCKETS];
    memset(buckets, 0, sizeof buckets);
    FreqPool *pool = calloc(1, sizeof *pool);
    if (!pool) { free(buf); h->dirty = false; return; }

    
    IPNode *ip_bkts[IP_DEDUP_BUCKETS];
    DTNode *dt_bkts[DT_DEDUP_BUCKETS];
    memset(ip_bkts, 0, sizeof ip_bkts);
    memset(dt_bkts, 0, sizeof dt_bkts);
    
    IPNode *ip_pool = malloc(8192 * sizeof(IPNode));
    DTNode *dt_pool = malloc(4096 * sizeof(DTNode));
    int ip_pool_used = 0, dt_pool_used = 0;
    int ip_pool_cap  = ip_pool ? 8192 : 0;
    int dt_pool_cap  = dt_pool ? 4096 : 0;

    size_t i = 0;
    size_t next_tick = 0;
    while (i < buflen) {
        if (hl_progress_fn && i >= next_tick) {
            hl_progress_fn(i, buflen);
            next_tick = i + (256u << 10);
        }
        unsigned char c = (unsigned char)buf[i];

        
        if (isdigit(c)) {
            size_t iplen = 0;
            if (scan_ipv4(buf, i, buflen, &iplen)) {
                
                add_match_fast(h, i, iplen, HLCAT_IP, HL_CP_MATCH_IP, buf + i);

                
                if (ip_pool) {
                    char tmp[64];
                    size_t n = iplen < 63 ? iplen : 63;
                    memcpy(tmp, buf + i, n); tmp[n] = '\0';
                    unsigned slot = str_hash(tmp) & (IP_DEDUP_BUCKETS - 1);
                    IPNode *nd = ip_bkts[slot];
                    while (nd && strcmp(nd->ip, tmp) != 0) nd = nd->next;
                    if (!nd && ip_pool_used < ip_pool_cap) {
                        nd = &ip_pool[ip_pool_used++];
                        memcpy(nd->ip, tmp, n + 1);
                        nd->cnt  = 0;
                        nd->next = ip_bkts[slot];
                        ip_bkts[slot] = nd;
                    }
                    if (nd) nd->cnt++;
                }

                i += iplen;
                continue;
            }
            size_t dlen = 0;
            if (scan_date(buf, i, buflen, &dlen)) {
                add_match_fast(h, i, dlen, HLCAT_DATE, HL_CP_MATCH_DATE, buf + i);

                if (dt_pool) {
                    char tmp[64];
                    size_t n = dlen < 63 ? dlen : 63;
                    memcpy(tmp, buf + i, n); tmp[n] = '\0';
                    unsigned slot = str_hash(tmp) & (DT_DEDUP_BUCKETS - 1);
                    DTNode *nd = dt_bkts[slot];
                    while (nd && strcmp(nd->dt, tmp) != 0) nd = nd->next;
                    if (!nd && dt_pool_used < dt_pool_cap) {
                        nd = &dt_pool[dt_pool_used++];
                        memcpy(nd->dt, tmp, n + 1);
                        nd->cnt  = 0;
                        nd->next = dt_bkts[slot];
                        dt_bkts[slot] = nd;
                    }
                    if (nd) nd->cnt++;
                }

                i += dlen;
                continue;
            }
            i++;
            continue;
        }

        
        if (isalpha(c) || c == '_') {
            
            size_t wstart = i;
            while (i < buflen && is_word_char(buf[i])) i++;
            size_t wlen = i - wstart;
            if (wlen == 0) continue;
            if (wlen >= 64) continue; 

            char word[64];
            memcpy(word, buf + wstart, wlen);
            word[wlen] = '\0';

            bool found_cat = false;

            
            for (int m = 0; m < HTTP_KW_N; m++) {
                if (wlen == HTTP_KW[m].len &&
                    memcmp(word, HTTP_KW[m].w, wlen) == 0)
                {
                    add_match_fast(h, wstart, wlen, HLCAT_HTTP, HL_CP_MATCH_HTTP, word);
                    found_cat = true;
                    break;
                }
            }

            if (!found_cat) {
                
                char lw[64];
                for (size_t k = 0; k < wlen; k++) lw[k] = (char)tolower((unsigned char)word[k]);
                lw[wlen] = '\0';

                for (int m = 0; m < SENS_KW_N; m++) {
                    if (wlen == SENS_KW[m].len &&
                        memcmp(lw, SENS_KW[m].w, wlen) == 0)
                    {
                        add_match_fast(h, wstart, wlen, HLCAT_SENSITIVE, HL_CP_MATCH_SENS, word);
                        found_cat = true;
                        break;
                    }
                }

                if (!found_cat) {
                    
                    for (int m = 0; m < MONTH_KW_N; m++) {
                        if (wlen == MONTH_KW[m].len &&
                            memcmp(lw, MONTH_KW[m].w, wlen) == 0)
                        {
                            add_match_fast(h, wstart, wlen, HLCAT_DATE, HL_CP_MATCH_DATE, word);
                            found_cat = true;
                            break;
                        }
                    }
                }

                
                if (wlen >= 3 && !is_stop(lw)) {
                    unsigned slot = str_hash(lw);
                    FreqNode *fn = buckets[slot];
                    while (fn && strcmp(fn->word, lw) != 0) fn = fn->next;
                    if (!fn) {
                        if (pool->used < FREQ_POOL_SIZE) {
                            fn = &pool->nodes[pool->used++];
                            memcpy(fn->word, lw, wlen + 1);
                            fn->count = 0;
                            fn->next  = buckets[slot];
                            buckets[slot] = fn;
                        }
                    }
                    if (fn) fn->count++;
                }
            }
            continue;
        }

        i++;
    }

    
    h->nips = 0;
    if (ip_pool) {
        
        for (int b = 0; b < IP_DEDUP_BUCKETS && h->nips < HL_IP_MAX; b++) {
            for (IPNode *nd = ip_bkts[b]; nd && h->nips < HL_IP_MAX; nd = nd->next) {
                h->ips[h->nips++] = (HLIPEntry){ .cnt = nd->cnt };
                strncpy(h->ips[h->nips - 1].ip, nd->ip, 63);
            }
        }
        
        for (int a = 1; a < h->nips; a++) {
            HLIPEntry key = h->ips[a]; int b = a - 1;
            while (b >= 0 && h->ips[b].cnt < key.cnt) { h->ips[b+1] = h->ips[b]; b--; }
            h->ips[b+1] = key;
        }
        free(ip_pool);
    }

    
    h->ndts = 0;
    if (dt_pool) {
        for (int b = 0; b < DT_DEDUP_BUCKETS && h->ndts < HL_DT_MAX; b++) {
            for (DTNode *nd = dt_bkts[b]; nd && h->ndts < HL_DT_MAX; nd = nd->next) {
                h->dts[h->ndts++] = (HLDTEntry){ .cnt = nd->cnt };
                strncpy(h->dts[h->ndts - 1].dt, nd->dt, 63);
            }
        }
        for (int a = 1; a < h->ndts; a++) {
            HLDTEntry key = h->dts[a]; int b = a - 1;
            while (b >= 0 && h->dts[b].cnt < key.cnt) { h->dts[b+1] = h->dts[b]; b--; }
            h->dts[b+1] = key;
        }
        free(dt_pool);
    }

    
    size_t total_words = 0;
    for (int b = 0; b < FREQ_BUCKETS; b++)
        for (FreqNode *fn = buckets[b]; fn; fn = fn->next) total_words++;

    FreqNode **all_nodes = malloc(total_words * sizeof *all_nodes);
    if (all_nodes) {
        size_t idx = 0;
        for (int b = 0; b < FREQ_BUCKETS; b++)
            for (FreqNode *fn = buckets[b]; fn; fn = fn->next)
                all_nodes[idx++] = fn;

        
        size_t limit = total_words < (size_t)HL_TOP_WORDS ? total_words : (size_t)HL_TOP_WORDS;
        for (size_t a = 0; a < limit; a++) {
            size_t best = a;
            for (size_t bb = a + 1; bb < total_words; bb++)
                if (all_nodes[bb]->count > all_nodes[best]->count) best = bb;
            if (best != a) { FreqNode *tmp = all_nodes[a]; all_nodes[a] = all_nodes[best]; all_nodes[best] = tmp; }
        }

        int added = 0;
        for (size_t a = 0; a < limit && added < HL_TOP_WORDS; a++) {
            FreqNode *fn = all_nodes[a];
            if (fn->count < 2) break;
            bool skip = false;
            for (int m = 0; m < HTTP_KW_N && !skip; m++)
                if (strcasecmp(fn->word, HTTP_KW[m].w) == 0) skip = true;
            for (int m = 0; m < SENS_KW_N && !skip; m++)
                if (strcasecmp(fn->word, SENS_KW[m].w) == 0) skip = true;
            if (skip) continue;
            h->top[added] = (HLWordCount){ .count = fn->count, .cat = HLCAT_WORD };
            strncpy(h->top[added].word, fn->word, 63);
            added++;
        }
        h->ntop = added;
        free(all_nodes);
    }

    
    for (int t = 0; t < h->ntop; t++) {
        size_t wlen = strlen(h->top[t].word);
        for (size_t pos = 0; pos + wlen <= buflen; ) {
            unsigned char c2 = (unsigned char)buf[pos];
            if (isalpha(c2) || c2 == '_') {
                
                bool lb = (pos == 0 || !is_word_char(buf[pos - 1]));
                bool rb = (pos + wlen >= buflen || !is_word_char(buf[pos + wlen]));
                if (lb && rb && strncasecmp(buf + pos, h->top[t].word, wlen) == 0) {
                    add_match_fast(h, pos, wlen, HLCAT_WORD, HL_CP_MATCH_WORD, buf + pos);
                    pos += wlen;
                    continue;
                }
            }
            pos++;
        }
    }

    
    for (int m = 0; m < HTTP_KW_N && h->http_nkw < HL_KW_MAX; m++) {
        size_t cnt = 0;
        for (size_t ii = 0; ii < h->nmatch; ii++)
            if (h->matches[ii].cat == HLCAT_HTTP && h->matches[ii].len == HTTP_KW[m].len) cnt++;
        if (cnt) { h->http_kw[h->http_nkw].word = HTTP_KW[m].w; h->http_kw[h->http_nkw++].count = cnt; }
    }
    for (int m = 0; m < SENS_KW_N && h->sens_nkw < HL_KW_MAX; m++) {
        size_t cnt = 0;
        for (size_t ii = 0; ii < h->nmatch; ii++)
            if (h->matches[ii].cat == HLCAT_SENSITIVE && h->matches[ii].len == SENS_KW[m].len) cnt++;
        if (cnt) { h->sens_kw[h->sens_nkw].word = SENS_KW[m].w; h->sens_kw[h->sens_nkw++].count = cnt; }
    }

    free(buf);
    free(pool);
    h->dirty = false;
}

const HLMatch *hl_match_at(const HLCtx *h, size_t byte_off) {
    if (h->nmatch == 0) return NULL;
    size_t lo = 0, hi = h->nmatch;
    while (lo + 1 < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (h->matches[mid].offset <= byte_off) lo = mid;
        else hi = mid;
    }
    const HLMatch *m = &h->matches[lo];
    if (byte_off >= m->offset && byte_off < m->offset + m->len) return m;
    return NULL;
}

/* Copy s into out, clamped to at most cap display columns; append '~' when
 * truncated. Backs off UTF-8 continuation bytes so a multibyte sequence is
 * never cut in half. Keeps panel content inside the box border. */
static void hl_fit(char *out, size_t outsz, const char *s, int cap) {
    if (cap < 1) cap = 1;
    if ((size_t)cap >= outsz) cap = (int)outsz - 1;
    int slen = (int)strlen(s);
    if (slen <= cap) { memcpy(out, s, (size_t)slen); out[slen] = '\0'; return; }
    int keep = cap - 1;                 /* leave a column for '~' */
    if (keep < 0) keep = 0;
    while (keep > 0 && ((unsigned char)s[keep] & 0xC0) == 0x80) keep--;
    memcpy(out, s, (size_t)keep);
    out[keep] = '~';
    out[keep + 1] = '\0';
}

#define PANEL_ROW(label, cp_label, val, cp_val, cnt)                     \
    do {                                                                  \
        (void)(cp_val); (void)(val);                                      \
        if (row - scroll >= 0 && row - scroll < win_h - 2) {            \
            int r = row - scroll + 1;                                    \
            int wcap = win_w - 6;                                        \
            char _cb[24]; int _cx = 0;                                  \
            if ((cnt) > 0) {                                             \
                /* "×" is 2 bytes but a single column */                \
                int _n = snprintf(_cb, sizeof _cb, "×%zu", (size_t)(cnt)); \
                int _dcols = _n - 1;                                    \
                _cx  = win_w - 1 - _dcols;   /* ends at col win_w-2 */  \
                if (_cx < 3) _cx = 3;                                   \
                wcap = _cx - 3;              /* word + 1-col gap */     \
            }                                                            \
            if (wcap < 1) wcap = 1;                                     \
            char _lbl[128];                                             \
            hl_fit(_lbl, sizeof _lbl, (label), wcap);                   \
            wattron(win, COLOR_PAIR(cp_label));                          \
            mvwprintw(win, r, 2, "%-*s", wcap, _lbl);                   \
            wattroff(win, COLOR_PAIR(cp_label));                         \
            if ((cnt) > 0) {                                             \
                wattron(win, COLOR_PAIR(HL_CP_COUNT));                   \
                mvwprintw(win, r, _cx, "%s", _cb);                     \
                wattroff(win, COLOR_PAIR(HL_CP_COUNT));                  \
            }                                                            \
        }                                                                \
        row++;                                                           \
    } while (0)

void hl_render(HLCtx *h, WINDOW *win, int win_h, int win_w) {
    if (!win || win_h < 3 || win_w < 12) return;
    werase(win);

    wattron(win, COLOR_PAIR(HL_CP_BORDER));
    box(win, 0, 0);
    wattroff(win, COLOR_PAIR(HL_CP_BORDER));

    wattron(win, COLOR_PAIR(HL_CP_HEADER) | A_BOLD);
    mvwprintw(win, 0, 2, " Smart Highlight ");
    wattroff(win, COLOR_PAIR(HL_CP_HEADER) | A_BOLD);

    int row = 0, scroll = h->scroll;

    if (h->cat_count[HLCAT_HTTP] > 0) {
        if (row - scroll >= 0 && row - scroll < win_h - 2) {
            wattron(win, COLOR_PAIR(HL_CP_SECTION) | A_BOLD);
            mvwprintw(win, row - scroll + 1, 1, "── HTTP Methods");
            wattroff(win, COLOR_PAIR(HL_CP_SECTION) | A_BOLD);
        }
        row++;
        for (int m = 0; m < h->http_nkw; m++)
            PANEL_ROW(h->http_kw[m].word, HL_CP_HTTP, "", HL_CP_HTTP, h->http_kw[m].count);
    }

    if (h->cat_count[HLCAT_SENSITIVE] > 0) {
        if (row - scroll >= 0 && row - scroll < win_h - 2) {
            wattron(win, COLOR_PAIR(HL_CP_SECTION) | A_BOLD);
            mvwprintw(win, row - scroll + 1, 1, "── Sensitive");
            wattroff(win, COLOR_PAIR(HL_CP_SECTION) | A_BOLD);
        }
        row++;
        for (int m = 0; m < h->sens_nkw; m++)
            PANEL_ROW(h->sens_kw[m].word, HL_CP_SENSITIVE, "", HL_CP_SENSITIVE, h->sens_kw[m].count);
    }

    if (h->cat_count[HLCAT_IP] > 0) {
        if (row - scroll >= 0 && row - scroll < win_h - 2) {
            wattron(win, COLOR_PAIR(HL_CP_SECTION) | A_BOLD);
            mvwprintw(win, row - scroll + 1, 1, "── IP Addresses");
            wattroff(win, COLOR_PAIR(HL_CP_SECTION) | A_BOLD);
        }
        row++;
        
        for (int k = 0; k < h->nips; k++)
            PANEL_ROW(h->ips[k].ip, HL_CP_IP, "", HL_CP_IP, h->ips[k].cnt);
    }

    if (h->cat_count[HLCAT_DATE] > 0) {
        if (row - scroll >= 0 && row - scroll < win_h - 2) {
            wattron(win, COLOR_PAIR(HL_CP_SECTION) | A_BOLD);
            mvwprintw(win, row - scroll + 1, 1, "── Dates / Times");
            wattroff(win, COLOR_PAIR(HL_CP_SECTION) | A_BOLD);
        }
        row++;
        for (int k = 0; k < h->ndts; k++)
            PANEL_ROW(h->dts[k].dt, HL_CP_DATE, "", HL_CP_DATE, h->dts[k].cnt);
    }

    if (h->ntop > 0) {
        if (row - scroll >= 0 && row - scroll < win_h - 2) {
            wattron(win, COLOR_PAIR(HL_CP_SECTION) | A_BOLD);
            mvwprintw(win, row - scroll + 1, 1, "── Top Words");
            wattroff(win, COLOR_PAIR(HL_CP_SECTION) | A_BOLD);
        }
        row++;
        for (int t = 0; t < h->ntop; t++)
            PANEL_ROW(h->top[t].word, HL_CP_WORD, "", HL_CP_WORD, h->top[t].count);
    }

    wattron(win, COLOR_PAIR(HL_CP_BORDER));
    if (scroll > 0)                    mvwprintw(win, 1,        win_w - 4, " ▲ ");
    if (row - scroll > win_h - 2)      mvwprintw(win, win_h-2,  win_w - 4, " ▼ ");
    wattroff(win, COLOR_PAIR(HL_CP_BORDER));

    wnoutrefresh(win);
}