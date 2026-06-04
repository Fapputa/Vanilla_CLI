#include "abyss.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <regex.h>

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

HLCtx *hl_new(void) {
    HLCtx *h = calloc(1, sizeof *h);
    h->dirty   = true;
    h->visible = false;
    h->width   = 34;
    return h;
}

void hl_free(HLCtx *h) {
    if (!h) return;
    if (h->win) delwin(h->win);
    free(h);
}

static bool is_word_char(char c) {
    return isalnum((unsigned char)c) || c == '_';
}

static size_t extract_word(const GapBuf *g, size_t off, char *out, size_t max) {
    size_t len = gb_len(g);
    size_t n = 0;
    while (off + n < len && n < max - 1 && is_word_char(gb_at(g, off + n)))
        n++;
    gb_get_range(g, off, n, out);
    out[n] = '\0';
    return n;
}

static void add_match(HLCtx *h, const GapBuf *g, size_t off, size_t len, HLCat cat) {
    if (h->nmatch >= HL_MAX_MATCHES) return;
    int cp;
    switch (cat) {
        case HLCAT_HTTP:      cp = HL_CP_MATCH_HTTP; break;
        case HLCAT_SENSITIVE: cp = HL_CP_MATCH_SENS; break;
        case HLCAT_IP:        cp = HL_CP_MATCH_IP;   break;
        case HLCAT_DATE:      cp = HL_CP_MATCH_DATE; break;
        default:              cp = HL_CP_MATCH_WORD; break;
    }
    HLMatch *m = &h->matches[h->nmatch++];
    m->offset = off;
    m->len    = len;
    m->cat    = cat;
    m->cp     = cp;
    size_t n  = len < 63 ? len : 63;
    gb_get_range(g, off, n, m->text);
    m->text[n] = '\0';
    h->cat_count[cat]++;
}

static const char *HTTP_METHODS[] = {
    "GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS","CONNECT","TRACE",
    NULL
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
    "endpoint","webhook","request","response","status","code",
    NULL
};

static const char *MONTH_NAMES[] = {
    "jan","feb","mar","apr","may","jun",
    "jul","aug","sep","oct","nov","dec",
    "january","february","march","april","june","july",
    "august","september","october","november","december",
    NULL
};

static bool match_word_boundary(const GapBuf *g, size_t off, const char *word, size_t wlen) {
    size_t buflen = gb_len(g);
    if (off + wlen > buflen) return false;
    
    if (off > 0 && is_word_char(gb_at(g, off - 1))) return false;
    
    if (off + wlen < buflen && is_word_char(gb_at(g, off + wlen))) return false;
    for (size_t i = 0; i < wlen; i++) {
        if (tolower((unsigned char)gb_at(g, off + i)) != tolower((unsigned char)word[i]))
            return false;
    }
    return true;
}

static bool scan_ipv4_at(const GapBuf *g, size_t off, size_t *out_len) {
    size_t buflen = gb_len(g);
    size_t pos = off;
    
    if (off > 0 && is_word_char(gb_at(g, off - 1))) return false;

    for (int octet = 0; octet < 4; octet++) {
        if (pos >= buflen || !isdigit((unsigned char)gb_at(g, pos))) return false;
        int digits = 0;
        while (pos < buflen && isdigit((unsigned char)gb_at(g, pos))) {
            pos++; digits++;
            if (digits > 3) return false;
        }
        if (octet < 3) {
            if (pos >= buflen || gb_at(g, pos) != '.') return false;
            pos++;
        }
    }
    
    if (pos < buflen && (gb_at(g, pos) == '.' || isalpha((unsigned char)gb_at(g, pos)))) return false;
    *out_len = pos - off;
    return true;
}

static bool scan_date_at(const GapBuf *g, size_t off, size_t *out_len) {
    size_t buflen = gb_len(g);
    if (off > 0 && isdigit((unsigned char)gb_at(g, off - 1))) return false;

    
    if (off + 8 > buflen) return false;

    
    char tmp[20];
    size_t n = 0;
    size_t pos = off;
    while (pos < buflen && n < 19) {
        char c = gb_at(g, pos);
        if (isdigit((unsigned char)c) || c == '/' || c == '-' || c == ':') {
            tmp[n++] = c;
            pos++;
        } else break;
    }
    tmp[n] = '\0';

    
    if (n >= 8) {
        
        if (n >= 10 && tmp[2]=='/' && tmp[5]=='/' && isdigit((unsigned char)tmp[6])) {
            *out_len = 10;
            return true;
        }
        
        if (n >= 10 && tmp[4]=='-' && tmp[7]=='-') {
            *out_len = 10;
            return true;
        }
        
        if (n >= 10 && tmp[2]=='-' && tmp[5]=='-' && isdigit((unsigned char)tmp[6])) {
            *out_len = 10;
            return true;
        }
        
        if (n >= 8 && tmp[2]==':' && tmp[5]==':') {
            *out_len = 8;
            return true;
        }
        
        if (n >= 5 && tmp[2]==':' && isdigit((unsigned char)tmp[3])) {
            *out_len = 5;
            return true;
        }
    }
    return false;
}

#define FREQ_BUCKETS 1024
typedef struct FreqNode {
    char            word[64];
    size_t          count;
    struct FreqNode *next;
} FreqNode;

static unsigned str_hash(const char *s) {
    unsigned h = 5381;
    while (*s) h = ((h << 5) + h) ^ (unsigned char)*s++;
    return h % FREQ_BUCKETS;
}

static const char *STOP_WORDS[] = {
    "the","a","an","is","it","in","of","to","and","or","for",
    "if","do","int","char","void","return","true","false","null",
    "NULL","new","this","self","else","then","end","not","be",
    "at","by","on","as","so","no","up","my","we","our","its",
    "with","from","that","have","had","has","was","were","are",
    "been","but","also","when","who","they","their","than","can",
    "will","more","some","into","over","out","get","set","use",
    "var","let","def","fn","pub","mod","use","type","size",
    NULL
};

static bool is_stop(const char *w) {
    for (int i = 0; STOP_WORDS[i]; i++)
        if (strcasecmp(w, STOP_WORDS[i]) == 0) return true;
    return false;
}

void hl_scan(HLCtx *h, const GapBuf *g) {
    h->nmatch   = 0;
    h->ntop     = 0;
    h->http_nkw = 0;
    h->sens_nkw = 0;
    memset(h->cat_count, 0, sizeof h->cat_count);

    size_t buflen = gb_len(g);
    if (buflen == 0) { h->dirty = false; return; }

    
    FreqNode *buckets[FREQ_BUCKETS];
    memset(buckets, 0, sizeof buckets);

    
    size_t i = 0;
    while (i < buflen) {
        char c = gb_at(g, i);

        
        if (isdigit((unsigned char)c)) {
            size_t iplen = 0;
            if (scan_ipv4_at(g, i, &iplen)) {
                add_match(h, g, i, iplen, HLCAT_IP);
                i += iplen;
                continue;
            }
        }

        
        if (isdigit((unsigned char)c)) {
            size_t dlen = 0;
            if (scan_date_at(g, i, &dlen)) {
                add_match(h, g, i, dlen, HLCAT_DATE);
                i += dlen;
                continue;
            }
        }

        
        if (isalpha((unsigned char)c) || c == '_') {
            char word[64];
            size_t wlen = extract_word(g, i, word, sizeof word);
            if (wlen == 0) { i++; continue; }

            bool found_cat = false;

            
            for (int m = 0; HTTP_METHODS[m]; m++) {
                size_t ml = strlen(HTTP_METHODS[m]);
                if (wlen == ml && match_word_boundary(g, i, HTTP_METHODS[m], ml)) {
                    add_match(h, g, i, ml, HLCAT_HTTP);
                    found_cat = true;
                    break;
                }
            }

            if (!found_cat) {
                
                for (int m = 0; SENSITIVE_WORDS[m]; m++) {
                    size_t ml = strlen(SENSITIVE_WORDS[m]);
                    if (wlen == ml && match_word_boundary(g, i, SENSITIVE_WORDS[m], ml)) {
                        add_match(h, g, i, ml, HLCAT_SENSITIVE);
                        found_cat = true;
                        break;
                    }
                }
            }

            if (!found_cat) {
                
                for (int m = 0; MONTH_NAMES[m]; m++) {
                    size_t ml = strlen(MONTH_NAMES[m]);
                    if (wlen == ml && match_word_boundary(g, i, MONTH_NAMES[m], ml)) {
                        add_match(h, g, i, ml, HLCAT_DATE);
                        found_cat = true;
                        break;
                    }
                }
            }

            
            if (wlen >= 3 && wlen < 63 && !is_stop(word)) {
                char lw[64];
                for (size_t k = 0; k <= wlen; k++) lw[k] = (char)tolower((unsigned char)word[k]);
                unsigned slot = str_hash(lw);
                FreqNode *fn = buckets[slot];
                while (fn && strcmp(fn->word, lw) != 0) fn = fn->next;
                if (!fn) {
                    fn = calloc(1, sizeof *fn);
                    strncpy(fn->word, lw, 63);
                    fn->next = buckets[slot];
                    buckets[slot] = fn;
                }
                fn->count++;
            }

            i += wlen;
            continue;
        }

        i++;
    }

    
    
    size_t total_words = 0;
    
    for (int b = 0; b < FREQ_BUCKETS; b++)
        for (FreqNode *fn = buckets[b]; fn; fn = fn->next) total_words++;
    FreqNode **all_nodes = malloc(total_words * sizeof *all_nodes);
    if (!all_nodes) { h->dirty = false; goto cleanup; }
    total_words = 0;
    for (int b = 0; b < FREQ_BUCKETS; b++)
        for (FreqNode *fn = buckets[b]; fn; fn = fn->next)
            all_nodes[total_words++] = fn;
    
    for (size_t a = 1; a < total_words; a++) {
        FreqNode *key = all_nodes[a];
        long j = (long)a - 1;
        while (j >= 0 && all_nodes[j]->count < key->count) {
            all_nodes[j + 1] = all_nodes[j]; j--;
        }
        all_nodes[j + 1] = key;
    }

    
    int added = 0;
    for (size_t a = 0; a < total_words && added < HL_TOP_WORDS; a++) {
        FreqNode *fn = all_nodes[a];
        if (fn->count < 2) break; 

        
        bool skip = false;
        for (int m = 0; HTTP_METHODS[m]; m++)
            if (strcasecmp(fn->word, HTTP_METHODS[m]) == 0) { skip = true; break; }
        if (!skip)
            for (int m = 0; SENSITIVE_WORDS[m]; m++)
                if (strcasecmp(fn->word, SENSITIVE_WORDS[m]) == 0) { skip = true; break; }
        if (skip) continue;

        h->top[added++] = (HLWordCount){ .count = fn->count, .cat = HLCAT_WORD };
        strncpy(h->top[added - 1].word, fn->word, 63);
    }
    h->ntop = added;

    
    for (int t = 0; t < h->ntop; t++) {
        size_t wlen = strlen(h->top[t].word);
        for (size_t pos = 0; pos < buflen; ) {
            char c2 = gb_at(g, pos);
            if (isalpha((unsigned char)c2) || c2 == '_') {
                if (match_word_boundary(g, pos, h->top[t].word, wlen)) {
                    add_match(h, g, pos, wlen, HLCAT_WORD);
                    pos += wlen;
                    continue;
                }
            }
            pos++;
        }
    }

    
cleanup:
    free(all_nodes);
    for (int b = 0; b < FREQ_BUCKETS; b++) {
        FreqNode *fn = buckets[b];
        while (fn) { FreqNode *nx = fn->next; free(fn); fn = nx; }
    }

    
    for (int m = 0; HTTP_METHODS[m] && h->http_nkw < HL_KW_MAX; m++) {
        size_t cnt = 0, ml = strlen(HTTP_METHODS[m]);
        for (size_t ii = 0; ii < h->nmatch; ii++) {
            if (h->matches[ii].cat == HLCAT_HTTP && h->matches[ii].len == ml)
                cnt++;
        }
        if (cnt > 0) {
            h->http_kw[h->http_nkw].word  = HTTP_METHODS[m];
            h->http_kw[h->http_nkw].count = cnt;
            h->http_nkw++;
        }
    }
    for (int m = 0; SENSITIVE_WORDS[m] && h->sens_nkw < HL_KW_MAX; m++) {
        size_t cnt = 0, ml = strlen(SENSITIVE_WORDS[m]);
        for (size_t ii = 0; ii < h->nmatch; ii++) {
            if (h->matches[ii].cat == HLCAT_SENSITIVE && h->matches[ii].len == ml)
                cnt++;
        }
        if (cnt > 0) {
            h->sens_kw[h->sens_nkw].word  = SENSITIVE_WORDS[m];
            h->sens_kw[h->sens_nkw].count = cnt;
            h->sens_nkw++;
        }
    }

    h->dirty = false;
}

int hl_match_cp(HLCat cat) {
    switch (cat) {
        case HLCAT_HTTP:      return HL_CP_MATCH_HTTP;
        case HLCAT_SENSITIVE: return HL_CP_MATCH_SENS;
        case HLCAT_IP:        return HL_CP_MATCH_IP;
        case HLCAT_DATE:      return HL_CP_MATCH_DATE;
        default:              return HL_CP_MATCH_WORD;
    }
}

const HLMatch *hl_match_at(const HLCtx *h, size_t byte_off) {
    if (h->nmatch == 0) return NULL;

    
    size_t lo = 0, hi = h->nmatch;
    while (lo + 1 < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (h->matches[mid].offset <= byte_off) lo = mid;
        else                                     hi = mid;
    }
    const HLMatch *m = &h->matches[lo];
    if (byte_off >= m->offset && byte_off < m->offset + m->len)
        return m;
    return NULL;
}

#define PANEL_ROW(label, cp_label, val, cp_val, cnt)                     \
    do {                                                                  \
        if (row - scroll >= 0 && row - scroll < win_h - 2) {            \
            int r = row - scroll + 1;                                    \
            wattron(win, COLOR_PAIR(cp_label));                          \
            mvwprintw(win, r, 2, "%-14s", (label));                     \
            wattroff(win, COLOR_PAIR(cp_label));                         \
            wattron(win, COLOR_PAIR(cp_val) | A_BOLD);                   \
            mvwprintw(win, r, 16, "%-*s", win_w - 18, (val));           \
            wattroff(win, COLOR_PAIR(cp_val) | A_BOLD);                  \
            if ((cnt) > 0) {                                             \
                wattron(win, COLOR_PAIR(HL_CP_COUNT));                   \
                mvwprintw(win, r, win_w - 6, "×%-4zu", (size_t)(cnt));  \
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

    int row    = 0;
    int scroll = h->scroll;

    
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

        
        typedef struct { char ip[64]; size_t cnt; } IPEntry;
        IPEntry ips[256]; int nips = 0;
        for (size_t i = 0; i < h->nmatch; i++) {
            const HLMatch *mm = &h->matches[i];
            if (mm->cat != HLCAT_IP) continue;
            bool found = false;
            for (int k = 0; k < nips; k++) {
                if (strcmp(ips[k].ip, mm->text) == 0) { ips[k].cnt++; found = true; break; }
            }
            if (!found && nips < 256) {
                strncpy(ips[nips].ip, mm->text, 63);
                ips[nips].ip[63] = '\0';
                ips[nips].cnt = 1;
                nips++;
            }
        }
        
        for (int a = 1; a < nips; a++) {
            IPEntry key = ips[a]; int b = a - 1;
            while (b >= 0 && ips[b].cnt < key.cnt) { ips[b+1] = ips[b]; b--; }
            ips[b+1] = key;
        }
        for (int k = 0; k < nips; k++)
            PANEL_ROW(ips[k].ip, HL_CP_IP, "", HL_CP_IP, ips[k].cnt);
    }

    
    if (h->cat_count[HLCAT_DATE] > 0) {
        if (row - scroll >= 0 && row - scroll < win_h - 2) {
            wattron(win, COLOR_PAIR(HL_CP_SECTION) | A_BOLD);
            mvwprintw(win, row - scroll + 1, 1, "── Dates / Times");
            wattroff(win, COLOR_PAIR(HL_CP_SECTION) | A_BOLD);
        }
        row++;
        typedef struct { char dt[64]; size_t cnt; } DTEntry;
        DTEntry dts[128]; int ndts = 0;
        for (size_t i = 0; i < h->nmatch; i++) {
            const HLMatch *mm = &h->matches[i];
            if (mm->cat != HLCAT_DATE) continue;
            bool found = false;
            for (int k = 0; k < ndts; k++) {
                if (strcmp(dts[k].dt, mm->text) == 0) { dts[k].cnt++; found = true; break; }
            }
            if (!found && ndts < 128) {
                strncpy(dts[ndts].dt, mm->text, 63);
                dts[ndts].dt[63] = '\0';
                dts[ndts].cnt = 1;
                ndts++;
            }
        }
        for (int a = 1; a < ndts; a++) {
            DTEntry key = dts[a]; int b = a - 1;
            while (b >= 0 && dts[b].cnt < key.cnt) { dts[b+1] = dts[b]; b--; }
            dts[b+1] = key;
        }
        for (int k = 0; k < ndts; k++)
            PANEL_ROW(dts[k].dt, HL_CP_DATE, "", HL_CP_DATE, dts[k].cnt);
    }

    
    if (h->ntop > 0) {
        if (row - scroll >= 0 && row - scroll < win_h - 2) {
            wattron(win, COLOR_PAIR(HL_CP_SECTION) | A_BOLD);
            mvwprintw(win, row - scroll + 1, 1, "── Top Words");
            wattroff(win, COLOR_PAIR(HL_CP_SECTION) | A_BOLD);
        }
        row++;
        for (int t = 0; t < h->ntop; t++) {
            PANEL_ROW(h->top[t].word, HL_CP_WORD, "", HL_CP_WORD, h->top[t].count);
        }
    }

    wattron(win, COLOR_PAIR(HL_CP_BORDER));
    if (scroll > 0)
        mvwprintw(win, 1, win_w - 4, " ▲ ");
    if (row - scroll > win_h - 2)
        mvwprintw(win, win_h - 2, win_w - 4, " ▼ ");
    wattroff(win, COLOR_PAIR(HL_CP_BORDER));

    wnoutrefresh(win);
}