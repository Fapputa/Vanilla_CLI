/* PE loader (read-only): Windows .exe / .dll into an ElfFile, see "PE
 * files" in elfload.h and peload.h. Both PE32 (x86) and PE32+ (x64)
 * files are loaded with their imports (descriptors, ILT / IAT, 4- or
 * 8-byte thunks, by name or ordinal, delay-load; bound imports listed),
 * exports (forwarders counted, not taken as code), base relocations
 * (HIGHLOW in PE32, DIR64 in PE32+) and the .NET header flags; PE32+ also
 * with .pdata, TLS, load config, debug directory and COFF symbols, not
 * read yet in PE32. Every table walk has an explicit cap (MAX_*).
 *
 * Same rule as elfload.c: no byte of the file is read before the offset
 * AND the length of what is read have been checked against the file
 * size (in_file / rva_ptr), with overflow-safe arithmetic, and names are
 * cleaned to printable ASCII. A bad optional table (imports, exports,
 * relocations, .pdata, TLS, load config, COFF symbols) is reported as a
 * warning and skipped; the headers and the section table must be sound
 * (pe_read_headers, and the section checks of pe_parse).
 *
 * Addresses are ImageBase + RVA. A section is mapped from its raw data:
 * min(SizeOfRawData, VirtualSize) bytes, the rest of VirtualSize is
 * zero-filled memory (memsz); the headers are mapped too (SizeOfHeaders).
 *
 * No curses, no capstone, no <windows.h>: this file builds everywhere. */
#include "elfload.h"
#include "peload.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define PE_MACHINE_AMD64  0x8664
#define PE_MACHINE_I386   0x014c
#define PE_MACHINE_ARM64  0xaa64
#define PE_MAGIC_PE32     0x10b
#define PE_MAGIC_PE32P    0x20b

#define PE_FILE_RELOCS_STRIPPED 0x0001
#define PE_FILE_DLL             0x2000

#define PE_SCN_CNT_CODE      0x00000020u
#define PE_SCN_CNT_UNINIT    0x00000080u
#define PE_SCN_MEM_EXECUTE   0x20000000u
#define PE_SCN_MEM_READ      0x40000000u
#define PE_SCN_MEM_WRITE     0x80000000u

#define PE_DLLCHAR_DYNAMIC_BASE 0x0040

enum { DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_EXCEPTION, DIR_SECURITY,
       DIR_BASERELOC, DIR_DEBUG, DIR_ARCH, DIR_GLOBALPTR, DIR_TLS,
       DIR_LOAD_CONFIG, DIR_BOUND_IMPORT, DIR_IAT, DIR_DELAY_IMPORT, DIR_CLR,
       DIR_COUNT = 16 };

/* ElfSection / ElfMap flags (ELF values, what disasm.c and disview.c test) */
#define S_WRITE 1
#define S_ALLOC 2
#define S_EXEC  4
#define SHT_PROGBITS 1
#define SHT_NOBITS   8
#define PF_X 1
#define PF_W 2
#define PF_R 4

#define MAX_SECTIONS  96          /* the Windows loader refuses more        */
#define MAX_IMPORTS   (1u << 20)
#define MAX_DLLS      1024
#define MAX_EXPORTS   (1u << 20)
#define MAX_COFF_SYMS (4u << 20)
#define MAX_RELOCS    (8u << 20)
#define MAX_PDATA     (2u << 20)
#define MAX_TLS_CB    256

static uint16_t r16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t r32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t r64(const uint8_t *p) { return (uint64_t)r32(p) | (uint64_t)r32(p + 4) << 32; }

static bool in_file(const ElfFile *ef, uint64_t off, uint64_t len) {
    return off <= ef->size && len <= ef->size - off;
}

static void set_err(char *err, size_t esz, const char *fmt, ...) __attribute__((format(gnu_printf, 3, 4)));
static void set_err(char *err, size_t esz, const char *fmt, ...) {
    if (!err || !esz) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, esz, fmt, ap);
    va_end(ap);
}

static void warn(ElfFile *ef, const char *fmt, ...) __attribute__((format(gnu_printf, 2, 3)));
static void warn(ElfFile *ef, const char *fmt, ...) {
    if (ef->nwarn >= ELF_MAX_WARN) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(ef->warn[ef->nwarn++], sizeof ef->warn[0], fmt, ap);
    va_end(ap);
}

/* appends ", text" (or "text" first) to a bounded summary */
static void note(char *b, size_t sz, size_t *u, const char *fmt, ...) __attribute__((format(gnu_printf, 4, 5)));
static void note(char *b, size_t sz, size_t *u, const char *fmt, ...) {
    if (*u + 3 >= sz) return;
    if (*u) { b[(*u)++] = ','; b[(*u)++] = ' '; b[*u] = '\0'; }
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(b + *u, sz - *u, fmt, ap);
    va_end(ap);
    if (k > 0) *u += (size_t)k < sz - *u ? (size_t)k : sz - *u - 1;
}

static void clean_copy(char *dst, size_t dsz, const char *s, size_t n) {
    if (!dsz) return;
    if (n > dsz - 1) n = dsz - 1;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        dst[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
    }
    dst[n] = '\0';
}

static char *clean_dup(const char *s, size_t n) {
    if (n > 255) n = 255;
    char *d = malloc(n + 1);
    if (d) clean_copy(d, n + 1, s, n);
    return d;
}

/* ─── addresses ────────────────────────────────────────────────── */

static uint64_t rva_va(const ElfFile *ef, uint64_t rva) { return ef->pe.image_base + rva; }

/* bytes at an RVA, `need` of them inside one mapping of the file; NULL
 * when not file-backed or too short. *avail (optional): what follows. */
static const uint8_t *rva_ptr(const ElfFile *ef, uint64_t rva, uint64_t need, size_t *avail) {
    if (rva > UINT64_MAX - ef->pe.image_base) return NULL;
    size_t av = 0;
    const uint8_t *p = elf_va_ptr(ef, rva_va(ef, rva), &av);
    if (!p || av < need) return NULL;
    if (avail) *avail = av;
    return p;
}

/* NUL-terminated string at an RVA (at most `max` bytes looked at) */
static const char *rva_str(const ElfFile *ef, uint64_t rva, size_t max, size_t *len) {
    size_t av = 0;
    const uint8_t *p = rva_ptr(ef, rva, 1, &av);
    if (!p) return NULL;
    if (av > max) av = max;
    const uint8_t *z = memchr(p, 0, av);
    if (!z) return NULL;
    *len = (size_t)(z - p);
    return (const char *)p;
}

static bool add_map(ElfFile *ef, uint64_t va, uint64_t off, uint64_t filesz, uint64_t memsz, uint32_t flags) {
    ElfMap *n = realloc(ef->map, (size_t)(ef->nmap + 1) * sizeof *n);
    if (!n) return false;
    ef->map = n;
    ef->map[ef->nmap++] = (ElfMap){ va, off, filesz, memsz, flags };
    return true;
}

/* ─── tables ───────────────────────────────────────────────────── */

typedef struct { uint32_t rva, size; } Dir;

static bool push_symbol(ElfFile *ef, int *cap, const ElfSymbol *s) {
    if (ef->nsym >= (int)(MAX_EXPORTS + MAX_COFF_SYMS)) return false;
    if (ef->nsym == *cap) {
        int nc = *cap ? *cap * 2 : 256;
        ElfSymbol *n = realloc(ef->sym, (size_t)nc * sizeof *n);
        if (!n) return false;
        ef->sym = n; *cap = nc;
    }
    ef->sym[ef->nsym++] = *s;
    return true;
}

static bool add_needed(ElfFile *ef, const char *s, size_t n, bool delay) {
    if (ef->nneeded >= MAX_DLLS) return false;
    char b[300];
    snprintf(b, sizeof b, "%.*s%s", (int)(n > 255 ? 255 : n), s, delay ? " (delay-load)" : "");
    for (int i = 0; i < ef->nneeded; i++) if (!strcmp(ef->needed[i], b)) return true;
    char **nn = realloc(ef->needed, (size_t)(ef->nneeded + 1) * sizeof *nn);
    if (!nn) return false;
    ef->needed = nn;
    if (!(ef->needed[ef->nneeded] = clean_dup(b, strlen(b)))) return false;
    ef->nneeded++;
    return true;
}

/* thunks read in all (import and delay-load tables): bounds the work on
 * name tables that never end or that several descriptors share */
#define MAX_THUNK_READS (4u << 20)

typedef struct {
    int      cap;                 /* ef->imp capacity                        */
    uint32_t reads;               /* thunks read, up to MAX_THUNK_READS       */
    uint32_t noname;              /* hint/name outside the file, unterminated */
    uint32_t runout;              /* name tables without their null entry    */
    uint32_t badiat;              /* IAT outside the image                    */
    uint32_t dllname;             /* DLL names outside the file, unterminated */
    bool     capped;              /* MAX_IMPORTS or MAX_THUNK_READS reached   */
} ImpCtx;

static void add_import(ElfFile *ef, ImpCtx *c, const char *name, size_t nl, const char *dll, uint64_t slot) {
    if (ef->nimp >= (int)MAX_IMPORTS) { c->capped = true; return; }
    if (ef->nimp == c->cap) {
        int nc = c->cap ? c->cap * 2 : 64;
        ElfImport *n = realloc(ef->imp, (size_t)nc * sizeof *n);
        if (!n) return;
        ef->imp = n; c->cap = nc;
    }
    ElfImport *im = &ef->imp[ef->nimp];
    memset(im, 0, sizeof *im);
    if (!(im->name = clean_dup(name, nl))) return;
    clean_copy(im->version, sizeof im->version, dll, strlen(dll));
    im->got = slot;
    ef->nimp++;
}

/* The thunks of one import table: name table (ILT / INT) at `ilt` (0:
 * the IAT itself), slots at `iat`; 4-byte entries in PE32, 8-byte ones in
 * PE32+, the top bit set for an import by ordinal, else the RVA of a
 * hint (2 bytes) + name. Ends at a null entry. `names` false: the IAT of
 * a bound DLL without a name table holds addresses, not names. */
static void read_thunks(ElfFile *ef, ImpCtx *c, const char *dll, uint64_t ilt, uint64_t iat, bool names) {
    unsigned ws = ef->bits == 32 ? 4u : 8u;
    if (!ilt) ilt = iat;
    for (uint64_t k = 0; ; k++) {
        if (ef->nimp >= (int)MAX_IMPORTS || c->reads >= MAX_THUNK_READS) { c->capped = true; return; }
        c->reads++;
        const uint8_t *p = rva_ptr(ef, ilt + k * ws, ws, NULL);
        if (!p) {
            if (k == 0) warn(ef, "imports of %.60s: name table not in the file", dll);
            else c->runout++;
            return;
        }
        uint64_t t = ws == 4 ? r32(p) : r64(p);
        if (!t) return;
        if (iat + (k + 1) * ws > ef->pe.size_image) { c->badiat++; return; }
        uint64_t slot = rva_va(ef, iat + k * ws);
        char nb[32];
        if (ws == 4 ? (t >> 31) & 1 : t >> 63) {       /* by ordinal */
            int n = snprintf(nb, sizeof nb, "Ordinal_%u", (unsigned)(t & 0xffff));
            add_import(ef, c, nb, (size_t)n, dll, slot);
            continue;
        }
        size_t nl = 0;
        const char *s = names ? rva_str(ef, (t & 0x7fffffff) + 2, 512, &nl) : NULL;
        if (!s || !nl) {
            if (names) c->noname++;
            int n = snprintf(nb, sizeof nb, "import_%llu", (unsigned long long)k);
            add_import(ef, c, nb, (size_t)n, dll, slot);
            continue;
        }
        add_import(ef, c, s, nl, dll, slot);
    }
}

/* the DLL name at an RVA, "?" when it is not a string in the file */
static void dll_name(ElfFile *ef, ImpCtx *c, uint64_t rva, char *dll, size_t dsz) {
    size_t nl = 0;
    const char *s = rva_str(ef, rva, 256, &nl);
    if (s && nl) clean_copy(dll, dsz, s, nl);
    else { snprintf(dll, dsz, "?"); c->dllname++; }
}

/* IMAGE_IMPORT_DESCRIPTOR { OriginalFirstThunk (ILT), TimeDateStamp,
 * ForwarderChain, Name, FirstThunk (IAT) }, up to a null one. A non-zero
 * TimeDateStamp: bound (the IAT holds addresses in the file), names from
 * the ILT only. */
static void read_imports(ElfFile *ef, Dir d, ImpCtx *c) {
    if (!d.rva || !d.size) return;
    for (uint32_t i = 0; ; i++) {
        if (i >= MAX_DLLS) { warn(ef, "import table: more than %d descriptors, the rest is ignored", MAX_DLLS); return; }
        const uint8_t *p = rva_ptr(ef, (uint64_t)d.rva + (uint64_t)i * 20, 20, NULL);
        if (!p) { warn(ef, "import table at RVA 0x%x runs out of the file", d.rva); return; }
        uint32_t ilt = r32(p), ts = r32(p + 4), name = r32(p + 12), iat = r32(p + 16);
        if (!ilt && !name && !iat) return;
        char dll[128];
        dll_name(ef, c, name, dll, sizeof dll);
        add_needed(ef, dll, strlen(dll), false);
        if (!iat) continue;
        if (iat >= ef->pe.size_image) { c->badiat++; continue; }
        if (!ilt && ts) {
            warn(ef, "imports of %.60s are bound and have no name table: names unknown", dll);
            read_thunks(ef, c, dll, 0, iat, false);
        } else read_thunks(ef, c, dll, ilt, iat, true);
    }
}

/* ImgDelayDescr { Attributes, DllName, ModuleHandle, IAT, INT, BoundIAT,
 * UnloadIAT, TimeStamp }: RVAs when bit 0 of Attributes is set, else
 * (old Visual C++ 6 form) VAs */
static void read_delay_imports(ElfFile *ef, Dir d, ImpCtx *c) {
    if (!d.rva || !d.size) return;
    for (uint32_t i = 0; ; i++) {
        if (i >= MAX_DLLS) { warn(ef, "delay-load import table: more than %d descriptors, the rest is ignored", MAX_DLLS); return; }
        const uint8_t *p = rva_ptr(ef, (uint64_t)d.rva + (uint64_t)i * 32, 32, NULL);
        if (!p) { warn(ef, "delay-load import table runs out of the file"); return; }
        uint32_t attr = r32(p);
        uint64_t name = r32(p + 4), iat = r32(p + 12), ilt = r32(p + 16);
        if (!name && !iat && !ilt) return;
        if (!(attr & 1)) {                     /* old form: VAs, not RVAs */
            uint64_t b = (uint32_t)ef->pe.image_base;
            name = name >= b ? name - b : 0;
            iat  = iat  >= b ? iat  - b : 0;
            ilt  = ilt  >= b ? ilt  - b : 0;
        }
        char dll[128];
        dll_name(ef, c, name, dll, sizeof dll);
        add_needed(ef, dll, strlen(dll), true);
        ef->pe.ndelay++;
        if (iat && iat >= ef->pe.size_image) { c->badiat++; continue; }
        if (iat && ilt) read_thunks(ef, c, dll, ilt, iat, true);
    }
}

static void imports_done(ElfFile *ef, const ImpCtx *c) {
    if (c->capped) warn(ef, "imports: limit reached (%u entries, %u table reads), the rest is ignored", MAX_IMPORTS, MAX_THUNK_READS);
    if (c->runout) warn(ef, "%u import name table%s run%s out of the file before a null entry", c->runout,
                        c->runout > 1 ? "s" : "", c->runout > 1 ? "" : "s");
    if (c->noname) warn(ef, "%u import names outside the file or unterminated (named import_N)", c->noname);
    if (c->badiat) warn(ef, "%u import address table%s outside the image: ignored", c->badiat, c->badiat > 1 ? "s" : "");
    if (c->dllname) warn(ef, "%u imported DLL names outside the file or unterminated (shown as ?)", c->dllname);
}

/* IMAGE_BOUND_IMPORT_DESCRIPTOR { TimeDateStamp, OffsetModuleName,
 * NumberOfModuleForwarderRefs } + that many forwarder refs (8 bytes
 * each), up to a null entry; names at an offset from the table start,
 * inside the table. -1: malformed (what was read is kept in b). */
static int bound_walk(const ElfFile *ef, Dir d, PeBound *b) {
    memset(b, 0, sizeof *b);
    if (!d.rva || !d.size) return 0;
    const uint8_t *p = rva_ptr(ef, d.rva, d.size, NULL);
    if (!p) return -1;
    uint64_t off = 0;
    while (off + 8 <= d.size) {
        uint32_t ts = r32(p + off);
        uint16_t on = r16(p + off + 4), nf = r16(p + off + 6);
        if (!ts && !on && !nf) return b->n;
        if (b->n >= MAX_DLLS || on >= d.size) return -1;
        const uint8_t *z = memchr(p + on, 0, d.size - on);
        if (!z) return -1;
        if (b->n < PE_BOUND_SHOW) clean_copy(b->name[b->n], sizeof b->name[0], (const char *)p + on, (size_t)(z - p - on));
        b->n++;
        b->nfwd += nf;
        off += 8 + (uint64_t)nf * 8;
    }
    return -1;                                 /* no null entry */
}

/* The export directory: one walk for the symbols (read_exports) and for
 * the F9 summary (pe_exports). A forwarder (its RVA inside the export
 * directory) is a "dll.func" string, not code. Each function gets the
 * name an ordinal entry gives it (the last one for an alias), else
 * Ordinal_<base + index>. fn returns false to stop. */
typedef bool (*ExpFn)(void *ctx, const char *name, size_t nl, uint64_t va, bool code);

static bool export_walk(const ElfFile *ef, Dir d, PeExports *x, ExpFn fn, void *ctx) {
    memset(x, 0, sizeof *x);
    if (!d.rva || !d.size) return false;
    const uint8_t *p = rva_ptr(ef, d.rva, 40, NULL);
    if (!p) { snprintf(x->err, sizeof x->err, "export table at RVA 0x%x is not in the file", d.rva); return false; }
    uint32_t name = r32(p + 12), nfunc = r32(p + 20), nname = r32(p + 24);
    uint32_t afunc = r32(p + 28), aname = r32(p + 32), aord = r32(p + 36);
    x->base = r32(p + 16);
    x->nfunc = nfunc;
    x->nname = nname;
    size_t nl = 0;
    const char *s = rva_str(ef, name, 256, &nl);
    if (s) clean_copy(x->name, sizeof x->name, s, nl);
    if (nfunc > MAX_EXPORTS || nname > MAX_EXPORTS) { snprintf(x->err, sizeof x->err, "export table too large: ignored"); return false; }
    if (!nfunc) return true;
    const uint8_t *pf = rva_ptr(ef, afunc, (uint64_t)nfunc * 4, NULL);
    if (!pf) { snprintf(x->err, sizeof x->err, "export addresses outside the file: ignored"); return false; }
    const uint8_t *pn = nname ? rva_ptr(ef, aname, (uint64_t)nname * 4, NULL) : NULL;
    const uint8_t *po = nname ? rva_ptr(ef, aord, (uint64_t)nname * 2, NULL) : NULL;
    x->names_bad = nname && (!pn || !po);
    uint32_t *nm = calloc(nfunc, sizeof *nm);
    if (!nm) { snprintf(x->err, sizeof x->err, "out of memory"); return false; }
    if (pn && po)
        for (uint32_t i = 0; i < nname; i++) {
            uint16_t o = r16(po + (uint64_t)i * 2);
            if (o < nfunc) nm[o] = r32(pn + (uint64_t)i * 4);
            else x->nbadord++;
        }
    for (uint32_t i = 0; i < nfunc; i++) {
        uint32_t rva = r32(pf + (uint64_t)i * 4);
        if (!rva) continue;
        char ob[32];
        const char *sn = NULL;
        size_t sl = 0;
        if (nm[i] && !(sn = rva_str(ef, nm[i], 512, &sl))) x->nbadname++;
        if (!sn || !sl) { sl = (size_t)snprintf(ob, sizeof ob, "Ordinal_%u", x->base + i); sn = ob; }
        if (rva >= d.rva && rva - d.rva < d.size) {    /* forwarder: "DLL.func" */
            x->nfwd++;
            size_t fl = 0;
            const char *f = rva_str(ef, rva, d.size - (rva - d.rva), &fl);
            const char *dot = f && fl ? memchr(f, '.', fl) : NULL;
            if (!dot || dot == f || dot == f + fl - 1) { x->nbadfwd++; continue; }
            if (x->nfwdshow < PE_FWD_SHOW) {
                char a[64], t[64];
                clean_copy(a, sizeof a, sn, sl);
                clean_copy(t, sizeof t, f, fl);
                snprintf(x->fwd[x->nfwdshow++], sizeof x->fwd[0], "%s -> %s", a, t);
            }
            continue;
        }
        if (rva >= ef->pe.size_image) { x->nbadrva++; continue; }
        uint64_t va = rva_va(ef, rva);
        bool code = elf_va_exec(ef, va);
        if (code) x->ncode++; else x->ndata++;
        if (fn && !fn(ctx, sn, sl, va, code)) break;
    }
    free(nm);
    return true;
}

typedef struct { ElfFile *ef; int *scap; } ExpCtx;

static bool export_sym(void *ctx, const char *sn, size_t sl, uint64_t va, bool code) {
    ExpCtx *c = ctx;
    ElfSymbol sym = {0};
    sym.kind = code ? ELF_SYM_FUNC : ELF_SYM_OBJECT;
    sym.bind = 1;
    sym.value = va;
    sym.dynamic = sym.exported = true;
    sym.name = clean_dup(sn, sl);
    if (!sym.name || !push_symbol(c->ef, c->scap, &sym)) { free(sym.name); return false; }
    c->ef->pe.nexports++;
    return true;
}

static void read_exports(ElfFile *ef, Dir d, int *scap) {
    PeExports x;
    ExpCtx c = { ef, scap };
    bool ok = export_walk(ef, d, &x, export_sym, &c);
    if (x.name[0]) snprintf(ef->soname, sizeof ef->soname, "%s", x.name);
    if (!ok) { if (x.err[0]) warn(ef, "%s", x.err); return; }
    if (x.names_bad) warn(ef, "export names outside the file: exports by ordinal only");
    if (x.nbadord) warn(ef, "%u export name entries with an ordinal outside the address table: ignored", x.nbadord);
    if (x.nbadname) warn(ef, "%u export names outside the file or unterminated (named by ordinal)", x.nbadname);
    if (x.nbadrva) warn(ef, "%u exports point outside the image: ignored", x.nbadrva);
    if (x.nbadfwd) warn(ef, "%u export forwarders without a valid \"dll.func\" string", x.nbadfwd);
}

/* COFF symbol table (MinGW binaries not stripped): functions, statics,
 * labels; section and file entries skipped */
static bool read_coff_syms(ElfFile *ef, int *scap, uint32_t off, uint32_t count,
                           uint64_t sec_off, int nsec_hdr) {
    if (!off || !count) return false;
    if (count > MAX_COFF_SYMS || !in_file(ef, off, (uint64_t)count * 18)) {
        warn(ef, "COFF symbol table outside the file: ignored");
        return false;
    }
    uint64_t str = (uint64_t)off + (uint64_t)count * 18, strsz = 0;
    if (in_file(ef, str, 4)) strsz = r32(ef->data + str);
    if (strsz < 4 || !in_file(ef, str, strsz)) strsz = 0;
    bool funcs = false;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *p = ef->data + off + (uint64_t)i * 18;
        uint32_t value = r32(p + 8);
        int16_t  secn  = (int16_t)r16(p + 12);
        uint16_t type  = r16(p + 14);
        uint8_t  cls   = p[16], naux = p[17];
        i += naux;                                     /* aux records follow */
        if (secn < 1 || secn > nsec_hdr) continue;     /* undefined, absolute, debug */
        if (cls != 2 && cls != 3 && cls != 6) continue;  /* EXTERNAL, STATIC, LABEL */
        if (cls == 3 && naux) continue;                /* section definition */
        char nb[9];
        const char *s;
        size_t nl;
        if (r32(p) == 0) {                             /* long name: string table */
            uint32_t o = r32(p + 4);
            if (!strsz || o < 4 || o >= strsz) continue;
            s = (const char *)ef->data + str + o;
            const char *z = memchr(s, 0, (size_t)(strsz - o));
            if (!z) continue;
            nl = (size_t)(z - s);
        } else {
            memcpy(nb, p, 8);
            nb[8] = '\0';
            s = nb;
            nl = strlen(nb);
        }
        if (!nl || s[0] == '.') continue;              /* .text, .file, .weak... */
        const uint8_t *sh = ef->data + sec_off + (uint64_t)(secn - 1) * 40;
        uint64_t va = rva_va(ef, (uint64_t)r32(sh + 12) + value);
        bool fn = (type >> 4) == 2;                    /* DTYPE_FUNCTION */
        bool code = elf_va_exec(ef, va);
        ElfSymbol sym = {0};
        sym.kind  = fn && code ? ELF_SYM_FUNC : code ? ELF_SYM_OTHER : ELF_SYM_OBJECT;
        sym.bind  = cls == 2 ? 1 : 0;
        sym.shndx = (uint16_t)secn;
        sym.value = va;
        if (sym.kind == ELF_SYM_FUNC) funcs = true;
        sym.name = clean_dup(s, nl);
        if (!sym.name || !push_symbol(ef, scap, &sym)) { free(sym.name); break; }
    }
    return funcs;
}

static void add_reloc(ElfFile *ef, int *cap, uint64_t va, uint64_t addend) {
    if (ef->nrel >= (int)MAX_RELOCS) return;
    if (ef->nrel == *cap) {
        int nc = *cap ? *cap * 2 : 256;
        ElfReloc *n = realloc(ef->rel, (size_t)nc * sizeof *n);
        if (!n) return;
        ef->rel = n; *cap = nc;
    }
    ef->rel[ef->nrel++] = (ElfReloc){ va, addend };
}

/* Base relocations: IMAGE_BASE_RELOCATION blocks { page RVA, block size }
 * + 16-bit entries (type << 12 | offset). HIGHLOW (3) words in PE32,
 * DIR64 (10) in PE32+ are kept, value = what the file holds there (the
 * VA at ImageBase); ABSOLUTE (0) is padding; HIGHADJ (4) takes the next
 * entry as its parameter; other types are counted and ignored. A block
 * of 0 bytes ends the table when its page is 0 too (zero padding), any
 * other block under 8 bytes, of odd size or past the table ends it with
 * a warning. Bounded by the table size and MAX_RELOCS. */
static void read_relocs(ElfFile *ef, Dir d) {
    if (!d.rva || !d.size) return;
    bool p32 = ef->bits == 32;
    unsigned ws = p32 ? 4u : 8u, want = p32 ? 3u : 10u;
    uint32_t nother = 0, nout = 0;
    bool capped = false;
    int cap = 0;
    uint64_t at = d.rva, end = (uint64_t)d.rva + d.size;
    while (at + 8 <= end && !capped) {
        const uint8_t *b = rva_ptr(ef, at, 8, NULL);
        if (!b) { warn(ef, "base relocations run out of the file"); break; }
        uint32_t page = r32(b), bsz = r32(b + 4);
        if (!bsz && !page) break;
        if (bsz < 8 || (bsz & 1) || bsz > end - at) {
            warn(ef, "base relocation block of %u bytes at RVA 0x%llx: rest ignored", bsz, (unsigned long long)at);
            break;
        }
        const uint8_t *e = rva_ptr(ef, at + 8, bsz - 8, NULL);
        if (!e) { warn(ef, "base relocations run out of the file"); break; }
        for (uint32_t k = 0; k + 2 <= bsz - 8; k += 2) {
            uint16_t w = r16(e + k);
            unsigned type = w >> 12;
            if (type == 0) continue;                   /* IMAGE_REL_BASED_ABSOLUTE */
            if (type == 4) { k += 2; nother++; continue; }   /* HIGHADJ + its parameter */
            if (type != want) { nother++; continue; }
            uint64_t rva = (uint64_t)page + (w & 0xfff);
            size_t av = 0;
            const uint8_t *q = rva + ws <= ef->pe.size_image ? elf_va_ptr(ef, rva_va(ef, rva), &av) : NULL;
            if (!q || av < ws) { nout++; continue; }
            if (ef->nrel >= (int)MAX_RELOCS) { capped = true; break; }
            add_reloc(ef, &cap, rva_va(ef, rva), p32 ? r32(q) : r64(q));
        }
        at += bsz;
    }
    if (capped) warn(ef, "base relocations: limit of %u reached, the rest is ignored", MAX_RELOCS);
    if (nother) warn(ef, "%u base relocations of another type than %s ignored", nother, p32 ? "HIGHLOW" : "DIR64");
    if (nout) warn(ef, "%u base relocations outside the image or the file data: ignored", nout);
}

/* ─── .pdata / UNWIND_INFO (PE32+) ─────────────────────────────── */

#define UNW_FLAG_EHANDLER  1
#define UNW_FLAG_UHANDLER  2
#define UNW_FLAG_CHAININFO 4

/* UNWIND_INFO at an RVA: flags, and what follows the codes (the chained
 * RUNTIME_FUNCTION, or the handler RVA). false when its header or that
 * tail is not in the file, or the version is not 1 or 2. */
typedef struct { uint8_t flags; uint32_t cb, ce, cu, handler; } Unw;

static bool unwind_read(const ElfFile *ef, uint32_t rva, Unw *u) {
    memset(u, 0, sizeof *u);
    const uint8_t *p = rva_ptr(ef, rva, 4, NULL);
    if (!p) return false;
    uint8_t ver = p[0] & 7;
    if (ver != 1 && ver != 2) return false;
    u->flags = p[0] >> 3;
    uint64_t tail = 4 + 2 * (((uint64_t)p[2] + 1) & ~1ull);   /* codes, even count */
    if (u->flags & UNW_FLAG_CHAININFO) {
        const uint8_t *c = rva_ptr(ef, (uint64_t)rva + tail, 12, NULL);
        if (!c) return false;
        u->cb = r32(c); u->ce = r32(c + 4); u->cu = r32(c + 8);
    } else if (u->flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) {
        const uint8_t *h = rva_ptr(ef, (uint64_t)rva + tail, 4, NULL);
        if (!h) return false;
        u->handler = r32(h);
    }
    return true;
}

static int cmp_rtf(const void *a, const void *b) {
    const PeRtFunc *x = a, *y = b;
    return x->begin < y->begin ? -1 : x->begin > y->begin;
}

/* root of the chain of an entry whose unwind data is `u` (RVA, bit 0:
 * points to another RUNTIME_FUNCTION): 1 found (*root = its begin),
 * 0 not chained (or its own UNWIND_INFO unreadable), -1 cyclic, -2 too
 * long, -3 broken (a link past the first one unreadable) */
static int chain_root(const ElfFile *ef, uint32_t u, uint32_t *root) {
    uint32_t seen[PE_CHAIN_MAX];
    int ns = 0;
    uint32_t begin = 0;
    for (;;) {
        if (u & 1) {                                   /* indirect: another entry */
            const uint8_t *r = rva_ptr(ef, (uint64_t)(u & ~1u), 12, NULL);
            if (!r) return -3;
            for (int i = 0; i < ns; i++) if (seen[i] == u) return -1;
            if (ns == PE_CHAIN_MAX) return -2;
            seen[ns++] = u;
            begin = r32(r);
            u = r32(r + 8);
            continue;
        }
        Unw w;
        if (!unwind_read(ef, u, &w)) return ns ? -3 : 0;
        if (!(w.flags & UNW_FLAG_CHAININFO)) {
            if (!ns) return 0;                         /* not chained at all */
            *root = begin;
            return 1;
        }
        for (int i = 0; i < ns; i++) if (seen[i] == u) return -1;
        if (ns == PE_CHAIN_MAX) return -2;
        seen[ns++] = u;
        begin = w.cb;
        u = w.cu;
    }
}

static bool rva_code(const ElfFile *ef, uint32_t rva) {
    return rva && rva < ef->pe.size_image && elf_va_exec(ef, rva_va(ef, rva));
}

static bool pdata_walk(const ElfFile *ef, Dir d, PePdata *pd) {
    memset(pd, 0, sizeof *pd);
    if (!d.rva || !d.size) return false;
    uint64_t n = d.size / 12;
    pd->rest = d.size % 12;
    if (n > MAX_PDATA) { n = MAX_PDATA; pd->capped = true; }
    pd->nent = (uint32_t)n;
    const uint8_t *p = rva_ptr(ef, d.rva, n * 12, NULL);
    if (!p) { snprintf(pd->err, sizeof pd->err, "exception table (.pdata) outside the file data"); return false; }
    if (!n) return true;
    pd->e = malloc((size_t)n * sizeof *pd->e);
    if (!pd->e) { snprintf(pd->err, sizeof pd->err, "out of memory"); return false; }
    uint32_t prev = 0;
    for (uint64_t i = 0; i < n; i++) {
        uint32_t b = r32(p + i * 12), e = r32(p + i * 12 + 4), u = r32(p + i * 12 + 8);
        if (!b || e <= b) { pd->nempty++; continue; }
        if (b < prev) pd->nunsorted++;
        prev = b;
        if (e > ef->pe.size_image || !rva_code(ef, b)) { pd->nout++; continue; }
        PeRtFunc f = { b, e, 0, 0, 0 };
        uint32_t root = 0;
        int c = chain_root(ef, u, &root);
        if (c == -1) { pd->ncycle++; continue; }
        if (c == -2) { pd->ndeep++; continue; }
        if (c == -3 || (c == 1 && !rva_code(ef, root))) {
            pd->norphan++;                             /* a fragment, parent unknown */
            f.flags = PE_RF_FRAG;
        } else if (c == 1) {
            f.flags = PE_RF_FRAG;
            f.parent = root;
        } else {
            Unw w;
            if (!(u & 1) && unwind_read(ef, u, &w)) {
                if (w.flags & UNW_FLAG_EHANDLER) f.flags |= PE_RF_EH;
                if (w.flags & UNW_FLAG_UHANDLER) f.flags |= PE_RF_UH;
                if (w.handler && w.handler < ef->pe.size_image) f.handler = w.handler;
                else if (w.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) pd->nbadhandler++;
            } else { f.flags |= PE_RF_NOUNW; pd->nbadunw++; }
        }
        pd->e[pd->n++] = f;
    }
    if (pd->nunsorted) qsort(pd->e, pd->n, sizeof *pd->e, cmp_rtf);
    uint32_t k = 0, end = 0;
    for (uint32_t i = 0; i < pd->n; i++) {            /* overlaps: the first one wins */
        if (k && pd->e[i].begin < end) { pd->noverlap++; continue; }
        end = pd->e[i].end;
        pd->e[k++] = pd->e[i];
    }
    pd->n = k;
    for (uint32_t i = 0; i < pd->n; i++) {
        if (pd->e[i].flags & PE_RF_FRAG) pd->nfrag++; else pd->nfunc++;
        if (pd->e[i].handler) pd->nhandler++;
    }
    return true;
}

void pe_pdata_free(PePdata *p) {
    if (!p) return;
    free(p->e);
    p->e = NULL;
    p->n = 0;
}

/* .pdata: the function entries become ef->fstart (fragments are not
 * functions); what the checks found goes to one or two warnings */
static void read_pdata(ElfFile *ef, Dir d) {
    PePdata pd;
    if (!pdata_walk(ef, d, &pd)) {
        if (pd.err[0]) warn(ef, "%s: ignored", pd.err);
        pe_pdata_free(&pd);
        return;
    }
    if (pd.nfunc && (ef->fstart = malloc((size_t)pd.nfunc * sizeof *ef->fstart)))
        for (uint32_t i = 0; i < pd.n; i++)
            if (!(pd.e[i].flags & PE_RF_FRAG)) ef->fstart[ef->nfstart++] = rva_va(ef, pd.e[i].begin);
    /* symbols without a size get the one of their .pdata entry */
    for (uint32_t i = 0, j = 0; i < pd.n; i++) {
        if (pd.e[i].flags & PE_RF_FRAG) continue;
        uint64_t va = rva_va(ef, pd.e[i].begin);
        while (j < (uint32_t)ef->nsym && ef->sym[j].value < va) j++;
        for (uint32_t s = j; s < (uint32_t)ef->nsym && ef->sym[s].value == va; s++)
            if (!ef->sym[s].size && ef->sym[s].kind == ELF_SYM_FUNC) ef->sym[s].size = pd.e[i].end - pd.e[i].begin;
    }
    char b[160] = "";
    size_t u = 0;
    if (pd.rest)      note(b, sizeof b, &u, "size not a multiple of 12");
    if (pd.capped)    note(b, sizeof b, &u, "more than %u entries", MAX_PDATA);
    if (pd.nunsorted) note(b, sizeof b, &u, "not sorted (%u)", pd.nunsorted);
    if (pd.noverlap)  note(b, sizeof b, &u, "%u overlapping", pd.noverlap);
    if (pd.nempty)    note(b, sizeof b, &u, "%u empty", pd.nempty);
    if (pd.nout)      note(b, sizeof b, &u, "%u outside the code", pd.nout);
    if (b[0]) warn(ef, ".pdata: %s (bad entries ignored)", b);
    b[0] = '\0'; u = 0;
    if (pd.nbadunw)     note(b, sizeof b, &u, "%u unreadable", pd.nbadunw);
    if (pd.ncycle)      note(b, sizeof b, &u, "%u cyclic chains", pd.ncycle);
    if (pd.ndeep)       note(b, sizeof b, &u, "%u chains over %d links", pd.ndeep, PE_CHAIN_MAX);
    if (pd.norphan)     note(b, sizeof b, &u, "%u broken chains (fragments without a parent)", pd.norphan);
    if (pd.nbadhandler) note(b, sizeof b, &u, "%u handlers outside the image", pd.nbadhandler);
    if (b[0]) warn(ef, "UNWIND_INFO: %s", b);
    pe_pdata_free(&pd);
}

static void add_ctor(ElfFile *ef, uint64_t va) {
    if (!va || ef->nctors >= MAX_TLS_CB || !elf_va_exec(ef, va)) return;
    for (int i = 0; i < ef->nctors; i++) if (ef->ctors[i] == va) return;
    uint64_t *n = realloc(ef->ctors, (size_t)(ef->nctors + 1) * sizeof *n);
    if (!n) return;
    ef->ctors = n;
    ef->ctors[ef->nctors++] = va;
}

/* TLS callbacks: run by the loader before the entry point.
 * IMAGE_TLS_DIRECTORY32 / 64: AddressOfCallBacks at 12 / 24, a VA of a
 * NULL-terminated array of 4- / 8-byte VAs */
static void read_tls(ElfFile *ef, Dir d) {
    if (!d.rva || !d.size) return;
    bool p32 = ef->bits == 32;
    const uint8_t *p = rva_ptr(ef, d.rva, p32 ? 24 : 40, NULL);
    if (!p) { warn(ef, "TLS directory outside the file: ignored"); return; }
    uint64_t cb = p32 ? r32(p + 12) : r64(p + 24);
    if (!cb) return;
    unsigned w = p32 ? 4 : 8;
    int i;
    for (i = 0; i < MAX_TLS_CB; i++) {
        uint64_t v;
        if (!elf_read_ptr(ef, cb + (uint64_t)i * w, &v)) {
            if (!i) warn(ef, "TLS callback array at 0x%llx outside the file data: ignored", (unsigned long long)cb);
            break;
        }
        if (!v) break;
        add_ctor(ef, v);
    }
    if (i == MAX_TLS_CB) warn(ef, "TLS callbacks: limit of %d reached, the rest is ignored", MAX_TLS_CB);
}

/* IMAGE_LOAD_CONFIG_DIRECTORY32 / 64 field offsets */
#define LC32_COOKIE  0x3c
#define LC32_SEH     0x40          /* SEHandlerTable, SEHandlerCount (4 + 4) */
#define LC32_CFTAB   0x50          /* GuardCFFunctionTable, Count (4 + 4)    */
#define LC32_GFLAGS  0x58
#define LC64_COOKIE  0x58
#define LC64_CFTAB   0x80          /* (8 + 8)                                */
#define LC64_GFLAGS  0x90

/* the structure's Size field is checked before every field: a field is
 * read only inside min(Size, bytes in the file, PE_LC_MAX) */
static bool lc_walk(const ElfFile *ef, Dir d, PeLoadConfig *lc) {
    memset(lc, 0, sizeof *lc);
    if (!d.rva || !d.size) return false;
    lc->dirsize = d.size;
    size_t av = 0;
    const uint8_t *p = rva_ptr(ef, d.rva, 4, &av);
    if (!p) { snprintf(lc->err, sizeof lc->err, "load config outside the file data"); return false; }
    lc->present = true;
    lc->size = r32(p);
    lc->avail = av > UINT32_MAX ? UINT32_MAX : (uint32_t)av;
    uint32_t u = lc->size;
    if (u < 8) {
        snprintf(lc->err, sizeof lc->err, "load config Size %u is too small: no field read", lc->size);
        return true;
    }
    if (u > lc->avail) {
        snprintf(lc->err, sizeof lc->err, "load config Size 0x%x runs past the file data (0x%x bytes): cut", u, lc->avail);
        u = lc->avail;
    }
    if (u > PE_LC_MAX) {
        if (!lc->err[0]) snprintf(lc->err, sizeof lc->err, "load config Size 0x%x is aberrant: only 0x%x bytes read", lc->size, PE_LC_MAX);
        u = PE_LC_MAX;
    }
    lc->used = u;
    if (ef->bits == 32) {
        if (u >= LC32_COOKIE + 4) { lc->has_cookie = true; lc->cookie = r32(p + LC32_COOKIE); }
        if (u >= LC32_SEH + 8)    { lc->has_seh = true; lc->seh_table = r32(p + LC32_SEH); lc->seh_count = r32(p + LC32_SEH + 4); }
        if (u >= LC32_CFTAB + 8)  { lc->has_cf = true; lc->cf_table = r32(p + LC32_CFTAB); lc->cf_count = r32(p + LC32_CFTAB + 4); }
        if (u >= LC32_GFLAGS + 4) { lc->has_gflags = true; lc->guard_flags = r32(p + LC32_GFLAGS); }
    } else {
        if (u >= LC64_COOKIE + 8) { lc->has_cookie = true; lc->cookie = r64(p + LC64_COOKIE); }
        if (u >= LC64_CFTAB + 16) { lc->has_cf = true; lc->cf_table = r64(p + LC64_CFTAB); lc->cf_count = r64(p + LC64_CFTAB + 8); }
        if (u >= LC64_GFLAGS + 4) { lc->has_gflags = true; lc->guard_flags = r32(p + LC64_GFLAGS); }
    }
    return true;
}

static void read_load_config(ElfFile *ef, Dir d) {
    PeLoadConfig lc;
    if (!lc_walk(ef, d, &lc)) {
        if (lc.err[0]) warn(ef, "%s: ignored", lc.err);
        return;
    }
    if (lc.err[0]) warn(ef, "%s", lc.err);
    if (lc.has_cookie) ef->pe.cookie = lc.cookie;
    if (lc.has_gflags) ef->pe.guard_flags = lc.guard_flags;
}

/* a table of RVAs at `va` (a VA, as the load config stores it): `count`
 * entries of `stride` bytes, the table inside the image and the file */
static bool table_walk(const ElfFile *ef, uint64_t va, uint64_t count, uint32_t stride, PeTable *t) {
    t->present = true;
    t->count = count;
    t->stride = stride;
    if (!va) {
        t->bad = true;
        snprintf(t->err, sizeof t->err, "%llu entries declared but no table", (unsigned long long)count);
        return false;
    }
    uint64_t n = count;
    if (n > PE_TABLE_MAX) { n = PE_TABLE_MAX; t->capped = true; }
    uint64_t base = ef->pe.image_base;
    const uint8_t *p = NULL;
    if (va >= base && va - base < ef->pe.size_image && n * stride <= ef->pe.size_image - (va - base))
        p = rva_ptr(ef, va - base, n * stride, NULL);
    if (!p) {
        t->bad = true;
        snprintf(t->err, sizeof t->err, "table at 0x%llx (%llu x %u bytes) outside the image or the file",
                 (unsigned long long)va, (unsigned long long)count, stride);
        return false;
    }
    t->va = malloc((size_t)(n ? n : 1) * sizeof *t->va);
    if (!t->va) { t->bad = true; snprintf(t->err, sizeof t->err, "out of memory"); return false; }
    /* the loader looks entries up by binary search: the table is read up
     * to its first entry not above the one before (a count running past
     * the real table reads other data, which breaks the order) */
    uint32_t prev = 0;
    for (uint64_t i = 0; i < n; i++) {
        uint32_t r = r32(p + i * stride);
        if (i && r <= prev) { t->nunsorted = (uint32_t)(n - i); break; }
        prev = r;
        if (!rva_code(ef, r)) { t->nout++; continue; }
        t->va[t->n++] = rva_va(ef, r);
    }
    return true;
}

static bool safeseh_walk(const ElfFile *ef, Dir d, PeTable *t) {
    PeLoadConfig lc;
    memset(t, 0, sizeof *t);
    if (ef->bits != 32 || !lc_walk(ef, d, &lc) || !lc.has_seh || (!lc.seh_table && !lc.seh_count)) return false;
    return table_walk(ef, lc.seh_table, lc.seh_count, 4, t);
}

static bool guard_cf_walk(const ElfFile *ef, Dir d, PeTable *t) {
    PeLoadConfig lc;
    memset(t, 0, sizeof *t);
    if (!lc_walk(ef, d, &lc) || !lc.has_cf || (!lc.cf_table && !lc.cf_count)) return false;
    uint32_t stride = 4 + (lc.has_gflags ? lc.guard_flags >> 28 : 0);
    return table_walk(ef, lc.cf_table, lc.cf_count, stride, t);
}

void pe_table_free(PeTable *t) {
    if (!t) return;
    free(t->va);
    t->va = NULL;
    t->n = 0;
}

/* the SafeSEH and CFG tables, checked once at load time (warnings) */
static void check_table(ElfFile *ef, const char *what, bool ok, const PeTable *t) {
    if (!t->present) return;
    if (!ok) { warn(ef, "%s: %s: ignored", what, t->err); return; }
    char b[160] = "";
    size_t u = 0;
    if (t->capped)    note(b, sizeof b, &u, "%llu entries, only %u read", (unsigned long long)t->count, PE_TABLE_MAX);
    if (t->nunsorted) note(b, sizeof b, &u, "not in ascending order: the last %u entries ignored", t->nunsorted);
    if (t->nout)      note(b, sizeof b, &u, "%u entries outside the code (ignored)", t->nout);
    if (b[0]) warn(ef, "%s: %s", what, b);
}

/* CodeView entry of the debug directory: path of the .pdb */
static void read_debug(ElfFile *ef, Dir d) {
    if (!d.rva || !d.size) return;
    for (uint32_t k = 0; k + 28 <= d.size && k < 28 * 32; k += 28) {
        const uint8_t *p = rva_ptr(ef, (uint64_t)d.rva + k, 28, NULL);
        if (!p) return;
        uint32_t type = r32(p + 12), size = r32(p + 16), foff = r32(p + 24);
        if (type != 2 || size < 25 || !in_file(ef, foff, size)) continue;   /* CODEVIEW */
        const uint8_t *cv = ef->data + foff;
        if (memcmp(cv, "RSDS", 4)) continue;
        const uint8_t *z = memchr(cv + 24, 0, size - 24);
        size_t n = z ? (size_t)(z - cv - 24) : size - 24;
        clean_copy(ef->pe.pdb, sizeof ef->pe.pdb, (const char *)cv + 24, n);
        return;
    }
}

/* .pdata ranges, to tell a thunk from a jmp inside a function */
typedef struct { uint64_t lo, hi; } Range;

static int cmp_range(const void *a, const void *b) {
    const Range *x = a, *y = b;
    return x->lo < y->lo ? -1 : x->lo > y->lo;
}

static bool in_ranges(const Range *r, size_t n, uint64_t va) {
    size_t lo = 0, hi = n;
    while (lo < hi) {                                  /* first lo > va */
        size_t mid = lo + (hi - lo) / 2;
        if (r[mid].lo <= va) lo = mid + 1; else hi = mid;
    }
    return lo && va < r[lo - 1].hi;
}

static Range *pdata_ranges(const ElfFile *ef, Dir d, size_t *n) {
    *n = 0;
    if (!d.rva || !d.size) return NULL;
    uint64_t k = d.size / 12;
    if (k > MAX_PDATA) k = MAX_PDATA;
    const uint8_t *p = rva_ptr(ef, d.rva, k * 12, NULL);
    Range *r = p && k ? malloc((size_t)k * sizeof *r) : NULL;
    if (!r) return NULL;
    for (uint64_t i = 0; i < k; i++) {
        uint32_t b = r32(p + i * 12), e = r32(p + i * 12 + 4);
        if (b && e > b) r[(*n)++] = (Range){ rva_va(ef, b), rva_va(ef, e) };
    }
    qsort(r, *n, sizeof *r, cmp_range);
    return r;
}

/* MinGW import stubs in the code: `jmp [rip+slot]` (ff 25, no REX
 * prefix) with slot an IAT entry, outside every .pdata function, 8-byte
 * aligned or followed by padding (a tail call `rex.W jmp [rip+slot]` in
 * a function body is not one); the first one of a slot becomes its
 * "plt" */
static void map_thunks(ElfFile *ef, const Range *pr, size_t npr) {
    if (!ef->nimp) return;
    for (int m = 0; m < ef->nmap; m++) {
        const ElfMap *mp = &ef->map[m];
        if (!(mp->flags & PF_X) || mp->filesz < 6) continue;
        const uint8_t *p = ef->data + mp->off;
        for (uint64_t i = 0; i + 6 <= mp->filesz; i++) {
            if (p[i] != 0xff || p[i + 1] != 0x25) continue;
            if (i && (p[i - 1] & 0xf0) == 0x40) continue;          /* REX prefix */
            uint64_t at = mp->va + i;
            bool pad = i + 8 > mp->filesz || ((p[i + 6] == 0x90 || p[i + 6] == 0xcc || p[i + 6] == 0) &&
                                              (p[i + 7] == 0x90 || p[i + 7] == 0xcc || p[i + 7] == 0));
            if ((at & 7) && !pad) continue;
            if (in_ranges(pr, npr, at)) continue;
            int32_t  rel  = (int32_t)r32(p + i + 2);
            uint64_t slot = at + 6 + (uint64_t)(int64_t)rel;
            ElfImport *im = (ElfImport *)elf_import_got(ef, slot);
            if (im && !im->plt) { im->plt = at; i += 5; }
        }
    }
}

/* PE32 import stubs: `jmp [abs32]` (ff 25) with abs32 an IAT slot, that
 * nothing runs into: at the start of an executable mapping, after
 * padding (cc / 90), a ret, or another such stub (MSVC and MinGW thunk
 * tables). A `jmp [IAT]` ending a function (tail call) follows code and
 * is not one. The first one of a slot becomes its "plt". */
static void map_thunks32(ElfFile *ef) {
    if (!ef->nimp) return;
    for (int m = 0; m < ef->nmap; m++) {
        const ElfMap *mp = &ef->map[m];
        if (!(mp->flags & PF_X) || mp->filesz < 6) continue;
        const uint8_t *p = ef->data + mp->off;
        for (uint64_t i = 0; i + 6 <= mp->filesz; i++) {
            if (p[i] != 0xff || p[i + 1] != 0x25) continue;
            ElfImport *im = (ElfImport *)elf_import_got(ef, r32(p + i + 2));
            if (!im || im->plt) continue;
            uint8_t b = i ? p[i - 1] : 0;
            bool lone = !i || b == 0xcc || b == 0x90 || b == 0xc3 ||
                        (i >= 6 && p[i - 6] == 0xff && p[i - 5] == 0x25 && elf_import_got(ef, r32(p + i - 4)));
            if (!lone) continue;
            im->plt = mp->va + i;
            i += 5;
        }
    }
}

static int cmp_sym(const void *a, const void *b) {
    const ElfSymbol *x = a, *y = b;
    if (x->value != y->value) return x->value < y->value ? -1 : 1;
    if (x->kind != y->kind) return x->kind < y->kind ? -1 : 1;
    if (x->dynamic != y->dynamic) return x->dynamic ? 1 : -1;
    if ((x->bind == 0) != (y->bind == 0)) return x->bind == 0 ? 1 : -1;
    return strcmp(x->name, y->name);
}
static int cmp_imp(const void *a, const void *b) {
    const ElfImport *x = a, *y = b;
    return x->got < y->got ? -1 : x->got > y->got;
}
static int cmp_rel(const void *a, const void *b) {
    const ElfReloc *x = a, *y = b;
    return x->va < y->va ? -1 : x->va > y->va;
}

/* ─── entry points ─────────────────────────────────────────────── */

bool pe_is_pe(const uint8_t *buf, size_t len) {
    if (len < 0x40 || buf[0] != 'M' || buf[1] != 'Z') return false;
    uint32_t lfa = r32(buf + 0x3c);
    return lfa <= len - 4 && !memcmp(buf + lfa, "PE\0\0", 4);
}

const char *pe_machine_name(uint16_t m) {
    switch (m) {
        case PE_MACHINE_AMD64: return "x86-64 (AMD64)";
        case PE_MACHINE_I386:  return "x86 (i386)";
        case PE_MACHINE_ARM64: return "ARM64";
        case 0x01c4:           return "ARM Thumb-2";
        case 0x0200:           return "Itanium";
        case 0xa641:           return "ARM64EC";
        default:               return "unknown";
    }
}

const char *pe_subsystem_name(uint16_t s) {
    switch (s) {
        case 1:  return "native (driver)";
        case 2:  return "Windows GUI";
        case 3:  return "Windows console";
        case 7:  return "POSIX console";
        case 9:  return "Windows CE GUI";
        case 10: return "EFI application";
        case 11: return "EFI boot service driver";
        case 12: return "EFI runtime driver";
        case 13: return "EFI ROM";
        case 14: return "Xbox";
        case 16: return "Windows boot application";
        default: return "unknown";
    }
}

/* ─── headers ──────────────────────────────────────────────────── */

static bool pow2(uint32_t x) { return x && !(x & (x - 1)); }

const char *pe_dir_name(unsigned i) {
    static const char *n[PE_NDIR] = {
        "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG",
        "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT",
        "DELAY_IMPORT", "CLR", "RESERVED" };
    return i < PE_NDIR ? n[i] : "?";
}

bool pe_read_headers(const uint8_t *buf, size_t len, PeHeaders *h, char *err, size_t esz) {
    memset(h, 0, sizeof *h);
    if (!buf || len < 0x40 || buf[0] != 'M' || buf[1] != 'Z') { set_err(err, esz, "Not a PE file (no MZ header)"); return false; }
    uint32_t lfa = r32(buf + 0x3c);
    if (lfa > len - 4) {
        set_err(err, esz, "MS-DOS executable or corrupt PE: e_lfanew 0x%x points outside the file (%zu bytes)", lfa, len);
        return false;
    }
    if (memcmp(buf + lfa, "PE\0\0", 4)) { set_err(err, esz, "MS-DOS executable (MZ without a PE header): not analysed"); return false; }
    if ((uint64_t)lfa + 24 > len) { set_err(err, esz, "Truncated PE: the COFF header is cut at the end of the file"); return false; }
    const uint8_t *fh = buf + lfa + 4;
    h->lfanew    = lfa;
    h->machine   = r16(fh);
    h->nsec      = r16(fh + 2);
    h->timestamp = r32(fh + 4);
    h->symoff    = r32(fh + 8);
    h->nsyms     = r32(fh + 12);
    h->optsz     = r16(fh + 16);
    h->chars     = r16(fh + 18);
    if (!h->nsec || h->nsec > MAX_SECTIONS) {
        set_err(err, esz, "Malformed PE: %u sections (1 to %d accepted)", h->nsec, MAX_SECTIONS);
        return false;
    }
    uint64_t oh = (uint64_t)lfa + 24;
    h->opt_off = oh;
    if (h->optsz < 2 || oh + 2 > len) {
        set_err(err, esz, "Truncated PE: no optional header (SizeOfOptionalHeader %u)", h->optsz);
        return false;
    }
    h->magic = r16(buf + oh);
    if (h->magic == 0x107) { set_err(err, esz, "ROM image (optional header magic 0x107): not analysed"); return false; }
    if (h->magic != PE_MAGIC_PE32 && h->magic != PE_MAGIC_PE32P) {
        set_err(err, esz, "Malformed PE: optional header magic 0x%x", h->magic);
        return false;
    }
    bool p32 = h->magic == PE_MAGIC_PE32;
    unsigned fixed = p32 ? 96 : 112;               /* up to NumberOfRvaAndSizes included */
    if (h->optsz < fixed) {
        set_err(err, esz, "Malformed PE: SizeOfOptionalHeader %u is shorter than a %s optional header (%u bytes)",
                h->optsz, p32 ? "PE32" : "PE32+", fixed);
        return false;
    }
    if (oh + h->optsz > len) {
        set_err(err, esz, "Truncated PE: the optional header (%u bytes at 0x%llx) is cut at the end of the file",
                h->optsz, (unsigned long long)oh);
        return false;
    }
    const uint8_t *o = buf + oh;
    h->bits         = p32 ? 32 : 64;
    h->linker_major = o[2];
    h->linker_minor = o[3];
    h->entry        = r32(o + 16);
    h->image_base   = p32 ? r32(o + 28) : r64(o + 24);
    h->sect_align   = r32(o + 32);
    h->file_align   = r32(o + 36);
    h->os_major     = r16(o + 40);
    h->os_minor     = r16(o + 42);
    h->size_image   = r32(o + 56);
    h->size_headers = r32(o + 60);
    h->checksum     = r32(o + 64);
    h->subsystem    = r16(o + 68);
    h->dllchars     = r16(o + 70);
    h->nrva         = r32(o + fixed - 4);
    h->ndir         = h->nrva < PE_NDIR ? h->nrva : PE_NDIR;
    if (fixed + (uint64_t)h->ndir * 8 > h->optsz) {
        set_err(err, esz, "Malformed PE: SizeOfOptionalHeader %u is too small for its %u data directories (%u bytes needed)",
                h->optsz, h->ndir, fixed + h->ndir * 8);
        return false;
    }
    for (uint32_t i = 0; i < h->ndir; i++)
        h->dir[i] = (PeDir){ r32(o + fixed + i * 8), r32(o + fixed + 4 + i * 8) };
    h->sec_off = oh + h->optsz;
    if (h->sec_off + (uint64_t)h->nsec * 40 > len) {
        set_err(err, esz, "Truncated PE: the section table (%u entries at 0x%llx) is cut at the end of the file",
                h->nsec, (unsigned long long)h->sec_off);
        return false;
    }
    if (!pow2(h->sect_align)) { set_err(err, esz, "Malformed PE: SectionAlignment 0x%x is not a power of two", h->sect_align); return false; }
    if (!pow2(h->file_align)) { set_err(err, esz, "Malformed PE: FileAlignment 0x%x is not a power of two", h->file_align); return false; }
    if (h->file_align > h->sect_align) {
        set_err(err, esz, "Malformed PE: FileAlignment 0x%x is larger than SectionAlignment 0x%x", h->file_align, h->sect_align);
        return false;
    }
    if (h->sect_align < 0x1000 && h->file_align != h->sect_align) {
        set_err(err, esz, "Malformed PE: SectionAlignment 0x%x is below the page size but FileAlignment (0x%x) differs from it",
                h->sect_align, h->file_align);
        return false;
    }
    if (!h->size_image) { set_err(err, esz, "Malformed PE: SizeOfImage is 0"); return false; }
    if (h->size_headers > h->size_image) {
        set_err(err, esz, "Malformed PE: SizeOfHeaders 0x%x is larger than SizeOfImage 0x%x", h->size_headers, h->size_image);
        return false;
    }
    if (p32 ? h->image_base + h->size_image > 0x100000000ull : h->size_image > UINT64_MAX - h->image_base) {
        set_err(err, esz, p32 ? "Malformed PE: the image (ImageBase 0x%llx + SizeOfImage 0x%x) goes past 4 GiB"
                              : "Malformed PE: the image (ImageBase 0x%llx + SizeOfImage 0x%x) wraps around the address space",
                (unsigned long long)h->image_base, h->size_image);
        return false;
    }
    return true;
}

/* ─── RVA <-> offset <-> VA ────────────────────────────────────── */

uint64_t pe_rva_to_va(const ElfFile *ef, uint32_t rva) { return ef->pe.image_base + rva; }

bool pe_va_to_rva(const ElfFile *ef, uint64_t va, uint32_t *rva) {
    if (ef->fmt != ELF_FMT_PE || va < ef->pe.image_base || va - ef->pe.image_base >= ef->pe.size_image) return false;
    *rva = (uint32_t)(va - ef->pe.image_base);
    return true;
}

bool pe_rva_to_off(const ElfFile *ef, uint32_t rva, uint64_t *off) {
    if (ef->fmt != ELF_FMT_PE || rva >= ef->pe.size_image) return false;
    return elf_va_to_off(ef, ef->pe.image_base + rva, off);
}

bool pe_off_to_rva(const ElfFile *ef, uint64_t off, uint32_t *rva) {
    uint64_t va;
    return ef->fmt == ELF_FMT_PE && elf_off_to_va(ef, off, &va) && pe_va_to_rva(ef, va, rva);
}

/* ─── tables for the F9 view ──────────────────────────────────── */

/* a data directory of a loaded PE, if it lies inside the image */
static bool loaded_dir(const ElfFile *ef, unsigned i, Dir *d) {
    PeHeaders h;
    if (ef->fmt != ELF_FMT_PE || !pe_read_headers(ef->data, ef->size, &h, NULL, 0) || i >= h.ndir) return false;
    *d = (Dir){ h.dir[i].rva, h.dir[i].size };
    return d->rva && d->size && (uint64_t)d->rva + d->size <= h.size_image;
}

int pe_bound_imports(const ElfFile *ef, PeBound *b) {
    Dir d;
    memset(b, 0, sizeof *b);
    return loaded_dir(ef, DIR_BOUND_IMPORT, &d) ? bound_walk(ef, d, b) : 0;
}

bool pe_exports(const ElfFile *ef, PeExports *x) {
    Dir d;
    memset(x, 0, sizeof *x);
    return loaded_dir(ef, DIR_EXPORT, &d) && export_walk(ef, d, x, NULL, NULL);
}

/* IMAGE_COR20_HEADER { cb, runtime version (2 x 2), MetaData (8),
 * Flags, ... } */
bool pe_clr_flags(const ElfFile *ef, uint32_t *flags) {
    Dir d;
    if (!loaded_dir(ef, DIR_CLR, &d) || d.size < 24) return false;
    const uint8_t *p = rva_ptr(ef, d.rva, 24, NULL);
    if (!p || r32(p) < 24) return false;
    *flags = r32(p + 16);
    return true;
}

bool pe_pdata(const ElfFile *ef, PePdata *p) {
    Dir d;
    memset(p, 0, sizeof *p);
    if (ef->bits != 64 || !loaded_dir(ef, DIR_EXCEPTION, &d)) return false;
    if (pdata_walk(ef, d, p)) return true;
    pe_pdata_free(p);
    return false;
}

bool pe_load_config(const ElfFile *ef, PeLoadConfig *lc) {
    Dir d;
    memset(lc, 0, sizeof *lc);
    return loaded_dir(ef, DIR_LOAD_CONFIG, &d) && lc_walk(ef, d, lc);
}

bool pe_safeseh(const ElfFile *ef, PeTable *t) {
    Dir d;
    memset(t, 0, sizeof *t);
    if (!loaded_dir(ef, DIR_LOAD_CONFIG, &d)) return false;
    if (safeseh_walk(ef, d, t)) return true;
    pe_table_free(t);
    return false;
}

bool pe_guard_cf(const ElfFile *ef, PeTable *t) {
    Dir d;
    memset(t, 0, sizeof *t);
    if (!loaded_dir(ef, DIR_LOAD_CONFIG, &d)) return false;
    if (guard_cf_walk(ef, d, t)) return true;
    pe_table_free(t);
    return false;
}

/* ─── loader ───────────────────────────────────────────────────── */

bool pe_parse(ElfFile *ef, const uint8_t *buf, size_t len, char *err, size_t esz) {
    memset(ef, 0, sizeof *ef);
    if (len < 0x40 || buf[0] != 'M' || buf[1] != 'Z') { set_err(err, esz, "Not a PE file (no MZ header)"); return false; }
    if (len > ELF_MAX_FILE) { set_err(err, esz, "File too large for the analysis (%zu MB)", len >> 20); return false; }
    PeHeaders h;
    if (!pe_read_headers(buf, len, &h, err, esz)) return false;
    bool p32 = h.bits == 32;
    if (h.machine != PE_MACHINE_AMD64 && h.machine != PE_MACHINE_I386) {
        set_err(err, esz, "PE for %s (machine 0x%04x): only x86 (i386) and x64 are analysed", pe_machine_name(h.machine), h.machine);
        return false;
    }
    if (h.machine == PE_MACHINE_AMD64 && p32) { set_err(err, esz, "PE32 (32-bit) optional header on an x64 file: not analysed"); return false; }
    if (h.machine == PE_MACHINE_I386 && !p32) { set_err(err, esz, "PE32+ (64-bit) optional header on an x86 (i386) file: not analysed"); return false; }
    int nsec = h.nsec;

    ef->data = malloc(len);
    if (!ef->data) { set_err(err, esz, "Out of memory"); return false; }
    memcpy(ef->data, buf, len);
    ef->size = len;
    ef->fmt = ELF_FMT_PE;
    ef->machine = p32 ? 3 : 62;                    /* EM_386 / EM_X86_64: what the analysis checks */
    ef->arch = p32 ? ELF_ARCH_X86_32 : ELF_ARCH_X86_64;
    ef->bits = p32 ? 32 : 64;
    PeInfo *pe = &ef->pe;
    pe->machine      = h.machine;
    pe->chars        = h.chars;
    pe->timestamp    = h.timestamp;
    pe->dll          = (h.chars & PE_FILE_DLL) != 0;
    pe->linker_major = h.linker_major;
    pe->linker_minor = h.linker_minor;
    pe->image_base   = h.image_base;
    pe->os_major     = h.os_major;
    pe->os_minor     = h.os_minor;
    pe->size_image   = h.size_image;
    pe->size_headers = h.size_headers;
    pe->checksum     = h.checksum;
    pe->subsystem    = h.subsystem;
    pe->dllchars     = h.dllchars;
    Dir dir[DIR_COUNT] = {{0, 0}};
    for (uint32_t i = 0; i < h.ndir && i < DIR_COUNT; i++) dir[i] = (Dir){ h.dir[i].rva, h.dir[i].size };
    if (h.nrva > PE_NDIR) warn(ef, "NumberOfRvaAndSizes is %u: only the first %d data directories are read", h.nrva, PE_NDIR);
    if (pe->image_base & 0xffff) warn(ef, "ImageBase 0x%llx is not 64 KiB aligned", (unsigned long long)pe->image_base);
    if ((h.file_align < 0x200 || h.file_align > 0x10000) && h.file_align != h.sect_align)
        warn(ef, "FileAlignment 0x%x is outside 0x200..0x10000", h.file_align);
    if (h.size_image % h.sect_align)
        warn(ef, "SizeOfImage 0x%x is not a multiple of SectionAlignment 0x%x", h.size_image, h.sect_align);
    if (h.size_headers % h.file_align)
        warn(ef, "SizeOfHeaders 0x%x is not a multiple of FileAlignment 0x%x", h.size_headers, h.file_align);
    if (h.sec_off + (uint64_t)nsec * 40 > h.size_headers)
        warn(ef, "the section table ends past SizeOfHeaders 0x%x", h.size_headers);

    /* headers, then the sections: in ascending RVA order, aligned on
     * SectionAlignment, inside SizeOfImage, never overlapping in memory
     * (what the Windows loader requires); raw data cut by the end of the
     * file is only a warning (truncated samples stay readable) */
    uint64_t hsz = pe->size_headers < len ? pe->size_headers : len;
    if (hsz && !add_map(ef, pe->image_base, 0, hsz, hsz, PF_R)) goto oom;
    ef->sec = calloc((size_t)nsec, sizeof *ef->sec);
    if (!ef->sec) goto oom;
    ef->nsec = nsec;
    uint64_t raw_end = hsz, prev_end = 0;
    int ent_sec = -1, nraw_align = 0;
    bool ent_x = false;
    uint64_t str = h.symoff && h.nsyms <= MAX_COFF_SYMS ? (uint64_t)h.symoff + (uint64_t)h.nsyms * 18 : 0;
    uint64_t strsz = str && in_file(ef, str, 4) ? r32(ef->data + str) : 0;
    if (strsz < 4 || !in_file(ef, str, strsz)) strsz = 0;
    for (int i = 0; i < nsec; i++) {
        const uint8_t *p = ef->data + h.sec_off + (uint64_t)i * 40;
        ElfSection *s = &ef->sec[i];
        char nm[9];
        memcpy(nm, p, 8);
        nm[8] = '\0';
        if (nm[0] == '/' && strsz) {                   /* "/123": long name in the string table */
            unsigned long k = strtoul(nm + 1, NULL, 10);
            const char *ln = k >= 4 && k < strsz ? (const char *)ef->data + str + k : NULL;
            const char *z = ln ? memchr(ln, 0, (size_t)(strsz - k)) : NULL;
            if (z) clean_copy(s->name, sizeof s->name, ln, (size_t)(z - ln));
            else clean_copy(s->name, sizeof s->name, nm, strlen(nm));
        } else clean_copy(s->name, sizeof s->name, nm, strlen(nm));
        uint32_t vsize = r32(p + 8), va = r32(p + 12), rsize = r32(p + 16), roff = r32(p + 20), ch = r32(p + 36);
        uint64_t mem = vsize ? vsize : rsize;
        if (va % h.sect_align) {
            set_err(err, esz, "Malformed PE: section %.20s at RVA 0x%x is not aligned on SectionAlignment 0x%x", s->name, va, h.sect_align);
            goto fail;
        }
        if (va < h.size_headers) {
            set_err(err, esz, "Malformed PE: section %.20s at RVA 0x%x overlaps the headers (SizeOfHeaders 0x%x)", s->name, va, h.size_headers);
            goto fail;
        }
        if ((uint64_t)va + mem > h.size_image) {
            set_err(err, esz, "Malformed PE: section %.20s (RVA 0x%x, 0x%llx bytes) runs past SizeOfImage 0x%x",
                    s->name, va, (unsigned long long)mem, h.size_image);
            goto fail;
        }
        if (i && va < prev_end) {
            set_err(err, esz, "Malformed PE: sections %.20s and %.20s overlap in memory (or are out of order)", ef->sec[i - 1].name, s->name);
            goto fail;
        }
        prev_end = (uint64_t)va + mem;
        if (rsize && roff % h.file_align) nraw_align++;
        uint64_t fsz = rsize < mem ? rsize : mem;
        if (!roff) fsz = 0;
        if (fsz && !in_file(ef, roff, fsz)) {
            if (roff < len) { warn(ef, "section %.20s: raw data cut at the end of the file", s->name); fsz = len - roff; }
            else { warn(ef, "section %.20s: raw data outside the file", s->name); fsz = 0; s->bad = true; }
        }
        if (fsz && roff + fsz > raw_end) raw_end = roff + fsz;
        if (roff && rsize && (uint64_t)roff + rsize > raw_end && in_file(ef, roff, rsize)) raw_end = (uint64_t)roff + rsize;
        bool x = (ch & PE_SCN_MEM_EXECUTE) || (ch & PE_SCN_CNT_CODE);
        if (h.entry >= va && h.entry - va < mem) { ent_sec = i; ent_x = x; }
        s->type  = fsz ? SHT_PROGBITS : SHT_NOBITS;
        s->flags = S_ALLOC | (x ? S_EXEC : 0) | ((ch & PE_SCN_MEM_WRITE) ? S_WRITE : 0);
        s->addr  = rva_va(ef, va);
        s->off   = roff;
        s->size  = fsz ? fsz : mem;
        s->info  = ch;                                 /* raw characteristics */
        uint32_t pf = ((ch & PE_SCN_MEM_READ) || !(ch & PE_SCN_MEM_WRITE) ? PF_R : 0) |
                      ((ch & PE_SCN_MEM_WRITE) ? PF_W : 0) | (x ? PF_X : 0);
        if (fsz && !add_map(ef, s->addr, roff, fsz, mem, pf)) goto oom;
    }
    if (!ef->nmap || ef->nmap == (hsz ? 1 : 0)) { set_err(err, esz, "Malformed PE: no section with data in the file"); goto fail; }
    if (h.entry && h.entry >= h.size_image) {
        set_err(err, esz, "Malformed PE: entry point RVA 0x%x is outside the image (SizeOfImage 0x%x)", h.entry, h.size_image);
        goto fail;
    }
    if (nraw_align)
        warn(ef, "%d section%s with raw data not aligned on FileAlignment 0x%x (offsets used as stored)",
             nraw_align, nraw_align > 1 ? "s" : "", h.file_align);

    /* data directories: read, kept only when inside the image (entry 4,
     * the certificate table, is a file offset: inside the file) */
    char bad[140] = "";
    size_t bu = 0;
    for (int i = 0; i < DIR_COUNT; i++) {
        if (!dir[i].rva && !dir[i].size) continue;
        if (i == DIR_SECURITY) {
            if (in_file(ef, dir[i].rva, dir[i].size)) continue;
            warn(ef, "certificate table (SECURITY directory) outside the file: ignored");
        } else {
            if (dir[i].rva && (uint64_t)dir[i].rva + dir[i].size <= h.size_image) continue;
            if (bu < sizeof bad) bu += (size_t)snprintf(bad + bu, sizeof bad - bu, "%s%s", bu ? ", " : "", pe_dir_name((unsigned)i));
        }
        dir[i] = (Dir){ 0, 0 };
    }
    if (bad[0]) warn(ef, "data directories outside the image, ignored: %s", bad);

    /* overlay (installers, appended payloads) and the signature (dir 4:
     * a file offset, not an RVA) */
    if (dir[DIR_SECURITY].rva && dir[DIR_SECURITY].size) pe->signature = true;
    if (h.symoff && h.symoff >= raw_end && strsz && str + strsz > raw_end && str + strsz <= len)
        raw_end = str + strsz;                         /* COFF symbols + names: not an overlay */
    if (raw_end < len) {
        uint64_t end = len;
        if (pe->signature && dir[DIR_SECURITY].rva >= raw_end) end = dir[DIR_SECURITY].rva;
        if (end > raw_end) { pe->overlay_off = raw_end; pe->overlay_size = end - raw_end; }
    }

    pe->relocs = dir[DIR_BASERELOC].rva && dir[DIR_BASERELOC].size && !(h.chars & PE_FILE_RELOCS_STRIPPED);
    /* the tables behind the data directories: imports (+ delay-load and
     * bound), base relocations, exports in both; .pdata, TLS, load config,
     * debug and COFF symbols in PE32+ only for now */
    ImpCtx ic = { 0 };
    int scap = 0;
    read_imports(ef, dir[DIR_IMPORT], &ic);
    read_delay_imports(ef, dir[DIR_DELAY_IMPORT], &ic);
    imports_done(ef, &ic);
    if (ef->nimp) qsort(ef->imp, (size_t)ef->nimp, sizeof *ef->imp, cmp_imp);
    PeBound bd;
    if (bound_walk(ef, dir[DIR_BOUND_IMPORT], &bd) < 0) warn(ef, "bound import table malformed: read up to entry %d", bd.n);
    if (pe->relocs) read_relocs(ef, dir[DIR_BASERELOC]);
    if (ef->nrel) qsort(ef->rel, (size_t)ef->nrel, sizeof *ef->rel, cmp_rel);
    read_exports(ef, dir[DIR_EXPORT], &scap);
    if (!p32) {
        bool coff = read_coff_syms(ef, &scap, h.symoff, h.nsyms, h.sec_off, nsec);
        ef->stripped = !coff;
        if (ef->nsym) qsort(ef->sym, (size_t)ef->nsym, sizeof *ef->sym, cmp_sym);
        read_pdata(ef, dir[DIR_EXCEPTION]);
        read_tls(ef, dir[DIR_TLS]);
        read_load_config(ef, dir[DIR_LOAD_CONFIG]);
        read_debug(ef, dir[DIR_DEBUG]);
        size_t npr = 0;
        Range *pr = pdata_ranges(ef, dir[DIR_EXCEPTION], &npr);
        map_thunks(ef, pr, npr);
        free(pr);
    } else {
        /* PE32 x86: TLS callbacks and load config; no COFF symbols, no
         * debug directory read yet (.pdata is not used by x86 code) */
        ef->stripped = true;
        if (ef->nsym) qsort(ef->sym, (size_t)ef->nsym, sizeof *ef->sym, cmp_sym);
        read_tls(ef, dir[DIR_TLS]);
        read_load_config(ef, dir[DIR_LOAD_CONFIG]);
        map_thunks32(ef);
    }
    PeTable tb;
    bool tok = safeseh_walk(ef, dir[DIR_LOAD_CONFIG], &tb);
    check_table(ef, "SafeSEH handler table", tok, &tb);
    pe_table_free(&tb);
    tok = guard_cf_walk(ef, dir[DIR_LOAD_CONFIG], &tb);
    check_table(ef, "CFG function table", tok, &tb);
    pe_table_free(&tb);
    pe->dotnet = dir[DIR_CLR].rva && dir[DIR_CLR].size;
    uint32_t clr = 0;
    bool clr_ok = pe->dotnet && pe_clr_flags(ef, &clr);
    if (pe->dotnet && !clr_ok) warn(ef, ".NET header (CLR directory) unreadable: analysed as native code");
    else if (pe->dotnet && !(clr & PE_CLR_ILONLY))
        warn(ef, p32 ? ".NET mixed-mode assembly: its native x86 code is analysed, not its CIL methods"
                     : ".NET mixed-mode assembly: its native x64 code is analysed, not its CIL methods");
    else if (pe->dotnet)
        warn(ef, p32 ? ".NET assembly: its code is CIL bytecode, not x86 (only native stubs are disassembled)"
                     : ".NET assembly: its code is CIL bytecode, not x64 (only native stubs are disassembled)");

    ef->type = pe->relocs ? 3 : 2;
    ef->pie = !pe->dll && pe->relocs && (pe->dllchars & PE_DLLCHAR_DYNAMIC_BASE);
    ef->is_static = ef->nneeded == 0;
    ef->entry = h.entry ? rva_va(ef, h.entry) : 0;
    /* the entry point is a function start only inside the file-backed
     * bytes of an executable section (da_analyze checks it again) */
    if (!ef->entry) {
        if (!pe->dll) warn(ef, "no entry point (AddressOfEntryPoint is 0)");
    } else if (!elf_va_exec(ef, ef->entry)) {
        if (ent_sec < 0)
            warn(ef, "entry point 0x%llx (RVA 0x%x) is in no section%s", (unsigned long long)ef->entry, h.entry,
                 h.entry < h.size_headers ? " (inside the headers)" : "");
        else if (!ent_x)
            warn(ef, "entry point 0x%llx is in %.20s, a non-executable section", (unsigned long long)ef->entry, ef->sec[ent_sec].name);
        else
            warn(ef, "entry point 0x%llx in %.20s has no data in the file (zero-filled or cut)",
                 (unsigned long long)ef->entry, ef->sec[ent_sec].name);
    }
    return true;

oom:
    set_err(err, esz, "Out of memory");
fail:
    elf_free(ef);
    return false;
}
