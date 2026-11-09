/* Static disassembly (capstone, x86-64 / x86-32, read-only), see disasm.h.
 *
 * Linear wrapper (da_open / da_linear) and recursive analysis
 * (da_analyze). Nothing here executes, emulates or writes the analysed
 * binary: the bytes are read from the ElfFile copy in memory. */
#include "disasm.h"
#include "peload.h"

#include <capstone/capstone.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_err(char *err, size_t esz, const char *fmt, ...) {
    if (!err || !esz) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, esz, fmt, ap);
    va_end(ap);
}

/* ─── capstone context ─────────────────────────────────────────── */

const char *da_capstone_version(char *buf, size_t sz) {
    int major = 0, minor = 0;
    cs_version(&major, &minor);
    if (buf && sz) snprintf(buf, sz, "%d.%d", major, minor);
    return buf;
}

bool da_open(Disasm *d, char *err, size_t esz) {
    if (!d) { set_err(err, esz, "no context"); return false; }
    if (d->cs) return true;                       /* already open */

    csh h = 0;
    cs_mode mode = d->elf.arch == ELF_ARCH_X86_32 ? CS_MODE_32 : CS_MODE_64;
    cs_err e = cs_open(CS_ARCH_X86, mode, &h);
    if (e != CS_ERR_OK) {
        set_err(err, esz, "capstone: %s", cs_strerror(e));
        return false;
    }
    if ((e = cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL)) != CS_ERR_OK ||
        (e = cs_option(h, CS_OPT_DETAIL, CS_OPT_ON)) != CS_ERR_OK) {
        set_err(err, esz, "capstone: %s", cs_strerror(e));
        cs_close(&h);
        return false;
    }
    d->cs  = (size_t)h;
    d->att = false;
    return true;
}

void da_close(Disasm *d) {
    if (!d || !d->cs) return;
    csh h = (csh)d->cs;
    cs_close(&h);
    d->cs = 0;
}

/* ─── output lines ─────────────────────────────────────────────── */

typedef struct {
    DisLine *v;
    size_t   n, cap;
} LineVec;

/* next free slot (zeroed), NULL when out of memory */
static DisLine *lv_push(LineVec *lv) {
    if (lv->n == lv->cap) {
        size_t ncap = lv->cap ? lv->cap * 2 : 256;
        if (ncap < lv->cap || ncap > SIZE_MAX / sizeof(DisLine)) return NULL;
        DisLine *nv = realloc(lv->v, ncap * sizeof(DisLine));
        if (!nv) return NULL;
        lv->v   = nv;
        lv->cap = ncap;
    }
    DisLine *l = &lv->v[lv->n++];
    memset(l, 0, sizeof *l);
    return l;
}

/* one byte capstone could not decode: "db 0x.." */
static void line_bad(DisLine *l, uint64_t addr, uint8_t byte) {
    l->addr     = addr;
    l->len      = 1;
    l->bytes[0] = byte;
    l->bad      = true;
    snprintf(l->mnem, sizeof l->mnem, "db");
    snprintf(l->ops,  sizeof l->ops,  "0x%02x", byte);
}

static bool in_group(const cs_insn *in, uint8_t g) {
    const cs_detail *dt = in->detail;
    if (!dt) return false;
    for (uint8_t i = 0; i < dt->groups_count && i < sizeof dt->groups; i++)
        if (dt->groups[i] == g) return true;
    return false;
}

static void line_insn(DisLine *l, const cs_insn *in) {
    size_t len = in->size;
    if (len > sizeof l->bytes) len = sizeof l->bytes;   /* x86: <= 15 */
    l->addr = in->address;
    l->len  = (uint8_t)len;
    memcpy(l->bytes, in->bytes, len);
    snprintf(l->mnem, sizeof l->mnem, "%s", in->mnemonic);
    snprintf(l->ops,  sizeof l->ops,  "%s", in->op_str);
    l->imm_size = 0;
    l->has_disp = false;
    if (!in->detail || in_group(in, CS_GRP_JUMP) || in_group(in, CS_GRP_CALL) ||
        in_group(in, CS_GRP_BRANCH_RELATIVE))
        return;                                         /* targets: addresses */
    const cs_x86 *x = &in->detail->x86;
    for (uint8_t k = 0; k < x->op_count && k < sizeof x->operands / sizeof *x->operands; k++) {
        const cs_x86_op *o = &x->operands[k];
        if (o->type == X86_OP_IMM) {
            l->imm      = o->imm;
            l->imm_size = o->size >= 1 && o->size <= 8 ? o->size : 8;
        } else if (o->type == X86_OP_MEM && o->mem.disp && o->mem.base != X86_REG_RIP &&
                   (o->mem.base != X86_REG_INVALID || o->mem.index != X86_REG_INVALID)) {
            l->disp     = o->mem.disp;              /* [rbp - 0x18], not [0x404040] */
            l->has_disp = true;
        }
    }
}

void da_lines_free(DisLine *lines) {
    free(lines);
}

/* ─── linear sweep ─────────────────────────────────────────────── */

/* Decodes one contiguous file-backed chunk [addr, addr + size). Every
 * iteration consumes at least one byte, so the loop always ends. */
static bool sweep_chunk(csh h, cs_insn *in, LineVec *lv,
                        const uint8_t *code, size_t size, uint64_t addr) {
    while (size > 0) {
        DisLine *l = lv_push(lv);
        if (!l) return false;

        const uint8_t *c0 = code;
        size_t         s0 = size;
        uint64_t       a0 = addr;
        if (cs_disasm_iter(h, &code, &size, &addr, in) &&
            code > c0 && (size_t)(code - c0) <= s0) {
            line_insn(l, in);
        } else {
            /* undecodable or truncated by the end of the chunk: one byte */
            line_bad(l, a0, *c0);
            code = c0 + 1;
            size = s0 - 1;
            addr = a0 + 1;
        }
    }
    return true;
}

bool da_linear(const Disasm *d, uint64_t va, size_t n,
               DisLine **out, size_t *count, char *err, size_t esz) {
    if (out)   *out   = NULL;
    if (count) *count = 0;
    if (!d || !out || !count) { set_err(err, esz, "bad arguments"); return false; }
    if (!d->cs)               { set_err(err, esz, "capstone context not open"); return false; }
    if (n == 0)               { set_err(err, esz, "empty range"); return false; }
    if (n > DA_LINEAR_MAX) {
        set_err(err, esz, "range too long (%zu bytes, max %u)", n, DA_LINEAR_MAX);
        return false;
    }
    if (va > UINT64_MAX - n) {
        set_err(err, esz, "range 0x%llx + %zu overflows",
                (unsigned long long)va, n);
        return false;
    }
    size_t avail = 0;
    if (!elf_va_ptr(&d->elf, va, &avail) || avail == 0) {
        set_err(err, esz, "0x%llx is not file-backed", (unsigned long long)va);
        return false;
    }

    csh h = (csh)d->cs;
    cs_insn *in = cs_malloc(h);
    if (!in) { set_err(err, esz, "out of memory"); return false; }

    LineVec  lv   = { 0 };
    uint64_t cur  = va;
    size_t   left = n;
    bool     ok   = true;

    /* one chunk per mapping: an instruction never spans two of them */
    while (left > 0) {
        const uint8_t *p = elf_va_ptr(&d->elf, cur, &avail);
        if (!p || avail == 0) break;                 /* bss / gap: stop */
        size_t chunk = avail < left ? avail : left;
        if (!sweep_chunk(h, in, &lv, p, chunk, cur)) { ok = false; break; }
        cur  += chunk;
        left -= chunk;
    }
    cs_free(in, 1);

    if (!ok) {
        free(lv.v);
        set_err(err, esz, "out of memory");
        return false;
    }
    *out   = lv.v;
    *count = lv.n;
    return true;
}

/* ═══ recursive analysis ═══════════════════════════════════════════ */

#define X_PF_X           1
#define X_SHF_EXECINSTR  4
#define X_ET_EXEC        2
#define X_ET_DYN         3
#define X_SHT_NOBITS     8

#define FN_DEAD          0xff      /* FnSeed.kind: dropped, not output    */

#define INSN_MAX         15        /* longest x86 instruction            */
#define PROLOGUE_PASSES  4         /* gap scans, each one after the last  */
#define PROBE_INSNS      256       /* linear check of a prologue guess    */
#define JT_MAX_ENTRIES   4096u     /* entries read from one jump table    */
#define JT_SPAN          (256u << 10) /* farthest function start looked for
                                      around an indexed jmp, in bytes     */
#define COLD_LOOKUPS     4096u     /* .cold symbols without an owner
                                      matched to a function by name      */
#define COLD_GAP         16u       /* bytes skipped inside a .cold part   */
#define NORET_ROUNDS     8         /* no-return inference: rounds, and    */
#define NORET_STEPS      8u        /* expansions per instruction, total   */
#define JT_SCAN_MAX      (1u << 26) /* table bases compared, all reads of
                                      tables without a known size        */

/* one executable mapping: 1 bit per byte for "an instruction starts here",
 * "an instruction covers this byte", "the instruction just before
 * falls through to here" (not set after a call, which may not return,
 * nor after a nop, the padding that may follow such a call) and "a
 * function starts here" */
typedef struct {
    const ElfMap *m;
    uint8_t      *start, *cover, *fall, *fstart;
} XMap;

typedef struct {
    uint64_t addr;
    uint8_t  kind;
    uint32_t dp;                   /* FN_DATAPTR: index in An.dp, else
                                      UINT32_MAX                         */
} FnSeed;

/* code pointer read in data: the word at `slot` holds `target`. Runs of
 * consecutive slots (slot, slot + 8...) are tables. */
typedef struct {
    uint64_t slot, target;
    uint64_t run;                  /* first slot of its run               */
    uint32_t len;                  /* slots in the run, 1: a lone pointer */
    bool     raw;                  /* x86-32: a word of the file, no relocation */
} DPtr;

/* edge from an indexed jmp at `pc` to one of its cases */
typedef struct {
    uint64_t pc, va;
} JRef;

/* indexed jmp at `pc` reading the jump table at `base`, still to read:
 * 8-byte addresses (esz 8) or int32 offsets from `rb` (esz 4); `n`
 * entries when the bound of the index is known, else 0 */
typedef struct {
    uint64_t pc, base, rb;
    uint32_t n;
    uint8_t  esz;
} JTab;

/* one table read: its entries gave the edges je[e0 .. e0 + n) */
typedef struct {
    uint64_t base;
    size_t   e0, n;
    uint8_t  esz;
} JRead;

/* a PLT stub and what it jumps to: an import, or (x86-32) a function
 * of the file itself called through the PLT (JMP_SLOT on a defined
 * symbol), im NULL then */
typedef struct {
    uint64_t         stub;
    const ElfImport *im;
    const char      *name;         /* im->name, or the dynamic symbol's  */
} PltRef;

/* x86-32: one dynamic relocation (see x32_relocs) */
typedef struct {
    uint32_t va;                   /* r_offset                            */
    uint32_t val;                  /* RELATIVE: A; 32: S + A; GLOB_DAT,
                                      JMP_SLOT: S; GOTOFF: S + A (the
                                      address); PC32, PLT32: S + A - P
                                      (the field)                         */
    uint8_t  type;                 /* R386_*                              */
} X32Rel;

/* x86-32: registers holding the GOT base at the start of a path not
 * walked yet (see x32_hint) */
#define X32_MAX_SLOT 4
typedef struct {
    uint64_t va;                   /* 0: free entry                       */
    uint8_t  got;                  /* bit r: register r holds a->got      */
    uint8_t  nslot;                /* stack words holding a->got, at      */
    uint16_t slot[X32_MAX_SLOT];   /* these offsets from esp              */
} X32Hint;

typedef struct {
    Disasm   *d;
    csh       h;
    cs_insn  *in;
    bool      oom;
    bool      x32;                           /* ELF32 i386: 32-bit idioms
                                                (see disasm.h)            */

    XMap     *xm;  int nxm;

    uint64_t *q;   size_t qn, qcap;          /* work list (LIFO)          */

    uint64_t *cp;  size_t ncp, cpcap;        /* lea [rip+X] targets in code,
                                                checked once walk() is done */
    bool      xsec;                          /* usable executable sections */

    DPtr     *dp;  size_t ndp, dpcap;        /* code pointers in data,
                                                sorted by slot            */
    bool      dpraw;                         /* read from raw words, not
                                                relocations (may be ints) */
    uint64_t *jt;  size_t njt, jtcap;        /* X of `jmp [reg*8+X]`      */
    size_t    jtsorted;                      /* jt[0..jtsorted) sorted    */
    JTab     *jq;  size_t njq, jqcap;        /* jump tables still to read:
                                                size known               */
    JTab     *jqu; size_t njqu, jqucap;      /* size unknown, read last   */
    size_t    jtscan;                        /* spent by jt_next_base     */
    uint64_t *lt;  size_t nlt;               /* X of every byte pattern
                                                `lea r64, [rip+X]` in the
                                                code, X not code, sorted  */
    bool      ltdone;                        /* lt built                  */
    JRef     *je;  size_t nje, jecap;        /* jmp -> case, for owners   */
    JRead    *jr;  size_t njr, jrcap;        /* tables read               */
    size_t    jtent;                         /* entries read, all tables  */

    FnSeed   *fs;  size_t nfs, fscap;        /* functions found           */
    uint64_t *hk;  uint32_t *hv; size_t hcap; /* addr -> index in fs      */

    size_t    icap;                          /* capacity of d->ins        */
    PltRef   *plt; size_t nplt;              /* imports sorted by stub    */

    /* x86-32 only */
    X32Rel   *xr;  size_t nxr;               /* dynamic relocations, by va */
    uint64_t  got;                           /* GOT base (DT_PLTGOT, else
                                                .got.plt), 0 if unknown   */
    X32Hint  *xh;  size_t nxh, xhcap;        /* jump target -> GOT regs,
                                                hash table               */

    /* PE only: data the file declares (data directories), sorted; an
     * import table merged into .text is not code */
    uint64_t (*pd)[2]; size_t npd;           /* [lo, hi) VAs              */
    PePdata   rf;                            /* x64 .pdata, checked       */
    uint64_t *frag; size_t nfrag;            /* chained fragment starts,
                                                sorted (never functions)  */
    uint32_t rejected_insns;  /* see pe32_rejected_calls */
} An;

/* PE: va lies in a data directory (import descriptors, IAT, exports,
 * resources...) or is an import slot: data, never a function start */
static bool pe_data_at(const An *a, uint64_t va) {
    if (a->d->elf.fmt != ELF_FMT_PE) return false;
    size_t lo = 0, hi = a->npd;                  /* first lo > va */
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (a->pd[mid][0] <= va) lo = mid + 1; else hi = mid;
    }
    if (lo && va < a->pd[lo - 1][1]) return true;
    return elf_import_got(&a->d->elf, va) != NULL;
}

/* end of the data range holding va, va when none */
static uint64_t pe_data_end(const An *a, uint64_t va) {
    size_t lo = 0, hi = a->npd;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (a->pd[mid][0] <= va) lo = mid + 1; else hi = mid;
    }
    return lo && va < a->pd[lo - 1][1] ? a->pd[lo - 1][1] : va;
}

static inline bool bit_get(const uint8_t *b, uint64_t i) { return b[i >> 3] >> (i & 7) & 1; }
static inline void bit_set(uint8_t *b, uint64_t i)       { b[i >> 3] |= (uint8_t)(1u << (i & 7)); }

static XMap *xmap_of(An *a, uint64_t va) {
    for (int i = 0; i < a->nxm; i++) {
        const ElfMap *m = a->xm[i].m;
        if (va >= m->va && va - m->va < m->filesz) return &a->xm[i];
    }
    return NULL;
}

static bool is_decoded(An *a, uint64_t va) {
    XMap *x = xmap_of(a, va);
    return x && bit_get(x->start, va - x->m->va);
}

/* ─── no-return functions ───────────────────────────────────────── */

static bool name_noreturn(const char *n) {
    static const char *const nr[] = {
        "exit", "_exit", "_Exit", "quick_exit", "abort", "__stack_chk_fail",
        "__assert_fail", "__assert_perror_fail", "__fortify_fail",
        "__chk_fail", "err", "errx", "verr", "verrx", "error_at_line_noreturn",
        "longjmp", "_longjmp", "siglongjmp", "__longjmp_chk",
        "pthread_exit", "thrd_exit", "__libc_start_main",
        "__cxa_throw", "__cxa_rethrow", "__cxa_bad_cast", "__cxa_bad_typeid",
        "__cxa_throw_bad_array_new_length", "_Unwind_Resume",
        "__cxa_call_unexpected", "_ZSt9terminatev",
        "_ZSt17__throw_bad_allocv", "_ZSt20__throw_length_errorPKc",
        "_ZSt20__throw_out_of_rangePKc", "_ZSt24__throw_out_of_range_fmtPKcz",
        "_ZSt19__throw_logic_errorPKc",
        /* Windows */
        "ExitProcess", "ExitThread", "FatalExit", "FatalAppExitA", "FatalAppExitW",
        "RtlExitUserProcess", "RtlExitUserThread", "RaiseFailFastException",
        "_invalid_parameter_noinfo_noreturn", "__report_gsfailure", "_invoke_watson",
        "_CxxThrowException", "__std_terminate", "_amsg_exit", "__mingw_raise_matherr_noreturn",
    };
    if (!n) return false;
    for (size_t i = 0; i < sizeof nr / sizeof *nr; i++)
        if (!strcmp(n, nr[i])) return true;
    return false;
}

/* a .cold part split off by GCC: "f.cold" or "f.cold.N" (the code of f
 * on its unlikely paths, reached by jumps from f) */
static bool cold_name(const char *n) {
    if (!n || !*n) return false;
    for (const char *c = strstr(n + 1, ".cold"); c; c = strstr(c + 1, ".cold"))
        if (!c[5] || (c[5] == '.' && c[6] && strspn(c + 6, "0123456789") == strlen(c + 6)))
            return true;
    return false;
}

/* PLT stub starting at va (elf_import_plt is a linear scan, too slow
 * once per call instruction) */
static const PltRef *plt_import(const An *a, uint64_t va) {
    size_t lo = 0, hi = a->nplt;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (a->plt[mid].stub < va) lo = mid + 1; else hi = mid;
    }
    return (lo < a->nplt && a->plt[lo].stub == va) ? &a->plt[lo] : NULL;
}

/* name of what a call reaches: import by PLT stub or GOT slot, else a
 * function symbol */
static const char *callee_name(const An *a, uint64_t target, bool via_mem) {
    const ElfFile *ef = &a->d->elf;
    if (via_mem) {
        const ElfImport *im = elf_import_got(ef, target);
        return im ? im->name : NULL;
    }
    const PltRef *pr = plt_import(a, target);
    if (pr) return pr->name;
    const ElfSymbol *s = elf_symbol_at(ef, target);
    return (s && s->kind == ELF_SYM_FUNC) ? s->name : NULL;
}

/* ─── work list and function table ──────────────────────────────── */

/* room for one more element in v (n used of *cap): the new array, NULL
 * when out of memory (a->oom set, v untouched) */
static void *grow(An *a, void *v, size_t n, size_t *cap, size_t esz, size_t init) {
    if (n < *cap) return v;
    size_t nc = *cap ? *cap * 2 : init;
    void *nv = nc > SIZE_MAX / esz ? NULL : realloc(v, nc * esz);
    if (!nv) { a->oom = true; return NULL; }
    *cap = nc;
    return nv;
}

static void push(An *a, uint64_t va) {
    if (a->oom || !va || is_decoded(a, va) || !xmap_of(a, va)) return;
    if (a->qn >= DA_MAX_QUEUE) { a->d->capped = true; return; }
    if (a->qn == a->qcap) {
        size_t nc = a->qcap ? a->qcap * 2 : 1024;
        uint64_t *n = realloc(a->q, nc * sizeof *n);
        if (!n) { a->oom = true; return; }
        a->q = n; a->qcap = nc;
    }
    a->q[a->qn++] = va;
}

static size_t hslot(const An *a, uint64_t va) {
    uint64_t x = va * 0x9e3779b97f4a7c15ull;
    size_t i = (size_t)(x >> 17) & (a->hcap - 1);
    while (a->hk[i] && a->hk[i] != va) i = (i + 1) & (a->hcap - 1);
    return i;
}

static bool hgrow(An *a) {
    size_t nc = a->hcap ? a->hcap * 2 : 1024;
    uint64_t *ok = a->hk; uint32_t *ov = a->hv; size_t oc = a->hcap;
    a->hk = calloc(nc, sizeof *a->hk);
    a->hv = calloc(nc, sizeof *a->hv);
    if (!a->hk || !a->hv) {
        free(a->hk); free(a->hv);
        a->hk = ok; a->hv = ov;
        return false;
    }
    a->hcap = nc;
    for (size_t i = 0; i < oc; i++)
        if (ok[i]) { size_t j = hslot(a, ok[i]); a->hk[j] = ok[i]; a->hv[j] = ov[i]; }
    free(ok); free(ov);
    return true;
}

/* how sure a kind is, best first (FN_SEH / FN_GUARD were added after
 * FN_PROLOGUE in the enum, they rank after FN_PDATA) */
static unsigned kind_rank(uint8_t k) {
    switch (k) {
    case FN_SEH:   return 2 * FN_PDATA + 1;
    case FN_GUARD: return 2 * FN_PDATA + 2;
    default:       return k <= FN_PDATA ? 2u * k : 2u * k + 3;
    }
}

/* PE x64: [begin, end) of the .pdata function entry starting at va */
static const PeRtFunc *pdata_func(const An *a, uint64_t va) {
    const ElfFile *ef = &a->d->elf;
    uint32_t rva;
    if (!a->rf.n || !pe_va_to_rva(ef, va, &rva)) return NULL;
    size_t lo = 0, hi = a->rf.n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (a->rf.e[mid].begin < rva) lo = mid + 1; else hi = mid;
    }
    return lo < a->rf.n && a->rf.e[lo].begin == rva && !(a->rf.e[lo].flags & PE_RF_FRAG) ? &a->rf.e[lo] : NULL;
}

/* PE x64: va lies in a .pdata range without being the start of a
 * function entry (inside a function, or in a chained fragment) */
static bool pdata_inside(const An *a, uint64_t va) {
    uint32_t rva;
    if (!pe_va_to_rva(&a->d->elf, va, &rva)) return false;
    size_t lo = 0, hi = a->rf.n;                 /* first begin > rva */
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (a->rf.e[mid].begin <= rva) lo = mid + 1; else hi = mid;
    }
    if (!lo) return false;
    const PeRtFunc *r = &a->rf.e[lo - 1];
    return rva < r->end && (rva != r->begin || (r->flags & PE_RF_FRAG));
}

/* registers a function start (or improves its kind) and queues it. PE
 * x64: an address inside a .pdata range other than the start of a
 * function entry (a chained fragment, the middle of a function: catch
 * continuations taken by lea) is never a function guessed (call, code
 * pointer, prologue): it is only queued, as code */
static void add_func(An *a, uint64_t va, uint8_t kind) {
    if (a->oom || !va || !xmap_of(a, va)) return;
    if (a->hcap) {
        size_t i = hslot(a, va);
        if (a->hk[i]) {
            FnSeed *f = &a->fs[a->hv[i]];
            if (kind_rank(kind) < kind_rank(f->kind)) f->kind = kind;
            return;
        }
    }
    if (a->rf.n && kind_rank(kind) >= kind_rank(FN_CALL) && pdata_inside(a, va)) {
        push(a, va);
        return;
    }
    if (a->nfs >= DA_MAX_FUNCS) { a->d->capped = true; return; }
    if ((a->nfs + 1) * 2 > a->hcap && !hgrow(a)) { a->oom = true; return; }
    if (a->nfs == a->fscap) {
        size_t nc = a->fscap ? a->fscap * 2 : 256;
        FnSeed *n = realloc(a->fs, nc * sizeof *n);
        if (!n) { a->oom = true; return; }
        a->fs = n; a->fscap = nc;
    }
    size_t i = hslot(a, va);
    a->hk[i] = va;
    a->hv[i] = (uint32_t)a->nfs;
    a->fs[a->nfs++] = (FnSeed){ va, kind, UINT32_MAX };
    XMap *x = xmap_of(a, va);
    bit_set(x->fstart, va - x->m->va);
    push(a, va);
}

static DisInsn *ins_push(An *a) {
    Disasm *d = a->d;
    if (d->nins == a->icap) {
        size_t nc = a->icap ? a->icap * 2 : 4096;
        if (nc > DA_MAX_INSNS) nc = DA_MAX_INSNS;
        DisInsn *n = realloc(d->ins, nc * sizeof *n);
        if (!n) { a->oom = true; return NULL; }
        d->ins = n; a->icap = nc;
    }
    return &d->ins[d->nins++];
}

/* ─── x86-32: dynamic relocations ───────────────────────────────── */

/* i386 relocation types (r_info & 0xff) */
#define R386_32         1
#define R386_PC32       2
#define R386_PLT32      4
#define R386_GLOB_DAT   6
#define R386_JMP_SLOT   7
#define R386_RELATIVE   8
#define R386_GOTOFF     9
#define R386_GOTPC     10

#define X_PT_DYNAMIC    2
#define X_SHT_REL       9
#define X_SHF_ALLOC     2
#define X32_DYN_MAX     4096u      /* entries read from the dynamic table */

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* the DT_* entries the analysis needs (elfload reads them but does not
 * keep them in the ElfFile) */
typedef struct {
    uint64_t rel, relsz, jmprel, pltrelsz, pltrel, symtab, strtab, pltgot;
} X32Dyn;

static void x32_dyn(const ElfFile *ef, X32Dyn *dy) {
    memset(dy, 0, sizeof *dy);
    for (int i = 0; i < ef->nseg; i++) {
        const ElfSegment *sg = &ef->seg[i];
        if (sg->type != X_PT_DYNAMIC) continue;
        if (sg->off > ef->size || sg->filesz > ef->size - sg->off) return;
        const uint8_t *p = ef->data + sg->off;
        for (uint64_t k = 0; k + 8 <= sg->filesz && k / 8 < X32_DYN_MAX; k += 8) {
            uint32_t tag = rd32(p + k), val = rd32(p + k + 4);
            if (!tag) break;
            switch (tag) {
                case 17: dy->rel = val; break;          /* DT_REL      */
                case 18: dy->relsz = val; break;        /* DT_RELSZ    */
                case 23: dy->jmprel = val; break;       /* DT_JMPREL   */
                case  2: dy->pltrelsz = val; break;     /* DT_PLTRELSZ */
                case 20: dy->pltrel = val; break;       /* DT_PLTREL   */
                case  6: dy->symtab = val; break;       /* DT_SYMTAB   */
                case  5: dy->strtab = val; break;       /* DT_STRTAB   */
                case  3: dy->pltgot = val; break;       /* DT_PLTGOT   */
                default: break;
            }
        }
        return;
    }
}

/* value and definedness of dynamic symbol idx of the table at p (nsym
 * entries of 16 bytes, Elf32_Sym): st_value at 4, st_shndx at 14 */
static bool x32_sym(const uint8_t *p, uint64_t nsym, uint32_t idx, uint32_t *val) {
    if (!p || idx >= nsym) return false;
    const uint8_t *e = p + (uint64_t)idx * 16;
    if ((uint16_t)(e[14] | e[15] << 8) == 0) return false;    /* SHN_UNDEF: an import */
    *val = rd32(e + 4);
    return true;
}

static int cmp_xrel(const void *x, const void *y) {
    const X32Rel *p = x, *q = y;
    if (p->va != q->va) return p->va < q->va ? -1 : 1;
    if (p->type != q->type) return p->type < q->type ? -1 : 1;
    return p->val < q->val ? -1 : p->val > q->val;
}

static void x32_rel_add(An *a, size_t *cap, uint32_t va, uint32_t val, uint8_t type) {
    if (a->oom) return;
    if (a->nxr >= DA_MAX_QUEUE) { a->d->capped = true; return; }
    X32Rel *n = grow(a, a->xr, a->nxr, cap, sizeof *n, 256);
    if (!n) return;
    a->xr = n;
    a->xr[a->nxr++] = (X32Rel){ va, val, type };
}

/* One Elf32_Rel table (8-byte entries, the addend A is the word stored
 * at r_offset): n entries at p, symbols at sym (nsym). Entries whose
 * value is not known here are left out: imports (undefined S, elfload
 * lists them), GOTPC (the GOT base, not an address the analysis needs),
 * any other type, r_info naming a symbol past the table, r_offset whose
 * word is not in the file. */
static void x32_rel_table(An *a, size_t *cap, const uint8_t *p, uint64_t n,
                          const uint8_t *sym, uint64_t nsym) {
    const ElfFile *ef = &a->d->elf;
    for (uint64_t i = 0; i < n && !a->oom && !a->d->capped; i++) {
        uint32_t off = rd32(p + i * 8), info = rd32(p + i * 8 + 4);
        uint8_t  type = (uint8_t)info;
        uint32_t si = info >> 8, S = 0, A = 0;
        if (type != R386_32 && type != R386_PC32 && type != R386_PLT32 && type != R386_GLOB_DAT &&
            type != R386_JMP_SLOT && type != R386_RELATIVE && type != R386_GOTOFF)
            continue;
        if (type != R386_RELATIVE && (si || type != R386_32) && !x32_sym(sym, nsym, si, &S))
            continue;
        if (type != R386_GLOB_DAT && type != R386_JMP_SLOT) {
            size_t avail = 0;
            const uint8_t *w = elf_va_ptr(ef, off, &avail);
            if (!w || avail < 4) continue;
            A = rd32(w);
        }
        uint32_t val = type == R386_RELATIVE ? A
                     : type == R386_GLOB_DAT || type == R386_JMP_SLOT ? S
                     : type == R386_PC32 || type == R386_PLT32 ? S + A - off
                     : S + A;                                  /* 32, GOTOFF */
        x32_rel_add(a, cap, off, val, type);
    }
}

/* table [va, va + size) given by the dynamic table, symbols at symtab */
static void x32_rel_dyn(An *a, size_t *cap, uint64_t va, uint64_t size,
                        const uint8_t *sym, uint64_t nsym) {
    size_t avail = 0;
    const uint8_t *p = va && size >= 8 ? elf_va_ptr(&a->d->elf, va, &avail) : NULL;
    if (!p) return;
    uint64_t n = size / 8;
    if (n > avail / 8) n = avail / 8;             /* truncated: what is in the file */
    x32_rel_table(a, cap, p, n, sym, nsym);
}

/* Reads the i386 dynamic relocations into a->xr, sorted by va: the
 * allocated SHT_REL sections (.rel.dyn, .rel.plt), their symbols from
 * their sh_link section; without such a section, DT_REL and DT_JMPREL
 * (when DT_PLTREL says REL), symbols at DT_SYMTAB (up to DT_STRTAB when
 * it follows, else to the end of the mapping). The RELATIVE words
 * elfload computed (RELA, RELR tables too) are added. Also sets a->got.
 * The tables are bounded by the file and DA_MAX_QUEUE entries. */
static void x32_relocs(An *a) {
    const ElfFile *ef = &a->d->elf;
    X32Dyn dy;
    size_t cap = 0;
    bool secs = false;
    x32_dyn(ef, &dy);
    a->got = dy.pltgot;
    if (!a->got) {
        const ElfSection *g = elf_section_named(ef, ".got.plt");
        if (g && !g->bad) a->got = g->addr;
    }
    for (int i = 0; i < ef->nsec; i++) {
        const ElfSection *s = &ef->sec[i];
        if (s->type != X_SHT_REL || !(s->flags & X_SHF_ALLOC) || s->bad) continue;
        if (s->off > ef->size || s->size > ef->size - s->off) continue;
        secs = true;
        const uint8_t *sym = NULL;
        uint64_t nsym = 0;
        if (s->link < (uint32_t)ef->nsec) {
            const ElfSection *y = &ef->sec[s->link];
            if (!y->bad && y->off <= ef->size && y->size <= ef->size - y->off) {
                sym = ef->data + y->off;
                nsym = y->size / 16;
            }
        }
        x32_rel_table(a, &cap, ef->data + s->off, s->size / 8, sym, nsym);
    }
    if (!secs) {
        size_t avail = 0;
        const uint8_t *sym = dy.symtab ? elf_va_ptr(ef, dy.symtab, &avail) : NULL;
        uint64_t nsym = avail / 16;
        if (sym && dy.strtab > dy.symtab && (dy.strtab - dy.symtab) / 16 < nsym)
            nsym = (dy.strtab - dy.symtab) / 16;
        x32_rel_dyn(a, &cap, dy.rel, dy.relsz, sym, nsym);
        if (!dy.pltrel || dy.pltrel == 17)
            x32_rel_dyn(a, &cap, dy.jmprel, dy.pltrelsz, sym, nsym);
    }
    for (int i = 0; i < ef->nrel && !a->oom && !a->d->capped; i++)
        if (ef->rel[i].va <= UINT32_MAX)
            x32_rel_add(a, &cap, (uint32_t)ef->rel[i].va, (uint32_t)ef->rel[i].addend, R386_RELATIVE);
    if (!a->nxr) return;
    qsort(a->xr, a->nxr, sizeof *a->xr, cmp_xrel);
    size_t k = 0;                                  /* one per va */
    for (size_t i = 0; i < a->nxr; i++)
        if (!k || a->xr[i].va != a->xr[k - 1].va) a->xr[k++] = a->xr[i];
    a->nxr = k;
}

static const X32Rel *x32_rel_at(const An *a, uint64_t va) {
    size_t lo = 0, hi = a->nxr;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (a->xr[mid].va < va) lo = mid + 1; else hi = mid;
    }
    return lo < a->nxr && a->xr[lo].va == va ? &a->xr[lo] : NULL;
}

/* a relocation whose value is the address the word at va will hold */
static bool x32_rel_word(uint8_t t) {
    return t == R386_RELATIVE || t == R386_32 || t == R386_GLOB_DAT || t == R386_JMP_SLOT;
}

/* The 4-byte word at va as the program sees it: a relocation's value
 * (*reloc true: it is an address), else the bytes of the file. */
static bool x32_load(const An *a, uint64_t va, uint64_t *out, bool *reloc) {
    const X32Rel *r = x32_rel_at(a, va);
    *reloc = r && x32_rel_word(r->type);
    if (*reloc) { *out = r->val; return true; }
    return elf_read_ptr(&a->d->elf, va, out);
}

/* ─── x86-32: PLT stubs ─────────────────────────────────────────── */

/* Stub of each R_386_JMP_SLOT import elfload left without one (it maps
 * the stubs from the .plt* sections only): a `jmp [slot]` (ff 25 abs32,
 * non-PIC) or `jmp [ebx + slot - GOT]` (ff a3, PIC, GOT = a->got),
 * optionally after endbr32 (f3 0f 1e fb, .plt.sec) or bnd (f2), that
 * shows it is a stub: a lazy entry `push imm32; jmp rel32` follows it
 * or the slot's word (the lazy-binding address) is the stub + 6; with
 * endbr32, the stub is 16-aligned and the slot's word points to an
 * `endbr32; push` lazy entry. Looked for in the .plt* sections, or in
 * every executable mapping without a section table; the first stub
 * found for a slot wins. Bounded by the executable bytes. */
/* name of the function of the file a JMP_SLOT on a defined symbol
 * points to: a dynamic symbol at that address, else any function symbol */
static const char *x32_slot_name(const ElfFile *ef, uint64_t va) {
    const ElfSymbol *s = elf_symbol_at(ef, va), *best = NULL;
    for (; s && s < ef->sym + ef->nsym && s->value == va; s++) {
        if (s->kind != ELF_SYM_FUNC || !s->name || !*s->name) continue;
        if (s->dynamic) return s->name;
        if (!best) best = s;
    }
    return best ? best->name : NULL;
}

static void x32_plt(An *a, size_t *cap) {
    const ElfFile *ef = &a->d->elf;
    /* done[0 .. nimp): imports, done[nimp + i]: a->xr[i] (defined) */
    size_t ni = (size_t)(ef->nimp > 0 ? ef->nimp : 0);
    bool *done = calloc(ni + a->nxr + 1, 1);
    if (!done) { a->oom = true; return; }
    size_t left = 0;
    for (size_t i = 0; i < ni; i++) {
        done[i] = ef->imp[i].plt || ef->imp[i].rtype != R386_JMP_SLOT;
        left += !done[i];
    }
    for (size_t i = 0; i < a->nxr; i++) {
        done[ni + i] = a->xr[i].type != R386_JMP_SLOT || elf_import_got(ef, a->xr[i].va) ||
                       !x32_slot_name(ef, a->xr[i].val);
        left += !done[ni + i];
    }
    for (int k = 0; k < (ef->nsec ? ef->nsec : a->nxm) && left && !a->oom; k++) {
        uint64_t va, n;
        const uint8_t *p;
        if (ef->nsec) {
            const ElfSection *s = &ef->sec[k];
            if (strncmp(s->name, ".plt", 4) || s->bad || s->type == X_SHT_NOBITS ||
                s->off > ef->size || s->size > ef->size - s->off || !elf_va_exec(ef, s->addr))
                continue;
            va = s->addr; n = s->size; p = ef->data + s->off;
        } else {
            const ElfMap *m = a->xm[k].m;
            if (m->off > ef->size || m->filesz > ef->size - m->off) continue;
            va = m->va; n = m->filesz; p = ef->data + m->off;
        }
        for (uint64_t o = 0; n >= 6 && o <= n - 6 && left; o++) {
            uint64_t j = o;
            bool ibt = n - o >= 10 && p[o] == 0xf3 && p[o + 1] == 0x0f && p[o + 2] == 0x1e && p[o + 3] == 0xfb;
            if (ibt) j += 4;
            if (j < n && p[j] == 0xf2) j++;
            if (n - j < 6 || p[j] != 0xff || (p[j + 1] != 0x25 && p[j + 1] != 0xa3)) continue;
            uint32_t disp = rd32(p + j + 2);
            if (p[j + 1] == 0xa3 && !a->got) continue;
            uint64_t slot = p[j + 1] == 0x25 ? disp : (uint32_t)(a->got + disp);
            const ElfImport *im = elf_import_got(ef, slot);
            const X32Rel    *xr = im ? NULL : x32_rel_at(a, slot);
            size_t id = im ? (size_t)(im - ef->imp) : xr ? ni + (size_t)(xr - a->xr) : 0;
            if ((!im && !xr) || done[id]) continue;
            uint64_t stub = va + o, lazy = 0;
            size_t la = 0;
            const uint8_t *w = elf_va_ptr(ef, slot, &la);
            if (w && la >= 4) lazy = rd32(w);
            const uint8_t *lz = lazy ? elf_va_ptr(ef, lazy, &la) : NULL;
            bool ok;
            if (ibt) ok = !(stub & 15) && lz && la >= 5 && lz[0] == 0xf3 && lz[1] == 0x0f &&
                          lz[2] == 0x1e && lz[3] == 0xfb && lz[4] == 0x68;
            else     ok = (n - j >= 16 && p[j + 6] == 0x68 && p[j + 11] == 0xe9) ||
                          (lazy == stub + 6 && lz && la >= 1 && lz[0] == 0x68);
            if (!ok) continue;
            PltRef *r = grow(a, a->plt, a->nplt, cap, sizeof *r, 64);
            if (!r) break;
            a->plt = r;
            a->plt[a->nplt++] = (PltRef){ stub, im, im ? im->name : x32_slot_name(ef, xr->val) };
            done[id] = true;
            left--;
            o = j + 5;
        }
    }
    free(done);
}

/* ─── decoding one instruction ──────────────────────────────────── */

enum { DEC_OK, DEC_KNOWN, DEC_OUT, DEC_BAD, DEC_OVERLAP };

/* what a decoded instruction does to the control flow */
typedef struct {
    uint64_t target;     /* see DisInsn.target                            */
    uint8_t  len, flags;
    bool     direct;     /* target is a branch / call destination         */
    bool     end;        /* the path stops after it                       */
    bool     lea;        /* lea reg, [rip+X]: target = X                  */
    bool     nop;        /* nop (padding after a call that may not return) */
    int8_t   rdi;        /* +1 loads a code pointer in rdi, -1 clobbers it */
} Step;

static bool reg_is_rdi(unsigned r) {
    return r == X86_REG_RDI || r == X86_REG_EDI || r == X86_REG_DI || r == X86_REG_DIL;
}

static void classify(const An *a, const cs_insn *in, Step *st) {
    const cs_x86 *x = &in->detail->x86;
    uint64_t next = in->address + in->size;
    memset(st, 0, sizeof *st);
    st->len = (uint8_t)in->size;
    st->nop = in->id == X86_INS_NOP;

    /* rip-relative operand: data / slot address */
    for (int k = 0; k < x->op_count; k++) {
        const cs_x86_op *op = &x->operands[k];
        if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP &&
            op->mem.index == X86_REG_INVALID) {
            st->target = next + (uint64_t)op->mem.disp;
            st->lea    = in->id == X86_INS_LEA;
            break;
        }
    }

    bool call = cs_insn_group(a->h, in, CS_GRP_CALL);
    bool jump = cs_insn_group(a->h, in, CS_GRP_JUMP);
    if (call || jump) {
        if (x->op_count == 1 && x->operands[0].type == X86_OP_IMM) {
            st->target = (uint64_t)x->operands[0].imm;
            st->direct = true;
            if (a->x32) {
                st->target &= 0xffffffffu;           /* eip wraps at 4 GiB */
                /* text relocation (non-PIC shared object): an R_386_PC32 /
                 * PLT32 on the rel32 of a call / jmp / jcc to a symbol
                 * defined here gives its real target, S + A + 4 */
                const X32Rel *r = a->nxr && in->size >= 5 ? x32_rel_at(a, next - 4) : NULL;
                if (r && (r->type == R386_PC32 || r->type == R386_PLT32) &&
                    (in->bytes[in->size - 5] == 0xe8 || in->bytes[in->size - 5] == 0xe9 ||
                     (in->size >= 6 && in->bytes[in->size - 6] == 0x0f && (in->bytes[in->size - 5] & 0xf0) == 0x80)))
                    st->target = (uint32_t)(next + r->val);
                /* i386 object file: an unrelocated rel32 holds its implicit
                 * addend (-4), the target falls inside the branch itself:
                 * no target, neither followed nor indirect */
                if (st->target - in->address < in->size) { st->target = 0; st->direct = false; }
            }
        } else {
            st->flags |= DI_INDIRECT;           /* target: GOT slot or 0 */
        }
        if (call) {
            st->flags |= DI_CALL;
            st->rdi = -1;                       /* caller-saved */
        } else if (in->id == X86_INS_JMP || in->id == X86_INS_LJMP) {
            st->flags |= DI_JUMP;
            st->end = true;
        } else {
            st->flags |= DI_COND;
        }
        return;
    }
    if (cs_insn_group(a->h, in, CS_GRP_RET) || cs_insn_group(a->h, in, CS_GRP_IRET)) {
        st->flags |= DI_RET;
        st->end = true;
        return;
    }
    switch (in->id) {
        case X86_INS_HLT: case X86_INS_UD0: case X86_INS_UD1:
        case X86_INS_UD2: case X86_INS_INT3:
            st->flags |= DI_STOP;
            st->end = true;
            return;
        default: break;
    }

    /* writes to rdi: `lea rdi, [rip+X]` / `mov rdi, imm` give a code
     * pointer (main for __libc_start_main), anything else forgets it.
     * x86-64 only: i386 passes main on the stack, edi means nothing. */
    if (!a->x32 && x->op_count >= 1 && x->operands[0].type == X86_OP_REG &&
        reg_is_rdi(x->operands[0].reg) && (x->operands[0].access & CS_AC_WRITE)) {
        st->rdi = -1;
        if (in->id == X86_INS_LEA && st->target) {
            st->rdi = 1;
        } else if (in->id == X86_INS_MOV && x->op_count == 2 &&
                   x->operands[1].type == X86_OP_IMM &&
                   elf_va_exec(&a->d->elf, (uint64_t)x->operands[1].imm)) {
            st->target = (uint64_t)x->operands[1].imm;
            st->rdi = 1;
        }
    }
}

/* Decodes the instruction at pc without recording it. Never reads past
 * the executable mapping that holds pc. */
static int decode_at(An *a, uint64_t pc, XMap **xo, Step *st) {
    XMap *x = xmap_of(a, pc);
    if (!x) return DEC_OUT;
    const ElfFile *ef = &a->d->elf;
    uint64_t o = pc - x->m->va;
    if (bit_get(x->start, o)) return DEC_KNOWN;
    if (bit_get(x->cover, o)) return DEC_OVERLAP;     /* inside an instruction */

    uint64_t foff = x->m->off + o;
    if (x->m->off > ef->size || o >= ef->size - x->m->off) return DEC_OUT;
    uint64_t left = x->m->filesz - o;
    if (left > ef->size - foff) left = ef->size - foff;
    size_t n = left < INSN_MAX ? (size_t)left : INSN_MAX;

    const uint8_t *c  = ef->data + foff;
    size_t         sz = n;
    uint64_t       ad = pc;
    if (!cs_disasm_iter(a->h, &c, &sz, &ad, a->in)) return DEC_BAD;
    size_t len = a->in->size;
    if (len == 0 || len > n) return DEC_BAD;
    for (size_t k = 1; k < len; k++)
        if (bit_get(x->cover, o + k)) return DEC_OVERLAP;   /* runs into code */

    classify(a, a->in, st);
    *xo = x;
    return DEC_OK;
}

static void commit(An *a, XMap *x, uint64_t pc, const Step *st) {
    DisInsn *n = ins_push(a);
    if (!n) return;
    uint64_t o = pc - x->m->va;
    bit_set(x->start, o);
    for (unsigned k = 0; k < st->len; k++) bit_set(x->cover, o + k);
    if (!st->end && !(st->flags & DI_CALL) && !st->nop && o + st->len < x->m->filesz)
        bit_set(x->fall, o + st->len);
    n->addr   = pc;
    n->target = st->target;
    n->func   = DA_NOFUNC;
    n->len    = st->len;
    n->flags  = st->flags;
}

/* ─── recursive descent ─────────────────────────────────────────── */

/* lea target in an executable mapping, checked by explore. Each
 * instruction is decoded once, so this is bounded by DA_MAX_INSNS; the
 * list itself counts as pending work (DA_MAX_QUEUE). */
static void cp_push(An *a, uint64_t va) {
    if (a->oom || !va || !xmap_of(a, va)) return;
    if (a->ncp >= DA_MAX_QUEUE) { a->d->capped = true; return; }
    if (a->ncp == a->cpcap) {
        size_t nc = a->cpcap ? a->cpcap * 2 : 256;
        uint64_t *n = realloc(a->cp, nc * sizeof *n);
        if (!n) { a->oom = true; return; }
        a->cp = n; a->cpcap = nc;
    }
    a->cp[a->ncp++] = va;
}

/* base of an indexed jmp table, for the data pointers (bounded like cp) */
static void jt_push(An *a, uint64_t va) {
    if (a->oom) return;
    if (a->njt >= DA_MAX_QUEUE) { a->d->capped = true; return; }
    if (a->njt == a->jtcap) {
        size_t nc = a->jtcap ? a->jtcap * 2 : 64;
        uint64_t *n = realloc(a->jt, nc * sizeof *n);
        if (!n) { a->oom = true; return; }
        a->jt = n; a->jtcap = nc;
    }
    a->jt[a->njt++] = va;
}

/* indexed jmp at pc reading a table: read once the work list is empty
 * (bounded like cp: one per decoded jmp) */
static void jq_push(An *a, const JTab *t) {
    if (a->oom) return;
    if (a->njq + a->njqu >= DA_MAX_QUEUE) { a->d->capped = true; return; }
    if (t->n) {
        JTab *n = grow(a, a->jq, a->njq, &a->jqcap, sizeof *n, 64);
        if (!n) return;
        a->jq = n;
        a->jq[a->njq++] = *t;
    } else {
        JTab *n = grow(a, a->jqu, a->njqu, &a->jqucap, sizeof *n, 64);
        if (!n) return;
        a->jqu = n;
        a->jqu[a->njqu++] = *t;
    }
}

/* Switch tables read along one path, T from `lea r, [rip+T]` / `mov r, T`
 * (or an absolute T):
 *  - absolute: `jmp [r + i*8]`, or `mov r2, [r + i*8]; ...; jmp r2`;
 *  - relative (PIE): `movsxd r2, dword [r + i*4]; add r2, r; jmp r2`
 *    (or `add r, r2` / `lea r3, [r + r2]`), each case at T + entry.
 * The number of entries is known when the index i was bounded on the way
 * by `cmp i, imm; ja` (imm + 1 entries) or `jae` (imm), or by
 * `and i, imm` (imm + 1), and then only moved by `mov / movzx / movsxd`
 * between registers. Only the 16 general registers are followed, from
 * the start of the path; any other write to one of them (first operand),
 * or a call, forgets what it held. */
enum { RT_NONE, RT_ADDR, RT_ENT, RT_REL, RT_CASE };
typedef struct {
    uint64_t v[16];                /* RT_ADDR: address T; else table read */
    uint64_t rb[16];               /* RT_REL / RT_CASE: what the entries
                                      are relative to                     */
    uint32_t nb[16];               /* entries of that table, 0 unknown    */
    uint32_t bound[16];            /* index below this, 0 unknown         */
    uint8_t  k[16];                /* RT_ADDR: holds T; RT_ENT: an 8-byte
                                      entry of table v; RT_REL: an int32
                                      entry of table v, sign-extended;
                                      RT_CASE: rb + such an entry         */
    int      creg;                 /* `cmp creg, cimm` just before, or -1 */
    uint32_t cimm;
} RegTrack;

static int gpr(unsigned r) {
    switch (r) {
        case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL: case X86_REG_AH: return 0;
        case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL: case X86_REG_CH: return 1;
        case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL: case X86_REG_DH: return 2;
        case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL: case X86_REG_BH: return 3;
        case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL: return 4;
        case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL: return 5;
        case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL: return 6;
        case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL: return 7;
        case X86_REG_R8:  case X86_REG_R8D:  case X86_REG_R8W:  case X86_REG_R8B:  return 8;
        case X86_REG_R9:  case X86_REG_R9D:  case X86_REG_R9W:  case X86_REG_R9B:  return 9;
        case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B: return 10;
        case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B: return 11;
        case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B: return 12;
        case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B: return 13;
        case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B: return 14;
        case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B: return 15;
        default: return -1;
    }
}

static void rt_reset(RegTrack *rt) {
    memset(rt, 0, sizeof *rt);
    rt->creg = -1;
}

/* table read by [base + index*scale + disp] (scale = entry size), 0 when
 * unknown; *nb: its entries when the index is bounded, *rb: the address
 * held by base */
static uint64_t table_of(const RegTrack *rt, const cs_x86_op *op, unsigned scale,
                         uint32_t *nb, uint64_t *rb) {
    if (op->type != X86_OP_MEM || op->mem.index == X86_REG_INVALID ||
        (unsigned)op->mem.scale != scale || op->mem.segment != X86_REG_INVALID || op->size != scale)
        return 0;
    int i = gpr(op->mem.index);
    *nb = i >= 0 ? rt->bound[i] : 0;
    *rb = 0;
    if (op->mem.base == X86_REG_INVALID) return op->mem.disp > 0 ? (uint64_t)op->mem.disp : 0;
    int b = gpr(op->mem.base);
    if (b < 0 || rt->k[b] != RT_ADDR || !rt->v[b]) return 0;
    *rb = rt->v[b];
    return rt->v[b] + (uint64_t)op->mem.disp;
}

/* register r := a relative entry held by e plus the address held by b,
 * when b holds the address the entries are relative to */
static bool rt_case(RegTrack *rt, int r, int e, int b) {
    if (e < 0 || b < 0 || rt->k[e] != RT_REL || rt->k[b] != RT_ADDR || rt->v[b] != rt->rb[e])
        return false;
    rt->v[r] = rt->v[e]; rt->rb[r] = rt->rb[e]; rt->nb[r] = rt->nb[e];
    rt->k[r] = RT_CASE;
    return true;
}

/* PE32 (MSVC), and non-PIE ELF32: `jmp dword ptr [reg*4 + X]`, X a switch table
 * of absolute case addresses (HIGHLOW relocations in PE, plain words in ELF),
 * often inside .text in PE: its entries are labels of the function, not code
 * pointers */
static void pe32_switch(An *a, const cs_insn *in) {
    const cs_x86 *x = &in->detail->x86;
    if (in->id != X86_INS_JMP || x->op_count != 1) return;
    const cs_x86_op *op = &x->operands[0];
    if (op->type != X86_OP_MEM || op->mem.base != X86_REG_INVALID || op->mem.index == X86_REG_INVALID ||
        op->mem.scale != 4 || op->mem.segment != X86_REG_INVALID || op->mem.disp <= 0) return;
    jt_push(a, (uint64_t)(uint32_t)op->mem.disp);
    /* its displacement is a relocated word too: not a pointer (see dataptr_ok) */
    if (in->size >= 4) jt_push(a, in->address + in->size - 4);
}

static void track(An *a, RegTrack *rt, const cs_insn *in, const Step *st) {
    const cs_x86 *x = &in->detail->x86;
    int      creg = rt->creg;
    uint32_t cimm = rt->cimm;
    rt->creg = -1;
    if (st->flags & DI_CALL) { rt_reset(rt); return; }
    if (in->id == X86_INS_JMP && x->op_count == 1) {
        const cs_x86_op *op = &x->operands[0];
        int r = op->type == X86_OP_REG ? gpr(op->reg) : -1;
        JTab t = { in->address, 0, 0, 0, 8 };
        if (r >= 0 && rt->k[r] == RT_ENT) {
            t.base = rt->v[r]; t.n = rt->nb[r];
        } else if (r >= 0 && rt->k[r] == RT_CASE) {
            t.base = rt->v[r]; t.rb = rt->rb[r]; t.n = rt->nb[r]; t.esz = 4;
        } else if (r < 0) {
            t.base = table_of(rt, op, 8, &t.n, &t.rb);
            t.rb = 0;
        }
        if (t.base) {
            if (t.esz == 8) jt_push(a, t.base);   /* may hold code pointers */
            jq_push(a, &t);
        }
        return;
    }
    if (st->flags & DI_COND) {                   /* cmp i, imm; ja / jae */
        if (creg >= 0 && (in->id == X86_INS_JA || in->id == X86_INS_JAE))
            rt->bound[creg] = in->id == X86_INS_JA ? cimm + 1 : cimm;
        return;
    }
    if (in->id == X86_INS_CMP && x->op_count == 2 && x->operands[0].type == X86_OP_REG &&
        x->operands[1].type == X86_OP_IMM &&
        x->operands[1].imm >= 0 && x->operands[1].imm < (int64_t)JT_MAX_ENTRIES) {
        rt->creg = gpr(x->operands[0].reg);
        rt->cimm = (uint32_t)x->operands[1].imm;
        return;
    }
    if (x->op_count < 1 || x->operands[0].type != X86_OP_REG ||
        !(x->operands[0].access & CS_AC_WRITE))
        return;
    int r = gpr(x->operands[0].reg);
    if (r < 0) return;
    const cs_x86_op *o1 = x->op_count == 2 ? &x->operands[1] : NULL;
    int s = o1 && o1->type == X86_OP_REG ? gpr(o1->reg) : -1;
    bool wide = x->operands[0].size == 8;

    /* the bound of an index */
    uint32_t bound = 0;
    if ((in->id == X86_INS_MOV || in->id == X86_INS_MOVZX || in->id == X86_INS_MOVSXD) && s >= 0)
        bound = rt->bound[s];
    else if (in->id == X86_INS_AND && o1 && o1->type == X86_OP_IMM &&
             o1->imm >= 0 && o1->imm < (int64_t)JT_MAX_ENTRIES)
        bound = (uint32_t)o1->imm + 1;

    /* what the register holds */
    RegTrack old = *rt;
    uint8_t  k = RT_NONE;
    uint64_t v = 0, rb = 0;
    uint32_t nb = 0;
    if (in->id == X86_INS_LEA && st->lea && wide) {
        k = RT_ADDR; v = st->target;
    } else if (in->id == X86_INS_MOV && o1 && o1->type == X86_OP_IMM &&
               x->operands[0].size >= 4) {             /* mov ecx, imm: zero-extended */
        k = RT_ADDR;
        v = wide ? (uint64_t)o1->imm : (uint32_t)o1->imm;
    } else if (in->id == X86_INS_MOV && o1 && wide) {
        if ((v = table_of(rt, o1, 8, &nb, &rb))) k = RT_ENT;
    } else if (in->id == X86_INS_MOVSXD && o1 && wide) {
        if ((v = table_of(rt, o1, 4, &nb, &rb)) && rb) k = RT_REL;
    } else if (in->id == X86_INS_ADD && wide && s >= 0) {
        if (rt_case(&old, r, r, s) || rt_case(&old, r, s, r)) {
            k = RT_CASE; v = old.v[r]; rb = old.rb[r]; nb = old.nb[r];
        }
    } else if (in->id == X86_INS_LEA && wide && o1 && o1->type == X86_OP_MEM &&
               o1->mem.scale == 1 && !o1->mem.disp && o1->mem.segment == X86_REG_INVALID) {
        int b = gpr(o1->mem.base), i = gpr(o1->mem.index);
        if (rt_case(&old, r, b, i) || rt_case(&old, r, i, b)) {
            k = RT_CASE; v = old.v[r]; rb = old.rb[r]; nb = old.nb[r];
        }
    }
    if (k == RT_NONE || !v) { k = RT_NONE; v = rb = 0; nb = 0; }
    rt->k[r] = k; rt->v[r] = v; rt->rb[r] = rb; rt->nb[r] = nb;
    rt->bound[r] = bound;
}

static bool is_func(const An *a, uint64_t va);

/* imports a Windows CRT start-up calls to get argc / argv / envp just
 * before it calls main (MSVC: invoke_main; MinGW: __initenv = envp) */
static bool crt_args_call(const char *n) {
    static const char *const t[] = {
        "__p___argc", "__p___argv", "__p___wargv", "__p___initenv", "__p___winitenv",
        "_get_initial_narrow_environment", "_get_initial_wide_environment",
        "__getmainargs", "__wgetmainargs", "__p__environ", "__p__wenviron" };
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) if (!strcmp(n, t[i])) return true;
    return false;
}

/* ─── x86-32: register values along a path ──────────────────────── */

/* What a path of i386 code holds, for main and the GOT base: the eight
 * 32-bit registers whose value is known, and the last value pushed.
 * Known values come from `mov r, imm32`, `lea r, [abs32]` or `[r2 +
 * disp]` (r2 known), `add / sub r, imm` on a known r, `mov r, r2`, loads
 * `mov r, [abs32 / known + disp]` (the word, relocations applied), `pop
 * r` of a known push, the return address left in r by a call to a get-pc
 * thunk (`mov r, [esp]; ret`) and the address pushed by a call to the
 * next instruction (`call $+5; pop r`). Any other write to a register
 * (implicit ones included, from capstone) forgets it; a call forgets
 * eax, ecx, edx (caller-saved) and the last push; any write to esp other
 * than a push forgets the last push. */
typedef struct {
    uint32_t v[8];
    uint8_t  known;                /* bit r: v[r] is known                */
    uint8_t  lea;                  /* bit r: v[r] comes from a lea        */
    uint8_t  addr;                 /* bit r: v[r] is an address: from the
                                      pc (thunk, call $+5) or a relocated
                                      word, plus / minus constants        */
    uint32_t top;                  /* last value pushed, if top_ok        */
    bool     top_ok, top_lea, top_addr;
    uint8_t  nslot;                /* GOT base spilled to the stack: the  */
    uint16_t slot[X32_MAX_SLOT];   /* offsets from esp of those words     */
} X32Regs;

/* index 0..7 of a full 32-bit general register, else -1 */
static int gpr32(unsigned r) {
    switch (r) {
        case X86_REG_EAX: return 0; case X86_REG_ECX: return 1;
        case X86_REG_EDX: return 2; case X86_REG_EBX: return 3;
        case X86_REG_ESP: return 4; case X86_REG_EBP: return 5;
        case X86_REG_ESI: return 6; case X86_REG_EDI: return 7;
        default: return -1;
    }
}

/* address of a memory operand [abs32] or [known + disp] (no index, no
 * segment override) */
static bool x32_mem_addr(const X32Regs *t, const cs_x86_op *op, uint32_t *out) {
    if (op->type != X86_OP_MEM || op->mem.index != X86_REG_INVALID || op->mem.segment != X86_REG_INVALID)
        return false;
    uint32_t base = 0;
    if (op->mem.base != X86_REG_INVALID) {
        int b = gpr32(op->mem.base);
        if (b < 0 || b == 4 || !(t->known >> b & 1)) return false;
        base = t->v[b];
    }
    *out = base + (uint32_t)op->mem.disp;
    return true;
}

/* register a get-pc thunk at va loads with its return address
 * (`8b /r 24 c3`: mov r, [esp]; ret), else -1 */
static int x32_thunk_reg(const An *a, uint64_t va) {
    size_t avail = 0;
    const uint8_t *p = elf_va_ptr(&a->d->elf, va, &avail);
    if (!p || avail < 4 || p[0] != 0x8b || (p[1] & 0xc7) != 0x04 || p[2] != 0x24 || p[3] != 0xc3) return -1;
    int r = p[1] >> 3 & 7;
    return r == 4 ? -1 : r;
}

static void x32_set(X32Regs *t, int r, uint32_t v, bool lea, bool addr) {
    t->v[r] = v;
    t->known |= (uint8_t)(1u << r);
    t->lea  = (uint8_t)(lea  ? t->lea  | 1u << r : t->lea  & ~(1u << r));
    t->addr = (uint8_t)(addr ? t->addr | 1u << r : t->addr & ~(1u << r));
}

/* ---- GOT base spilled to the stack ----
 * GCC runs out of registers in a big PIC function: `mov [esp + 8], ebx`, and
 * later `mov edi, [esp + 8]; lea eax, [edi + X@GOTOFF]`. Only words that were
 * written from a register known to hold a->got count; esp is followed through
 * push / pop / add / sub / lea, and the list is dropped when esp changes any
 * other way (and esp, leave...). */

/* the stack word(s) at [esp + off, esp + off + size) are written */
static void x32_slot_clobber(X32Regs *t, int64_t off, int64_t size) {
    for (uint8_t i = 0; i < t->nslot; ) {
        if (off < t->slot[i] + 4 && t->slot[i] < off + size) t->slot[i] = t->slot[--t->nslot];
        else i++;
    }
}

static void x32_slot_add(X32Regs *t, int64_t off) {
    if (off < 0 || off > UINT16_MAX) return;
    x32_slot_clobber(t, off, 4);
    if (t->nslot < X32_MAX_SLOT) t->slot[t->nslot++] = (uint16_t)off;
}

static bool x32_slot_has(const X32Regs *t, int64_t off) {
    for (uint8_t i = 0; i < t->nslot; i++) if (t->slot[i] == off) return true;
    return false;
}

/* esp went down by d (up: d < 0) */
static void x32_slot_move(X32Regs *t, int64_t d) {
    for (uint8_t i = 0; i < t->nslot; ) {
        int64_t o = (int64_t)t->slot[i] + d;
        if (o < 0 || o > UINT16_MAX) t->slot[i] = t->slot[--t->nslot];
        else t->slot[i++] = (uint16_t)o;
    }
}

/* [esp + disp], no index, no segment */
static bool x32_esp_mem(const cs_x86_op *op, int64_t *off) {
    if (op->type != X86_OP_MEM || op->mem.base != X86_REG_ESP || op->mem.index != X86_REG_INVALID ||
        op->mem.segment != X86_REG_INVALID) return false;
    *off = op->mem.disp;
    return true;
}

static bool x32_is_got(const An *a, const X32Regs *t, int r) {
    return a->got && r >= 0 && r != 4 && (t->known & t->addr) >> r & 1 && t->v[r] == a->got;
}

/* memory operand [b + disp] (no index) whose base b holds the GOT base:
 * a GOT slot (b + X@GOT) or a GOTOFF address (b + X@GOTOFF). The base
 * must be an address equal to a->got, or, when the GOT base is unknown,
 * an address outside the code (the pc itself is in the code). */
static bool x32_got_rel(const An *a, const X32Regs *t, const cs_x86_op *op) {
    if (op->type != X86_OP_MEM || op->mem.index != X86_REG_INVALID ||
        op->mem.segment != X86_REG_INVALID || op->mem.base == X86_REG_INVALID)
        return false;
    int b = gpr32(op->mem.base);
    if (b < 0 || b == 4 || !(t->known >> b & 1) || !(t->addr >> b & 1)) return false;
    return a->got ? t->v[b] == a->got : !elf_va_exec(&a->d->elf, t->v[b]);
}

/* A code pointer reached through the GOT base: `lea r, [GOT + X@GOTOFF]`
 * (a static function's address, PIC), or the relocated word of a GOT
 * slot read by `mov r, / push / call / jmp [GOT + X@GOT]`, when it lies
 * in executable code. An import slot (undefined symbol) holds no
 * address here and is never taken. Checked later like a lea target
 * (codeptr_ok). */
static void x32_got_ptr(An *a, uint64_t v) {
    if (v && elf_va_exec(&a->d->elf, v)) cp_push(a, v);
}

/* the effect of the instruction just decoded (a->in) on t */
static void x32_track(An *a, X32Regs *t, const cs_insn *in, const Step *st) {
    const cs_x86 *x = &in->detail->x86;
    uint32_t next = (uint32_t)(in->address + in->size);
    if (st->flags & DI_CALL) {
        int r;
        if (st->direct && st->target == next) {                /* call $+5 */
            t->top = next; t->top_ok = true; t->top_lea = false; t->top_addr = true;
        } else if (st->direct && (r = x32_thunk_reg(a, st->target)) >= 0) {
            x32_set(t, r, next, false, true);
        } else {
            t->known &= (uint8_t)~0x07u;
            t->top_ok = false;
        }
        return;
    }
    int r0 = x->op_count >= 1 && x->operands[0].type == X86_OP_REG ? gpr32(x->operands[0].reg) : -1;
    const cs_x86_op *o1 = x->op_count == 2 ? &x->operands[1] : NULL;
    bool vok = false, vlea = false, vaddr = false, pushed = false, pok = false, plea = false, paddr = false;
    bool rl;
    uint32_t v = 0, pv = 0, ad;
    uint64_t w;
    int64_t spo = 0, spd = 0;
    bool spknown = false, sppush = false;
    /* stack words written here, esp after it */
    for (uint8_t k = 0; k < x->op_count; k++)
        if ((x->operands[k].access & CS_AC_WRITE) && x32_esp_mem(&x->operands[k], &spo))
            x32_slot_clobber(t, spo, x->operands[k].size);
    if (in->id == X86_INS_MOV && x->op_count == 2 && x32_esp_mem(&x->operands[0], &spo) &&
        x->operands[0].size == 4 && x->operands[1].type == X86_OP_REG && x32_is_got(a, t, gpr32(x->operands[1].reg)))
        x32_slot_add(t, spo);
    if (in->id == X86_INS_PUSH) {
        spknown = true; spd = 4;
        sppush = x->op_count == 1 && x->operands[0].type == X86_OP_REG && x32_is_got(a, t, gpr32(x->operands[0].reg));
    } else if (in->id == X86_INS_POP) {
        spknown = true; spd = -4;
    } else if ((in->id == X86_INS_ADD || in->id == X86_INS_SUB) && x->op_count == 2 &&
               x->operands[0].type == X86_OP_REG && x->operands[0].reg == X86_REG_ESP &&
               x->operands[1].type == X86_OP_IMM) {
        spknown = true;
        spd = in->id == X86_INS_SUB ? (int64_t)(int32_t)x->operands[1].imm : -(int64_t)(int32_t)x->operands[1].imm;
    } else if (in->id == X86_INS_LEA && x->op_count == 2 && x->operands[0].type == X86_OP_REG &&
               x->operands[0].reg == X86_REG_ESP && x32_esp_mem(&x->operands[1], &spo)) {
        spknown = true;
        spd = -spo;
    }
    if (r0 == 4) r0 = -1;                                      /* esp: the stack */
    switch (in->id) {
        case X86_INS_PUSH:
            if (x->op_count != 1) break;
            pushed = true;
            if (x->operands[0].type == X86_OP_IMM) {
                pv = (uint32_t)x->operands[0].imm; pok = true;
            } else if (x->operands[0].type == X86_OP_REG) {
                int r = gpr32(x->operands[0].reg);
                if (r >= 0 && r != 4 && (t->known >> r & 1)) {
                    pv = t->v[r]; pok = true; plea = t->lea >> r & 1; paddr = t->addr >> r & 1;
                }
            } else if (x->operands[0].size == 4 && x32_mem_addr(t, &x->operands[0], &ad) &&
                       x32_load(a, ad, &w, &rl)) {
                pv = (uint32_t)w; pok = true; paddr = rl;
                if (rl && x32_got_rel(a, t, &x->operands[0])) x32_got_ptr(a, pv);
            }
            break;
        case X86_INS_POP:
            if (r0 >= 0 && t->top_ok) { v = t->top; vok = true; vlea = t->top_lea; vaddr = t->top_addr; }
            break;
        case X86_INS_MOV:
            if (r0 < 0 || !o1) break;
            if (o1->type == X86_OP_IMM) { v = (uint32_t)o1->imm; vok = true; }
            else if (o1->type == X86_OP_REG) {
                int r = gpr32(o1->reg);
                if (r >= 0 && r != 4 && (t->known >> r & 1)) {
                    v = t->v[r]; vok = true; vlea = t->lea >> r & 1; vaddr = t->addr >> r & 1;
                }
            } else if (o1->size == 4 && x32_mem_addr(t, o1, &ad) && x32_load(a, ad, &w, &rl)) {
                v = (uint32_t)w; vok = true; vaddr = rl;
                if (rl && x32_got_rel(a, t, o1)) x32_got_ptr(a, v);
            } else if (o1->size == 4 && x32_esp_mem(o1, &spo) && x32_slot_has(t, spo)) {
                v = (uint32_t)a->got; vok = true; vaddr = true;     /* reloaded */
            }
            break;
        case X86_INS_LEA:
            if (r0 >= 0 && o1 && x32_mem_addr(t, o1, &ad)) {
                v = ad; vok = true; vlea = true;
                vaddr = o1->mem.base != X86_REG_INVALID && (t->addr >> gpr32(o1->mem.base) & 1);
                if (x32_got_rel(a, t, o1)) x32_got_ptr(a, v);
            }
            break;
        case X86_INS_ADD: case X86_INS_SUB:
            if (r0 >= 0 && o1 && o1->type == X86_OP_IMM && (t->known >> r0 & 1)) {
                v = in->id == X86_INS_ADD ? t->v[r0] + (uint32_t)o1->imm : t->v[r0] - (uint32_t)o1->imm;
                vok = true; vlea = t->lea >> r0 & 1; vaddr = t->addr >> r0 & 1;
            }
            break;
        default: break;
    }
    /* every register written is forgotten, then the one set above */
    cs_regs rr, rw;
    uint8_t nr = 0, nw = 0;
    bool esp = false;
    if (cs_regs_access(a->h, in, rr, &nr, rw, &nw) == CS_ERR_OK) {
        for (uint8_t k = 0; k < nw; k++) {
            int g = gpr(rw[k]);
            if (g == 4) esp = true;
            else if (g >= 0 && g < 8) t->known &= (uint8_t)~(1u << g);
        }
    } else {
        t->known = 0;
        esp = true;
    }
    if (vok && r0 >= 0) x32_set(t, r0, v, vlea, vaddr);
    if (pushed) { t->top = pv; t->top_ok = pok; t->top_lea = plea; t->top_addr = paddr; }
    else if (esp) t->top_ok = false;
    if (spknown) x32_slot_move(t, spd);
    else if (esp) t->nslot = 0;
    if (sppush) x32_slot_add(t, 0);
}

/* Registers holding the GOT base are carried along the direct jumps:
 * GCC loads it once at the start of a PIC function and uses it in blocks
 * reached only by branches, each walked as a new path. A jmp / jcc to
 * code not decoded yet records which registers hold a->got there; the
 * path starting at that address gets them (those all its predecessors
 * seen so far agree on). At most X32_HINT_MAX targets are recorded. */
#define X32_HINT_MAX  (1u << 20)

static size_t x32_hslot(const An *a, uint64_t va) {
    size_t i = (size_t)((va * 0x9e3779b97f4a7c15ull) >> 17) & (a->xhcap - 1);
    while (a->xh[i].va && a->xh[i].va != va) i = (i + 1) & (a->xhcap - 1);
    return i;
}

static uint8_t x32_got_regs(const An *a, const X32Regs *t) {
    uint8_t m = 0;
    for (int r = 0; r < 8; r++)
        if (r != 4 && (t->known & t->addr) >> r & 1 && t->v[r] == a->got) m |= (uint8_t)(1u << r);
    return m;
}

static void x32_hint_put(An *a, uint64_t va, const X32Regs *t) {
    if (!a->got || a->oom || !va || is_decoded(a, va) || !xmap_of(a, va)) return;
    if ((a->nxh + 1) * 2 > a->xhcap) {
        if (a->nxh >= X32_HINT_MAX) return;
        size_t nc = a->xhcap ? a->xhcap * 2 : 1024, oc = a->xhcap;
        X32Hint *o = a->xh, *n = calloc(nc, sizeof *n);
        if (!n) { a->oom = true; return; }
        a->xh = n; a->xhcap = nc;
        for (size_t i = 0; i < oc; i++)
            if (o[i].va) a->xh[x32_hslot(a, o[i].va)] = o[i];
        free(o);
    }
    uint8_t m = x32_got_regs(a, t);
    X32Hint *h = &a->xh[x32_hslot(a, va)];
    if (h->va) {
        h->got &= m;
        for (uint8_t i = 0; i < h->nslot; ) {     /* words all of them agree on */
            if (x32_slot_has(t, h->slot[i])) i++;
            else h->slot[i] = h->slot[--h->nslot];
        }
    } else {
        h->va = va; h->got = m; a->nxh++;
        h->nslot = t->nslot;
        memcpy(h->slot, t->slot, sizeof h->slot);
    }
}

static void x32_hint_get(const An *a, uint64_t va, X32Regs *t) {
    if (!a->xhcap) return;
    const X32Hint *h = &a->xh[x32_hslot(a, va)];
    if (h->va != va) return;
    for (int r = 0; r < 8; r++)
        if (h->got >> r & 1) x32_set(t, r, (uint32_t)a->got, false, true);
    t->nslot = h->nslot;
    memcpy(t->slot, h->slot, sizeof t->slot);
}

/* `push imm32`, `mov r32, imm32`, `lea r, [abs32]` whose value lies in
 * executable code (non-PIE executable only: elsewhere such a value is not
 * an address): a code pointer, checked like a lea target (codeptr_ok) */
static void x32_imm_ptr(An *a, const cs_insn *in) {
    const cs_x86 *x = &in->detail->x86;
    uint64_t v = 0;
    if (in->id == X86_INS_PUSH && x->op_count == 1 && x->operands[0].type == X86_OP_IMM)
        v = (uint32_t)x->operands[0].imm;
    else if (in->id == X86_INS_MOV && x->op_count == 2 && x->operands[0].type == X86_OP_REG &&
             x->operands[0].size == 4 && x->operands[1].type == X86_OP_IMM)
        v = (uint32_t)x->operands[1].imm;
    else if (in->id == X86_INS_LEA && x->op_count == 2 && x->operands[1].type == X86_OP_MEM &&
             x->operands[1].mem.base == X86_REG_INVALID && x->operands[1].mem.index == X86_REG_INVALID &&
             x->operands[1].mem.segment == X86_REG_INVALID)
        v = (uint32_t)x->operands[1].mem.disp;
    if (v && elf_va_exec(&a->d->elf, v)) cp_push(a, v);
}

static bool codeptr_ok(An *a, uint64_t va);

/* main given to __libc_start_main by the i386 start code (the last push
 * before the call). Static PIE pushes the address of __wrap_main (`lea
 * r, [ebx + GOTOFF]`), a `jmp main`: a lea value starting with a direct
 * jmp is followed once. The target must be executable and pass
 * codeptr_ok (not inside decoded code, clean decode). */
static void x32_main(An *a, uint64_t va, bool lea) {
    if (lea) {
        Step st;
        XMap *x = NULL;
        if (decode_at(a, va, &x, &st) == DEC_OK && (st.flags & DI_JUMP) && st.direct && st.target) va = st.target;
    }
    if (elf_va_exec(&a->d->elf, va) && codeptr_ok(a, va)) add_func(a, va, FN_MAIN);
}

/* Empties the work list. Each address is decoded at most once (start
 * bitmap), each pass of the inner loop consumes a new instruction, so
 * the total work is bounded by the executable bytes and DA_MAX_INSNS. */
static void walk_queue(An *a) {
    Disasm *d = a->d;
    RegTrack rt;
    X32Regs  xr;                   /* x86-32 only */
    uint64_t carry = 0;            /* target of the direct jmp that ended
                                      the last path, popped next (LIFO):
                                      its path keeps the registers (a
                                      table address loaded before a jmp
                                      to the loop head) */
    while (a->qn && !a->oom) {
        uint64_t pc  = a->q[--a->qn];
        uint64_t rdi = 0;
        bool crt_args = false;     /* argc / argv fetched: next call is main */
        if (!carry || pc != carry) {
            rt_reset(&rt);
            memset(&xr, 0, sizeof xr);
            if (a->x32) x32_hint_get(a, pc, &xr);
        }
        carry = 0;
        for (;;) {
            if (d->nins >= DA_MAX_INSNS) { d->capped = true; a->qn = 0; return; }
            Step st;
            XMap *x = NULL;
            int r = decode_at(a, pc, &x, &st);
            if (r == DEC_BAD || r == DEC_OVERLAP) d->nbad++;
            if (r != DEC_OK) break;

            uint64_t main32 = 0;       /* x86-32: main candidate, checked after commit */
            bool     main32_lea = false;
            if (a->x32 && (st.flags & DI_INDIRECT) && a->in->detail->x86.op_count == 1 &&
                a->in->detail->x86.operands[0].size == 4) {
                uint32_t slot;         /* call / jmp [abs32] or [GOT base + disp]: the slot */
                uint64_t w;
                bool rl;
                if (x32_mem_addr(&xr, &a->in->detail->x86.operands[0], &slot)) {
                    st.target = slot;
                    if (x32_load(a, slot, &w, &rl) && rl) x32_got_ptr(a, w);
                }
            }
            if (st.flags & DI_CALL) {
                const char *cn = st.target ? callee_name(a, st.target, !st.direct) : NULL;
                if (cn && rdi && !strcmp(cn, "__libc_start_main"))
                    add_func(a, rdi, FN_MAIN);
                if (a->x32 && cn && xr.top_ok && !strcmp(cn, "__libc_start_main")) {
                    main32 = xr.top;
                    main32_lea = xr.top_lea;
                }
                if (st.direct && crt_args && (!cn || !strcmp(cn, "main") || !strcmp(cn, "wmain"))) {
                    add_func(a, st.target, FN_MAIN);
                    crt_args = false;
                } else if (cn && !a->x32 && crt_args_call(cn))
                    crt_args = true;
                if (st.direct && !(a->x32 && st.target == pc + st.len))   /* x86-32 call $+5: get pc */
                    add_func(a, st.target, FN_CALL);
                if (name_noreturn(cn)) { st.flags |= DI_NORET; st.end = true; }
            } else if ((st.flags & (DI_JUMP | DI_COND)) && st.direct) {
                /* also a tail call to a known function: it is not
                 * decoded again (push skips decoded code), its callers
                 * are counted in finalize */
                if (a->x32) x32_hint_put(a, st.target, &xr);
                push(a, st.target);
            }
            if (st.rdi > 0) rdi = st.target;
            else if (st.rdi < 0) rdi = 0;
            if (st.lea && st.target != pc + st.len) cp_push(a, st.target);  /* not lea [rip+0] */
            if (!a->x32) track(a, &rt, a->in, &st);   /* x86-64 switch idioms only */
            else {
                if (a->d->elf.type == X_ET_EXEC) x32_imm_ptr(a, a->in);
                x32_track(a, &xr, a->in, &st);
                if (a->d->elf.fmt == ELF_FMT_PE || a->d->elf.type == X_ET_EXEC) pe32_switch(a, a->in);
            }

            commit(a, x, pc, &st);
            if (main32) x32_main(a, main32, main32_lea);   /* probes: a->in is free now */
            if ((st.flags & DI_JUMP) && st.direct && a->qn && a->q[a->qn - 1] == st.target &&
                !is_func(a, st.target))
                carry = st.target;
            if (a->oom || st.end) break;
            pc += st.len;
        }
    }
}

/* A guess is kept only if a linear decode from it reaches a terminator
 * (or known code) without hitting undecodable bytes or the middle of an
 * instruction already decoded. Nothing is recorded here. */
static bool probe(An *a, uint64_t pc) {
    for (int i = 0; i < PROBE_INSNS; i++) {
        Step st;
        XMap *x = NULL;
        int r = decode_at(a, pc, &x, &st);
        if (r == DEC_KNOWN) return i > 0;
        if (r != DEC_OK) return false;
        if (st.end) return true;
        pc += st.len;
    }
    return true;
}

static bool plt_section(const char *n) { return !strncmp(n, ".plt", 4); }

static bool is_func(const An *a, uint64_t va) {
    return a->hcap && a->hk[hslot(a, va)] == va;
}

/* ─── jump tables ───────────────────────────────────────────────── */

static const ElfSymbol *func_symbol(const ElfFile *ef, uint64_t va, bool *exported);

/* last function start at an offset in [lo, o] of x */
static bool fstart_prev(const XMap *x, uint64_t o, uint64_t lo, uint64_t *out) {
    for (;;) {
        if (bit_get(x->fstart, o)) { *out = o; return true; }
        if (o == lo) return false;
        o--;
        while ((o & 7) == 7 && o >= lo + 8 && !x->fstart[o >> 3]) o -= 8;
    }
}

/* first function start at an offset in [o, hi) of x */
static bool fstart_next(const XMap *x, uint64_t o, uint64_t hi, uint64_t *out) {
    while (o < hi) {
        if (!(o & 7) && hi - o >= 8 && !x->fstart[o >> 3]) { o += 8; continue; }
        if (bit_get(x->fstart, o)) { *out = o; return true; }
        o++;
    }
    return false;
}

/* [lo, hi): the function holding the jmp at pc, as known now: from the
 * last function start <= pc to the next one, or to the end of its symbol
 * when it has a size. Within JT_SPAN of pc, inside the executable section
 * (or mapping) of pc. */
static void jt_func_range(An *a, XMap *x, uint64_t pc, uint64_t *lo, uint64_t *hi) {
    const ElfMap *m = x->m;
    uint64_t o = pc - m->va, f = 0, nx = 0;
    uint64_t blo = o > JT_SPAN ? o - JT_SPAN : 0;
    uint64_t bhi = m->filesz - o > JT_SPAN ? o + JT_SPAN : m->filesz;
    bool known = fstart_prev(x, o, blo, &f);
    *lo = m->va + (known ? f : blo);
    *hi = m->va + (fstart_next(x, o + 1, bhi, &nx) ? nx : bhi);
    if (known) {
        bool exp;
        const ElfSymbol *s = func_symbol(&a->d->elf, *lo, &exp);
        if (s && s->size > pc - *lo && s->size < *hi - *lo) *hi = *lo + s->size;
    }
    const ElfSection *s = a->xsec ? elf_section_at(&a->d->elf, pc) : NULL;
    if (s && s->size <= UINT64_MAX - s->addr) {
        if (s->addr > *lo) *lo = s->addr;
        if (s->addr + s->size < *hi) *hi = s->addr + s->size;
    }
}

/* [lo, hi): the data holding a table at base, entries of esz bytes. With
 * a section table: its section, which must be file-backed and not code
 * (.rodata is one even in the R+X segment of a -z noseparate-code
 * binary); without: its mapping, which must not be executable. */
static bool jt_region(An *a, uint64_t base, unsigned esz, uint64_t *lo, uint64_t *hi) {
    const ElfFile *ef = &a->d->elf;
    if (ef->nsec) {
        const ElfSection *s = elf_section_at(ef, base);
        if (!s || s->bad || s->type == X_SHT_NOBITS || (s->flags & X_SHF_EXECINSTR) ||
            s->size > UINT64_MAX - s->addr)
            return false;
        *lo = s->addr; *hi = s->addr + s->size;
    } else {
        const ElfMap *m = elf_map_of(ef, base);
        if (!m || (m->flags & X_PF_X) || m->filesz > UINT64_MAX - m->va) return false;
        *lo = m->va; *hi = m->va + m->filesz;
    }
    return *hi - *lo >= esz && base <= *hi - esz;
}

/* a case of the switch whose function spans [lo, hi): in an executable
 * section (not a PLT), not inside an instruction already decoded, and
 * either decoded already or decoding cleanly (probe) */
static bool jt_target_ok(An *a, uint64_t t, uint64_t lo, uint64_t hi) {
    if (t < lo || t >= hi) return false;
    XMap *x = xmap_of(a, t);
    if (!x) return false;
    if (a->xsec) {
        const ElfSection *s = elf_section_at(&a->d->elf, t);
        if (!s || !(s->flags & X_SHF_EXECINSTR) || s->bad || plt_section(s->name)) return false;
    }
    uint64_t o = t - x->m->va;
    if (bit_get(x->start, o)) return true;
    if (bit_get(x->cover, o)) return false;
    return probe(a, t);
}

/* the case of the table entry at s */
static bool jt_entry(const ElfFile *ef, const JTab *j, uint64_t s, uint64_t *t) {
    if (j->esz == 8) return elf_read_ptr(ef, s, t);
    size_t avail = 0;
    const uint8_t *p = elf_va_ptr(ef, s, &avail);
    if (!p || avail < 4) return false;
    uint32_t u = (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
    *t = j->rb + (uint64_t)(int64_t)(int32_t)u;
    return true;
}

static int cmp_u64(const void *x, const void *y);

/* Builds a->lt from the raw bytes of the executable mappings (decoded or
 * not, so it does not depend on what was reached yet): REX.W 8D modrm
 * with mod 00, r/m 101. A false match only ends a table earlier. */
static void lea_targets(An *a) {
    const ElfFile *ef = &a->d->elf;
    size_t cap = 0;
    a->ltdone = true;
    for (int k = 0; k < a->nxm; k++) {
        const ElfMap *m = a->xm[k].m;
        if (m->off > ef->size || m->filesz > ef->size - m->off || m->filesz < 7) continue;
        const uint8_t *p = ef->data + m->off;
        for (uint64_t o = 0; o + 7 <= m->filesz; o++) {
            if ((p[o] & 0xf8) != 0x48 || p[o + 1] != 0x8d || (p[o + 2] & 0xc7) != 0x05) continue;
            int32_t disp = (int32_t)((uint32_t)p[o + 3] | (uint32_t)p[o + 4] << 8 |
                                     (uint32_t)p[o + 5] << 16 | (uint32_t)p[o + 6] << 24);
            uint64_t x = m->va + o + 7 + (uint64_t)(int64_t)disp;
            if (elf_va_exec(ef, x) || !elf_map_of(ef, x)) continue;
            if (a->nlt >= DA_MAX_QUEUE) break;
            uint64_t *n = grow(a, a->lt, a->nlt, &cap, sizeof *n, 256);
            if (!n) return;
            a->lt = n;
            a->lt[a->nlt++] = x;
        }
    }
    if (a->nlt) qsort(a->lt, a->nlt, sizeof *a->lt, cmp_u64);
}

/* first address above `base` that code takes with `lea [rip+X]`, or
 * UINT64_MAX */
static uint64_t lea_next(An *a, uint64_t base) {
    if (!a->ltdone) lea_targets(a);
    size_t lo = 0, hi = a->nlt;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (a->lt[mid] <= base) lo = mid + 1; else hi = mid;
    }
    return lo < a->nlt ? a->lt[lo] : UINT64_MAX;
}

/* first base above `base` of a table known now (still to read or read),
 * UINT64_MAX when none or once JT_SCAN_MAX comparisons are spent */
static uint64_t jt_next_base(An *a, uint64_t base) {
    size_t cost = a->njq + a->njqu + a->njr;
    if (cost > JT_SCAN_MAX - a->jtscan) return UINT64_MAX;
    a->jtscan += cost;
    uint64_t nx = UINT64_MAX;
    for (size_t i = 0; i < a->njq; i++)
        if (a->jq[i].base > base && a->jq[i].base < nx) nx = a->jq[i].base;
    for (size_t i = 0; i < a->njqu; i++)
        if (a->jqu[i].base > base && a->jqu[i].base < nx) nx = a->jqu[i].base;
    for (size_t i = 0; i < a->njr; i++)
        if (a->jr[i].base > base && a->jr[i].base < nx) nx = a->jr[i].base;
    return nx;
}

/* Reads the table of the indexed jmp at j->pc from j->base on, up to the
 * first entry that is not a case (see jt_target_ok), the end of its data,
 * its j->n entries when known, else the start of the next table known
 * and, for int32 offsets (those of the next table, read from the wrong
 * base, still land in code), the next data the code takes the address
 * of (lea_next: the next table, or a string). Each case is walked before the next
 * entry is checked, so repeated entries (holes going to the default
 * label) are decoded once and probed once. A case is code of the
 * function, not a new one. The total number of entries read is bounded
 * by DA_MAX_QUEUE. */
static void walk_queue(An *a);

static void jt_read(An *a, const JTab *j) {
    Disasm *d = a->d;
    XMap *x = xmap_of(a, j->pc);
    uint64_t lo, hi, dlo, dhi, base = j->base;
    if (!x || !jt_region(a, base, j->esz, &dlo, &dhi) || base < dlo) return;
    jt_func_range(a, x, j->pc, &lo, &hi);
    size_t n = 0, e0 = a->nje, max = j->n && j->n < JT_MAX_ENTRIES ? j->n : JT_MAX_ENTRIES;
    uint64_t stop = j->n ? UINT64_MAX : jt_next_base(a, base);
    if (!j->n && j->esz == 4) { uint64_t l = lea_next(a, base); if (l < stop) stop = l; }
    for (uint64_t s = base; s <= dhi - j->esz && s < stop && n < max; s += j->esz) {
        if (a->oom || d->nins >= DA_MAX_INSNS) break;
        if (a->jtent >= DA_MAX_QUEUE) { d->capped = true; break; }
        a->jtent++;
        uint64_t t;
        if (!jt_entry(&d->elf, j, s, &t) || !jt_target_ok(a, t, lo, hi)) break;
        JRef *e = grow(a, a->je, a->nje, &a->jecap, sizeof *e, 256);
        if (!e) break;
        a->je = e;
        a->je[a->nje++] = (JRef){ j->pc, t };
        n++;
        push(a, t);
        walk_queue(a);
    }
    if (!n || a->oom) return;
    JRead *r = grow(a, a->jr, a->njr, &a->jrcap, sizeof *r, 64);
    if (!r) return;
    a->jr = r;
    a->jr[a->njr++] = (JRead){ base, e0, n, j->esz };
}

/* Empties the work list, then reads the jump tables found on the way
 * (their cases may hold more), until there is nothing left: those of a
 * known size first, so that more table starts are known when the others
 * are read. Each jmp is decoded once, so each table is read once per jmp
 * reading it. */
static void walk(An *a) {
    for (;;) {
        walk_queue(a);
        if (a->oom || a->d->nins >= DA_MAX_INSNS) break;
        JTab j;
        if (a->njq)       j = a->jq[--a->njq];
        else if (a->njqu) j = a->jqu[--a->njqu];
        else break;
        jt_read(a, &j);
    }
    a->njq = a->njqu = 0;
}

/* ─── code pointers ─────────────────────────────────────────────── */

/* Whether the target of a `lea reg, [rip+X]` is taken as a function.
 * Called once the work list is empty, so the code reachable from what
 * is already known has been decoded:
 *  - already a function: yes (its kind is only improved);
 *  - inside an instruction already decoded: no;
 *  - start of an instruction already decoded: yes (code reached by a
 *    tail jmp or by falling through a call that does not return; its
 *    decoding is known to be in sync), it becomes a function start;
 *  - with a section table, outside an executable section (.rodata in
 *    the R+X segment of a -z noseparate-code binary) or in .plt*: no;
 *  - otherwise only if the linear decode from X is clean (probe). */
static bool codeptr_ok(An *a, uint64_t va) {
    if (is_func(a, va)) return true;
    XMap *x = xmap_of(a, va);
    if (!x || pe_data_at(a, va)) return false;
    uint64_t o = va - x->m->va;
    if (bit_get(x->start, o)) return true;
    if (bit_get(x->cover, o)) return false;
    if (a->xsec) {
        const ElfSection *s = elf_section_at(&a->d->elf, va);
        if (!s || !(s->flags & X_SHF_EXECINSTR) || s->bad || plt_section(s->name))
            return false;
    }
    return probe(a, va);
}

/* walk, then each pending lea target as a new root, walked at once so
 * the next target is checked against the code it reached. Targets met
 * on the way are pushed on the same list (LIFO). Each address is
 * decoded once and each lea is seen once: this ends. */
static void explore(An *a) {
    walk(a);
    while (a->ncp && !a->oom && !a->d->capped) {
        uint64_t va = a->cp[--a->ncp];
        if (!codeptr_ok(a, va)) continue;
        add_func(a, va, FN_CODEPTR);
        walk(a);
    }
    a->ncp = 0;
}

/* ─── prologue heuristic ────────────────────────────────────────── */

static bool is_push_or_frame(bool x32, const uint8_t *p, size_t n) {
    if (x32) {                                    /* push ebp/ebx/esi/edi, sub esp, imm */
        if (n >= 1 && (p[0] == 0x55 || p[0] == 0x53 || p[0] == 0x56 || p[0] == 0x57)) return true;
        return n >= 2 && (p[0] == 0x83 || p[0] == 0x81) && p[1] == 0xec;
    }
    if (n >= 2 && p[0] == 0x41 && p[1] >= 0x54 && p[1] <= 0x57) return true; /* push r12..r15 */
    if (n >= 1 && (p[0] == 0x55 || p[0] == 0x53)) return true;               /* push rbp/rbx  */
    if (n >= 3 && p[0] == 0x48 && (p[1] == 0x83 || p[1] == 0x81) && p[2] == 0xec)
        return true;                                                          /* sub rsp, imm  */
    return false;
}

/* strong: endbr64, push rbp; mov rbp, rsp. weak (16-aligned after
 * padding only): a run of callee-saved pushes / sub rsp. x86-32: strong:
 * endbr32, push ebp; mov ebp, esp (55 89 e5), the stack realignment of
 * main / AVX code (lea r, [esp + d8]; and esp, -N); weak: push ebp / ebx
 * / esi / edi or sub esp, imm (GCC schedules register-argument moves and
 * get-pc calls between the saves), which must also pass x32_clean_entry. */
static int prologue_kind(bool x32, const uint8_t *p, size_t n) {
    if (x32) {
        if (n >= 4 && p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x1e && p[3] == 0xfb) return 2;
        if (n >= 3 && p[0] == 0x55 && p[1] == 0x89 && p[2] == 0xe5) return 2;
        if (n >= 6 && p[0] == 0x8d && (p[1] & 0xc7) == 0x44 && p[2] == 0x24 &&
            p[4] == 0x83 && p[5] == 0xe4) return 2;      /* lea r, [esp + d8]; and esp, -N */
        return is_push_or_frame(true, p, n) ? 1 : 0;
    }
    if (n >= 4 && p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x1e && p[3] == 0xfa) return 2;
    if (n >= 4 && p[0] == 0x55 && p[1] == 0x48 && p[2] == 0x89 && p[3] == 0xe5) return 2;
    if (n >= 2 && p[0] == 0x41 && p[1] >= 0x54 && p[1] <= 0x57 && is_push_or_frame(false, p + 2, n - 2)) return 1;
    if (n >= 1 && (p[0] == 0x55 || p[0] == 0x53) && is_push_or_frame(false, p + 1, n - 1)) return 1;
    if (n >= 4 && p[0] == 0x48 && (p[1] == 0x83 || p[1] == 0x81) && p[2] == 0xec) return 1;
    return 0;
}

/* `add r, imm32` (81 /0, or 05 for eax) at p: r, else -1 */
static int x32_add_imm32(const uint8_t *p, size_t n) {
    if (n >= 5 && p[0] == 0x05) return 0;
    if (n >= 6 && p[0] == 0x81 && (p[1] & 0xf8) == 0xc0) return p[1] & 7;
    return -1;
}

/* the bytes just before va end a prologue step (push r, mov ebp, esp,
 * sub esp, imm, and esp, imm): a PIC sequence there is not a start */
static bool x32_after_prologue(const An *a, uint64_t va) {
    const ElfFile *ef = &a->d->elf;
    size_t av = 0;
    const uint8_t *q;
    if ((q = elf_va_ptr(ef, va - 1, &av)) && av >= 1 && *q >= 0x50 && *q <= 0x57) return true;
    if ((q = elf_va_ptr(ef, va - 2, &av)) && av >= 2 && q[0] == 0x89 && q[1] == 0xe5) return true;
    if ((q = elf_va_ptr(ef, va - 3, &av)) && av >= 3 && q[0] == 0x83 && (q[1] == 0xec || q[1] == 0xe4))
        return true;
    if ((q = elf_va_ptr(ef, va - 6, &av)) && av >= 6 && q[0] == 0x81 && (q[1] == 0xec || q[1] == 0xe4))
        return true;
    return false;
}

/* x86-32 PIC entry, strong: `call T; add r, imm32` with T a get-pc thunk
 * loading r (`8b /r 24 c3`), or `call $+5; pop r; add r, imm32`, not
 * right after a prologue step (the same sequence follows the pushes of
 * most PIC prologues). Without it, the `push ebp; mov ebp, esp` that
 * follows it at -Os -fPIC would be taken 10 bytes too far, after an
 * imm32 ending in 00. */
static bool x32_pic_entry(const An *a, uint64_t va, const uint8_t *p, size_t n) {
    if (n < 10 || p[0] != 0xe8) return false;
    uint32_t rel = (uint32_t)p[1] | (uint32_t)p[2] << 8 | (uint32_t)p[3] << 16 | (uint32_t)p[4] << 24;
    int r;
    if (!rel) {                                       /* call $+5; pop r; add r, imm32 */
        if (p[5] < 0x58 || p[5] > 0x5f || p[5] == 0x5c) return false;
        r = x32_add_imm32(p + 6, n - 6);
        if (r != (p[5] & 7)) return false;
    } else {
        r = x32_add_imm32(p + 5, n - 5);
        if (r < 0 || x32_thunk_reg(a, (uint32_t)(va + 5 + rel)) != r) return false;
    }
    return !x32_after_prologue(a, va);
}

/* x86-32 weak prologue (push run / sub esp): the first instructions, up
 * to the first branch, call or ret and at most 8, read none of ebx, esi,
 * edi, ebp before writing it, except to save it (`push r` of a register
 * not written yet, ebp before the others; `mov [esp + d], r`) or zero it
 * (`xor r, r`), until an `and esp, imm` (realignment, a prologue for
 * sure): they are callee-saved, a function
 * start can only save them, while a block inside a function (a switch
 * case: 32-bit jump tables are not read yet) uses them as they are
 * (`mov ebx, [ebp - 8]`, `lea eax, [ebx + GOTOFF]`). Uses a->in. */
static bool x32_clean_entry(An *a, uint64_t va, const uint8_t *p, size_t n) {
    uint8_t  set = 0;                             /* gpr written so far */
    bool     saved = false;                       /* ebx / esi / edi pushed */
    uint64_t ad  = va;
    for (int i = 0; i < 8 && n; i++) {
        if (!cs_disasm_iter(a->h, &p, &n, &ad, a->in)) return false;
        const cs_insn *in = a->in;
        const cs_x86  *x  = &in->detail->x86;
        bool save = (in->id == X86_INS_PUSH && x->op_count == 1 && x->operands[0].type == X86_OP_REG) ||
                    (in->id == X86_INS_MOV && x->op_count == 2 && x->operands[0].type == X86_OP_MEM &&
                     x->operands[0].mem.base == X86_REG_ESP && x->operands[1].type == X86_OP_REG) ||
                    ((in->id == X86_INS_XOR || in->id == X86_INS_SUB) && x->op_count == 2 &&
                     x->operands[0].type == X86_OP_REG && x->operands[1].type == X86_OP_REG &&
                     x->operands[0].reg == x->operands[1].reg);
        if (in->id == X86_INS_AND && x->op_count == 2 && x->operands[0].type == X86_OP_REG &&
            x->operands[0].reg == X86_REG_ESP)
            return true;                  /* stack realignment: only in a prologue */
        if (in->id == X86_INS_PUSH && x->op_count == 1 && x->operands[0].type == X86_OP_REG) {
            int g = gpr(x->operands[0].reg);
            if (g == 3 || g == 5 || g == 6 || g == 7) {
                if (set >> g & 1) return false;           /* a value, not a save */
                if (g == 5 && saved) return false;        /* ebp is saved first  */
                if (g != 5) saved = true;
            }
        }
        cs_regs rr, rw;
        uint8_t nr = 0, nw = 0;
        if (cs_regs_access(a->h, in, rr, &nr, rw, &nw) != CS_ERR_OK) return false;
        if (!save)
            for (uint8_t k = 0; k < nr; k++) {
                int g = gpr(rr[k]);
                if ((g == 3 || g == 5 || g == 6 || g == 7) && !(set >> g & 1)) return false;
            }
        for (uint8_t k = 0; k < nw; k++) {
            int g = gpr(rw[k]);
            if (g >= 0 && g < 8) set |= (uint8_t)(1u << g);
        }
        if (cs_insn_group(a->h, in, CS_GRP_JUMP) || cs_insn_group(a->h, in, CS_GRP_CALL) ||
            cs_insn_group(a->h, in, CS_GRP_RET))
            break;
    }
    return true;
}

/* x86-32 weak prologue guess at pc: its linear path (as probe walks it)
 * has a direct jmp / jcc into the middle of code already decoded, not a
 * function start: it is a block of that code's function (a switch case
 * jumping back into its function), not a function. */
static bool x32_jumps_inside(An *a, uint64_t pc) {
    for (int i = 0; i < PROBE_INSNS; i++) {
        Step st;
        XMap *x = NULL;
        if (decode_at(a, pc, &x, &st) != DEC_OK) return false;
        if ((st.flags & (DI_JUMP | DI_COND)) && st.direct && st.target &&
            is_decoded(a, st.target) && !is_func(a, st.target))
            return true;
        if (st.end) return false;
        pc += st.len;
    }
    return false;
}

/* last byte of the alignment padding GCC / Clang / ld emit (multi-byte
 * nops end in 00), or of a ret */
static bool pad_byte(uint8_t b) { return b == 0x00 || b == 0x90 || b == 0xcc || b == 0xc3; }

/* PE32: a `push r; call` refused as a start is still real code, often the only way
 * to the functions it calls. Its paths are walked, nothing of them is kept but the
 * direct calls, queued as exploring them from a start did. Unlike exploring, it
 * covers nothing, so the same bytes can be walked again: a budget for the whole
 * analysis keeps a crafted file from spending minutes here (the corpus uses < 1%). */
#define PE32_REJECTED_BLOCKS 256
#define PE32_REJECTED_BUDGET (1u << 20)
static size_t pe32_rejected_calls(An *a, uint64_t start) {
    uint64_t block[PE32_REJECTED_BLOCKS];
    size_t   before = a->nfs;
    int      n = 0;
    block[n++] = start;
    for (int b = 0; b < n; b++) {
        uint64_t pc = block[b];
        for (int i = 0; i < PROBE_INSNS && a->rejected_insns < PE32_REJECTED_BUDGET; i++) {
            Step st;
            XMap *x = NULL;
            a->rejected_insns++;
            if (decode_at(a, pc, &x, &st) != DEC_OK) break;
            if ((st.flags & DI_CALL) && st.direct && st.target && !is_func(a, st.target) && xmap_of(a, st.target)) {
                a->rejected_insns += PROBE_INSNS;
                if (probe(a, st.target)) add_func(a, st.target, FN_CALL);
            }
            if ((st.flags & (DI_JUMP | DI_COND)) && st.direct && st.target && n < PE32_REJECTED_BLOCKS) {
                int k = 0;
                while (k < n && block[k] != st.target) k++;
                if (k == n) block[n++] = st.target;
            }
            if (st.end) break;
            pc += st.len;
        }
    }
    explore(a);
    return a->nfs - before;
}

/* scans [va, va + len) of one executable mapping for prologues in the
 * bytes no instruction covers; every hit is explored at once so the next
 * bytes it reaches are skipped. Returns the number of functions added. */
static size_t scan_gap_range(An *a, XMap *x, uint64_t va, uint64_t len) {
    const ElfFile *ef = &a->d->elf;
    const ElfMap  *m  = x->m;
    if (va < m->va) { uint64_t c = m->va - va; if (c >= len) return 0; va += c; len -= c; }
    if (va - m->va >= m->filesz) return 0;
    if (len > m->filesz - (va - m->va)) len = m->filesz - (va - m->va);
    if (m->off > ef->size || m->filesz > ef->size - m->off) return 0;

    const uint8_t *base = ef->data + m->off;
    size_t found = 0;
    for (uint64_t o = va - m->va, end = o + len; o < end; o++) {
        if (a->oom || a->d->capped) break;
        if (bit_get(x->cover, o)) continue;
        if (a->npd && pe_data_at(a, m->va + o)) {              /* PE data directory: skip it */
            uint64_t e = pe_data_end(a, m->va + o);
            if (e > m->va + o) o = e - m->va - 1;
            continue;
        }
        int k = prologue_kind(a->x32, base + o, (size_t)(end - o));
        if (!k && a->x32 && x32_pic_entry(a, m->va + o, base + o, (size_t)(end - o))) k = 2;
        if (!k) continue;
        bool aligned = ((m->va + o) & 15) == 0;
        bool after   = o == 0 || bit_get(x->cover, o - 1) || pad_byte(base[o - 1]);
        if (k == 2 ? !(aligned || after) : !(aligned && after)) continue;
        uint64_t pc = m->va + o;
        if (k == 1 && a->x32 && !x32_clean_entry(a, pc, base + o, (size_t)(end - o))) continue;
        /* PE32, `push r; call`: common in the middle of MSVC code (an argument). A 00
         * before it is more often the end of a displacement than padding, and such a
         * function start is rare: only after a path end or real padding. Once the
         * budget is spent pe32_rejected_calls walks nothing: no probe either, or
         * the time would still grow with the size of the code */
        if (k == 1 && a->x32 && a->d->elf.fmt == ELF_FMT_PE && o + 1 < end &&
            base[o] >= 0x50 && base[o] <= 0x57 && base[o + 1] == 0xe8 && o > 0 &&
            !bit_get(x->cover, o - 1) && base[o - 1] != 0xcc && base[o - 1] != 0x90) {
            if (a->rejected_insns < PE32_REJECTED_BUDGET && probe(a, pc)) found += pe32_rejected_calls(a, pc);
            continue;
        }
        if (!probe(a, pc)) continue;
        if (k == 1 && a->x32 && x32_jumps_inside(a, pc)) continue;
        size_t before = a->nfs;
        add_func(a, pc, FN_PROLOGUE);
        explore(a);
        found += a->nfs - before;
    }
    return found;
}

/* code sections (PLT stubs excluded: they are found through the imports
 * and the lazy-binding entries are not functions), or whole executable
 * mappings when there is no usable section table */
static void prologue_scan(An *a) {
    const ElfFile *ef = &a->d->elf;
    for (int pass = 0; pass < PROLOGUE_PASSES; pass++) {
        size_t found = 0;
        bool any_sec = false;
        for (int i = 0; i < ef->nsec; i++) {
            const ElfSection *s = &ef->sec[i];
            if (!(s->flags & X_SHF_EXECINSTR) || s->bad || s->type == 8 /* NOBITS */ || !s->size)
                continue;
            any_sec = true;
            if (plt_section(s->name)) continue;
            for (int k = 0; k < a->nxm; k++) found += scan_gap_range(a, &a->xm[k], s->addr, s->size);
        }
        if (!any_sec)
            for (int k = 0; k < a->nxm; k++)
                found += scan_gap_range(a, &a->xm[k], a->xm[k].m->va, a->xm[k].m->filesz);
        if (!found || a->oom || a->d->capped) break;
    }
}

/* PE32: the MSVC entry stub ends in `jmp __tmainCRTStartup` (the DLL one in `jmp
 * __DllMainCRTStartup`). No .pdata, nothing else shows that target is a function:
 * it would look like the entry's own .cold part. The straight path from the entry,
 * short by construction (bounded): its first direct jmp leaving it starts a
 * function. Uses a->in. */
#define PE32_ENTRY_INSNS 32
static void pe32_entry_tail(An *a) {
    const ElfFile *ef = &a->d->elf;
    size_t n = 0;
    const uint8_t *p = elf_va_ptr(ef, ef->entry, &n);
    uint64_t ad = ef->entry;
    if (!p) return;
    for (int i = 0; i < PE32_ENTRY_INSNS && n; i++) {
        if (!cs_disasm_iter(a->h, &p, &n, &ad, a->in)) return;
        const cs_insn *in = a->in;
        const cs_x86  *x  = &in->detail->x86;
        if (cs_insn_group(a->h, in, CS_GRP_RET)) return;
        if (in->id != X86_INS_JMP) continue;
        if (x->op_count != 1 || x->operands[0].type != X86_OP_IMM) return;
        uint64_t t = (uint64_t)(uint32_t)x->operands[0].imm;
        if ((t < ef->entry || t >= ad) && xmap_of(a, t) && is_decoded(a, t)) add_func(a, t, FN_CALL);
        return;
    }
}

/* ─── tail calls to functions nothing else marks ───────────────── */

static const ElfSymbol *func_symbol(const ElfFile *ef, uint64_t va, bool *exported);

/* A direct jmp / jcc to t, not a function start yet, makes t one
 * (FN_PROLOGUE) when t shows a prologue (strong, or weak and 16-byte
 * aligned after padding or the end of a path), nothing falls through
 * into t, t is not a .cold part, and a function start lies between the
 * jmp and t (t is outside the jmp's function): a function only reached
 * by a tail call, from a switch case for instance, which the prologue
 * scan does not see (already decoded). One pass over the instructions,
 * with the function starts sorted once. */
static void tail_scan(An *a) {
    Disasm *d = a->d;
    const ElfFile *ef = &d->elf;
    if (!a->nfs || !d->nins) return;
    uint64_t *st = malloc(a->nfs * sizeof *st);
    if (!st) { a->oom = true; return; }
    size_t ns = 0;
    for (size_t i = 0; i < a->nfs; i++) if (a->fs[i].kind != FN_DEAD) st[ns++] = a->fs[i].addr;
    if (ns) qsort(st, ns, sizeof *st, cmp_u64);
    for (size_t i = 0, nins = d->nins; i < nins && !a->oom && !d->capped; i++) {
        const DisInsn *in = &d->ins[i];
        uint64_t t = in->target, pc = in->addr;
        if (!(in->flags & (DI_JUMP | DI_COND)) || (in->flags & DI_INDIRECT) || !t || is_func(a, t))
            continue;
        XMap *x = xmap_of(a, t);
        if (!x) continue;
        uint64_t o = t - x->m->va;
        if (!bit_get(x->start, o) || bit_get(x->fall, o)) continue;
        size_t avail = 0;
        const uint8_t *p = elf_va_ptr(ef, t, &avail);
        int k = p ? prologue_kind(a->x32, p, avail) : 0;
        if (!k && p && a->x32 && x32_pic_entry(a, t, p, avail)) k = 2;
        if (!k) continue;
        if (k == 1 && ((t & 15) || !(o == 0 || bit_get(x->cover, o - 1) || pad_byte(p[-1]))))
            continue;
        if (k == 1 && a->x32 && !x32_clean_entry(a, t, p, avail)) continue;
        uint64_t lo = t < pc ? t : pc, hi = t < pc ? pc : t;   /* a start in (lo, hi] */
        size_t l = 0, h = ns;
        while (l < h) {
            size_t mid = l + (h - l) / 2;
            if (st[mid] <= lo) l = mid + 1; else h = mid;
        }
        if (l == ns || st[l] > hi) continue;
        bool exp;
        const ElfSymbol *sy = func_symbol(ef, t, &exp);
        if (sy && cold_name(sy->name)) continue;
        if (pe_data_at(a, t)) continue;
        add_func(a, t, FN_PROLOGUE);
    }
    free(st);
}

/* ─── code pointers in data ─────────────────────────────────────── */

static bool dp_section(const char *n) {
    return !strcmp(n, ".data") || !strcmp(n, ".data.rel.ro") ||
           !strcmp(n, ".rodata") || !strcmp(n, ".init_array") || !strcmp(n, ".rdata");
}

/* a word worth checking: it points into executable code (with a section
 * table: an executable section, not a PLT), and it is not an import GOT
 * slot (filled by the dynamic linker; the file holds a lazy-binding
 * address inside the PLT). Bounded by DA_MAX_QUEUE. */
static void dp_add(An *a, uint64_t slot, uint64_t t) {
    const ElfFile *ef = &a->d->elf;
    if (a->oom || !t || !xmap_of(a, t) || elf_import_got(ef, slot) || pe_data_at(a, t)) return;
    if (a->xsec) {
        const ElfSection *s = elf_section_at(ef, t);
        if (!s || !(s->flags & X_SHF_EXECINSTR) || s->bad || plt_section(s->name)) return;
    }
    if (a->ndp >= DA_MAX_QUEUE) { a->d->capped = true; return; }
    if (a->ndp == a->dpcap) {
        size_t nc = a->dpcap ? a->dpcap * 2 : 256;
        DPtr *n = realloc(a->dp, nc * sizeof *n);
        if (!n) { a->oom = true; return; }
        a->dp = n; a->dpcap = nc;
    }
    a->dp[a->ndp++] = (DPtr){ slot, t, slot, 1, false };
}

/* the aligned words of [va, va + size), 8 or 4 bytes (non-PIE: no relocation) */
static void dp_words(An *a, uint64_t va, uint64_t size, unsigned w) {
    if (size < w || va > UINT64_MAX - size || va > UINT64_MAX - (w - 1)) return;
    uint64_t end = va + size;                            /* >= w */
    size_t first = a->ndp;
    for (uint64_t s = (va + (w - 1)) & ~(uint64_t)(w - 1); s <= end - w; s += w) {
        uint64_t v;
        if (elf_read_ptr(&a->d->elf, s, &v)) dp_add(a, s, v);
        if (a->oom || a->d->capped) break;
    }
    if (w == 4) for (size_t i = first; i < a->ndp; i++) a->dp[i].raw = true;
}

static int cmp_dp(const void *x, const void *y) {
    const DPtr *p = x, *q = y;
    if (p->slot != q->slot) return p->slot < q->slot ? -1 : 1;
    return (int)p->raw - (int)q->raw;           /* same slot: the relocation wins */
}
static int cmp_u64(const void *x, const void *y) {
    uint64_t p = *(const uint64_t *)x, q = *(const uint64_t *)y;
    return p < q ? -1 : p > q;
}

/* PIE / shared object: the RELATIVE (RELA, RELR) relocations elfload
 * read, the addend is the target. Non-PIE executable: the words of the
 * data sections, or of the non-executable mappings without a section
 * table. x86-32: the value relocations of x32_relocs, any file type, and
 * the raw 4-byte words of a non-PIE ELF (the addresses are final; a PE has
 * relocations for them). Object files: nothing (their relocations are not read). Then sorted by
 * slot and cut into runs (slots one word apart). */
static void dp_data_words(An *a, unsigned w) {
    const ElfFile *ef = &a->d->elf;
    if (ef->nsec) {
        for (int i = 0; i < ef->nsec && !a->oom && !a->d->capped; i++) {
            const ElfSection *s = &ef->sec[i];
            if (!s->bad && s->type != X_SHT_NOBITS && dp_section(s->name))
                dp_words(a, s->addr, s->size, w);
        }
    } else {
        for (int i = 0; i < ef->nmap && !a->oom && !a->d->capped; i++)
            if (!(ef->map[i].flags & X_PF_X))
                dp_words(a, ef->map[i].va, ef->map[i].filesz, w);
    }
}

static void dp_collect(An *a) {
    const ElfFile *ef = &a->d->elf;
    if (a->x32) {
        for (size_t i = 0; i < a->nxr && !a->oom && !a->d->capped; i++) {
            const X32Rel *r = &a->xr[i];
            if (x32_rel_word(r->type) || r->type == R386_GOTOFF) dp_add(a, r->va, r->val);
        }
        if (ef->fmt == ELF_FMT_ELF && ef->type == X_ET_EXEC) dp_data_words(a, 4);
    } else if (ef->type == X_ET_DYN) {
        for (int i = 0; i < ef->nrel && !a->oom && !a->d->capped; i++)
            dp_add(a, ef->rel[i].va, ef->rel[i].addend);
    } else if (ef->type == X_ET_EXEC) {
        dp_data_words(a, 8);
        a->dpraw = true;
    }
    if (!a->ndp) return;
    qsort(a->dp, a->ndp, sizeof *a->dp, cmp_dp);
    size_t k = 0;                                        /* same slot twice */
    for (size_t i = 0; i < a->ndp; i++)
        if (!k || a->dp[i].slot != a->dp[k - 1].slot) a->dp[k++] = a->dp[i];
    a->ndp = k;
    unsigned w = a->x32 ? 4 : 8;                         /* word size */
    for (size_t i = 1; i < a->ndp; i++)
        if (a->dp[i].slot == a->dp[i - 1].slot + w) a->dp[i].run = a->dp[i - 1].run;
    for (size_t i = 0, j; i < a->ndp; i = j) {
        for (j = i + 1; j < a->ndp && a->dp[j].run == a->dp[i].run; j++) ;
        for (size_t t = i; t < j; t++) a->dp[t].len = (uint32_t)(j - i);
    }
}

static long dp_find_slot(const An *a, uint64_t slot) {
    size_t lo = 0, hi = a->ndp;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (a->dp[mid].slot < slot) lo = mid + 1; else hi = mid;
    }
    return lo < a->ndp && a->dp[lo].slot == slot ? (long)lo : -1;
}

/* Whether p is an entry of a switch jump table: a decoded `jmp
 * [reg*8+X]` reads its run, X being the run start or, for a switch
 * whose lowest case is not 0, up to 8 slots before it (and not a slot of
 * another run). */
static bool jt_covers(An *a, const DPtr *p) {
    if (!a->njt) return false;
    if (a->jtsorted != a->njt) {
        qsort(a->jt, a->njt, sizeof *a->jt, cmp_u64);
        a->jtsorted = a->njt;
    }
    size_t lo = 0, hi = a->njt;                          /* first X > slot */
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (a->jt[mid] <= p->slot) lo = mid + 1; else hi = mid;
    }
    if (!lo) return false;
    uint64_t x = a->jt[lo - 1];
    if (x >= p->run) return true;
    if (x + 64 < p->run) return false;
    long o = dp_find_slot(a, x);
    return o < 0 || a->dp[o].run == p->run;
}

/* Signs that a function starts at va. Strong: 16-byte aligned, start
 * of the mapping, or endbr64 / push rbp; mov rbp, rsp. Weak adds: the
 * bytes before it are not code running into it (end of a decoded path,
 * padding, ret). A relocated word is an address for sure, so the weak
 * signs are enough; a raw word may be an integer and needs a strong one. */
static bool start_sign(An *a, XMap *x, uint64_t va, bool raw) {
    const ElfFile *ef = &a->d->elf;
    uint64_t o = va - x->m->va;
    if (!(va & 15) || o == 0) return true;
    size_t avail = 0, pavail = 0;
    const uint8_t *p = elf_va_ptr(ef, va, &avail);
    if (p && prologue_kind(a->x32, p, avail) == 2) return true;
    if (p && a->x32 && x32_pic_entry(a, va, p, avail)) return true;
    if (raw) return false;
    bool start = bit_get(x->start, o), prev = bit_get(x->cover, o - 1);
    if (start != prev) return true;        /* decoded after undecoded bytes,
                                              or undecoded after a path end */
    const uint8_t *q = elf_va_ptr(ef, va - 1, &pavail);
    return !prev && q && pad_byte(*q);
}

/* A run is taken as a table of functions when at least 3/4 of its
 * entries show a start sign (vtables, callback arrays: every entry is a
 * function; the case labels of a switch table seldom are aligned). Its
 * entries then need no sign of their own. */
static bool table_sign(An *a, size_t first) {
    const DPtr *p = &a->dp[first];
    size_t n = 0, len = p->len;
    for (size_t i = first; i < first + len && i < a->ndp; i++) {
        XMap *x = xmap_of(a, a->dp[i].target);
        if (x && start_sign(a, x, a->dp[i].target, a->dpraw || a->dp[i].raw)) n++;
    }
    return 4 * n >= 3 * len;
}

/* Whether the target of p is taken as a function, the code reachable
 * from what is known being already decoded:
 *  - not when p is in a switch jump table;
 *  - not inside an instruction already decoded, nor at an instruction
 *    reached by falling through another one (a label inside a body);
 *  - an instruction start already decoded is taken (in sync), anything
 *    else only if the linear decode from it is clean (probe);
 *  - outside a table taken as such, a start sign is also needed. */
static bool dataptr_ok(An *a, const DPtr *p, bool table) {
    uint64_t va = p->target;
    XMap *x = xmap_of(a, va);
    if (!x || jt_covers(a, p)) return false;
    if (a->d->elf.fmt == ELF_FMT_PE && dp_find_slot(a, va) >= 0)
        return false;                                  /* PE: a relocated word is data (a table) */
    /* PE32: the slot is the displacement of `jmp [reg*4 + X]` (ff 24 85+r*8), reached or
     * not: an operand, not a code pointer, even when X is code (the MSVC memcpy indexes
     * its tables backwards: `sub ecx, 4; jmp [ecx*4 + X]`, X the end of the table) */
    if (a->x32 && a->d->elf.fmt == ELF_FMT_PE) {
        size_t sn = 0;
        const uint8_t *sb = p->slot >= 3 ? elf_va_ptr(&a->d->elf, p->slot - 3, &sn) : NULL;
        if (sb && sn >= 3 && sb[0] == 0xff && sb[1] == 0x24 && (sb[2] & 0xc7) == 0x85) return false;
    }
    uint64_t o = va - x->m->va;
    bool start = bit_get(x->start, o);
    if (start ? bit_get(x->fall, o) : bit_get(x->cover, o)) return false;
    if (!table && !start_sign(a, x, va, a->dpraw || p->raw)) return false;
    return start || probe(a, va);
}

static long seed_index(const An *a, uint64_t va) {
    if (!a->hcap) return -1;
    size_t i = hslot(a, va);
    return a->hk[i] == va ? (long)a->hv[i] : -1;
}

/* lone pointers first (each one explored before the next is checked),
 * then the runs, so that the switch code reading a table is more likely
 * decoded before the table is looked at. Whether a run is a table of
 * functions is decided once, before any of its entries is explored; a
 * run that is not (most likely a switch table whose jmp was not reached)
 * gives nothing, not even its aligned entries. */
static void dataptr_scan(An *a) {
    dp_collect(a);
    for (int runs = 0; runs < 2; runs++) {
        bool table = false;
        for (size_t i = 0; i < a->ndp && !a->oom && !a->d->capped; i++) {
            const DPtr *p = &a->dp[i];
            if ((p->len > 1) != runs) continue;
            if (runs && p->slot == p->run) table = table_sign(a, i);
            if ((runs && !table) || is_func(a, p->target) || !dataptr_ok(a, p, runs))
                continue;
            uint8_t kind = a->x32 ? FN_CODEPTR : FN_DATAPTR;
            add_func(a, p->target, kind);
            long s = seed_index(a, p->target);
            if (s >= 0 && a->fs[s].kind == kind) a->fs[s].dp = (uint32_t)i;
            explore(a);
        }
    }
}

/* Once everything is decoded: a FN_DATAPTR function is dropped when the
 * code decoded after it was accepted shows it is not one, i.e. an
 * instruction falls through into it, or every slot pointing to it lies
 * in a jump table whose jmp was found later. Its instructions stay. */
static void dataptr_recheck(An *a) {
    for (size_t i = 0; i < a->nfs; i++) {
        FnSeed *f = &a->fs[i];
        if (f->kind != (a->x32 ? FN_CODEPTR : FN_DATAPTR) || f->dp >= a->ndp) continue;
        XMap *x = xmap_of(a, f->addr);
        bool drop = x && bit_get(x->fall, f->addr - x->m->va);
        if (!drop && jt_covers(a, &a->dp[f->dp])) {
            drop = true;
            for (size_t j = 0; j < a->ndp && drop; j++)
                if (a->dp[j].target == f->addr && !jt_covers(a, &a->dp[j])) drop = false;
        }
        if (drop) f->kind = FN_DEAD;
    }
}

/* ─── finishing ─────────────────────────────────────────────────── */

static int cmp_ins(const void *x, const void *y) {
    const DisInsn *p = x, *q = y;
    return p->addr < q->addr ? -1 : p->addr > q->addr;
}
static int cmp_seed(const void *x, const void *y) {
    const FnSeed *p = x, *q = y;
    return p->addr < q->addr ? -1 : p->addr > q->addr;
}
static int cmp_jref(const void *x, const void *y) {
    const JRef *p = x, *q = y;
    if (p->pc != q->pc) return p->pc < q->pc ? -1 : 1;
    return p->va < q->va ? -1 : p->va > q->va;
}
static int cmp_jread(const void *x, const void *y) {
    const JRead *p = x, *q = y;
    return p->base < q->base ? -1 : p->base > q->base;
}
static int cmp_plt(const void *x, const void *y) {
    const PltRef *p = x, *q = y;
    return p->stub < q->stub ? -1 : p->stub > q->stub;
}

/* a global untyped .symtab symbol inside a code section: an assembly
 * label without `.type`, listed as T by nm (linker markers such as
 * etext sit at the end of a section and are not taken) */
static bool code_label(const ElfFile *ef, const ElfSymbol *s) {
    if (s->kind != ELF_SYM_OTHER || s->dynamic || s->bind == 0) return false;
    const ElfSection *sec = elf_section_at(ef, s->value);
    return sec && (sec->flags & X_SHF_EXECINSTR) && elf_va_exec(ef, s->value);
}

/* best function symbol at va (the table puts FUNC, .symtab, global
 * first), else a code label */
static const ElfSymbol *func_symbol(const ElfFile *ef, uint64_t va, bool *exported) {
    const ElfSymbol *s = elf_symbol_at(ef, va), *best = NULL, *label = NULL;
    *exported = false;
    for (; s && s < ef->sym + ef->nsym && s->value == va; s++) {
        if (s->kind == ELF_SYM_FUNC) { if (!best) best = s; }
        else if (!label && code_label(ef, s)) label = s;
        else continue;
        if (s->exported) *exported = true;
    }
    return best ? best : label;
}

/* first jump table edge from the jmp at pc (a->je sorted), or a->nje */
static size_t je_first(const An *a, uint64_t pc) {
    size_t lo = 0, hi = a->nje;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (a->je[mid].pc < pc) lo = mid + 1; else hi = mid;
    }
    return lo;
}

/* Owners are given in levels: what is reached across no call, then one
 * more call each level (dq[0 .. nd): index, function), then what follows
 * a call that does not return but was decoded before that was known
 * (dq[nl .. cap), filled downwards). Each instruction is expanded once
 * and adds at most one entry: cap = nins entries is enough. */
typedef struct {
    uint32_t *dq;
    size_t    nd, nl, cap;
} OwnQ;

/* Gives the instructions reached from d->ins[s0] to function f, without
 * entering another function's start nor what has an owner already. The
 * instruction after a call is not followed but queued in q (without q:
 * followed, after a returning call only). stk: room for 2 pushes per
 * instruction plus one per jump table edge (each instruction is
 * expanded once, all calls together). */
static void own_from(An *a, uint32_t *stk, size_t s0, uint32_t f, OwnQ *q) {
    Disasm *d = a->d;
    size_t sp = 0;
    stk[sp++] = (uint32_t)s0;
    while (sp) {
        size_t   i = stk[--sp];
        DisInsn *n = &d->ins[i];
        if (n->func != DA_NOFUNC) continue;
        if (n->addr != d->fn[f].addr && da_func_at(d, n->addr) >= 0) continue;
        n->func = f;
        if (!(n->flags & (DI_JUMP | DI_RET | DI_STOP)) &&
            i + 1 < d->nins && d->ins[i + 1].addr == n->addr + n->len) {
            if (q && (n->flags & DI_CALL) && q->nd < q->nl) {
                size_t k = (n->flags & DI_NORET) ? --q->nl : q->nd++;
                q->dq[2 * k] = (uint32_t)(i + 1);
                q->dq[2 * k + 1] = f;
            } else if (!(n->flags & DI_NORET)) {
                stk[sp++] = (uint32_t)(i + 1);
            }
        }
        if ((n->flags & (DI_JUMP | DI_COND)) && !(n->flags & DI_INDIRECT) && n->target) {
            long t = da_insn_at(d, n->target);
            if (t >= 0) stk[sp++] = (uint32_t)t;
        }
        if ((n->flags & DI_JUMP) && (n->flags & DI_INDIRECT))
            for (size_t e = je_first(a, n->addr); e < a->nje && a->je[e].pc == n->addr; e++) {
                long t = da_insn_at(d, a->je[e].va);
                if (t >= 0) stk[sp++] = (uint32_t)t;
            }
    }
}

/* Functions that never return, besides the names known (exit, abort...):
 * no path from the start reaches a ret, an indirect jmp other than a
 * switch read, a jump to code not decoded, the end of the decoded code,
 * or a function start (tail call, falling into it) that may return. A
 * path ends at hlt / ud2 / int3 and at a direct call to a function that
 * does not return. Rounds until nothing changes (each one can only add
 * functions), at most NORET_ROUNDS, all of them NORET_STEPS * nins
 * expansions at most (a judgement made is sound either way). The direct
 * calls to them become DI_NORET. stk: 2 * nins + nje + 1 entries; vis:
 * nins at least. */
static void noreturn_infer(An *a, uint32_t *stk, uint32_t *vis) {
    Disasm *d = a->d;
    uint64_t budget = (uint64_t)NORET_STEPS * d->nins;
    for (int round = 0; round < NORET_ROUNDS && budget; round++) {
        bool changed = false;
        memset(vis, 0, d->nins * sizeof *vis);
        for (size_t f = 0; f < d->nfn && budget; f++) {
            if (d->fn[f].noreturn) continue;
            long s0 = da_insn_at(d, d->fn[f].addr);
            if (s0 < 0) continue;
            bool ret = false;
            size_t sp = 0;
            stk[sp++] = (uint32_t)s0;
            while (sp && !ret && budget) {
                budget--;
                size_t i = stk[--sp];
                const DisInsn *n = &d->ins[i];
                if (vis[i] == f + 1) continue;
                vis[i] = (uint32_t)f + 1;
                long g = i != (size_t)s0 ? da_func_at(d, n->addr) : -1;
                if (g >= 0) { ret = !d->fn[g].noreturn; continue; }
                if (n->flags & DI_RET) { ret = true; continue; }
                if (n->flags & (DI_STOP | DI_NORET)) continue;
                if ((n->flags & DI_CALL) && !(n->flags & DI_INDIRECT) && n->target &&
                    (g = da_func_at(d, n->target)) >= 0 && d->fn[g].noreturn)
                    continue;
                if ((n->flags & DI_JUMP) && (n->flags & DI_INDIRECT)) {
                    size_t e = je_first(a, n->addr);
                    if (e == a->nje || a->je[e].pc != n->addr) { ret = true; continue; }
                    for (; e < a->nje && a->je[e].pc == n->addr; e++) {
                        long t = da_insn_at(d, a->je[e].va);
                        if (t >= 0) stk[sp++] = (uint32_t)t;
                    }
                    continue;
                }
                if ((n->flags & (DI_JUMP | DI_COND)) && !(n->flags & DI_INDIRECT)) {
                    long t = n->target ? da_insn_at(d, n->target) : -1;
                    if (t < 0) { ret = true; continue; }
                    stk[sp++] = (uint32_t)t;
                }
                if (!(n->flags & DI_JUMP)) {
                    if (i + 1 < d->nins && d->ins[i + 1].addr == n->addr + n->len)
                        stk[sp++] = (uint32_t)(i + 1);
                    else
                        ret = true;
                }
            }
            if (!ret && budget) { d->fn[f].noreturn = true; changed = true; }
        }
        if (!changed) break;
    }
    for (size_t i = 0; i < d->nins; i++) {
        DisInsn *n = &d->ins[i];
        long g;
        if ((n->flags & DI_CALL) && !(n->flags & DI_INDIRECT) && n->target &&
            (g = da_func_at(d, n->target)) >= 0 && d->fn[g].noreturn)
            n->flags |= DI_NORET;
    }
}

/* names, owners, sizes, counters */
/* instructions [b, e) are all padding: int3, nop (90, 66 90, 0f 1f /0
 * with prefixes 66 / 2e) */
static bool pad_run(const ElfFile *ef, const DisInsn *b, const DisInsn *e) {
    for (; b < e; b++) {
        size_t av = 0;
        const uint8_t *p = elf_va_ptr(ef, b->addr, &av);
        if (!p || av < b->len) return false;
        size_t k = 0;
        while (k < b->len && (p[k] == 0x66 || p[k] == 0x2e)) k++;
        bool pad = (b->len == 1 && (p[0] == 0xcc || p[0] == 0x90)) ||
                   (k + 1 == b->len && p[k] == 0x90) ||
                   (k + 2 < b->len && p[k] == 0x0f && p[k + 1] == 0x1f && ((p[k + 2] >> 3) & 7) == 0);
        if (!pad) return false;
    }
    return true;
}

static bool finalize(An *a) {
    Disasm  *d  = a->d;
    ElfFile *ef = &d->elf;

    if (d->nins) qsort(d->ins, d->nins, sizeof *d->ins, cmp_ins);
    /* A table ends where the next table read starts (two switches of one
     * function may have adjacent tables: reading the first one runs into
     * the cases of the second, the same function's code, decoded either
     * way). The edges past that end are dropped (pc = UINT64_MAX, sorted
     * last). A table read by several jmps counts once. */
    if (a->njr) qsort(a->jr, a->njr, sizeof *a->jr, cmp_jread);
    for (size_t i = 0, j; i < a->njr; i = j) {
        for (j = i + 1; j < a->njr && a->jr[j].base == a->jr[i].base; j++) ;
        d->njtab++;
        uint64_t gap = j < a->njr ? a->jr[j].base - a->jr[i].base : UINT64_MAX;
        for (size_t k = i; k < j; k++)
            for (size_t e = gap / a->jr[k].esz; e < a->jr[k].n; e++)
                a->je[a->jr[k].e0 + e].pc = UINT64_MAX;
    }
    if (a->nje) {                                /* sorted, without repeats */
        qsort(a->je, a->nje, sizeof *a->je, cmp_jref);
        size_t k = 0;
        for (size_t i = 0; i < a->nje && a->je[i].pc != UINT64_MAX; i++)
            if (!k || cmp_jref(&a->je[i], &a->je[k - 1])) a->je[k++] = a->je[i];
        a->nje = k;
    }
    size_t live = 0;                             /* drop FN_DEAD seeds */
    for (size_t i = 0; i < a->nfs; i++)
        if (a->fs[i].kind != FN_DEAD) a->fs[live++] = a->fs[i];
    a->nfs = live;
    if (a->nfs)  qsort(a->fs, a->nfs, sizeof *a->fs, cmp_seed);

    d->fn = calloc(a->nfs ? a->nfs : 1, sizeof *d->fn);
    if (!d->fn) return false;
    for (size_t i = 0; i < a->nfs; i++) {
        DisFunc *f = &d->fn[i];
        f->addr = a->fs[i].addr;
        f->kind = a->fs[i].kind;
        bool exp = false;
        const ElfSymbol *s  = func_symbol(ef, f->addr, &exp);
        const PltRef    *im = plt_import(a, f->addr);
        char buf[160];
        if (s) {
            snprintf(buf, sizeof buf, "%s", s->name);
            f->kind = s->dynamic ? FN_DYNSYM : FN_SYMTAB;
            f->size = s->size;
        } else if (im) {
            snprintf(buf, sizeof buf, ef->fmt == ELF_FMT_PE ? "%s" : "%s@plt", im->name);
            f->kind = FN_PLT;
        } else if (f->kind == FN_MAIN) {
            snprintf(buf, sizeof buf, "main");
        } else {
            snprintf(buf, sizeof buf, "sub_%llx", (unsigned long long)f->addr);
        }
        if (!f->size && a->rf.n) {               /* PE x64: the .pdata range */
            const PeRtFunc *r = pdata_func(a, f->addr);
            if (r) f->size = r->end - r->begin;
        }
        f->exported = exp;
        f->noreturn = name_noreturn(s ? s->name : im ? im->name : NULL);
        if (!(f->name = strdup(buf))) { d->nfn = i; return false; }
    }
    d->nfn = a->nfs;

    /* owners: from each function start, follow fall-through, direct
     * jumps and the cases of a jump table without entering another
     * function's start. The code after a call that does not return (by
     * name, or inferred) is not followed. An instruction goes to the
     * function reaching it across the fewest calls (the call may still
     * not return), then to the lowest one: otherwise the .cold part of
     * f, laid out after the .cold part of a lower function that ends in
     * such a call, would go to that function instead of f, whose jumps
     * reach it. .cold symbols left without an owner (their jump not
     * decoded) go to the function of the same name without the suffix. */
    uint32_t *stk = NULL;
    OwnQ q = { NULL, 0, d->nins, d->nins };
    if (d->nins) {
        stk  = malloc((2 * d->nins + a->nje + 1) * sizeof *stk);
        q.dq = malloc(2 * d->nins * sizeof *q.dq);
        if (!stk || !q.dq) { free(stk); free(q.dq); return false; }
        noreturn_infer(a, stk, q.dq);
    }
    for (size_t f = 0; f < d->nfn && d->nins; f++) {
        long s0 = da_insn_at(d, d->fn[f].addr);
        if (s0 >= 0) own_from(a, stk, (size_t)s0, (uint32_t)f, &q);
    }
    for (size_t kn = 0, kl = q.cap;;) {          /* one more call crossed, */
        size_t k;                                /* else after a no-return */
        if (kn < q.nd)      k = kn++;            /* call                   */
        else if (kl > q.nl) k = --kl;
        else break;
        own_from(a, stk, q.dq[2 * k], q.dq[2 * k + 1], &q);
    }
    free(q.dq);
    size_t ncold = 0;                            /* name lookups, bounded */
    for (int i = 0; i < ef->nsym && d->nins && ncold < COLD_LOOKUPS; i++) {
        const ElfSymbol *sy = &ef->sym[i];
        if (sy->kind != ELF_SYM_FUNC || sy->dynamic || !cold_name(sy->name)) continue;
        long s0 = da_insn_at(d, sy->value);
        if (s0 < 0 || d->ins[s0].func != DA_NOFUNC || da_func_at(d, sy->value) >= 0) continue;
        ncold++;
        const char *c = strstr(sy->name + 1, ".cold"), *nx;
        while ((nx = strstr(c + 1, ".cold"))) c = nx;
        char parent[256];
        snprintf(parent, sizeof parent, "%.*s", (int)(c - sy->name), sy->name);
        long f = da_func_named(d, parent);
        if (f >= 0) own_from(a, stk, (size_t)s0, (uint32_t)f, NULL);
    }
    for (uint32_t i = 0; i < a->rf.n && d->nins; i++) {   /* PE x64: .pdata fragments */
        const PeRtFunc *r = &a->rf.e[i];               /* nothing reached: */
        if (!(r->flags & PE_RF_FRAG) || !r->parent) continue;   /* to their parent */
        long s0 = da_insn_at(d, pe_rva_to_va(ef, r->begin));
        long f = da_func_at(d, pe_rva_to_va(ef, r->parent));
        if (s0 >= 0 && f >= 0 && d->ins[s0].func == DA_NOFUNC) own_from(a, stk, (size_t)s0, (uint32_t)f, NULL);
    }
    free(stk);
    for (size_t e = 0; e < a->nje; e++) {        /* cases are branch targets */
        long t = da_insn_at(d, a->je[e].va);
        if (t >= 0) d->ins[t].flags |= DI_TARGET;
    }

    /* counters, branch targets, extents (the part of a function between
     * its start and the next function; .cold parts are not counted) */
    uint64_t *ext = calloc(d->nfn ? d->nfn : 1, sizeof *ext);
    if (!ext) return false;
    for (size_t i = 0; i < d->nins; i++) {
        DisInsn *n = &d->ins[i];
        if (n->func != DA_NOFUNC) {
            DisFunc *f = &d->fn[n->func];
            f->ninsn++;
            uint64_t lim = n->func + 1 < d->nfn ? d->fn[n->func + 1].addr : UINT64_MAX;
            if (n->addr >= f->addr && n->addr < lim && n->addr + n->len > ext[n->func])
                ext[n->func] = n->addr + n->len;
        }
        if ((n->flags & (DI_CALL | DI_JUMP | DI_COND)) && !(n->flags & DI_INDIRECT) && n->target) {
            long t = da_insn_at(d, n->target);
            if (t >= 0) d->ins[t].flags |= DI_TARGET;
            /* a call, or a tail call: a jmp or jcc to another function's
             * start (one to its own start is a loop) */
            long g = da_func_at(d, n->target);
            if (g >= 0 && ((n->flags & DI_CALL) || n->func != (uint32_t)g))
                d->fn[g].ncallers++;
        }
    }
    for (size_t f = 0; f < d->nfn; f++)
        if (!d->fn[f].size && ext[f] > d->fn[f].addr) d->fn[f].size = ext[f] - d->fn[f].addr;
    free(ext);

    /* the part of a function outside its body: the longest run of its
     * instructions outside [addr, addr + size), each one at most
     * COLD_GAP bytes after the previous one, no other decoded
     * instruction between them */
    for (size_t i = 0, j; i < d->nins; i = j) {
        const DisInsn *n = &d->ins[i];
        j = i + 1;
        if (n->func == DA_NOFUNC) continue;
        DisFunc *f = &d->fn[n->func];
        if (!f->size || n->addr - f->addr < f->size) continue;
        uint64_t end = n->addr + n->len;
        for (; j < d->nins && d->ins[j].func == n->func && d->ins[j].addr - end <= COLD_GAP &&
               d->ins[j].addr - f->addr >= f->size; j++)
            end = d->ins[j].addr + d->ins[j].len;
        if (a->rf.n && pad_run(ef, d->ins + i, d->ins + j)) continue;   /* PE x64: int3 / nop after the .pdata end */
        if (end - n->addr > f->cold_size) { f->cold = n->addr; f->cold_size = end - n->addr; }
    }
    return true;
}

/* ─── entry points ──────────────────────────────────────────────── */

static bool an_init(An *a) {
    Disasm  *d  = a->d;
    ElfFile *ef = &d->elf;
    if (!(a->in = cs_malloc(a->h))) return false;

    a->xm = calloc(ef->nmap ? (size_t)ef->nmap : 1, sizeof *a->xm);
    if (!a->xm) return false;
    for (int i = 0; i < ef->nmap; i++) {
        const ElfMap *m = &ef->map[i];
        if (!(m->flags & X_PF_X) || !m->filesz) continue;
        XMap *x = &a->xm[a->nxm++];
        x->m     = m;
        x->start = calloc((size_t)(m->filesz / 8 + 1), 1);
        x->cover = calloc((size_t)(m->filesz / 8 + 1), 1);
        x->fall  = calloc((size_t)(m->filesz / 8 + 1), 1);
        x->fstart = calloc((size_t)(m->filesz / 8 + 1), 1);
        if (!x->start || !x->cover || !x->fall || !x->fstart) return false;
        d->code_bytes += m->filesz;
    }

    for (int i = 0; i < ef->nsec; i++) {
        const ElfSection *s = &ef->sec[i];
        if ((s->flags & X_SHF_EXECINSTR) && !s->bad && s->type != 8 /* NOBITS */ && s->size)
            a->xsec = true;
    }

    PeHeaders ph;                                 /* PE: data directory ranges */
    if (ef->fmt == ELF_FMT_PE && pe_read_headers(ef->data, ef->size, &ph, NULL, 0)) {
        a->pd = malloc(PE_NDIR * sizeof *a->pd);
        if (!a->pd) return false;
        for (unsigned i = 0; i < ph.ndir; i++) {
            const PeDir *e = &ph.dir[i];
            if (i == 4 || !e->rva || !e->size || (uint64_t)e->rva + e->size > ph.size_image) continue;
            a->pd[a->npd][0] = ph.image_base + e->rva;      /* SECURITY (4) is a file offset */
            a->pd[a->npd][1] = ph.image_base + e->rva + e->size;
            a->npd++;
        }
        qsort(a->pd, a->npd, sizeof *a->pd, cmp_u64);       /* by lo (first word) */
        size_t k = 0;                                       /* overlapping ones merged */
        for (size_t i = 0; i < a->npd; i++) {
            if (k && a->pd[i][0] <= a->pd[k - 1][1]) {
                if (a->pd[i][1] > a->pd[k - 1][1]) a->pd[k - 1][1] = a->pd[i][1];
            } else { a->pd[k][0] = a->pd[i][0]; a->pd[k][1] = a->pd[i][1]; k++; }
        }
        a->npd = k;
    }
    if (ef->fmt == ELF_FMT_PE && pe_pdata(ef, &a->rf) && a->rf.nfrag) {
        a->frag = malloc(a->rf.nfrag * sizeof *a->frag);
        if (!a->frag) return false;
        for (uint32_t i = 0; i < a->rf.n; i++)          /* sorted: rf is */
            if (a->rf.e[i].flags & PE_RF_FRAG) a->frag[a->nfrag++] = pe_rva_to_va(ef, a->rf.e[i].begin);
    }

    size_t pcap = ef->nimp ? (size_t)ef->nimp : 1;
    a->plt = malloc(pcap * sizeof *a->plt);
    if (!a->plt) return false;
    for (int i = 0; i < ef->nimp; i++)
        if (ef->imp[i].plt) a->plt[a->nplt++] = (PltRef){ ef->imp[i].plt, &ef->imp[i], ef->imp[i].name };
    if (a->x32) {                                 /* see x32_relocs, x32_plt */
        x32_relocs(a);
        x32_plt(a, &pcap);
        if (a->oom) return false;
    }
    if (a->nplt) qsort(a->plt, a->nplt, sizeof *a->plt, cmp_plt);
    return true;
}

static void an_free(An *a) {
    if (a->in) cs_free(a->in, 1);
    for (int i = 0; i < a->nxm; i++) {
        free(a->xm[i].start); free(a->xm[i].cover); free(a->xm[i].fall); free(a->xm[i].fstart);
    }
    free(a->xm); free(a->q); free(a->fs); free(a->hk); free(a->hv); free(a->plt);
    free(a->cp); free(a->dp); free(a->jt); free(a->jq); free(a->jqu); free(a->je); free(a->lt); free(a->jr);
    free(a->xr); free(a->xh); free(a->pd); free(a->frag);
    pe_pdata_free(&a->rf);
}

/* PE seeds from the exception and load config tables. The chained
 * .pdata fragments are queued as code with the other seeds (their owner
 * is the parent function, see finalize). The language handlers of
 * UNWIND_INFO (x64), the SafeSEH handlers (x86) and the CFG function
 * table entries are checked once the code reachable from the seeds has
 * been walked, each one as a lea target is (codeptr_ok: not inside an
 * instruction already decoded, clean linear decode), and walked at once:
 * FN_SEH, FN_GUARD. A corrupt table then gives no start in the middle of
 * known code. They come before the code pointers and the guesses. */
static void pe_frag_seeds(An *a) {
    for (size_t i = 0; i < a->nfrag; i++) push(a, a->frag[i]);
}

static void pe_table_seed(An *a, uint64_t va, uint8_t kind) {
    if (a->oom || a->d->capped || !codeptr_ok(a, va)) return;
    add_func(a, va, kind);
    walk(a);
}

static void pe_table_seeds(An *a) {
    const ElfFile *ef = &a->d->elf;
    for (uint32_t i = 0; i < a->rf.n; i++)
        if (a->rf.e[i].handler) pe_table_seed(a, pe_rva_to_va(ef, a->rf.e[i].handler), FN_SEH);
    PeTable t;
    if (pe_safeseh(ef, &t))
        for (uint32_t i = 0; i < t.n; i++) pe_table_seed(a, t.va[i], FN_SEH);
    pe_table_free(&t);
    if (pe_guard_cf(ef, &t))
        for (uint32_t i = 0; i < t.n; i++) pe_table_seed(a, t.va[i], FN_GUARD);
    pe_table_free(&t);
}

bool da_analyze(Disasm *d, const char *path, char *err, size_t esz) {
    if (!d || !path) { set_err(err, esz, "bad arguments"); return false; }
    memset(d, 0, sizeof *d);
    if (!elf_load(&d->elf, path, err, esz)) return false;
    if (d->elf.arch != ELF_ARCH_X86_64 && d->elf.arch != ELF_ARCH_X86_32) {
        set_err(err, esz, "unsupported architecture (%s)", elf_machine_name(d->elf.machine));
        da_free(d);
        return false;
    }
    if (!da_open(d, err, esz)) { da_free(d); return false; }

    An a = { 0 };
    a.d = d;
    a.h = (csh)d->cs;
    a.x32 = d->elf.arch == ELF_ARCH_X86_32;
    bool ok = an_init(&a);
    if (ok) {
        const ElfFile *ef = &d->elf;
        /* seeds: what is known to be a function */
        add_func(&a, ef->entry, FN_ENTRY);
        for (int i = 0; i < ef->nsym; i++) {
            const ElfSymbol *sy = &ef->sym[i];
            if (sy->kind == ELF_SYM_FUNC && !sy->dynamic && cold_name(sy->name) &&
                elf_va_exec(ef, sy->value))
                push(&a, sy->value);             /* code of its function, not one */
            else if ((sy->kind == ELF_SYM_FUNC && elf_va_exec(ef, sy->value)) || code_label(ef, sy)) {
                /* a PE export in code is a function only if it decodes
                 * cleanly (exported data can sit in .text) */
                if (ef->fmt == ELF_FMT_PE && sy->dynamic && !probe(&a, sy->value)) continue;
                add_func(&a, sy->value, sy->dynamic ? FN_DYNSYM : FN_SYMTAB);
            }
        }
        for (size_t i = 0; i < a.nplt; i++) add_func(&a, a.plt[i].stub, FN_PLT);
        for (int i = 0; i < ef->nctors; i++) add_func(&a, ef->ctors[i], FN_CTOR);
        for (int i = 0; i < ef->nfstart; i++) add_func(&a, ef->fstart[i], FN_PDATA);
        if (ef->fmt == ELF_FMT_PE) {
            pe_frag_seeds(&a);
            walk(&a);
            pe_table_seeds(&a);
        }
        explore(&a);
        /* then the code pointers stored in data (x86-64 only for now:
         * 8-byte words), then what nothing points to (prologues), then
         * the functions reached only by a tail jmp. Not in an IL-only
         * .NET assembly: besides the entry stub its code is CIL bytecode,
         * which these guesses would decode as x86. */
        uint32_t clr = 0;
        bool ilonly = ef->fmt == ELF_FMT_PE && ef->pe.dotnet && pe_clr_flags(ef, &clr) && (clr & PE_CLR_ILONLY);
        if (!a.oom && !d->capped && !ilonly && a.x32 && ef->fmt == ELF_FMT_PE && ef->entry) {
            pe32_entry_tail(&a);
            explore(&a);
        }
        if (!a.oom && !d->capped && !ilonly) dataptr_scan(&a);
        if (!a.oom && !d->capped && !ilonly) prologue_scan(&a);
        if (!a.oom && !d->capped && !ilonly) tail_scan(&a);
        dataptr_recheck(&a);
        ok = !a.oom && finalize(&a);
    }
    an_free(&a);
    if (!ok) {
        set_err(err, esz, "out of memory");
        da_free(d);
        return false;
    }
    return true;
}

void da_free(Disasm *d) {
    if (!d) return;
    for (size_t i = 0; i < d->nfn; i++) free(d->fn[i].name);
    free(d->fn);
    free(d->ins);
    da_close(d);
    elf_free(&d->elf);
    memset(d, 0, sizeof *d);
}

void da_set_att(Disasm *d, bool att) {
    if (!d || !d->cs) return;
    if (cs_option((csh)d->cs, CS_OPT_SYNTAX, att ? CS_OPT_SYNTAX_ATT : CS_OPT_SYNTAX_INTEL) == CS_ERR_OK)
        d->att = att;
}

/* ─── lookups ───────────────────────────────────────────────────── */

long da_insn_floor(const Disasm *d, uint64_t addr) {
    if (!d || !d->nins) return -1;
    size_t lo = 0, hi = d->nins;                 /* first start > addr */
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (d->ins[mid].addr <= addr) lo = mid + 1; else hi = mid;
    }
    return lo ? (long)(lo - 1) : -1;
}

long da_insn_at(const Disasm *d, uint64_t addr) {
    long i = da_insn_floor(d, addr);
    return (i >= 0 && d->ins[i].addr == addr) ? i : -1;
}

static long func_floor(const Disasm *d, uint64_t addr) {
    if (!d || !d->nfn) return -1;
    size_t lo = 0, hi = d->nfn;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (d->fn[mid].addr <= addr) lo = mid + 1; else hi = mid;
    }
    return lo ? (long)(lo - 1) : -1;
}

long da_func_at(const Disasm *d, uint64_t addr) {
    long i = func_floor(d, addr);
    return (i >= 0 && d->fn[i].addr == addr) ? i : -1;
}

long da_func_named(const Disasm *d, const char *name) {
    if (!d || !name) return -1;
    for (size_t i = 0; i < d->nfn; i++)
        if (d->fn[i].name && !strcmp(d->fn[i].name, name)) return (long)i;
    return -1;
}

long da_func_containing(const Disasm *d, uint64_t addr) {
    long i = da_insn_floor(d, addr);
    if (i >= 0 && addr - d->ins[i].addr < d->ins[i].len && d->ins[i].func != DA_NOFUNC)
        return (long)d->ins[i].func;
    long f = func_floor(d, addr);
    if (f >= 0 && addr - d->fn[f].addr < d->fn[f].size) return f;
    return -1;
}

const char *da_name_for(const Disasm *d, uint64_t addr, char *buf, size_t sz) {
    if (!d || !buf || !sz) return NULL;
    long f = da_func_at(d, addr);
    if (f >= 0) { snprintf(buf, sz, "%s", d->fn[f].name); return buf; }
    const ElfImport *im = elf_import_got(&d->elf, addr);
    bool pe = d->elf.fmt == ELF_FMT_PE;
    if (im && pe) {                              /* IAT slot: "dll!function" */
        /* ElfImport.version holds the DLL name cut at 31 characters: the
         * full one from the needed list when only one starts that way */
        const char *dll = im->version, *full = NULL;
        size_t vl = strlen(dll), fl = 0;
        bool cut = vl == sizeof im->version - 1, amb = false;
        for (int k = 0; k < d->elf.nneeded && !amb; k++) {
            const char *n = d->elf.needed[k];
            size_t nl = strlen(n);
            if (nl > 13 && !strcmp(n + nl - 13, " (delay-load)")) nl -= 13;
            if (nl < vl || strncmp(n, dll, vl) || (nl != vl && !cut)) continue;
            if (full && (nl != fl || strncmp(full, n, nl))) amb = true;
            full = n; fl = nl;
        }
        if (!full || amb) { full = dll; fl = vl; }
        snprintf(buf, sz, "%.*s!%s", (int)fl, full, im->name);
        return buf;
    }
    if (im) { snprintf(buf, sz, "%s@got", im->name); return buf; }
    if ((im = elf_import_plt(&d->elf, addr))) { snprintf(buf, sz, pe ? "%s" : "%s@plt", im->name); return buf; }
    if ((f = da_func_containing(d, addr)) >= 0) {
        const DisFunc *fn = &d->fn[f];
        uint64_t o = addr - fn->cold;
        if (fn->cold_size && o < fn->cold_size) {
            if (o) snprintf(buf, sz, "%s.cold+0x%llx", fn->name, (unsigned long long)o);
            else   snprintf(buf, sz, "%s.cold", fn->name);
            return buf;
        }
        if (addr >= fn->addr) {
            snprintf(buf, sz, "%s+0x%llx", fn->name, (unsigned long long)(addr - fn->addr));
            return buf;
        }
    }
    uint64_t delta = 0;
    const ElfSymbol *s = elf_symbol_near(&d->elf, addr, &delta);
    if (s) {
        if (delta) snprintf(buf, sz, "%s+0x%llx", s->name, (unsigned long long)delta);
        else       snprintf(buf, sz, "%s", s->name);
        return buf;
    }
    return NULL;
}

/* printable C string at va (not in code), quoted and escaped */
static bool string_at(const Disasm *d, uint64_t va, char *out, size_t osz) {
    if (elf_va_code(&d->elf, va) || osz < 8) return false;
    size_t avail = 0;
    const uint8_t *p = elf_va_ptr(&d->elf, va, &avail);
    if (!p) return false;
    size_t n = 0, o = 0;
    out[o++] = '"';
    for (; n < avail && n < 64 && p[n]; n++) {
        uint8_t c = p[n];
        const char *e = c == '\n' ? "\\n" : c == '\t' ? "\\t" : c == '"' ? "\\\"" : c == '\\' ? "\\\\" : NULL;
        if (!e && (c < 0x20 || c > 0x7e)) return false;
        size_t need = e ? 2 : 1;
        if (o + need + 5 > osz) break;
        if (e) { out[o++] = e[0]; out[o++] = e[1]; } else out[o++] = (char)c;
    }
    if (n < 2) return false;
    bool cut = n < avail && p[n] != 0;
    if (cut) { memcpy(out + o, "...", 3); o += 3; }
    out[o++] = '"';
    out[o] = 0;
    return true;
}

bool da_string_at(const Disasm *d, uint64_t va, char *out, size_t osz) {
    return d && out && osz && string_at(d, va, out, osz);
}

void da_format(const Disasm *d, size_t i, char *mnem, size_t msz,
               char *ops, size_t osz, char *cmt, size_t csz) {
    if (mnem && msz) *mnem = 0;
    if (ops && osz)  *ops  = 0;
    if (cmt && csz)  *cmt  = 0;
    if (!d || !d->cs || i >= d->nins || !mnem || !ops || !cmt) return;

    const DisInsn *n = &d->ins[i];
    size_t avail = 0;
    const uint8_t *p = elf_va_ptr(&d->elf, n->addr, &avail);
    csh h = (csh)d->cs;
    cs_insn *in = p && avail >= n->len ? cs_malloc(h) : NULL;
    const uint8_t *c  = p;
    size_t         sz = n->len;
    uint64_t       ad = n->addr;
    if (!in || !cs_disasm_iter(h, &c, &sz, &ad, in)) {
        snprintf(mnem, msz, "??");
        if (in) cs_free(in, 1);
        return;
    }
    snprintf(mnem, msz, "%s", in->mnemonic);
    snprintf(ops,  osz, "%s", in->op_str);
    cs_free(in, 1);

    char nb[160];
    bool branch = (n->flags & (DI_CALL | DI_JUMP | DI_COND)) && !(n->flags & DI_INDIRECT);
    if (!n->target) return;
    if (branch) {
        if (da_name_for(d, n->target, nb, sizeof nb)) {
            snprintf(ops, osz, "%s", nb);
            snprintf(cmt, csz, "0x%llx", (unsigned long long)n->target);
        }
    } else if ((d->elf.fmt == ELF_FMT_PE && elf_import_got(&d->elf, n->target) &&
                da_name_for(d, n->target, nb, sizeof nb)) ||       /* an IAT slot holds an RVA, not text */
               string_at(d, n->target, nb, sizeof nb) ||
               da_name_for(d, n->target, nb, sizeof nb)) {
        snprintf(cmt, csz, "%s", nb);
    }
}
