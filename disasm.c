/* Static disassembly (capstone, x86-64, read-only), see disasm.h.
 *
 * Linear wrapper (da_open / da_linear) and recursive analysis
 * (da_analyze). Nothing here executes, emulates or writes the analysed
 * binary: the bytes are read from the ElfFile copy in memory. */
#include "disasm.h"

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
    cs_err e = cs_open(CS_ARCH_X86, CS_MODE_64, &h);
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

#define X_EM_X86_64      62
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

typedef struct {
    Disasm   *d;
    csh       h;
    cs_insn  *in;
    bool      oom;

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
    const ElfImport **plt; size_t nplt;      /* imports sorted by stub    */
} An;

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

/* import whose PLT stub starts at va (elf_import_plt is a linear scan,
 * too slow once per call instruction) */
static const ElfImport *plt_import(const An *a, uint64_t va) {
    size_t lo = 0, hi = a->nplt;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (a->plt[mid]->plt < va) lo = mid + 1; else hi = mid;
    }
    return (lo < a->nplt && a->plt[lo]->plt == va) ? a->plt[lo] : NULL;
}

/* name of what a call reaches: import by PLT stub or GOT slot, else a
 * function symbol */
static const char *callee_name(const An *a, uint64_t target, bool via_mem) {
    const ElfFile *ef = &a->d->elf;
    const ElfImport *im = via_mem ? elf_import_got(ef, target) : plt_import(a, target);
    if (im) return im->name;
    if (via_mem) return NULL;
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

/* registers a function start (or improves its kind) and queues it */
static void add_func(An *a, uint64_t va, uint8_t kind) {
    if (a->oom || !va || !xmap_of(a, va)) return;
    if (a->hcap) {
        size_t i = hslot(a, va);
        if (a->hk[i]) {
            FnSeed *f = &a->fs[a->hv[i]];
            if (kind < f->kind) f->kind = kind;
            return;
        }
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
     * pointer (main for __libc_start_main), anything else forgets it */
    if (x->op_count >= 1 && x->operands[0].type == X86_OP_REG &&
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

/* Empties the work list. Each address is decoded at most once (start
 * bitmap), each pass of the inner loop consumes a new instruction, so
 * the total work is bounded by the executable bytes and DA_MAX_INSNS. */
static void walk_queue(An *a) {
    Disasm *d = a->d;
    RegTrack rt;
    uint64_t carry = 0;            /* target of the direct jmp that ended
                                      the last path, popped next (LIFO):
                                      its path keeps the registers (a
                                      table address loaded before a jmp
                                      to the loop head) */
    while (a->qn && !a->oom) {
        uint64_t pc  = a->q[--a->qn];
        uint64_t rdi = 0;
        if (!carry || pc != carry) rt_reset(&rt);
        carry = 0;
        for (;;) {
            if (d->nins >= DA_MAX_INSNS) { d->capped = true; a->qn = 0; return; }
            Step st;
            XMap *x = NULL;
            int r = decode_at(a, pc, &x, &st);
            if (r == DEC_BAD || r == DEC_OVERLAP) d->nbad++;
            if (r != DEC_OK) break;

            if (st.flags & DI_CALL) {
                const char *cn = st.target ? callee_name(a, st.target, !st.direct) : NULL;
                if (cn && rdi && !strcmp(cn, "__libc_start_main"))
                    add_func(a, rdi, FN_MAIN);
                if (st.direct) add_func(a, st.target, FN_CALL);
                if (name_noreturn(cn)) { st.flags |= DI_NORET; st.end = true; }
            } else if ((st.flags & (DI_JUMP | DI_COND)) && st.direct) {
                /* also a tail call to a known function: it is not
                 * decoded again (push skips decoded code), its callers
                 * are counted in finalize */
                push(a, st.target);
            }
            if (st.rdi > 0) rdi = st.target;
            else if (st.rdi < 0) rdi = 0;
            if (st.lea && st.target != pc + st.len) cp_push(a, st.target);  /* not lea [rip+0] */
            track(a, &rt, a->in, &st);

            commit(a, x, pc, &st);
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
    if (!x) return false;
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

static bool is_push_or_frame(const uint8_t *p, size_t n) {
    if (n >= 2 && p[0] == 0x41 && p[1] >= 0x54 && p[1] <= 0x57) return true; /* push r12..r15 */
    if (n >= 1 && (p[0] == 0x55 || p[0] == 0x53)) return true;               /* push rbp/rbx  */
    if (n >= 3 && p[0] == 0x48 && (p[1] == 0x83 || p[1] == 0x81) && p[2] == 0xec)
        return true;                                                          /* sub rsp, imm  */
    return false;
}

/* strong: endbr64, push rbp; mov rbp, rsp. weak (16-aligned after
 * padding only): a run of callee-saved pushes / sub rsp. */
static int prologue_kind(const uint8_t *p, size_t n) {
    if (n >= 4 && p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x1e && p[3] == 0xfa) return 2;
    if (n >= 4 && p[0] == 0x55 && p[1] == 0x48 && p[2] == 0x89 && p[3] == 0xe5) return 2;
    if (n >= 2 && p[0] == 0x41 && p[1] >= 0x54 && p[1] <= 0x57 && is_push_or_frame(p + 2, n - 2)) return 1;
    if (n >= 1 && (p[0] == 0x55 || p[0] == 0x53) && is_push_or_frame(p + 1, n - 1)) return 1;
    if (n >= 4 && p[0] == 0x48 && (p[1] == 0x83 || p[1] == 0x81) && p[2] == 0xec) return 1;
    return 0;
}

/* last byte of the alignment padding GCC / Clang / ld emit (multi-byte
 * nops end in 00), or of a ret */
static bool pad_byte(uint8_t b) { return b == 0x00 || b == 0x90 || b == 0xcc || b == 0xc3; }

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
        int k = prologue_kind(base + o, (size_t)(end - o));
        if (!k) continue;
        bool aligned = ((m->va + o) & 15) == 0;
        bool after   = o == 0 || bit_get(x->cover, o - 1) || pad_byte(base[o - 1]);
        if (k == 2 ? !(aligned || after) : !(aligned && after)) continue;
        uint64_t pc = m->va + o;
        if (!probe(a, pc)) continue;
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
        int k = p ? prologue_kind(p, avail) : 0;
        if (!k) continue;
        if (k == 1 && ((t & 15) || !(o == 0 || bit_get(x->cover, o - 1) || pad_byte(p[-1]))))
            continue;
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
        add_func(a, t, FN_PROLOGUE);
    }
    free(st);
}

/* ─── code pointers in data ─────────────────────────────────────── */

static bool dp_section(const char *n) {
    return !strcmp(n, ".data") || !strcmp(n, ".data.rel.ro") ||
           !strcmp(n, ".rodata") || !strcmp(n, ".init_array");
}

/* a word worth checking: it points into executable code (with a section
 * table: an executable section, not a PLT), and it is not an import GOT
 * slot (filled by the dynamic linker; the file holds a lazy-binding
 * address inside the PLT). Bounded by DA_MAX_QUEUE. */
static void dp_add(An *a, uint64_t slot, uint64_t t) {
    const ElfFile *ef = &a->d->elf;
    if (a->oom || !t || !xmap_of(a, t) || elf_import_got(ef, slot)) return;
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
    a->dp[a->ndp++] = (DPtr){ slot, t, slot, 1 };
}

/* the 8-aligned words of [va, va + size) (non-PIE: no relocation) */
static void dp_words(An *a, uint64_t va, uint64_t size) {
    if (size < 8 || va > UINT64_MAX - size || va > UINT64_MAX - 7) return;
    uint64_t end = va + size;                            /* >= 8 */
    for (uint64_t s = (va + 7) & ~(uint64_t)7; s <= end - 8; s += 8) {
        uint64_t v;
        if (elf_read_ptr(&a->d->elf, s, &v)) dp_add(a, s, v);
        if (a->oom || a->d->capped) return;
    }
}

static int cmp_dp(const void *x, const void *y) {
    const DPtr *p = x, *q = y;
    return p->slot < q->slot ? -1 : p->slot > q->slot;
}
static int cmp_u64(const void *x, const void *y) {
    uint64_t p = *(const uint64_t *)x, q = *(const uint64_t *)y;
    return p < q ? -1 : p > q;
}

/* PIE / shared object: the RELATIVE (RELA, RELR) relocations elfload
 * read, the addend is the target. Non-PIE executable: the words of the
 * data sections, or of the non-executable mappings without a section
 * table. Object files: nothing (their relocations are not read). Then
 * sorted by slot and cut into runs. */
static void dp_collect(An *a) {
    const ElfFile *ef = &a->d->elf;
    if (ef->type == X_ET_DYN) {
        for (int i = 0; i < ef->nrel && !a->oom && !a->d->capped; i++)
            dp_add(a, ef->rel[i].va, ef->rel[i].addend);
    } else if (ef->type == X_ET_EXEC) {
        if (ef->nsec) {
            for (int i = 0; i < ef->nsec && !a->oom && !a->d->capped; i++) {
                const ElfSection *s = &ef->sec[i];
                if (!s->bad && s->type != X_SHT_NOBITS && dp_section(s->name))
                    dp_words(a, s->addr, s->size);
            }
        } else {
            for (int i = 0; i < ef->nmap && !a->oom && !a->d->capped; i++)
                if (!(ef->map[i].flags & X_PF_X))
                    dp_words(a, ef->map[i].va, ef->map[i].filesz);
        }
        a->dpraw = true;
    }
    if (!a->ndp) return;
    qsort(a->dp, a->ndp, sizeof *a->dp, cmp_dp);
    size_t k = 0;                                        /* same slot twice */
    for (size_t i = 0; i < a->ndp; i++)
        if (!k || a->dp[i].slot != a->dp[k - 1].slot) a->dp[k++] = a->dp[i];
    a->ndp = k;
    for (size_t i = 1; i < a->ndp; i++)
        if (a->dp[i].slot == a->dp[i - 1].slot + 8) a->dp[i].run = a->dp[i - 1].run;
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
static bool start_sign(An *a, XMap *x, uint64_t va) {
    const ElfFile *ef = &a->d->elf;
    uint64_t o = va - x->m->va;
    if (!(va & 15) || o == 0) return true;
    size_t avail = 0, pavail = 0;
    const uint8_t *p = elf_va_ptr(ef, va, &avail);
    if (p && prologue_kind(p, avail) == 2) return true;
    if (a->dpraw) return false;
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
        if (x && start_sign(a, x, a->dp[i].target)) n++;
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
    uint64_t o = va - x->m->va;
    bool start = bit_get(x->start, o);
    if (start ? bit_get(x->fall, o) : bit_get(x->cover, o)) return false;
    if (!table && !start_sign(a, x, va)) return false;
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
            add_func(a, p->target, FN_DATAPTR);
            long s = seed_index(a, p->target);
            if (s >= 0 && a->fs[s].kind == FN_DATAPTR) a->fs[s].dp = (uint32_t)i;
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
        if (f->kind != FN_DATAPTR || f->dp >= a->ndp) continue;
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
    const ElfImport *p = *(const ElfImport *const *)x, *q = *(const ElfImport *const *)y;
    return p->plt < q->plt ? -1 : p->plt > q->plt;
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
        const ElfImport *im = plt_import(a, f->addr);
        char buf[160];
        if (s) {
            snprintf(buf, sizeof buf, "%s", s->name);
            f->kind = s->dynamic ? FN_DYNSYM : FN_SYMTAB;
            f->size = s->size;
        } else if (im) {
            snprintf(buf, sizeof buf, "%s@plt", im->name);
            f->kind = FN_PLT;
        } else if (f->kind == FN_MAIN) {
            snprintf(buf, sizeof buf, "main");
        } else {
            snprintf(buf, sizeof buf, "sub_%llx", (unsigned long long)f->addr);
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

    a->plt = malloc((ef->nimp ? (size_t)ef->nimp : 1) * sizeof *a->plt);
    if (!a->plt) return false;
    for (int i = 0; i < ef->nimp; i++)
        if (ef->imp[i].plt) a->plt[a->nplt++] = &ef->imp[i];
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
}

bool da_analyze(Disasm *d, const char *path, char *err, size_t esz) {
    if (!d || !path) { set_err(err, esz, "bad arguments"); return false; }
    memset(d, 0, sizeof *d);
    if (!elf_load(&d->elf, path, err, esz)) return false;
    if (d->elf.machine != X_EM_X86_64) {
        set_err(err, esz, "not an x86-64 binary (%s)", elf_machine_name(d->elf.machine));
        da_free(d);
        return false;
    }
    if (!da_open(d, err, esz)) { da_free(d); return false; }

    An a = { 0 };
    a.d = d;
    a.h = (csh)d->cs;
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
            else if ((sy->kind == ELF_SYM_FUNC && elf_va_exec(ef, sy->value)) || code_label(ef, sy))
                add_func(&a, sy->value, sy->dynamic ? FN_DYNSYM : FN_SYMTAB);
        }
        for (size_t i = 0; i < a.nplt; i++) add_func(&a, a.plt[i]->plt, FN_PLT);
        for (int i = 0; i < ef->nctors; i++) add_func(&a, ef->ctors[i], FN_CTOR);
        explore(&a);
        /* then the code pointers stored in data */
        if (!a.oom && !d->capped) dataptr_scan(&a);
        /* then what nothing points to */
        if (!a.oom && !d->capped) prologue_scan(&a);
        /* then the functions reached only by a tail jmp */
        if (!a.oom && !d->capped) tail_scan(&a);
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
    if (im) { snprintf(buf, sz, "%s@got", im->name); return buf; }
    if ((im = elf_import_plt(&d->elf, addr))) { snprintf(buf, sz, "%s@plt", im->name); return buf; }
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
    if (elf_va_exec(&d->elf, va) || osz < 8) return false;
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
    } else if (string_at(d, n->target, nb, sizeof nb) ||
               da_name_for(d, n->target, nb, sizeof nb)) {
        snprintf(cmt, csz, "%s", nb);
    }
}
