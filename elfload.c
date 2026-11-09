/* ELF64 x86-64 / ELF32 i386 loader (read-only), see elfload.h.
 *
 * Both classes go through the same code: the entry sizes and the field
 * offsets come from the class (ElfFile.bits), 32-bit fields are read
 * with r32 and zero-extended. The ELF64 path is unchanged.
 *
 * Rule followed everywhere below: no byte of the file is read before the
 * offset AND the length of what is read have been checked against the
 * file size, with overflow-safe arithmetic (table_ok / in_file). Strings
 * must end inside their string table and are cleaned to printable ASCII
 * before they can reach the terminal. */
#include "elfload.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* ─── ELF constants (no <elf.h>: not available with MinGW) ───────── */
#define ET_REL   1
#define ET_EXEC  2
#define ET_DYN   3
#define ET_CORE  4
#define EM_386     3
#define EM_X86_64 62

#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define PF_X 1

#define SHT_SYMTAB   2
#define SHT_STRTAB   3
#define SHT_NOBITS   8
#define SHT_DYNSYM  11
#define SHF_ALLOC     2
#define SHF_EXECINSTR 4
#define SHN_UNDEF     0
#define SHN_LORESERVE 0xff00
#define SHN_XINDEX    0xffff
#define PN_XNUM       0xffff

#define DT_NULL          0
#define DT_NEEDED        1
#define DT_PLTRELSZ      2
#define DT_PLTGOT        3
#define DT_HASH          4
#define DT_STRTAB        5
#define DT_SYMTAB        6
#define DT_RELA          7
#define DT_RELASZ        8
#define DT_RELAENT       9
#define DT_STRSZ        10
#define DT_INIT         12
#define DT_FINI         13
#define DT_SONAME       14
#define DT_REL          17
#define DT_RELSZ        18
#define DT_RELENT       19
#define DT_PLTREL       20
#define DT_JMPREL       23
#define DT_INIT_ARRAY   25
#define DT_FINI_ARRAY   26
#define DT_INIT_ARRAYSZ 27
#define DT_FINI_ARRAYSZ 28
#define DT_PREINIT_ARRAY   32
#define DT_PREINIT_ARRAYSZ 33
#define DT_RELRSZ       35
#define DT_RELR         36
#define DT_GNU_HASH     0x6ffffef5
#define DT_VERSYM       0x6ffffff0
#define DT_FLAGS_1      0x6ffffffb
#define DT_VERNEED      0x6ffffffe
#define DT_VERNEEDNUM   0x6fffffff
#define DF_1_PIE        0x08000000

#define R_X86_64_64        1
#define R_X86_64_GLOB_DAT  6
#define R_X86_64_JUMP_SLOT 7
#define R_X86_64_RELATIVE  8
/* i386: the same numbers */
#define R_386_32           1
#define R_386_GLOB_DAT     6
#define R_386_JMP_SLOT     7
#define R_386_RELATIVE     8

#define STT_OBJECT 1
#define STT_FUNC   2
#define STT_SECTION 3
#define STT_FILE   4
#define STT_COMMON 5
#define STT_TLS    6
#define STT_GNU_IFUNC 10

#define MAX_PHNUM   65536
#define MAX_SHNUM   65536
#define MAX_SYMS    (4u * 1024u * 1024u)
#define MAX_RELOCS  (8u * 1024u * 1024u)
#define MAX_NEEDED  512
#define MAX_CTORS   4096

/* ─── little helpers ───────────────────────────────────────────── */

static uint16_t r16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t r32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t r64(const uint8_t *p) { return (uint64_t)r32(p) | (uint64_t)r32(p + 4) << 32; }

/* class: ELF32 (bits 32) or ELF64 (anything else, PE included) */
static bool     is32(const ElfFile *ef) { return ef->bits == 32; }
static unsigned wsz(const ElfFile *ef)  { return is32(ef) ? 4u : 8u; }
/* an address / size / offset field of the file's class, zero-extended */
static uint64_t rw(const ElfFile *ef, const uint8_t *p) { return is32(ef) ? r32(p) : r64(p); }
/* entry sizes */
static unsigned sym_ent(const ElfFile *ef) { return is32(ef) ? 16u : 24u; }

static bool in_file(const ElfFile *ef, uint64_t off, uint64_t len) {
    return off <= ef->size && len <= ef->size - off;
}

/* n entries of `ent` bytes from `off`, all inside the file */
static bool table_ok(const ElfFile *ef, uint64_t off, uint64_t n, uint64_t ent) {
    if (n == 0) return true;
    if (ent == 0 || n > UINT64_MAX / ent) return false;
    return in_file(ef, off, n * ent);
}

static void set_err(char *err, size_t esz, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void set_err(char *err, size_t esz, const char *fmt, ...) {
    if (!err || !esz) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, esz, fmt, ap);
    va_end(ap);
}

static void warn(ElfFile *ef, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void warn(ElfFile *ef, const char *fmt, ...) {
    if (ef->nwarn >= ELF_MAX_WARN) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(ef->warn[ef->nwarn++], sizeof ef->warn[0], fmt, ap);
    va_end(ap);
}

/* string `idx` of the string table at [tab_off, tab_off + tab_size):
 * NULL unless it is NUL-terminated inside the table */
static const char *str_at(const ElfFile *ef, uint64_t tab_off, uint64_t tab_size,
                          uint64_t idx, size_t *len) {
    if (!in_file(ef, tab_off, tab_size) || idx >= tab_size) return NULL;
    const char *s = (const char *)ef->data + tab_off + idx;
    const char *z = memchr(s, 0, (size_t)(tab_size - idx));
    if (!z) return NULL;
    *len = (size_t)(z - s);
    return s;
}

/* copy cleaned to printable ASCII (names come from untrusted files and
 * end up on the terminal), at most 255 characters */
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

/* ─── address mapping ──────────────────────────────────────────── */

const ElfMap *elf_map_of(const ElfFile *ef, uint64_t va) {
    for (int i = 0; i < ef->nmap; i++) {
        const ElfMap *m = &ef->map[i];
        if (va >= m->va && va - m->va < m->filesz) return m;
    }
    return NULL;
}

bool elf_va_to_off(const ElfFile *ef, uint64_t va, uint64_t *off) {
    const ElfMap *m = elf_map_of(ef, va);
    if (!m) return false;
    *off = m->off + (va - m->va);
    return *off < ef->size;
}

/* executable mappings first: for an offset mapped twice (the first page
 * of a file is often in two segments) the code view wins */
bool elf_off_to_va(const ElfFile *ef, uint64_t off, uint64_t *va) {
    for (int pass = 0; pass < 2; pass++)
        for (int i = 0; i < ef->nmap; i++) {
            const ElfMap *m = &ef->map[i];
            if (pass == 0 && !(m->flags & PF_X)) continue;
            if (pass == 1 &&  (m->flags & PF_X)) continue;
            if (off >= m->off && off - m->off < m->filesz) { *va = m->va + (off - m->off); return true; }
        }
    return false;
}

const uint8_t *elf_va_ptr(const ElfFile *ef, uint64_t va, size_t *avail) {
    const ElfMap *m = elf_map_of(ef, va);
    if (!m) return NULL;
    uint64_t delta = va - m->va;
    uint64_t off   = m->off + delta;               /* checked at load: map is inside the file */
    if (off >= ef->size) return NULL;
    uint64_t left  = m->filesz - delta;
    if (left > ef->size - off) left = ef->size - off;
    if (avail) *avail = (size_t)left;
    return ef->data + off;
}

bool elf_va_exec(const ElfFile *ef, uint64_t va) {
    const ElfMap *m = elf_map_of(ef, va);
    return m && (m->flags & PF_X);
}

/* code at va: an executable segment and, when a section holds va, an
 * executable section (an old ld puts .rodata in the r-x segment of .text:
 * its strings are data) */
bool elf_va_code(const ElfFile *ef, uint64_t va) {
    if (!elf_va_exec(ef, va)) return false;
    const ElfSection *s = elf_section_at(ef, va);
    return !s || (s->flags & SHF_EXECINSTR);
}

static const ElfReloc *rel_at(const ElfFile *ef, uint64_t va) {
    int lo = 0, hi = ef->nrel - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (ef->rel[mid].va == va) return &ef->rel[mid];
        if (ef->rel[mid].va < va) lo = mid + 1; else hi = mid - 1;
    }
    return NULL;
}

bool elf_read_ptr(const ElfFile *ef, uint64_t va, uint64_t *out) {
    const ElfReloc *r = rel_at(ef, va);
    if (r) { *out = r->addend; return true; }
    size_t avail = 0;
    const uint8_t *p = elf_va_ptr(ef, va, &avail);
    if (!p || avail < wsz(ef)) return false;
    *out = rw(ef, p);
    return true;
}

/* ─── lookups ──────────────────────────────────────────────────── */

const ElfSection *elf_section_at(const ElfFile *ef, uint64_t va) {
    const ElfSection *best = NULL;
    for (int i = 0; i < ef->nsec; i++) {
        const ElfSection *s = &ef->sec[i];
        if (!(s->flags & SHF_ALLOC) || !s->size) continue;
        if (va >= s->addr && va - s->addr < s->size) {
            if (!best || (best->type == SHT_NOBITS && s->type != SHT_NOBITS)) best = s;
        }
    }
    return best;
}

const ElfSection *elf_section_named(const ElfFile *ef, const char *name) {
    for (int i = 0; i < ef->nsec; i++)
        if (!strcmp(ef->sec[i].name, name)) return &ef->sec[i];
    return NULL;
}

/* first symbol whose value is >= va */
static int sym_lower(const ElfFile *ef, uint64_t va) {
    int lo = 0, hi = ef->nsym;
    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        if (ef->sym[mid].value < va) lo = mid + 1; else hi = mid;
    }
    return lo;
}

const ElfSymbol *elf_symbol_at(const ElfFile *ef, uint64_t va) {
    int i = sym_lower(ef, va);
    return (i < ef->nsym && ef->sym[i].value == va) ? &ef->sym[i] : NULL;
}

/* the symbol covering va (value <= va < value + size), or the closest
 * one below it within 4 KiB when sizes are unknown */
const ElfSymbol *elf_symbol_near(const ElfFile *ef, uint64_t va, uint64_t *delta) {
    int i = sym_lower(ef, va);
    if (i < ef->nsym && ef->sym[i].value == va) { *delta = 0; return &ef->sym[i]; }
    for (int k = i - 1; k >= 0 && k >= i - 64; k--) {
        const ElfSymbol *s = &ef->sym[k];
        if (s->kind == ELF_SYM_OTHER) continue;
        uint64_t d = va - s->value;
        if ((s->size && d < s->size) || (!s->size && d < 4096)) { *delta = d; return s; }
        if (s->size) break;
    }
    return NULL;
}

const ElfImport *elf_import_got(const ElfFile *ef, uint64_t got) {
    int lo = 0, hi = ef->nimp - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (ef->imp[mid].got == got) return &ef->imp[mid];
        if (ef->imp[mid].got < got) lo = mid + 1; else hi = mid - 1;
    }
    return NULL;
}

const ElfImport *elf_import_plt(const ElfFile *ef, uint64_t plt) {
    if (!plt) return NULL;
    for (int i = 0; i < ef->nimp; i++)
        if (ef->imp[i].plt == plt) return &ef->imp[i];
    return NULL;
}

/* ─── names ────────────────────────────────────────────────────── */

const char *elf_type_name(uint16_t t) {
    switch (t) {
        case ET_REL:  return "REL (object file)";
        case ET_EXEC: return "EXEC";
        case ET_DYN:  return "DYN";
        case ET_CORE: return "CORE";
        default:      return "unknown";
    }
}

const char *elf_machine_name(uint16_t m) {
    switch (m) {
        case 3:   return "x86 (i386)";
        case 40:  return "ARM";
        case 62:  return "x86-64";
        case 183: return "AArch64";
        case 243: return "RISC-V";
        case 8:   return "MIPS";
        case 20:  return "PowerPC";
        case 21:  return "PowerPC64";
        default:  return "unknown";
    }
}

const char *elf_seg_type_name(uint32_t t) {
    switch (t) {
        case 0: return "NULL";
        case 1: return "LOAD";
        case 2: return "DYNAMIC";
        case 3: return "INTERP";
        case 4: return "NOTE";
        case 5: return "SHLIB";
        case 6: return "PHDR";
        case 7: return "TLS";
        case 0x6474e550: return "GNU_EH_FRAME";
        case 0x6474e551: return "GNU_STACK";
        case 0x6474e552: return "GNU_RELRO";
        case 0x6474e553: return "GNU_PROPERTY";
        default: return "OTHER";
    }
}

const char *elf_sec_type_name(uint32_t t) {
    switch (t) {
        case 0: return "NULL";       case 1: return "PROGBITS";
        case 2: return "SYMTAB";     case 3: return "STRTAB";
        case 4: return "RELA";       case 5: return "HASH";
        case 6: return "DYNAMIC";    case 7: return "NOTE";
        case 8: return "NOBITS";     case 9: return "REL";
        case 11: return "DYNSYM";    case 14: return "INIT_ARRAY";
        case 15: return "FINI_ARRAY"; case 16: return "PREINIT_ARRAY";
        case 17: return "GROUP";
        case 0x6ffffff6: return "GNU_HASH";
        case 0x6ffffffe: return "VERNEED";
        case 0x6fffffff: return "VERSYM";
        default: return "OTHER";
    }
}

void elf_flags_str(uint32_t pf, char out[4]) {
    out[0] = (pf & 4) ? 'R' : '-';
    out[1] = (pf & 2) ? 'W' : '-';
    out[2] = (pf & 1) ? 'X' : '-';
    out[3] = '\0';
}

void elf_sec_flags_str(uint64_t f, char out[8]) {
    int n = 0;
    if (f & 1) out[n++] = 'W';
    if (f & 2) out[n++] = 'A';
    if (f & 4) out[n++] = 'X';
    if (f & 0x10) out[n++] = 'M';
    if (f & 0x20) out[n++] = 'S';
    if (f & 0x400) out[n++] = 'T';
    out[n] = '\0';
}

const char *elf_arch_name(uint8_t arch) {
    switch (arch) {
        case ELF_ARCH_X86_64: return "x86-64";
        case ELF_ARCH_X86_32: return "x86-32";
        default:              return "unknown";
    }
}

bool elf_is_elf(const uint8_t *buf, size_t len) {
    return len >= 16 && buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F';
}

/* ─── parsing steps ────────────────────────────────────────────── */

static bool push_symbol(ElfFile *ef, int *cap, const ElfSymbol *s) {
    if (ef->nsym >= (int)MAX_SYMS) return false;
    if (ef->nsym == *cap) {
        int nc = *cap ? *cap * 2 : 256;
        ElfSymbol *n = realloc(ef->sym, (size_t)nc * sizeof *n);
        if (!n) return false;
        ef->sym = n; *cap = nc;
    }
    ef->sym[ef->nsym++] = *s;
    return true;
}

/* one symbol table: `count` entries of 24 bytes (ELF32: 16) at file
 * offset `off`, names in [str_off, str_off + str_size) */
static void read_symtab(ElfFile *ef, int *cap, uint64_t off, uint64_t count,
                        uint64_t str_off, uint64_t str_size, bool dynamic) {
    if (count > MAX_SYMS) { warn(ef, "symbol table too large (%llu entries): truncated", (unsigned long long)count); count = MAX_SYMS; }
    const unsigned ent = sym_ent(ef);
    if (!table_ok(ef, off, count, ent)) { warn(ef, "symbol table outside the file: ignored"); return; }
    for (uint64_t i = 1; i < count; i++) {
        const uint8_t *p = ef->data + off + i * ent;
        uint32_t name  = r32(p);
        uint8_t  info;
        uint16_t shndx;
        uint64_t value, size;
        if (is32(ef)) {                                /* Elf32_Sym */
            value = r32(p + 4); size = r32(p + 8);
            info  = p[12];      shndx = r16(p + 14);
        } else {                                       /* Elf64_Sym */
            info  = p[4];       shndx = r16(p + 6);
            value = r64(p + 8); size = r64(p + 16);
        }
        uint8_t  type  = info & 0xf, bind = info >> 4;
        if (type == STT_SECTION || type == STT_FILE) continue;
        if (shndx == SHN_UNDEF) continue;              /* imports come from relocations */
        size_t nl = 0;
        const char *s = str_at(ef, str_off, str_size, name, &nl);
        if (!s || !nl) continue;
        ElfSymbol sym = {0};
        sym.kind  = (type == STT_FUNC || type == STT_GNU_IFUNC) ? ELF_SYM_FUNC
                  : (type == STT_OBJECT || type == STT_TLS || type == STT_COMMON) ? ELF_SYM_OBJECT
                  : ELF_SYM_OTHER;
        sym.bind  = bind;
        sym.shndx = shndx;
        sym.size  = size;
        sym.value = value;
        sym.dynamic  = dynamic;
        sym.exported = dynamic && (bind == 1 || bind == 2);
        /* object files: values are relative to their section */
        if (ef->type == ET_REL && shndx < SHN_LORESERVE) {
            if (shndx >= ef->nsec) continue;
            sym.value += ef->sec[shndx].addr;
        }
        if (type == STT_TLS) continue;                 /* not an address */
        sym.name = clean_dup(s, nl);
        if (!sym.name || !push_symbol(ef, cap, &sym)) { free(sym.name); return; }
    }
}

/* section header table: on any structural problem the whole table is
 * ignored (with a warning), never trusted halfway */
static void parse_sections(ElfFile *ef, uint64_t shoff, uint32_t shnum, uint16_t shentsize,
                           uint32_t shstrndx) {
    if (shoff == 0 || shnum == 0) return;
    const unsigned ent = is32(ef) ? 40u : 64u;
    if (shentsize != ent) { warn(ef, "section headers: entry size %u (expected %u): ignored", shentsize, ent); return; }
    if (shnum > MAX_SHNUM || !table_ok(ef, shoff, shnum, ent)) {
        warn(ef, "section header table outside the file: ignored");
        return;
    }
    ef->sec = calloc(shnum, sizeof *ef->sec);
    if (!ef->sec) return;
    ef->nsec = (int)shnum;
    for (uint32_t i = 0; i < shnum; i++) {
        const uint8_t *p = ef->data + shoff + (uint64_t)i * ent;
        ElfSection *s = &ef->sec[i];
        s->type    = r32(p + 4);
        if (is32(ef)) {                            /* Elf32_Shdr */
            s->flags   = r32(p + 8);
            s->addr    = r32(p + 12);
            s->off     = r32(p + 16);
            s->size    = r32(p + 20);
            s->link    = r32(p + 24);
            s->info    = r32(p + 28);
            s->entsize = r32(p + 36);
        } else {                                   /* Elf64_Shdr */
            s->flags   = r64(p + 8);
            s->addr    = r64(p + 16);
            s->off     = r64(p + 24);
            s->size    = r64(p + 32);
            s->link    = r32(p + 40);
            s->info    = r32(p + 44);
            s->entsize = r64(p + 56);
        }
        if (s->type != SHT_NOBITS && s->type != 0 && !in_file(ef, s->off, s->size)) {
            s->bad = true;
            warn(ef, "section %u: contents outside the file: ignored", i);
        }
    }
    /* names */
    if (shstrndx < shnum && !ef->sec[shstrndx].bad && ef->sec[shstrndx].type == SHT_STRTAB) {
        const ElfSection *st = &ef->sec[shstrndx];
        for (uint32_t i = 0; i < shnum; i++) {
            size_t nl = 0;
            const char *s = str_at(ef, st->off, st->size, r32(ef->data + shoff + (uint64_t)i * ent), &nl);
            if (s) clean_copy(ef->sec[i].name, sizeof ef->sec[i].name, s, nl);
        }
    } else if (shstrndx != 0) {
        warn(ef, "section name table (index %u) invalid: sections unnamed", shstrndx);
    }
    /* object files have no addresses: each allocated section gets its
     * file offset as a pseudo address */
    if (ef->type == ET_REL)
        for (uint32_t i = 0; i < shnum; i++)
            if ((ef->sec[i].flags & SHF_ALLOC) && !ef->sec[i].addr && ef->sec[i].type != SHT_NOBITS)
                ef->sec[i].addr = ef->sec[i].off;
}

static bool add_map(ElfFile *ef, uint64_t va, uint64_t off, uint64_t filesz, uint64_t memsz, uint32_t flags) {
    ElfMap *n = realloc(ef->map, (size_t)(ef->nmap + 1) * sizeof *n);
    if (!n) return false;
    ef->map = n;
    ef->map[ef->nmap++] = (ElfMap){ va, off, filesz, memsz, flags };
    return true;
}

/* the dynamic table, read through the segments */
typedef struct {
    uint64_t strtab, strsz, symtab, hash, gnuhash, rela, relasz, jmprel, pltrelsz;
    uint64_t versym, verneed, verneednum;
    uint64_t init, fini, initarr, initarrsz, finiarr, finiarrsz, prearr, prearrsz;
    uint64_t flags1, relr, relrsz;
    /* ELF32 only (i386 uses REL tables; JMPREL is REL unless DT_PLTREL
     * says RELA) */
    uint64_t rel, relsz, relent, relaent, pltrel, pltgot;
    bool     has_relent, has_relaent, has_pltrel;
    uint64_t needed[MAX_NEEDED]; int nneeded;
    int64_t  soname;
    bool     present;
    /* resolved file offsets */
    uint64_t str_off, str_size, sym_off;
    bool     have_str, have_sym;
} DynInfo;

static void parse_dynamic(ElfFile *ef, DynInfo *d) {
    memset(d, 0, sizeof *d);
    d->soname = -1;
    for (int i = 0; i < ef->nseg; i++) {
        const ElfSegment *s = &ef->seg[i];
        if (s->type != PT_DYNAMIC) continue;
        if (!in_file(ef, s->off, s->filesz)) { warn(ef, "DYNAMIC segment outside the file: ignored"); return; }
        d->present = true;
        const unsigned ent = is32(ef) ? 8u : 16u;  /* Elf32_Dyn / Elf64_Dyn */
        uint64_t n = s->filesz / ent;
        for (uint64_t k = 0; k < n; k++) {
            const uint8_t *p = ef->data + s->off + k * ent;
            int64_t  tag = is32(ef) ? (int64_t)r32(p) : (int64_t)r64(p);
            uint64_t val = rw(ef, p + ent / 2);
            if (tag == DT_NULL) break;
            if (is32(ef)) {
                switch (tag) {
                    case DT_REL:     d->rel = val; break;
                    case DT_RELSZ:   d->relsz = val; break;
                    case DT_RELENT:  d->relent = val; d->has_relent = true; break;
                    case DT_RELAENT: d->relaent = val; d->has_relaent = true; break;
                    case DT_PLTREL:  d->pltrel = val; d->has_pltrel = true; break;
                    case DT_PLTGOT:  d->pltgot = val; break;
                    default: break;
                }
            }
            switch (tag) {
                case DT_NEEDED: if (d->nneeded < MAX_NEEDED) d->needed[d->nneeded++] = val; break;
                case DT_STRTAB: d->strtab = val; break;
                case DT_STRSZ:  d->strsz = val; break;
                case DT_SYMTAB: d->symtab = val; break;
                case DT_HASH:   d->hash = val; break;
                case DT_GNU_HASH: d->gnuhash = val; break;
                case DT_RELA:   d->rela = val; break;
                case DT_RELASZ: d->relasz = val; break;
                case DT_JMPREL: d->jmprel = val; break;
                case DT_PLTRELSZ: d->pltrelsz = val; break;
                case DT_VERSYM: d->versym = val; break;
                case DT_VERNEED: d->verneed = val; break;
                case DT_VERNEEDNUM: d->verneednum = val; break;
                case DT_INIT:   d->init = val; break;
                case DT_FINI:   d->fini = val; break;
                case DT_INIT_ARRAY: d->initarr = val; break;
                case DT_INIT_ARRAYSZ: d->initarrsz = val; break;
                case DT_FINI_ARRAY: d->finiarr = val; break;
                case DT_FINI_ARRAYSZ: d->finiarrsz = val; break;
                case DT_PREINIT_ARRAY: d->prearr = val; break;
                case DT_PREINIT_ARRAYSZ: d->prearrsz = val; break;
                case DT_FLAGS_1: d->flags1 = val; break;
                case DT_RELR:   d->relr = val; break;
                case DT_RELRSZ: d->relrsz = val; break;
                case DT_SONAME: d->soname = (int64_t)val; break;
                default: break;
            }
        }
        break;
    }
    if (!d->present) return;
    if (d->strtab && elf_va_to_off(ef, d->strtab, &d->str_off)) {
        uint64_t room = ef->size - d->str_off;
        d->str_size = (d->strsz && d->strsz < room) ? d->strsz : room;
        d->have_str = true;
    }
    if (d->symtab && elf_va_to_off(ef, d->symtab, &d->sym_off)) d->have_sym = true;
}

static const char *dyn_str(const ElfFile *ef, const DynInfo *d, uint64_t idx, size_t *len) {
    if (!d->have_str) return NULL;
    return str_at(ef, d->str_off, d->str_size, idx, len);
}

/* number of .dynsym entries from DT_HASH / DT_GNU_HASH (needed when the
 * section headers are missing) */
static uint64_t dynsym_count(const ElfFile *ef, const DynInfo *d) {
    uint64_t off;
    if (d->hash && elf_va_to_off(ef, d->hash, &off) && in_file(ef, off, 8))
        return r32(ef->data + off + 4);                 /* nchain */
    if (!d->gnuhash || !elf_va_to_off(ef, d->gnuhash, &off) || !in_file(ef, off, 16)) return 0;
    uint32_t nbuckets = r32(ef->data + off), symoff = r32(ef->data + off + 4);
    uint32_t bloom    = r32(ef->data + off + 8);
    uint64_t buckets  = off + 16 + (uint64_t)bloom * wsz(ef);   /* bloom words: class-sized */
    if (!table_ok(ef, buckets, nbuckets, 4)) return 0;
    uint32_t maxsym = 0;
    for (uint32_t i = 0; i < nbuckets; i++) {
        uint32_t b = r32(ef->data + buckets + (uint64_t)i * 4);
        if (b > maxsym) maxsym = b;
    }
    if (maxsym < symoff) return symoff;
    uint64_t chain = buckets + (uint64_t)nbuckets * 4;
    for (uint64_t i = maxsym; i - symoff < MAX_SYMS; i++) {
        uint64_t at = chain + (i - symoff) * 4;
        if (!in_file(ef, at, 4)) return i;
        if (r32(ef->data + at) & 1) return i + 1;
    }
    return maxsym + 1;
}

/* GLIBC_2.2.5-style version name of dynamic symbol `idx` */
static void sym_version(const ElfFile *ef, const DynInfo *d, uint64_t idx, char *out, size_t osz) {
    out[0] = '\0';
    uint64_t vs_off, vn_off;
    if (!d->versym || !d->verneed) return;
    if (!elf_va_to_off(ef, d->versym, &vs_off) || !elf_va_to_off(ef, d->verneed, &vn_off)) return;
    if (idx > (UINT64_MAX - vs_off) / 2 || !in_file(ef, vs_off + idx * 2, 2)) return;
    uint16_t want = r16(ef->data + vs_off + idx * 2) & 0x7fff;
    if (want < 2) return;                               /* local / global: no name */
    uint64_t vn = vn_off;
    for (int i = 0; i < 256; i++) {                     /* bounded walk */
        if (!in_file(ef, vn, 16)) return;
        uint16_t cnt  = r16(ef->data + vn + 2);
        uint32_t aux  = r32(ef->data + vn + 8), next = r32(ef->data + vn + 12);
        uint64_t va = vn + aux;
        for (int k = 0; k < cnt && k < 256; k++) {
            if (!in_file(ef, va, 16)) return;
            uint16_t other = r16(ef->data + va + 6);
            uint32_t name  = r32(ef->data + va + 8), anext = r32(ef->data + va + 12);
            if (other == want) {
                size_t nl = 0;
                const char *s = dyn_str(ef, d, name, &nl);
                if (s) clean_copy(out, osz, s, nl);
                return;
            }
            if (!anext) break;
            va += anext;
        }
        if (!next) return;
        vn += next;
    }
}

static void add_import(ElfFile *ef, int *cap, const DynInfo *d, uint64_t symidx,
                       uint64_t got, uint32_t rtype) {
    const unsigned ent = sym_ent(ef);
    if (!d->have_sym || symidx > (UINT64_MAX - d->sym_off) / ent) return;
    uint64_t so = d->sym_off + symidx * ent;
    if (!in_file(ef, so, ent)) return;
    const uint8_t *p = ef->data + so;
    if (r16(p + (is32(ef) ? 14 : 6)) != SHN_UNDEF) return;   /* defined here: not an import */
    size_t nl = 0;
    const char *s = dyn_str(ef, d, r32(p), &nl);
    if (!s || !nl) return;
    if (ef->nimp == *cap) {
        int nc = *cap ? *cap * 2 : 64;
        ElfImport *n = realloc(ef->imp, (size_t)nc * sizeof *n);
        if (!n) return;
        ef->imp = n; *cap = nc;
    }
    ElfImport *im = &ef->imp[ef->nimp];
    memset(im, 0, sizeof *im);
    im->name = clean_dup(s, nl);
    if (!im->name) return;
    im->got = got;
    im->rtype = rtype;
    sym_version(ef, d, symidx, im->version, sizeof im->version);
    ef->nimp++;
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

static void read_relocs(ElfFile *ef, const DynInfo *d, uint64_t va, uint64_t size,
                        int *icap, int *rcap) {
    uint64_t off;
    if (!va || !size) return;
    if (!elf_va_to_off(ef, va, &off)) { warn(ef, "relocation table at 0x%llx is not in the file", (unsigned long long)va); return; }
    uint64_t n = size / 24;
    if (n > MAX_RELOCS) n = MAX_RELOCS;
    if (!table_ok(ef, off, n, 24)) { warn(ef, "relocation table runs past the end of the file: ignored"); return; }
    for (uint64_t i = 0; i < n; i++) {
        const uint8_t *p = ef->data + off + i * 24;
        uint64_t r_off = r64(p), info = r64(p + 8), addend = r64(p + 16);
        uint32_t type = (uint32_t)info;
        uint64_t sym  = info >> 32;
        if (type == R_X86_64_RELATIVE) add_reloc(ef, rcap, r_off, addend);
        else if (sym && (type == R_X86_64_JUMP_SLOT || type == R_X86_64_GLOB_DAT || type == R_X86_64_64))
            add_import(ef, icap, d, sym, r_off, type);
    }
}

/* ELF32 i386 tables: REL (8-byte entries, the addend is the word stored
 * at r_offset) or RELA (12 bytes); r_info = sym << 8 | type */
static void read_relocs32(ElfFile *ef, const DynInfo *d, uint64_t va, uint64_t size,
                          bool rela, int *icap, int *rcap) {
    uint64_t off;
    if (!va || !size) return;
    if (!elf_va_to_off(ef, va, &off)) { warn(ef, "relocation table at 0x%llx is not in the file", (unsigned long long)va); return; }
    const unsigned ent = rela ? 12u : 8u;
    uint64_t n = size / ent;
    if (n > MAX_RELOCS) n = MAX_RELOCS;
    if (!table_ok(ef, off, n, ent)) { warn(ef, "relocation table runs past the end of the file: ignored"); return; }
    for (uint64_t i = 0; i < n; i++) {
        const uint8_t *p = ef->data + off + i * ent;
        uint64_t r_off = r32(p);
        uint32_t info  = r32(p + 4);
        uint32_t type  = info & 0xff, sym = info >> 8;
        if (type == R_386_RELATIVE) {
            if (rela) add_reloc(ef, rcap, r_off, r32(p + 8));
            else {                                     /* implicit addend */
                size_t avail = 0;
                const uint8_t *w = elf_va_ptr(ef, r_off, &avail);
                if (w && avail >= 4) add_reloc(ef, rcap, r_off, r32(w));
            }
        } else if (sym && (type == R_386_JMP_SLOT || type == R_386_GLOB_DAT || type == R_386_32))
            add_import(ef, icap, d, sym, r_off, type);
    }
}

/* DT_RELR (packed relative relocations): the value is the one stored in
 * the file, kept so code pointers in data can be found like RELA ones */
static void relr_apply(ElfFile *ef, int *rcap, uint64_t va) {
    size_t avail = 0;
    const uint8_t *p = elf_va_ptr(ef, va, &avail);
    if (p && avail >= wsz(ef)) add_reloc(ef, rcap, va, rw(ef, p));
}

static void read_relr(ElfFile *ef, uint64_t va, uint64_t size, int *rcap) {
    uint64_t off;
    if (!va || !size) return;
    if (!elf_va_to_off(ef, va, &off)) { warn(ef, "RELR table at 0x%llx is not in the file", (unsigned long long)va); return; }
    const unsigned w = wsz(ef);                    /* entry = word: 8, ELF32 4 */
    uint64_t n = size / w;
    if (n > MAX_RELOCS) n = MAX_RELOCS;
    if (!table_ok(ef, off, n, w)) { warn(ef, "RELR table runs past the end of the file: ignored"); return; }
    uint64_t base = 0;
    for (uint64_t i = 0; i < n && ef->nrel < (int)MAX_RELOCS; i++) {
        uint64_t e = rw(ef, ef->data + off + i * w);
        if (!(e & 1)) { relr_apply(ef, rcap, e); base = e + w; continue; }
        for (int b = 0; (e >>= 1) != 0; b++)
            if (e & 1) relr_apply(ef, rcap, base + (uint64_t)b * w);
        base += (uint64_t)(w * 8 - 1) * w;
    }
}

/* PLT stubs: every `jmp [rip+X]` (optionally `bnd`-prefixed) in .plt,
 * .plt.sec and .plt.got gives the GOT slot X of the stub it starts */
static void map_plt(ElfFile *ef) {
    static const char *names[] = { ".plt", ".plt.sec", ".plt.got" };
    for (int n = 0; n < 3; n++) {
        const ElfSection *s = elf_section_named(ef, names[n]);
        if (!s || s->bad || s->type == SHT_NOBITS || !in_file(ef, s->off, s->size)) continue;
        uint64_t ent = s->entsize ? s->entsize : 16;
        const uint8_t *p = ef->data + s->off;
        for (uint64_t i = 0; i + 6 <= s->size; i++) {
            uint64_t len;
            if (p[i] == 0xff && p[i + 1] == 0x25) len = 6;
            else if (i + 7 <= s->size && p[i] == 0xf2 && p[i + 1] == 0xff && p[i + 2] == 0x25) len = 7;
            else continue;
            int32_t  rel = (int32_t)r32(p + i + len - 4);
            uint64_t got = s->addr + i + len + (uint64_t)(int64_t)rel;
            ElfImport *im = (ElfImport *)elf_import_got(ef, got);
            if (im && !im->plt) im->plt = s->addr + (i / ent) * ent;
            i += len - 1;
        }
    }
}

/* i386 PLT stubs: `jmp [abs32]` (ff 25, non-PIC executables) or
 * `jmp [ebx+disp32]` (ff a3, PIC: ebx = the GOT base, DT_PLTGOT /
 * .got.plt), optionally `bnd`-prefixed, in .plt, .plt.sec and .plt.got */
static void map_plt32(ElfFile *ef, uint64_t gotbase) {
    static const char *names[] = { ".plt", ".plt.sec", ".plt.got" };
    if (!gotbase) {
        const ElfSection *g = elf_section_named(ef, ".got.plt");
        if (g && !g->bad) gotbase = g->addr;
    }
    for (int n = 0; n < 3; n++) {
        const ElfSection *s = elf_section_named(ef, names[n]);
        if (!s || s->bad || s->type == SHT_NOBITS || !in_file(ef, s->off, s->size)) continue;
        uint64_t ent = s->entsize >= 8 ? s->entsize : 16;   /* ld gives .plt entsize 4 */
        const uint8_t *p = ef->data + s->off;
        for (uint64_t i = 0; i + 6 <= s->size; i++) {
            uint64_t k = i;
            if (p[k] == 0xf2) { if (i + 7 > s->size) break; k++; }
            if (p[k] != 0xff || (p[k + 1] != 0x25 && p[k + 1] != 0xa3)) continue;
            uint32_t disp = r32(p + k + 2);
            uint64_t got;
            if (p[k + 1] == 0x25) got = disp;
            else if (gotbase) got = (gotbase + disp) & 0xffffffffu;
            else { i = k + 5; continue; }
            ElfImport *im = (ElfImport *)elf_import_got(ef, got);
            if (im && !im->plt) im->plt = s->addr + (i / ent) * ent;
            i = k + 5;
        }
    }
}

static void add_ctor(ElfFile *ef, uint64_t va) {
    if (!va || va == UINT64_MAX || (is32(ef) && va == UINT32_MAX) || ef->nctors >= MAX_CTORS || !elf_va_exec(ef, va)) return;
    for (int i = 0; i < ef->nctors; i++) if (ef->ctors[i] == va) return;
    uint64_t *n = realloc(ef->ctors, (size_t)(ef->nctors + 1) * sizeof *n);
    if (!n) return;
    ef->ctors = n;
    ef->ctors[ef->nctors++] = va;
}

static void read_ptr_array(ElfFile *ef, uint64_t va, uint64_t size) {
    if (!va) return;
    const unsigned w = wsz(ef);
    for (uint64_t i = 0; i < size / w && i < MAX_CTORS; i++) {
        uint64_t v;
        if (!elf_read_ptr(ef, va + i * w, &v)) break;
        add_ctor(ef, v);
    }
}

static int cmp_sym(const void *a, const void *b) {
    const ElfSymbol *x = a, *y = b;
    if (x->value != y->value) return x->value < y->value ? -1 : 1;
    if (x->kind != y->kind) return x->kind < y->kind ? -1 : 1;        /* FUNC first   */
    if (x->dynamic != y->dynamic) return x->dynamic ? 1 : -1;         /* .symtab first */
    if ((x->bind == 0) != (y->bind == 0)) return x->bind == 0 ? 1 : -1; /* global first */
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

void elf_free(ElfFile *ef) {
    if (!ef) return;
    for (int i = 0; i < ef->nsym; i++) free(ef->sym[i].name);
    for (int i = 0; i < ef->nimp; i++) free(ef->imp[i].name);
    for (int i = 0; i < ef->nneeded; i++) free(ef->needed[i]);
    free(ef->sym); free(ef->imp); free(ef->rel); free(ef->needed);
    free(ef->seg); free(ef->sec); free(ef->map); free(ef->ctors); free(ef->fstart);
    free(ef->data);
    memset(ef, 0, sizeof *ef);
}

bool elf_parse(ElfFile *ef, const uint8_t *buf, size_t len, char *err, size_t esz) {
    memset(ef, 0, sizeof *ef);
    const bool c32 = elf_is_elf(buf, len) && buf[4] == 1;      /* ELF32 header: 52 bytes */
    if (len < (c32 ? 52u : 64u))  { set_err(err, esz, "File too small for an ELF header (%zu bytes)", len); return false; }
    if (len > ELF_MAX_FILE)       { set_err(err, esz, "File too large for the analysis (%zu MB)", len >> 20); return false; }
    if (!elf_is_elf(buf, len))    { set_err(err, esz, "Not an ELF file (no \\x7fELF magic)"); return false; }
    if (buf[4] != 1 && buf[4] != 2) { set_err(err, esz, "Malformed ELF: invalid class %u", buf[4]); return false; }
    if (buf[5] == 2)              { set_err(err, esz, "Big-endian ELF: not supported"); return false; }
    if (buf[5] != 1)              { set_err(err, esz, "Malformed ELF: invalid data encoding %u", buf[5]); return false; }
    if (buf[6] != 1)              { set_err(err, esz, "Malformed ELF: invalid version %u", buf[6]); return false; }

    ef->data = malloc(len);
    if (!ef->data) { set_err(err, esz, "Out of memory"); return false; }
    memcpy(ef->data, buf, len);
    ef->size = len;

    const uint8_t *h = ef->data;
    ef->bits    = c32 ? 32 : 64;
    ef->type    = r16(h + 16);
    ef->machine = r16(h + 18);
    ef->osabi   = h[7];
    uint64_t phoff, shoff;
    uint16_t ehsize, phentsize, shentsize;
    uint32_t phnum, shnum, shstrndx;
    if (c32) {                                     /* Elf32_Ehdr */
        ef->entry = r32(h + 24);
        phoff  = r32(h + 28); shoff = r32(h + 32);
        ehsize = r16(h + 40); phentsize = r16(h + 42); shentsize = r16(h + 46);
        phnum  = r16(h + 44); shnum = r16(h + 48); shstrndx = r16(h + 50);
    } else {                                       /* Elf64_Ehdr */
        ef->entry = r64(h + 24);
        phoff  = r64(h + 32); shoff = r64(h + 40);
        ehsize = r16(h + 52); phentsize = r16(h + 54); shentsize = r16(h + 58);
        phnum  = r16(h + 56); shnum = r16(h + 60); shstrndx = r16(h + 62);
    }
    const unsigned ehmin = c32 ? 52u : 64u, phent = c32 ? 32u : 56u, shent = c32 ? 40u : 64u;

    if (c32) {
        if (ef->machine == EM_X86_64) {
            set_err(err, esz, "32-bit ELF for x86-64 (x32 ABI): not supported");
            goto fail;
        }
        if (ef->machine != EM_386) {
            set_err(err, esz, "32-bit ELF for %s (machine %u): only x86 (i386) is supported in 32 bits",
                    elf_machine_name(ef->machine), ef->machine);
            goto fail;
        }
        ef->arch = ELF_ARCH_X86_32;
    } else {
        if (ef->machine != EM_X86_64) {
            set_err(err, esz, "Machine %s (%u): only x86-64 is supported for now", elf_machine_name(ef->machine), ef->machine);
            goto fail;
        }
        ef->arch = ELF_ARCH_X86_64;
    }
    if (ehsize < ehmin) { set_err(err, esz, "Malformed ELF: header size %u < %u", ehsize, ehmin); goto fail; }
    if (ef->type != ET_REL && ef->type != ET_EXEC && ef->type != ET_DYN) {
        set_err(err, esz, "ELF type %s: only executables, shared objects and object files are analysed", elf_type_name(ef->type));
        goto fail;
    }

    /* extended numbering: the real counts live in section header 0 */
    if ((shnum == 0 && shoff) || shstrndx == SHN_XINDEX || phnum == PN_XNUM) {
        if (shentsize == shent && table_ok(ef, shoff, 1, shent)) {
            const uint8_t *s0 = ef->data + shoff;  /* sh_size, sh_link, sh_info */
            if (shnum == 0)             shnum    = c32 ? r32(s0 + 20) : (uint32_t)r64(s0 + 32);
            if (shstrndx == SHN_XINDEX) shstrndx = r32(s0 + (c32 ? 24 : 40));
            if (phnum == PN_XNUM)       phnum    = r32(s0 + (c32 ? 28 : 44));
        } else if (phnum == PN_XNUM) {
            set_err(err, esz, "Malformed ELF: extended segment count without a readable section 0");
            goto fail;
        }
    }

    /* program headers: required to be sound */
    if (phnum) {
        if (phentsize != phent) { set_err(err, esz, "Malformed ELF: program header size %u (expected %u)", phentsize, phent); goto fail; }
        if (phnum > MAX_PHNUM || !table_ok(ef, phoff, phnum, phent)) {
            set_err(err, esz, "Malformed ELF: program header table (offset 0x%llx, %u entries) outside the file",
                    (unsigned long long)phoff, phnum);
            goto fail;
        }
        ef->seg = calloc(phnum, sizeof *ef->seg);
        if (!ef->seg) { set_err(err, esz, "Out of memory"); goto fail; }
        ef->nseg = (int)phnum;
        for (uint32_t i = 0; i < phnum; i++) {
            const uint8_t *p = ef->data + phoff + (uint64_t)i * phent;
            ElfSegment *s = &ef->seg[i];
            s->type   = r32(p);
            if (c32) {                             /* Elf32_Phdr: p_flags after p_memsz */
                s->off    = r32(p + 4);
                s->vaddr  = r32(p + 8);
                s->filesz = r32(p + 16);
                s->memsz  = r32(p + 20);
                s->flags  = r32(p + 24);
                s->align  = r32(p + 28);
            } else {                               /* Elf64_Phdr */
                s->flags  = r32(p + 4);
                s->off    = r64(p + 8);
                s->vaddr  = r64(p + 16);
                s->filesz = r64(p + 32);
                s->memsz  = r64(p + 40);
                s->align  = r64(p + 48);
            }
            if (s->type != PT_LOAD) continue;
            if (s->filesz > s->memsz) {
                set_err(err, esz, "Malformed ELF: segment %u has file size > memory size", i);
                goto fail;
            }
            if (!in_file(ef, s->off, s->filesz)) {
                set_err(err, esz, "Malformed ELF: segment %u (LOAD, offset 0x%llx, 0x%llx bytes) runs past the end of the file (truncated sample?)",
                        i, (unsigned long long)s->off, (unsigned long long)s->filesz);
                goto fail;
            }
            if (s->memsz > (c32 ? (uint64_t)UINT32_MAX + 1 : UINT64_MAX) - s->vaddr) {
                set_err(err, esz, "Malformed ELF: segment %u wraps around the address space", i);
                goto fail;
            }
            if (s->filesz && !add_map(ef, s->vaddr, s->off, s->filesz, s->memsz, s->flags)) {
                set_err(err, esz, "Out of memory"); goto fail;
            }
        }
    }

    /* section headers: optional, ignored when they cannot be trusted */
    parse_sections(ef, shoff, shnum, shentsize, shstrndx);

    if (ef->type == ET_REL) {                      /* object file: sections are the map */
        for (int i = 0; i < ef->nsec; i++) {
            const ElfSection *s = &ef->sec[i];
            if (!(s->flags & SHF_ALLOC) || s->bad || s->type == SHT_NOBITS || !s->size) continue;
            add_map(ef, s->addr, s->off, s->size, s->size, 4 | ((s->flags & SHF_EXECINSTR) ? PF_X : 0) | ((s->flags & 1) ? 2 : 0));
        }
    } else if (ef->nmap == 0) {
        set_err(err, esz, "Malformed ELF: no loadable segment");
        goto fail;
    }

    /* interpreter */
    for (int i = 0; i < ef->nseg; i++) {
        const ElfSegment *s = &ef->seg[i];
        if (s->type != PT_INTERP) continue;
        if (!in_file(ef, s->off, s->filesz) || !s->filesz) { warn(ef, "INTERP segment outside the file"); break; }
        const char *z = memchr(ef->data + s->off, 0, (size_t)s->filesz);
        size_t n = z ? (size_t)(z - (const char *)ef->data - s->off) : (size_t)s->filesz;
        clean_copy(ef->interp, sizeof ef->interp, (const char *)ef->data + s->off, n);
        break;
    }

    /* dynamic table: libraries, imports, relocations, dynamic symbols */
    DynInfo *d = calloc(1, sizeof *d);
    if (!d) { set_err(err, esz, "Out of memory"); goto fail; }
    parse_dynamic(ef, d);
    if (d->present) {
        ef->needed = calloc((size_t)d->nneeded + 1, sizeof *ef->needed);
        for (int i = 0; ef->needed && i < d->nneeded; i++) {
            size_t nl = 0;
            const char *s = dyn_str(ef, d, d->needed[i], &nl);
            if (s) ef->needed[ef->nneeded++] = clean_dup(s, nl);
        }
        if (d->soname >= 0) {
            size_t nl = 0;
            const char *s = dyn_str(ef, d, (uint64_t)d->soname, &nl);
            if (s) clean_copy(ef->soname, sizeof ef->soname, s, nl);
        }
        int icap = 0, rcap = 0;
        if (c32) {
            if (d->has_relent && d->relent != 8) warn(ef, "DT_RELENT %llu (expected 8): REL table ignored", (unsigned long long)d->relent);
            else read_relocs32(ef, d, d->rel, d->relsz, false, &icap, &rcap);
            if (d->has_relaent && d->relaent != 12) warn(ef, "DT_RELAENT %llu (expected 12): RELA table ignored", (unsigned long long)d->relaent);
            else read_relocs32(ef, d, d->rela, d->relasz, true, &icap, &rcap);
            if (d->has_pltrel && d->pltrel != DT_REL && d->pltrel != DT_RELA)
                warn(ef, "DT_PLTREL %llu is neither REL nor RELA: PLT relocations ignored", (unsigned long long)d->pltrel);
            else read_relocs32(ef, d, d->jmprel, d->pltrelsz, d->has_pltrel && d->pltrel == DT_RELA, &icap, &rcap);
        } else {
            read_relocs(ef, d, d->rela, d->relasz, &icap, &rcap);
            read_relocs(ef, d, d->jmprel, d->pltrelsz, &icap, &rcap);
        }
        read_relr(ef, d->relr, d->relrsz, &rcap);
    }
    if (ef->nimp) qsort(ef->imp, (size_t)ef->nimp, sizeof *ef->imp, cmp_imp);
    if (ef->nrel) qsort(ef->rel, (size_t)ef->nrel, sizeof *ef->rel, cmp_rel);

    /* symbols */
    int scap = 0;
    bool have_symtab = false, have_dynsym = false;
    for (int i = 0; i < ef->nsec; i++) {
        const ElfSection *s = &ef->sec[i];
        if ((s->type != SHT_SYMTAB && s->type != SHT_DYNSYM) || s->bad) continue;
        if (s->entsize && s->entsize != sym_ent(ef)) { warn(ef, "section %d: symbol size %llu: ignored", i, (unsigned long long)s->entsize); continue; }
        if (s->link >= (uint32_t)ef->nsec || ef->sec[s->link].bad || ef->sec[s->link].type != SHT_STRTAB) {
            warn(ef, "section %d: symbol names (section %u) invalid: ignored", i, s->link);
            continue;
        }
        const ElfSection *st = &ef->sec[s->link];
        read_symtab(ef, &scap, s->off, s->size / sym_ent(ef), st->off, st->size, s->type == SHT_DYNSYM);
        if (s->type == SHT_SYMTAB) have_symtab = true; else have_dynsym = true;
    }
    if (!have_dynsym && d->present && d->have_sym && d->have_str) {   /* no sections: via the hash table */
        uint64_t n = dynsym_count(ef, d);
        if (n) read_symtab(ef, &scap, d->sym_off, n, d->str_off, d->str_size, true);
    }
    ef->stripped = !have_symtab;
    if (ef->nsym) qsort(ef->sym, (size_t)ef->nsym, sizeof *ef->sym, cmp_sym);

    if (c32) map_plt32(ef, d->pltgot);
    else     map_plt(ef);

    /* constructors / destructors */
    if (d->present) {
        add_ctor(ef, d->init);
        add_ctor(ef, d->fini);
        read_ptr_array(ef, d->prearr, d->prearrsz);
        read_ptr_array(ef, d->initarr, d->initarrsz);
        read_ptr_array(ef, d->finiarr, d->finiarrsz);
    } else {
        const char *arr[] = { ".preinit_array", ".init_array", ".fini_array" };
        for (int k = 0; k < 3; k++) {
            const ElfSection *s = elf_section_named(ef, arr[k]);
            if (s && !s->bad) read_ptr_array(ef, s->addr, s->size);
        }
    }

    bool has_interp = ef->interp[0] != '\0';
    ef->pie = ef->type == ET_DYN && ((d->flags1 & DF_1_PIE) || has_interp);
    ef->is_static = ef->type != ET_REL && !has_interp && d->nneeded == 0;
    free(d);

    if (ef->type != ET_REL && ef->entry && !elf_va_exec(ef, ef->entry))
        warn(ef, "entry point 0x%llx is not in an executable segment", (unsigned long long)ef->entry);
    return true;

fail:
    elf_free(ef);
    return false;
}

bool elf_load(ElfFile *ef, const char *path, char *err, size_t esz) {
    memset(ef, 0, sizeof *ef);
    FILE *f = fopen(path, "rb");
    if (!f) { set_err(err, esz, "Cannot open %s", path); return false; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); set_err(err, esz, "Cannot seek in %s", path); return false; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); set_err(err, esz, "Cannot size %s", path); return false; }
    if ((unsigned long)sz > ELF_MAX_FILE) { fclose(f); set_err(err, esz, "File too large for the analysis (%ld MB)", sz >> 20); return false; }
    rewind(f);
    uint8_t *buf = malloc(sz ? (size_t)sz : 1);
    if (!buf) { fclose(f); set_err(err, esz, "Out of memory"); return false; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); set_err(err, esz, "Read error on %s", path); return false; }
    bool ok = pe_is_pe(buf, (size_t)sz) || ((size_t)sz >= 2 && buf[0] == 'M' && buf[1] == 'Z')
            ? pe_parse(ef, buf, (size_t)sz, err, esz)
            : elf_parse(ef, buf, (size_t)sz, err, esz);
    free(buf);
    return ok;
}

const char *elf_kind_name(const ElfFile *ef) {
    if (ef->fmt == ELF_FMT_PE) return ef->pe.dll ? "PE DLL" : "PE EXE";
    return elf_type_name(ef->type);
}
