/* ELF64 x86-64 loader for the F9 static analysis view (read-only).
 *
 * The whole file is copied in memory and every table is checked against
 * its size before it is read: offsets, counts, entry sizes, string
 * tables, overflows. Segments are what the kernel uses, so a bad program
 * header table (or a segment running past the end of the file) makes the
 * load fail; a bad section header table (often wiped or forged by packers
 * and malware) is only reported and ignored, the analysis then relies on
 * the segments and the dynamic table.
 *
 * Nothing here executes, maps executable memory or writes to the file.
 * No curses, no capstone: this file builds everywhere. */
#ifndef ELFLOAD_H
#define ELFLOAD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define ELF_MAX_FILE   (512u * 1024u * 1024u)   /* refuse bigger files     */
#define ELF_MAX_WARN   8

/* program header (segment) */
typedef struct {
    uint32_t type, flags;                  /* PT_*, PF_X / PF_W / PF_R      */
    uint64_t off, vaddr, filesz, memsz, align;
} ElfSegment;

/* section header */
typedef struct {
    char     name[64];
    uint32_t type, link, info;
    uint64_t flags, addr, off, size, entsize;
    bool     bad;                          /* contents outside the file    */
} ElfSection;

enum { ELF_SYM_FUNC = 1, ELF_SYM_OBJECT = 2, ELF_SYM_OTHER = 3 };

typedef struct {
    char     *name;
    uint64_t  value, size;
    uint8_t   kind;                        /* ELF_SYM_*                    */
    uint8_t   bind;                        /* 0 local, 1 global, 2 weak    */
    uint16_t  shndx;
    bool      dynamic;                     /* from .dynsym                 */
    bool      exported;                    /* defined + global/weak + dyn  */
} ElfSymbol;

typedef struct {
    char     *name;                        /* "puts" (version stripped)    */
    char      version[32];                 /* "GLIBC_2.2.5" or ""          */
    uint64_t  got;                         /* GOT slot address             */
    uint64_t  plt;                         /* PLT stub address, 0 if none  */
    uint32_t  rtype;                       /* R_X86_64_JUMP_SLOT/GLOB_DAT  */
} ElfImport;

/* R_X86_64_RELATIVE relocation: *(va) = base + addend */
typedef struct { uint64_t va; uint64_t addend; } ElfReloc;

/* a file-backed address range (PT_LOAD, or a section for .o files) */
typedef struct {
    uint64_t va, off, filesz, memsz;
    uint32_t flags;                        /* PF_*                         */
} ElfMap;

typedef struct {
    uint8_t    *data;                      /* the whole file (owned)       */
    size_t      size;

    uint16_t    type, machine;             /* ET_*, EM_*                   */
    uint8_t     osabi;
    uint64_t    entry;
    bool        pie, is_static, stripped;

    ElfSegment *seg;  int nseg;
    ElfSection *sec;  int nsec;            /* 0 when the table is ignored  */
    ElfMap     *map;  int nmap;
    ElfSymbol  *sym;  int nsym;            /* sorted by value              */
    ElfImport  *imp;  int nimp;            /* sorted by GOT address        */
    ElfReloc   *rel;  int nrel;            /* sorted by va                 */
    char      **needed; int nneeded;       /* DT_NEEDED                    */
    char        interp[256];
    char        soname[128];

    /* constructors / destructors (DT_INIT, DT_FINI, .init_array...) */
    uint64_t   *ctors; int nctors;

    char        warn[ELF_MAX_WARN][160];
    int         nwarn;
} ElfFile;

/* Loads and checks `path`. On failure returns false with a reason in err;
 * the ElfFile is then empty (elf_free is still safe). */
bool elf_load(ElfFile *ef, const char *path, char *err, size_t esz);
/* Same on a buffer; the bytes are copied. */
bool elf_parse(ElfFile *ef, const uint8_t *buf, size_t len, char *err, size_t esz);
void elf_free(ElfFile *ef);

/* quick check of the 4 magic bytes + class, without loading */
bool elf_is_elf(const uint8_t *buf, size_t len);

/* virtual address <-> file offset. va_ptr gives the bytes behind a
 * virtual address and how many follow it inside the same mapping. */
bool           elf_va_to_off(const ElfFile *ef, uint64_t va, uint64_t *off);
bool           elf_off_to_va(const ElfFile *ef, uint64_t off, uint64_t *va);
const uint8_t *elf_va_ptr(const ElfFile *ef, uint64_t va, size_t *avail);
const ElfMap  *elf_map_of(const ElfFile *ef, uint64_t va);   /* NULL: unmapped */
bool           elf_va_exec(const ElfFile *ef, uint64_t va);  /* file-backed + X */
/* pointer-sized value stored at va, RELATIVE relocations applied */
bool           elf_read_ptr(const ElfFile *ef, uint64_t va, uint64_t *out);

/* lookups (NULL when nothing matches) */
const ElfSection *elf_section_at(const ElfFile *ef, uint64_t va);
const ElfSection *elf_section_named(const ElfFile *ef, const char *name);
const ElfSymbol  *elf_symbol_at(const ElfFile *ef, uint64_t va);          /* exact   */
const ElfSymbol  *elf_symbol_near(const ElfFile *ef, uint64_t va, uint64_t *delta);
const ElfImport  *elf_import_got(const ElfFile *ef, uint64_t got);
const ElfImport  *elf_import_plt(const ElfFile *ef, uint64_t plt);

/* names for display */
const char *elf_type_name(uint16_t type);
const char *elf_machine_name(uint16_t m);
const char *elf_seg_type_name(uint32_t t);
const char *elf_sec_type_name(uint32_t t);
void        elf_flags_str(uint32_t pf, char out[4]);           /* "R-X"   */
void        elf_sec_flags_str(uint64_t f, char out[8]);        /* "WAX"   */

#endif
