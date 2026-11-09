/* PE headers and address conversions (peload.c), for the F9 view.
 *
 * pe_parse (elfload.h) loads a PE32 (x86) or PE32+ (x64) file into an
 * ElfFile; this header gives what the ElfFile has no field for: the raw
 * header values (alignments, data directories) and RVA conversions.
 *
 * pe_read_headers reads and checks the DOS header, the "PE\0\0"
 * signature, the COFF header and the optional header (PE32 0x10b or
 * PE32+ 0x20b), nothing past them: every read is bounded by `len`. It
 * fails, with a reason in err, on anything the Windows loader would
 * refuse in these headers (e_lfanew outside the file, truncated or
 * inconsistent optional header, 0 or more than 96 sections, invalid
 * alignments, image wrapping around the address space). The machine is
 * not checked here: pe_parse refuses what it does not analyse.
 *
 * The data directories are copied as stored (entry 4, the certificate
 * table, holds a file offset, the others RVAs); they are not checked
 * against the image here.
 *
 * No curses, no capstone, no <windows.h>. */
#ifndef PELOAD_H
#define PELOAD_H

#include "elfload.h"

#define PE_NDIR 16                         /* data directories looked at    */

typedef struct { uint32_t rva, size; } PeDir;

typedef struct {
    uint32_t lfanew;                       /* DOS e_lfanew: "PE\0\0" offset  */
    /* COFF file header */
    uint16_t machine, nsec, optsz, chars;
    uint32_t timestamp, symoff, nsyms;
    /* optional header */
    uint16_t magic;                        /* 0x10b PE32, 0x20b PE32+        */
    uint8_t  bits;                         /* 32 (PE32) or 64 (PE32+)        */
    uint8_t  linker_major, linker_minor;
    uint32_t entry;                        /* AddressOfEntryPoint (RVA)      */
    uint64_t image_base;
    uint32_t sect_align, file_align;
    uint16_t os_major, os_minor;
    uint32_t size_image, size_headers, checksum;
    uint16_t subsystem, dllchars;
    uint32_t nrva;                         /* NumberOfRvaAndSizes as stored  */
    uint32_t ndir;                         /* read: min(nrva, PE_NDIR)       */
    PeDir    dir[PE_NDIR];                 /* beyond ndir: zero              */
    uint64_t opt_off, sec_off;             /* file offsets of the optional
                                              header and the section table  */
} PeHeaders;

bool        pe_read_headers(const uint8_t *buf, size_t len, PeHeaders *h, char *err, size_t esz);
const char *pe_dir_name(unsigned i);       /* "IMPORT", "BASERELOC"... */

/* RVA <-> file offset <-> VA on a file pe_parse loaded (VA = ImageBase +
 * RVA). An RVA has a file offset only inside the headers or the raw data
 * of a section: not in the zero-filled tail of a section (VirtualSize >
 * SizeOfRawData), nor in a section without data. */
uint64_t pe_rva_to_va(const ElfFile *ef, uint32_t rva);
bool     pe_va_to_rva(const ElfFile *ef, uint64_t va, uint32_t *rva);   /* inside SizeOfImage */
bool     pe_rva_to_off(const ElfFile *ef, uint32_t rva, uint64_t *off);
bool     pe_off_to_rva(const ElfFile *ef, uint64_t off, uint32_t *rva);

/* Tables behind the data directories (pe_parse reads them into the
 * ElfFile: imports, exports as symbols, base relocations; these give the
 * rest for the F9 view). */
#define PE_BOUND_SHOW 8
typedef struct {
    int      n;                            /* bound DLLs                    */
    uint32_t nfwd;                         /* their forwarder refs          */
    char     name[PE_BOUND_SHOW][64];      /* the first ones                */
} PeBound;
/* bound import table: number of DLLs, 0 when none, -1 when malformed
 * (b holds what was read before) */
int  pe_bound_imports(const ElfFile *ef, PeBound *b);

#define PE_FWD_SHOW 6
typedef struct {
    char     name[128];                    /* DLL name in the table         */
    uint32_t base, nfunc, nname;           /* ordinal base, table sizes     */
    uint32_t ncode, ndata;                 /* exports in code / elsewhere   */
    uint32_t nfwd;                         /* forwarders ("dll.func")       */
    uint32_t nbadord, nbadname, nbadrva, nbadfwd;   /* malformed entries    */
    bool     names_bad;                    /* name tables outside the file  */
    int      nfwdshow;
    char     fwd[PE_FWD_SHOW][136];        /* "name -> dll.func"            */
    char     err[96];                      /* why the table was not read    */
} PeExports;
/* export directory summary: false when there is none or it is unreadable
 * (x->err says why) */
bool pe_exports(const ElfFile *ef, PeExports *x);

/* Flags of the .NET (CLR) header, false when there is none */
#define PE_CLR_ILONLY 0x1                  /* COMIMAGE_FLAGS_ILONLY: no native code */
bool pe_clr_flags(const ElfFile *ef, uint32_t *flags);

/* ─── exception data, load config (part 3) ─────────────────────────
 *
 * .pdata (PE32+ x64 only): RUNTIME_FUNCTION { BeginAddress, EndAddress,
 * UnwindData } entries, each one checked: [begin, end) non-empty, inside
 * SizeOfImage and starting in file-backed executable bytes; table size a
 * multiple of 12 (the rest is ignored), sorted by begin (an unsorted
 * table is sorted here, with a warning), no entry overlapping the one
 * before it (the later one is dropped). UNWIND_INFO { version 1 or 2 |
 * flags << 3, prolog size, CountOfCodes, frame }: read only when its 4
 * bytes and its codes are in the file. A chained entry (UNW_FLAG_CHAININFO:
 * a RUNTIME_FUNCTION after the codes, or UnwindData with bit 0 set: the
 * RVA + 1 of another entry) is a fragment of the function at the root of
 * its chain, followed at most PE_CHAIN_MAX links; a chain coming back to
 * an unwind block already seen is cyclic and the entry is dropped, as
 * one longer than that; a chain cut by bytes outside the file, or whose
 * root is not code, leaves a fragment without a parent. With
 * UNW_FLAG_EHANDLER / UHANDLER the RVA after the codes is the language
 * handler (kept if inside the image). */
#define PE_CHAIN_MAX   32                  /* links followed in one chain    */

#define PE_RF_FRAG     0x01                /* chained: part of `parent`      */
#define PE_RF_EH       0x02                /* UNW_FLAG_EHANDLER              */
#define PE_RF_UH       0x04                /* UNW_FLAG_UHANDLER              */
#define PE_RF_NOUNW    0x08                /* UNWIND_INFO unreadable / bad   */

typedef struct {
    uint32_t begin, end;                   /* RVAs, [begin, end)             */
    uint32_t parent;                       /* PE_RF_FRAG: begin of the root
                                              function of the chain         */
    uint32_t handler;                      /* RVA of the handler, 0: none    */
    uint8_t  flags;                        /* PE_RF_*                        */
} PeRtFunc;

typedef struct {
    PeRtFunc *e;   uint32_t n;             /* entries kept, sorted by begin
                                              (malloc'ed: pe_pdata_free)    */
    uint32_t nent;                         /* entries in the table (capped)  */
    uint32_t rest;                         /* size % 12                      */
    uint32_t nfunc, nfrag, nhandler;       /* among the kept ones            */
    uint32_t nempty;                       /* begin 0 or end <= begin        */
    uint32_t nout;                         /* past SizeOfImage / not code    */
    uint32_t nunsorted;                    /* begin lower than the one before */
    uint32_t noverlap;                     /* overlapping the one before     */
    uint32_t nbadunw;                      /* UNWIND_INFO cut / bad version  */
    uint32_t ncycle, ndeep, norphan;       /* chains: cyclic (dropped),
                                              longer than PE_CHAIN_MAX
                                              (dropped), broken or root not
                                              code (kept as fragments with
                                              parent 0)                    */
    uint32_t nbadhandler;                  /* handler RVA outside the image  */
    bool     capped;                       /* more than the MAX_PDATA cap    */
    char     err[96];                      /* why the table was not read     */
} PePdata;
/* false when there is no .pdata (PE32+ only) or it is unreadable (err) */
bool pe_pdata(const ElfFile *ef, PePdata *p);
void pe_pdata_free(PePdata *p);

/* IMAGE_LOAD_CONFIG_DIRECTORY32 / 64: a field is read only when it lies
 * inside both the structure's own Size and the bytes of the file. */
typedef struct {
    bool     present;                      /* directory there and readable   */
    uint32_t dirsize;                      /* size in the data directory     */
    uint32_t size;                         /* the structure's Size field     */
    uint32_t avail;                        /* bytes of it in the file        */
    uint32_t used;                         /* min(size, avail, PE_LC_MAX)    */
    bool     has_cookie, has_seh, has_cf, has_gflags;   /* fields present    */
    uint64_t cookie;                       /* SecurityCookie (VA)            */
    uint64_t seh_table, seh_count;         /* SEHandlerTable / Count (PE32)  */
    uint64_t cf_table, cf_count;           /* GuardCFFunctionTable / Count   */
    uint32_t guard_flags;                  /* GuardFlags                     */
    char     err[96];                      /* aberrant size, unreadable...   */
} PeLoadConfig;
#define PE_LC_MAX      0x1000              /* bytes of the structure looked at */
#define PE_GUARD_CF_INSTRUMENTED     0x00000100u
#define PE_GUARD_CF_FUNCTION_TABLE   0x00000400u
bool pe_load_config(const ElfFile *ef, PeLoadConfig *lc);

/* SafeSEH handler table (PE32) and CFG function table (GuardCF, PE32 and
 * PE32+, entries of 4 + (GuardFlags >> 28) bytes): the VAs of the
 * entries inside the image and in file-backed executable bytes, in
 * table order. The table itself must lie inside the image and the file
 * (else bad, err), at most PE_TABLE_MAX entries are read, and only up to
 * the first entry not above the one before it (the loader binary-searches
 * these tables; a count running past the real table reads other data):
 * nunsorted is then the number of entries ignored. */
#define PE_TABLE_MAX   (1u << 20)
typedef struct {
    uint64_t *va;  uint32_t n;             /* malloc'ed: pe_table_free       */
    uint64_t count;                        /* entries the header declares    */
    uint32_t nout;                         /* outside the image / not code   */
    uint32_t nunsorted;                    /* ignored: from the first entry
                                              not above the one before      */
    uint32_t stride;                       /* bytes per entry                */
    bool     present, bad, capped;
    char     err[96];
} PeTable;
bool pe_safeseh(const ElfFile *ef, PeTable *t);
bool pe_guard_cf(const ElfFile *ef, PeTable *t);
void pe_table_free(PeTable *t);

#endif
