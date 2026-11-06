/* Static disassembly engine for the F9 view (capstone, x86-64, read-only).
 *
 * Recursive descent from the entry point, the function symbols, the
 * constructors / destructors (DT_INIT, .init_array...) and the PLT stubs:
 * direct calls start new functions, direct jmp/jcc are followed, ret,
 * indirect jmp, hlt/ud2/int3 and `call` to a no-return function (exit,
 * abort, __stack_chk_fail...) end the path. `main` is taken from the
 * `rdi` argument of the call to __libc_start_main. Code nothing points
 * to is then looked for in the gaps with prologue patterns (endbr64,
 * push rbp; mov rbp, rsp...).
 *
 * Code pointers: a `lea reg, [rip+X]` whose X lies in executable code
 * (a callback given to qsort / signal / pthread_create...) makes X a
 * function (FN_CODEPTR) and a new root of the work list, once the code
 * already reachable has been walked, and only if X is not inside an
 * instruction already decoded and a linear decode from it is clean.
 *
 * Code pointers in data (callback tables, vtables, `fp = func`): the
 * relocated words of a PIE / shared object (RELATIVE, RELR: the addend
 * is the target), or the 8-aligned words of .data, .data.rel.ro, .rodata
 * and .init_array of a non-PIE executable (its non-executable mappings
 * when there is no section table; import GOT slots are skipped). A
 * target must lie in executable code (with a section table: an
 * executable section other than .plt*), not inside an instruction
 * already decoded nor in code reached by falling through, and decode
 * cleanly (same probe as FN_CODEPTR). It also needs a function-start
 * sign: strong (16-byte alignment, endbr64 / push rbp; mov rbp, rsp) or,
 * for a relocated word only (a raw word may be an integer), weak
 * (padding or the end of a decoded path just before it). A run of
 * consecutive code pointers is a table of functions when 3/4 of its
 * entries show such a sign, and its entries need none of their own;
 * otherwise (likely a switch table) the run gives nothing. A run read
 * by a decoded indexed jump (`jmp [r+i*8]`, or `mov r2, [r+i*8]` then
 * `jmp r2`, r from `lea [rip+X]` / `mov r, X`) is a switch table and is
 * skipped. Accepted targets become FN_DATAPTR functions, explored at
 * once, lone pointers first, after the lea code pointers and before the
 * prologue scan. One is dropped at the end if code decoded later reads
 * its table by such a jump or falls through into it (its instructions
 * stay decoded).
 *
 * Jump tables (switch), read along a path (registers followed from its
 * start, and across a direct jmp to code not decoded yet, the next path
 * walked): absolute, `jmp [T + i*8]` or `mov r, [T + i*8]; jmp r`;
 * relative (PIE, hand-written asm), `movsxd r, dword [T + i*4]; add r,
 * T; jmp r` (or `lea r2, [T + r]`), each case at T + entry. The number
 * of entries is known when the index was bounded on the path: `cmp i,
 * imm; ja` (imm + 1), `jae` (imm), `and i, imm` (imm + 1). A table is
 * read once the work list is empty (those of a known size first), from
 * T on, in the data holding T (with a section table: a file-backed
 * non-code section, .rodata even in an R+X segment; without: a
 * non-executable mapping), as 8-byte words (relocations applied) or
 * int32 offsets. Reading stops after the known number of entries, else
 * at the start of the next table known and, for int32 offsets, at the
 * next address of data taken by a `lea r64, [rip+X]` byte pattern
 * anywhere in the code (the offsets of the next table, read from the
 * wrong base, would still land in code); and at the first entry that
 * is not a case: outside the function of the jmp as known then (last
 * function start <= jmp to the next one or the end of its symbol,
 * within the jmp's section, at most 256 KiB away), outside an
 * executable section or in .plt*, inside an instruction already
 * decoded, or not decoding cleanly; and after 4096 entries. Each case
 * is code of that function (pushed, not a new function) and is walked
 * before the next entry is checked; the owners follow the jmp -> case
 * edges. A table ends where the next table read starts. njtab counts
 * the distinct tables read. Not followed: address arithmetic (`shl; add
 * r, T; mov r, [r]` at -O0 with -fjump-tables).
 *
 * Tail calls: a direct jmp or jcc to the start of another function
 * counts as one of its callers (ncallers), like a call; its target is
 * queued like any jmp target (not decoded twice). A jmp to its own
 * function's start is a loop, not counted. A jmp / jcc target nothing
 * else marks becomes a function (FN_PROLOGUE) only when it shows a
 * prologue, nothing falls through into it, and a function start lies
 * between the jmp and it (a switch case tail-calling a function called
 * from nowhere else); otherwise it stays code of the jmp's function.
 *
 * No-return functions: by name (exit, abort, __stack_chk_fail...), then
 * inferred once the code is decoded: no path from the start reaches a
 * ret, an indirect jmp other than a switch, or a function that may
 * return. Calls to them become DI_NORET (the code after them is still
 * decoded when this was not known while walking).
 *
 * Owners: each instruction goes to the function reaching it (fall-
 * through, jumps, switch cases, never entering another function's
 * start) across the fewest calls that may not return, then to the
 * lowest one; the code after a no-return call comes last. .cold parts
 * (`f.cold` symbols, and in a stripped binary the blocks f jumps to
 * outside its body) belong to f: a .cold symbol is not a function of
 * its own. DisFunc.cold / cold_size give the longest run of a function's
 * instructions outside [addr, addr + size).
 *
 * Not done yet: `mov reg, imm` code pointers outside rdi, exception
 * landing pads (found by the prologue scan as functions of their own:
 * .eh_frame is not read).
 *
 * An address is never decoded twice, decoding never leaves the
 * executable mappings, and the work done is bounded by DA_MAX_*: a
 * trapped or packed binary gives a partial result (capped = true).
 *
 * Only the instruction boundaries are kept; the text of an instruction is
 * decoded again when it is shown. No curses here. */
#ifndef DISASM_H
#define DISASM_H

#include "elfload.h"

/* DisInsn.flags */
#define DI_CALL     0x01
#define DI_JUMP     0x02           /* unconditional jmp                  */
#define DI_COND     0x04           /* conditional branch (jcc, loop...)  */
#define DI_RET      0x08
#define DI_TARGET   0x10           /* something branches here            */
#define DI_INDIRECT 0x20           /* call/jmp through a register/memory */
#define DI_STOP     0x40           /* hlt, ud2, int3                     */
#define DI_NORET    0x80           /* call to a no-return function       */

#define DA_NOFUNC   UINT32_MAX     /* DisInsn.func: no owner             */

/* analysis limits (a hit sets Disasm.capped) */
#define DA_MAX_INSNS   4000000u    /* decoded instructions               */
#define DA_MAX_QUEUE   1000000u    /* pending addresses in the work list */
#define DA_MAX_FUNCS   500000u     /* functions                          */

typedef struct {
    uint64_t addr;
    uint64_t target;               /* branch/call target, rip-relative or
                                      code-pointer reference, 0 if none   */
    uint32_t func;                 /* index in Disasm.fn, DA_NOFUNC       */
    uint8_t  len;
    uint8_t  flags;
} DisInsn;

/* where a function name comes from, best first */
enum { FN_SYMTAB, FN_DYNSYM, FN_PLT, FN_ENTRY, FN_MAIN, FN_CTOR, FN_CALL,
       FN_CODEPTR,                 /* address taken by lea [rip+X]       */
       FN_DATAPTR,                 /* code pointer stored in data (less
                                      sure than FN_CODEPTR)              */
       FN_PROLOGUE };

typedef struct {
    uint64_t addr, size;           /* size: from the symbol, else extent  */
    uint64_t cold, cold_size;      /* its part outside [addr, addr + size)
                                      (.cold, error paths), 0 if none     */
    uint32_t ninsn, ncallers;
    char    *name;
    uint8_t  kind;                 /* FN_*                                */
    bool     noreturn;
    bool     exported;
} DisFunc;

typedef struct {
    ElfFile   elf;
    size_t    cs;                  /* capstone handle (csh)               */
    bool      att;                 /* AT&T syntax instead of Intel        */

    DisInsn  *ins;  size_t nins;   /* sorted by address                   */
    DisFunc  *fn;   size_t nfn;    /* sorted by address                   */

    size_t    nbad;                /* undecodable / overlapping starts    */
    size_t    njtab;               /* jump tables read                    */
    size_t    code_bytes;          /* executable bytes in the file        */
    bool      capped;              /* a DA_MAX_* limit was reached        */
} Disasm;

/* Loads `path` and runs the analysis. false + err when the file cannot
 * be used (not ELF, malformed, not x86-64, capstone failure...). */
bool da_analyze(Disasm *d, const char *path, char *err, size_t esz);
void da_free(Disasm *d);
const char *da_capstone_version(char *buf, size_t sz);

/* lookups: index or -1 */
long da_insn_at(const Disasm *d, uint64_t addr);          /* exact start      */
long da_insn_floor(const Disasm *d, uint64_t addr);       /* last start <= addr */
long da_func_at(const Disasm *d, uint64_t addr);          /* exact start      */
long da_func_named(const Disasm *d, const char *name);
/* function holding addr: the owner of the instruction covering it, else
 * the function whose [addr, addr + size) range contains it */
long da_func_containing(const Disasm *d, uint64_t addr);

/* name for an address: function, import (by PLT stub or GOT slot), or
 * symbol (+offset); NULL when none */
const char *da_name_for(const Disasm *d, uint64_t addr, char *buf, size_t sz);

/* Text of instruction i: mnemonic, operands (branch targets replaced by
 * their names) and a comment (target name, string, pointed data...). */
void da_format(const Disasm *d, size_t i, char *mnem, size_t msz,
               char *ops, size_t osz, char *cmt, size_t csz);
void da_set_att(Disasm *d, bool att);

/* ─── linear wrapper (v1) ──────────────────────────────────────────
 * Plain linear sweep of a byte range, no analysis. The caller loads
 * d->elf itself (elf_load) and keeps ownership of it: da_close only
 * releases the capstone context. */

#define DA_LINEAR_MAX  (1u << 20)  /* longest range accepted, in bytes   */

typedef struct {
    uint64_t addr;
    uint8_t  len;                  /* 1..15                               */
    uint8_t  bytes[16];            /* the first `len` bytes are valid     */
    bool     bad;                  /* not decodable: shown as "db 0x.."   */
    char     mnem[32];
    char     ops[160];
    /* numbers in the operands, for their decimal value: the last
     * immediate (not a branch target), sign-extended, imm_size its bytes
     * (0: none); the displacement of a memory operand with a base or index
     * register other than rip (has_disp) */
    int64_t  imm, disp;
    uint8_t  imm_size;
    bool     has_disp;
} DisLine;

/* capstone x86-64, Intel syntax, instruction details on.
 * Only d->cs and d->att are touched. */
bool da_open(Disasm *d, char *err, size_t esz);
void da_close(Disasm *d);                 /* safe twice / when not open */

/* Disassembles [va, va + n) linearly with the bytes from elf_va_ptr.
 * *out is one malloc'ed block (free with da_lines_free, which is free;
 * it may be realloc'ed), *count lines. The sweep
 * stops early at the first byte that is not file-backed (bss, gap
 * between segments); an instruction is never read past the end of the
 * range nor across two mappings. false + err if the range is empty, too
 * long, overflows, starts unmapped, or memory runs out. */
bool da_linear(const Disasm *d, uint64_t va, size_t n,
               DisLine **out, size_t *count, char *err, size_t esz);
void da_lines_free(DisLine *lines);

#endif
