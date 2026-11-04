/* Memory scanner engine (the F8 memory editor): process list, memory
 * regions, read / write, value scans and refinements. No curses here. */
#ifndef MEMSCAN_H
#define MEMSCAN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef enum {
    MT_I8, MT_I16, MT_I32, MT_I64, MT_F32, MT_F64, MT_STR, MT_STR16, MT_BYTES, MT_COUNT
} MemType;

typedef enum {
    MS_EXACT, MS_BIGGER, MS_SMALLER, MS_BETWEEN, MS_UNKNOWN,
    MS_INCREASED, MS_DECREASED, MS_INC_BY, MS_DEC_BY, MS_CHANGED, MS_UNCHANGED,
    MS_COUNT
} MemScanMode;

typedef struct {
    int  pid;
    char name[128];
    unsigned long long rss_kb;     /* 0 when unknown */
} MemProc;

typedef struct {
    uint64_t start, end;
    bool     write;
    char     name[160];
} MemRegion;

/* a parsed search / write value */
typedef struct {
    MemType  type;
    int      size;                 /* bytes compared / written          */
    uint8_t  bytes[256];
    uint8_t  mask[256];            /* MT_BYTES: 0 = wildcard (??)       */
    int64_t  i, i2;                /* integers (i2: upper bound)        */
    double   f, f2;                /* floats                            */
    double   tol;                  /* float tolerance from the decimals */
} MemValue;

#define MEM_MAX_RESULTS 6000000u

typedef struct {
    uint64_t *addr;
    uint8_t  *prev;                /* MEM_PREV bytes per result         */
    size_t    n, cap;
    bool      overflow;            /* more matches than MEM_MAX_RESULTS */
} MemResults;
#define MEM_PREV 8

/* processes */
int         mem_list_procs(MemProc **out);                  /* caller frees */
bool        mem_attach(int pid, const char *name, char *err, size_t esz);
void        mem_detach(void);
bool        mem_attached(void);
int         mem_pid(void);
const char *mem_pname(void);
bool        mem_alive(void);
/* Starts `cmdline` as a child of Abyss (Linux: a child may be inspected
 * without root even when ptrace_scope = 1) and attaches to it. */
bool        mem_launch(const char *cmdline, char *err, size_t esz);

/* memory */
int         mem_regions(MemRegion **out, bool writable_only);
size_t      mem_read(uint64_t addr, void *buf, size_t n);
bool        mem_write(uint64_t addr, const void *buf, size_t n);

/* values */
const char *mem_type_name(MemType t);
int         mem_type_size(MemType t);                      /* 0 = variable */
bool        mem_parse(MemType t, MemScanMode m, const char *text, MemValue *v, char *err, size_t esz);
void        mem_format(MemType t, const uint8_t *p, int len, char *out, size_t out_sz);
const char *mem_mode_name(MemScanMode m);
bool        mem_mode_needs_value(MemScanMode m);
bool        mem_mode_first_ok(MemScanMode m);              /* usable as a first scan */
bool        mem_mode_ok_for(MemType t, MemScanMode m);

/* scans: progress(done, total) is called now and then (may be NULL) */
extern void (*mem_progress)(uint64_t done, uint64_t total);
bool        mem_first_scan(MemType t, MemScanMode m, const MemValue *v, bool aligned,
                           MemResults *r, char *err, size_t esz);
bool        mem_next_scan(MemType t, MemScanMode m, const MemValue *v, MemResults *r,
                          char *err, size_t esz);
bool        mem_has_snapshot(void);
void        mem_results_free(MemResults *r);

#endif
