#include "abyss.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <libgen.h>
#include <dirent.h>
#include <time.h>
#include <stdarg.h>

/* ─── Platform bits ──────────────────────────────────────────────── */

#ifdef _WIN32
#  define EXE_EXT     ".exe"
#  define DLL_PREFIX  ""
#  define DLL_EXT     ".dll"
#  define TMP_BIN     "abyss_run.exe"
#  define RUN_PREFIX  ".\\"
#  define PY_CMD      "python"
#  define CD_CMD      "cd /d"
/* winproc.c: background processes and URLs (kept away from ncurses) */
int  win_bg_start(const char *cmdline, const char *cwd, const char *log_path);
int  win_bg_alive(void);
void win_bg_stop(void);
void win_open_url(const char *url);
#else
#  define EXE_EXT     ""
#  define DLL_PREFIX  "lib"
#  define DLL_EXT     ".so"
#  define TMP_BIN     ".abyss_run"
#  define RUN_PREFIX  "./"
#  define PY_CMD      "python3"
#  define CD_CMD      "cd"
#endif

/* ─── Build options ───────────────────────────────────────────────
 * Every runnable language carries a table of menu entries, edited from
 * the ^B ^B menu and applied by ^B. Entries that share a non-zero
 * `group` are mutually exclusive (picking -O3 drops -O2, picking clang
 * drops gcc...). Besides compiler flags (BK_FLAG) a table holds the
 * compiler choice, the kind of output (temporary binary, kept
 * executable, shared / static library, objects), the "whole folder into
 * one output" switch, and for web files how to serve them. */

#define F(l, f, h, g, o)    { l, f, h, g, o, BK_FLAG }
#define K(l, f, h, g, o, k) { l, f, h, g, o, k }

#define G_CC   10
#define G_OUT  11
#define G_SRV  20
#define G_PORT 21

#define OUTPUTS_NATIVE \
    K("output: run only",       "run", "temporary binary, deleted after the run",   G_OUT, true,  BK_OUT), \
    K("output: executable",     "exe", "keep <name>" EXE_EXT " beside the source, then run", G_OUT, false, BK_OUT), \
    K("output: shared lib", "dll", DLL_PREFIX "<name>" DLL_EXT " (-shared)",       G_OUT, false, BK_OUT), \
    K("output: static lib", "lib", "lib<name>.a (objects + ar)",                   G_OUT, false, BK_OUT), \
    K("output: object files",   "obj", "one .o per source (-c), no link",              G_OUT, false, BK_OUT)

static const BuildFlag flags_c[] = {
    K("compiler: gcc",        "gcc",    "GNU C",                                 G_CC, true,  BK_CC),
    K("compiler: clang",      "clang",  "LLVM, sharper diagnostics",             G_CC, false, BK_CC),
    K("compiler: tcc",        "tcc",    "tiny C: instant builds, few optims",    G_CC, false, BK_CC),
    K("compiler: zig cc",     "zig cc", "clang + bundled libc, easy cross-build", G_CC, false, BK_CC),
    OUTPUTS_NATIVE,
    K("all .c of the folder", "*.c",    "every .c file of the folder -> one output", 0, false, BK_ALLSRC),
    F("-O0  no optimisation", "-O0",          "fastest build, slowest code",        1, false),
    F("-O2  balanced",        "-O2",          "the sane default",                   1, true ),
    F("-O3  aggressive",      "-O3",          "inlining + auto-vectorisation",      1, false),
    F("-Ofast",               "-Ofast",       "-O3 plus non-IEEE math",             1, false),
    F("-Os  small",           "-Os",          "optimise for size",                  1, false),
    F("SIMD: native",         "-march=native","every ISA of THIS cpu (AVX-512...)", 2, false),
    F("SIMD: AVX2 + FMA",     "-mavx2 -mfma", "portable across AVX2 machines",      2, false),
    F("SIMD: SSE4.2",         "-msse4.2",     "old x86-64 baseline",                2, false),
    F("vectorise report",     "-ftree-vectorize -fopt-info-vec", "which loops vectorised", 0, false),
    F("fast math",            "-ffast-math",  "reassociates FP, breaks IEEE",       0, false),
    F("unroll loops",         "-funroll-loops","bigger code, fewer branches",       0, false),
    F("LTO",                  "-flto",        "optimise across translation units",  0, false),
    F("static link",          "-static",      "standalone exe: no DLL / .so needed", 0, false),
    F("strip symbols",        "-s",           "smaller executable",                 0, false),
    F("debug symbols",        "-g",           "keep symbols for gdb",               0, false),
    F("warnings",             "-Wall -Wextra","all the usual warnings",             0, true ),
    F("AddressSanitizer",     "-fsanitize=address -g", "catch OOB / use-after-free", 0, false),
    F("OpenMP",               "-fopenmp",     "#pragma omp parallel",               0, false),
    F("pthread",              "-pthread",     "link libpthread",                    0, false),
    F("libm",                 "-lm",          "link the math library",              0, true ),
};

static const BuildFlag flags_cpp[] = {
    K("compiler: g++",        "g++",     "GNU C++",                              G_CC, true,  BK_CC),
    K("compiler: clang++",    "clang++", "LLVM, sharper diagnostics",            G_CC, false, BK_CC),
    K("compiler: zig c++",    "zig c++", "clang + bundled libc++",               G_CC, false, BK_CC),
    OUTPUTS_NATIVE,
    K("all .cpp of the folder","*.cpp",  "every .cpp/.cc/.cxx -> one output",      0, false, BK_ALLSRC),
    F("-O0  no optimisation", "-O0",          "fastest build, slowest code",        1, false),
    F("-O2  balanced",        "-O2",          "the sane default",                   1, true ),
    F("-O3  aggressive",      "-O3",          "inlining + auto-vectorisation",      1, false),
    F("-Ofast",               "-Ofast",       "-O3 plus non-IEEE math",             1, false),
    F("-Os  small",           "-Os",          "optimise for size",                  1, false),
    F("std: c++17",           "-std=c++17",   "",                                   3, true ),
    F("std: c++20",           "-std=c++20",   "",                                   3, false),
    F("std: c++23",           "-std=c++23",   "",                                   3, false),
    F("SIMD: native",         "-march=native","every ISA of THIS cpu (AVX-512...)", 2, false),
    F("SIMD: AVX2 + FMA",     "-mavx2 -mfma", "portable across AVX2 machines",      2, false),
    F("SIMD: SSE4.2",         "-msse4.2",     "old x86-64 baseline",                2, false),
    F("fast math",            "-ffast-math",  "reassociates FP, breaks IEEE",       0, false),
    F("unroll loops",         "-funroll-loops","bigger code, fewer branches",       0, false),
    F("LTO",                  "-flto",        "optimise across translation units",  0, false),
    F("static link",          "-static",      "standalone exe: no DLL / .so needed", 0, false),
    F("strip symbols",        "-s",           "smaller executable",                 0, false),
    F("debug symbols",        "-g",           "keep symbols for gdb",               0, false),
    F("warnings",             "-Wall -Wextra","all the usual warnings",             0, true ),
    F("AddressSanitizer",     "-fsanitize=address -g", "catch OOB / use-after-free", 0, false),
    F("OpenMP",               "-fopenmp",     "#pragma omp parallel",               0, false),
    F("pthread",              "-pthread",     "link libpthread",                    0, false),
};

static const BuildFlag flags_rust[] = {
    K("output: run only",     "run", "temporary binary, deleted after the run",     G_OUT, true,  BK_OUT),
    K("output: executable",   "exe", "keep <name>" EXE_EXT " beside the source, then run", G_OUT, false, BK_OUT),
    K("output: cdylib",       "dll", DLL_PREFIX "<name>" DLL_EXT " for C / FFI",  G_OUT, false, BK_OUT),
    K("output: staticlib",    "lib", "lib<name>.a for C / FFI",                     G_OUT, false, BK_OUT),
    F("opt-level 0",          "-C opt-level=0",   "debug build",                    1, false),
    F("opt-level 2",          "-C opt-level=2",   "the sane default",               1, true ),
    F("opt-level 3",          "-C opt-level=3",   "aggressive",                     1, false),
    F("opt-level s",          "-C opt-level=s",   "optimise for size",              1, false),
    F("edition 2021",         "--edition 2021",   "",                               2, true ),
    F("edition 2018",         "--edition 2018",   "",                               2, false),
    F("SIMD: native",         "-C target-cpu=native", "every ISA of THIS cpu",      3, false),
    F("SIMD: AVX2 + FMA",     "-C target-feature=+avx2,+fma", "portable AVX2",      3, false),
    F("LTO (fat)",            "-C lto=fat",       "optimise across crates",         0, false),
    F("codegen-units 1",      "-C codegen-units=1","slower build, faster code",     0, false),
    F("panic = abort",        "-C panic=abort",   "no unwinding, smaller binary",   0, false),
    F("overflow checks",      "-C overflow-checks=on", "trap integer overflow",     0, false),
    F("static CRT",           "-C target-feature=+crt-static", "standalone executable", 0, false),
    F("debug symbols",        "-C debuginfo=2",   "keep symbols for gdb",           0, false),
    F("deny warnings",        "-D warnings",      "warnings become errors",         0, false),
};

static const BuildFlag flags_cs[] = {
#ifdef _WIN32
    K("compiler: csc",        "csc",          ".NET Framework / Roslyn",            G_CC, true,  BK_CC),
    K("compiler: mcs",        "mcs",          "Mono",                               G_CC, false, BK_CC),
#else
    K("compiler: mcs",        "mcs",          "Mono",                               G_CC, true,  BK_CC),
    K("compiler: csc",        "csc",          "Roslyn (mono-devel)",                G_CC, false, BK_CC),
#endif
    K("output: run only",     "run",  "temporary .exe, deleted after the run",       G_OUT, true,  BK_OUT),
    K("output: executable",   "exe",  "keep <name>.exe beside the source, then run", G_OUT, false, BK_OUT),
    K("output: library",      "dll",  "<name>.dll (-target:library)",                 G_OUT, false, BK_OUT),
    K("all .cs of the folder","*.cs", "every .cs file -> one assembly",               0, false, BK_ALLSRC),
    F("optimise",             "-optimize+",   "release codegen",                    1, true ),
    F("no optimise",          "-optimize-",   "debug codegen",                      1, false),
    F("debug info",           "-debug",       "keep symbols",                       0, false),
    F("unsafe blocks",        "-unsafe",      "allow unsafe { }",                   0, false),
    F("platform x64",         "-platform:x64","",                                   0, false),
    F("warnings as errors",   "-warnaserror", "",                                   0, false),
};

static const BuildFlag flags_asm[] = {
    K("assembler: nasm",      "nasm",         "Netwide Assembler",                  G_CC, true,  BK_CC),
    K("assembler: yasm",      "yasm",         "NASM-compatible",                    G_CC, false, BK_CC),
    K("output: run only",     "run",  "temporary binary, deleted after the run",     G_OUT, true,  BK_OUT),
    K("output: executable",   "exe",  "keep <name>" EXE_EXT " beside the source, then run", G_OUT, false, BK_OUT),
    K("output: object file",  "obj",  "<name>.o only, no link",                       G_OUT, false, BK_OUT),
#ifdef _WIN32
    F("Win 64-bit",           "-f win64",     "",                                   1, true ),
    F("ELF 64-bit",           "-f elf64",     "",                                   1, false),
#else
    F("ELF 64-bit",           "-f elf64",     "",                                   1, true ),
    F("ELF 32-bit",           "-f elf32",     "",                                   1, false),
#endif
    F("optimise",             "-Ox",          "multi-pass branch optimisation",     0, true ),
    F("debug info",           "-g -F dwarf",  "keep symbols for gdb",               0, false),
    F("warnings: all",        "-w+all",       "",                                   0, false),
};

#define PORTS(dflt_hint) \
    K("port: auto",  "auto", dflt_hint,                G_PORT, true,  BK_PORT), \
    K("port 8000",   "8000", "",                       G_PORT, false, BK_PORT), \
    K("port 8080",   "8080", "",                       G_PORT, false, BK_PORT), \
    K("port 5000",   "5000", "",                       G_PORT, false, BK_PORT), \
    K("port 3000",   "3000", "",                       G_PORT, false, BK_PORT), \
    K("open browser","",     "once the server is up",  0,      true,  BK_BROWSER)

static const BuildFlag flags_py[] = {
    K("run: auto",               "auto",   "Flask app -> dev server, else run the script", G_SRV, true,  BK_SERVER),
    K("run: python script",      "script", PY_CMD " file.py, output below",                G_SRV, false, BK_SERVER),
    K("serve: Flask (dev)", "flask",  "flask run in the background (debug)",          G_SRV, false, BK_SERVER),
    K("serve: http.server",      "http",   "static files of the folder",                   G_SRV, false, BK_SERVER),
    PORTS("Flask 5000, http.server 8000"),
};

static const BuildFlag flags_web[] = {          /* HTML, CSS */
    K("serve: http.server",      "http",   PY_CMD " -m http.server on the folder",         G_SRV, true,  BK_SERVER),
    K("serve: php -S",           "php",    "PHP built-in server (php code works too)",     G_SRV, false, BK_SERVER),
    K("open the file directly",  "file",   "file:// in the browser, no server",            G_SRV, false, BK_SERVER),
    PORTS("8000"),
};

static const BuildFlag flags_php[] = {
    K("serve: php -S",           "php",    "built-in server, docroot = the folder",        G_SRV, true,  BK_SERVER),
    K("run: php CLI",            "script", "php file.php, output below",                   G_SRV, false, BK_SERVER),
    PORTS("8080"),
};

static const BuildFlag flags_js[] = {
    K("run: node script",        "script", "node file.js, output below",                   G_SRV, true,  BK_SERVER),
    K("serve: http.server",      "http",   "static files of the folder",                   G_SRV, false, BK_SERVER),
    PORTS("8000"),
};

#undef F
#undef K

typedef struct {
    const BuildFlag *tbl;
    int              n;
    bool             state[BUILD_MAX_FLAGS];
    bool             loaded;
} BuildSet;

#define SET(t) { t, (int)(sizeof t / sizeof *t), {0}, false }
static BuildSet build_sets[] = {
    [LANG_C]    = SET(flags_c),
    [LANG_CPP]  = SET(flags_cpp),
    [LANG_RUST] = SET(flags_rust),
    [LANG_CS]   = SET(flags_cs),
    [LANG_ASM]  = SET(flags_asm),
    [LANG_PY]   = SET(flags_py),
    [LANG_HTML] = SET(flags_web),
    [LANG_CSS]  = SET(flags_web),
    [LANG_PHP]  = SET(flags_php),
    [LANG_JS]   = SET(flags_js),
    [LANG_NONE] = { NULL, 0, {0}, false },
};
#undef SET

static BuildSet *build_set(Language lang) {
    if (lang < 0 || lang > LANG_NONE) return NULL;
    BuildSet *bs = &build_sets[lang];
    if (!bs->tbl) return NULL;
    if (!bs->loaded) {                       /* first use: take the defaults */
        for (int i = 0; i < bs->n && i < BUILD_MAX_FLAGS; i++)
            bs->state[i] = bs->tbl[i].on;
        bs->loaded = true;
    }
    return bs;
}

bool build_is_compiled(Language lang) {
    return lang == LANG_C || lang == LANG_CPP || lang == LANG_RUST ||
           lang == LANG_CS || lang == LANG_ASM;
}

bool build_has_menu(Language lang) { return build_set(lang) != NULL; }

const BuildFlag *build_flag_table(Language lang, int *count) {
    BuildSet *bs = build_set(lang);
    if (!bs) { if (count) *count = 0; return NULL; }
    if (count) *count = bs->n;
    return bs->tbl;
}

bool *build_flag_state(Language lang) {
    BuildSet *bs = build_set(lang);
    return bs ? bs->state : NULL;
}

/* Toggling a grouped flag turns its siblings off; a group always keeps
 * exactly one member selected, so re-picking the active one is a no-op. */
void build_flag_toggle(Language lang, int idx) {
    BuildSet *bs = build_set(lang);
    if (!bs || idx < 0 || idx >= bs->n) return;
    int grp = bs->tbl[idx].group;
    if (grp == 0) { bs->state[idx] = !bs->state[idx]; return; }
    if (bs->state[idx]) return;
    for (int i = 0; i < bs->n; i++)
        if (bs->tbl[i].group == grp) bs->state[i] = false;
    bs->state[idx] = true;
}

/* Is the program behind a compiler entry installed? Cached: PATH is
 * scanned once per program. */
bool build_flag_available(Language lang, int idx) {
    BuildSet *bs = build_set(lang);
    if (!bs || idx < 0 || idx >= bs->n || bs->tbl[idx].kind != BK_CC) return true;
    static struct { char name[32]; bool have; } cache[32];
    static int ncache = 0;
    char prog[32];
    snprintf(prog, sizeof prog, "%s", bs->tbl[idx].flag);
    char *sp = strchr(prog, ' ');
    if (sp) *sp = '\0';
    for (int i = 0; i < ncache; i++) if (!strcmp(cache[i].name, prog)) return cache[i].have;
    bool have = proc_have(prog);
    if (ncache < 32) {
        snprintf(cache[ncache].name, sizeof cache[ncache].name, "%s", prog);
        cache[ncache++].have = have;
    }
    return have;
}

/* The selected entry of a kind (compiler, output...), or NULL. */
static const char *sel_of(Language lang, int kind) {
    BuildSet *bs = build_set(lang);
    if (!bs) return NULL;
    for (int i = 0; i < bs->n; i++)
        if (bs->tbl[i].kind == kind && bs->state[i]) return bs->tbl[i].flag;
    return NULL;
}

static bool on_of(Language lang, int kind) { return sel_of(lang, kind) != NULL; }

void build_flags_string(Language lang, char *out, size_t out_sz) {
    BuildSet *bs = build_set(lang);
    out[0] = '\0';
    if (!bs) return;
    size_t pos = 0;
    for (int i = 0; i < bs->n; i++) {
        if (bs->tbl[i].kind != BK_FLAG) continue;
        if (!bs->state[i] || !bs->tbl[i].flag[0]) continue;
        int w = snprintf(out + pos, out_sz - pos, "%s%s", pos ? " " : "", bs->tbl[i].flag);
        if (w < 0 || (size_t)w >= out_sz - pos) break;
        pos += (size_t)w;
    }
}

const char *build_compiler_name(Language lang) {
    const char *cc = sel_of(lang, BK_CC);
    if (cc) return cc;
    switch (lang) {
        case LANG_C:    return "gcc";
        case LANG_CPP:  return "g++";
        case LANG_RUST: return "rustc";
        case LANG_CS:   return "mcs";
        case LANG_ASM:  return "nasm";
        case LANG_PY:   return PY_CMD;
        case LANG_JS:   return "node";
        case LANG_PHP:  return "php";
        case LANG_HTML: case LANG_CSS: return "web server";
        default:        return "";
    }
}

/* Libraries (-l...) must follow the translation unit on the gcc command
 * line, so the selected flags are split into "before the file" and
 * "after the file" halves. clang has no -fopt-info: its equivalent
 * vectoriser report is swapped in. */
static void flags_split(Language lang, const char *cc, char *pre, size_t pre_sz,
                        char *post, size_t post_sz) {
    char all[2048];
    build_flags_string(lang, all, sizeof all);
    pre[0] = post[0] = '\0';
    bool llvm = cc && (strstr(cc, "clang") || strstr(cc, "zig"));
    size_t pp = 0, qp = 0;
    char *save = NULL;
    for (char *tok = strtok_r(all, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
        if (llvm && !strcmp(tok, "-fopt-info-vec")) tok = "-Rpass=loop-vectorize";
        bool is_lib = (tok[0] == '-' && tok[1] == 'l');
        char  *dst  = is_lib ? post : pre;
        size_t sz   = is_lib ? post_sz : pre_sz;
        size_t *cur = is_lib ? &qp : &pp;
        int w = snprintf(dst + *cur, sz - *cur, "%s%s", *cur ? " " : "", tok);
        if (w < 0 || (size_t)w >= sz - *cur) continue;
        *cur += (size_t)w;
    }
}

/* A .rs file sitting in a Cargo project is built by cargo, not rustc:
 * rustc alone cannot resolve the crate's dependencies. Walks up from the
 * file for a Cargo.toml, at most a few levels. */
static bool cargo_root(const char *path, char *out, size_t out_sz) {
    char dir[4096];
    snprintf(dir, sizeof dir, "%s", path);
    char *d = dirname(dir);
    char probe[4200];
    for (int up = 0; up < 5; up++) {
        snprintf(probe, sizeof probe, "%s/Cargo.toml", d);
        if (access(probe, R_OK) == 0) { snprintf(out, out_sz, "%s", d); return true; }
        if (strcmp(d, "/") == 0 || strcmp(d, ".") == 0) break;
        char up_buf[4096];
        snprintf(up_buf, sizeof up_buf, "%s", d);
        d = dirname(up_buf);
        snprintf(dir, sizeof dir, "%s", d);
        d = dir;
    }
    return false;
}

/* ─── Build plan ─────────────────────────────────────────────────
 * ^B turns into a plan: an optional build command and a run command,
 * both executed from the source's folder (`cwd`), or a background
 * server plus a URL to open. Paths in commands are relative to cwd. */

#define CMD_MAX 32768

typedef struct {
    char cwd[4096];
    char build[CMD_MAX];
    char run[CMD_MAX];
    bool server;            /* `run` is a long-lived server             */
    char url[2048];         /* opened in the browser (server or file)   */
    bool open_browser;
    char produced[4096];    /* what stays on disk once built            */
    char cleanup[8][4400];   /* temporary files removed after the run    */
    int  ncleanup;
} Plan;

static void sappend(char *dst, size_t sz, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void sappend(char *dst, size_t sz, const char *fmt, ...) {
    size_t n = strlen(dst);
    if (n >= sz - 1) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(dst + n, sz - n, fmt, ap);
    va_end(ap);
}

static bool has_ext(const char *name, const char *const *exts) {
    const char *dot = strrchr(name, '.');
    if (!dot) return false;
    for (int i = 0; exts[i]; i++) if (!strcasecmp(dot, exts[i])) return true;
    return false;
}

static int name_cmp(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Quoted names of every source of `dir` with one of `exts`, sorted,
 * space separated. Returns how many were found. */
static int folder_sources(const char *dir, const char *const *exts, char *out, size_t out_sz,
                          char names[][256], int max_names) {
    out[0] = '\0';
    DIR *d = opendir(dir);
    if (!d) return 0;
    char *list[512];
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) && n < 512) {
        if (e->d_name[0] == '.') continue;
        if (!has_ext(e->d_name, exts)) continue;
        list[n++] = strdup(e->d_name);
    }
    closedir(d);
    qsort(list, (size_t)n, sizeof *list, name_cmp);
    for (int i = 0; i < n; i++) {
        sappend(out, out_sz, "%s\"%s\"", i ? " " : "", list[i]);
        if (names && i < max_names) snprintf(names[i], 256, "%s", list[i]);
        free(list[i]);
    }
    return n;
}

static void file_parts(const char *path, char *dir, size_t dsz, char *base, size_t bsz,
                       char *stem, size_t ssz) {
    char tmp[4096];
    snprintf(tmp, sizeof tmp, "%s", path);
    snprintf(dir, dsz, "%s", dirname(tmp));
    snprintf(tmp, sizeof tmp, "%s", path);
    snprintf(base, bsz, "%s", basename(tmp));
    snprintf(stem, ssz, "%s", base);
    char *dot = strrchr(stem, '.');
    if (dot && dot != stem) *dot = '\0';
}

static bool file_mentions(const char *path, const char *const *needles) {
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    char buf[1 << 16];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = '\0';
    for (int i = 0; needles[i]; i++) if (strstr(buf, needles[i])) return true;
    return false;
}

static void obj_name(const char *src, char *out, size_t sz) {
    snprintf(out, sz, "%s", src);
    char *dot = strrchr(out, '.');
    if (dot) *dot = '\0';
    sappend(out, sz, ".o");
}

static void url_path(char *out, size_t sz, const char *name) {
    size_t o = 0;
    for (const unsigned char *c = (const unsigned char *)name; *c && o + 4 < sz; c++) {
        if (isalnum(*c) || strchr("-_.~/", *c)) out[o++] = (char)*c;
        else o += (size_t)snprintf(out + o, sz - o, "%%%02X", *c);
    }
    out[o] = '\0';
}

/* C, C++: one or every source of the folder, into the chosen output. */
static void plan_native(Plan *pl, Language lang, const char *dir, const char *base, const char *stem) {
    const char *cc  = build_compiler_name(lang);
    const char *out = sel_of(lang, BK_OUT);
    if (!out) out = "run";
    char pre[1024], post[512];
    flags_split(lang, cc, pre, sizeof pre, post, sizeof post);

    static const char *const c_ext[]   = { ".c", NULL };
    static const char *const cpp_ext[] = { ".cpp", ".cc", ".cxx", ".c++", NULL };
    char srcs[CMD_MAX / 2];
    char names[64][256];
    int  nsrc = 1;
    if (on_of(lang, BK_ALLSRC)) {
        nsrc = folder_sources(dir, lang == LANG_C ? c_ext : cpp_ext, srcs, sizeof srcs, names, 64);
        if (nsrc == 0) { snprintf(srcs, sizeof srcs, "\"%s\"", base); snprintf(names[0], 256, "%s", base); nsrc = 1; }
    } else {
        snprintf(srcs, sizeof srcs, "\"%s\"", base);
        snprintf(names[0], 256, "%s", base);
    }

    if (!strcmp(out, "exe")) {
        snprintf(pl->build, sizeof pl->build, "%s %s %s -o \"%s" EXE_EXT "\" %s", cc, pre, srcs, stem, post);
        snprintf(pl->run, sizeof pl->run, "\"" RUN_PREFIX "%s" EXE_EXT "\"", stem);
        snprintf(pl->produced, sizeof pl->produced, "%s" EXE_EXT, stem);
    } else if (!strcmp(out, "dll")) {
#ifdef _WIN32
        snprintf(pl->build, sizeof pl->build,
                 "%s %s -shared %s -o \"%s.dll\" -Wl,--out-implib,\"lib%s.dll.a\" %s",
                 cc, pre, srcs, stem, stem, post);
        snprintf(pl->produced, sizeof pl->produced, "%s.dll + lib%s.dll.a", stem, stem);
#else
        snprintf(pl->build, sizeof pl->build, "%s %s -shared -fPIC %s -o \"lib%s.so\" %s",
                 cc, pre, srcs, stem, post);
        snprintf(pl->produced, sizeof pl->produced, "lib%s.so", stem);
#endif
    } else if (!strcmp(out, "lib") || !strcmp(out, "obj")) {
        snprintf(pl->build, sizeof pl->build, "%s %s -c %s", cc, pre, srcs);
        if (!strcmp(out, "lib")) {
            char objs[CMD_MAX / 2] = "";
            for (int i = 0; i < nsrc && i < 64; i++) {
                char o[300];
                obj_name(names[i], o, sizeof o);
                sappend(objs, sizeof objs, "%s\"%s\"", i ? " " : "", o);
                if (pl->ncleanup < 8) snprintf(pl->cleanup[pl->ncleanup++], sizeof pl->cleanup[0], "%s/%s", dir, o);
            }
            sappend(pl->build, sizeof pl->build, " && ar rcs \"lib%s.a\" %s", stem, objs);
            snprintf(pl->produced, sizeof pl->produced, "lib%s.a", stem);
        } else {
            if (nsrc > 1) snprintf(pl->produced, sizeof pl->produced, "%d object files (.o)", nsrc);
            else          obj_name(names[0], pl->produced, sizeof pl->produced);
        }
    } else {                                              /* run only */
        snprintf(pl->build, sizeof pl->build, "%s %s %s -o \"" TMP_BIN "\" %s", cc, pre, srcs, post);
        snprintf(pl->run, sizeof pl->run, "\"" RUN_PREFIX TMP_BIN "\"");
        snprintf(pl->cleanup[pl->ncleanup++], sizeof pl->cleanup[0], "%s/" TMP_BIN, dir);
    }
}

static void plan_rust(Plan *pl, const char *path, const char *base, const char *stem) {
    char pre[1024], post[512];
    flags_split(LANG_RUST, "rustc", pre, sizeof pre, post, sizeof post);
    char root[4096];
    if (cargo_root(path, root, sizeof root)) {
        /* rustc flags reach a cargo build through RUSTFLAGS — minus
         * --edition, which a cargo crate takes from its Cargo.toml
         * and which rustc rejects when passed twice. */
        char rf[1024]; rf[0] = '\0';
        size_t rp = 0; char *save = NULL;
        bool skip_next = false;
        for (char *tok = strtok_r(pre, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
            if (skip_next) { skip_next = false; continue; }
            if (strcmp(tok, "--edition") == 0) { skip_next = true; continue; }
            if (strncmp(tok, "--edition=", 10) == 0) continue;
            int w = snprintf(rf + rp, sizeof rf - rp, "%s%s", rp ? " " : "", tok);
            if (w < 0 || (size_t)w >= sizeof rf - rp) break;
            rp += (size_t)w;
        }
        snprintf(pl->cwd, sizeof pl->cwd, "%s", root);
#ifdef _WIN32
        snprintf(pl->build, sizeof pl->build, "set \"RUSTFLAGS=%s\"&& cargo build --quiet", rf);
        snprintf(pl->run, sizeof pl->run, "set \"RUSTFLAGS=%s\"&& cargo run --quiet", rf);
#else
        /* the run phase finds the build up to date and only execs */
        snprintf(pl->build, sizeof pl->build, "RUSTFLAGS=\"%s\" cargo build --quiet", rf);
        snprintf(pl->run, sizeof pl->run, "RUSTFLAGS=\"%s\" cargo run --quiet", rf);
#endif
        return;
    }
    const char *out = sel_of(LANG_RUST, BK_OUT);
    if (!out) out = "run";
    if (!strcmp(out, "exe")) {
        snprintf(pl->build, sizeof pl->build, "rustc %s \"%s\" -o \"%s" EXE_EXT "\"", pre, base, stem);
        snprintf(pl->run, sizeof pl->run, "\"" RUN_PREFIX "%s" EXE_EXT "\"", stem);
        snprintf(pl->produced, sizeof pl->produced, "%s" EXE_EXT, stem);
    } else if (!strcmp(out, "dll")) {
        snprintf(pl->build, sizeof pl->build, "rustc %s --crate-type cdylib \"%s\" -o \"" DLL_PREFIX "%s" DLL_EXT "\"",
                 pre, base, stem);
        snprintf(pl->produced, sizeof pl->produced, DLL_PREFIX "%s" DLL_EXT, stem);
    } else if (!strcmp(out, "lib")) {
        snprintf(pl->build, sizeof pl->build, "rustc %s --crate-type staticlib \"%s\" -o \"lib%s.a\"",
                 pre, base, stem);
        snprintf(pl->produced, sizeof pl->produced, "lib%s.a", stem);
    } else {
        snprintf(pl->build, sizeof pl->build, "rustc %s \"%s\" -o \"" TMP_BIN "\"", pre, base);
        snprintf(pl->run, sizeof pl->run, "\"" RUN_PREFIX TMP_BIN "\"");
        snprintf(pl->cleanup[pl->ncleanup++], sizeof pl->cleanup[0], "%s/" TMP_BIN, pl->cwd);
    }
}

static void plan_cs(Plan *pl, const char *dir, const char *base, const char *stem) {
    const char *cc  = build_compiler_name(LANG_CS);
    const char *out = sel_of(LANG_CS, BK_OUT);
    if (!out) out = "run";
    char flags[1024];
    build_flags_string(LANG_CS, flags, sizeof flags);
    static const char *const cs_ext[] = { ".cs", NULL };
    char srcs[CMD_MAX / 2];
    if (!on_of(LANG_CS, BK_ALLSRC) || folder_sources(dir, cs_ext, srcs, sizeof srcs, NULL, 0) == 0)
        snprintf(srcs, sizeof srcs, "\"%s\"", base);
#ifdef _WIN32
    const char *host = "";
#else
    const char *host = "mono ";
#endif
    if (!strcmp(out, "dll")) {
        snprintf(pl->build, sizeof pl->build, "%s %s -target:library %s -out:\"%s.dll\"", cc, flags, srcs, stem);
        snprintf(pl->produced, sizeof pl->produced, "%s.dll", stem);
    } else if (!strcmp(out, "exe")) {
        snprintf(pl->build, sizeof pl->build, "%s %s %s -out:\"%s.exe\"", cc, flags, srcs, stem);
        snprintf(pl->run, sizeof pl->run, "%s" "\"" RUN_PREFIX "%s.exe\"", host, stem);
        snprintf(pl->produced, sizeof pl->produced, "%s.exe", stem);
    } else {
        snprintf(pl->build, sizeof pl->build, "%s %s %s -out:\"abyss_run.exe\"", cc, flags, srcs);
        snprintf(pl->run, sizeof pl->run, "%s\"" RUN_PREFIX "abyss_run.exe\"", host);
        snprintf(pl->cleanup[pl->ncleanup++], sizeof pl->cleanup[0], "%s/abyss_run.exe", dir);
    }
}

static void plan_asm(Plan *pl, const char *dir, const char *base, const char *stem) {
    const char *as  = build_compiler_name(LANG_ASM);
    const char *out = sel_of(LANG_ASM, BK_OUT);
    if (!out) out = "run";
    char flags[1024];
    build_flags_string(LANG_ASM, flags, sizeof flags);
    if (!strcmp(out, "obj")) {
        snprintf(pl->build, sizeof pl->build, "%s %s \"%s\" -o \"%s.o\"", as, flags, base, stem);
        snprintf(pl->produced, sizeof pl->produced, "%s.o", stem);
    } else if (!strcmp(out, "exe")) {
        snprintf(pl->build, sizeof pl->build, "%s %s \"%s\" -o \"%s.o\" && ld \"%s.o\" -o \"%s" EXE_EXT "\"",
                 as, flags, base, stem, stem, stem);
        snprintf(pl->run, sizeof pl->run, "\"" RUN_PREFIX "%s" EXE_EXT "\"", stem);
        snprintf(pl->produced, sizeof pl->produced, "%s" EXE_EXT, stem);
        snprintf(pl->cleanup[pl->ncleanup++], sizeof pl->cleanup[0], "%s/%s.o", dir, stem);
    } else {
        snprintf(pl->build, sizeof pl->build,
                 "%s %s \"%s\" -o \"abyss_run.o\" && ld \"abyss_run.o\" -o \"" TMP_BIN "\"", as, flags, base);
        snprintf(pl->run, sizeof pl->run, "\"" RUN_PREFIX TMP_BIN "\"");
        snprintf(pl->cleanup[pl->ncleanup++], sizeof pl->cleanup[0], "%s/abyss_run.o", dir);
        snprintf(pl->cleanup[pl->ncleanup++], sizeof pl->cleanup[0], "%s/" TMP_BIN, dir);
    }
}

static int pick_port(Language lang, const char *server) {
    const char *p = sel_of(lang, BK_PORT);
    if (p && strcmp(p, "auto") != 0) return atoi(p);
    if (!strcmp(server, "flask")) return 5000;
    if (!strcmp(server, "php"))   return 8080;
    return 8000;
}

/* Web files and Python: a script run (output below) or a server. */
static void plan_web(Plan *pl, Language lang, const char *path, const char *base, const char *stem) {
    const char *mode = sel_of(lang, BK_SERVER);
    if (!mode) mode = "script";
    if (!strcmp(mode, "auto")) {
        static const char *const flask_marks[] = { "from flask", "import flask", "Flask(", NULL };
        mode = file_mentions(path, flask_marks) ? "flask" : "script";
    }
    pl->open_browser = on_of(lang, BK_BROWSER);

    if (!strcmp(mode, "script")) {
        switch (lang) {
            case LANG_PY:  snprintf(pl->run, sizeof pl->run, PY_CMD " -u \"%s\"", base); break;
            case LANG_JS:  snprintf(pl->run, sizeof pl->run, "node \"%s\"", base); break;
            case LANG_PHP: snprintf(pl->run, sizeof pl->run, "php \"%s\"", base); break;
            default: break;
        }
        pl->open_browser = false;
        return;
    }
    if (!strcmp(mode, "file")) {
        char abs[4096];
        if (!realpath(path, abs)) snprintf(abs, sizeof abs, "%s", path);
        char enc[3072];
#ifdef _WIN32
        for (char *c = abs; *c; c++) if (*c == '\\') *c = '/';
        url_path(enc, sizeof enc, abs);
        snprintf(pl->url, sizeof pl->url, "file:///%s", enc);
#else
        url_path(enc, sizeof enc, abs);
        snprintf(pl->url, sizeof pl->url, "file://%s", enc);
#endif
        pl->open_browser = true;
        return;
    }

    int port = pick_port(lang, mode);
    pl->server = true;
    char page[1024] = "";
    if (lang == LANG_HTML || lang == LANG_PHP) url_path(page, sizeof page, base);
    snprintf(pl->url, sizeof pl->url, "http://127.0.0.1:%d/%s", port, page);

    if (!strcmp(mode, "flask")) {
#ifdef _WIN32
        snprintf(pl->run, sizeof pl->run,
                 "set \"FLASK_APP=%s\"&& set \"FLASK_DEBUG=1\"&& " PY_CMD " -u -m flask run --port %d",
                 stem, port);
#else
        snprintf(pl->run, sizeof pl->run,
                 "FLASK_APP=\"%s\" FLASK_DEBUG=1 " PY_CMD " -u -m flask run --port %d", stem, port);
#endif
    } else if (!strcmp(mode, "php")) {
        snprintf(pl->run, sizeof pl->run, "php -S 127.0.0.1:%d -t .", port);
    } else {
        snprintf(pl->run, sizeof pl->run, PY_CMD " -u -m http.server %d --bind 127.0.0.1", port);
    }
}

static void make_plan(Plan *pl, Language lang, const char *path) {
    memset(pl, 0, sizeof *pl);
    char base[1024], stem[1024];
    file_parts(path, pl->cwd, sizeof pl->cwd, base, sizeof base, stem, sizeof stem);

    switch (lang) {
        case LANG_C: case LANG_CPP: plan_native(pl, lang, pl->cwd, base, stem); break;
        case LANG_RUST:             plan_rust(pl, path, base, stem); break;
        case LANG_CS:               plan_cs(pl, pl->cwd, base, stem); break;
        case LANG_ASM:              plan_asm(pl, pl->cwd, base, stem); break;
        case LANG_PY: case LANG_JS: case LANG_PHP:
        case LANG_HTML: case LANG_CSS:
            plan_web(pl, lang, path, base, stem);
            break;
        case LANG_SH:
            snprintf(pl->run, sizeof pl->run, "bash \"%s\"", base);
            break;
        default:
            break;
    }
}

/* One-line summary for the build menu: what ^B is about to do. */
void build_preview(Language lang, const char *path, char *out, size_t out_sz) {
    out[0] = '\0';
    if (!path || !path[0]) { build_flags_string(lang, out, out_sz); return; }
    Plan *pl = malloc(sizeof *pl);
    if (!pl) return;
    make_plan(pl, lang, path);
    if (pl->build[0]) snprintf(out, out_sz, "%s", pl->build);
    if (pl->server)            sappend(out, out_sz, "%s[bg] %s  ->  %s", out[0] ? "  ->  " : "", pl->run, pl->url);
    else if (pl->run[0])       sappend(out, out_sz, "%s%s", out[0] ? "  ->  " : "", pl->run);
    else if (pl->url[0])       sappend(out, out_sz, "open %s", pl->url);
    if (pl->produced[0])       sappend(out, out_sz, "   [keeps %s]", pl->produced);
    free(pl);
}

/* ─── Running ───────────────────────────────────────────────────── */

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void fmt_duration(double s, char *out, size_t out_sz) {
    if (s < 1.0) snprintf(out, out_sz, "%.0f ms", s * 1000.0);
    else         snprintf(out, out_sz, "%.2f s", s);
}

/* Runs `cmd` from `cwd` with stderr folded into stdout, appending its
 * output to out_buf at *pos. Returns the pclose status, or -1. */
static int capture(const char *cmd, const char *cwd, char *out_buf, size_t out_max, size_t *pos) {
    static char full_cmd[CMD_MAX + 4200];
    if (cwd && cwd[0]) snprintf(full_cmd, sizeof full_cmd, "(" CD_CMD " \"%s\" && %s) 2>&1", cwd, cmd);
    else               snprintf(full_cmd, sizeof full_cmd, "(%s) 2>&1", cmd);

    FILE *fp = popen(full_cmd, "r");
    if (!fp) {
        int w = snprintf(out_buf + *pos, out_max - *pos, "(popen failed: %s)\n", strerror(errno));
        if (w > 0) *pos = min_sz(*pos + (size_t)w, out_max - 1);
        return -1;
    }
    char tmp[4096];
    while (fgets(tmp, sizeof tmp, fp)) {
        if (*pos >= out_max - 1) continue;   /* keep draining so the child can exit */
        size_t n = strlen(tmp);
        if (*pos + n >= out_max) n = out_max - *pos - 1;
        memcpy(out_buf + *pos, tmp, n);
        *pos += n;
    }
    out_buf[*pos] = '\0';
    return pclose(fp);
}

static int exit_code(int status) {
#ifdef _WIN32
    return status;
#else
    if (status == -1)        return -1;
    if (WIFEXITED(status))   return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
#endif
}

/* ─── Background server ─────────────────────────────────────────── */

static char srv_url[2048];
static char srv_log[4096];
#ifndef _WIN32
static pid_t srv_pid = 0;
#endif

const char *server_url(void) { return srv_url; }

bool server_running(void) {
#ifdef _WIN32
    return win_bg_alive() != 0;
#else
    if (srv_pid <= 0) return false;
    int st;
    if (waitpid(srv_pid, &st, WNOHANG) == srv_pid) { srv_pid = 0; return false; }
    return true;
#endif
}

void server_stop(void) {
#ifdef _WIN32
    win_bg_stop();
#else
    if (srv_pid <= 0) return;
    kill(-srv_pid, SIGTERM);                    /* its whole process group */
    for (int i = 0; i < 20; i++) {
        if (waitpid(srv_pid, NULL, WNOHANG) == srv_pid) { srv_pid = 0; return; }
        struct timespec ts = { 0, 25 * 1000000L };
        nanosleep(&ts, NULL);
    }
    kill(-srv_pid, SIGKILL);
    waitpid(srv_pid, NULL, 0);
    srv_pid = 0;
#endif
}

static void temp_path(char *out, size_t sz, const char *name) {
#ifdef _WIN32
    const char *t = getenv("TEMP");
    if (!t) t = ".";
    snprintf(out, sz, "%s\\%s", t, name);
#else
    const char *t = getenv("TMPDIR");
    if (!t || !*t) t = "/tmp";
    snprintf(out, sz, "%s/%s.%d", t, name, (int)getpid());
#endif
}

static void open_url(const char *url) {
#ifdef _WIN32
    win_open_url(url);
#else
    const char *opener = proc_have("xdg-open") ? "xdg-open" : proc_have("open") ? "open" : NULL;
    if (!opener) return;
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        int nul = open("/dev/null", O_RDWR);
        if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); dup2(nul, 2); }
        if (fork() == 0) { execlp(opener, opener, url, (char *)NULL); }
        _exit(0);
    }
    if (pid > 0) waitpid(pid, NULL, 0);        /* the grandchild is orphaned, no zombie */
#endif
}

static bool server_start(const char *cmd, const char *cwd, char *err, size_t esz) {
    server_stop();
    temp_path(srv_log, sizeof srv_log, "abyss-server.log");
#ifdef _WIN32
    if (!win_bg_start(cmd, cwd, srv_log)) {
        snprintf(err, esz, "could not start: %s", cmd);
        return false;
    }
#else
    pid_t pid = fork();
    if (pid < 0) { snprintf(err, esz, "fork failed: %s", strerror(errno)); return false; }
    if (pid == 0) {
        setsid();
        if (cwd && cwd[0] && chdir(cwd) != 0) _exit(127);
        int fd = open(srv_log, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        int nul = open("/dev/null", O_RDONLY);
        if (nul >= 0) dup2(nul, 0);
        if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); }
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    srv_pid = pid;
#endif
    return true;
}

static size_t read_log(char *out, size_t out_max) {
    FILE *f = fopen(srv_log, "rb");
    if (!f) { out[0] = '\0'; return 0; }
    size_t n = fread(out, 1, out_max - 1, f);
    fclose(f);
    out[n] = '\0';
    return n;
}

/* Starts the server, waits a moment for it to come up (or die), then
 * opens the browser. The panel shows the URL and the first log lines. */
static void run_server(const Plan *pl, char *out_buf, size_t out_max, char *timing, size_t timing_sz) {
    char err[256] = "";
    size_t pos = 0;
    if (!server_start(pl->run, pl->cwd, err, sizeof err)) {
        snprintf(out_buf, out_max, "(%s)\n", err);
        snprintf(timing, timing_sz, "server failed");
        return;
    }
    snprintf(srv_url, sizeof srv_url, "%s", pl->url);

    char log[2048] = "";
    bool alive = true;
    for (int i = 0; i < 15; i++) {                       /* up to ~1.5 s */
        struct timespec ts = { 0, 100 * 1000000L };
        nanosleep(&ts, NULL);
        if (!server_running()) { alive = false; break; }
        read_log(log, sizeof log);
        if (strstr(log, "Running on") || strstr(log, "Serving HTTP") ||
            strstr(log, "Development Server") || strstr(log, "started")) break;
    }
    read_log(log, sizeof log);

    if (!alive) {
        pos += (size_t)snprintf(out_buf + pos, out_max - pos,
                                "Server exited right away:\n  %s\n  (in %s)\n\n%s\n", pl->run, pl->cwd, log);
        snprintf(timing, timing_sz, "server exited");
        srv_url[0] = '\0';
        return;
    }
    if (pl->open_browser) open_url(pl->url);
    snprintf(out_buf, out_max,
             "Server running in the background\n"
             "  url : %s\n"
             "  cmd : %s\n"
             "  dir : %s\n"
             "  log : %s\n"
             "  ^B restarts it  ·  F5 then k stops it  ·  stopped when Abyss quits\n"
             "-- log --\n%s",
             pl->url, pl->run, pl->cwd, srv_log, log);
    snprintf(timing, timing_sz, "serving %s", pl->url);
}

void run_file(const char *path, Language lang, char *out_buf, size_t out_max,
              char *timing, size_t timing_sz) {
    static Plan pl;
    make_plan(&pl, lang, path);
    timing[0] = '\0';
    out_buf[0] = '\0';

    if (pl.server) { run_server(&pl, out_buf, out_max, timing, timing_sz); return; }
    if (!pl.build[0] && !pl.run[0]) {
        if (pl.url[0]) {
            open_url(pl.url);
            snprintf(out_buf, out_max, "Opened %s\n", pl.url);
            snprintf(timing, timing_sz, "opened in the browser");
            return;
        }
        snprintf(out_buf, out_max, "(No run command for this file type)");
        return;
    }

    size_t pos = 0;
    char build_t[32] = "", run_t[32] = "";
    int code = 0;
    bool build_failed = false;

    if (pl.build[0]) {
        double t0 = now_sec();
        code = exit_code(capture(pl.build, pl.cwd, out_buf, out_max, &pos));
        fmt_duration(now_sec() - t0, build_t, sizeof build_t);
        build_failed = (code != 0);
    }

    if (!build_failed && pl.run[0]) {
        double t0 = now_sec();
        code = exit_code(capture(pl.run, pl.cwd, out_buf, out_max, &pos));
        fmt_duration(now_sec() - t0, run_t, sizeof run_t);
    }

    if (pos == 0) {
        if (build_failed)          snprintf(out_buf, out_max, "(Compilation failed with code %d)", code);
        else if (!pl.run[0])       snprintf(out_buf, out_max, "(Build finished)");
        else if (code == 0)        snprintf(out_buf, out_max, "(Execution finished)");
        else                       snprintf(out_buf, out_max, "(Process exited with code %d)", code);
        pos = strlen(out_buf);
    }

    if (build_failed)
        snprintf(timing, timing_sz, "compile %s (failed)", build_t);
    else if (pl.build[0] && pl.run[0])
        snprintf(timing, timing_sz, "compile %s | run %s", build_t, run_t);
    else if (pl.build[0])
        snprintf(timing, timing_sz, "compile %s -> %s", build_t, pl.produced[0] ? pl.produced : "done");
    else
        snprintf(timing, timing_sz, "run %s", run_t);

    /* footer in the output panel, which stays visible after the notification clears */
    if (pos > 0 && out_buf[pos - 1] != '\n' && pos < out_max - 1) out_buf[pos++] = '\n';
    if (!build_failed && pl.produced[0] && pos < out_max)
        pos += (size_t)snprintf(out_buf + pos, out_max - pos, "-> built %s in %s\n", pl.produced, pl.cwd);
    if (pos < out_max) {
        if (!build_failed && code != 0)
            snprintf(out_buf + pos, out_max - pos, "-- %s | exit %d --\n", timing, code);
        else
            snprintf(out_buf + pos, out_max - pos, "-- %s --\n", timing);
    }

    for (int i = 0; i < pl.ncleanup; i++) unlink(pl.cleanup[i]);
}
