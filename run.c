#include "abyss.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <time.h>

/* ─── Build options ───────────────────────────────────────────────
 * Compiled languages carry a table of toggleable compiler flags,
 * edited from the ^B ^B menu and applied by ^B. Flags that
 * share a non-zero `group` are mutually exclusive (picking -O3 drops
 * -O2, picking AVX2 drops -march=native, ...). */

static const BuildFlag flags_c[] = {
    { "-O0  no optimisation", "-O0",          "fastest build, slowest code",        1, false },
    { "-O2  balanced",        "-O2",          "the sane default",                   1, true  },
    { "-O3  aggressive",      "-O3",          "inlining + auto-vectorisation",      1, false },
    { "-Ofast",               "-Ofast",       "-O3 plus non-IEEE math",             1, false },
    { "-Os  small",           "-Os",          "optimise for size",                  1, false },
    { "SIMD: native",         "-march=native","every ISA of THIS cpu (AVX-512...)", 2, false },
    { "SIMD: AVX2 + FMA",     "-mavx2 -mfma", "portable across AVX2 machines",      2, false },
    { "SIMD: SSE4.2",         "-msse4.2",     "old x86-64 baseline",                2, false },
    { "vectorise report",     "-ftree-vectorize -fopt-info-vec", "which loops vectorised", 0, false },
    { "fast math",            "-ffast-math",  "reassociates FP, breaks IEEE",       0, false },
    { "unroll loops",         "-funroll-loops","bigger code, fewer branches",       0, false },
    { "LTO",                  "-flto",        "optimise across translation units",  0, false },
    { "static link",          "-static",      "no shared libs at runtime",          0, false },
    { "debug symbols",        "-g",           "keep symbols for gdb",               0, false },
    { "warnings",             "-Wall -Wextra","all the usual warnings",             0, true  },
    { "AddressSanitizer",     "-fsanitize=address -g", "catch OOB / use-after-free", 0, false },
    { "OpenMP",               "-fopenmp",     "#pragma omp parallel",               0, false },
    { "pthread",              "-pthread",     "link libpthread",                    0, false },
    { "libm",                 "-lm",          "link the math library",              0, true  },
};

static const BuildFlag flags_cpp[] = {
    { "-O0  no optimisation", "-O0",          "fastest build, slowest code",        1, false },
    { "-O2  balanced",        "-O2",          "the sane default",                   1, true  },
    { "-O3  aggressive",      "-O3",          "inlining + auto-vectorisation",      1, false },
    { "-Ofast",               "-Ofast",       "-O3 plus non-IEEE math",             1, false },
    { "-Os  small",           "-Os",          "optimise for size",                  1, false },
    { "std: c++17",           "-std=c++17",   "",                                   3, true  },
    { "std: c++20",           "-std=c++20",   "",                                   3, false },
    { "std: c++23",           "-std=c++23",   "",                                   3, false },
    { "SIMD: native",         "-march=native","every ISA of THIS cpu (AVX-512...)", 2, false },
    { "SIMD: AVX2 + FMA",     "-mavx2 -mfma", "portable across AVX2 machines",      2, false },
    { "SIMD: SSE4.2",         "-msse4.2",     "old x86-64 baseline",                2, false },
    { "fast math",            "-ffast-math",  "reassociates FP, breaks IEEE",       0, false },
    { "unroll loops",         "-funroll-loops","bigger code, fewer branches",       0, false },
    { "LTO",                  "-flto",        "optimise across translation units",  0, false },
    { "static link",          "-static",      "no shared libs at runtime",          0, false },
    { "debug symbols",        "-g",           "keep symbols for gdb",               0, false },
    { "warnings",             "-Wall -Wextra","all the usual warnings",             0, true  },
    { "AddressSanitizer",     "-fsanitize=address -g", "catch OOB / use-after-free", 0, false },
    { "OpenMP",               "-fopenmp",     "#pragma omp parallel",               0, false },
    { "pthread",              "-pthread",     "link libpthread",                    0, false },
};

static const BuildFlag flags_rust[] = {
    { "opt-level 0",          "-C opt-level=0",   "debug build",                    1, false },
    { "opt-level 2",          "-C opt-level=2",   "the sane default",               1, true  },
    { "opt-level 3",          "-C opt-level=3",   "aggressive",                     1, false },
    { "opt-level s",          "-C opt-level=s",   "optimise for size",              1, false },
    { "edition 2021",         "--edition 2021",   "",                               2, true  },
    { "edition 2018",         "--edition 2018",   "",                               2, false },
    { "SIMD: native",         "-C target-cpu=native", "every ISA of THIS cpu",      3, false },
    { "SIMD: AVX2 + FMA",     "-C target-feature=+avx2,+fma", "portable AVX2",      3, false },
    { "LTO (fat)",            "-C lto=fat",       "optimise across crates",         0, false },
    { "codegen-units 1",      "-C codegen-units=1","slower build, faster code",     0, false },
    { "panic = abort",        "-C panic=abort",   "no unwinding, smaller binary",   0, false },
    { "overflow checks",      "-C overflow-checks=on", "trap integer overflow",     0, false },
    { "debug symbols",        "-C debuginfo=2",   "keep symbols for gdb",           0, false },
    { "deny warnings",        "-D warnings",      "warnings become errors",         0, false },
};

static const BuildFlag flags_cs[] = {
    { "optimise",             "-optimize+",   "release codegen",                    1, true  },
    { "no optimise",          "-optimize-",   "debug codegen",                      1, false },
    { "debug info",           "-debug",       "keep symbols",                       0, false },
    { "unsafe blocks",        "-unsafe",      "allow unsafe { }",                   0, false },
    { "platform x64",         "-platform:x64","",                                   0, false },
    { "warnings as errors",   "-warnaserror", "",                                   0, false },
};

static const BuildFlag flags_asm[] = {
    { "ELF 64-bit",           "-f elf64",     "",                                   1, true  },
    { "ELF 32-bit",           "-f elf32",     "",                                   1, false },
    { "optimise",             "-Ox",          "multi-pass branch optimisation",     0, true  },
    { "debug info",           "-g -F dwarf",  "keep symbols for gdb",               0, false },
    { "warnings: all",        "-w+all",       "",                                   0, false },
};

typedef struct {
    const BuildFlag *tbl;
    int              n;
    bool             state[BUILD_MAX_FLAGS];
    bool             loaded;
} BuildSet;

static BuildSet build_sets[] = {
    [LANG_C]    = { flags_c,    (int)(sizeof flags_c    / sizeof *flags_c),    {0}, false },
    [LANG_CPP]  = { flags_cpp,  (int)(sizeof flags_cpp  / sizeof *flags_cpp),  {0}, false },
    [LANG_RUST] = { flags_rust, (int)(sizeof flags_rust / sizeof *flags_rust), {0}, false },
    [LANG_CS]   = { flags_cs,   (int)(sizeof flags_cs   / sizeof *flags_cs),   {0}, false },
    [LANG_ASM]  = { flags_asm,  (int)(sizeof flags_asm  / sizeof *flags_asm),  {0}, false },
    [LANG_NONE] = { NULL, 0, {0}, false },
};

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

bool build_is_compiled(Language lang) { return build_set(lang) != NULL; }

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

void build_flags_string(Language lang, char *out, size_t out_sz) {
    BuildSet *bs = build_set(lang);
    out[0] = '\0';
    if (!bs) return;
    size_t pos = 0;
    for (int i = 0; i < bs->n; i++) {
        if (!bs->state[i] || !bs->tbl[i].flag[0]) continue;
        int w = snprintf(out + pos, out_sz - pos, "%s%s", pos ? " " : "", bs->tbl[i].flag);
        if (w < 0 || (size_t)w >= out_sz - pos) break;
        pos += (size_t)w;
    }
}

const char *build_compiler_name(Language lang) {
    switch (lang) {
        case LANG_C:    return "gcc";
        case LANG_CPP:  return "g++";
        case LANG_RUST: return "rustc";
        case LANG_CS:   return "mcs";
        case LANG_ASM:  return "nasm + ld";
        default:        return "";
    }
}

/* Libraries (-l...) must follow the translation unit on the gcc command
 * line, so the selected flags are split into "before the file" and
 * "after the file" halves. */
static void flags_split(Language lang, char *pre, size_t pre_sz,
                                       char *post, size_t post_sz) {
    char all[2048];
    build_flags_string(lang, all, sizeof all);
    pre[0] = post[0] = '\0';
    size_t pp = 0, qp = 0;
    char *save = NULL;
    for (char *tok = strtok_r(all, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
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

/* Splits a ^B into its two phases so each can be timed: `build` compiles
 * (empty for interpreted languages), `run` executes the result. */
static void lang_cmd(Language lang, const char *path,
                     char *build, size_t build_sz, char *run, size_t run_sz) {
    char pre[1024], post[512];
    flags_split(lang, pre, sizeof pre, post, sizeof post);
    build[0] = run[0] = '\0';

    switch (lang) {
        case LANG_C:
            snprintf(build, build_sz, "gcc %s \"%s\" -o ./temp_bin %s", pre, path, post);
            snprintf(run, run_sz, "./temp_bin");
            break;
        case LANG_CPP:
            snprintf(build, build_sz, "g++ %s \"%s\" -o ./temp_bin %s", pre, path, post);
            snprintf(run, run_sz, "./temp_bin");
            break;
        case LANG_RUST: {
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
                /* the run phase finds the build up to date and only execs */
                snprintf(build, build_sz,
                         "cd \"%s\" && RUSTFLAGS=\"%s\" cargo build --quiet", root, rf);
                snprintf(run, run_sz,
                         "cd \"%s\" && RUSTFLAGS=\"%s\" cargo run --quiet", root, rf);
            } else {
                snprintf(build, build_sz, "rustc %s \"%s\" -o ./temp_bin", pre, path);
                snprintf(run, run_sz, "./temp_bin");
            }
            break;
        }
        case LANG_CS:
            snprintf(build, build_sz, "mcs %s \"%s\" -out:./temp_bin.exe", pre, path);
            snprintf(run, run_sz, "mono ./temp_bin.exe");
            break;
        case LANG_ASM:
            snprintf(build, build_sz,
                     "nasm %s \"%s\" -o ./temp_obj.o && ld ./temp_obj.o -o ./temp_bin", pre, path);
            snprintf(run, run_sz, "./temp_bin");
            break;
        case LANG_PY:
            snprintf(run, run_sz, "python3 \"%s\"", path);
            break;
        case LANG_SH:
            snprintf(run, run_sz, "bash \"%s\"", path);
            break;
        case LANG_JS:
            snprintf(run, run_sz, "node \"%s\"", path);
            break;
        case LANG_PHP:
            snprintf(run, run_sz,
                "php -S localhost:8080 -t \"%s\" &"
                " sleep 0.3 && xdg-open 'http://localhost:8080/%s'",
                path, path);
            break;
        default:
            break;
    }
}

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void fmt_duration(double s, char *out, size_t out_sz) {
    if (s < 1.0) snprintf(out, out_sz, "%.0f ms", s * 1000.0);
    else         snprintf(out, out_sz, "%.2f s", s);
}

/* Runs `cmd` with stderr folded into stdout, appending its output to
 * out_buf at *pos. Returns the pclose status, or -1 if popen failed. */
static int capture(const char *cmd, char *out_buf, size_t out_max, size_t *pos) {
    char full_cmd[8256];
    snprintf(full_cmd, sizeof full_cmd, "(%s) 2>&1", cmd);

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
    if (status == -1)        return -1;
    if (WIFEXITED(status))   return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

void run_file(const char *path, Language lang, char *out_buf, size_t out_max,
              char *timing, size_t timing_sz) {
    char build[8192], run[8192];
    lang_cmd(lang, path, build, sizeof build, run, sizeof run);
    timing[0] = '\0';
    out_buf[0] = '\0';
    if (!run[0]) {
        snprintf(out_buf, out_max, "(No run command for this file type)");
        return;
    }

    size_t pos = 0;
    char build_t[32] = "", run_t[32] = "";
    int code = 0;
    bool build_failed = false;

    if (build[0]) {
        double t0 = now_sec();
        code = exit_code(capture(build, out_buf, out_max, &pos));
        fmt_duration(now_sec() - t0, build_t, sizeof build_t);
        build_failed = (code != 0);
    }

    if (!build_failed) {
        double t0 = now_sec();
        code = exit_code(capture(run, out_buf, out_max, &pos));
        fmt_duration(now_sec() - t0, run_t, sizeof run_t);
    }

    if (pos == 0) {
        if (build_failed)   snprintf(out_buf, out_max, "(Compilation failed with code %d)", code);
        else if (code == 0) snprintf(out_buf, out_max, "(Execution finished)");
        else                snprintf(out_buf, out_max, "(Process exited with code %d)", code);
        pos = strlen(out_buf);
    }

    if (build_failed)
        snprintf(timing, timing_sz, "compile %s (failed)", build_t);
    else if (build[0])
        snprintf(timing, timing_sz, "compile %s | run %s", build_t, run_t);
    else
        snprintf(timing, timing_sz, "run %s", run_t);

    /* footer in the output panel, which stays visible after the notification clears */
    if (pos > 0 && out_buf[pos - 1] != '\n' && pos < out_max - 1) out_buf[pos++] = '\n';
    if (!build_failed && code != 0)
        snprintf(out_buf + pos, out_max - pos, "-- %s | exit %d --\n", timing, code);
    else
        snprintf(out_buf + pos, out_max - pos, "-- %s --\n", timing);

    if (build_is_compiled(lang)) {
        unlink("./temp_bin");
        unlink("./temp_bin.exe");
        unlink("./temp_obj.o");
    }
}
