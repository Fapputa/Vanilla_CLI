/* lsc.c — ls wrapper with custom colorization
 * Compile: gcc -O2 -Wall -Wextra -o lsc lsc.c
 * Config:  ~/.colorrc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define MAX_EXT   128
#define MAX_COLOR  64
#define MAX_RULES 512

typedef struct {
    char ext[MAX_EXT];
    char fg[MAX_COLOR];
    char bg[MAX_COLOR];
    int  bold, italic, underline, outline;
} Rule;

static Rule  rules[MAX_RULES];
static int   nrules     = 0;
static char  target_dir[4096];

/* ─────────────────────────────────────────────
 * Config parser
 * ───────────────────────────────────────────── */

static void parse_line(char *line)
{
    char *p;
    if ((p = strchr(line, '#')))  *p = '\0';
    if ((p = strchr(line, '\n'))) *p = '\0';
    if ((p = strchr(line, '\r'))) *p = '\0';
    while (*line == ' ' || *line == '\t') line++;
    if (!*line) return;

    char *eq = strchr(line, '=');
    if (!eq) return;
    *eq = '\0';
    char *key = line, *val = eq + 1;

    for (p = key + strlen(key) - 1; p >= key && (*p == ' ' || *p == '\t'); )
        *p-- = '\0';
    while (*val == ' ' || *val == '\t') val++;
    if (!*key) return;

    if (nrules >= MAX_RULES) return;
    Rule *r = &rules[nrules++];
    memset(r, 0, sizeof(*r));
    snprintf(r->ext, MAX_EXT, "%s", key);

    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", val);
    char *tok = strtok(tmp, " \t");
    int ci = 0;
    while (tok) {
        if      (!strcmp(tok, "bold"))      r->bold = 1;
        else if (!strcmp(tok, "italic"))    r->italic = 1;
        else if (!strcmp(tok, "underline")) r->underline = 1;
        else if (!strcmp(tok, "outline"))   r->outline = 1;
        else {
            if (ci == 0) snprintf(r->fg, MAX_COLOR, "%s", tok);
            if (ci == 1) snprintf(r->bg, MAX_COLOR, "%s", tok);
            ci++;
        }
        tok = strtok(NULL, " \t");
    }
}

static void load_config(void)
{
    const char *home = getenv("HOME");
    if (!home) return;
    char path[512];
    snprintf(path, sizeof(path), "%s/.colorrc", home);
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f))
        parse_line(line);
    fclose(f);
}

/* ─────────────────────────────────────────────
 * ANSI
 * ───────────────────────────────────────────── */

static void emit_color(const char *name, int is_bg)
{
    if (!name || !*name || !strcmp(name, "default")) return;

    struct { const char *n; int fg; int bg; } table[] = {
        {"black",          30,  40}, {"red",            31,  41},
        {"green",          32,  42}, {"yellow",         33,  43},
        {"blue",           34,  44}, {"magenta",        35,  45},
        {"cyan",           36,  46}, {"white",          37,  47},
        {"bright_black",   90, 100}, {"bright_red",     91, 101},
        {"bright_green",   92, 102}, {"bright_yellow",  93, 103},
        {"bright_blue",    94, 104}, {"bright_magenta", 95, 105},
        {"bright_cyan",    96, 106}, {"bright_white",   97, 107},
        {NULL, 0, 0}
    };
    for (int i = 0; table[i].n; i++) {
        if (!strcmp(table[i].n, name)) {
            printf("\033[%dm", is_bg ? table[i].bg : table[i].fg);
            return;
        }
    }
    char *end;
    long v = strtol(name, &end, 10);
    if (*end == '\0' && v >= 0 && v <= 255)
        printf("\033[%d;5;%ldm", is_bg ? 48 : 38, v);
}

static void ansi_apply(const Rule *r)
{
    if (!r) return;
    if (r->bold)      fputs("\033[1m", stdout);
    if (r->italic)    fputs("\033[3m", stdout);
    if (r->underline) fputs("\033[4m", stdout);
    if (r->outline)   fputs("\033[7m", stdout);  /* reverse video (fg↔bg) */
    emit_color(r->fg, 0);
    emit_color(r->bg, 1);
}

static void ansi_reset(void) { fputs("\033[0m", stdout); }

/* ─────────────────────────────────────────────
 * Stat d'un fichier
 * ───────────────────────────────────────────── */

typedef struct { int is_dir, is_exec, is_link; } FileType;

static FileType stat_file(const char *name)
{
    FileType ft = {0, 0, 0};
    char fullpath[8192];

    if (name[0] == '/')
        snprintf(fullpath, sizeof(fullpath), "%s", name);
    else
        snprintf(fullpath, sizeof(fullpath), "%s/%s", target_dir, name);

    struct stat st;
    if (lstat(fullpath, &st) != 0) return ft;

    ft.is_dir  = S_ISDIR(st.st_mode);
    ft.is_link = S_ISLNK(st.st_mode);
    ft.is_exec = !ft.is_dir && !ft.is_link &&
                 (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH));
    return ft;
}

/* ─────────────────────────────────────────────
 * Rule lookup
 *
 * Priorité :
 *   1. extension  (.c .py …)  — sauf si dir ou lien
 *   2. type spécial (dir / link / exec)
 *   3. noext  (fichiers sans extension, ni exec)
 * ───────────────────────────────────────────── */

static const Rule *find_rule(const char *name, int is_dir,
                              int is_exec, int is_link)
{
    /* 1. extension */
    if (!is_dir && !is_link) {
        const char *dot = strrchr(name, '.');
        if (dot && dot != name) {
            for (int i = 0; i < nrules; i++)
                if (!strcmp(rules[i].ext, dot))
                    return &rules[i];
        }
    }

    /* 2. type spécial */
    const char *special = NULL;
    if      (is_link) special = "link";
    else if (is_dir)  special = "dir";
    else if (is_exec) special = "exec";

    if (special) {
        for (int i = 0; i < nrules; i++)
            if (!strcmp(rules[i].ext, special))
                return &rules[i];
    }

    /* 3. noext */
    if (!is_dir && !is_link && !is_exec) {
        const char *dot = strrchr(name, '.');
        if (!dot || dot == name) {
            for (int i = 0; i < nrules; i++)
                if (!strcmp(rules[i].ext, "noext"))
                    return &rules[i];
        }
    }

    return NULL;
}

/* ─────────────────────────────────────────────
 * Détection mode long (ls -l)
 * ───────────────────────────────────────────── */

static int is_long_line(const char *s)
{
    if (strlen(s) < 10) return 0;
    if (s[0]!='-' && s[0]!='d' && s[0]!='l' &&
        s[0]!='c' && s[0]!='b' && s[0]!='p' && s[0]!='s') return 0;
    for (int i = 1; i <= 9; i++)
        if (s[i]!='r' && s[i]!='w' && s[i]!='x' && s[i]!='-') return 0;
    return 1;
}

/* ─────────────────────────────────────────────
 * Largeur terminal
 * ───────────────────────────────────────────── */

static int term_cols(void)
{
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 0)
        return (int)w.ws_col;
    return 80;
}

/* ─────────────────────────────────────────────
 * fork + execvp ls  (-1p : un fichier par ligne)
 * ───────────────────────────────────────────── */

static FILE *spawn_ls(int argc, char **argv)
{
    int  cols = term_cols();
    char cols_env[32];
    snprintf(cols_env, sizeof(cols_env), "COLUMNS=%d", cols);

    char **lsargv = malloc((size_t)(argc + 4) * sizeof(char *));
    if (!lsargv) return NULL;
    int ai = 0;
    lsargv[ai++] = "ls";
    lsargv[ai++] = "-1p";
    lsargv[ai++] = "--color=never";
    for (int i = 1; i < argc; i++) lsargv[ai++] = argv[i];
    lsargv[ai] = NULL;

    int pipefd[2];
    if (pipe(pipefd) < 0) { free(lsargv); return NULL; }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        free(lsargv); return NULL;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        putenv(cols_env);
        execvp("ls", lsargv);
        _exit(127);
    }

    close(pipefd[1]);
    free(lsargv);
    return fdopen(pipefd[0], "r");
}

/* ─────────────────────────────────────────────
 * Traitement mode long (ls -l)
 * ───────────────────────────────────────────── */

static void process_long_line(const char *buf)
{
    FileType lm_ft;
    lm_ft.is_dir  = (buf[0] == 'd');
    lm_ft.is_link = (buf[0] == 'l');
    lm_ft.is_exec = !lm_ft.is_dir && !lm_ft.is_link &&
                    (buf[3]=='x' || buf[6]=='x' || buf[9]=='x');

    const char *p = buf;
    int token_idx = 0;
    while (*p) {
        if (*p == ' ' || *p == '\t') { putchar(*p++); continue; }

        const char *start = p;
        while (*p && *p != ' ' && *p != '\t') p++;

        char raw[4096];
        size_t len = (size_t)(p - start);
        if (len >= sizeof(raw)) len = sizeof(raw) - 1;
        memcpy(raw, start, len);
        raw[len] = '\0';

        if (token_idx < 8 || !strcmp(raw, "->")) {
            fputs(raw, stdout);
        } else {
            char clean[4096];
            snprintf(clean, sizeof(clean), "%s", raw);
            size_t clen = strlen(clean);
            if (clen > 0 && clean[clen-1] == '/') clean[clen-1] = '\0';
            const Rule *r = find_rule(clean,
                lm_ft.is_dir, lm_ft.is_exec, lm_ft.is_link);
            if (r) ansi_apply(r);
            fputs(raw, stdout);
            if (r) ansi_reset();
        }
        token_idx++;
    }
    putchar('\n');
}

/* ─────────────────────────────────────────────
 * Affichage en colonnes (mode normal)
 *
 * On collecte tous les noms, on calcule la largeur
 * de colonne, puis on imprime avec padding — exactement
 * comme ls -C, mais avec nos couleurs ANSI.
 * ───────────────────────────────────────────── */

#define MAX_ENTRIES 65536

typedef struct {
    char  name[4096];   /* nom avec '/' éventuel pour l'affichage */
    char  clean[4096];  /* nom sans '/' pour le lookup            */
    FileType ft;
} Entry;

static Entry  entries[MAX_ENTRIES];
static int    nentries = 0;

static void collect_entry(const char *buf)
{
    if (nentries >= MAX_ENTRIES) return;
    Entry *e = &entries[nentries++];

    snprintf(e->name, sizeof(e->name), "%s", buf);
    snprintf(e->clean, sizeof(e->clean), "%s", buf);

    size_t clen = strlen(e->clean);
    int had_slash = (clen > 0 && e->clean[clen-1] == '/');
    if (had_slash) e->clean[--clen] = '\0';

    e->ft = stat_file(e->clean);
    if (had_slash) e->ft.is_dir = 1;
}

/* Largeur d'affichage reelle d'une chaine UTF-8.
 * Les octets de continuation (10xxxxxx) ne comptent pas. */
static int display_width(const char *s)
{
    int w = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if ((*p & 0xC0) != 0x80) w++;
    return w;
}

static void print_columns(void)
{
    if (nentries == 0) return;

    int cols = term_cols();

    /* largeur max en colonnes d'affichage (UTF-8 correct) */
    int maxw = 0;
    for (int i = 0; i < nentries; i++) {
        int w = display_width(entries[i].name);
        if (w > maxw) maxw = w;
    }

    /* nombre de colonnes qui tiennent */
    int gap   = 2;
    int col_w = maxw + gap;
    int ncols = cols / col_w;
    if (ncols < 1) ncols = 1;
    int nrows = (nentries + ncols - 1) / ncols;

    for (int row = 0; row < nrows; row++) {
        for (int col = 0; col < ncols; col++) {
            int idx = col * nrows + row;   /* ordre colonne-major, comme ls -C */
            if (idx >= nentries) break;

            Entry *e = &entries[idx];
            const Rule *r = find_rule(e->clean,
                e->ft.is_dir, e->ft.is_exec, e->ft.is_link);

            if (r) ansi_apply(r);
            fputs(e->name, stdout);
            if (r) ansi_reset();

            /* padding sauf pour la derniere colonne de la ligne */
            int is_last_col = (col == ncols - 1) ||
                              ((col + 1) * nrows + row >= nentries);
            if (!is_last_col) {
                int w = display_width(e->name);
                for (int s = w; s < col_w; s++) putchar(' ');
            }
        }
        putchar('\n');
    }
}

/* ─────────────────────────────────────────────
 * Main
 * ───────────────────────────────────────────── */

int main(int argc, char **argv)
{
    load_config();

    /* Répertoire cible : argument non-option, sinon CWD absolu réel */
    const char *arg_dir = NULL;
    int long_mode = 0;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (strchr(argv[i], 'l')) long_mode = 1;
        } else {
            arg_dir = argv[i];
        }
    }

    if (arg_dir) {
        snprintf(target_dir, sizeof(target_dir), "%s", arg_dir);
    } else {
        if (!getcwd(target_dir, sizeof(target_dir)))
            snprintf(target_dir, sizeof(target_dir), ".");
    }

    FILE *f = spawn_ls(argc, argv);
    if (!f) { perror("lsc: spawn_ls"); return 1; }

    char line[8192];
    while (fgets(line, sizeof(line), f)) {
        /* strip newline */
        char buf[8192];
        snprintf(buf, sizeof(buf), "%s", line);
        char *nl = strchr(buf, '\n'); if (nl) *nl = '\0';
        char *cr = strchr(buf, '\r'); if (cr) *cr = '\0';
        if (!*buf) continue;

        if (long_mode || is_long_line(buf)) {
            /* mode long : on vide d'abord le buffer colonne si besoin */
            if (nentries > 0) { print_columns(); nentries = 0; }
            process_long_line(buf);
        } else {
            collect_entry(buf);
        }
    }

    /* afficher ce qui reste en colonnes */
    if (nentries > 0) print_columns();

    fclose(f);
    int status;
    wait(&status);
    return WEXITSTATUS(status);
}