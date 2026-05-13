#include "abyss.h"
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

/* ═══════════════════════════════════════════════════════════════
 *  Constantes color pairs ncurses
 *
 *  TREE_CP_BASE … TREE_CP_BASE+TREE_CP_SLOTS-1  → règles .colorrc
 *  TREE_CP_SEL    → entrée sélectionnée
 *  TREE_CP_HEADER → bandeau chemin
 *  TREE_CP_BORDER → bordure gauche
 * ═══════════════════════════════════════════════════════════════ */
#define TREE_CP_BASE   40
#define TREE_CP_SLOTS  64

#define TREE_CP_SEL    (TREE_CP_BASE + TREE_CP_SLOTS)
#define TREE_CP_HEADER (TREE_CP_BASE + TREE_CP_SLOTS + 1)
#define TREE_CP_BORDER (TREE_CP_BASE + TREE_CP_SLOTS + 2)

/* ═══════════════════════════════════════════════════════════════
 *  Parser .colorrc
 * ═══════════════════════════════════════════════════════════════ */

typedef struct {
    char  key[32];      /* ".c", "dir", "exec", "noext", "link" … */
    short fg;           /* couleur ncurses FG, -1 = défaut         */
    bool  bold, italic, underline;
    int   pair_id;      /* color pair ncurses allouée              */
} ColorRule;

static ColorRule g_rules[TREE_CP_SLOTS];
static int       g_nrules        = 0;
static bool      g_colorrc_ready = false;   /* init_pair appelés ? */

/* Conversion nom texte → id couleur ncurses (-1 = défaut/inconnu).
 * Les variantes bright_* sont mappées sur leur couleur de base ;
 * le "bright" est traduit en A_BOLD dans apply_rule(). */
static short name_to_color(const char *s)
{
    if (!s || !s[0] || strcmp(s, "default") == 0) return -1;

    static const struct { const char *n; short c; } tbl[] = {
        { "black",          COLOR_BLACK   },
        { "red",            COLOR_RED     },
        { "green",          COLOR_GREEN   },
        { "yellow",         COLOR_YELLOW  },
        { "blue",           COLOR_BLUE    },
        { "magenta",        COLOR_MAGENTA },
        { "cyan",           COLOR_CYAN    },
        { "white",          COLOR_WHITE   },
        { "bright_black",   COLOR_BLACK   },
        { "bright_red",     COLOR_RED     },
        { "bright_green",   COLOR_GREEN   },
        { "bright_yellow",  COLOR_YELLOW  },
        { "bright_blue",    COLOR_BLUE    },
        { "bright_magenta", COLOR_MAGENTA },
        { "bright_cyan",    COLOR_CYAN    },
        { "bright_white",   COLOR_WHITE   },
        { NULL, 0 }
    };
    for (int i = 0; tbl[i].n; i++)
        if (strcmp(tbl[i].n, s) == 0) return tbl[i].c;
    return -1;
}

/* Parser une ligne "key = FG [BG] [bold] [italic] [underline]".
 *
 * La BG du .colorrc est IGNORÉE dans le tree : on force toujours
 * bg=-1 (fond transparent du terminal) pour ne jamais produire
 * de bandes colorées derrière les noms de fichiers. */
static void parse_colorrc_line(const char *line)
{
    if (g_nrules >= TREE_CP_SLOTS) return;

    while (isspace((unsigned char)*line)) line++;
    if (!*line || *line == '#') return;

    /* Clé */
    char key[32] = "";
    int  ki = 0;
    while (*line && !isspace((unsigned char)*line) && *line != '=' && ki < 31)
        key[ki++] = *line++;
    key[ki] = '\0';
    if (!key[0]) return;

    /* Avancer jusqu'au '=' */
    while (*line && *line != '=') line++;
    if (*line != '=') return;
    line++;
    while (isspace((unsigned char)*line)) line++;

    /* Tokens de valeur */
    short fg        = -1;
    bool  bold      = false;
    bool  italic    = false;
    bool  underline = false;
    bool  fg_done   = false;

    char tok[32];
    while (*line) {
        while (isspace((unsigned char)*line)) line++;
        if (!*line || *line == '#' || *line == '\n' || *line == '\r') break;

        int ti = 0;
        while (*line && !isspace((unsigned char)*line) && ti < 31)
            tok[ti++] = *line++;
        tok[ti] = '\0';
        if (!tok[0]) break;

        if      (strcmp(tok, "bold")      == 0) { bold      = true; continue; }
        else if (strcmp(tok, "italic")    == 0) { italic    = true; continue; }
        else if (strcmp(tok, "underline") == 0) { underline = true; continue; }
        else if (strcmp(tok, "outline")   == 0) { continue; } /* ignoré */

        /* Token couleur : bright_* → forcer bold */
        if (strncmp(tok, "bright_", 7) == 0) bold = true;

        if (!fg_done) {
            fg      = name_to_color(tok);
            fg_done = true;
        }
        /* Deuxième token (BG du .colorrc) : lu mais ignoré. */
    }

    ColorRule *r = &g_rules[g_nrules];
    strncpy(r->key, key, sizeof r->key - 1);
    r->key[sizeof r->key - 1] = '\0';
    r->fg        = fg;
    r->bold      = bold;
    r->italic    = italic;
    r->underline = underline;
    r->pair_id   = TREE_CP_BASE + g_nrules;
    /* Les init_pair sont différés dans ft_init_color_pairs(),
     * appelé après initscr(). */
    g_nrules++;
}

/* Charger ~/.colorrc — parsing seul, sans toucher ncurses. */
static void load_colorrc(void)
{
    const char *home = NULL;
    const char *sudo_user = getenv("SUDO_USER");
    char sudo_home[4096] = "";
    if (sudo_user && sudo_user[0]) {
        snprintf(sudo_home, sizeof sudo_home, "/home/%s", sudo_user);
        home = sudo_home;
    }
    if (!home) home = getenv("HOME");
    if (!home) return;

    char path[4096];
    snprintf(path, sizeof path, "%s/.colorrc", home);

    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[512];
    while (fgets(line, sizeof line, f))
        parse_colorrc_line(line);
    fclose(f);
}

/* Allouer les color pairs ncurses.
 * À appeler UNE FOIS après initscr() + start_color() + use_default_colors().
 * Peut être appelée depuis l'init principale de l'éditeur. */
void ft_init_color_pairs(void)
{
    if (g_colorrc_ready) return;
    g_colorrc_ready = true;

    for (int i = 0; i < g_nrules; i++) {
        ColorRule *r = &g_rules[i];
        /* bg toujours -1 : fond transparent, zéro bande colorée. */
        init_pair((short)r->pair_id, r->fg, -1);
    }

    /* Paires fixes internes */
    init_pair(TREE_CP_SEL,    COLOR_BLACK, COLOR_CYAN);
    init_pair(TREE_CP_HEADER, COLOR_WHITE, COLOR_RED);
    init_pair(TREE_CP_BORDER, COLOR_CYAN,  -1);
}

/* ── Trouver la règle pour une entrée ──
 *
 * Priorité (calquée sur lsc) :
 *   1. dirs  → "dir"
 *   2. liens → extension d'abord, puis "link"
 *   3. execs → extension d'abord, puis "exec"
 *   4. fichiers normaux avec extension → ".ext"
 *   5. fichiers sans extension          → "noext"
 */
static const ColorRule *find_rule(const FTEntry *e)
{
    if (e->is_dir) {
        for (int i = 0; i < g_nrules; i++)
            if (strcmp(g_rules[i].key, "dir") == 0) return &g_rules[i];
        return NULL;
    }

    if (e->is_lnk) {
        const char *dot = strrchr(e->name, '.');
        if (dot && dot != e->name)
            for (int i = 0; i < g_nrules; i++)
                if (strcmp(g_rules[i].key, dot) == 0) return &g_rules[i];
        for (int i = 0; i < g_nrules; i++)
            if (strcmp(g_rules[i].key, "link") == 0) return &g_rules[i];
        return NULL;
    }

    if (e->is_exe) {
        const char *dot = strrchr(e->name, '.');
        if (dot && dot != e->name)
            for (int i = 0; i < g_nrules; i++)
                if (strcmp(g_rules[i].key, dot) == 0) return &g_rules[i];
        for (int i = 0; i < g_nrules; i++)
            if (strcmp(g_rules[i].key, "exec") == 0) return &g_rules[i];
        return NULL;
    }

    /* Fichier normal */
    const char *dot = strrchr(e->name, '.');
    if (dot && dot != e->name) {
        for (int i = 0; i < g_nrules; i++)
            if (strcmp(g_rules[i].key, dot) == 0) return &g_rules[i];
    } else {
        for (int i = 0; i < g_nrules; i++)
            if (strcmp(g_rules[i].key, "noext") == 0) return &g_rules[i];
    }
    return NULL;
}

/* ── Appliquer les attributs d'une règle ── */
static void apply_rule(WINDOW *win, const ColorRule *r)
{
    wattron(win, COLOR_PAIR(r->pair_id));
    if (r->bold)      wattron(win, A_BOLD);
    if (r->italic)    wattron(win, A_ITALIC);
    if (r->underline) wattron(win, A_UNDERLINE);
}

/* ═══════════════════════════════════════════════════════════════
 *  Helpers internes
 * ═══════════════════════════════════════════════════════════════ */

static int ft_entry_cmp(const void *a, const void *b)
{
    const FTEntry *ea = (const FTEntry *)a;
    const FTEntry *eb = (const FTEntry *)b;
    if (ea->is_dir != eb->is_dir) return eb->is_dir - ea->is_dir;
    return strcasecmp(ea->name, eb->name);
}

/* Exécutable = bit x owner posé ET fichier lisible par owner.
 * Évite les faux positifs sur les fichiers avec S_IXGRP/S_IXOTH
 * seuls (fichiers .o, .md, etc. souvent marqués group+x). */
static bool is_executable(const struct stat *st)
{
    return (st->st_mode & S_IXUSR) && (st->st_mode & S_IRUSR);
}

/* ═══════════════════════════════════════════════════════════════
 *  API publique
 * ═══════════════════════════════════════════════════════════════ */

FileTree *ft_new(void)
{
    load_colorrc();   /* parsing seul, sans appels ncurses */

    FileTree *ft = calloc(1, sizeof *ft);
    if (!ft) return NULL;

    if (!getcwd(ft->cwd, sizeof ft->cwd))
        strncpy(ft->cwd, ".", sizeof ft->cwd - 1);

    ft->visible = false;
    ft->width   = TREE_DEFAULT_W;
    ft_reload(ft);
    return ft;
}

void ft_free(FileTree *ft)
{
    if (!ft) return;
    free(ft->entries);
    free(ft);
}

void ft_reload(FileTree *ft)
{
    free(ft->entries);
    ft->entries = NULL;
    ft->count   = 0;
    ft->cap     = 0;

    DIR *d = opendir(ft->cwd);
    if (!d) return;

    struct dirent *de;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0) continue;

        char full[4096];
        snprintf(full, sizeof full, "%s/%s", ft->cwd, de->d_name);

        struct stat st;
        if (lstat(full, &st) != 0) continue;   /* lstat pour les liens */

        if (ft->count >= ft->cap) {
            ft->cap     = ft->cap ? ft->cap * 2 : 64;
            ft->entries = realloc(ft->entries, ft->cap * sizeof(FTEntry));
            if (!ft->entries) { ft->cap = 0; ft->count = 0; break; }
        }

        FTEntry *e = &ft->entries[ft->count++];
        strncpy(e->name, de->d_name, sizeof e->name - 1);
        e->name[sizeof e->name - 1] = '\0';

        e->is_dir = S_ISDIR(st.st_mode);
        e->is_lnk = S_ISLNK(st.st_mode);
        e->is_exe = !e->is_dir && !e->is_lnk && is_executable(&st);
        e->size   = (size_t)st.st_size;
    }
    closedir(d);

    qsort(ft->entries, ft->count, sizeof(FTEntry), ft_entry_cmp);

    if (ft->count > 0 && ft->selected >= ft->count)
        ft->selected = ft->count - 1;
    ft->scroll = 0;
}

void ft_enter(FileTree *ft)
{
    if (!ft->count) return;
    FTEntry *e = &ft->entries[ft->selected];
    if (!e->is_dir) return;

    if (strcmp(e->name, "..") == 0) { ft_go_up(ft); return; }

    char new_cwd[4096];
    snprintf(new_cwd, sizeof new_cwd, "%s/%s", ft->cwd, e->name);

    char resolved[4096];
    if (realpath(new_cwd, resolved))
        strncpy(ft->cwd, resolved, sizeof ft->cwd - 1);
    else
        strncpy(ft->cwd, new_cwd,  sizeof ft->cwd - 1);

    ft->selected = 0;
    ft->scroll   = 0;
    ft_reload(ft);
}

void ft_go_up(FileTree *ft)
{
    /* Mémoriser le nom du répertoire courant pour repointer dessus */
    char old_name[256] = "";
    const char *slash = strrchr(ft->cwd, '/');
    if (slash && slash != ft->cwd)
        strncpy(old_name, slash + 1, sizeof old_name - 1);

    char new_cwd[4096];
    snprintf(new_cwd, sizeof new_cwd, "%s/..", ft->cwd);

    char resolved[4096];
    if (realpath(new_cwd, resolved))
        strncpy(ft->cwd, resolved, sizeof ft->cwd - 1);

    ft->selected = 0;
    ft->scroll   = 0;
    ft_reload(ft);

    if (old_name[0]) {
        for (size_t i = 0; i < ft->count; i++) {
            if (strcmp(ft->entries[i].name, old_name) == 0) {
                ft->selected = i;
                break;
            }
        }
    }
}

const char *ft_selected_path(FileTree *ft, char *buf, size_t bufsz)
{
    if (!ft->count) return NULL;
    FTEntry *e = &ft->entries[ft->selected];
    if (e->is_dir) return NULL;
    snprintf(buf, bufsz, "%s/%s", ft->cwd, e->name);
    return buf;
}

/* ═══════════════════════════════════════════════════════════════
 *  Rendu — panneau à DROITE, bordure à GAUCHE
 * ═══════════════════════════════════════════════════════════════ */
void ft_render(FileTree *ft, WINDOW *win, int win_h, int win_w, bool is_active)
{
    if (!win || !ft->visible) return;

    /* Garde-fou : s'assurer que les pairs sont prêtes. */
    if (!g_colorrc_ready) ft_init_color_pairs();

    /* Fond transparent sur toute la fenêtre — élimine toute bande. */
    wbkgdset(win, ' ' | COLOR_PAIR(COLOR_PAIR_NORMAL));
    werase(win);

    /* ── Bordure gauche ── */
    {
        int cp = is_active
            ? COLOR_PAIR(TREE_CP_BORDER)
            : COLOR_PAIR(COLOR_PAIR_INACTIVE_BORDER);
        wattron(win, cp);
        for (int r = 0; r < win_h; r++) mvwaddch(win, r, 0, ACS_VLINE);
        wattroff(win, cp);
    }

    /* Zone utile : colonne 1 … win_w-1 */
    int inner_w = win_w - 1;
    if (inner_w < 1) inner_w = 1;

    /* ── Header : chemin courant ── */
    {
        wattron(win, COLOR_PAIR(TREE_CP_HEADER) | A_BOLD);
        wmove(win, 0, 1);

        char display_cwd[4096];
        const char *home = getenv("HOME");
        if (home && strncmp(ft->cwd, home, strlen(home)) == 0)
            snprintf(display_cwd, sizeof display_cwd,
                     "~%s", ft->cwd + strlen(home));
        else
            strncpy(display_cwd, ft->cwd, sizeof display_cwd - 1);

        /* Tronquer par la gauche si trop long */
        const char *cwd_disp = display_cwd;
        int cwd_len = (int)strlen(display_cwd);
        if (cwd_len > inner_w - 1)
            cwd_disp = display_cwd + (cwd_len - (inner_w - 1));

        /* Padding fixe — PAS wclrtoeol (propagerait la couleur header
         * jusqu'au bord et créerait une bande rouge sur toute la ligne). */
        wprintw(win, " %-*s", inner_w - 1, cwd_disp);
        wattroff(win, COLOR_PAIR(TREE_CP_HEADER) | A_BOLD);
    }

    /* ── Liste des entrées ── */
    int rows = win_h - 1;
    if (rows < 1) rows = 1;

    /* Ajuster le scroll pour garder la sélection visible */
    if ((int)ft->selected < (int)ft->scroll)
        ft->scroll = ft->selected;
    if ((int)ft->selected >= (int)ft->scroll + rows)
        ft->scroll = ft->selected - rows + 1;

    for (int row = 0; row < rows; row++) {
        size_t idx = ft->scroll + (size_t)row;
        wmove(win, row + 1, 1);

        /* Ligne vide sous la liste */
        if (idx >= ft->count) {
            wattron(win, COLOR_PAIR(COLOR_PAIR_NORMAL));
            wprintw(win, "%-*s", inner_w - 1, "");
            wattroff(win, COLOR_PAIR(COLOR_PAIR_NORMAL));
            continue;
        }

        FTEntry *e       = &ft->entries[idx];
        bool    selected = (idx == ft->selected) && is_active;

        /* ── Appliquer l'attribut de la ligne ── */
        if (selected) {
            wattron(win, COLOR_PAIR(TREE_CP_SEL) | A_BOLD);
        } else {
            const ColorRule *r = find_rule(e);
            if (r) apply_rule(win, r);
            else   wattron(win, COLOR_PAIR(COLOR_PAIR_NORMAL));
        }

        /* Préfixe : '/' répertoire, '@' lien, ' ' fichier normal */
        char prefix   = e->is_dir ? '/' : (e->is_lnk ? '@' : ' ');
        int  max_name = inner_w - 2;
        if (max_name < 1) max_name = 1;

        /* Padding fixe sur toute la largeur — PAS wclrtoeol pour
         * éviter que la couleur courante se propage jusqu'au bord. */
        wprintw(win, " %c%-*.*s", prefix, max_name, max_name, e->name);

        /* Réinitialiser TOUS les attributs avant la ligne suivante. */
        wstandend(win);
    }

    wnoutrefresh(win);
}

/* ═══════════════════════════════════════════════════════════════
 *  Gestion des touches
 * ═══════════════════════════════════════════════════════════════ */
bool ft_handle_key(FileTree *ft, int key, char *open_path, size_t path_sz)
{
    open_path[0] = '\0';

    switch (key) {
        case KEY_UP:
            if (ft->selected > 0) ft->selected--;
            return true;
        case KEY_DOWN:
            if (ft->selected + 1 < ft->count) ft->selected++;
            return true;
        case KEY_PPAGE:
            ft->selected = (ft->selected > 10) ? ft->selected - 10 : 0;
            return true;
        case KEY_NPAGE:
            ft->selected = (ft->selected + 10 < ft->count)
                         ? ft->selected + 10
                         : (ft->count > 0 ? ft->count - 1 : 0);
            return true;
        case KEY_HOME:
            ft->selected = 0;
            return true;
        case KEY_END:
            ft->selected = ft->count > 0 ? ft->count - 1 : 0;
            return true;
        case '\n': case '\r': case KEY_RIGHT:
            if (ft->count > 0) {
                FTEntry *e = &ft->entries[ft->selected];
                if (e->is_dir) ft_enter(ft);
                else           ft_selected_path(ft, open_path, path_sz);
            }
            return true;
        case KEY_LEFT:
        case KEY_BACKSPACE:
        case 127:
        case '\b':
            ft_go_up(ft);
            return true;
        default:
            return false;
    }
}