/* lsc-config.c — TUI ncurses pour éditer ~/.colorrc
 * Compile: gcc -O2 -Wall -Wextra -o lsc-config lsc-config.c -lncurses
 *
 * Contrôles:
 *   ↑↓        naviguer les règles
 *   f         changer couleur FG (menu déroulant avec preview)
 *   g         changer couleur BG (menu déroulant avec preview)
 *   b/i/u     toggle Bold / Italic / Underline
 *   a         ajouter une règle
 *   d         supprimer la règle sélectionnée
 *   s         sauvegarder
 *   q         quitter
 */

#include <ncurses.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define MAX_RULES 512
#define MAX_EXT   128
#define MAX_COLOR  64

/* ─────────────────────────────────────────────
 * Palette de couleurs disponibles
 * ───────────────────────────────────────────── */

typedef struct {
    const char *name;
    int         ncurses_id;
} ColorDef;

static const ColorDef COLOR_TABLE[] = {
    { "default",        -1   },
    { "black",           0   },
    { "red",             1   },
    { "green",           2   },
    { "yellow",          3   },
    { "blue",            4   },
    { "magenta",         5   },
    { "cyan",            6   },
    { "white",           7   },
    { "bright_black",    8   },
    { "bright_red",      9   },
    { "bright_green",   10   },
    { "bright_yellow",  11   },
    { "bright_blue",    12   },
    { "bright_magenta", 13   },
    { "bright_cyan",    14   },
    { "bright_white",   15   },
    { "196",           196   },
    { "208",           208   },
    { "226",           226   },
    { "46",             46   },
    { "51",             51   },
    { "21",             21   },
    { "129",           129   },
    { "201",           201   },
    { "214",           214   },
    { "240",           240   },
    { "250",           250   },
    { NULL, 0 }
};

static int n_palette = 0;
#define PAIR_FG(i)   ((i) + 1)
#define PAIR_BG(i)   (n_palette + (i) + 1)
#define PAIR_PREVIEW (2 * n_palette + 2)

static int color_count(void)
{
    int n = 0; while (COLOR_TABLE[n].name) n++; return n;
}

static int color_index(const char *name)
{
    if (!name || !*name) return 0;
    int n = color_count();
    for (int i = 0; i < n; i++)
        if (!strcmp(COLOR_TABLE[i].name, name)) return i;
    return 0;
}

static int resolve_color(const char *name)
{
    if (!name || !*name || !strcmp(name, "default")) return -1;
    int n = color_count();
    for (int i = 1; i < n; i++)
        if (!strcmp(COLOR_TABLE[i].name, name)) return COLOR_TABLE[i].ncurses_id;
    char *ep; long v = strtol(name, &ep, 10);
    if (*ep == '\0' && v >= 0 && v <= 255) return (int)v;
    return -1;
}

static void init_color_pairs(void)
{
    n_palette = color_count();
    for (int i = 0; i < n_palette; i++) {
        int cid = COLOR_TABLE[i].ncurses_id;
        init_pair((short)PAIR_FG(i), (short)cid, -1);
        init_pair((short)PAIR_BG(i), -1, (short)cid);
    }
    init_pair((short)PAIR_PREVIEW, -1, -1);
}

/* ─────────────────────────────────────────────
 * Modèle de données
 * ───────────────────────────────────────────── */

typedef struct {
    char ext[MAX_EXT];
    char fg[MAX_COLOR];
    char bg[MAX_COLOR];
    int  bold, italic, underline, outline;
} Rule;

static Rule  rules[MAX_RULES];
static int   nrules = 0;
static int   sel    = 0;
static char  config_path[512];

/* ─────────────────────────────────────────────
 * I/O fichier
 * ───────────────────────────────────────────── */

static void load_file(void)
{
    FILE *f = fopen(config_path, "r");
    if (!f) return;
    char line[256];
    nrules = 0;
    while (fgets(line, sizeof(line), f) && nrules < MAX_RULES) {
        char *p;
        if ((p = strchr(line, '#')))  *p = '\0';
        if ((p = strchr(line, '\n'))) *p = '\0';
        if ((p = strchr(line, '\r'))) *p = '\0';
        while (*line == ' ' || *line == '\t') memmove(line, line+1, strlen(line));
        if (!*line) continue;
        char *eq = strchr(line, '='); if (!eq) continue;
        *eq = '\0';
        char *key = line, *val = eq+1;
        for (p = key+strlen(key)-1; p >= key && (*p==' '||*p=='\t'); ) *p--='\0';
        while (*val == ' ' || *val == '\t') val++;
        if (!*key) continue;

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
    fclose(f);
}

static void save_file(void)
{
    FILE *f = fopen(config_path, "w");
    if (!f) return;
    fprintf(f, "# lsc color config\n");
    fprintf(f, "# format: .ext = FG [BG] [bold] [italic] [underline]\n");
    fprintf(f, "# special keys: dir  exec  link  noext\n\n");
    for (int i = 0; i < nrules; i++) {
        Rule *r = &rules[i];
        fprintf(f, "%-14s = %s", r->ext, *r->fg ? r->fg : "default");
        if (*r->bg) fprintf(f, " %s", r->bg);
        if (r->bold)      fprintf(f, " bold");
        if (r->italic)    fprintf(f, " italic");
        if (r->underline) fprintf(f, " underline");
        if (r->outline)   fprintf(f, " outline");
        fprintf(f, "\n");
    }
    fclose(f);
}

/* ─────────────────────────────────────────────
 * Rendu ANSI inline dans ncurses via escape raw
 * On utilise attron/attroff ncurses pour les attributs,
 * et on émet directement les codes ANSI pour les couleurs
 * (puisque ncurses gère mal les 256 couleurs sans init complexe).
 * ───────────────────────────────────────────── */

/* Applique fg+bg+attrs pour preview dans ncurses via color pairs */
static void apply_preview(WINDOW *w, const Rule *r)
{
    if (r->bold)      wattron(w, A_BOLD);
    if (r->italic)    wattron(w, A_ITALIC);
    if (r->underline) wattron(w, A_UNDERLINE);
#ifdef A_OVERLINE
    if (r->outline)   wattron(w, A_OVERLINE);
#endif

    int fg_idx = color_index(r->fg);
    int bg_idx = color_index(r->bg);
    int fg_id  = resolve_color(r->fg);
    int bg_id  = resolve_color(r->bg);

    if (fg_id >= 0 || bg_id >= 0) {
        /* init d'un pair temporaire fg+bg */
        init_pair((short)PAIR_PREVIEW,
                  (short)(fg_id >= 0 ? fg_id : -1),
                  (short)(bg_id >= 0 ? bg_id : -1));
        wattron(w, COLOR_PAIR(PAIR_PREVIEW));
    } else {
        (void)fg_idx; (void)bg_idx;
    }
}

static void clear_preview(WINDOW *w, const Rule *r)
{
    wattroff(w, A_BOLD | A_ITALIC | A_UNDERLINE);
#ifdef A_OVERLINE
    if (r->outline) wattroff(w, A_OVERLINE);
#else
    (void)r;
#endif
    wattroff(w, COLOR_PAIR(PAIR_PREVIEW));
}

/* ─────────────────────────────────────────────
 * Menu déroulant avec preview couleur ANSI
 * Retourne l'index sélectionné dans COLOR_TABLE[]
 * ───────────────────────────────────────────── */

static int dropdown_color(int y, int x, int current, const char *label)
{
    int n = color_count();
    int width = 34;

    int maxy, maxx;
    getmaxyx(stdscr, maxy, maxx);

    /* hauteur visible bornée à ce qui tient dans le terminal */
    int max_visible = maxy - 4;
    if (max_visible < 3) max_visible = 3;
    int visible = (n < max_visible) ? n : max_visible;
    int height  = visible + 2;  /* bordures */

    /* position : recalculer pour tenir */
    if (y + height > maxy) y = maxy - height;
    if (x + width  > maxx) x = maxx - width;
    if (y < 0) y = 0;
    if (x < 0) x = 0;

    WINDOW *w = newwin(height, width, y, x);
    if (!w) return current;   /* guard : newwin a échoué */
    keypad(w, TRUE);
    raw();       /* raw() : Enter = 13 (\r), pas besoin de \n */
    flushinp();  /* vider tout ce qui traîne dans le buffer */
    box(w, 0, 0);

    char title[40];
    snprintf(title, sizeof(title), " %s ", label);
    mvwprintw(w, 0, (width - (int)strlen(title)) / 2, "%s", title);

    int idx    = current;
    int scroll = 0;  /* première entrée visible */

    /* mettre la sélection dans la fenêtre */
    if (idx >= scroll + visible) scroll = idx - visible + 1;
    if (idx < scroll)            scroll = idx;

    for (;;) {
        /* dessiner les entrées visibles */
        for (int vi = 0; vi < visible; vi++) {
            int i   = scroll + vi;
            int row = vi + 1;

            wmove(w, row, 1);
            for (int c = 1; c < width - 1; c++) waddch(w, ' ');
            wmove(w, row, 2);

            const ColorDef *cd = &COLOR_TABLE[i];
            if (cd->ncurses_id >= 0) {
                wattron(w, COLOR_PAIR(PAIR_BG(i)));
                waddstr(w, "  ");
                wattroff(w, COLOR_PAIR(PAIR_BG(i)));
            } else {
                waddstr(w, "  ");
            }
            waddch(w, ' ');

            if (i == idx) wattron(w, A_REVERSE);
            wprintw(w, "%-26s", cd->name);
            if (i == idx) wattroff(w, A_REVERSE);
        }

        /* indicateur scroll */
        if (scroll > 0)
            mvwprintw(w, 0, width - 4, " ▲ ");
        if (scroll + visible < n)
            mvwprintw(w, height - 1, width - 4, " ▼ ");

        wrefresh(w);

        int c = wgetch(w);
        switch (c) {
            case KEY_UP:
                if (idx > 0) {
                    idx--;
                    if (idx < scroll) scroll = idx;
                }
                break;
            case KEY_DOWN:
                if (idx < n - 1) {
                    idx++;
                    if (idx >= scroll + visible) scroll = idx - visible + 1;
                }
                break;
            case KEY_PPAGE:
                idx = (idx > visible) ? idx - visible : 0;
                if (idx < scroll) scroll = idx;
                break;
            case KEY_NPAGE:
                idx = (idx + visible < n) ? idx + visible : n - 1;
                if (idx >= scroll + visible) scroll = idx - visible + 1;
                break;
            case '\n':
            case '\r':
            case KEY_ENTER:
                goto done;
            case 27:
            case 'q':
                idx = current;
                goto done;
        }
    }
done:
    delwin(w);
    cbreak();    /* rétablir cbreak pour la boucle principale */
    touchwin(stdscr);
    refresh();
    return idx;
}

/* ─────────────────────────────────────────────
 * Dessin de la liste principale
 * ───────────────────────────────────────────── */

static void draw_list(int sy, int sx, int height)
{
    attron(A_BOLD);
    mvprintw(sy - 1, sx,
        "%-16s %-3s %-20s %-3s %-18s  B I U O",
        "Extension", " ", "Foreground", " ", "Background");
    attroff(A_BOLD);
    mvhline(sy, sx, ACS_HLINE, 72);

    int visible = height - 2;
    static int scroll = 0;
    if (sel < scroll) scroll = sel;
    if (sel >= scroll + visible) scroll = sel - visible + 1;

    for (int i = 0; i < visible && (scroll + i) < nrules; i++) {
        int ri = scroll + i;
        Rule *r = &rules[ri];
        int row = sy + 1 + i;

        /* Extension */
        if (ri == sel) attron(A_REVERSE);
        mvprintw(row, sx, "%-16s", r->ext);
        if (ri == sel) attroff(A_REVERSE);

        /* FG : carré coloré (couleur en fond) + nom */
        {
            int fidx = color_index(r->fg);
            int fid  = resolve_color(r->fg);
            move(row, sx + 16);
            if (fid >= 0) {
                attron(COLOR_PAIR(PAIR_BG(fidx)));
                addstr("  ");
                attroff(COLOR_PAIR(PAIR_BG(fidx)));
            } else {
                addstr("  ");
            }
            addch(' ');
            if (ri == sel) attron(A_REVERSE);
            printw("%-20s", *r->fg ? r->fg : "default");
            if (ri == sel) attroff(A_REVERSE);
        }

        /* BG : carré coloré (couleur en fond) + nom */
        {
            int bidx = color_index(r->bg);
            int bid  = resolve_color(r->bg);
            move(row, sx + 39);
            if (bid >= 0) {
                attron(COLOR_PAIR(PAIR_BG(bidx)));
                addstr("  ");
                attroff(COLOR_PAIR(PAIR_BG(bidx)));
            } else {
                addstr("  ");
            }
            addch(' ');
            if (ri == sel) attron(A_REVERSE);
            printw("%-18s", *r->bg ? r->bg : "-");
            if (ri == sel) attroff(A_REVERSE);
        }

        /* Flags */
        if (ri == sel) attron(A_REVERSE);
        mvprintw(row, sx + 62, " %c %c %c %c",
            r->bold      ? 'B' : '.',
            r->italic    ? 'I' : '.',
            r->underline ? 'U' : '.',
            r->outline   ? 'O' : '.');
        if (ri == sel) attroff(A_REVERSE);
    }

    if (nrules > visible)
        mvprintw(sy + 1 + visible, sx, " [%d/%d]", sel + 1, nrules);
}

/* ─────────────────────────────────────────────
 * Preview de la règle sélectionnée
 * ───────────────────────────────────────────── */

static void draw_preview(int y, int x, const Rule *r)
{
    attron(A_BOLD);
    mvprintw(y, x, "Preview:");
    attroff(A_BOLD);

    move(y, x + 9);

    /* Construire un color pair fg+bg combiné pour la preview */
    int fg_id = resolve_color(r->fg);
    int bg_id = resolve_color(r->bg);
    init_pair((short)PAIR_PREVIEW,
              (short)(fg_id >= 0 ? fg_id : -1),
              (short)(bg_id >= 0 ? bg_id : -1));

    attr_t attrs = COLOR_PAIR(PAIR_PREVIEW);
    if (r->bold)      attrs |= A_BOLD;
    if (r->italic)    attrs |= A_ITALIC;
    if (r->underline) attrs |= A_UNDERLINE;
#ifdef A_OVERLINE
    if (r->outline)   attrs |= A_OVERLINE;
#endif

    attron(attrs);
    printw("  %s  ", *r->ext ? r->ext : "fichier");
    attroff(attrs);
}

/* ─────────────────────────────────────────────
 * Actions
 * ───────────────────────────────────────────── */

static void action_fg(void)
{
    if (nrules == 0) return;
    Rule *r = &rules[sel];
    int cur = color_index(r->fg);
    int maxy, maxx; getmaxyx(stdscr, maxy, maxx);
    int ci = dropdown_color(4, maxx/2 - 16, cur, "Foreground color");
    snprintf(r->fg, MAX_COLOR, "%s", COLOR_TABLE[ci].name);
    if (!strcmp(r->fg, "default")) r->fg[0] = '\0';
}

static void action_bg(void)
{
    if (nrules == 0) return;
    Rule *r = &rules[sel];
    int cur = color_index(r->bg);
    int maxy, maxx; getmaxyx(stdscr, maxy, maxx);
    int ci = dropdown_color(4, maxx/2, cur, "Background color");
    snprintf(r->bg, MAX_COLOR, "%s", COLOR_TABLE[ci].name);
    if (!strcmp(r->bg, "default")) r->bg[0] = '\0';
}

static void action_add(void)
{
    if (nrules >= MAX_RULES) return;

    int maxy, maxx; getmaxyx(stdscr, maxy, maxx);
    WINDOW *w = newwin(9, 50, maxy/2 - 4, maxx/2 - 25);
    box(w, 0, 0);
    mvwprintw(w, 1, 2, "Nouvelle règle");
    mvwprintw(w, 2, 2, "Extension  : .ext, noext, dir, exec, link");
    mvwprintw(w, 4, 2, "> ");
    echo(); curs_set(1);

    char input[MAX_EXT] = {0};
    wgetnstr(w, input, MAX_EXT - 1);
    noecho(); curs_set(0);
    delwin(w);
    touchwin(stdscr);

    /* trim */
    char *p = input;
    while (*p == ' ' || *p == '\t') p++;
    char *e = p + strlen(p) - 1;
    while (e > p && (*e == ' ' || *e == '\t')) *e-- = '\0';

    if (!*p) return;

    Rule *r = &rules[nrules];
    memset(r, 0, sizeof(*r));
    snprintf(r->ext, MAX_EXT, "%s", p);
    sel = nrules++;
}

static void action_del(void)
{
    if (nrules == 0) return;
    memmove(&rules[sel], &rules[sel+1],
            sizeof(Rule) * (size_t)(nrules - sel - 1));
    nrules--;
    if (sel >= nrules && sel > 0) sel--;
}

static void action_toggle(char flag)
{
    if (nrules == 0) return;
    Rule *r = &rules[sel];
    if (flag == 'b') r->bold      ^= 1;
    if (flag == 'i') r->italic    ^= 1;
    if (flag == 'u') r->underline ^= 1;
    if (flag == 'o') r->outline   ^= 1;
}

/* ─────────────────────────────────────────────
 * Main loop
 * ───────────────────────────────────────────── */

int main(void)
{
    const char *home = getenv("HOME");
    snprintf(config_path, sizeof(config_path),
             "%s/.colorrc", home ? home : ".");
    load_file();

    initscr();
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE);
    /* Activer les couleurs si dispo */
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_color_pairs();
    }

    int running = 1;
    char status_msg[128] = "";

    while (running) {
        int maxy, maxx;
        getmaxyx(stdscr, maxy, maxx);
        clear();

        /* ── titre ── */
        attron(A_BOLD | A_REVERSE);
        mvprintw(0, 0, "%-*s", maxx, "  lsc-config");
        attroff(A_BOLD | A_REVERSE);
        mvprintw(1, 2, "%s", config_path);

        /* ── aide ── */
        int help_y = maxy - 2;
        attron(A_DIM);
        mvprintw(help_y, 0,
            " ↑↓:nav  f:fg  g:bg  b:bold  i:italic  u:underline  o:outline"
            "  a:add  d:del  s:save  q:quit");
        attroff(A_DIM);

        /* ── status ── */
        if (*status_msg) {
            attron(A_BOLD);
            mvprintw(maxy - 1, 0, " %s", status_msg);
            attroff(A_BOLD);
        }

        /* ── liste ── */
        int list_y = 3;
        int list_h = help_y - list_y - 3;
        draw_list(list_y, 2, list_h);

        /* ── preview ── */
        if (nrules > 0) {
            draw_preview(help_y - 2, 2, &rules[sel]);
        }

        refresh();

        int ch = getch();
        status_msg[0] = '\0';

        switch (ch) {
            case KEY_UP:   if (sel > 0) sel--;         break;
            case KEY_DOWN: if (sel < nrules-1) sel++;  break;
            case '\n':
            case '\r':
            case KEY_ENTER: action_fg(); break;
            case 'f': action_fg();    break;
            case 'g': action_bg();    break;
            case 'b': action_toggle('b'); break;
            case 'i': action_toggle('i'); break;
            case 'u': action_toggle('u'); break;
            case 'o': action_toggle('o'); break;
            case 'a': action_add();   break;
            case 'd': action_del();   break;
            case 's':
                save_file();
                snprintf(status_msg, sizeof(status_msg),
                         "Sauvegardé → %s", config_path);
                break;
            case 'q':
            case 'Q':
                running = 0;
                break;
        }
    }

    endwin();
    return 0;
}