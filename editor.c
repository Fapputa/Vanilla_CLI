#include "abyss.h"
#include <string.h>
#include <locale.h>

Editor E;

/* ─── Layout ─────────────────────────────────────────────────── */

static void layout_windows(void) {
    int rows, cols;
    getmaxyx(stdscr, rows, cols);

    int title_h  = 1;
    int status_h = 1;
    int out_h    = E.out_visible ? (rows / 3) : 0;
    int edit_h   = rows - title_h - status_h - out_h;
    if (edit_h < 1) edit_h = 1;

    /* ── File tree panel (à droite) ── */
    int tree_w = 0;
    if (E.tree && E.tree->visible) {
        tree_w = E.tree->width;
        if (tree_w < TREE_MIN_W) tree_w = TREE_MIN_W;
        if (tree_w > cols / 2)   tree_w = cols / 2;
        int tree_x = cols - tree_w;
        if (!E.tree->win)
            E.tree->win = newwin(edit_h, tree_w, title_h, tree_x);
        else {
            mvwin(E.tree->win, title_h, tree_x);
            wresize(E.tree->win, edit_h, tree_w);
        }
    }

    int edit_x = 0;
    int edit_cols = cols - tree_w;
    if (edit_cols < 1) edit_cols = 1;

    if (!E.title_win)  E.title_win  = newwin(title_h, cols, 0, 0);
    else { mvwin(E.title_win, 0, 0); wresize(E.title_win, title_h, cols); }

    if (E.out_visible) {
        if (!E.out_win) E.out_win = newwin(out_h, cols, title_h + edit_h, 0);
        else { mvwin(E.out_win, title_h + edit_h, 0); wresize(E.out_win, out_h, cols); }
    }

    if (!E.status_win) E.status_win = newwin(status_h, cols, rows - 1, 0);
    else { mvwin(E.status_win, rows - 1, 0); wresize(E.status_win, status_h, cols); }

    int npanes = E.npanes < 1 ? 1 : E.npanes;
    int pane_w = (edit_cols - (npanes - 1)) / npanes;

    for (int i = 0; i < E.npanes; i++) {
        Pane *p = E.panes[i];
        int px = edit_x + i * (pane_w + 1);
        int pw = (i == E.npanes - 1) ? (cols - px) : pane_w;
        if (pw < 1) pw = 1;
        if (!p->win) p->win = newwin(edit_h, pw, title_h, px);
        else { mvwin(p->win, title_h, px); wresize(p->win, edit_h, pw); }
        pane_set_window(p, p->win, title_h, px, edit_h, pw);
    }
}

/* ─── Title bar ──────────────────────────────────────────────── */

static void render_title(void) {
    wbkgdset(E.title_win, ' ' | COLOR_PAIR(COLOR_PAIR_TITLE));
    wmove(E.title_win, 0, 0);
    wattron(E.title_win, COLOR_PAIR(COLOR_PAIR_TITLE) | A_BOLD);
    Pane *ap = E.panes[E.active];
    if (E.show_shortcuts) {
        if (ap->hex_mode)
            wprintw(E.title_win,
                " [HEX] Tab:Switch  ^J:Jump  ^F:Search  ^N/^P:Next/Prev"
                "  ^S:Save  F2:Exit Hex  ^Q:Quit");
        else
            wprintw(E.title_win,
                " ^O:Save  ^K:DelLine  ^B:Run  ^F:Find  ^Z:Undo"
                "  ^R:LineNums  ^W:Wipe  ^D:Beautify  F1:Tree  F2:Hex  ^A:Help  ^Q:Quit");
    } else {
        bool mod = ap->hex_mode ? (ap->hex && ap->hex->modified) : ap->modified;
        const char *hex_tag  = ap->hex_mode ? "  [HEX]" : "";
        const char *tree_tag = (E.tree && E.tree->visible && E.tree_focus) ? "  [TREE]" : "";
        if (ap->filename[0])
            wprintw(E.title_win, " Abyss  |  %s%s%s%s  |  ^A for shortcuts",
                    ap->filename, mod ? " *" : "", hex_tag, tree_tag);
        else
            wprintw(E.title_win, " Abyss  |  [No File]%s%s  |  ^A for shortcuts",
                    hex_tag, tree_tag);
    }
    wclrtoeol(E.title_win);
    wattroff(E.title_win, COLOR_PAIR(COLOR_PAIR_TITLE) | A_BOLD);
    wnoutrefresh(E.title_win);
}

/* ─── Status bar ─────────────────────────────────────────────── */

static void render_status(void) {
    wmove(E.status_win, 0, 0);
    wattron(E.status_win, COLOR_PAIR(COLOR_PAIR_STATUS));
    Pane *ap = E.panes[E.active];

    if (ap->hex_mode && ap->hex) {
        HexPane *h = ap->hex;
        const char *panel = (h->focus == HEX_FOCUS_HEX) ? "HEX" : "ASCII";
        wprintw(E.status_win,
                " Offset 0x%07zx (%zu)  Row %zu  Col %zu  [%s]  %zu bytes%s ",
                h->cursor, h->cursor,
                h->cursor / 16, h->cursor % 16,
                panel, h->data_len,
                h->modified ? "  [modified]" : "");
    } else {
        size_t line, col;
        pane_cursor_line_col(ap, &line, &col);
        static const char *lang_names[] = {
            "C","C++","Python","Shell","JS","JSON","SQL","ASM",
            "HTML","CSS","PHP","C#","HEX","Plain"
        };
        const char *lname = lang_names[ap->lang <= LANG_NONE ? ap->lang : LANG_NONE];
        size_t nlines = li_line_count(ap->li);
        char search_info[512] = "";
        if (ap->search.query[0])
            snprintf(search_info, sizeof search_info, " | \"%s\" [%d/%zu]",
                     ap->search.query,
                     ap->search.current >= 0 ? ap->search.current+1 : 0,
                     ap->search.count);
        wprintw(E.status_win, " Ln %zu/%zu  Col %zu  [%s]%s%s ",
                line+1, nlines, col+1, lname, search_info,
                ap->show_line_numbers ? "  [LN]" : "");
    }
    wclrtoeol(E.status_win);
    wattroff(E.status_win, COLOR_PAIR(COLOR_PAIR_STATUS));
    wnoutrefresh(E.status_win);
}

/* ─── Pane borders ────────────────────────────────────────────── */

static void render_pane_borders(void) {
    if (E.npanes < 2) return;
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    int title_h = 1, status_h = 1;
    int out_h   = E.out_visible ? (rows / 3) : 0;
    int edit_h  = rows - title_h - status_h - out_h;
    int tree_w  = (E.tree && E.tree->visible) ? E.tree->width : 0;
    int edit_cols = cols - tree_w;
    int pane_w  = (edit_cols - (E.npanes - 1)) / E.npanes;
    for (int i = 0; i < E.npanes - 1; i++) {
        int bx = (i + 1) * (pane_w + 1) - 1;
        int cp = (i == E.active || i+1 == E.active)
                 ? COLOR_PAIR_ACTIVE_BORDER : COLOR_PAIR_INACTIVE_BORDER;
        attron(COLOR_PAIR(cp));
        for (int y = title_h; y < title_h + edit_h; y++) mvaddch(y, bx, ACS_VLINE);
        attroff(COLOR_PAIR(cp));
    }
    (void)cols;
}

/* ─── Output pane ────────────────────────────────────────────── */

static void render_output(void) {
    if (!E.out_visible || !E.out_win || !E.out_text) return;
    int h, w; getmaxyx(E.out_win, h, w);
    werase(E.out_win);
    wattron(E.out_win, COLOR_PAIR(COLOR_PAIR_COMMENT));
    const char *ptr = E.out_text;
    int row = 0; size_t scroll = E.out_scroll;
    while (*ptr && row < h) {
        const char *nl = strchr(ptr, '\n');
        size_t len = nl ? (size_t)(nl - ptr) : strlen(ptr);
        if (scroll > 0) { scroll--; }
        else { mvwaddnstr(E.out_win, row, 0, ptr, (int)min_sz(len,(size_t)w)); row++; }
        ptr = nl ? nl+1 : ptr+len;
        if (!nl) break;
    }
    wattroff(E.out_win, COLOR_PAIR(COLOR_PAIR_COMMENT));
    wnoutrefresh(E.out_win);
}

/* ─── Dialog ──────────────────────────────────────────────────── */

static void render_dialog(const char *title) {
    int rows, cols; getmaxyx(stdscr, rows, cols);
    int dw = 62, dh = 3;
    int dy = rows/2-1, dx = (cols-dw)/2;
    if (dx < 0) dx = 0;
    WINDOW *dw2 = newwin(dh, dw, dy, dx);
    wattron(dw2, COLOR_PAIR(COLOR_PAIR_STATUS) | A_BOLD);
    box(dw2, 0, 0);
    mvwprintw(dw2, 0, 2, " %s ", title);
    wattron(dw2, COLOR_PAIR(COLOR_PAIR_NORMAL));
    mvwprintw(dw2, 1, 1, "%-*s", dw-2, E.dialog_buf);
    int cx = 1 + (int)E.dialog_cursor;
    if (cx < dw-1) {
        wmove(dw2, 1, cx);
        wattron(dw2, A_REVERSE);
        waddch(dw2, E.dialog_buf[E.dialog_cursor] ? E.dialog_buf[E.dialog_cursor] : ' ');
        wattroff(dw2, A_REVERSE);
    }
    wattroff(dw2, A_BOLD | COLOR_PAIR(COLOR_PAIR_STATUS) | COLOR_PAIR(COLOR_PAIR_NORMAL));
    wnoutrefresh(dw2);
    delwin(dw2);
}

/* ─── Full redraw ────────────────────────────────────────────── */

static void full_redraw(bool force) {
    for (int i = 0; i < E.npanes; i++) {
        Pane *p = E.panes[i];
        if (p->hex_mode && p->hex)
            hex_render(p->hex, p->win, p->win_h, p->win_w);
        else
            pane_render(p, force);
    }
    /* File tree */
    if (E.tree && E.tree->visible && E.tree->win) {
        int rows, cols; getmaxyx(stdscr, rows, cols);
        int title_h = 1, status_h = 1;
        int out_h = E.out_visible ? (rows / 3) : 0;
        int edit_h = rows - title_h - status_h - out_h;
        if (edit_h < 1) edit_h = 1;
        ft_render(E.tree, E.tree->win, edit_h, E.tree->width, E.tree_focus);
        (void)cols;
    }
    render_pane_borders();
    render_title();
    render_status();
    render_output();
    if (E.mode != MODE_NORMAL) {
        const char *titles[] = {
            "",
            "Save As",
            "Search",
            "Open File",
            "Go to Line",
            "Jump to Offset  (decimal: 1024  or hex: 0x400)",
            "Search ASCII"
        };
        render_dialog(titles[E.mode]);
    }
    doupdate();
}

/* ─── Dialog input ────────────────────────────────────────────── */

static void dialog_insert(char c) {
    size_t len = strlen(E.dialog_buf);
    if (len >= sizeof(E.dialog_buf)-1) return;
    memmove(E.dialog_buf + E.dialog_cursor+1,
            E.dialog_buf + E.dialog_cursor,
            len - E.dialog_cursor + 1);
    E.dialog_buf[E.dialog_cursor++] = c;
}

static void dialog_backspace(void) {
    if (!E.dialog_cursor) return;
    size_t len = strlen(E.dialog_buf);
    memmove(E.dialog_buf + E.dialog_cursor-1,
            E.dialog_buf + E.dialog_cursor,
            len - E.dialog_cursor + 1);
    E.dialog_cursor--;
}

static void force_full_dirty(void) {
    for (int i = 0; i < E.npanes; i++)
        syn_mark_dirty_from(E.panes[i]->syn, 0);
}

static void dialog_confirm(void) {
    Pane *ap = E.panes[E.active];
    switch (E.mode) {

        /* ── Hex dialogs ─────────────────────────────────────── */
        case MODE_HEX_JUMP: {
            if (ap->hex && E.dialog_buf[0]) {
                char *end;
                long off = strtol(E.dialog_buf, &end, 0);
                if (end != E.dialog_buf && off >= 0
                        && (size_t)off < ap->hex->data_len) {
                    ap->hex->cursor = (size_t)off;
                    ap->hex->nibble = 0;
                    hex_scroll_to_cursor(ap->hex, ap->win_h); /* ← scroll */
                }
            }
            E.mode = MODE_NORMAL;
            full_redraw(true); /* ← redraw */
            return;
        }
        case MODE_HEX_SEARCH: {
            if (!ap->hex) { E.mode = MODE_NORMAL; return; }
            HexPane *h = ap->hex;
            if (strcmp(E.dialog_buf, h->search_query) != 0) {
                /* Nouvelle query → chercher et aller au premier résultat */
                hex_search_ascii(h, E.dialog_buf);
                if (h->search_count > 0) {
                    h->search_current = 0;
                    h->cursor = h->search_results[0];
                    hex_scroll_to_cursor(h, ap->win_h); /* ← scroll */
                }
            } else if (h->search_count > 0) {
                /* Même query → résultat suivant */
                h->search_current = (h->search_current + 1) % h->search_count;
                h->cursor = h->search_results[h->search_current];
                hex_scroll_to_cursor(h, ap->win_h); /* ← scroll */
            }
            /* Rester dans le dialog — Échap pour fermer */
            full_redraw(true); /* ← redraw */
            return;
        }

        /* ── Normal dialogs ──────────────────────────────────── */
        case MODE_SAVE_DIALOG:
            pane_save_file(ap, E.dialog_buf);
            force_full_dirty();
            break;
        case MODE_OPEN_DIALOG:
            gb_free(ap->buf);  ap->buf = gb_new(GAP_DEFAULT);
            li_free(ap->li);   ap->li  = li_new();
            syn_free(ap->syn); ap->syn = syn_new(LANG_C);
            ap->cursor = 0;
            pane_open_file(ap, E.dialog_buf);
            layout_windows();
            force_full_dirty();
            break;
        case MODE_SEARCH_DIALOG:
            if (strcmp(E.dialog_buf, ap->search.query) != 0) {
                snprintf(ap->search.query, sizeof(ap->search.query), "%s", E.dialog_buf);
                snprintf(ap->syn->search_word, sizeof(ap->syn->search_word), "%s", E.dialog_buf);
                search_find(&ap->search, ap->buf);
                syn_mark_dirty_from(ap->syn, 0);
                if (ap->search.count > 0) {
                    ap->search.current = 0;
                    ap->cursor = ap->search.matches[0];
                    li_rebuild(ap->li, ap->buf);
                    pane_move_cursor(ap, 0, 0);
                }
            } else {
                pane_search_next(ap);
            }
            full_redraw(true); /* ← redraw */
            return; /* stay in dialog */
        case MODE_GOTO_LINE: {
            long l = atol(E.dialog_buf);
            if (l > 0) pane_move_to_line_col(ap, (size_t)(l-1), 0);
            break;
        }
        default: break;
    }
    E.mode = MODE_NORMAL;
}

static void open_dialog(EditorMode m, const char *prefill) {
    E.mode = m;
    if (prefill) snprintf(E.dialog_buf, sizeof(E.dialog_buf), "%s", prefill);
    else E.dialog_buf[0] = '\0';
    E.dialog_cursor = strlen(E.dialog_buf);
}

/* ─── Key handling ────────────────────────────────────────────── */

static void handle_key_normal(int key) {
    /* ── F1 : toggle file tree ───────────────────────────────────── */
    if (key == KEY_F(1)) {
        if (E.tree) {
            E.tree->visible = !E.tree->visible;
            if (!E.tree->visible) E.tree_focus = false;
            else                  E.tree_focus = true;
        }
        layout_windows();
        force_full_dirty();
        return;
    }

    /* ── Focus / unfocus le tree avec Tab quand il est visible ─────── */
    /* Tab bascule focus tree ↔ éditeur (seulement si tree visible) */
    if (key == '\t' && E.tree && E.tree->visible) {
        /* En mode hex le Tab est utilisé pour basculer hex↔ascii,
           donc on le laisse passer si hex_mode */
        Pane *ap2 = E.panes[E.active];
        if (!ap2->hex_mode) {
            E.tree_focus = !E.tree_focus;
            return;
        }
    }

    /* ── Routing vers le tree si focus ──────────────────────────── */
    if (E.tree_focus && E.tree && E.tree->visible) {
        char open_path[4096] = "";
        bool consumed = ft_handle_key(E.tree, key, open_path, sizeof open_path);
        if (open_path[0]) {
            /* Ouvrir le fichier dans le pane actif */
            Pane *ap2 = E.panes[E.active];
            gb_free(ap2->buf);  ap2->buf = gb_new(GAP_DEFAULT);
            li_free(ap2->li);   ap2->li  = li_new();
            syn_free(ap2->syn); ap2->syn = syn_new(LANG_C);
            ap2->cursor = 0;
            pane_open_file(ap2, open_path);
            /* Mettre à jour le cwd du tree vers le répertoire du fichier */
            char tmp[4096];
            strncpy(tmp, open_path, sizeof tmp - 1);
            char *slash = strrchr(tmp, '/');
            if (slash && slash != tmp) {
                *slash = '\0';
                char resolved[4096];
                if (realpath(tmp, resolved))
                    strncpy(E.tree->cwd, resolved, sizeof E.tree->cwd - 1);
                ft_reload(E.tree);
            }
            E.tree_focus = false;   /* revenir au focus éditeur */
            layout_windows();
            force_full_dirty();
        } else if (consumed) {
            /* simple navigation dans le tree, juste redraw */
        }
        if (consumed) return;
    }

    Pane *ap = E.panes[E.active];

    /* ── Hex mode ─────────────────────────────────────────────── */
    if (ap->hex_mode && ap->hex) {
        if (key == ('q'&0x1f)) { E.running = false; return; }
        if (key == ('a'&0x1f)) { E.show_shortcuts = !E.show_shortcuts; return; }
        if (key == KEY_F(2))   { ap->hex_mode = false; force_full_dirty(); return; }
        if (key == ('s'&0x1f)) { hex_save(ap->hex, NULL); return; }
        if (key == ('o'&0x1f)) {
            open_dialog(MODE_SAVE_DIALOG,
                        ap->hex->filename[0] ? ap->hex->filename : NULL);
            return;
        }
        if (key == ('j'&0x1f)) {
            open_dialog(MODE_HEX_JUMP, NULL);
            return;
        }
        if (key == ('f'&0x1f)) {
            open_dialog(MODE_HEX_SEARCH,
                        ap->hex->search_query[0] ? ap->hex->search_query : NULL);
            return;
        }
        /* Tout le reste : navigation, Tab, nibbles, ASCII edit */
        hex_handle_key(ap->hex, key, ap->win_h);
        return;
    }

    /* ── Mode texte normal ────────────────────────────────────── */
    switch (key) {
        case KEY_UP:    pane_move_cursor(ap, -1, 0); break;
        case KEY_DOWN:  pane_move_cursor(ap,  1, 0); break;
        case KEY_LEFT:  pane_move_cursor(ap,  0,-1); break;
        case KEY_RIGHT: pane_move_cursor(ap,  0, 1); break;
        case KEY_PPAGE: pane_move_cursor(ap, -(ap->win_h/2), 0); break;
        case KEY_NPAGE: pane_move_cursor(ap,  (ap->win_h/2), 0); break;
        case KEY_HOME: {
            size_t ls = li_line_start(ap->li, ap->cursor_line);
            ap->cursor = ls;
            ap->scroll_col = 0;   /* always reset horizontal scroll */
            pane_move_cursor(ap, 0, 0); break;
        }
        case KEY_END: {
            size_t nl = li_line_count(ap->li);
            size_t le = (ap->cursor_line+1 < nl)
                        ? li_line_start(ap->li, ap->cursor_line+1)-1
                        : gb_len(ap->buf);
            ap->cursor = le; pane_move_cursor(ap, 0, 0); break;
        }
        case KEY_BACKSPACE: case 127: case '\b': pane_delete_char(ap); break;
        case KEY_DC:  pane_delete_forward(ap); break;
        case '\n': case '\r': pane_insert_char(ap, '\n'); break;
        case '\t': pane_insert_str(ap, "    ", 4); break;

        case 'o'&0x1f:
            open_dialog(MODE_SAVE_DIALOG, ap->filename[0] ? ap->filename : NULL);
            break;
        case 's'&0x1f:
            if (ap->filename[0]) pane_save_file(ap, NULL);
            else open_dialog(MODE_SAVE_DIALOG, NULL);
            break;
        case 'z'&0x1f: pane_undo(ap); break;
        case 'y'&0x1f: pane_redo(ap); break;
        case 'c'&0x1f: pane_copy(ap); break;
        case 'x'&0x1f: pane_cut(ap);  break;
        case 'v'&0x1f: pane_paste(ap); break;
        case 'k'&0x1f: pane_kill_whole_line(ap); break;
        case 't'&0x1f: pane_kill_whole_line(ap); break;
        case 'f'&0x1f:
            open_dialog(MODE_SEARCH_DIALOG,
                        ap->search.query[0] ? ap->search.query : NULL);
            break;
        case 'n'&0x1f: pane_search_next(ap); break;
        case 'p'&0x1f: pane_search_prev(ap); break;
        case 'b'&0x1f:
            if (ap->filename[0]) {
                pane_save_file(ap, NULL);
                E.out_visible = true;
                layout_windows();
                free(E.out_text);
                E.out_text = malloc(1<<16); E.out_text[0] = '\0';
                run_file(ap->filename, ap->lang, E.out_text, 1<<16);
            }
            break;
        case 'r'&0x1f:
            ap->show_line_numbers = !ap->show_line_numbers;
            pane_set_window(ap, ap->win, ap->win_y, ap->win_x, ap->win_h, ap->win_w);
            pane_scroll_to_cursor(ap);
            break;
        case 'w'&0x1f:
            pane_wipe_file(ap);
            break;
        case 'l'&0x1f: editor_split(); layout_windows(); break;
        case 'e'&0x1f: editor_focus_next(); break;
        case 'g'&0x1f: open_dialog(MODE_GOTO_LINE, NULL); break;
        case 'a'&0x1f: E.show_shortcuts = !E.show_shortcuts; break;

        /* Ctrl+D : beautify (strip emojis + comments) */
        case 'd'&0x1f:
            pane_beautify(ap);
            force_full_dirty();
            break;

        /* F2 — entrer en hex mode */
        case KEY_F(2):
            if (!ap->hex) ap->hex = hex_new();
            if (ap->filename[0]) hex_load(ap->hex, ap->filename);
            ap->hex_mode = true;
            force_full_dirty();
            break;

        case 'q'&0x1f: E.running = false; break;

        case KEY_SLEFT:
            if (!ap->sel_active) { ap->sel_active=true; ap->sel_anchor=ap->cursor; }
            pane_move_cursor(ap, 0, -1); break;
        case KEY_SRIGHT:
            if (!ap->sel_active) { ap->sel_active=true; ap->sel_anchor=ap->cursor; }
            pane_move_cursor(ap, 0, 1); break;
        case KEY_SR:
            if (!ap->sel_active) { ap->sel_active=true; ap->sel_anchor=ap->cursor; }
            pane_move_cursor(ap, -1, 0); break;
        case KEY_SF:
            if (!ap->sel_active) { ap->sel_active=true; ap->sel_anchor=ap->cursor; }
            pane_move_cursor(ap, 1, 0); break;

        case 27:
            ap->sel_active = false;
            search_clear(&ap->search);
            ap->search.query[0] = '\0';
            ap->syn->search_word[0] = '\0';
            syn_mark_dirty_from(ap->syn, 0);
            break;

        default:
            if (key >= 32 && key < 127)  pane_insert_char(ap, (char)key);
            else if (key >= 128)          pane_insert_char(ap, (char)key);
            break;
    }
}

static void handle_key_dialog(int key) {
    switch (key) {
        case '\n': case '\r': dialog_confirm(); break;
        case 27:
            if (E.mode == MODE_SEARCH_DIALOG) {
                Pane *ap = E.panes[E.active];
                search_clear(&ap->search);
                ap->search.query[0] = '\0';
                ap->syn->search_word[0] = '\0';
                syn_mark_dirty_from(ap->syn, 0);
            }
            E.mode = MODE_NORMAL;
            break;
        case KEY_BACKSPACE: case 127: case '\b': dialog_backspace(); break;
        case KEY_LEFT:  if (E.dialog_cursor > 0) E.dialog_cursor--; break;
        case KEY_RIGHT:
            if (E.dialog_cursor < strlen(E.dialog_buf)) E.dialog_cursor++;
            break;
        default:
            if (key >= 32 && key < 127) dialog_insert((char)key);
            break;
    }
}

/* ─── Editor lifecycle ────────────────────────────────────────── */

void editor_init(void) {
    memset(&E, 0, sizeof E);
    pthread_mutex_init(&E.save_mutex, NULL);
    E.panes[0] = pane_new();
    E.npanes   = 1;
    E.active   = 0;
    E.running  = true;
    E.tree     = ft_new();
    E.tree_focus = false;  /* focus sur l'éditeur par défaut */
}

void editor_split(void) {
    if (E.npanes >= MAX_PANES) return;
    Pane *np = pane_new();
    Pane *ap = E.panes[E.active];
    if (ap->filename[0]) {
        pane_open_file(np, ap->filename);
        np->cursor      = ap->cursor;
        np->cursor_line = ap->cursor_line;
        np->cursor_col  = ap->cursor_col;
        np->scroll_line = ap->scroll_line;
    }
    E.panes[E.npanes++] = np;
    E.active = E.npanes - 1;
}

void editor_close_split(void) {
    if (E.npanes <= 1) return;
    if (E.panes[E.active]->win) {
        delwin(E.panes[E.active]->win);
        E.panes[E.active]->win = NULL;
    }
    pane_free(E.panes[E.active]);
    for (int i = E.active; i < E.npanes-1; i++) E.panes[i] = E.panes[i+1];
    E.npanes--;
    if (E.active >= E.npanes) E.active = E.npanes-1;
}

void editor_focus_next(void) { E.active = (E.active + 1) % E.npanes; }
void editor_resize_panes(void) { layout_windows(); }

void editor_cleanup(void) {
    for (int i = 0; i < E.npanes; i++) {
        if (E.panes[i]->win) delwin(E.panes[i]->win);
        pane_free(E.panes[i]);
    }
    if (E.title_win)  delwin(E.title_win);
    if (E.status_win) delwin(E.status_win);
    if (E.out_win)    delwin(E.out_win);
    if (E.tree) {
        if (E.tree->win) delwin(E.tree->win);
        ft_free(E.tree);
    }
    free(E.out_text);
    pthread_mutex_destroy(&E.save_mutex);
    unlink("./temp_bin");
}

/* ─── Main loop ──────────────────────────────────────────────── */

void editor_run(const char *initial_file) {
    setlocale(LC_ALL, "");
    initscr(); raw(); noecho();
    keypad(stdscr, TRUE);
    set_escdelay(25);
    curs_set(0);
    colors_init();
    use_default_colors();  /* bg=-1 dans init_pair = fond terminal transparent */
    hex_colors_init();

    printf("\033[?2004h"); fflush(stdout);
    layout_windows();

    if (initial_file) {
        pane_open_file(E.panes[0], initial_file);
        layout_windows();
    }
    full_redraw(true);

    {
        struct termios t;
        tcgetattr(STDIN_FILENO, &t);
        t.c_iflag &= ~(IXON | IXOFF);
        tcsetattr(STDIN_FILENO, TCSANOW, &t);
        def_prog_mode();
    }

    bool in_paste  = false;
    char paste_batch[1 << 18];
    int  paste_len = 0;

    while (E.running) {
        WINDOW *iw = E.panes[E.active]->win;
        int key = wgetch(iw ? iw : stdscr);

        if (key == 0 || key == ERR || key == 0x16) continue;

        if (key == KEY_RESIZE) {
            endwin(); refresh();
            layout_windows(); full_redraw(true);
            continue;
        }

        /* Escape sequence dispatcher.
         * Reads up to 8 extra bytes (short timeout) to recognise:
         *   Ctrl+Tab sequences from common terminals:
         *     xterm        ESC [ 2 7 ; 5 ; 9 ~
         *     xterm-alt    ESC [ 1 ; 5 I
         *     kitty        ESC [ 9 ; 5 u
         *     Shift+Tab    ESC [ Z          (fallback, same action)
         *   Bracketed paste markers (handled as before).
         *   Anything else: bytes pushed back unchanged.
         */
        if (key == 27) {
            wtimeout(iw ? iw : stdscr, 5);
            int sq[8]; int sn = 0;
            for (; sn < 8; sn++) {
                sq[sn] = wgetch(iw ? iw : stdscr);
                if (sq[sn] == ERR) { sn--; break; }
            }
            sn++; if (sn < 0) sn = 0;
            wtimeout(iw ? iw : stdscr, -1);

            bool consumed = false;

            if (sn >= 1 && sq[0] == '[') {

                /* ESC [ Z  -- Shift+Tab (many terminals) */
                if (!consumed && sn >= 2 && sq[1] == 'Z') {
                    for (int si = sn-1; si >= 2; si--)
                        if (sq[si]!=ERR) ungetch(sq[si]);
                    key = KEY_BTAB; consumed = true;
                }

                /* ESC [ 2 7 ; 5 ; 9 ~  -- xterm Ctrl+Tab */
                if (!consumed && sn >= 6
                        && sq[1]=='2' && sq[2]=='7'
                        && sq[3]==';' && sq[4]=='5' && sq[5]==';') {
                    int n9  = (sn > 6) ? sq[6] : ERR;
                    int ntl = (sn > 7) ? sq[7] : ERR;
                    if (n9 == '9') {
                        if (ntl != '~' && ntl != ERR) ungetch(ntl);
                        key = KEY_BTAB; consumed = true;
                    }
                }

                /* ESC [ 1 ; 5 I  -- xterm alternate Ctrl+Tab */
                if (!consumed && sn >= 5
                        && sq[1]=='1' && sq[2]==';' && sq[3]=='5' && sq[4]=='I') {
                    for (int si = sn-1; si >= 5; si--)
                        if (sq[si]!=ERR) ungetch(sq[si]);
                    key = KEY_BTAB; consumed = true;
                }

                /* ESC [ 9 ; 5 u  -- kitty Ctrl+Tab */
                if (!consumed && sn >= 5
                        && sq[1]=='9' && sq[2]==';' && sq[3]=='5' && sq[4]=='u') {
                    for (int si = sn-1; si >= 5; si--)
                        if (sq[si]!=ERR) ungetch(sq[si]);
                    key = KEY_BTAB; consumed = true;
                }

                /* ESC [ 2 0 0 ~  -- bracketed paste start */
                if (!consumed && sn >= 5
                        && sq[1]=='2' && sq[2]=='0'
                        && sq[3]=='0' && sq[4]=='~') {
                    in_paste=true; paste_len=0;
                    if (sn > 5 && sq[5]!=ERR
                            && paste_len<(int)sizeof(paste_batch)-1)
                        paste_batch[paste_len++]=(char)sq[5];
                    for (int si = sn-1; si >= 6; si--)
                        if (sq[si]!=ERR) ungetch(sq[si]);
                    consumed = true;
                    continue;
                }

                /* ESC [ 2 0 1 ~  -- bracketed paste end */
                if (!consumed && sn >= 5
                        && sq[1]=='2' && sq[2]=='0'
                        && sq[3]=='1' && sq[4]=='~') {
                    if (in_paste && paste_len>0 && E.mode==MODE_NORMAL) {
                        paste_batch[paste_len]='\0';
                        Pane *ap2=E.panes[E.active];
                        if (!ap2->hex_mode)
                            pane_insert_str(ap2, paste_batch, paste_len);
                    }
                    in_paste=false; paste_len=0;
                    for (int si = sn-1; si >= 5; si--)
                        if (sq[si]!=ERR) ungetch(sq[si]);
                    consumed = true;
                    full_redraw(true); continue;
                }

                /* Unknown ESC [ sequence -- push everything back */
                if (!consumed) {
                    for (int si = sn-1; si >= 0; si--)
                        if (sq[si]!=ERR) ungetch(sq[si]);
                }
            } else {
                /* Not ESC [ -- push back */
                for (int si = sn-1; si >= 0; si--)
                    if (sq[si]!=ERR) ungetch(sq[si]);
            }
            (void)consumed;
        }

        if (in_paste) {
            if (key!=ERR && paste_len<(int)sizeof(paste_batch)-1)
                paste_batch[paste_len++]=(char)key;
            continue;
        }

        /* Fast-paste batching — skip in hex mode and dialog */
        Pane *ap = E.panes[E.active];
        (void)ap;
        EditorMode prev_mode = E.mode;
        if (E.mode == MODE_NORMAL) handle_key_normal(key);
        else                       handle_key_dialog(key);

        bool force = (prev_mode != MODE_NORMAL && E.mode == MODE_NORMAL);
        full_redraw(force);
    }

    printf("\033[?2004l"); fflush(stdout);
    endwin();
}

int main(int argc, char *argv[]) {
    editor_init();
    editor_run(argc > 1 ? argv[1] : NULL);
    editor_cleanup();
    return 0;
}