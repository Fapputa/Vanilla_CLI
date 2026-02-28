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

    if (!E.title_win)  E.title_win  = newwin(title_h,  cols, 0,               0);
    else { mvwin(E.title_win,  0, 0); wresize(E.title_win,  title_h,  cols); }

    if (E.out_visible) {
        if (!E.out_win) E.out_win = newwin(out_h, cols, title_h + edit_h, 0);
        else { mvwin(E.out_win, title_h + edit_h, 0); wresize(E.out_win, out_h, cols); }
    }

    if (!E.status_win) E.status_win = newwin(status_h, cols, rows - 1, 0);
    else { mvwin(E.status_win, rows - 1, 0); wresize(E.status_win, status_h, cols); }

    int npanes = E.npanes < 1 ? 1 : E.npanes;
    int pane_w = (cols - (npanes - 1)) / npanes;

    for (int i = 0; i < E.npanes; i++) {
        Pane *p = E.panes[i];
        int px = i * (pane_w + 1);
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
    if (E.show_shortcuts) {
        /* Show full shortcut bar */
        wprintw(E.title_win,
            " ^O:Save  ^K:DelLine  ^T:KillLine  ^B:Run  ^F:Find"
            "  ^Z:Undo  ^R:LineNums  ^W:Wipe  ^A:Help  ^Q:Quit");
    } else {
        /* Clean title: editor name + active file */
        Pane *ap = E.panes[E.active];
        if (ap->filename[0])
            wprintw(E.title_win, " Abyss  |  %s%s  |  ^A for shortcuts",
                    ap->filename, ap->modified ? " *" : "");
        else
            wprintw(E.title_win, " Abyss  |  [No File]  |  ^A for shortcuts");
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
    size_t line, col;
    pane_cursor_line_col(ap, &line, &col);
    static const char *lang_names[] = {
        "C","C++","Python","Shell","JS","JSON","SQL","ASM","HTML","CSS","PHP","C#","Plain"
    };
    const char *lname = lang_names[ap->lang < LANG_NONE ? ap->lang : LANG_NONE];
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
    int pane_w  = (cols - (E.npanes - 1)) / E.npanes;
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
    for (int i = 0; i < E.npanes; i++)
        pane_render(E.panes[i], force);
    render_pane_borders();
    render_title();
    render_status();
    render_output();
    if (E.mode != MODE_NORMAL) {
        const char *titles[] = {"","Save As","Search","Open File","Go to Line"};
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
    for (int i = 0; i < E.npanes; i++) {
        Pane *p = E.panes[i];
        syn_mark_dirty_from(p->syn, 0);
    }
}

static void dialog_confirm(void) {
    Pane *ap = E.panes[E.active];
    switch (E.mode) {
        case MODE_SAVE_DIALOG:
            pane_save_file(ap, E.dialog_buf);
            force_full_dirty();
            break;
        case MODE_OPEN_DIALOG:
            gb_free(ap->buf);   ap->buf = gb_new(GAP_DEFAULT);
            li_free(ap->li);    ap->li  = li_new();
            syn_free(ap->syn);  ap->syn = syn_new(LANG_C);
            ap->cursor = 0;
            pane_open_file(ap, E.dialog_buf);
            layout_windows();
            force_full_dirty();
            break;
        case MODE_SEARCH_DIALOG:
            if (strcmp(E.dialog_buf, ap->search.query) != 0) {
                /* New query: find all matches and jump to first */
                strncpy(ap->search.query,     E.dialog_buf, sizeof(ap->search.query)-1);
                strncpy(ap->syn->search_word, E.dialog_buf, sizeof(ap->syn->search_word)-1);
                search_find(&ap->search, ap->buf);
                syn_mark_dirty_from(ap->syn, 0);
                if (ap->search.count > 0) {
                    ap->search.current = 0;
                    ap->cursor = ap->search.matches[0];
                    li_rebuild(ap->li, ap->buf);
                    pane_move_cursor(ap, 0, 0);
                }
            } else {
                /* Same query: cycle to next match */
                pane_search_next(ap);
            }
            /* Stay in SEARCH_DIALOG — only Esc closes it */
            return;
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
    if (prefill) strncpy(E.dialog_buf, prefill, sizeof(E.dialog_buf)-1);
    else E.dialog_buf[0] = '\0';
    E.dialog_cursor = strlen(E.dialog_buf);
}

/* ─── Key handling ────────────────────────────────────────────── */

static void handle_key_normal(int key) {
    Pane *ap = E.panes[E.active];

    switch (key) {
        case KEY_UP:    pane_move_cursor(ap, -1, 0); break;
        case KEY_DOWN:  pane_move_cursor(ap,  1, 0); break;
        case KEY_LEFT:  pane_move_cursor(ap,  0,-1); break;
        case KEY_RIGHT: pane_move_cursor(ap,  0, 1); break;
        case KEY_PPAGE: pane_move_cursor(ap, -(ap->win_h/2), 0); break;
        case KEY_NPAGE: pane_move_cursor(ap,  (ap->win_h/2), 0); break;
        case KEY_HOME: {
            size_t ls = li_line_start(ap->li, ap->cursor_line);
            ap->cursor = ls; pane_move_cursor(ap, 0, 0); break;
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

        /* ── Ctrl shortcuts ──────────────────────────────────── */
        case 'o'&0x1f:  /* ^O  Save As */
            open_dialog(MODE_SAVE_DIALOG, ap->filename[0] ? ap->filename : NULL);
            break;
        case 's'&0x1f:  /* ^S  Save in-place */
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
            open_dialog(MODE_SEARCH_DIALOG, ap->search.query[0] ? ap->search.query : NULL);
            break;
        case 'n'&0x1f: pane_search_next(ap); break;
        case 'p'&0x1f: pane_search_prev(ap); break;
        case 'b'&0x1f: /* ^B  Build & Run */
            if (ap->filename[0]) {
                pane_save_file(ap, NULL);
                E.out_visible = true;
                layout_windows();
                free(E.out_text); E.out_text = malloc(1<<16); E.out_text[0]='\0';
                run_file(ap->filename, ap->lang, E.out_text, 1<<16);
            }
            break;
        case 'r'&0x1f: /* ^R  Toggle line numbers */
            ap->show_line_numbers = !ap->show_line_numbers;
            pane_set_window(ap, ap->win, ap->win_y, ap->win_x, ap->win_h, ap->win_w);
            pane_scroll_to_cursor(ap);
            break;
        case 'w'&0x1f: /* ^W  Wipe file */
            if (ap->filename[0]) pane_wipe_file(ap);
            break;
        case 'l'&0x1f: /* ^L  Split */
            editor_split(); layout_windows(); break;
        case 'e'&0x1f: /* ^E  Cycle pane focus */
            editor_focus_next(); break;
        case 'g'&0x1f: /* ^G  Go to line */
            open_dialog(MODE_GOTO_LINE, NULL); break;
        case 'a'&0x1f: /* ^A  Toggle shortcuts */
            E.show_shortcuts = !E.show_shortcuts;
            break;
        case 'q'&0x1f: /* ^Q  Quit */
            E.running = false; break;

        /* Selection */
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

        case 27: /* ESC: clear search/selection */
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
        case 27: {
            /* When closing search dialog, erase highlights */
            if (E.mode == MODE_SEARCH_DIALOG) {
                Pane *ap = E.panes[E.active];
                search_clear(&ap->search);
                ap->search.query[0] = '\0';
                ap->syn->search_word[0] = '\0';
                syn_mark_dirty_from(ap->syn, 0);
            }
            E.mode = MODE_NORMAL;
            break;
        }
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
}

void editor_split(void) {
    if (E.npanes >= MAX_PANES) return;
    Pane *np = pane_new();
    Pane *ap = E.panes[E.active];
    if (ap->filename[0]) {
        pane_open_file(np, ap->filename);
        np->cursor = ap->cursor;
        np->cursor_line = ap->cursor_line;
        np->cursor_col  = ap->cursor_col;
        np->scroll_line = ap->scroll_line;
    }
    E.panes[E.npanes++] = np;
    E.active = E.npanes - 1;
}

void editor_close_split(void) {
    if (E.npanes <= 1) return;
    if (E.panes[E.active]->win) { delwin(E.panes[E.active]->win); E.panes[E.active]->win=NULL; }
    pane_free(E.panes[E.active]);
    for (int i = E.active; i < E.npanes-1; i++) E.panes[i] = E.panes[i+1];
    E.npanes--;
    if (E.active >= E.npanes) E.active = E.npanes-1;
}

void editor_focus_next(void) {
    E.active = (E.active + 1) % E.npanes;
}

void editor_resize_panes(void) { layout_windows(); }

void editor_cleanup(void) {
    for (int i = 0; i < E.npanes; i++) {
        if (E.panes[i]->win) delwin(E.panes[i]->win);
        pane_free(E.panes[i]);
    }
    if (E.title_win)  delwin(E.title_win);
    if (E.status_win) delwin(E.status_win);
    if (E.out_win)    delwin(E.out_win);
    free(E.out_text);
    pthread_mutex_destroy(&E.save_mutex);
    unlink("./temp_bin");
}

/* ─── Main loop ──────────────────────────────────────────────── */

void editor_run(const char *initial_file) {
    setlocale(LC_ALL, "");
    initscr();
    raw();
    noecho();
    keypad(stdscr, TRUE);
    set_escdelay(25);
    curs_set(0);
    colors_init();

    /* Enable bracketed paste: terminal wraps pasted text with ESC[200~ ... ESC[201~ */
    printf("\033[?2004h"); fflush(stdout);

    layout_windows();

    if (initial_file) {
        pane_open_file(E.panes[0], initial_file);
        layout_windows();
    }

    /* Force complete first draw immediately — no wait for keypress */
    full_redraw(true);

    /* Disable XON/XOFF *after* all ncurses init so ncurses doesn't restore
       the flag via reset_prog_mode(). Re-save with def_prog_mode() so future
       ncurses internal tcsetattr calls also keep IXON disabled. */
    {
        struct termios t;
        tcgetattr(STDIN_FILENO, &t);
        t.c_iflag &= ~(IXON | IXOFF);
        tcsetattr(STDIN_FILENO, TCSANOW, &t);
        def_prog_mode(); /* tell ncurses: this is now the "normal" program state */
    }

    /* Bracketed paste state */
    bool in_paste = false;
    char paste_batch[1 << 18]; /* 256 KB */
    int  paste_len = 0;

    while (E.running) {
        /* Use active pane window for input so wgetch doesn't trigger
           wrefresh(stdscr) which blanks subwindow areas in the virtual screen */
        WINDOW *input_win = E.panes[E.active]->win;
        int key = wgetch(input_win ? input_win : stdscr);

        if (key == KEY_RESIZE) {
            endwin(); refresh();
            layout_windows();
            full_redraw(true);
            continue;
        }

        /* ── Bracketed paste detection ──────────────────────────
           ESC [ 2 0 0 ~  → start collecting
           ESC [ 2 0 1 ~  → flush collected text as one insert    */
        if (key == 27) {
            /* Peek at next chars with short timeout */
            wtimeout(input_win ? input_win : stdscr, 5);
            int c1 = wgetch(input_win ? input_win : stdscr);
            if (c1 == '[') {
                int c2 = wgetch(input_win ? input_win : stdscr);
                int c3 = wgetch(input_win ? input_win : stdscr);
                int c4 = wgetch(input_win ? input_win : stdscr);
                int c5 = wgetch(input_win ? input_win : stdscr);
                int c6 = wgetch(input_win ? input_win : stdscr);
                wtimeout(input_win ? input_win : stdscr, -1);
                if (c2=='2' && c3=='0' && c4=='0' && c5=='~') {
                    /* ESC[200~ — start of bracketed paste */
                    in_paste = true;
                    paste_len = 0;
                    if (c6 != ERR) { /* first pasted char came in same seq */
                        if (paste_len < (int)sizeof(paste_batch)-1)
                            paste_batch[paste_len++] = (char)c6;
                    }
                    continue;
                } else if (c2=='2' && c3=='0' && c4=='1' && c5=='~') {
                    /* ESC[201~ — end of bracketed paste */
                    if (in_paste && paste_len > 0 && E.mode == MODE_NORMAL) {
                        paste_batch[paste_len] = '\0';
                        pane_insert_str(E.panes[E.active], paste_batch, paste_len);
                    }
                    in_paste = false; paste_len = 0;
                    if (c6 != ERR) ungetch(c6);
                    full_redraw(true);
                    continue;
                } else {
                    /* Not a bracketed paste sequence — restore chars */
                    if (c6 != ERR) ungetch(c6);
                    if (c5 != ERR) ungetch(c5);
                    if (c4 != ERR) ungetch(c4);
                    if (c3 != ERR) ungetch(c3);
                    if (c2 != ERR) ungetch(c2);
                    /* Fall through to normal ESC handling */
                }
            } else {
                wtimeout(input_win ? input_win : stdscr, -1);
                if (c1 != ERR) ungetch(c1);
                /* Fall through to normal ESC handling */
            }
        }

        /* Accumulate chars if we are inside a bracketed paste */
        if (in_paste) {
            if (key != ERR && paste_len < (int)sizeof(paste_batch)-1)
                paste_batch[paste_len++] = (char)key;
            continue;
        }

        /* ── Fast-paste batching for terminals without bracketed paste ──
           If a printable char arrives and more are immediately available,
           collect them all in one shot → single pane_insert_str call.    */
        if (E.mode == MODE_NORMAL && key >= 32 && key < 256 && key != 27) {
            char batch[1 << 18];
            int blen = 0;
            batch[blen++] = (char)key;
            wtimeout(input_win ? input_win : stdscr, 0); /* non-blocking */
            int ch2;
            while (blen < (int)sizeof(batch)-1 &&
                   (ch2 = wgetch(input_win ? input_win : stdscr)) != ERR &&
                   ch2 >= 32 && ch2 < 256 && ch2 != 27) {
                batch[blen++] = (char)ch2;
            }
            wtimeout(input_win ? input_win : stdscr, -1); /* back to blocking */
            /* Put back the char that broke the batch (if not ERR) */
            if (ch2 != ERR && (ch2 < 32 || ch2 >= 256 || ch2 == 27))
                ungetch(ch2);

            if (blen > 1) {
                /* Batch of printable chars — insert as string (one undo, one rebuild) */
                pane_insert_str(E.panes[E.active], batch, blen);
                full_redraw(false);
                continue;
            }
            /* Single char — fall through to normal handling */
        }

        EditorMode prev_mode = E.mode;

        if (E.mode == MODE_NORMAL) handle_key_normal(key);
        else handle_key_dialog(key);

        /* When a dialog just closed, force full redraw to erase dialog remnants */
        bool force = (prev_mode != MODE_NORMAL && E.mode == MODE_NORMAL);
        if (force) {
            for (int i = 0; i < E.npanes; i++) {
                Pane *p = E.panes[i];
            }
        }
        full_redraw(force);
    }

    /* Disable bracketed paste before leaving */
    printf("\033[?2004l"); fflush(stdout);
    endwin();
}

int main(int argc, char *argv[]) {
    editor_init();
    editor_run(argc > 1 ? argv[1] : NULL);
    editor_cleanup();
    return 0;
}