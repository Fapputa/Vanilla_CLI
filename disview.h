/* F9 — static analysis view (read-only), drawn in a pane.
 *
 * Opens on the file behind the current buffer when it is an ELF64
 * x86-64 binary: loader (elfload.c) + analysis (disasm.c), then an
 * information screen (type, architecture, entry point, protections,
 * segments, sections, functions found, loader warnings), with Tab the
 * function list (sort, name filter, jump to an address), and with Enter
 * on a function its disassembly (linear sweep of its bytes; Esc goes
 * back to the list; Left / Right shift its lines after their margin when
 * the window is too narrow, Home back to column 0).
 *
 * d (from any screen, and back): the data sections (allocated, not
 * executable: .rodata, .data, .bss, .got, .init_array...; without a
 * section table the non-executable mappings), and with Enter the
 * contents of one, row by row: addresses (8-aligned words pointing into
 * the file, GOT slots of the imports) with what they point to, strings,
 * runs of zero bytes, hex. Tab cycles info -> functions -> disassembly
 * -> data sections -> contents.
 *
 * Links: Enter or a click on an address (a "→" row of the contents, the
 * branch / rip-relative target of a disassembly line) shows it: code in
 * the disassembly of its function, on its line; data on its row in the
 * contents of its section. ':' goes to a typed address the same way,
 * Backspace back to the place left (64 places kept).
 *
 * Debugger (Linux: ELF64 and ELF32, dbg.c; Windows: PE32+, dbg_win.c), on
 * the disassembly screen: b sets or removes a breakpoint on the line (• in
 * the margin, ○ disabled, ◆ debug register), e turns it on / off, h makes it a
 * hardware one, B types one (name, address, module+offset, condition), L
 * lists them in the panel, n goes to the next one, F5 runs the file
 * (launched by dbg_launch, stopped at the first breakpoint) or continues,
 * F6 steps one instruction, F7 steps over (a call or rep instruction: runs
 * to the next line; anything else: one step). While the process is
 * stopped its rip line is highlighted (▶) and a right column shows its
 * registers; each stop jumps to the function and the line of rip. One
 * debuggee and one set of breakpoints, for one file at a time.
 *
 * Without the debugger the analysed file is only read: never executed,
 * emulated or written.
 *
 * Without capstone (HAVE_CAPSTONE undefined) disview.c, disasm.c and
 * elfload.c are left out of the build and the inline stubs below take
 * their place: dis_open then fails with a clear message. */
#ifndef DISVIEW_H
#define DISVIEW_H

#include "abyss.h"
#include "dbg.h"

#ifdef HAVE_CAPSTONE

/* Opens the view on `path`, or keeps *v as it is when it already shows
 * that file unchanged (same size and mtime). On failure returns false
 * with a reason in err; a view on another file is then left untouched,
 * a view on the same (changed) file is freed. */
bool dis_open(DisView **v, const char *path, char *err, size_t esz);
void dis_free(DisView *v);
void dis_render(DisView *v, WINDOW *win, int h, int w);
/* false: key not used (Esc: the caller closes the view) */
bool dis_key(DisView *v, int key, int win_h);
void dis_status(const DisView *v, char *out, size_t sz);
/* Mouse event at (y, x) of the pane window (bstate: ncurses BUTTON*):
 * wheel scrolls, a click selects a row and acts as Enter on it.
 * false: not used. */
bool dis_mouse(DisView *v, int y, int x, unsigned long bstate, int win_h);
/* To call from the wgetch loop when it times out (dbg_ui_timeout): collects
 * the stop / exit of a running debuggee (dbg_poll). true: redraw, the
 * views on its file then jump to its rip line. */
bool dis_ui_poll(void);

#else

static inline bool dis_open(DisView **v, const char *path, char *err, size_t esz) {
    (void)v; (void)path;
    if (err && esz) snprintf(err, esz, "analyse statique indisponible (capstone absent)");
    return false;
}
static inline void dis_free(DisView *v) { (void)v; }
static inline void dis_render(DisView *v, WINDOW *win, int h, int w) { (void)v; (void)win; (void)h; (void)w; }
static inline bool dis_key(DisView *v, int key, int win_h) { (void)v; (void)key; (void)win_h; return false; }
static inline void dis_status(const DisView *v, char *out, size_t sz) { (void)v; if (out && sz) out[0] = '\0'; }
static inline bool dis_mouse(DisView *v, int y, int x, unsigned long bstate, int win_h) {
    (void)v; (void)y; (void)x; (void)bstate; (void)win_h; return false;
}
static inline bool dis_ui_poll(void) { return false; }

#endif

#endif
