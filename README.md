# Vanilla_CLI Suite

A high-performance, versatile toolkit designed to supercharge the Linux terminal experience. From low-level system monitoring to a high-speed C-engineered text editor, this suite brings efficiency and fun to the command line.

![Demo](.rem.gif)

---

## Repository Layout

```
Vanilla_CLI/
├── Makefile
├── install.sh
├── *.c / *.h              -- Abyss, lsc, lsc-config source files
├── cmd/
│   ├── wipe               -- Clear a file's contents
│   ├── clip               -- Copy a file to the clipboard
│   ├── compil             -- Smart compiler/runner
│   ├── redem              -- WiFi driver reset
│   └── tree               -- Directory tree view
├── bin/
│   ├── blackjack          -- Blackjack game
│   └── minesweeper        -- Minesweeper game
└── scripts/
    ├── monitoring.py      -- System dashboard
    └── wifi_monitoring.py -- Network monitor
```

---

## Getting Started

**1. Clone the repository:**

```bash
git clone https://github.com/Fapputa/Vanilla_CLI.git
cd Vanilla_CLI
```

**2. Run the installer as root:**

```bash
sudo ./install.sh
```

The installer will automatically:
- Detect your package manager (`apt` or `pacman`) and install system dependencies
- Install Python dependencies (`rich`, `prompt_toolkit`, `pygments`, `psutil`)
- Build `abyss`, `lsc`, and `lsc-config` with `make clean && make`
- Deploy all commands to both `~/bin` and `/usr/local/bin`
- Remove compiled binaries and object files from the project root once installed

---

## Abyss - Text Editor

Engineered for zero-latency, Abyss is written in C and uses a **Gap Buffer** and **Line Indexing** to handle massive files without breaking a sweat.

- **Performance:** O(1) insertions and deletions
- **Architecture:** Low-level memory management with `ncurses` for a flicker-free UI
- **Features:** Undo/Redo, syntax highlighting, integrated compilation, hex view

### Compiling and running

`Ctrl + B` saves the buffer and builds it, with the output shown in a pane at
the bottom. Commands run from the folder of the file.

| Language | Toolchain (selectable in the `F5` menu) |
|----------|-----------|
| C | `gcc`, `clang`, `tcc`, `zig cc` |
| C++ | `g++`, `clang++`, `zig c++` |
| Rust | `rustc`, or `cargo run` when the file belongs to a crate (a `Cargo.toml` found up the tree) |
| Assembly | `nasm` or `yasm` + `ld` |
| C# | `mcs` (+ `mono`) or `csc` |

When it finishes, the compile and run times are shown in the status bar and at
the end of the output pane (`-- compile 412 ms | run 1.27 s --`). A failed
compilation reports only its compile time; a nonzero exit code is appended.

Pressing `Ctrl + B` twice quickly (within 350 ms) — or `F5` — opens a dropdown
at the bottom. `Space` toggles an entry, `Enter` builds and runs with the
selection, `Esc` closes. Bracketed entries `[x]` are independent; `(*)` entries
belong to a group where only one can be active at a time (you cannot ask for
`-O2` and `-O3` at once). The line above the border previews the exact command
`^B` will run. For compiled languages the menu holds:

- **Compiler** — gcc / clang / tcc / zig (C), g++ / clang++ / zig (C++),
  nasm / yasm, mcs / csc. Compilers that are not installed are dimmed and
  marked `(not installed)`.
- **Output** — `run only` (temporary binary, deleted after the run),
  `executable` (keeps `<name>` / `<name>.exe` next to the source and runs it),
  `shared lib` (`lib<name>.so` / `<name>.dll`), `static lib` (`lib<name>.a`),
  `object files` (`.o`, no link). Rust offers `cdylib` / `staticlib`, C# a `.dll`.
- **All sources of the folder** — compiles every `.c` (or `.cpp`/`.cc`/`.cxx`,
  `.cs`) of the folder into **one** output: one executable built from the
  whole project. Combine with `static link` for a standalone binary that needs
  no `.so` / `.dll` beside it.
- **Flags** — optimisation level, SIMD/vector ISA (`-march=native`,
  `-mavx2 -mfma`, `-msse4.2`, or `-C target-cpu=native` for Rust), LTO, fast
  math, strip, sanitizers, OpenMP, and so on.

#### Web files and Python

`Ctrl + B` on web files starts a server in the background (its log goes to a
temporary file), then opens the page in the browser:

| File | Choices in the `F5` menu (default first) |
|------|---------|
| `.html`, `.css` | `python -m http.server`, `php -S`, open the file directly (`file://`) |
| `.php` | `php -S` (built-in server, docroot = the folder), `php` CLI |
| `.py` | auto (a Flask app gets `flask run`, anything else is run as a script), script, Flask, `http.server` |
| `.js` | `node` script, `http.server` |

The port is `auto` (Flask 5000, php 8080, others 8000) or 8000 / 8080 / 5000 /
3000; opening the browser can be turned off. `^B` again restarts the server,
`k` in the `F5` menu stops it, and it is stopped when Abyss quits. The title
bar shows `[SERVER <url>]` while it runs.

### Manual Build

```bash
make clean && make
```

### Manual Installation

```bash
sudo cp abyss /usr/local/bin/
# also copy to user-local bin
cp abyss ~/bin/
```

### Usage

```bash
abyss main.c
```

### Keybindings

| Key | Action |
|-----|--------|
| `Ctrl + S` | Save file |
| `Ctrl + Q` | Exit |
| `Ctrl + Z` | Undo |
| `Ctrl + Y` | Redo |
| `Ctrl + B` | Compile and run the current file |
| `Ctrl + B` `Ctrl + B` (or `F5`) | Build-flags menu for compiled languages |
| `Ctrl + N` | Split screen view |
| `Ctrl + K` | Delete current line |
| `Ctrl + D` | Beautify / auto-format |
| `F1` | File tree navigator |
| `F2` | Hex view |
| `F3` | File inspector |
| `F4` | Smart highlight panel |
| `F6` | Table view (CSV, JSON, SQL, SQLite...) |
| `F7` | Markdown: rendered view / text |
| `F8` | Memory editor: pick a process, scan and edit its memory |

### Table view

`F6` shows the current buffer as a grid, and `F6` again goes back to the
text. Data-only files open in the table directly: `.csv`, `.tsv`, `.psv`,
`.jsonl` / `.ndjson`, and SQLite databases (`.db`, `.sqlite`, or any file
starting with the SQLite header).

| Source | What becomes a table |
|--------|----------------------|
| CSV / TSV / PSV | Separator detected (`,` `;` tab `\|`), quoted fields, first line as header |
| JSON | Arrays of objects (columns = union of keys), arrays of arrays, objects of objects; each array in an object gets its own table, leftover fields a `key \| value` table |
| JSON Lines | One row per line |
| SQL dump | `CREATE TABLE` column lists, `INSERT ... VALUES`, pg_dump `COPY ... FROM stdin` |
| Markdown / psql | Pipe tables (`\| a \| b \|`, `a \| b` over `---+---`) |
| SQLite | Every table and view, through the `sqlite3` CLI (read-only) |

Files with another extension are sniffed. The view reads the buffer as it is,
unsaved edits included.

**Editing.** `Enter` (or `e`) on a cell opens an edit box. The new value is
written back at the exact place the cell came from in the source, encoded for
its format (CSV quoting, JSON string or literal, SQL literal, `COPY` escapes,
escaped `|` in Markdown), so the rest of the file is untouched. The edit goes
into the buffer: `^S` saves it, `^Z` / `^Y` undo / redo. SQLite tables are
updated directly with `UPDATE ... WHERE rowid = ...`; views and
`WITHOUT ROWID` tables are read-only. Cells that do not exist in the source
(a key missing from one JSON object, for instance) cannot be edited.

**Sorting.** `s` sorts the grid on the current column (ascending, then
descending, then back to the file order), `S` clears it. Number columns sort
numerically, text sorts in natural order (`file2` before `file10`), empty cells
go last. Sorting only changes the display: the file keeps its order and the
gutter keeps showing each row's original number.

**Column bar.** The bottom line of the grid always names the current column
(whatever the horizontal scroll), its type, its sort, whether it is editable,
and shows the full value of the current cell.

| Key | Action |
|-----|--------|
| Arrows / `hjkl` | Move between cells |
| `PgUp` / `PgDn`, `g` / `G` | Page, first / last row |
| `Home` / `End` | First / last column |
| `Tab` / `Shift+Tab` | Next / previous table |
| `Enter` / `e` | Edit the cell (`^U` clears the field) |
| `s` / `S` | Sort on the column (asc / desc / off) / unsort |
| `v` | Show the full cell in the status bar |
| `^Z` / `^Y`, `^S` | Undo / redo an edit, save |
| `Ctrl + F`, `Ctrl + N` / `Ctrl + P` | Search cells, next / previous match |
| `F2` | Hex view |

### Image view

Pictures open in the pane with **nothing to install**: Abyss has its own
decoders for PNG (every color type and depth, transparency, interlacing),
JPEG (baseline and progressive, phone photos turned the right way up from
their EXIF orientation), GIF, BMP, ICO, PNM, TGA and QOI. The picture is
scaled to the pane (two pixels per character cell with `▀` half blocks, 256
colors), centered, and redrawn whenever the window or the split changes size.

`d` turns dithering on / off, `r` reloads the file, `F2` shows the bytes in the
hex view (and `F2` again comes back to the picture). Nothing is ever saved over
the image. WebP, SVG, HEIC/AVIF and TIFF are shown through
[chafa](https://hpjansson.org/chafa/) if it happens to be installed; it is
never required.

### Document view

Markdown files open **rendered**: headings, bold / italic / `code`, links,
nested and task lists, quotes, code blocks, tables and rules, word-wrapped in a
centered column of at most 100 characters. `F7` switches to the text to edit
it and `F7` again shows the result; `^S` saves from either. Documents that are
not text open in this view too, read-only:

| Format | Read with |
|--------|-----------|
| PDF | `pdftotext` (poppler), else `mutool`, else Python `pypdf` |
| Word `.docx`, OpenDocument `.odt` | the XML read out of the archive (`unzip`, `tar`/bsdtar or Python), headings, lists, bold / italic and tables kept |
| Word 97 `.doc` | `antiword` or `catdoc` |
| `.rtf`, `.epub` | `pandoc` |

Arrows / `j` `k` scroll, `PgUp` / `PgDn` / `Space` page, `g` / `G` jump to the
top / end, `^F` searches (matches highlighted, `^N` / `^P` next / previous).

Optional tools used by these views: `poppler` (`pdftotext`) for PDFs,
`sqlite3` for databases, `pandoc` for RTF / EPUB.

### Memory editor

`F8` opens a scanner in the style of Cheat Engine, for your own programs and
offline games.

**1. Pick a process.** The list shows the running processes, newest first,
with their memory use. Type to filter by name or PID, `Enter` to analyse it.
`^O` launches a program from here, `^R` refreshes the list.

Linux only lets a program read another one's memory if it is root, or if the
other program is its child (with the usual `kernel.yama.ptrace_scope = 1`).
So either start the program from the list with `^O` (it becomes a child of
Abyss: no root needed), run Abyss with `sudo`, or allow it for the session
with `sudo sysctl kernel.yama.ptrace_scope=0`. Abyss says which one applies
when access is refused.

**2. Find a value.** `t` picks the type (int8 / 16 / 32 / 64, float, double,
text, UTF-16 text, bytes with `??` wildcards), `m` the kind of scan and `s`
runs it. The first scan reads all the writable memory: exact value, bigger /
smaller than, between `low..high`, or *unknown initial value* (a copy of the
memory). Next scans only re-check the addresses found: exact value, changed,
unchanged, increased, decreased, increased / decreased by N. Change the value
in the program between two scans (lose a life, spend coins...) until a
handful of addresses remain. `n` starts over. Values are re-read live; the
ones that changed since the last scan are highlighted.

**3. Change it.** `Enter` writes a new value into the program's memory. `a`
saves an address in the list below, `f` saves it frozen: its value is written
back ten times a second, even when the view is closed. In the saved list
(`Tab`), `Enter` edits, `f` toggles the freeze, `r` names it, `d` removes it.
`x` shows the bytes around an address (changing bytes in color), `g` jumps to
any address.

---

## lsc - Colorized ls

A drop-in replacement for `ls` with fully customizable per-extension colorization, driven by a simple config file (`~/.colorrc`) and a ncurses TUI editor.

### Features

- Per-extension color rules (`.c`, `.py`, `.md`, ...)
- Special rules for directories (`dir`), executables (`exec`), symlinks (`link`), and files without extension (`noext`)
- Attributes: `bold`, `italic`, `underline`, `outline` (reverse video)
- 16 named colors + full 256-color palette
- Automatic column layout matching your terminal width, with proper UTF-8 display width handling
- Compatible with `ls` flags (`-l`, `-a`, `-h`, ...)

### Manual Build

```bash
gcc -O2 -Wall -Wextra -o lsc lsc.c
gcc -O2 -Wall -Wextra -o lsc-config lsc-config.c -lncurses
```

Or from the root with make:

```bash
make lsc
make lsc-config
```

### Manual Installation

```bash
# User-local
cp lsc        ~/bin/lsc
cp lsc-config ~/bin/lsc-config

# System-wide
sudo cp lsc        /usr/local/bin/lsc
sudo cp lsc-config /usr/local/bin/lsc-config
```

### Usage

```bash
lsc              # current directory
lsc -la          # long format, all files
lsc ~/projects   # specific directory
lsc-config       # open the TUI color rule editor
```

To replace `ls` permanently, add to your `~/.bashrc`:

```bash
alias ls='lsc'
alias lsconfig='lsc-config'
```

### Config file - `~/.colorrc`

```
# format: .ext = FG [BG] [bold] [italic] [underline] [outline]
# special keys: dir  exec  link  noext
# colors: black red green yellow blue magenta cyan white
#         bright_black ... bright_white   (16 named)
#         0-255                           (256-color palette)

dir            = blue bold
exec           = red outline
link           = cyan italic
noext          = white

.c             = red bold
.h             = bright_red bold
.py            = green bold
.sh            = white bold
.md            = white italic
.txt           = white italic
.js            = yellow bold
.json          = yellow
.rs            = 208 bold
.go            = cyan bold
.zip           = 196
.tar           = 196
.gz            = 196
.png           = bright_cyan bold
.jpg           = bright_cyan bold
.mp4           = magenta bold
.pdf           = red italic
```

### lsc-config - TUI Rule Editor

An interactive ncurses editor for `~/.colorrc`.

| Key | Action |
|-----|--------|
| `Up / Down` | Navigate rules |
| `f` | Change foreground color |
| `g` | Change background color |
| `b` | Toggle bold |
| `i` | Toggle italic |
| `u` | Toggle underline |
| `o` | Toggle outline (reverse video) |
| `a` | Add a new rule |
| `d` | Delete selected rule |
| `s` | Save to `~/.colorrc` |
| `q` | Quit |

---

## Integrated Commands

| Command | Description |
|---------|-------------|
| `compil` | Automatically detects file extensions (`.py`, `.c`, `.js`, etc.), compiles if necessary, and executes the code. Also used internally by Abyss via `Ctrl+B`. |
| `clip` | Copies file content to the system clipboard. Binary files (`.bin`) may be truncated. |
| `wipe` | Clears the content of a file while preserving its original permissions. |
| `tree` | Displays a visual tree of the current directory structure. |
| `redem` | Emergency reset for WiFi drivers. Restarts stuck or crashing wireless interfaces. |

---

## Monitoring

### `monitoring`

A dashboard built with the `Rich` library displaying real-time system diagnostics:

- CPU and GPU usage, frequencies, RAM, disk I/O
- Top processes by resource usage
- Active network interfaces, mounted network drives, packet counters
- Python version and installed package count

### `wifi_monitoring`

Focused network monitor tracking wireless interface state and traffic in real time.

---

## Terminal Games

### `blackjack`

Classic CLI Blackjack with full dealer AI and a betting system. Player and dealer cards displayed in the terminal.

### `minesweeper`

Customizable Minesweeper with adjustable grid dimensions.

```bash
minesweeper <width> <height>
# Example:
minesweeper 4 4
```
