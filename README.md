# Vanilla_CLI Suite

A high-performance, versatile toolkit designed to supercharge the terminal experience on Linux and Windows. From low-level system monitoring to a high-speed C-engineered text editor, this suite brings efficiency and fun to the command line.

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

## Windows

Abyss fully supports Windows 10 and 11, through a **precompiled `abyss.exe`**
available on the [Releases page](https://github.com/Fapputa/Vanilla_CLI/releases).

**1. Download** `abyss.exe` from the latest release. It is statically linked:
a single self-contained file, with no DLL or MSYS2 install needed beside it.

**2. Put it on your `PATH`**, for example in `%USERPROFILE%\bin` (from PowerShell):

```powershell
mkdir $env:USERPROFILE\bin -Force
move .\abyss.exe $env:USERPROFILE\bin\
[Environment]::SetEnvironmentVariable("Path", "$env:Path;$env:USERPROFILE\bin", "User")
```

**3. Run it** from Windows Terminal, PowerShell or `cmd.exe`:

```powershell
abyss main.c
```

Every feature works on Windows: compile and run with `Ctrl + B` (gcc, clang,
tcc, zig, nasm, csc... whichever are on `PATH`), web servers, table view, image
and document views, hex view and the memory editor. Notes specific to Windows:

- The console cannot redefine colors, so the editor uses its own xterm-256
  theme (Monokai-style syntax, deep red title bar, slate status bar).
- Images need nothing to install. PDFs and SQLite databases use `pdftotext`
  (poppler) and `sqlite3` when they are on `PATH` (scoop, winget or MSYS2).
  `.docx` / `.odt` files are read with the `tar.exe` shipped with Windows 10+.
- The memory editor (`F8`) needs Abyss to be run as administrator to attach to
  processes started by another user or elevated.

To build the `.exe` yourself instead, from an **MSYS2 UCRT64** shell:

```bash
pacman -S --needed make mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-ncurses
make            # -> abyss.exe
```

---

## Abyss - Text Editor

Engineered for zero-latency, Abyss is written in C and uses a **Gap Buffer** and **Line Indexing** to handle massive files without breaking a sweat.

- **Performance:** O(1) insertions and deletions
- **Architecture:** Low-level memory management with `ncurses` for a flicker-free UI
- **Features:** Undo/Redo, syntax highlighting, integrated compilation, hex view

### Compiling and running

`Ctrl + B` saves the buffer and builds it, with the output shown in a pane at
the bottom:

| Language | Toolchain |
|----------|-----------|
| C | `gcc` |
| C++ | `g++` |
| Rust | `rustc`, or `cargo run` when the file belongs to a crate (a `Cargo.toml` found up the tree) |
| Assembly | `nasm` + `ld` |
| C# | `mcs` + `mono` |

Interpreted files (Python, shell, JS, PHP) are simply run.

When it finishes, the compile and run times are shown in the status bar and at
the end of the output pane (`-- compile 412 ms | run 1.27 s --`). A failed
compilation reports only its compile time; a nonzero exit code is appended.

Pressing `Ctrl + B` twice quickly (within 350 ms) — or `F5` — opens a dropdown at the bottom listing the compiler flags for the current
language: optimisation level, SIMD/vector ISA (`-march=native`, `-mavx2 -mfma`,
`-msse4.2`, or `-C target-cpu=native` for Rust), LTO, fast math, sanitizers,
and so on. `Space` toggles a flag, `Enter` builds and runs with the selection,
`Esc` closes. Bracketed entries `[x]` are independent; `(*)` entries belong to
a group where only one can be active at a time (you cannot ask for `-O2` and
`-O3` at once). The line above the border previews the exact flags that `^B`
will pass to the compiler.

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
| `F8` | Memory editor (scan and change a running program's variables) |

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
unsaved edits included; it is read-only, edits happen in the text.

**Sorting.** `s` sorts the grid on the current column (ascending, then
descending, then off for that column), `S` clears every sort. Sorts combine:
`s` on another column adds it as the next key, ordering the rows the previous
keys leave equal (up to 8 columns). With several keys each sorted header shows
its rank (`▲1`, `▼2`...), and the status bar lists them in order. Number columns sort
numerically, text sorts in natural order (`file2` before `file10`), empty cells
go last. Sorting only changes the display: the gutter keeps showing each row's
original number. Switching to another table clears it.

**Filtering.** `f` on a column opens a dropdown under its header with
the distinct values of the column, sorted like the column, each with a
box and the number of rows holding it (`(empty)` and `(missing)` cells
included). Values and counts follow the current view: they are taken from
the rows the filters of the *other* columns leave, so filtering one column
changes what the others' dropdowns list and count. Type to narrow the
list (space is not typed: it ticks), `Up` / `Down` to move, `Space` to
tick / untick a value (on `(all)`: every value listed at once), `Enter` to
keep the rows with any ticked value, `Esc` to close. Without ticking
anything, `Enter` keeps only the highlighted value, and on `(all)` drops
the column's filter. Filters combine: each filtered column (up to 16) is
marked `≡`, a row is shown when it passes them all, and `F` in the grid
drops them all. The tab shows `shown/total`, the status bar lists the
filters, and they work together with the sort and the search (only the
rows shown). Switching to another table clears them.

| Key | Action |
|-----|--------|
| Arrows / `hjkl` | Move between cells |
| `PgUp` / `PgDn`, `g` / `G` | Page, first / last row |
| `Home` / `End` | First / last column |
| `Tab` / `Shift+Tab` | Next / previous table |
| `s` / `S` | Add the column to the sort (asc / desc / off) / clear every sort |
| `f` / `F` | Filter the rows on the values ticked in the column (dropdown, `Space` ticks) / drop every filter |
| `Enter` | Show the full cell in the status bar |
| `Ctrl + F`, `Ctrl + N` / `Ctrl + P` | Search cells, next / previous match |
| `F2` | Hex view |

### Memory editor

`F8` opens a memory scanner in the current pane, in the spirit of Cheat
Engine: attach to a running process, find where a variable lives in its
memory by scanning for its value, then read it live, change it or freeze
it. `F8` again closes the view; frozen values keep being written while it
is hidden.

**1. Pick a process.** The list shows running processes, newest first,
with their memory usage. Type to filter it, `Enter` attaches, `Ctrl + R`
refreshes. `Ctrl + O` launches a program from a command line as a child of
Abyss and attaches to it right away.

> **Permissions (Linux).** Reading another process's memory needs ptrace
> rights. With the default `kernel.yama.ptrace_scope = 1`, only a child of
> Abyss can be inspected without root, so `Ctrl + O` is the easy way.
> Otherwise run Abyss with `sudo`, or allow it system-wide with
> `sudo sysctl kernel.yama.ptrace_scope=0`. Memory is accessed through
> `process_vm_readv` / `process_vm_writev`, with `/proc/<pid>/mem` as a
> fallback.

**2. Scan.** Choose what you are looking for, then narrow it down:

- `t` cycles the value type: `int8`, `int16`, `int32` (default), `int64`,
  `float`, `double`, `text`, `text UTF-16`, `bytes`.
- `m` cycles the scan mode. A first scan can be `exact value`,
  `bigger than`, `smaller than`, `between` (`low..high`) or
  `unknown initial value`; the next ones add `increased`, `decreased`,
  `increased by`, `decreased by`, `changed` and `unchanged`. Text and
  bytes only support `exact value`, `changed` and `unchanged`.
- `u` toggles aligned scanning (default: values at addresses aligned to
  their size, much faster) versus every byte.
- `s` scans. The first scan walks all the writable memory of the process,
  each next scan only re-checks the previous results. `n` starts over.

Integers accept decimal or `0x` hex. Floats are matched with a tolerance
taken from the decimals you type: `100` matches 99.5 to 100.5, `1.25`
matches 1.245 to 1.255. Byte patterns are written in hex with `??` as a
wildcard (`DE AD ?? EF`).

A typical session to find a counter whose value you know:

1. Scan for its current value (`s`, e.g. `42`): thousands of results.
2. Change it in the program (lose a life, gain a point...).
3. Scan again for the new value, or pick `increased` / `decreased` with `m`.
4. Repeat until a handful of addresses remain.

When the value is not shown anywhere (a health bar), start with
`unknown initial value`: the memory is copied, then refine with
`changed` / `unchanged` / `increased` / `decreased` as it changes.

**3. Change the variable.** Values in the result list are re-read once a
second.

| Key | Action |
|-----|--------|
| `Enter` / `e` | Write a new value at the selected address |
| `a` / `+` | Save the address to the list below the results |
| `f` | Save the address and freeze it (its value is written back ten times a second) |
| `Tab` | Switch between results and saved addresses |
| `x` | Hex dump around the selected address (changed bytes highlighted) |
| `g` | Go to an address (hex) in the dump |
| `p` | Back to the process list |
| `F8` | Close the memory editor |

On a saved address, `Enter` edits its value, `f` toggles the freeze, `r`
renames it and `d` / `Del` removes it.

Results are capped at 6,000,000 addresses; refine with a value scan if the
first one hits the cap.

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
