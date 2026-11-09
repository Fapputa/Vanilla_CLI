# Vanilla_CLI Suite

A high-performance, versatile toolkit designed to supercharge the terminal experience on Linux and Windows. From low-level system monitoring to a high-speed C-engineered text editor, this suite brings efficiency and fun to the command line.

![Demo](.rem.gif)

---

## Repository Layout

```
Vanilla_CLI/
├── Makefile
├── install.sh
├── CHANGELOG.md           -- F9 and debugger changes, by session
├── tests/                 -- Test suite (Linux tree only)
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

### Self-contained Linux executable

```bash
static/build.sh ~/abyss-build/out        # -> ~/abyss-build/out/abyss
```

One file, no run-time dependency: linked statically (musl, ncursesw, capstone), with
the i386 loader of the F9 debugger and the terminfo entries of xterm, xterm-256color,
linux, vt100, screen, tmux, alacritty and kitty built in. Copy it anywhere and run it.
A terminfo database on the system is still used first; a terminal found nowhere is
shown as xterm-256color, with a message. Build needs `gcc`, `make`, `curl`, `tic` /
`infocmp` and `~/abyss32` (see `static/build.sh`); the sources of musl, ncurses and
capstone are downloaded into `OUT/dl` and checked by SHA-256. Run time writes only to the
loader cache, `$XDG_CACHE_HOME/abyss` (or `~/.cache/abyss`), and only when an i386
program is debugged on a system without a 32-bit loader.

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
| `F9` | Static analysis of an ELF (x86-64, x86) or PE (x64, x86) .exe / .dll binary, debugger (Linux ELF) |

### Indentation

Indentation is 2 spaces. `Tab` inserts spaces up to the next multiple of 2,
`Enter` keeps the indentation of the line (2 more after `{`, or after a Python
line that opens a block).
Inside the leading spaces of a line the cursor moves as if they were tabs: `←` /
`→` jump 2 spaces, `Backspace` / `Del` erase 2. Past the first non-blank
character every key works one character at a time again.

### Mouse

The mouse works in every view:

- **Text**: a click places the cursor, a drag selects (then `Ctrl + X`,
  `Ctrl + C`...). A click in the other pane of a split gives it the focus.
- **Wheel**: scrolls the pane, list or panel under the pointer, even when another
  one has the focus.
- **Buttons**: the shortcuts written in the title bar, in the bottom bars and in the
  output panel header (`F2:Hex`, `Esc: cancel`, `a: arguments`...) are buttons: a
  click does what the key does.
- **Lists** (file tree, F8 processes and results, F9 functions, build-flags
  menu): a click selects a row, a second click on it opens it (`Enter`); in the
  build-flags menu a click ticks the option.
- **Table view**: a click selects a cell, a second click edits it; a click on a
  sheet tab switches sheet, on a header selects the column.
- **Hex view**: a click on a byte, in the hex or the ASCII column, moves there.
- **F9**: a click on a line with an address follows it (same as `Enter`); a click
  on the console panel types into it.

Since Abyss takes the mouse, the terminal's own selection (to copy text outside
Abyss) needs `Shift` held while dragging, in most terminals (xterm, GNOME
Terminal, Konsole, kitty, Windows Terminal...).

### File tree (F1)

`F1` shows the tree of the current folder. The line under its header is a
field: just type (or paste) into it while the tree has the focus.

- **A path**, absolute (`/etc/hosts`, `~/notes.md`, `C:\dev\x.c`) or
  relative to the folder shown (`src/main.c`): `Enter` opens the file, or
  moves the tree to the folder. `Tab` completes the path.
- **A URL** (`http://`, `https://`, `ftp://`, or just `www.example.com`):
  `Enter` fetches it with `curl` and shows it in the editor, whatever its
  type (HTML, JSON, CSV in the table view, pictures, PDF...). Text pages
  live in memory only, with no file on disk: `Ctrl + S` offers a name
  (the page's own, in the tree's folder) to keep it. Pictures, PDFs and
  databases go through a temporary copy, removed when Abyss exits.
- **Anything else** filters the names of the folder as you type; `Enter`
  opens the highlighted one.

`Backspace` erases, `Esc` / `Ctrl + U` clears the field.

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

**Saving the rows shown.** `w` writes the table as it is displayed (only
the rows the filters keep, in the sort order) to a new file, in the format
of the source: CSV stays CSV (same separator), TSV / PSV, JSON (array of
objects) and JSON Lines, SQL dump (the original `CREATE TABLE` followed by
one `INSERT` per row, literals kept as written), Markdown / text tables,
and SQLite (a new database with the table's schema, rows copied from the
source with their types). The name offered is `<name>_view.<ext>` next to
the source; an extension left out is added back, and the source itself is
never overwritten. With several tables in the file, the one shown is saved.

| Key | Action |
|-----|--------|
| Arrows / `hjkl` | Move between cells |
| `PgUp` / `PgDn`, `g` / `G` | Page, first / last row |
| `Home` / `End` | First / last column |
| `Tab` / `Shift+Tab` | Next / previous table |
| `s` / `S` | Add the column to the sort (asc / desc / off) / clear every sort |
| `f` / `F` | Filter the rows on the values ticked in the column (dropdown, `Space` ticks) / drop every filter |
| `w` | Save the rows shown (sorted / filtered) as a new file, same format as the source |
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
| `g` | Go to an address (hex) in the dump (the field opens empty) |
| `p` | Back to the process list |
| `F8` | Close the memory editor |

On a saved address, `Enter` edits its value, `f` toggles the freeze, `r`
renames it and `d` / `Del` removes it.

**4. History.** Each saved address logs the value changes seen when it is
re-read (once a second while `F8` shows, and at every redraw): old value,
new value and the time, e.g. `0 → 245`. The last 32 changes are kept per
address, older ones are dropped; the list shows how many were seen.

| Key (saved list) | Action |
|-----|--------|
| `h` | Show / hide the history of the selected address (takes the place of the hex dump) |
| `c` | Clear its history |
| `v` | Pin the *value* rather than the address: when it leaves its address, the page around it and the two next to it are searched and the entry follows it (`A → B` is logged); `left … (not found nearby)` and `back at …` when it disappears and returns. `v` again pins the address |

Nothing is read while the view is closed, so changes made meanwhile show as
a single transition. When the process exits, its saved addresses and their
history stay on screen (a `process ended` line is added); `p` picks another
process, which starts a new list.

Results are capped at 6,000,000 addresses; refine with a value scan if the
first one hits the cap.

### Static analysis (F9)

`F9` opens an analysis of the file behind the current buffer, in the current
pane, when it is an ELF binary, x86-64 or 32-bit x86 (executable, PIE, shared
object or `.o`), or a Windows PE binary, x64 or 32-bit x86 (`.exe`, `.dll`), on
Linux and on Windows alike. 32-bit x86 PE32 files are opened too, with their imports, exports,
base relocations, TLS callbacks and load config (their COFF symbols are not
read yet; the Windows debugger runs them through WOW64). The analysis only reads the
binary: it never runs, emulates or modifies it (the debugger, below, runs it
only when asked to).
Anything else gets a message in the status bar (not an executable, another
architecture, MS-DOS executable, truncated or malformed file). The
file on disk is analysed, not unsaved changes in the buffer.

For a PE file the information screen shows the subsystem, image base, entry
point, the imports grouped by DLL (delay-loaded and bound ones too), the
exports (code, data, forwarders such as `HeapAlloc -> NTDLL.RtlAllocateHeap`),
whether a .NET assembly is IL only or mixed-mode, the PDB path, TLS
callbacks, an overlay appended after the sections, and the
Windows protections (ASLR / high entropy, DEP, CFG, `/GS` cookie, signature,
writable + executable sections). Functions come from the exports, the COFF
symbols MinGW leaves in unstripped binaries (`main`, your own functions),
the `.pdata` unwind table and the code itself; import thunks are named after
their import (`CreateFileW`), and a `call [IAT slot]` is commented
`KERNEL32.dll!CreateFileW`. Addresses the base relocations patch that point
into code are function candidates, kept only when their code decodes
cleanly (switch tables read by `jmp [reg*4 + table]` excepted). In an IL-only
.NET assembly only the native entry stub is disassembled: no function is
guessed in the CIL bytecode. In a stripped binary `main` is found after the
CRT start-up fetches argc / argv (MSVC with the dynamic UCRT, MinGW, x64).
Not handled yet: ARM64, MSVC switch tables (relative to the image base in
x64; in x86 their cases are not followed), the CIL code of .NET assemblies.

The first screen sums the file up: type, architecture, entry point (and
`main`), linking and libraries, protections (PIE, NX, RELRO, stack canary,
FORTIFY, writable + executable segments), the functions found and where they
come from, segments, sections and the loader's warnings (a damaged section
table is reported and ignored). Arrows / `j` `k`, `PgUp` / `PgDn` / `Space`
and `g` / `G` scroll it. `F9` or `Esc` closes the view; the analysis is kept,
so `F9` shows it again at once unless the file changed on disk.

`Tab` switches to the function list (and back, see below): address, size, number of
callers, origin and name of every function found. The origin says where the
function comes from: `symtab` / `dynsym` (symbol), `plt`, `entry`, `main`,
`ctor`, `call` (target of a direct call), `codeptr` (address taken by
`lea [rip+X]`), `dataptr` (code pointer stored in data) or `prologue` (found by
its prologue in unreached code); the last two are guessed starts, marked `?`.
Arrows / `j` `k`, `PgUp` / `PgDn` / `Space` and `g` / `G` move the selection.
`s` cycles the sort: address, name, size (largest first), callers (most called
first). `/` filters on the name (case-insensitive, applied as you type; `Enter`
keeps it, `Esc` gives the previous one back, `Esc` on the list clears it).
`:` jumps to a hex address (`401000`, `0x401000`): the function holding it is
selected (the filter is dropped if it hid it), or the closest one when the
address is in no function. The status bar shows the selected function, its
position in the list and the active filter.

`Enter` on a function opens its disassembly: a linear sweep of its bytes, from
its start over its size (up to the next function, at most 64 KiB, when the size
is unknown; never past the end of its section). Each line shows the address, the
bytes (in a window at least 90 columns wide), the instruction and a comment: the
name of a call / jump target, of the data or the string a `[rip + X]` operand
points to, the start of another function. A line marked `!` is one the
recursive analysis did not decode (bytes hidden in code, or code it did not
reach, e.g. the cases of a switch whose table it does not follow). Arrows /
`j` `k`, `PgUp` / `PgDn` / `Space` and `g` / `G` move; `Esc` goes back to the
list.

`Enter` (or a click) on a line with an address (a call or jump target, a
`[rip + X]` operand) follows it: to the disassembly of the function holding
it, or to its row in a data section (`.rodata`, `.rdata`, `.data`, `.bss`...). In
32-bit code the address of the data is often not written as is; it is found too:
an immediate or an absolute operand (`mov dword ptr [esp], 0x404058`,
`[0x804a020]`, `[eax*4 + 0x8049f00]`), and `[ebx + X]` / `[reg + X]` after the
get-pc thunk (`call __x86.get_pc_thunk.bx`, `call $+5; pop`), the register being
followed through `add`, `mov`, a spill to `[ebp - X]` and its reload. Those lines
show the string or the name they point to in the comment. What is code and what is
data follows the sections when the file has them: an old linker puts `.rodata` in the
executable segment of `.text`, its strings are data all the same. Constants are not taken
as addresses in a shared library or a PIE (where they cannot be one), nor below
`0x10000`. `Backspace` goes back along the links
followed.

A `call` also shows what it is given, read from the lines just before it, like C:
`call 0x401040  ; printf@plt("%d %s %d\n", ?, "literal")`. The arguments are the
registers on x86-64 (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`; on Windows `rcx`, `rdx`,
`r8`, `r9`) and the `push` / `mov dword ptr [esp + X]` in 32-bit code, followed back
through a copy (`lea eax, [...]` then `mov [esp], eax`) and through a local of the frame
(`mov eax, [ebp - 8]`: the last `mov [ebp - 8], ...` before it in the function, unless
the address of that local is taken). Each one is a string, `&name`
(the address of some data), a function name, a name alone (the value read from it,
`name[…]` when indexed), or `?` (not an address, or not known: a number, a register set
elsewhere). `Enter` (or a click) on a line that leads to several places, such as a call
and the strings it is given, opens a small list: the function first, then each
argument; `↑` / `↓` and `Enter`, its number, or a click choose; `Esc` closes it. `:` jumps to a hex address from the disassembly and data screens
too.

`d` lists the data sections (name, address, size, permissions, type and what
the section usually holds); `Enter` shows the contents of one, cut into rows:
a string, an address (with the name of what it points to; `Enter` follows it),
a run of zero bytes, or 16 bytes of hex. `d` again goes back to where you
were.

Both data screens are drawn in column blocks, like the table view: the list as
SECTION, ADDRESS, SIZE, RWX, TYPE, CONTENTS; the contents as ADDRESS, SYMBOL (when a
row starts one), BYTES, VALUE. When the window is too narrow, the first column stays
and `←` / `→` scroll the others one whole column at a time; `«` / `»` in the header
row say that columns are hidden on that side, and a text cut short ends with `…`. `Tab` cycles the screens: information, list, disassembly, data
sections, contents.

#### Debugger (Linux)

On a Windows `.exe` / `.dll` the keys below only say that the debugger runs
Linux ELF programs; the analysis works as usual.

The disassembly screen is also a debugger of the binary (ptrace, one program
at a time, run under Abyss and killed with it):

| Key | Action |
|-----|--------|
| `b` | Set / remove a breakpoint on the selected line (`•` in the margin) |
| `B` | Breakpoint by name: `main`, `main+0x10`, `0x1149`, `.` (selected line), `libc.so.6+0x2a1c0`; add `hw` for a debug register, `if rax == 0x10` for a condition; `-WHERE` removes, `-*` removes all, `!WHERE` turns on / off |
| `e` | Turn the breakpoint of the selected line on / off (`○` when off) |
| `h` | Debug register (DR0-DR3, `◆`) instead of an `int3`; Linux only |
| `L` | List of the breakpoints: passes, condition, state |
| `n` | Go to the next breakpoint |
| `F5` | Run up to the next breakpoint, or continue |
| `F6` | Step one instruction; with no program running, start it and stop at the first line of `main` |
| `F7` | Step over (a `call` runs to the line after it); starts at `main` like `F6` |
| `p` | Pause the running program |
| `K` / `Shift + F5` | Kill it |
| `i` / click on the panel | Type into its console |
| `a` | Arguments of the program: the prompt shows the last ones; `Enter` keeps them for every later launch by `F5`, `F6` or `F7`, until the file is closed (an empty line: no argument) |

The arguments are split like a shell does, nothing expanded (no `$VAR`, no `*`):
blanks separate them, `'...'` keeps everything as typed, `"..."` keeps the blanks
(`\"` for a quote inside), and a `\` outside quotes keeps the next character. On
Windows a `\` is a path separator and stays as typed (`C:\tmp\x.txt`,
`\\srv\share`); only `\"` stands for a quote. An unclosed quote is refused at `Enter`,
with the prompt kept. The program gets them as `argv[1]`... (`argv[0]` is its path).

While the program is stopped, its line (`▶`) is highlighted and a panel on the
right shows the registers (`rip rsp rbp rax rbx rcx rdx rsi rdi rflags`, the
changed ones highlighted, `rflags` decoded, where `rip` is). A stop on a
signal says why, with the faulting address for a segmentation fault.
A 32-bit ELF program runs too (`eip esp...` registers, 32-bit disassembly).
When its loader `/lib/ld-linux.so.2` is not installed, the Linux `abyss` runs it
with the i386 loader it carries: `ld-linux.so.2`, `libc.so.6`, `libm.so.6`,
`libdl.so.2`, `libpthread.so.0` and `librt.so.1`, taken at build time from
`~/abyss32/` (`make ABYSS32=DIR` for another directory; without those files the
build warns and leaves the loader out). The executable alone is enough: the
first such launch writes them to `$XDG_CACHE_HOME/abyss/i32-<hash>/`
(`~/.cache/abyss/...` by default, directory 0700), each file is checked by its
SHA-256 at every launch and written again when it differs. A cache that cannot
be written refuses the launch and says where. The program gets the same arguments,
environment, working directory and console as with the system loader; only
`/proc/self/exe` and the auxiliary vector point at the loader, and a PIE is
placed next to the libraries. A library the program needs and nobody has
(`LD_LIBRARY_PATH` is searched first), or another error of the loader is told
when `F5` is pressed, before anything runs. Nothing of this is in the Windows build.

Breakpoints are stored as an offset in their module and placed again from the
load base of each run (PIE, ASLR). They can be set while the program runs and
are kept from one run to the next; their pass counter restarts with each run.
An `int3` is in memory only while the program runs: neither the disassembly
nor the F8 view ever shows it, and the file on disk is never written. An
address that is not mapped, not code or in a shared mapping is refused; a byte
the program rewrites itself is left alone and reported. A condition is
`<register> <op> <number>` (`==` `!=` `<` `<=` `>` `>=`, unsigned) or
`hits <op> <number>`; a pass where it is false only counts. A pass is an
arrival on the breakpoint, by running or by `F6` landing on it (reported as a
step); leaving it never counts, so `hits` means the same run or stepped, as in
gdb.

Every thread of the program is followed and they all stop together, on Linux
and on Windows. The registers are those of the thread that stopped, which the
status line names when it is not the first one. `F6` moves that thread alone:
the others stay stopped (on Windows they are suspended for the step); `F5`, and
`F7` over a `call`, start them all. A breakpoint works in every thread, and so
does a debug register on Linux.

Limits: child processes are not followed (one that reaches a breakpoint written
at the time of its `fork` dies of `SIGTRAP`, its parent lives on). A step that
blocks on another thread waits until `p`. A process whose first thread has
exited cannot be attached to. A module loaded by `dlopen` is resolved at the
next stop. On Windows, breakpoints are limited to the program itself (no other
module, no debug register); a 32-bit program runs through WOW64, with its 32-bit
registers and disassembly as on Linux.

At the first run, a breakpoint is set on every call to an input function of
the C library in the program's own code (`scanf`, `fgets`, `getchar`,
`read`...), drawn in another colour: the program stops before it waits for
its input. `b` removes one for good.

The bottom of the panel is the program's console: its stdin / stdout /
stderr are a pseudo-terminal, so it behaves as in a terminal (line-buffered
`printf`, echo of what is typed). While the program waits for its input the
panel says `WAITING FOR INPUT` and the keys go to the console by themselves:
`Enter` sends the line, `^D` ends the input, `^C` sends `SIGINT`, arrows and
`PgUp` / `PgDn` still move the disassembly, `Esc` gives the keys back (they
also come back at the next stop).

The view needs [capstone](https://www.capstone-engine.org/) (`pacman -S
capstone`, `apt install libcapstone-dev`), found through `pkg-config` at build
time. Without it the module is left out of the build and `F9` says so.

#### F9 keys

| Screen | Key | Action |
|--------|-----|--------|
| All | `Tab` | Next screen: information, functions, disassembly, data sections, contents |
| All | `F9` / `Esc` | Close the view (`Esc` first leaves the disassembly or a data section) |
| All | Arrows / `j` `k`, `PgUp` / `PgDn` / `Space`, `g` / `G` | Scroll or move |
| All | `d` | Data sections, and back |
| Functions, disassembly, data | `:` | Go to a hex address |
| Functions | `s` | Sort: address, name, size, callers |
| Functions | `/` | Filter on the name |
| Functions | `Enter` | Disassembly of the function |
| Disassembly, data | `Enter` / click | Follow the address of the line (a choice when there are several: a call and its arguments) |
| Disassembly, data | `Backspace` | Back along the links followed |
| Data sections, data | `←` / `→` | Scroll the columns (window too narrow) |
| Disassembly | `b` `B` `e` `h` `L` `n` | Breakpoints, see the debugger table |
| Disassembly | `F5` `F6` `F7` `p` `K` `i` | Run, step, pause, kill, type: see the debugger table |
| Disassembly | `a` | Arguments of the program for the next launches |

#### Features by session

The F9 module and the debugger were extended in the sessions below, detailed in
[CHANGELOG.md](CHANGELOG.md).

| Session | Feature |
|---------|---------|
| 1 | ELF32 i386 loader; `arch` and `bits` of a file |
| 2 | 32-bit decoding |
| 3 | x86-32 function discovery: PIC registers, `main`, prologues |
| 4 | x86-32 discovery from relocations, GOT base, PLT without sections |
| 5 | PE: checked headers, PE32 opened |
| 6 | PE: imports, exports, base relocations, `.NET` |
| 7 | PE: `.pdata`, load config, SafeSEH, CFG, TLS, protections |
| 8 | Breakpoints: by name, conditions, debug registers, relocated at each run; 32-bit ELF programs in the debugger |
| 9 | Threads followed, ESC overflow fixed, ELF32 and PE32 discovery fixes |
| 10 | Test suite gathered in `tests/`, open results explained |
| 11 | 32-bit dynamic ELF programs debugged without an i386 system loader (loader embedded in the Linux executable) |
| 12 | Hygiene: 0 warnings, the PE32 worst case bounded in time |
| 13 | Self-contained static Linux executable (musl) |
| 14 | Self-contained Windows executable (MinGW-w64, UCRT) |
| 15 | Windows debugger tested under Wine: other threads held during a step, exact pass counts |
| 16 | Windows debugger: 32-bit programs through WOW64 |
| 18 | Program arguments (`a`), more data addresses followed in 32-bit code; for the editor: 2-space soft indentation, the mouse in every view |

#### Known limits

Debugger:

- `fork` is not followed: a child that reaches a breakpoint written at the time of
  its `fork` dies of `SIGTRAP`; its parent lives on.
- `F6` moves the current thread alone, on Linux and on Windows: a step that blocks on
  another thread (a lock, a wait) waits for `p`; on Windows the other threads stay
  suspended until then.
- Attaching is refused once the first thread is a zombie, and can wait when it falls
  during its exit. After a detach with a zombie first thread, the real parent is only
  told when Abyss ends.
- Signals of every thread stop the program (`SIGURG` in Go programs).
- The automatic console only watches the first thread's input.
- A module loaded by `dlopen` is resolved at the next stop.
- Windows: no module other than the program, no debug register, the program has its
  own console window (the console panel and the memory maps are not done there).
- Windows, 32-bit programs (WOW64): a break-in (`p`, attach) that stops in the 32-bit
  `DbgBreakPoint` of a process whose 32-bit `ntdll` load was never reported (Wine) is
  shown as a breakpoint stop.

Analysis:

- x86 switch tables are not followed, in ELF32 or PE32; neither are MSVC x64 tables.
- ELF32: functions with no direct reference are not found. In the data view, addresses
  are read on 8-byte boundaries. `__stack_chk_fail_local` does not count as a canary.
- PE32: COFF symbols and the debug directory are not read.
- PE32 residues: 3 case labels taken as functions, about 4% of weak `push r; call`
  prologues unverified, one TLS callback pointing into an instruction gives a shifted
  start.
- PE64: one `.cold` part of the entry remains (`lib_mysqludf_sys_64`).
- ARM64, ARM and the CIL code of `.NET` assemblies are not analysed.
- A crafted PE32 is bounded in instructions (1,048,576 per analysis) and so in time:
  an 11 MB `.text` built to hit the worst case takes 0.45 s (22 s before session 12).

#### Never tested

Each item below lacks a sample or a platform on the development machine. It may work:
nothing shows that it does.

- **Real Windows.** Nothing has run on a real Windows. `abyss.exe` is cross-built on
  the development machine (MinGW-w64) and tested under Wine 11.21 and against a
  simulated Win32 API (`dbg_win.c`, the console). Never seen for real: the WOW64
  codes `0x4000001F` / `0x4000001E` and the two loader breakpoints of a WOW64 launch
  (Wine raises the native codes and one loader breakpoint), ASLR (Wine maps every
  image at its ImageBase), attaching to a PE32 (Wine kills the target at the
  break-in), the module list of a WOW64 process, `SuspendThread` on busy threads on
  several cores, and the real console host (`conhost`, Windows Terminal): Wine's
  console ignores resizes and shows VT sequences as text.
- **Debugger:** a kernel
  without 32-bit support (simulated: `execve` made to fail with `ENOEXEC`); a real
  `dlopen`; real self-modifying code (simulated by writing to
  `/proc/pid/mem`); a real shared mapping (synthetic tables only).
- **ELF32:** `push [ebx+main@GOT]` of a glibc PIE, GOTOFF / GOTPC / PLT32 in
  `.rel.dyn`, GLOB_DAT or `R_386_32` on a defined function, PIE with `.plt.sec` and no
  sections, lld IBT PLT, i386 RELA symbol relocations, C++ vtables.
- **PE:** real delay-load and bound imports (mutations only), PE32 from MinGW, PE32
  with COFF symbols, CFG table in a PE32, real cyclic or deep `.pdata` chains, real
  unsorted SafeSEH. FORCE_INTEGRITY and APPCONTAINER are only seen absent, NO_ISOLATION
  on a single file. PE32 TLS callbacks: a single file (`template_x86_windows.dll` of
  cve-2017-8464).

The test suite is in `tests/` in the Linux tree: see `tests/README.md`.

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