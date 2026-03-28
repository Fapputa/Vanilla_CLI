# Vanilla_CLI Suite

A high-performance, versatile toolkit designed to supercharge the Linux terminal experience. From low-level system monitoring to a high-speed C-engineered text editor, this suite brings efficiency and fun to the command line.

![Demo](.lain.gif)
---

## Getting Started

**1. Clone the repository:**

```bash
git clone https://github.com/Fapputa/Vanilla_CLI.git
cd Vanilla_CLI
```

**2. Make the installer executable and run it:**

```bash
chmod +x install.sh && ./install.sh
```

The installer will automatically:
- Detect your package manager (`apt` or `pacman`) and install system dependencies
- Install Python dependencies (`rich`, `prompt_toolkit`, `pygments`, `psutil`)
- Build Abyss, lsc, and lsc-config with `make clean && make`
- Deploy all commands to both `~/bin` and `/usr/local/bin`

---

## Abyss – The Evolution

### Abyss.c (The Pro Version)

Engineered for zero-latency, the C version uses a **Gap Buffer** and **Line Indexing** to handle massive files without breaking a sweat.

- **Performance:** Instant $O(1)$ insertions/deletions
- **Architecture:** Low-level memory management with `ncurses` for a flicker-free UI
- **Features:** Undo/Redo (`Ctrl+Z` / `Ctrl+Y`), syntax highlighting, and integrated compilation, Hex view of any file

#### Manual Build

```bash
make clean && make
```

#### Manual System-wide Installation

```bash
sudo cp abyss /usr/local/bin/
```

#### Usage

```bash
abyss main.c
```

---

### Abyss.py (The Legacy Version)

The original Python version powered by `prompt_toolkit`. It remains available for users who prefer a pure Python environment.

---

## lsc – Colorized ls

A drop-in replacement for `ls` with fully customizable per-extension colorization, driven by a simple config file (`~/.colorrc`) and a ncurses TUI editor.

### Features

- Per-extension color rules (`.c`, `.py`, `.md`, …)
- Special rules for directories (`dir`), executables (`exec`), symlinks (`link`), and files without extension (`noext`)
- Attributes: `bold`, `italic`, `underline`, `outline` (reverse video)
- 16 named colors + full 256-color palette
- Automatic column layout matching your terminal width, with proper UTF-8 display width handling
- Compatible with `ls` flags (`-l`, `-a`, `-h`, …)

### Build

```bash
cd lsc
gcc -O2 -Wall -Wextra -o lsc lsc.c
gcc -O2 -Wall -Wextra -o lsc-config lsc-config.c -lncurses
```

Or from the root with make:

```bash
make lsc
make lsc-config
```

### Installation

```bash
# User-local
cp lsc/lsc     ~/bin/lsc
cp lsc/lsc-config ~/bin/lsc-config

# System-wide
sudo cp lsc/lsc        /usr/local/bin/lsc
sudo cp lsc/lsc-config /usr/local/bin/lsc-config
```

Or via the root Makefile:

```bash
sudo make install
```

### Usage

```bash
lsc            # current directory
lsc -la        # long format, all files
lsc ~/projects # specific directory
lsc-config     # open the TUI color rule editor
```

To replace `ls` permanently, add to your `~/.bashrc`:

```bash
alias ls='lsc'
alias lsconfig='lsc-config'
```

### Config file — `~/.colorrc`

```
# format: .ext = FG [BG] [bold] [italic] [underline] [outline]
# special keys: dir  exec  link  noext
# colors: black red green yellow blue magenta cyan white
#         bright_black … bright_white   (16 named)
#         0–255                         (256-color palette)

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

### lsc-config — TUI Rule Editor

An interactive ncurses editor for `~/.colorrc`.

| Key | Action |
|-----|--------|
| `↑↓` | Navigate rules |
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
| `lsc` | Colorized `ls` replacement with per-extension rules |
| `lsc-config` | TUI editor for lsc color rules |
| `compil` | The engine behind Abyss. Automatically detects extensions (`.py`, `.c`, `.js`, etc.), compiles if necessary, and executes the code instantly. |
| `clip` | Copies file content to the system clipboard. ⚠️ Binary files (`.bin`) may be truncated. |
| `wipe` | Completely clears the content of a file while strictly preserving its original system permissions. |
| `tree` | Displays a clean, visual tree of the current directory structure. |
| `redem` | Emergency reset for WiFi drivers. Quickly restarts stuck or crashing wireless interfaces. |

---

## Monitoring & Network

### `monitoring` & `wifi_monitoring`

A pro-grade dashboard using the `Rich` library to display real-time system diagnostics:

- **Hardware:** CPU/GPU usage, frequencies, RAM, and Disk I/O
- **Processes:** Top PIDs, resource-heavy tasks
- **Network:** Active interfaces, mounted network drives, and packet tracking (In/Out)
- **Software:** Python version and installed package count

---

## Terminal Games

### `blackjack`

A classic CLI Blackjack game. Player cards are displayed at the top, with full dealer AI and a betting system.

### `minesweeper`

Customizable Minesweeper with adjustable grid size.

```bash
minesweeper <width> <height>
# Example: a tactical 4x4 grid
minesweeper 4 4
```

---

## Keybindings (Abyss)

| Key | Action |
|-----|--------|
| `Ctrl + S` | Save File |
| `Ctrl + Q` | Exit |
| `Ctrl + Z` | Undo |
| `Ctrl + Y` | Redo |
| `Ctrl + B` | Compile & Run (via `compil`) |
| `Ctrl + N` | Split Screen View |
| `Ctrl + K` | Kill (Delete) Current Line |
| `f2` | Hex view of the code |
