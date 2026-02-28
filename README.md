# Vanilla_CLI Suite

A high-performance, versatile toolkit designed to supercharge the Linux terminal experience. From low-level system monitoring to a high-speed C-engineered text editor, this suite brings efficiency and fun to the command line.

---

## Getting Started

**1. Clone the repository:**

```bash
git clone https://github.com/your-username/Vanilla_CLI.git
cd Vanilla_CLI
```

**2. Make the installer executable and run it:**

```bash
chmod +x install.sh && ./install.sh
```

The installer will automatically:
- Detect your package manager (`apt` or `pacman`) and install system dependencies
- Install Python dependencies (`rich`, `prompt_toolkit`, `pygments`, `psutil`)
- Build Abyss with `make clean && make`
- Deploy all commands to both `~/bin` and `/usr/local/bin`

---

## Abyss – The Evolution of Editing

### Abyss.c (The Pro Version)

Engineered for zero-latency, the C version uses a **Gap Buffer** and **Line Indexing** to handle massive files without breaking a sweat.

- **Performance:** Instant $O(1)$ insertions/deletions
- **Architecture:** Low-level memory management with `ncurses` for a flicker-free UI
- **Features:** Undo/Redo (`Ctrl+Z` / `Ctrl+Y`), syntax highlighting, and integrated compilation

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

## Integrated Commands

| Command | Description |
|---------|-------------|
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
