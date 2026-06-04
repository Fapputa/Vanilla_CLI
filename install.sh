#!/usr/bin/env bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[v]${NC} $*"; }
info() { echo -e "${CYAN}[i]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[x]${NC} $*"; exit 1; }

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CMD_DIR="$SCRIPT_DIR/cmd"
BIN_DIR="$SCRIPT_DIR/bin"
SCRIPTS_DIR="$SCRIPT_DIR/scripts"

SYS_BIN="/usr/local/bin"
USER_BIN="$HOME/bin"

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
    fail "This script must be run as root. Re-run with: sudo $0"
fi

# ---------------------------------------------------------------------------
# Package manager detection
# ---------------------------------------------------------------------------
detect_pkg_manager() {
    if command -v apt &>/dev/null; then
        PKG_MANAGER="apt"
        info "Package manager detected: apt (Debian/Ubuntu)"
    elif command -v pacman &>/dev/null; then
        PKG_MANAGER="pacman"
        info "Package manager detected: pacman (Arch)"
    else
        fail "No supported package manager found (apt / pacman). Aborting."
    fi
}

# ---------------------------------------------------------------------------
# System dependencies
# ---------------------------------------------------------------------------
install_system_deps() {
    info "Installing system dependencies..."

    if [ "$PKG_MANAGER" = "apt" ]; then
        apt update -qq
        apt install -y \
            build-essential \
            libncurses-dev \
            libncursesw5-dev \
            python3 \
            python3-pip \
            xclip \
            xsel \
            wireless-tools \
            net-tools
    elif [ "$PKG_MANAGER" = "pacman" ]; then
        pacman -Sy --noconfirm \
            base-devel \
            ncurses \
            python \
            python-pip \
            xclip \
            xsel \
            wireless_tools \
            net-tools
    fi

    ok "System dependencies installed."
}

# ---------------------------------------------------------------------------
# Python dependencies
# ---------------------------------------------------------------------------
install_python_deps() {
    info "Installing Python dependencies..."

    pip install --break-system-packages \
        rich \
        prompt_toolkit \
        pygments \
        psutil

    ok "Python dependencies installed."
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
build_all() {
    info "Building C binaries..."

    [ -f "$SCRIPT_DIR/Makefile" ] || fail "Makefile not found in $SCRIPT_DIR."

    cd "$SCRIPT_DIR"
    make clean && make

    ok "Build complete."
}

# ---------------------------------------------------------------------------
# Install to a destination directory
# ---------------------------------------------------------------------------
install_to() {
    local dest="$1"
    mkdir -p "$dest"

    # Compiled binaries (project root)
    for bin in abyss lsc lsc-config; do
        if [ -f "$SCRIPT_DIR/$bin" ]; then
            install -m 755 "$SCRIPT_DIR/$bin" "$dest/$bin"
            ok "$bin  ->  $dest/$bin"
        else
            warn "$bin not found, skipping."
        fi
    done

    # Shell commands: cmd/
    for cmd in wipe clip compil redem tree; do
        if [ -f "$CMD_DIR/$cmd" ]; then
            install -m 755 "$CMD_DIR/$cmd" "$dest/$cmd"
            ok "$cmd  ->  $dest/$cmd"
        else
            warn "$cmd not found in cmd/, skipping."
        fi
    done

    # Games: bin/
    for game in blackjack minesweeper; do
        if [ -f "$BIN_DIR/$game" ]; then
            install -m 755 "$BIN_DIR/$game" "$dest/$game"
            ok "$game  ->  $dest/$game"
        else
            warn "$game not found in bin/, skipping."
        fi
    done

    # Python scripts: scripts/ (shell wrappers)
    declare -A PY_SCRIPTS=(
        ["monitoring"]="monitoring.py"
        ["wifi_monitoring"]="wifi_monitoring.py"
    )

    for cmd in "${!PY_SCRIPTS[@]}"; do
        src="$SCRIPTS_DIR/${PY_SCRIPTS[$cmd]}"
        if [ -f "$src" ]; then
            cat > "$dest/$cmd" <<WRAPPER
#!/usr/bin/env bash
exec python3 "$src" "\$@"
WRAPPER
            chmod +x "$dest/$cmd"
            ok "$cmd  ->  $dest/$cmd"
        else
            warn "${PY_SCRIPTS[$cmd]} not found in scripts/, skipping."
        fi
    done
}

# ---------------------------------------------------------------------------
# Install to both user-local and system-wide
# ---------------------------------------------------------------------------
install_binaries() {
    mkdir -p "$USER_BIN"
    if [[ ":$PATH:" != *":$USER_BIN:"* ]]; then
        warn "$USER_BIN is not in your PATH. Add to ~/.bashrc or ~/.zshrc:"
        echo -e "  ${CYAN}export PATH=\"\$HOME/bin:\$PATH\"${NC}"
    fi

    info "Installing to $USER_BIN (user-local)..."
    install_to "$USER_BIN"

    info "Installing to $SYS_BIN (system-wide)..."
    install_to "$SYS_BIN"

    ok "All available commands installed."
}

# ---------------------------------------------------------------------------
# Final cleanup: remove .o files and compiled binaries from project root
# ---------------------------------------------------------------------------
cleanup_build() {
    info "Removing object files (.o)..."
    cd "$SCRIPT_DIR"
    make clean_obj
    ok "Object files removed."

    info "Removing compiled binaries from project root..."
    for bin in abyss lsc lsc-config; do
        if [ -f "$SCRIPT_DIR/$bin" ]; then
            rm -f "$SCRIPT_DIR/$bin"
            ok "Removed $SCRIPT_DIR/$bin"
        fi
    done
    ok "Project root clean."
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
    echo ""
    echo -e "${BOLD}${GREEN}=======================================${NC}"
    echo -e "${BOLD}${GREEN}   Vanilla_CLI Suite - Install Complete ${NC}"
    echo -e "${BOLD}${GREEN}=======================================${NC}"
    echo ""
    echo -e "  Commands available globally:"
    echo -e "  ${CYAN}abyss${NC}            - Text editor (C)"
    echo -e "  ${CYAN}compil${NC}           - Smart compiler/runner"
    echo -e "  ${CYAN}clip${NC}             - Copy file to clipboard"
    echo -e "  ${CYAN}wipe${NC}             - Clear file contents"
    echo -e "  ${CYAN}tree${NC}             - Directory tree view"
    echo -e "  ${CYAN}redem${NC}            - WiFi driver reset"
    echo -e "  ${CYAN}monitoring${NC}       - System dashboard"
    echo -e "  ${CYAN}wifi_monitoring${NC}  - Network monitor"
    echo -e "  ${CYAN}blackjack${NC}        - Blackjack game"
    echo -e "  ${CYAN}minesweeper${NC}      - Minesweeper game"
    echo -e "  ${CYAN}lsc${NC}              - Colorized ls (~/.colorrc)"
    echo -e "  ${CYAN}lsc-config${NC}       - TUI editor for lsc color rules"
    echo ""
    echo -e "  Installed to:"
    echo -e "  ${CYAN}~/bin${NC}            (user-local)"
    echo -e "  ${CYAN}/usr/local/bin${NC}   (system-wide)"
    echo ""
    echo -e "  Tip - add to ~/.bashrc to replace ls:"
    echo -e "  ${CYAN}alias ls='lsc'${NC}"
    echo -e "  ${CYAN}alias lsconfig='lsc-config'${NC}"
    echo ""
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}${CYAN}  Vanilla_CLI Suite - Installer${NC}"
echo -e "${CYAN}  ------------------------------${NC}"
echo ""

detect_pkg_manager
install_system_deps
install_python_deps
build_all
install_binaries
cleanup_build
print_summary