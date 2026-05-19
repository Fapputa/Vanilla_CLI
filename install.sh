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

if [ "$EUID" -ne 0 ]; then
    fail "Ce script doit etre execute en tant que root. Relancez avec : sudo $0"
fi

INSTALL_BIN="/usr/local/bin"
USER_BIN="$HOME/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

install_python_deps() {
    info "Installing Python dependencies..."

    pip install --break-system-packages \
        rich \
        prompt_toolkit \
        pygments \
        psutil

    ok "Python dependencies installed."
}

build_all() {
    info "Building all C binaries..."

    if [ ! -f "$SCRIPT_DIR/Makefile" ]; then
        fail "No Makefile found in $SCRIPT_DIR."
    fi

    cd "$SCRIPT_DIR"
    make clean && make

    ok "All binaries built successfully."
}

install_to() {
    local dest="$1"

    if [ -f "$SCRIPT_DIR/abyss" ]; then
        cp "$SCRIPT_DIR/abyss" "$dest/abyss"
        chmod +x "$dest/abyss"
        ok "abyss            -> $dest/abyss"
    else
        warn "abyss binary not found after build, skipping."
    fi

    if [ -f "$SCRIPT_DIR/lsc/lsc" ]; then
        cp "$SCRIPT_DIR/lsc/lsc" "$dest/lsc"
        chmod +x "$dest/lsc"
        ok "lsc              -> $dest/lsc"
    else
        warn "lsc binary not found, skipping."
    fi

    if [ -f "$SCRIPT_DIR/lsc/lsc-config" ]; then
        cp "$SCRIPT_DIR/lsc/lsc-config" "$dest/lsc-config"
        chmod +x "$dest/lsc-config"
        ok "lsc-config       -> $dest/lsc-config"
    else
        warn "lsc-config binary not found, skipping."
    fi

    declare -A PY_SCRIPTS=(
        ["monitoring"]="monitoring.py"
        ["wifi_monitoring"]="wifi_monitoring.py"
    )

    for cmd in "${!PY_SCRIPTS[@]}"; do
        abs_path="$SCRIPT_DIR/${PY_SCRIPTS[$cmd]}"
        if [ -f "$abs_path" ]; then
            tee "$dest/$cmd" > /dev/null <<WRAPPER
#!/usr/bin/env bash
exec python3 "$abs_path" "\$@"
WRAPPER
            chmod +x "$dest/$cmd"
            ok "$cmd  -> $dest/$cmd"
        else
            warn "${PY_SCRIPTS[$cmd]} not found, skipping $cmd."
        fi
    done

    for cmd in compil clip wipe tree redem blackjack minesweeper; do
        abs_path="$SCRIPT_DIR/$cmd"
        if [ -f "$abs_path" ]; then
            cp "$abs_path" "$dest/$cmd"
            chmod +x "$dest/$cmd"
            ok "$cmd  -> $dest/$cmd"
        else
            warn "$cmd not found, skipping."
        fi
    done
}

install_binaries() {
    mkdir -p "$USER_BIN"
    if [[ ":$PATH:" != *":$USER_BIN:"* ]]; then
        warn "$USER_BIN is not in your PATH. Add the following to your ~/.bashrc or ~/.zshrc:"
        echo -e "  ${CYAN}export PATH=\"\$HOME/bin:\$PATH\"${NC}"
    fi

    info "Installing to $USER_BIN (user-local)..."
    install_to "$USER_BIN"

    info "Installing to $INSTALL_BIN (system-wide)..."
    install_to "$INSTALL_BIN"

    ok "All available commands installed."
}

print_summary() {
    echo ""
    echo -e "${BOLD}${GREEN}=======================================${NC}"
    echo -e "${BOLD}${GREEN}   Vanilla_CLI Suite - Install Complete${NC}"
    echo -e "${BOLD}${GREEN}=======================================${NC}"
    echo ""
    echo -e "  Commands now available globally:"
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
    echo -e "  ${CYAN}lsc${NC}              - ls with custom colors (~/.colorrc)"
    echo -e "  ${CYAN}lsc-config${NC}       - TUI editor for lsc color rules"
    echo ""
    echo -e "  Installed to:"
    echo -e "  ${CYAN}~/bin${NC}            (user-local)"
    echo -e "  ${CYAN}/usr/local/bin${NC}   (system-wide)"
    echo ""
    echo -e "  Tip - add to your ~/.bashrc to replace ls:"
    echo -e "  ${CYAN}alias ls='lsc'${NC}"
    echo -e "  ${CYAN}alias lsconfig='lsc-config'${NC}"
    echo ""
}

echo ""
echo -e "${BOLD}${CYAN}  Vanilla_CLI Suite - Installer${NC}"
echo -e "${CYAN}  ------------------------------${NC}"
echo ""

detect_pkg_manager
install_system_deps
install_python_deps
build_all
install_binaries
print_summary
