#!/usr/bin/env bash
# =============================================================================
#  Vanilla_CLI Suite — Installer
# =============================================================================

set -e

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[✔]${NC} $*"; }
info() { echo -e "${CYAN}[i]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[✘]${NC} $*"; exit 1; }

INSTALL_BIN="/usr/local/bin"
USER_BIN="$HOME/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
#  1. Detect package manager
# =============================================================================
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

# =============================================================================
#  2. Install system dependencies
# =============================================================================
install_system_deps() {
    info "Installing system dependencies..."

    if [ "$PKG_MANAGER" = "apt" ]; then
        sudo apt update -qq
        sudo apt install -y \
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
        sudo pacman -Sy --noconfirm \
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

# =============================================================================
#  3. Install Python dependencies
# =============================================================================
install_python_deps() {
    info "Installing Python dependencies..."

    pip install --break-system-packages \
        rich \
        prompt_toolkit \
        pygments \
        psutil

    ok "Python dependencies installed."
}

# =============================================================================
#  4. Build Abyss (C)
# =============================================================================
build_abyss() {
    info "Building Abyss (C)..."

    if [ ! -f "$SCRIPT_DIR/Makefile" ]; then
        fail "No Makefile found in $SCRIPT_DIR."
    fi

    cd "$SCRIPT_DIR"
    make clean && make

    ok "Abyss built successfully."
}

# =============================================================================
#  5. Install binaries & scripts
#     → /usr/local/bin  (system-wide, requires sudo)
#     → ~/bin           (user-local, no sudo needed)
# =============================================================================
install_to() {
    local dest="$1"
    local use_sudo="$2"   # "sudo" or ""
    local cp_cmd="cp"
    [ "$use_sudo" = "sudo" ] && cp_cmd="sudo cp"

    # ── Abyss C binary ────────────────────────────────────────────────────────
    if [ -f "$SCRIPT_DIR/abyss" ]; then
        $cp_cmd "$SCRIPT_DIR/abyss" "$dest/abyss"
        [ "$use_sudo" = "sudo" ] && sudo chmod +x "$dest/abyss" || chmod +x "$dest/abyss"
        ok "abyss            → $dest/abyss"
    else
        warn "abyss binary not found after build, skipping."
    fi

    # ── Python script wrappers ────────────────────────────────────────────────
    declare -A PY_SCRIPTS=(
        ["monitoring"]="monitoring.py"
        ["wifi_monitoring"]="wifi_monitoring.py"
    )

    for cmd in "${!PY_SCRIPTS[@]}"; do
        abs_path="$SCRIPT_DIR/${PY_SCRIPTS[$cmd]}"
        if [ -f "$abs_path" ]; then
            if [ "$use_sudo" = "sudo" ]; then
                sudo tee "$dest/$cmd" > /dev/null <<EOF
#!/usr/bin/env bash
exec python3 "$abs_path" "\$@"
EOF
                sudo chmod +x "$dest/$cmd"
            else
                tee "$dest/$cmd" > /dev/null <<EOF
#!/usr/bin/env bash
exec python3 "$abs_path" "\$@"
EOF
                chmod +x "$dest/$cmd"
            fi
            ok "$cmd  → $dest/$cmd"
        else
            warn "${PY_SCRIPTS[$cmd]} not found, skipping $cmd."
        fi
    done

    # ── Shell/binary commands ─────────────────────────────────────────────────
    for cmd in compil clip wipe tree redem blackjack minesweeper; do
        abs_path="$SCRIPT_DIR/$cmd"
        if [ -f "$abs_path" ]; then
            $cp_cmd "$abs_path" "$dest/$cmd"
            [ "$use_sudo" = "sudo" ] && sudo chmod +x "$dest/$cmd" || chmod +x "$dest/$cmd"
            ok "$cmd  → $dest/$cmd"
        else
            warn "$cmd not found, skipping."
        fi
    done
}

install_binaries() {
    # Ensure ~/bin exists and is in PATH
    mkdir -p "$USER_BIN"
    if [[ ":$PATH:" != *":$USER_BIN:"* ]]; then
        warn "$USER_BIN is not in your PATH. Add the following to your ~/.bashrc or ~/.zshrc:"
        echo -e "  ${CYAN}export PATH=\"\$HOME/bin:\$PATH\"${NC}"
    fi

    info "Installing to $USER_BIN (user-local)..."
    install_to "$USER_BIN" ""

    info "Installing to $INSTALL_BIN (system-wide)..."
    install_to "$INSTALL_BIN" "sudo"

    ok "All available commands installed."
}

# =============================================================================
#  6. Summary
# =============================================================================
print_summary() {
    echo ""
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}   Vanilla_CLI Suite — Install Complete ${NC}"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════${NC}"
    echo ""
    echo -e "  Commands now available globally:"
    echo -e "  ${CYAN}abyss${NC}            — Text editor (C)"
    echo -e "  ${CYAN}compil${NC}           — Smart compiler/runner"
    echo -e "  ${CYAN}clip${NC}             — Copy file to clipboard"
    echo -e "  ${CYAN}wipe${NC}             — Clear file contents"
    echo -e "  ${CYAN}tree${NC}             — Directory tree view"
    echo -e "  ${CYAN}redem${NC}            — WiFi driver reset"
    echo -e "  ${CYAN}monitoring${NC}       — System dashboard"
    echo -e "  ${CYAN}wifi_monitoring${NC}  — Network monitor"
    echo -e "  ${CYAN}blackjack${NC}        — Blackjack game"
    echo -e "  ${CYAN}minesweeper${NC}      — Minesweeper game"
    echo ""
    echo -e "  Installed to:"
    echo -e "  ${CYAN}~/bin${NC}            (user-local)"
    echo -e "  ${CYAN}/usr/local/bin${NC}   (system-wide)"
    echo ""
}

# =============================================================================
#  Entry point
# =============================================================================
echo ""
echo -e "${BOLD}${CYAN}  🌌 Vanilla_CLI Suite — Installer${NC}"
echo -e "${CYAN}  ──────────────────────────────────${NC}"
echo ""

detect_pkg_manager
install_system_deps
install_python_deps
build_abyss
install_binaries
print_summary