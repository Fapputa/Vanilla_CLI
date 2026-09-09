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

# Le script tourne en root : $HOME vaut alors /root et l'installation
# "user-local" atterrirait dans /root/bin. On cible le vrai utilisateur.
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
[ -n "$REAL_HOME" ] || REAL_HOME="$HOME"
USER_BIN="$REAL_HOME/bin"

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
            python3-rich \
            python3-prompt-toolkit \
            python3-pygments \
            python3-psutil \
            xclip \
            xsel \
            wireless-tools \
            net-tools
    elif [ "$PKG_MANAGER" = "pacman" ]; then
        # -Syu et non -Sy : sur Arch, installer un paquet apres un simple -Sy
        # produit une mise a jour partielle (ex. python compile contre une glibc
        # plus recente que celle installee -> ImportError GLIBC_x.yz not found).
        # La base de donnees et le systeme doivent etre mis a jour ensemble.
        warn "Arch: a full system upgrade (-Syu) is required to install safely."
        pacman -Syu --needed --noconfirm \
            base-devel \
            ncurses \
            python \
            python-pip \
            python-rich \
            python-prompt_toolkit \
            python-pygments \
            python-psutil \
            xclip \
            xsel \
            wireless_tools \
            net-tools
    fi

    ok "System dependencies installed."
}

# ---------------------------------------------------------------------------
# Python dependencies
#
# Les paquets de la distribution sont installes ci-dessus : pip n'intervient
# qu'en dernier recours, uniquement pour ce qui manque encore. Lancer
# "pip install --break-system-packages" en root ecrase des fichiers geres par
# le gestionnaire de paquets et casse l'environnement Python du systeme.
# ---------------------------------------------------------------------------
install_python_deps() {
    info "Checking Python dependencies..."

    local py
    py="$(command -v python3 || command -v python)" \
        || { warn "No Python interpreter found, skipping Python dependencies."; return 0; }

    if ! "$py" -c 'import sys' &>/dev/null; then
        warn "$py is present but cannot run (broken installation?)."
        warn "Fix the system Python first, then re-run this installer."
        return 0
    fi

    declare -A PY_MODULES=(
        ["rich"]="rich"
        ["prompt_toolkit"]="prompt_toolkit"
        ["pygments"]="pygments"
        ["psutil"]="psutil"
    )

    local missing=()
    for mod in "${!PY_MODULES[@]}"; do
        if "$py" -c "import $mod" &>/dev/null; then
            ok "$mod already available."
        else
            missing+=("${PY_MODULES[$mod]}")
        fi
    done

    if [ ${#missing[@]} -eq 0 ]; then
        ok "All Python dependencies satisfied by system packages."
        return 0
    fi

    warn "Missing from system packages: ${missing[*]}"
    info "Falling back to pip for those only..."

    if ! command -v pip &>/dev/null && ! "$py" -m pip --version &>/dev/null; then
        warn "pip unavailable; install manually: ${missing[*]}"
        return 0
    fi

    if ! "$py" -m pip install --break-system-packages "${missing[@]}"; then
        warn "pip install failed. Install manually: ${missing[*]}"
    else
        ok "Python dependencies installed."
    fi
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
    chown -R "$REAL_USER" "$USER_BIN" 2>/dev/null || true

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
