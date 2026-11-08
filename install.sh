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

# Lance une commande en tant que vrai utilisateur (ou telle quelle sans sudo).
as_user() {
    if [ "$REAL_USER" != "root" ] && [ "$(id -u)" -eq 0 ]; then
        sudo -u "$REAL_USER" -- "$@"
    else
        "$@"
    fi
}

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
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"
        info "Package manager detected: dnf (Fedora/RHEL)"
    else
        fail "No supported package manager found (apt / pacman / dnf). Aborting."
    fi
}

# ---------------------------------------------------------------------------
# System dependencies
# ---------------------------------------------------------------------------
APT_PKGS=(
    build-essential libncurses-dev rustc cargo
    python3 python3-pip python3-rich python3-prompt-toolkit
    python3-pygments python3-psutil
    poppler-utils sqlite3 unzip xclip xsel wireless-tools net-tools
)

PACMAN_PKGS=(
    base-devel ncurses rust
    python python-pip python-rich python-prompt_toolkit
    python-pygments python-psutil
    poppler sqlite unzip xclip xsel wireless_tools net-tools
)

DNF_PKGS=(
    gcc gcc-c++ make ncurses-devel rust cargo
    python3 python3-pip python3-rich python3-prompt-toolkit
    python3-pygments python3-psutil
    poppler-utils sqlite unzip xclip xsel wireless-tools net-tools
)

# Seuls les paquets absents sont installes ; s'il n'en manque aucun, le
# gestionnaire de paquets n'est meme pas appele (ni update, ni upgrade).
install_system_deps() {
    info "Checking system dependencies..."

    local missing=()

    if [ "$PKG_MANAGER" = "apt" ]; then
        local p
        for p in "${APT_PKGS[@]}"; do
            dpkg-query -W -f='${Status}' "$p" 2>/dev/null \
                | grep -q "install ok installed" || missing+=("$p")
        done

        if [ ${#missing[@]} -eq 0 ]; then
            ok "All system dependencies already installed."
            return 0
        fi

        info "Missing: ${missing[*]}"
        apt-get update -qq
        apt-get install -y "${missing[@]}"

    elif [ "$PKG_MANAGER" = "pacman" ]; then
        # pacman -T affiche les paquets non satisfaits (rien si tout est la).
        mapfile -t missing < <(pacman -T "${PACMAN_PKGS[@]}" || true)

        if [ ${#missing[@]} -eq 0 ]; then
            ok "All system dependencies already installed."
            return 0
        fi

        info "Missing: ${missing[*]}"

        # Pas de -Sy (mise a jour partielle, non supportee sur Arch) et pas de
        # -Syu impose : on installe depuis la base locale, coherente avec le
        # systeme en place. Si les miroirs ont deja retire ces versions, c'est
        # a l'utilisateur de faire sa mise a jour quand il le decide.
        if ! pacman -S --needed --noconfirm "${missing[@]}"; then
            warn "Could not install from the current package database"
            warn "(it is probably older than the mirrors)."
            fail "Update your system when convenient (pacman -Syu), then re-run this installer."
        fi

    elif [ "$PKG_MANAGER" = "dnf" ]; then
        # rpm -q echoue pour chaque paquet non installe.
        local p
        for p in "${DNF_PKGS[@]}"; do
            rpm -q --quiet "$p" 2>/dev/null || missing+=("$p")
        done

        if [ ${#missing[@]} -eq 0 ]; then
            ok "All system dependencies already installed."
            return 0
        fi

        info "Missing: ${missing[*]}"

        # dnf install rafraichit lui-meme ses metadonnees si besoin ; pas de
        # upgrade impose du systeme.
        if ! dnf install -y "${missing[@]}"; then
            warn "dnf could not install some packages."
            fail "Check your repositories (dnf makecache), then re-run this installer."
        fi
    fi

    ok "System dependencies installed."
}

# ---------------------------------------------------------------------------
# Rust toolchain
#
# abyss compiles and runs .rs files with ^B (rustc, or cargo when the file
# belongs to a crate). The distribution package is installed above; this
# only reports what actually landed, and points at rustup otherwise.
# ---------------------------------------------------------------------------
check_rust() {
    info "Checking Rust toolchain..."

    if command -v rustc &>/dev/null; then
        ok "rustc $(rustc --version 2>/dev/null | awk '{print $2}') available."
    else
        warn "rustc not found after install."
        warn "Install it manually, or via rustup:"
        echo -e "  ${CYAN}curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh${NC}"
        return 0
    fi

    if command -v cargo &>/dev/null; then
        ok "cargo $(cargo --version 2>/dev/null | awk '{print $2}') available."
    else
        warn "cargo not found: .rs files inside a crate will not build with ^B."
    fi
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
    # Compile en tant que vrai utilisateur : sinon les .o et binaires du
    # dossier du projet appartiennent a root.
    if ! as_user make clean || ! as_user make; then
        fail "Build failed (see the compiler errors above). Nothing was installed."
    fi

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
    as_user mkdir -p "$USER_BIN"
    # Sous sudo, $PATH est celui de root (secure_path) : on regarde plutot si
    # les fichiers de config du shell de l'utilisateur ajoutent ~/bin.
    if ! cat "$REAL_HOME/.bashrc" "$REAL_HOME/.bash_profile" "$REAL_HOME/.profile" \
             "$REAL_HOME/.zshrc" "$REAL_HOME/.zprofile" 2>/dev/null \
            | grep -qE '(\$HOME|~|'"$REAL_HOME"')/bin'; then
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
    as_user make clean_obj
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
    echo -e "                     ^B compiles & runs C / C++ / Rust / ASM / C#"
    echo -e "                     ^B ^B (or F5) opens the build-flags menu"
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
check_rust
install_python_deps
build_all
install_binaries
cleanup_build
print_summary