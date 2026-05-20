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
# Chemins
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CMD_DIR="$SCRIPT_DIR/cmd"
BIN_DIR="$SCRIPT_DIR/cmd/bin"
SCRIPTS_DIR="$SCRIPT_DIR/scripts"

SYS_BIN="/usr/local/bin"
USER_BIN="$HOME/bin"

# ---------------------------------------------------------------------------
# Droits root
# ---------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
    fail "Ce script doit être exécuté en tant que root. Relancez avec : sudo $0"
fi

# ---------------------------------------------------------------------------
# Détection du gestionnaire de paquets
# ---------------------------------------------------------------------------
detect_pkg_manager() {
    if command -v apt &>/dev/null; then
        PKG_MANAGER="apt"
        info "Package manager détecté : apt (Debian/Ubuntu)"
    elif command -v pacman &>/dev/null; then
        PKG_MANAGER="pacman"
        info "Package manager détecté : pacman (Arch)"
    else
        fail "Aucun gestionnaire de paquets supporté (apt / pacman). Abandon."
    fi
}

# ---------------------------------------------------------------------------
# Dépendances système
# ---------------------------------------------------------------------------
install_system_deps() {
    info "Installation des dépendances système..."

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
            net-tools
    elif [ "$PKG_MANAGER" = "pacman" ]; then
        pacman -Sy --noconfirm \
            base-devel \
            ncurses \
            python \
            python-pip \
            xclip \
            xsel \
            net-tools
    fi

    ok "Dépendances système installées."
}

# ---------------------------------------------------------------------------
# Dépendances Python
# ---------------------------------------------------------------------------
install_python_deps() {
    info "Installation des dépendances Python..."

    pip install --break-system-packages \
        rich \
        prompt_toolkit \
        pygments \
        psutil

    ok "Dépendances Python installées."
}

# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------
build_all() {
    info "Compilation des binaires C..."

    [ -f "$SCRIPT_DIR/Makefile" ] || fail "Makefile introuvable dans $SCRIPT_DIR."

    cd "$SCRIPT_DIR"
    make clean && make

    ok "Compilation terminée."
}

# ---------------------------------------------------------------------------
# Installation vers une destination
# ---------------------------------------------------------------------------
install_to() {
    local dest="$1"
    mkdir -p "$dest"

    # --- Binaires compilés (racine du projet) ---
    for bin in abyss lsc lsc-config; do
        if [ -f "$SCRIPT_DIR/$bin" ]; then
            install -m 755 "$SCRIPT_DIR/$bin" "$dest/$bin"
            ok "$bin  ->  $dest/$bin"
        else
            warn "$bin introuvable, ignoré."
        fi
    done

    # --- Commandes shell : cmd/ ---
    for cmd in wipe clip compil redem tree; do
        if [ -f "$CMD_DIR/$cmd" ]; then
            install -m 755 "$CMD_DIR/$cmd" "$dest/$cmd"
            ok "$cmd  ->  $dest/$cmd"
        else
            warn "$cmd introuvable dans cmd/, ignoré."
        fi
    done

    # --- Jeux : cmd/bin/ ---
    for game in blackjack minesweeper; do
        if [ -f "$BIN_DIR/$game" ]; then
            install -m 755 "$BIN_DIR/$game" "$dest/$game"
            ok "$game  ->  $dest/$game"
        else
            warn "$game introuvable dans cmd/bin/, ignoré."
        fi
    done

    # --- Scripts Python : scripts/ (wrappers shell) ---
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
            warn "${PY_SCRIPTS[$cmd]} introuvable dans scripts/, ignoré."
        fi
    done
}

# ---------------------------------------------------------------------------
# Nettoyage des .o après installation
# ---------------------------------------------------------------------------
cleanup_objects() {
    info "Suppression des fichiers objets (.o)..."
    cd "$SCRIPT_DIR"
    make clean_obj
    ok "Fichiers .o supprimés."
}

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
install_binaries() {
    # user-local
    mkdir -p "$USER_BIN"
    if [[ ":$PATH:" != *":$USER_BIN:"* ]]; then
        warn "$USER_BIN n'est pas dans votre PATH. Ajoutez à ~/.bashrc ou ~/.zshrc :"
        echo -e "  ${CYAN}export PATH=\"\$HOME/bin:\$PATH\"${NC}"
    fi

    info "Installation dans $USER_BIN (utilisateur)..."
    install_to "$USER_BIN"

    info "Installation dans $SYS_BIN (système)..."
    install_to "$SYS_BIN"

    ok "Toutes les commandes disponibles ont été installées."
}

# ---------------------------------------------------------------------------
# Résumé
# ---------------------------------------------------------------------------
print_summary() {
    echo ""
    echo -e "${BOLD}${GREEN}=======================================${NC}"
    echo -e "${BOLD}${GREEN}   Vanilla_CLI Suite - Installation OK ${NC}"
    echo -e "${BOLD}${GREEN}=======================================${NC}"
    echo ""
    echo -e "  Commandes disponibles globalement :"
    echo -e "  ${CYAN}abyss${NC}            - Éditeur de texte (C)"
    echo -e "  ${CYAN}compil${NC}           - Compilateur/runner intelligent"
    echo -e "  ${CYAN}clip${NC}             - Copie un fichier dans le presse-papier"
    echo -e "  ${CYAN}wipe${NC}             - Vide le contenu d'un fichier"
    echo -e "  ${CYAN}tree${NC}             - Vue arborescente d'un répertoire"
    echo -e "  ${CYAN}redem${NC}            - Reset pilote WiFi"
    echo -e "  ${CYAN}monitoring${NC}       - Dashboard système"
    echo -e "  ${CYAN}wifi_monitoring${NC}  - Moniteur réseau"
    echo -e "  ${CYAN}blackjack${NC}        - Jeu Blackjack"
    echo -e "  ${CYAN}minesweeper${NC}      - Jeu Démineur"
    echo -e "  ${CYAN}lsc${NC}              - ls avec couleurs custom (~/.colorrc)"
    echo -e "  ${CYAN}lsc-config${NC}       - Éditeur TUI pour les règles lsc"
    echo ""
    echo -e "  Installé dans :"
    echo -e "  ${CYAN}~/bin${NC}            (utilisateur)"
    echo -e "  ${CYAN}/usr/local/bin${NC}   (système)"
    echo ""
    echo -e "  Tip — ajoutez à ~/.bashrc pour remplacer ls :"
    echo -e "  ${CYAN}alias ls='lsc'${NC}"
    echo -e "  ${CYAN}alias lsconfig='lsc-config'${NC}"
    echo ""
}

# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}${CYAN}  Vanilla_CLI Suite - Installeur${NC}"
echo -e "${CYAN}  --------------------------------${NC}"
echo ""

detect_pkg_manager
install_system_deps
install_python_deps
build_all
install_binaries
cleanup_objects
print_summary
