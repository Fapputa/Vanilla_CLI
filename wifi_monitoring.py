#!/usr/bin/env python3
import os
import sys
import time
import psutil
import platform
import socket
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live

console = Console()

def get_screen_info():
    """Récupère les infos d'écran (résolution et Hz)"""
    try:
        xrandr = os.popen('xrandr 2>/dev/null | grep " connected" | head -1').read()
        if xrandr:
            parts = xrandr.split()
            for i, part in enumerate(parts):
                if 'x' in part and i + 1 < len(parts):
                    res = part
                    hz_part = parts[i + 1]
                    if '*' in hz_part:
                        hz = hz_part.replace('*', '').replace('+', '')
                        return res, hz
        return "Unknown", "Unknown"
    except:
        return "Unknown", "Unknown"

def create_network_blocks():
    """Affiche les connexions en blocs avec bordures"""
    text = Text()
    text.append("NETWORK CONNECTIONS\n\n", style="bold bright_red")
    
    # Récupérer les connexions IPv4 uniquement
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED':
                local_ip = conn.laddr.ip if conn.laddr else "N/A"
                local_port = conn.laddr.port if conn.laddr else 0
                remote_ip = conn.raddr.ip if conn.raddr else "N/A"
                remote_port = conn.raddr.port if conn.raddr else 0
                
                # Filtrer IPv6
                if ':' in local_ip or ':' in remote_ip:
                    continue
                
                # Protocole
                proto = "TCP" if conn.type == 1 else "UDP"
                
                # Simuler taille (en KB)
                size = 0
                
                connections.append({
                    'local': local_ip,
                    'local_port': local_port,
                    'remote': remote_ip,
                    'remote_port': remote_port,
                    'proto': proto,
                    'size': size
                })
    except:
        pass
    
    # Afficher chaque connexion comme un bloc
    for i, conn in enumerate(connections[:8]):  # Limiter à 8 pour l'espace
        # Bordure supérieure
        text.append("╔════════════════════════════════════╗\n", style="bold bright_red")
        
        # Ligne 1: IN - calculer précisément
        in_str = f"IN:  {conn['remote']:15s}:{conn['remote_port']:<5d}"
        spaces_needed = 35 - len(in_str)
        text.append("║ ", style="bold bright_red")
        text.append(in_str, style="")
        text.append(" " * spaces_needed, style="")
        text.append("║\n", style="bold bright_red")
        
        # Ligne 2: OUT
        out_str = f"OUT: {conn['local']:15s}:{conn['local_port']:<5d}"
        spaces_needed = 35 - len(out_str)
        text.append("║ ", style="bold bright_red")
        text.append(out_str, style="")
        text.append(" " * spaces_needed, style="")
        text.append("║\n", style="bold bright_red")
        
        # Ligne 3: PROTO et SIZE
        proto_str = f"PROTO: {conn['proto']:4s}  SIZE: {conn['size']:4d}KB"
        spaces_needed = 35 - len(proto_str)
        text.append("║ ", style="bold bright_red")
        text.append(proto_str, style="")
        text.append(" " * spaces_needed, style="")
        text.append("║\n", style="bold bright_red")
        
        # Bordure inférieure
        text.append("╚════════════════════════════════════╝\n\n", style="bold bright_red")
    
    if len(connections) == 0:
        text.append("╔═══════════════════════════════════╗\n", style="bold bright_red")
        text.append("║ ", style="bold bright_red")
        text.append("No active connections             ", style="dim white")
        text.append("║\n", style="bold bright_red")
        text.append("╚═══════════════════════════════════╝\n", style="bold bright_red")
    
    return text

def get_installed_packages():
    """Compte les paquets installés"""
    try:
        # Debian/Ubuntu
        if os.path.exists('/usr/bin/dpkg'):
            result = os.popen('dpkg -l 2>/dev/null | grep "^ii" | wc -l').read()
            count = int(result.strip())
            return count, "dpkg"
        # Arch
        elif os.path.exists('/usr/bin/pacman'):
            if os.path.exists('/var/lib/pacman/local'):
                count = len(os.listdir('/var/lib/pacman/local')) - 1
                return count, "pacman"
        # Fedora/RHEL
        elif os.path.exists('/usr/bin/rpm'):
            result = os.popen('rpm -qa 2>/dev/null | wc -l').read()
            count = int(result.strip())
            return count, "rpm"
    except:
        pass
    return 0, "unknown"

def get_python_version():
    """Version Python"""
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

def get_desktop_environment():
    """Détecte l'environnement graphique"""
    desktop = os.environ.get('XDG_CURRENT_DESKTOP', 'Unknown')
    session = os.environ.get('DESKTOP_SESSION', 'Unknown')
    
    if desktop == 'Unknown' and session != 'Unknown':
        return session
    return desktop

def get_shell():
    """Détecte le shell utilisé"""
    shell = os.environ.get('SHELL', 'Unknown')
    return os.path.basename(shell)

def create_system_info():
    """Infos système détaillées"""
    text = Text()
    text.append("SYSTEM INFORMATION\n\n", style="bold bright_red")
    
    # Paquets installés (CORRECTION: aligner sur 40 caractères pour la largeur de la boîte)
    pkg_count, pkg_manager = get_installed_packages()
    pkg_text = f"Packages:    {pkg_count} ({pkg_manager})"
    # Calculer l'espace nécessaire pour atteindre 40 caractères au total
    spaces = max(0, 40 - len(pkg_text))
    text.append(pkg_text, style="bright_white")
    text.append(" " * spaces, style="")
    text.append("\n", style="")
    
    # Version Python
    py_text = f"Python:      {get_python_version()}"
    spaces = max(0, 40 - len(py_text))
    text.append(py_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    # Architecture
    arch = platform.machine()
    arch_text = f"Arch:        {arch}"
    spaces = max(0, 40 - len(arch_text))
    text.append(arch_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    # OS
    try:
        with open('/etc/os-release', 'r') as f:
            for line in f:
                if line.startswith('PRETTY_NAME'):
                    os_name = line.split('=')[1].strip().strip('"')
                    break
            else:
                os_name = platform.system()
    except:
        os_name = platform.system()
    
    os_text = f"OS:          {os_name}"
    # Tronquer si trop long
    if len(os_text) > 40:
        os_text = os_text[:37] + "..."
    spaces = max(0, 40 - len(os_text))
    text.append(os_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    # Kernel
    kernel = platform.release()
    kernel_text = f"Kernel:      {kernel}"
    if len(kernel_text) > 40:
        kernel_text = kernel_text[:37] + "..."
    spaces = max(0, 40 - len(kernel_text))
    text.append(kernel_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    # Desktop Environment
    de = get_desktop_environment()
    de_text = f"DE:          {de}"
    if len(de_text) > 40:
        de_text = de_text[:37] + "..."
    spaces = max(0, 40 - len(de_text))
    text.append(de_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    # Écran (résolution et Hz)
    res, hz = get_screen_info()
    display_text = f"Display:     {res} @ {hz}Hz"
    if len(display_text) > 40:
        display_text = display_text[:37] + "..."
    spaces = max(0, 40 - len(display_text))
    text.append(display_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    # Shell
    shell = get_shell()
    shell_text = f"Shell:       {shell}"
    spaces = max(0, 40 - len(shell_text))
    text.append(shell_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    # Terminal
    term = os.environ.get('TERM', 'Unknown')
    term_program = os.environ.get('TERM_PROGRAM', term)
    term_text = f"Terminal:    {term_program}"
    if len(term_text) > 40:
        term_text = term_text[:37] + "..."
    spaces = max(0, 40 - len(term_text))
    text.append(term_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    # Uptime
    boot_time = psutil.boot_time()
    uptime_seconds = time.time() - boot_time
    uptime_hours = int(uptime_seconds // 3600)
    uptime_minutes = int((uptime_seconds % 3600) // 60)
    
    uptime_text = f"\nUptime:      {uptime_hours}h {uptime_minutes}m"
    spaces = max(0, 40 - len(uptime_text.replace("\n", "")))
    text.append(uptime_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    # CPU Info
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if 'model name' in line:
                    cpu_model = line.split(':')[1].strip()
                    break
            else:
                cpu_model = "Unknown"
    except:
        cpu_model = "Unknown"
    
    cpu_text = f"CPU:         {cpu_model[:25]}"
    if len(cpu_text) > 40:
        cpu_text = cpu_text[:37] + "..."
    spaces = max(0, 40 - len(cpu_text))
    text.append(cpu_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    # CPU Cores
    cpu_count = psutil.cpu_count(logical=False)
    cpu_threads = psutil.cpu_count(logical=True)
    cores_text = f"Cores:       {cpu_count} cores / {cpu_threads} threads"
    if len(cores_text) > 40:
        cores_text = cores_text[:37] + "..."
    spaces = max(0, 40 - len(cores_text))
    text.append(cores_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    # RAM Total
    mem = psutil.virtual_memory()
    ram_text = f"RAM:         {mem.total // (1024**3)}GB"
    spaces = max(0, 40 - len(ram_text))
    text.append(ram_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    # Hostname
    hostname = socket.gethostname()
    host_text = f"Hostname:    {hostname}"
    if len(host_text) > 40:
        host_text = host_text[:37] + "..."
    spaces = max(0, 40 - len(host_text))
    text.append(host_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    # IP locale
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "Unknown"
    
    ip_text = f"Local IP:    {local_ip}"
    spaces = max(0, 40 - len(ip_text))
    text.append(ip_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    return text

def generate_layout():
    """Layout complet"""
    
    net_panel = Panel(
        create_network_blocks(),
        border_style="bold bright_red",
        padding=(0, 1)
    )
    
    sys_panel = Panel(
        create_system_info(),
        border_style="bold bright_red",
        padding=(0, 1)
    )
    
    layout = Layout()
    
    layout.split_row(
        Layout(net_panel, name="network", ratio=1),
        Layout(sys_panel, name="sysinfo", ratio=1)
    )
    
    return layout

def main():
    os.system('clear')
    print("\033[?25l")
    
    try:
        with Live(generate_layout(), refresh_per_second=1, screen=False) as live:
            while True:
                time.sleep(2)
                live.update(generate_layout())
    except KeyboardInterrupt:
        print("\033[?25h")
        os.system('clear')

if __name__ == "__main__":
    main()
