#!/usr/bin/env python3
import os
import sys
import time
import psutil
import platform
import socket
import subprocess
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live

console = Console()

# Cache global pour éviter les appels système répétés
# SEULEMENT pour les données vraiment statiques
_static_cache = {}

def get_screen_info():
    """Récupère les infos d'écran (résolution et Hz) - CACHED"""
    if 'screen' in _static_cache:
        return _static_cache['screen']
    
    try:
        result = subprocess.run(['xrandr'], capture_output=True, text=True, timeout=0.5)
        for line in result.stdout.split('\n'):
            if ' connected' in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if 'x' in part and i + 1 < len(parts):
                        res = part
                        hz_part = parts[i + 1]
                        if '*' in hz_part:
                            hz = hz_part.replace('*', '').replace('+', '')
                            _static_cache['screen'] = (res, hz)
                            return res, hz
    except:
        pass
    
    _static_cache['screen'] = ("Unknown", "Unknown")
    return "Unknown", "Unknown"

def create_network_blocks():
    """Affiche les connexions en blocs avec bordures"""
    text = Text()
    text.append("NETWORK CONNECTIONS\n\n", style="bold bright_red")
    
    connections = []
    try:
        # Utiliser ss avec timeout très court
        result = subprocess.run(['ss', '-tunH'], 
                              capture_output=True, 
                              text=True, 
                              timeout=0.3)
        
        for line in result.stdout.strip().split('\n')[:8]:
            if not line or 'ESTAB' not in line:
                continue
            
            parts = line.split()
            if len(parts) < 6:
                continue
            
            proto = parts[0].upper()
            local_parts = parts[4].rsplit(':', 1)
            remote_parts = parts[5].rsplit(':', 1)
            
            # Nettoyer les IP (enlever %interface comme %wlo1)
            local_ip = local_parts[0].split('%')[0] if local_parts else "N/A"
            local_port = int(local_parts[1]) if len(local_parts) > 1 else 0
            remote_ip = remote_parts[0].split('%')[0] if remote_parts else "N/A"
            remote_port = int(remote_parts[1]) if len(remote_parts) > 1 else 0
            
            if ':' in local_ip or ':' in remote_ip or '[' in local_ip:
                continue
            
            connections.append({
                'local': local_ip,
                'local_port': local_port,
                'remote': remote_ip,
                'remote_port': remote_port,
                'proto': proto,
                'size': 0
            })
    except:
        pass
    
    for i, conn in enumerate(connections[:8]):
        text.append("╔════════════════════════════════════╗\n", style="bold bright_red")
        
        in_str = f"IN:  {conn['remote']:15s}:{conn['remote_port']:<5d}"
        spaces_needed = 35 - len(in_str)
        text.append("║ ", style="bold bright_red")
        text.append(in_str, style="")
        text.append(" " * spaces_needed, style="")
        text.append("║\n", style="bold bright_red")
        
        out_str = f"OUT: {conn['local']:15s}:{conn['local_port']:<5d}"
        spaces_needed = 35 - len(out_str)
        text.append("║ ", style="bold bright_red")
        text.append(out_str, style="")
        text.append(" " * spaces_needed, style="")
        text.append("║\n", style="bold bright_red")
        
        proto_str = f"PROTO: {conn['proto']:4s}  SIZE: {conn['size']:4d}KB"
        spaces_needed = 35 - len(proto_str)
        text.append("║ ", style="bold bright_red")
        text.append(proto_str, style="")
        text.append(" " * spaces_needed, style="")
        text.append("║\n", style="bold bright_red")
        
        text.append("╚════════════════════════════════════╝\n\n", style="bold bright_red")
    
    if len(connections) == 0:
        text.append("╔════════════════════════════════════╗\n", style="bold bright_red")
        text.append("║ ", style="bold bright_red")
        text.append("No active connections             ", style="dim white")
        text.append("║\n", style="bold bright_red")
        text.append("╚════════════════════════════════════╝\n", style="bold bright_red")
    
    return text

def get_disk_info():
    """Récupère les informations sur les disques - ACTUALISÉ à chaque appel"""
    disks = []
    try:
        if os.path.exists('/sys/block'):
            disk_devices = [d for d in os.listdir('/sys/block') if d.startswith('sd')]
            disk_devices.sort()
            
            # Lire /proc/mounts directement
            mounts = {}
            try:
                with open('/proc/mounts', 'r') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 3 and parts[0].startswith('/dev/sd'):
                            device = parts[0]
                            mountpoint = parts[1]
                            fstype = parts[2]
                            if 'snap' not in mountpoint:
                                mounts[device] = f"{mountpoint} ({fstype})"
            except:
                pass
            
            for disk in disk_devices:
                try:
                    size_path = f'/sys/block/{disk}/size'
                    if os.path.exists(size_path):
                        with open(size_path, 'r') as f:
                            sectors = int(f.read().strip())
                            size_gb = (sectors * 512) / (1024**3)
                    else:
                        size_gb = 0
                    
                    # Trouver les montages pour ce disque
                    mount_info = []
                    for device, mount_str in mounts.items():
                        if device.startswith('/dev/' + disk):
                            mount_info.append(mount_str)
                    
                    disks.append({
                        'name': disk,
                        'size': size_gb,
                        'mounts': mount_info if mount_info else ['Not mounted']
                    })
                except:
                    continue
    except:
        pass
    
    return disks

def get_installed_packages():
    """Compte les paquets installés - CACHED"""
    if 'packages' in _static_cache:
        return _static_cache['packages']
    
    try:
        if os.path.exists('/var/lib/pacman/local'):
            count = len(os.listdir('/var/lib/pacman/local')) - 1
            result = (count, "pacman")
        elif os.path.exists('/usr/bin/dpkg'):
            result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True, timeout=1)
            count = len([l for l in result.stdout.split('\n') if l.startswith('ii')])
            result = (count, "dpkg")
        elif os.path.exists('/usr/bin/rpm'):
            result = subprocess.run(['rpm', '-qa'], capture_output=True, text=True, timeout=1)
            count = len(result.stdout.strip().split('\n'))
            result = (count, "rpm")
        else:
            result = (0, "unknown")
    except:
        result = (0, "unknown")
    
    _static_cache['packages'] = result
    return result

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

def get_cpu_model():
    """Récupère le modèle CPU - CACHED"""
    if 'cpu_model' in _static_cache:
        return _static_cache['cpu_model']
    
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if 'model name' in line:
                    cpu_model = line.split(':')[1].strip()
                    _static_cache['cpu_model'] = cpu_model
                    return cpu_model
    except:
        pass
    
    _static_cache['cpu_model'] = "Unknown"
    return "Unknown"

def get_os_name():
    """Récupère le nom de l'OS - CACHED"""
    if 'os_name' in _static_cache:
        return _static_cache['os_name']
    
    try:
        with open('/etc/os-release', 'r') as f:
            for line in f:
                if line.startswith('PRETTY_NAME'):
                    os_name = line.split('=')[1].strip().strip('"')
                    _static_cache['os_name'] = os_name
                    return os_name
    except:
        pass
    
    os_name = platform.system()
    _static_cache['os_name'] = os_name
    return os_name

def create_system_info():
    """Infos système détaillées"""
    text = Text()
    text.append("SYSTEM INFORMATION\n\n", style="bold bright_red")
    
    pkg_count, pkg_manager = get_installed_packages()
    pkg_text = f"Packages:    {pkg_count} ({pkg_manager})"
    spaces = max(0, 40 - len(pkg_text))
    text.append(pkg_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    py_text = f"Python:      {get_python_version()}"
    spaces = max(0, 40 - len(py_text))
    text.append(py_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    arch = platform.machine()
    arch_text = f"Arch:        {arch}"
    spaces = max(0, 40 - len(arch_text))
    text.append(arch_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    os_name = get_os_name()
    os_text = f"OS:          {os_name}"
    if len(os_text) > 40:
        os_text = os_text[:37] + "..."
    spaces = max(0, 40 - len(os_text))
    text.append(os_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    kernel = platform.release()
    kernel_text = f"Kernel:      {kernel}"
    if len(kernel_text) > 40:
        kernel_text = kernel_text[:37] + "..."
    spaces = max(0, 40 - len(kernel_text))
    text.append(kernel_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    de = get_desktop_environment()
    de_text = f"DE:          {de}"
    if len(de_text) > 40:
        de_text = de_text[:37] + "..."
    spaces = max(0, 40 - len(de_text))
    text.append(de_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    res, hz = get_screen_info()
    display_text = f"Display:     {res} @ {hz}Hz"
    if len(display_text) > 40:
        display_text = display_text[:37] + "..."
    spaces = max(0, 40 - len(display_text))
    text.append(display_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    shell = get_shell()
    shell_text = f"Shell:       {shell}"
    spaces = max(0, 40 - len(shell_text))
    text.append(shell_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
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
    
    cpu_model = get_cpu_model()
    cpu_text = f"CPU:         {cpu_model[:25]}"
    if len(cpu_text) > 40:
        cpu_text = cpu_text[:37] + "..."
    spaces = max(0, 40 - len(cpu_text))
    text.append(cpu_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    cpu_count = psutil.cpu_count(logical=False)
    cpu_threads = psutil.cpu_count(logical=True)
    cores_text = f"Cores:       {cpu_count} cores / {cpu_threads} threads"
    if len(cores_text) > 40:
        cores_text = cores_text[:37] + "..."
    spaces = max(0, 40 - len(cores_text))
    text.append(cores_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    mem = psutil.virtual_memory()
    ram_text = f"RAM:         {mem.total // (1024**3)}GB"
    spaces = max(0, 40 - len(ram_text))
    text.append(ram_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    hostname = socket.gethostname()
    host_text = f"Hostname:    {hostname}"
    if len(host_text) > 40:
        host_text = host_text[:37] + "..."
    spaces = max(0, 40 - len(host_text))
    text.append(host_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    # IP locale - utiliser cache
    if 'local_ip' not in _static_cache:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.1)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            _static_cache['local_ip'] = local_ip
        except:
            _static_cache['local_ip'] = "Unknown"
    
    local_ip = _static_cache['local_ip']
    ip_text = f"Local IP:    {local_ip}"
    spaces = max(0, 40 - len(ip_text))
    text.append(ip_text, style="bright_white")
    text.append(" " * spaces + "\n", style="")
    
    text.append("\n", style="")
    text.append("STORAGE DEVICES\n", style="bold bright_red")
    text.append("─" * 40 + "\n", style="bright_red")
    
    # Appel direct sans cache - actualisation en temps réel
    disks = get_disk_info()
    if disks:
        for i in range(0, len(disks), 2):
            left_disk = disks[i]
            right_disk = disks[i + 1] if i + 1 < len(disks) else None
            
            left_header = f"{left_disk['name']:4s} {left_disk['size']:6.1f}GB"
            if right_disk:
                right_header = f"{right_disk['name']:4s} {right_disk['size']:6.1f}GB"
                header_line = f"{left_header:20s}{right_header}"
            else:
                header_line = left_header
            
            spaces = max(0, 40 - len(header_line))
            text.append(header_line, style="bright_yellow")
            text.append(" " * spaces + "\n", style="")
            
            left_mounts = left_disk['mounts'][0] if left_disk['mounts'] else 'Not mounted'
            left_mount_line = f"└─{left_mounts[:15]}"
            
            if right_disk:
                right_mounts = right_disk['mounts'][0] if right_disk['mounts'] else 'Not mounted'
                right_mount_line = f"└─{right_mounts[:15]}"
                mount_line = f"{left_mount_line:20s}{right_mount_line}"
            else:
                mount_line = left_mount_line
            
            spaces = max(0, 40 - len(mount_line))
            text.append(mount_line, style="dim white")
            text.append(" " * spaces + "\n", style="")
    else:
        no_disk_text = "No disks detected"
        spaces = max(0, 40 - len(no_disk_text))
        text.append(no_disk_text, style="dim white")
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
        with Live(generate_layout(), refresh_per_second=0.5, screen=False) as live:
            while True:
                time.sleep(2)
                live.update(generate_layout())
    except KeyboardInterrupt:
        print("\033[?25h")
        os.system('clear')

if __name__ == "__main__":
    main()