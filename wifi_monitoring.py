#!/usr/bin/env python3
import os
import sys
import re
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

# Cache global pour les données statiques uniquement
_static_cache = {}


def get_screen_info():
    """Récupère résolution et fréquence via xrandr - CACHED"""
    if 'screen' in _static_cache:
        return _static_cache['screen']

    try:
        result = subprocess.run(['xrandr'], capture_output=True, text=True, timeout=2)
        lines = result.stdout.split('\n')
        in_connected = False

        for line in lines:
            if ' connected' in line:
                in_connected = True
                continue

            if in_connected:
                # Ligne de mode : "   1920x1080     60.03*+  50.00  ..."
                if line.startswith('   ') or line.startswith('\t'):
                    parts = line.split()
                    if not parts:
                        continue
                    res_candidate = parts[0]
                    if re.match(r'^\d+x\d+$', res_candidate):
                        for hz_part in parts[1:]:
                            clean = hz_part.replace('*', '').replace('+', '').strip()
                            if re.match(r'^\d+(\.\d+)?$', clean) and '*' in hz_part:
                                hz = clean
                                _static_cache['screen'] = (res_candidate, hz)
                                return res_candidate, hz
                else:
                    in_connected = False

    except Exception:
        pass

    _static_cache['screen'] = ("Unknown", "Unknown")
    return "Unknown", "Unknown"


def create_network_blocks():
    """Affiche les connexions réseau actives en blocs avec bordures"""
    text = Text()
    text.append("NETWORK CONNECTIONS\n\n", style="bold bright_red")

    connections = []
    try:
        result = subprocess.run(
            ['ss', '-tunH'],
            capture_output=True,
            text=True,
            timeout=0.5
        )

        for line in result.stdout.strip().split('\n')[:8]:
            if not line or 'ESTAB' not in line:
                continue

            parts = line.split()
            if len(parts) < 6:
                continue

            proto = parts[0].upper()
            local_parts = parts[4].rsplit(':', 1)
            remote_parts = parts[5].rsplit(':', 1)

            local_ip = local_parts[0].split('%')[0] if local_parts else "N/A"
            local_port = int(local_parts[1]) if len(local_parts) > 1 else 0
            remote_ip = remote_parts[0].split('%')[0] if remote_parts else "N/A"
            remote_port = int(remote_parts[1]) if len(remote_parts) > 1 else 0

            # Ignorer IPv6
            if ':' in local_ip or ':' in remote_ip or '[' in local_ip:
                continue

            connections.append({
                'local': local_ip,
                'local_port': local_port,
                'remote': remote_ip,
                'remote_port': remote_port,
                'proto': proto,
            })
    except Exception:
        pass

    for conn in connections[:8]:
        text.append("╔════════════════════════════════════╗\n", style="bold bright_red")

        in_str = f"IN:  {conn['remote']:15s}:{conn['remote_port']:<5d}"
        text.append("║ ", style="bold bright_red")
        text.append(f"{in_str:<35s}", style="")
        text.append("║\n", style="bold bright_red")

        out_str = f"OUT: {conn['local']:15s}:{conn['local_port']:<5d}"
        text.append("║ ", style="bold bright_red")
        text.append(f"{out_str:<35s}", style="")
        text.append("║\n", style="bold bright_red")

        proto_str = f"PROTO: {conn['proto']:4s}"
        text.append("║ ", style="bold bright_red")
        text.append(f"{proto_str:<35s}", style="")
        text.append("║\n", style="bold bright_red")

        text.append("╚════════════════════════════════════╝\n\n", style="bold bright_red")

    if not connections:
        text.append("╔════════════════════════════════════╗\n", style="bold bright_red")
        text.append("║ ", style="bold bright_red")
        text.append(f"{'No active connections':<35s}", style="dim white")
        text.append("║\n", style="bold bright_red")
        text.append("╚════════════════════════════════════╝\n", style="bold bright_red")

    return text


def get_disk_info():
    """Récupère les informations sur les disques (temps réel, non caché)"""
    disks = []
    try:
        if not os.path.exists('/sys/block'):
            return disks

        disk_devices = sorted(d for d in os.listdir('/sys/block') if d.startswith('sd'))

        mounts = {}
        try:
            with open('/proc/mounts', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3 and parts[0].startswith('/dev/sd'):
                        device, mountpoint, fstype = parts[0], parts[1], parts[2]
                        if 'snap' not in mountpoint:
                            mounts[device] = f"{mountpoint} ({fstype})"
        except Exception:
            pass

        for disk in disk_devices:
            try:
                size_path = f'/sys/block/{disk}/size'
                size_gb = 0
                if os.path.exists(size_path):
                    with open(size_path, 'r') as f:
                        sectors = int(f.read().strip())
                        size_gb = (sectors * 512) / (1024 ** 3)

                mount_info = [
                    mount_str for device, mount_str in mounts.items()
                    if device.startswith('/dev/' + disk)
                ]

                disks.append({
                    'name': disk,
                    'size': size_gb,
                    'mounts': mount_info if mount_info else ['Not mounted']
                })
            except Exception:
                continue
    except Exception:
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
            out = subprocess.run(['dpkg', '-l'], capture_output=True, text=True, timeout=2)
            count = sum(1 for l in out.stdout.split('\n') if l.startswith('ii'))
            result = (count, "dpkg")
        elif os.path.exists('/usr/bin/rpm'):
            out = subprocess.run(['rpm', '-qa'], capture_output=True, text=True, timeout=2)
            count = len(out.stdout.strip().split('\n'))
            result = (count, "rpm")
        else:
            result = (0, "unknown")
    except Exception:
        result = (0, "unknown")

    _static_cache['packages'] = result
    return result


def get_python_version():
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def get_desktop_environment():
    desktop = os.environ.get('XDG_CURRENT_DESKTOP', 'Unknown')
    session = os.environ.get('DESKTOP_SESSION', 'Unknown')
    if desktop == 'Unknown' and session != 'Unknown':
        return session
    return desktop


def get_shell():
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
    except Exception:
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
    except Exception:
        pass

    os_name = platform.system()
    _static_cache['os_name'] = os_name
    return os_name


def fmt(text, width=40):
    """Tronque et padde un texte à la largeur donnée"""
    if len(text) > width:
        text = text[:width - 3] + "..."
    return text + " " * max(0, width - len(text))


def create_system_info():
    """Infos système détaillées"""
    text = Text()
    text.append("SYSTEM INFORMATION\n\n", style="bold bright_red")

    W = 40

    def row(label, value, style="bright_white"):
        line = f"{label:<13s}{value}"
        text.append(fmt(line, W) + "\n", style=style)

    pkg_count, pkg_manager = get_installed_packages()
    row("Packages:", f"{pkg_count} ({pkg_manager})")
    row("Python:", get_python_version())
    row("Arch:", platform.machine())
    row("OS:", get_os_name())
    row("Kernel:", platform.release())
    row("DE:", get_desktop_environment())

    res, hz = get_screen_info()
    row("Display:", f"{res} @ {hz}Hz")

    row("Shell:", get_shell())

    term = os.environ.get('TERM_PROGRAM', os.environ.get('TERM', 'Unknown'))
    row("Terminal:", term)

    boot_time = psutil.boot_time()
    uptime_seconds = time.time() - boot_time
    uptime_hours = int(uptime_seconds // 3600)
    uptime_minutes = int((uptime_seconds % 3600) // 60)
    row("Uptime:", f"{uptime_hours}h {uptime_minutes}m")

    cpu_model = get_cpu_model()
    row("CPU:", cpu_model[:25])

    cpu_count = psutil.cpu_count(logical=False)
    cpu_threads = psutil.cpu_count(logical=True)
    row("Cores:", f"{cpu_count} cores / {cpu_threads} threads")

    mem = psutil.virtual_memory()
    row("RAM:", f"{mem.total // (1024 ** 3)}GB")

    row("Hostname:", socket.gethostname())

    if 'local_ip' not in _static_cache:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.2)
            s.connect(("8.8.8.8", 80))
            _static_cache['local_ip'] = s.getsockname()[0]
            s.close()
        except Exception:
            _static_cache['local_ip'] = "Unknown"
    row("Local IP:", _static_cache['local_ip'])

    text.append("\n", style="")
    text.append("STORAGE DEVICES\n", style="bold bright_red")
    text.append("─" * W + "\n", style="bright_red")

    disks = get_disk_info()
    if disks:
        for i in range(0, len(disks), 2):
            left = disks[i]
            right = disks[i + 1] if i + 1 < len(disks) else None

            left_header = f"{left['name']:4s} {left['size']:6.1f}GB"
            if right:
                right_header = f"{right['name']:4s} {right['size']:6.1f}GB"
                header_line = f"{left_header:<20s}{right_header}"
            else:
                header_line = left_header

            text.append(fmt(header_line, W) + "\n", style="bright_yellow")

            left_mount = left['mounts'][0][:15] if left['mounts'] else 'Not mounted'
            left_mount_line = f"└─{left_mount}"

            if right:
                right_mount = right['mounts'][0][:15] if right['mounts'] else 'Not mounted'
                mount_line = f"{left_mount_line:<20s}└─{right_mount}"
            else:
                mount_line = left_mount_line

            text.append(fmt(mount_line, W) + "\n", style="dim white")
    else:
        text.append(fmt("No disks detected", W) + "\n", style="dim white")

    return text


def generate_layout():
    """Génère le layout complet (réseau + système)"""
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
    print("\033[?25l", end='', flush=True)  # Cacher le curseur

    try:
        with Live(generate_layout(), refresh_per_second=0.5, screen=False) as live:
            while True:
                time.sleep(2)
                live.update(generate_layout())
    except KeyboardInterrupt:
        pass
    finally:
        print("\033[?25h", end='', flush=True)  
        os.system('clear')


if __name__ == "__main__":
    main()
