#!/usr/bin/env python3
import os
import time
import subprocess
import psutil
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live

console = Console()

# Historique utilisation GPU pour graphique défilant
GRAPH_SIZE = 28
_latency_history = []

def get_system_volume():
    """Récupère le volume système via amixer ou pactl"""
    try:
        result = subprocess.run(
            ['pactl', 'get-sink-volume', '@DEFAULT_SINK@'],
            capture_output=True, text=True, timeout=0.3
        )
        if result.returncode == 0:
            for part in result.stdout.split():
                if part.endswith('%'):
                    return float(part.replace('%', ''))
    except:
        pass
    try:
        result = subprocess.run(
            ['amixer', 'get', 'Master'],
            capture_output=True, text=True, timeout=0.3
        )
        for line in result.stdout.split('\n'):
            if '%' in line and ('Playback' in line or 'Front Left' in line):
                import re
                m = re.search(r'\[(\d+)%\]', line)
                if m:
                    return float(m.group(1))
    except:
        pass
    return 0.0

def get_network_latency():
    """Mesure la latence réseau : ping ICMP en priorité, fallback TCP socket"""
    import re, socket, time as _time

    # 1) ping ICMP classique
    try:
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '1', '1.1.1.1'],
            capture_output=True, text=True, timeout=3
        )
        output = result.stdout + result.stderr
        for line in output.split('\n'):
            if 'time=' in line:
                m = re.search(r'time=([0-9]+\.?[0-9]*)\s*ms', line)
                if m:
                    val = float(m.group(1))
                    if val > 0:
                        return val
    except Exception:
        pass

    # 2) Fallback : connexion TCP sur le port 80/443 de plusieurs cibles
    targets = [
        ('1.1.1.1',   80),
        ('8.8.8.8',   53),
        ('9.9.9.9',   53),
        ('208.67.222.222', 53),
    ]
    for host, port in targets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            t0 = _time.monotonic()
            s.connect((host, port))
            ms = (_time.monotonic() - t0) * 1000
            s.close()
            if ms > 0:
                return ms
        except Exception:
            pass

    return -1.0

def volume_to_bars(volume_pct):
    """Convertit un % volume en chaîne de barres ▁▂▃▄▅▆▇█"""
    chars = "▁▂▃▄▅▆▇█"
    total = 16  # largeur fixe
    filled = round(volume_pct / 100 * total)
    filled = max(0, min(filled, total))
    if filled == 0:
        return "─" * total
    result = ""
    for i in range(filled):
        # chaque position prend le char selon sa hauteur relative
        idx = min(int(i / total * len(chars)), len(chars) - 1)
        result += chars[idx]
    return result

BAR_CHARS = " ▁▂▃▄▅▆▇█"

def pct_to_bar_char(pct):
    """Convertit un pourcentage en caractère de barre"""
    idx = int(pct / 100 * (len(BAR_CHARS) - 1))
    idx = max(0, min(idx, len(BAR_CHARS) - 1))
    return BAR_CHARS[idx]

def build_graph(history, max_val=100):
    bars = ""
    for val in history:
        pct = min(100, (val / max_val * 100)) if max_val > 0 else 0
        bars += pct_to_bar_char(pct)
    return bars.rjust(GRAPH_SIZE)

def get_gpu_info():
    """Récupère utilisation, fréquence et température GPU - priorité NVIDIA"""
    # NVIDIA
    try:
        result = subprocess.run(
            ['nvidia-smi', '--query-gpu=utilization.gpu,clocks.current.graphics,temperature.gpu',
             '--format=csv,noheader,nounits'],
            capture_output=True, text=True, timeout=0.5
        )
        if result.returncode == 0:
            parts = result.stdout.strip().split(',')
            if len(parts) >= 3:
                return float(parts[0].strip()), float(parts[1].strip()), float(parts[2].strip())
    except:
        pass

    # AMD via sysfs
    try:
        base = '/sys/class/drm/card0/device'
        usage, freq, temp = 0.0, 0.0, 0.0
        if os.path.exists(f'{base}/gpu_busy_percent'):
            with open(f'{base}/gpu_busy_percent') as f:
                usage = float(f.read().strip())
        if os.path.exists(f'{base}/pp_dpm_sclk'):
            with open(f'{base}/pp_dpm_sclk') as f:
                for line in f:
                    if '*' in line:
                        freq = float(line.split()[1].replace('Mhz','').replace('MHz','').strip())
        if os.path.exists(f'{base}/hwmon/hwmon0/temp1_input'):
            with open(f'{base}/hwmon/hwmon0/temp1_input') as f:
                temp = int(f.read().strip()) / 1000.0
        if usage > 0 or freq > 0 or temp > 0:
            return usage, freq, temp
    except:
        pass

    return 0.0, 0.0, 0.0


def latency_to_bars(ms):
    """
    Convertit une latence en barres visuelles progressives (ordre ▂▅█).
      ≤ 20ms  → ▂▅█
      ≤ 100ms → ▂▅
      ≤ 500ms → ▂
      > 500ms → (vide)
    """
    result = ""
    if ms <= 500:
        result += "▂"
    if ms <= 100:
        result += "▅"
    if ms <= 20:
        result += "█"
    return result if result else " "


def create_gpu_cpu_display():
    """GPU°C + CPU°C + volume statique + latence réseau défilante"""
    global _latency_history

    gpu_usage, gpu_freq, gpu_temp = get_gpu_info()
    cpu_temp = get_cpu_temp()

    volume = get_system_volume()
    latency = get_network_latency()

    if latency >= 0:
        _latency_history.append(latency)
    if len(_latency_history) > GRAPH_SIZE:
        _latency_history = _latency_history[-GRAPH_SIZE:]

    text = Text()
    text.append("GPU ", style="bold bright_red")
    text.append(f"{gpu_temp:.1f}°C", style="bright_yellow")
    text.append("  CPU ", style="bold bright_red")
    text.append(f"{cpu_temp:.1f}°C\n\n", style="bright_yellow")

    # Volume - affichage statique
    text.append("VOL ", style="bold bright_red")
    text.append(f"{volume:.0f}%\n", style="bright_white")
    text.append(volume_to_bars(volume) + "\n\n", style="bright_cyan")

    # Latence réseau - barres + ms sur la même ligne, en jaune
    text.append("PING\n", style="bold bright_red")
    if latency >= 0:
        text.append(latency_to_bars(latency) + f"    {latency:.0f}ms\n", style="bright_yellow")
    else:
        text.append("N/A\n", style="dim white")

    return text
    """Récupère utilisation, fréquence et température GPU via nvidia-smi ou sysfs AMD/Intel"""
    # NVIDIA
    try:
        result = subprocess.run(
            ['nvidia-smi', '--query-gpu=utilization.gpu,clocks.current.graphics,temperature.gpu',
             '--format=csv,noheader,nounits'],
            capture_output=True, text=True, timeout=0.5
        )
        if result.returncode == 0:
            parts = result.stdout.strip().split(',')
            if len(parts) >= 3:
                usage = float(parts[0].strip())
                freq = float(parts[1].strip())
                temp = float(parts[2].strip())
                return usage, freq, temp
    except:
        pass

    # AMD via sysfs
    try:
        base = '/sys/class/drm/card0/device'
        usage_path = f'{base}/gpu_busy_percent'
        freq_path = f'{base}/pp_dpm_sclk'
        temp_path = f'{base}/hwmon/hwmon0/temp1_input'

        usage = 0.0
        if os.path.exists(usage_path):
            with open(usage_path) as f:
                usage = float(f.read().strip())

        freq = 0.0
        if os.path.exists(freq_path):
            with open(freq_path) as f:
                for line in f:
                    if '*' in line:
                        freq = float(line.split()[1].replace('Mhz','').replace('MHz','').strip())

        temp = 0.0
        if os.path.exists(temp_path):
            with open(temp_path) as f:
                temp = int(f.read().strip()) / 1000.0

        if usage > 0 or freq > 0 or temp > 0:
            return usage, freq, temp
    except:
        pass

    # Intel via sysfs
    try:
        for card in os.listdir('/sys/class/drm'):
            freq_path = f'/sys/class/drm/{card}/device/drm/{card}/gt_cur_freq_mhz'
            if os.path.exists(freq_path):
                with open(freq_path) as f:
                    freq = float(f.read().strip())
                return 0.0, freq, 0.0
    except:
        pass

    return 0.0, 0.0, 0.0

def get_cpu_temp():
    """Récupère la température CPU"""
    try:
        temps = psutil.sensors_temperatures()
        if 'coretemp' in temps:
            return temps['coretemp'][0].current
        elif 'cpu_thermal' in temps:
            return temps['cpu_thermal'][0].current
        elif 'k10temp' in temps:
            return temps['k10temp'][0].current
    except:
        pass
    
    # Fallback: lire depuis /sys
    try:
        with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
            temp = int(f.read().strip()) / 1000
            return temp
    except:
        return 0

def get_ssid():
    """Récupère le SSID du réseau WiFi"""
    try:
        # Méthode 1: Lire depuis /proc/net/wireless
        with open('/proc/net/wireless', 'r') as f:
            lines = f.readlines()
            if len(lines) > 2:
                iface = lines[2].split(':')[0].strip()
                
                # Lire le SSID depuis /sys
                ssid_path = f'/sys/class/net/{iface}/operstate'
                if os.path.exists(ssid_path):
                    # Tenter de lire via iwgetid
                    try:
                        with os.popen(f'iwgetid -r 2>/dev/null') as p:
                            ssid = p.read().strip()
                            if ssid:
                                return ssid
                    except:
                        pass
                    
                    # Alternative: parser /proc/net/wireless
                    try:
                        with os.popen(f'iw dev {iface} link 2>/dev/null | grep SSID') as p:
                            line = p.read()
                            if 'SSID' in line:
                                return line.split('SSID:')[1].strip()
                    except:
                        pass
    except:
        pass
    
    return "NULL"

def create_bar_horizontal(pct, width=10):
    """Barre horizontale avec ■□"""
    filled = int((pct * width) / 100)
    return "■" * filled + "□" * (width - filled)

def create_system_info():
    """CPU, GPU, RAM, BATTERIE, RAM Freq avec ■□"""
    text = Text()
    
    # CPU
    cpu_pct = psutil.cpu_percent(interval=0.1)
    text.append("CPU ", style="bold bright_red")
    text.append(f"{cpu_pct:5.1f}% ", style="bright_white")
    text.append(create_bar_horizontal(cpu_pct, 10), style="bright_yellow")
    text.append("\n\n")
    
    # GPU
    gpu_pct, gpu_freq, gpu_temp = get_gpu_info()
    text.append("GPU ", style="bold bright_red")
    text.append(f"{gpu_pct:5.1f}% ", style="bright_white")
    text.append(create_bar_horizontal(gpu_pct, 10), style="bright_yellow")
    text.append("\n\n")
    
    # RAM
    mem = psutil.virtual_memory()
    text.append("RAM ", style="bold bright_red")
    text.append(f"{mem.percent:5.1f}% ", style="bright_white")
    text.append(create_bar_horizontal(mem.percent, 10), style="bright_yellow")
    text.append("\n\n")
    
    # BATTERIE
    try:
        battery = psutil.sensors_battery()
        bat_pct = battery.percent if battery else 100
    except:
        bat_pct = 100
    
    text.append("BAT ", style="bold bright_red")
    text.append(f"{bat_pct:5.1f}% ", style="bright_white")
    text.append(create_bar_horizontal(bat_pct, 10), style="bright_green")
    text.append("\n\n")
    
    # GPU FREQ (réutilise les données déjà récupérées)
    text.append("GPU FREQ: ", style="bold bright_red")
    text.append(f"{gpu_freq:.0f}MHz\n", style="bright_yellow")
    
    # CPU FREQ (directement en dessous, sans espace)
    cpu_freq = psutil.cpu_freq()
    if cpu_freq:
        text.append("CPU FREQ: ", style="bold bright_red")
        text.append(f"{cpu_freq.current:.0f}MHz\n\n", style="bright_yellow")
    
    mem = psutil.virtual_memory()
    used_gb = mem.used // (1024**3)
    total_gb = mem.total // (1024**3)
    text.append("RAM SIZE: ", style="bold bright_red")
    text.append(f"{used_gb}GB / {total_gb}GB\n", style="bright_yellow")
    text.append("    ", style="")
    ram_pct = (used_gb * 100) // total_gb if total_gb > 0 else 0
    text.append(create_bar_horizontal(ram_pct, 20), style="bright_cyan")
    
    return text

def create_disk_network():
    """Disque + Réseau"""
    text = Text()
    
    # DISK USAGE
    disk = psutil.disk_usage('/')
    text.append("DISK USAGE\n", style="bold bright_red")
    text.append(f"Total: ", style="bright_white")
    text.append(f"{disk.total // (1024**3)}G ", style="bright_yellow")
    text.append(f"Used: ", style="bright_white")
    text.append(f"{disk.used // (1024**3)}G\n", style="bright_yellow")
    text.append(create_bar_horizontal(disk.percent, 20), style="bright_yellow")
    text.append(f" {disk.percent:.0f}%\n\n", style="bright_white")
    
    # NETWORK
    text.append("NETWORK\n", style="bold bright_red")
    
    # Interface et SSID
    net_if = psutil.net_if_addrs()
    active_if = "NULL"
    for iface in net_if.keys():
        if iface != 'lo' and not iface.startswith('docker'):
            active_if = iface
            break
    
    ssid = get_ssid()
    
    text.append(f"IF: ", style="bright_white")
    text.append(f"{active_if:8s} ", style="bright_yellow")
    text.append(f"SSID: ", style="bright_white")
    text.append(f"{ssid}\n", style="bright_yellow")
    
    return text

def create_process_table():
    """Liste des processus"""
    table = Table(show_header=True, header_style="bold bright_red",
                  box=None, padding=(0, 1), expand=True)
    
    table.add_column("NAME", style="bright_cyan", width=12)
    table.add_column("PID", style="bright_yellow", width=8)
    table.add_column("MEM%", style="bright_white", width=6, justify="right")
    table.add_column("CPU%", style="bright_white", width=6, justify="right")
    
    # Obtenir les processus triés par CPU
    procs = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'cpu_percent']):
        try:
            info = proc.info
            procs.append((
                info['name'][:12],
                info['pid'],
                info['memory_percent'],
                info['cpu_percent']
            ))
        except:
            pass
    
    # Trier par CPU
    procs.sort(key=lambda x: x[3] or 0, reverse=True)
    
    # Afficher les 15 premiers
    for i in range(min(15, len(procs))):
        name, pid, mem, cpu = procs[i]
        table.add_row(
            name,
            str(pid),
            f"{mem:.1f}" if mem else "0.0",
            f"{cpu:.1f}" if cpu else "0.0"
        )
    
    return table

def generate_layout():
    """Layout complet"""
    cache_panel = Panel(
        create_gpu_cpu_display(),
        border_style="bold bright_red",
        padding=(0, 1)
    )
    
    sys_panel = Panel(
        create_system_info(),
        border_style="bold bright_red",
        padding=(0, 1)
    )
    
    disk_net_panel = Panel(
        create_disk_network(),
        border_style="bold bright_red",
        padding=(0, 1)
    )
    
    proc_panel = Panel(
        create_process_table(),
        title="[bold bright_red]PROCESSES[/]",
        border_style="bold bright_red",
        padding=(0, 0)
    )
    
    layout = Layout()
    
    layout.split_column(
        Layout(name="top", size=12),
        Layout(name="bottom")
    )
    
    layout["top"].split_row(
        Layout(cache_panel, name="cache", ratio=1),
        Layout(sys_panel, name="sysinfo", ratio=2)
    )
    
    layout["bottom"].split_row(
        Layout(disk_net_panel, name="disknet", ratio=1),
        Layout(proc_panel, name="processes", ratio=2)
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