#!/usr/bin/env python3
import os
import time
import psutil
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live

console = Console()

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

def get_ram_info():
    """Récupère infos RAM (fréquence et capacité)"""
    freq = 0
    try:
        # Lire la fréquence depuis dmidecode si disponible
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if 'MemTotal' in line:
                    # Pas de fréquence directement accessible sans dmidecode
                    break
        
        # Tenter de lire depuis /sys (estimation)
        freq = 2400  # Valeur par défaut approximative
    except:
        freq = 0
    
    mem = psutil.virtual_memory()
    total_gb = mem.total // (1024**3)
    used_gb = mem.used // (1024**3)
    
    return freq, used_gb, total_gb

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

def create_vertical_bar(pct, height=5):
    """Crée une barre verticale avec ░▒▓"""
    lines = []
    filled = int((pct * height) / 100)
    
    for i in range(height):
        level = height - i - 1
        if level < filled:
            if level < height * 0.3:
                lines.append("▓")
            elif level < height * 0.6:
                lines.append("▒")
            else:
                lines.append("░")
        else:
            lines.append(" ")
    
    return lines

def create_cache_display():
    """Cache CPU avec température"""
    try:
        cache_size = 0
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if 'cache size' in line.lower():
                    parts = line.split(':')
                    if len(parts) > 1:
                        cache_str = parts[1].strip().split()[0]
                        cache_size = int(cache_str)
                        break
        
        temp = get_cpu_temp()
        
        text = Text()
        text.append("CPU CACHE\n", style="bold bright_red")
        text.append(f"{cache_size} KB\n", style="bright_white")
        text.append(f"TEMP: ", style="bold bright_red")
        text.append(f"{temp:.1f}°C\n\n", style="bright_yellow")
        
        # Grille 5x5 avec ░▒▓
        usage = (cache_size % 100)
        grid_size = 25
        filled = int((usage * grid_size) / 100)
        
        for i in range(5):
            for j in range(5):
                idx = i * 5 + j
                if idx < filled * 0.6:
                    text.append("▓", style="bright_red")
                elif idx < filled * 0.8:
                    text.append("▒", style="yellow")
                elif idx < filled:
                    text.append("░", style="bright_white")
                else:
                    text.append("░", style="dim white")
                text.append(" ")
            text.append("\n")
        
        return text
    except:
        return Text("CACHE\nN/A", style="bold bright_red")

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
    
    # GPU (simulation)
    gpu_pct = 0
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
    
    # RAM Info détaillée (CORRECTION: suppression de la barre CPU parasite)
    freq, used_gb, total_gb = get_ram_info()
    text.append("RAM FREQ: ", style="bold bright_red")
    text.append(f"{freq}MHz\n", style="bright_yellow")
    
    # CPU FREQ (directement en dessous, sans espace)
    cpu_freq = psutil.cpu_freq()
    if cpu_freq:
        text.append("CPU FREQ: ", style="bold bright_red")
        text.append(f"{cpu_freq.current:.0f}MHz\n\n", style="bright_yellow")
    
    text.append("RAM SIZE: ", style="bold bright_red")
    text.append(f"{used_gb}GB / {total_gb}GB\n", style="bright_yellow")
    text.append("    ", style="")
    ram_pct = (used_gb * 100) // total_gb if total_gb > 0 else 0
    text.append(create_bar_horizontal(ram_pct, 20), style="bright_cyan")
    
    return text

# Variables globales pour calculer les vitesses
last_net_io = None
last_time = None

def create_disk_network():
    """Disque + Réseau avec équaliseur ░▒▓ étendu"""
    global last_net_io, last_time
    
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
    text.append(f"{ssid}\n\n", style="bright_yellow")
    
    # Calculer vitesse réseau
    net_io = psutil.net_io_counters()
    current_time = time.time()
    
    in_speed = 0
    out_speed = 0
    
    if last_net_io and last_time:
        time_delta = current_time - last_time
        if time_delta > 0:
            in_speed = (net_io.bytes_recv - last_net_io.bytes_recv) / time_delta / 1024
            out_speed = (net_io.bytes_sent - last_net_io.bytes_sent) / time_delta / 1024
    
    last_net_io = net_io
    last_time = current_time
    
    # Équaliseur IN - 10 barres
    text.append("IN  ", style="bright_white")
    text.append(f"{int(in_speed):5d}KB/s ", style="bright_yellow")
    
    for i in range(10):
        bars = create_vertical_bar(min(100, in_speed / (10 * (i + 1))), 5)
        for char in bars:
            if char == "▓":
                text.append(char, style="bright_green")
            elif char == "▒":
                text.append(char, style="yellow")
            elif char == "░":
                text.append(char, style="bright_white")
            else:
                text.append(char)
        text.append(" ")
    
    text.append("\nOUT ", style="bright_white")
    text.append(f"{int(out_speed):5d}KB/s ", style="bright_yellow")
    
    # Équaliseur OUT - 10 barres
    for i in range(10):
        bars = create_vertical_bar(min(100, out_speed / (10 * (i + 1))), 5)
        for char in bars:
            if char == "▓":
                text.append(char, style="bright_red")
            elif char == "▒":
                text.append(char, style="yellow")
            elif char == "░":
                text.append(char, style="bright_white")
            else:
                text.append(char)
        text.append(" ")
    
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
        create_cache_display(),
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
