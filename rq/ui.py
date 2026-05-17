import os
import shutil
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from rich.layout import Layout
from rich.live import Live
from rich.align import Align
from rich.text import Text
from rich import box

class UI:
    def __init__(self):
        self.console = Console()
        self.width = shutil.get_terminal_size().columns
        self.colors = {
            "Cloudflare": "orange3",
            "CloudFront": "deep_sky_blue1",
            "Fastly": "cyan",
            "nginx": "green",
            "Apache": "yellow",
            "Envoy": "purple3",
            "Unknown": "grey70",
            "success": "bold green",
            "warning": "bold yellow",
            "error": "bold red",
            "neon": "spring_green1"
        }

    def clear(self):
        self.console.clear()

    def banner(self):
        self.clear()
        banner_text = Text(r"""
 ╔═════════════════════════════════════════════════╗
 ║   ██████╗  █████╗ ██╗   ██╗ █████╗ ███╗   ██╗  ║
 ║   ██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║  ║
 ║   ██████╔╝███████║██║   ██║███████║██╔██╗ ██║  ║
 ║   ██╔══██╗██╔══██║╚██╗ ██╔╝██╔══██║██║╚██╗██║  ║
 ║   ██║  ██║██║  ██║ ╚████╔╝ ██║  ██║██║ ╚████║  ║
 ║   ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝  ║
 ║           INFRA TERMINAL | Made by RQ           ║
 ╚═════════════════════════════════════════════════╝
        """, style="bold bright_cyan")
        self.console.print(Align.center(banner_text))

    def menu(self):
        options = [
            "SINGLE HOST INSPECTOR", "CIDR INVENTORY", "BULK ASSET AUDIT",
            "METHOD ANALYZER", "REVERSE DNS PRO", "IP TO ASN/CIDR",
            "VIEW SAVED LOGS", "SETTINGS", "EXIT PROGRAM"
        ]
        
        table = Table(box=box.MINIMAL_DOUBLE_HEAD, show_header=False, border_style="cyan")
        for i, opt in enumerate(options, 1):
            table.add_row(f"[bold cyan][{i}][/bold cyan]", f"[bold white]{opt}[/bold white]")
        
        self.console.print(Align.center(table))
        self.console.print("\n[bold spring_green1]╭─ [white]TARGET INPUT[/white][/bold spring_green1]")
        self.console.print("[bold spring_green1]╰─► [/bold spring_green1]", end="")

    def hit_panel(self, target, server, tls, version, ws, cdn):
        server_color = self.colors.get(server, self.colors["Unknown"])
        
        content = Text.assemble(
            ("Host     : ", "cyan"), (f"{target}\n", "white"),
            ("Server   : ", "cyan"), (f"{server}\n", server_color),
            ("TLS      : ", "cyan"), (f"{tls}\n", "white"),
            ("Version  : ", "cyan"), (f"{version}\n", "white"),
            ("WebSocket: ", "cyan"), (("Supported" if ws else "No"), "green" if ws else "red"), ("\n", ""),
            ("CDN      : ", "cyan"), (("Active" if cdn else "No"), "orange3" if cdn else "grey50")
        )
        
        panel = Panel(
            Align.left(content),
            title="[bold green]✓ RESULT[/bold green]",
            border_style="cyan",
            box=box.ROUNDED,
            width=min(self.width - 2, 45)
        )
        self.console.print(panel)

    def progress_ui(self, current, total, target, hits):
        # Progress bar optimized for mobile
        width = 10
        percent = (current / total) * 100 if total > 0 else 0
        
        self.console.print(f"\n[bold spring_green1]『 RQ ACTIVE 』[/bold spring_green1]")
        self.console.print(f"[white]{target}[/white]")
        
        bar_len = int(width * percent / 100)
        bar = "█" * bar_len + "░" * (width - bar_len)
        self.console.print(f"[cyan]{bar}[/cyan] [bold white]{percent:.0f}%[/bold white]")
        self.console.print(f"[bold spring_green1]H:{hits} / T:{total}[/bold spring_green1]")
        # Shift cursor up to overwrite in next cycle
        self.console.print("\033[5A", end="")

    def info(self, msg):
        self.console.print(f"[bold blue][i][/bold blue] {msg}")

    def success(self, msg):
        self.console.print(f"[bold green][+][/bold green] {msg}")

    def error(self, msg):
        self.console.print(f"[bold red][!][/bold red] {msg}")

    def warning(self, msg):
        self.console.print(f"[bold yellow][?][/bold yellow] {msg}")

ui = UI()

