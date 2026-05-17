import os
import shutil
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich.table import Table
from rich import box

class UI:
    def __init__(self):
        self.console = Console()
        self.refresh_width()
        self.colors = {
            "Cloudflare": "bright_magenta",
            "CloudFront": "bright_blue",
            "Fastly": "bright_cyan",
            "nginx": "bright_green",
            "Apache": "bright_yellow",
            "Envoy": "purple",
            "Caddy": "magenta",
            "Unknown": "grey50",
            "error": "bold red",
            "warning": "bold yellow",
            "success": "bold green",
            "info": "bold cyan"
        }

    def refresh_width(self):
        self.width = shutil.get_terminal_size().columns
        # Mobile safe max width
        self.max_w = min(self.width - 2, 48)

    def banner(self):
        self.console.clear()
        self.refresh_width()
        
        banner_text = Text(r"""
 ╔═══════════════════════════╗
 ║     RQ INFRA TERMINAL     ║
 ║        Made by RQ         ║
 ╚═══════════════════════════╝
""", style="bold bright_cyan")
        
        self.console.print(Align.center(banner_text))
        self.console.print(Align.center(Text("» DEEP INFRASTRUCTURE INTELLIGENCE «", style="dim cyan italic")))
        self.console.print("-" * self.width, style="grey15")

    def menu(self):
        content = Text()
        options = [
            ("1", "SINGLE INSPECTOR"),
            ("2", "CIDR INVENTORY"),
            ("3", "BULK ASSET AUDIT"),
            ("4", "METHOD ANALYZER"),
            ("5", "REVERSE DNS PRO"),
            ("6", "VIEW LOGS"),
            ("7", "EXIT")
        ]
        
        for i, (idx, label) in enumerate(options):
            content.append(f"  [{idx}] ", style="bold bright_cyan")
            content.append(f"{label:<18}", style="bold white")
            if i % 1 == 0 and i != len(options)-1:
                content.append("\n")

        panel = Panel(
            content,
            title="[bold cyan]╭─ SYSTEM MENU ─╮[/bold cyan]",
            title_align="left",
            border_style="bright_cyan",
            box=box.ROUNDED,
            width=self.max_w - 4
        )
        self.console.print(Align.center(panel))

    def input_prompt(self, label):
        self.console.print(f"\n[bold bright_cyan]╭─ [white]{label}[/white][/bold bright_cyan]")
        val = input(" [bold bright_cyan]╰─► [/bold bright_cyan]").strip()
        return val

    def result_panel(self, data):
        content = Table.grid(expand=True)
        content.add_column(style="bold cyan", width=12)
        content.add_column(style="white")
        
        for key, (val, color) in data.items():
            content.add_row(f" {key}", f": {val}")
        
        panel = Panel(
            content,
            title="[bold green]✓ SCAN RESULT[/bold green]",
            border_style="bright_cyan",
            box=box.ROUNDED,
            width=self.max_w,
            padding=(0, 1)
        )
        self.console.print("\n")
        self.console.print(Align.center(panel))

    def hit_compact(self, count, total, target, server, status, version=""):
        server_color = self.colors.get(server, "white")
        status_color = "green" if str(status).startswith("2") else "yellow" if str(status).startswith("3") else "red"
        
        prog = f"[grey37][{count}/{total}][/grey37]"
        targ = f"[bold white]{target[:20]:<20}[/bold white]"
        serv = f"[{server_color}]{server[:10]:<10}[/]"
        stat = f"[{status_color}]HTTP {status}[/]"
        
        self.console.print(f"{prog} {targ} {stat} {serv}")

ui = UI()
