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
            "Cloudflare": "orange3",
            "CloudFront": "blue",
            "Fastly": "cyan",
            "nginx": "green",
            "Apache": "yellow",
            "Envoy": "purple",
            "Caddy": "magenta",
            "Unknown": "grey70",
            "error": "bold red",
            "warning": "bold yellow",
            "success": "bold green",
            "info": "bold blue"
        }

    def refresh_width(self):
        self.width = shutil.get_terminal_size().columns
        # Mobile safe max width
        self.max_w = min(self.width - 2, 45)

    def banner(self):
        self.console.clear()
        self.refresh_width()
        
        banner = Text(r"""
██████╗  ██████╗ 
██╔══██╗██╔═══██╗
██████╔╝██║   ██║
██╔══██╗██║▄▄ ██║
██║  ██║╚██████╔╝
╚═╝  ╚═╝ ╚══▀▀═╝ 
""", style="bold bright_cyan")
        
        tag = Text("\nRQ INFRA TERMINAL\nMade by RQ", style="bold white")
        
        content = Align.center(banner + tag)
        self.console.print(content)
        self.console.print("-" * self.width, style="grey15")

    def menu(self):
        options = [
            "1. SINGLE HOST INSPECTOR",
            "2. CIDR INVENTORY",
            "3. BULK ASSET AUDIT",
            "4. METHOD ANALYZER",
            "5. REVERSE DNS PRO",
            "6. VIEW LOGS",
            "7. EXIT"
        ]
        
        table = Table(box=box.SIMPLE, show_header=False)
        for opt in options:
            table.add_row(Text(opt, style="bold cyan"))
        
        self.console.print(Align.center(table))

    def input_prompt(self, label):
        self.console.print(f"\n[bold bright_cyan]╭─ [white]{label}[/white][/bold bright_cyan]")
        val = input(" [bold bright_cyan]╰─► [/bold bright_cyan]").strip()
        return val

    def result_panel(self, data):
        content = Text()
        for key, (val, color) in data.items():
            content.append(f"│ {key:<9}: ", style="cyan")
            content.append(f"{val}\n", style=color or "white")
        
        panel = Panel(
            content,
            title="[bold green]✓ RESULT[/bold green]",
            border_style="bright_cyan",
            box=box.ROUNDED,
            width=self.max_w
        )
        self.console.print(Align.center(panel))

    def hit_compact(self, target, server, status):
        server_color = self.colors.get(server, "white")
        self.console.print(f"[bold cyan]»[/bold cyan] [white]{target:<20}[/white] | [{server_color}]{server:<12}[/[{server_color}]] | [green]{status}[/green]")

ui = UI()
