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
        self.width = shutil.get_terminal_size().columns
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
        new_width = shutil.get_terminal_size().columns
        if new_width != self.width:
            self.width = new_width
        self.max_w = min(self.width - 2, 48)

    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def banner(self):
        self.clear()
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

    def menu(self, active_menu="SYSTEM MENU"):
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
            if (i + 1) % 1 == 0 and i != len(options)-1:
                content.append("\n")

        panel = Panel(
            content,
            title=f"[bold cyan]╭─ {active_menu} ─╮[/bold cyan]",
            title_align="left",
            border_style="bright_cyan",
            box=box.ROUNDED,
            width=self.max_w - 4
        )
        self.console.print(Align.center(panel))

    def input_prompt(self, label, placeholder=""):
        self.console.print(f"\n[bold bright_cyan]╭─ [white]{label}[/white][/bold bright_cyan]")
        if placeholder:
            self.console.print(f"[dim] │ {placeholder}[/dim]")
        
        # We print the arrow and wait for input on the same line if possible, 
        # but to keep it clean in Termux, we just print the arrow and take input.
        self.console.print(" [bold bright_cyan]╰─► [/bold bright_cyan]", end="")
        val = input().strip()
        return val

    def result_panel(self, data, title="SCAN RESULT"):
        content = Table.grid(expand=True)
        content.add_column(style="bold cyan", width=12)
        content.add_column(style="white")
        
        for key, value in data.items():
            if isinstance(value, tuple):
                val, color = value
                content.add_row(f" {key}", f": [{color or 'white'}]{val}[/]")
            else:
                content.add_row(f" {key}", f": {value}")
        
        panel = Panel(
            content,
            title=f"[bold green]✓ {title}[/bold green]",
            border_style="bright_cyan",
            box=box.ROUNDED,
            width=self.max_w,
            padding=(0, 1)
        )
        self.console.print("\n")
        self.console.print(Align.center(panel))

    def interesting_panel(self, target, server, status, signals, port=80, version="HTTP/1.1"):
        import datetime
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        
        from http import HTTPStatus
        try:
            status_msg = HTTPStatus(status).phrase
        except:
            status_msg = "Unknown"

        self.console.print(f"\n[bold green] ✓ HIT [{ts}][/bold green]")
        self.console.print(f" [bold white]Proxy  :[/bold white] [green]{target}[/green] [cyan]{port}[/cyan]")
        self.console.print(f" [bold white]Server :[/bold white] [{self.colors.get(server, 'white')}]{server}[/]")
        self.console.print(f" [bold white]Status :[/bold white] [bold bright_green]{version} {status} {status_msg}[/bold bright_green]")
        self.console.print("[dim]=============================================[/dim]\n")

    def hit_compact(self, count, total, target, server, status, port=80, version="HTTP/1.1"):
        percent = (count / total) * 100 if total and total > 0 else 0
        
        from http import HTTPStatus
        try:
            status_msg = HTTPStatus(status).phrase
        except:
            status_msg = "Unknown"

        status_color = "green" if str(status).startswith("2") else "yellow" if str(status).startswith("3") else "red"
        
        # Format: Progress: 3390/25856 (13.1%) [3458/25856] 56.228.x.x 443 HTTP/1.1 404 Not Found
        # The bracketed part in screenshot seems to be a lookahead or range, 
        # but often it's just showing the exact same count or a slightly shifted one.
        # I'll just show the count.
        
        prog_str = f"[grey37]Progress: {count}/{total or '??'} ({percent:.1f}%) [{count}/{total or '??'}][/grey37]"
        targ_str = f"[bold white]{target}[/bold white] [bold cyan]{port}[/bold cyan]"
        stat_str = f"[{status_color}]{version} {status} {status_msg}[/]"
        
        self.console.print(f"{prog_str} {targ_str} {stat_str}")

    def progress_bar(self, current, total, hits):
        # Compact progress bar for Termux
        width = 15
        percent = (current / total) * 100 if total > 0 else 0
        filled = int(width * percent // 100)
        bar = "█" * filled + "░" * (width - filled)
        
        self.console.print(f"\n[bold cyan]『 RQ ACTIVE 』[/bold cyan] [bright_cyan]{bar}[/] [bold white]{percent:.0f}%[/]")
        self.console.print(f"[dim]SCANNED: {current}/{total} | HITS: {hits}[/dim]")
        # Shift back up to dynamic update if needed in future
        # For scrolling logs, we just print once per update

ui = UI()
