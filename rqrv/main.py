import os
import sys
import asyncio
from .ui import ui
from .utils import utils
from .scanner import AsyncScanner
from .core.inspector import WebInspector
from .core.tls import TLSInspector
from .core.dns import DNSInspector

def get_txt_files():
    paths = [
        os.path.expanduser("~/"),
        os.path.expanduser("~/storage/shared"),
        os.path.expanduser("~/downloads"),
        os.getcwd()
    ]
    files = []
    for p in paths:
        if os.path.exists(p):
            for f in os.listdir(p):
                if f.endswith(".txt"):
                    files.append(os.path.join(p, f))
    return sorted(list(set(files)))

async def run_inspector():
    target = ui.input_prompt("TARGET (Domain/IP)")
    if not target: return
    
    ui.console.print("\n[bold cyan]»[/bold cyan] [bold yellow]INITIATING DEEP ANALYSIS...[/bold yellow]")
    ins = WebInspector()
    res80 = await ins.analyze(target, 80)
    res443 = await ins.analyze(target, 443)
    
    tls = TLSInspector.inspect(target)
    
    data = {"Host": (target, "white")}
    if "error" not in res443:
        data["Server"] = (res443['server'], ui.colors.get(res443['server'], "white"))
        data["CDN"] = (res443['cdn'] or "Direct", "bold blue" if res443['cdn'] else "white")
        data["TLS"] = (tls.get("version", "Unknown"), "bright_green")
        data["HTTP"] = (str(res443['version']), "bright_cyan")
        data["WebSocket"] = ("Supported" if res443['ws'] else "No", "green" if res443['ws'] else "grey50")
    elif "error" not in res80:
        data["Server"] = (res80['server'], ui.colors.get(res80['server'], "white"))
        data["Status"] = (f"HTTP {res80['status']}", "bright_green")
        
    ui.result_panel(data)

async def scan_cidr_flow():
    cidr = ui.input_prompt("CIDR (e.g. 192.168.1.0/24)")
    if not cidr: return
    scanner = AsyncScanner()
    ui.console.print(f"\n[bold cyan]»[/bold cyan] [bold yellow]PREPARING NETWORK MAP: {cidr}[/bold yellow]\n")
    hits = await scanner.scan_cidr(cidr)
    utils.log_scan("cidr", hits)
    ui.console.print(f"\n[bold bright_green]✓ ANALYSIS COMPLETE. {len(hits)} ACTIVE NODES IDENTIFIED.[/bold bright_green]")

async def bulk_audit_flow():
    files = get_txt_files()
    if not files:
        ui.console.print("[bold red]× ERROR:[/bold red] No .txt asset lists found in standard paths.")
        return
    
    ui.console.print("\n[bold cyan]╭─ SELECT ASSET LIST[/bold cyan]")
    for i, f in enumerate(files, 1):
        ui.console.print(f"[bold cyan]│[/bold cyan] [bright_cyan][{i}][/bright_cyan] {os.path.basename(f)}")
    ui.console.print("[bold cyan]╰─[/bold cyan]")
    
    choice = input(" [bold cyan]RQ [/bold cyan] ► ").strip()
    try:
        fpath = files[int(choice)-1]
        with open(fpath, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
        
        scanner = AsyncScanner()
        ui.console.print(f"\n[bold cyan]»[/bold cyan] [bold yellow]AUDITING {len(targets)} ASSETS[/bold yellow]\n")
        hits = await scanner.scan_list(targets)
        utils.log_scan("bulk", hits)
        ui.console.print(f"\n[bold bright_green]✓ BATCH AUDIT COMPLETE. {len(hits)} RESPONSIVE ASSETS.[/bold bright_green]")
    except Exception as e:
        ui.console.print(f"[bold red]× ERROR:[/bold red] {str(e)}")

def main():
    utils.ensure_dirs()
    while True:
        try:
            ui.banner()
            ui.menu()
            choice = input("\n [bold bright_cyan]RQ[/bold bright_cyan] ► ").strip()
            
            if choice == '1':
                asyncio.run(run_inspector())
            elif choice == '2':
                asyncio.run(scan_cidr_flow())
            elif choice == '3':
                asyncio.run(bulk_audit_flow())
            elif choice == '4':
                asyncio.run(run_inspector()) # Method analyzer now integrated into inspector v2
            elif choice == '5':
                ip = ui.input_prompt("TARGET IP")
                if ip:
                    ui.console.print(f"\n[bold cyan]»[/bold cyan] [bold yellow]RESOLVING REVERSE PTR...[/bold yellow]")
                    revs = DNSInspector.reverse_dns_pro(ip)
                    if revs:
                        for r in revs: ui.console.print(f" [bold green]✓[/bold green] [white]{r}[/white]")
                    else: ui.console.print(" [bold red]×[/bold red] No PTR records discovered.")
            elif choice == '6':
                ui.console.print("\n[bold cyan]╭─ SESSION LOGS[/bold cyan]")
                logs = os.listdir("results/")
                if not logs: ui.console.print("[bold cyan]│[/bold cyan] No active logs.")
                for l in logs: ui.console.print(f"[bold cyan]│[/bold cyan] [white]{l}[/white]")
                ui.console.print("[bold cyan]╰─[/bold cyan]")
            elif choice == '7' or choice.lower() == 'exit':
                ui.console.print("\n[bold red] » TERMINAL DEACTIVATED « [/bold red]")
                break
            
            input("\n[dim]Press ENTER to return to System Menu...[/dim]")
        except KeyboardInterrupt:
            ui.console.print("\n[bold red] » OPERATION ABORTED « [/bold red]")
            break
        except Exception as e:
            ui.console.print(f"\n[bold red] » SYSTEM ERROR: {str(e)} « [/bold red]")
            input("\nPress ENTER to reset...")

if __name__ == "__main__":
    main()
