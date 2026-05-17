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
    
    ui.console.print("\n[bold yellow]⚡ INITIATING DEEP SCAN...[/bold yellow]")
    ins = WebInspector()
    res80 = await ins.analyze(target, 80)
    res443 = await ins.analyze(target, 443)
    
    tls = TLSInspector.inspect(target)
    
    data = {"Host": (target, "white")}
    if "error" not in res443:
        data["Server"] = (res443['server'], ui.colors.get(res443['server'], "white"))
        data["CDN"] = (res443['cdn'] or "None", "bold blue" if res443['cdn'] else "white")
        data["TLS"] = (tls.get("version", "Unknown"), "green")
        data["HTTP"] = (str(res443['version']), "cyan")
    elif "error" not in res80:
        data["Server"] = (res80['server'], ui.colors.get(res80['server'], "white"))
        data["Status"] = (str(res80['status']), "green")
        
    ui.result_panel(data)

async def scan_cidr_flow():
    cidr = ui.input_prompt("CIDR (e.g. 192.168.1.0/24)")
    if not cidr: return
    scanner = AsyncScanner()
    ui.console.print(f"\n[bold yellow]『 SCANNING {cidr} 』[/bold yellow]\n")
    hits = await scanner.scan_cidr(cidr)
    utils.log_scan("cidr", hits)
    ui.console.print(f"\n[bold green]Scan complete. {len(hits)} hits saved.[/bold green]")

async def bulk_audit_flow():
    files = get_txt_files()
    if not files:
        ui.console.print("[red]No .txt files found in common paths.[/red]")
        return
    
    ui.console.print("\n[bold cyan]Select Asset List:[/bold cyan]")
    for i, f in enumerate(files, 1):
        ui.console.print(f"[{i}] {os.path.basename(f)}")
    
    choice = input("\nChoice: ").strip()
    try:
        fpath = files[int(choice)-1]
        with open(fpath, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
        
        scanner = AsyncScanner()
        ui.console.print(f"\n[bold yellow]『 AUDITING {len(targets)} ASSETS 』[/bold yellow]\n")
        hits = await scanner.scan_list(targets)
        utils.log_scan("bulk", hits)
    except:
        ui.console.print("[red]Invalid selection or file error.[/red]")

def main():
    utils.ensure_dirs()
    while True:
        ui.banner()
        ui.menu()
        choice = input("\n[bold cyan] RQ-TERMINAL [/bold cyan] $ ").strip()
        
        if choice == '1':
            asyncio.run(run_inspector())
        elif choice == '2':
            asyncio.run(scan_cidr_flow())
        elif choice == '3':
            asyncio.run(bulk_audit_flow())
        elif choice == '4':
            ui.console.print("[yellow]Feature coming in v2.1 (Method Analyzer)[/yellow]")
        elif choice == '5':
            ip = ui.input_prompt("TARGET IP")
            if ip:
                revs = DNSInspector.reverse_dns_pro(ip)
                if revs:
                    for r in revs: ui.console.print(f"[cyan]»[/cyan] {r}")
                else: ui.console.print("[red]No PTR records found.[/red]")
        elif choice == '6':
            os.system("ls results/")
        elif choice == '7' or choice.lower() == 'exit':
            ui.console.print("[bold red]TERMINAL CLOSED.[/bold red]")
            break
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
