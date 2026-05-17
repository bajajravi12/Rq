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
    search_dirs = [
        os.path.expanduser("~/"),
        os.path.expanduser("~/storage/shared"),
        os.path.expanduser("~/downloads"),
        os.getcwd()
    ]
    all_files = []
    for d in search_dirs:
        if os.path.exists(d):
            try:
                files = [os.path.join(d, f) for f in os.listdir(d) if f.endswith(".txt")]
                all_files.extend(files)
            except: pass
    return sorted(list(set(all_files)))

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
        data["Alt-Svc"] = (res443.get('alt_svc', 'None'), "dim")
        data["Via"] = (res443.get('via', 'None'), "dim")
        data["Cache"] = (res443.get('cache_control', 'None'), "dim")
    elif "error" not in res80:
        data["Server"] = (res80['server'], ui.colors.get(res80['server'], "white"))
        data["Status"] = (f"HTTP {res80['status']}", "bright_green")
        data["WebSocket"] = ("Supported" if res80['ws'] else "No", "green" if res80['ws'] else "grey50")
        data["Via"] = (res80.get('via', 'None'), "dim")
        
    ui.result_panel(data)

def get_ports_prompt():
    p_choice = ui.input_prompt("PORTS (80, 443, 8080 or custom comma-list)", f"Default: {utils.settings['ports']}")
    if not p_choice: 
        p_choice = utils.settings['ports']
    try:
        return [int(p.strip()) for p in p_choice.split(",") if p.strip().isdigit()]
    except:
        return [80, 443]

async def scan_cidr_flow():
    last_cidr = utils.session.get('last_cidr', '')
    cidr = ui.input_prompt(f"CIDR (e.g. 192.168.1.0/24)", f"Last used: {last_cidr}" if last_cidr else "")
    if not cidr and last_cidr: cidr = last_cidr
    if not cidr: return
    
    utils.save_session('last_cidr', cidr)
    ports = get_ports_prompt()
    
    last_idx = utils.session.get(f'checkpoint_cidr_{cidr}', 0)
    start_at = 0
    resume_choice = ui.input_prompt(f"START FROM INDEX (default: {last_idx})", "Press ENTER to use checkpoint" if last_idx else "Press ENTER for normal start")
    if resume_choice.isdigit():
        start_at = int(resume_choice)
    elif not resume_choice and last_idx:
        start_at = last_idx

    scanner = AsyncScanner(concurrency=utils.settings['threads'], timeout=utils.settings['timeout'])
    ui.console.print(f"\n[bold cyan]»[/bold cyan] [bold yellow]PREPARING NETWORK MAP: {cidr}[/bold yellow]")
    ui.console.print(f"[dim]Controls: [bold red]Ctrl+C[/bold red] to Pause/Stop | Ports: {ports}[/dim]\n")
    
    hits, last_pos = await scanner.scan_cidr(cidr, ports=ports, quiet_mode=utils.settings['quiet_mode'], start_at=start_at)
    
    # Save checkpoint
    import ipaddress
    net_total = ipaddress.ip_network(cidr).num_addresses
    if last_pos < net_total:
        utils.save_session(f'checkpoint_cidr_{cidr}', last_pos)
    else:
        # Clear checkpoint if finished
        if f'checkpoint_cidr_{cidr}' in utils.session:
            utils.session.pop(f'checkpoint_cidr_{cidr}')
            utils.save_session('dummy', 0) # Trigger save

    if utils.settings['save_logs']:
        utils.log_scan("cidr", hits)
    ui.console.print(f"\n[bold bright_green]✓ ANALYSIS COMPLETE. {len(hits)} ACTIVE NODES IDENTIFIED.[/bold bright_green]")
    if last_pos < net_total:
        ui.console.print(f"[dim]Note: Scan ended at index {last_pos}. Session saved.[/dim]")

async def bulk_audit_flow():
    files = get_txt_files()
    if not files:
        ui.console.print("[bold red]× ERROR:[/bold red] No .txt asset lists found in standard paths.")
        return
    
    last_file = utils.session.get('last_file', '')
    
    ui.console.print("\n[bold cyan]╭─ SELECT ASSET LIST[/bold cyan]")
    last_file_idx = -1
    for i, f in enumerate(files, 1):
        is_last = f == last_file
        if is_last: last_file_idx = i
        marker = "[bold yellow]*[/bold yellow]" if is_last else " "
        ui.console.print(f"[bold cyan]│[/bold cyan] [bright_cyan][{i:02}][/bright_cyan] {os.path.basename(f)} {marker}")
    ui.console.print("[bold cyan]╰─[/bold cyan]")
    
    ui.console.print(f" [bold cyan]RQ [/bold cyan] ► ", end="")
    choice = input().strip()
    if not choice and last_file_idx != -1:
        choice = str(last_file_idx)
        
    try:
        fpath = files[int(choice)-1]
        utils.save_session('last_file', fpath)
        ports = get_ports_prompt()
        
        # Memory optimized generator read - Chunk based for millions
        def target_generator(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    clean = line.strip()
                    if clean: yield clean

        # Resume Check
        last_pos_file = utils.session.get(f'checkpoint_file_{fpath}', 0)
        start_at = 0
        resume_choice = ui.input_prompt(f"START FROM LINE (default: {last_pos_file})", "Press ENTER to use checkpoint" if last_pos_file else "Press ENTER for normal start")
        if resume_choice.isdigit():
            start_at = int(resume_choice)
        elif not resume_choice and last_pos_file:
            start_at = last_pos_file

        scanner = AsyncScanner(concurrency=utils.settings['threads'], timeout=utils.settings['timeout'])
        ui.console.print(f"\n[bold cyan]»[/bold cyan] [bold yellow]AUDITING ASSETS FROM: {os.path.basename(fpath)}[/bold yellow]")
        ui.console.print(f"[dim]Controls: [bold red]Ctrl+C[/bold red] to Pause/Stop | Ports: {ports}[/dim]\n")
        
        # We need to slice the generator or just use islice
        import itertools
        targets_gen = itertools.islice(target_generator(fpath), start_at, None)
        
        hits, last_pos = await scanner.scan_list(targets_gen, ports=ports, quiet_mode=utils.settings['quiet_mode'], start_at=start_at)
        
        # Save checkpoint
        utils.save_session(f'checkpoint_file_{fpath}', last_pos)

        if utils.settings['save_logs']:
            utils.log_scan("bulk", hits)
        ui.console.print(f"\n[bold bright_green]✓ BATCH AUDIT COMPLETE. {len(hits)} RESPONSIVE ASSETS.[/bold bright_green]")
        if last_pos > start_at:
             ui.console.print(f"[dim]Note: Scan ended at line {last_pos}. Session saved.[/dim]")
    except Exception as e:
        ui.console.print(f"[bold red]× ERROR:[/bold red] {str(e)}")

def settings_menu():
    while True:
        ui.banner()
        ui.menu("SETTINGS")
        ui.console.print(f"\n[bold cyan]CURRENT CONFIGURATION:[/bold cyan]")
        for k, v in utils.settings.items():
            ui.console.print(f" [bright_cyan]»[/bright_cyan] [white]{k:<15}[/white] : [bold green]{v}[/bold green]")
        
        ui.console.print("\n[bold yellow][1-8][/bold yellow] Change Setting | [bold blue][C][/bold blue] Clear Session | [bold red][0][/bold red] Back")
        ui.console.print("\n RQ ► ", end="")
        choice = input().strip().upper()
        
        if choice == '1': utils.settings['threads'] = int(ui.input_prompt("THREADS (Current: {})".format(utils.settings['threads'])) or utils.settings['threads'])
        elif choice == '2': utils.settings['timeout'] = int(ui.input_prompt("TIMEOUT (Current: {})".format(utils.settings['timeout'])) or utils.settings['timeout'])
        elif choice == '3': utils.settings['retries'] = int(ui.input_prompt("RETRIES (Current: {})".format(utils.settings['retries'])) or utils.settings['retries'])
        elif choice == '4': utils.settings['chunk_size'] = int(ui.input_prompt("CHUNK SIZE (Current: {})".format(utils.settings['chunk_size'])) or utils.settings['chunk_size'])
        elif choice == '5': utils.settings['ports'] = ui.input_prompt("DEFAULT PORTS (Current: {})".format(utils.settings['ports'])) or utils.settings['ports']
        elif choice == '6': utils.settings['show_all'] = not utils.settings['show_all']
        elif choice == '7': utils.settings['save_logs'] = not utils.settings['save_logs']
        elif choice == '8': utils.settings['quiet_mode'] = not utils.settings['quiet_mode']
        elif choice == 'C':
            utils.session = {}
            utils.save_session('reset', True)
            ui.console.print("[bold green]✓ Session state cleared.[/bold green]")
            input("\nPress ENTER to continue...")
        elif choice == '0':
            utils.save_settings(utils.settings)
            break
        utils.save_settings(utils.settings)

def main():
    utils.ensure_dirs()
    while True:
        try:
            ui.banner()
            ui.menu()
            ui.console.print("\n [bold bright_cyan]RQ[/bold bright_cyan] ► ", end="")
            choice = input().strip()
            
            if choice == '1':
                asyncio.run(run_inspector())
            elif choice == '2':
                asyncio.run(scan_cidr_flow())
            elif choice == '3':
                asyncio.run(bulk_audit_flow())
            elif choice == '4':
                asyncio.run(run_inspector()) # Method analyzer integrated
            elif choice == '5':
                ip = ui.input_prompt("TARGET IP")
                if ip:
                    ui.console.print(f"\n[bold cyan]»[/bold cyan] [bold yellow]RESOLVING REVERSE PTR...[/bold yellow]")
                    revs = DNSInspector.reverse_dns_pro(ip)
                    if revs:
                        for r in revs: ui.console.print(f" [bold green]✓[/bold green] [white]{r}[/white]")
                    else: ui.console.print(" [bold red]×[/bold red] No PTR records discovered.")
            elif choice == '6':
                settings_menu()
            elif choice == '7':
                ui.banner()
                ui.console.print("\n[bold cyan]╭─ SESSION LOGS[/bold cyan]")
                if not os.path.exists("results/"): os.makedirs("results/")
                logs = sorted(os.listdir("results/"), reverse=True)
                if not logs: ui.console.print("[bold cyan]│[/bold cyan] No active logs.")
                for i, l in enumerate(logs[:15], 1): 
                    ui.console.print(f"[bold cyan]│[/bold cyan] [bright_cyan][{i:02}][/bright_cyan] {l}")
                ui.console.print("[bold cyan]╰─[/bold cyan]")
                input("\n[dim]Press ENTER to return...[/dim]")

            elif choice == '8' or choice.lower() == 'exit':
                ui.console.print("\n[bold red] » TERMINAL DEACTIVATED « [/bold red]")
                sys.exit(0)
            
            input("\n[dim]Press ENTER to return to System Menu...[/dim]")
        except KeyboardInterrupt:
            ui.console.print("\n[bold red] » OPERATION ABORTED « [/bold red]")
            break
        except Exception as e:
            ui.console.print(f"\n[bold red] » SYSTEM ERROR: {str(e)} « [/bold red]")
            input("\nPress ENTER to reset...")

if __name__ == "__main__":
    main()
