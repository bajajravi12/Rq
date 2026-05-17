import sys
import asyncio
import os
import ipaddress
from .ui import ui
from .core.inspector import Inspector
from .core.scanner import AsyncScanner
from .core.network import NetworkTool

def get_txt_files():
    search_paths = [
        os.path.expanduser("~"),
        os.path.expanduser("~/storage/downloads"),
        os.path.expanduser("~/storage/shared"),
        os.path.expanduser("~/storage/documents"),
        os.getcwd()
    ]
    files = []
    for p in search_paths:
        if os.path.exists(p):
            try:
                for f in os.listdir(p):
                    if f.endswith(".txt"):
                        files.append(os.path.join(p, f))
            except: pass
    return sorted(list(set(files)))

async def handle_choice(choice):
    if choice == '1': # SINGLE HOST INSPECTOR
        target = input("Enter host (IP/Domain): ").strip()
        if not target: return
        ports_raw = input("Ports (default 80,443): ").strip()
        ports = [int(p.strip()) for p in ports_raw.split(",")] if ports_raw else [80, 443]
        
        ui.info(f"Inspecting {target}...")
        results = await Inspector.analyze_host(target, ports)
        for r in results:
            ui.hit_panel(f"{target}:{r['port']}", r['server'], r['tls'], r['version'], r['ws'], r['cdn'] is not None)
            if r['cdn']: ui.success(f"CDN Detected: {r['cdn']}")
        
    elif choice == '2': # CIDR INVENTORY
        cidr = input("Enter CIDR (e.g. 192.168.1.0/24): ").strip()
        if not cidr: return
        try:
            ips = [str(ip) for ip in ipaddress.ip_network(cidr)]
            scanner = AsyncScanner("CIDR", ips)
            await scanner.run()
        except Exception as e:
            ui.error(f"Invalid CIDR: {e}")

    elif choice == '3': # BULK ASSET AUDIT
        files = get_txt_files()
        if not files:
            ui.error("No .txt files found.")
            return
        ui.info("Select a file:")
        for i, f in enumerate(files, 1):
            print(f"[{i}] {f}")
        f_idx = input("Choice: ").strip()
        try:
            path = files[int(f_idx)-1]
            with open(path, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
            scanner = AsyncScanner("BULK", targets)
            await scanner.run()
        except:
            ui.error("Invalid selection")

    elif choice == '4': # METHOD ANALYZER
        # Simplified for now: analyze different HTTP techniques
        target = input("Enter target: ").strip()
        ui.info(f"Analyzing methods for {target}...")
        # Dispatch to inspector for deep dive
        results = await Inspector.analyze_host(target)
        for r in results:
            print(f"Server: {r['server']} | Status: {r['status']} | WebSocket: {r['ws']}")

    elif choice == '5': # REVERSE DNS PRO
        ip = input("Enter IP: ").strip()
        ui.info(f"Reverse DNS for {ip}...")
        names = NetworkTool.get_reverse_dns(ip)
        if names:
            for name in names: ui.success(f"PTR: {name}")
        else:
            ui.warning("No PTR records found.")

    elif choice == '6': # IP TO ASN/CIDR
        ip = input("Enter IP: ").strip()
        ui.info(f"Looking up ASN for {ip}...")
        res = NetworkTool.ip_to_asn(ip)
        if res:
            ui.success(f"ASN: {res['asn']} | CIDR: {res['cidr']}")
            ui.success(f"ORG: {res['org']} | CC: {res['country']}")
        else:
            ui.error("Lookup failed.")

    elif choice == '7': # VIEW SAVED LOGS
        if os.path.exists("results"):
            logs = [f for f in os.listdir("results") if f.endswith(".txt")]
            if not logs: ui.info("No logs available.")
            else:
                for l in logs: print(f"- {l}")
        else: ui.info("Results directory empty.")

    elif choice == '8': # SETTINGS
        ui.info("Settings module coming soon...")

    elif choice == '9': # EXIT
        ui.success("Exiting...")
        sys.exit(0)

def main():
    while True:
        try:
            ui.banner()
            ui.menu()
            choice = input().strip()
            asyncio.run(handle_choice(choice))
            input("\nPress Enter to continue...")
        except KeyboardInterrupt:
            print("\n")
            ui.warning("Interrupted. Exiting...")
            break
        except Exception as e:
            ui.error(f"Error: {e}")
            input("\nPress Enter to return...")

if __name__ == "__main__":
    main()

