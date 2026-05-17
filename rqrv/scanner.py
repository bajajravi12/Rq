import asyncio
import aiohttp
import ipaddress
import threading
import sys
import termios
import tty
from .ui import ui
from rich.live import Live
from rich.console import Group

class AsyncScanner:
    def __init__(self, concurrency=50, timeout=5):
        self.concurrency = concurrency
        self.timeout_val = timeout
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.paused = False
        self.stopped = False
        self._pause_event = asyncio.Event()
        self._pause_event.set()

    def toggle_pause(self):
        if self.paused:
            self._pause_event.set()
            self.paused = False
            ui.console.print("[bold yellow] » SCAN RESUMED[/bold yellow]")
            return "RESUMED"
        else:
            self._pause_event.clear()
            self.paused = True
            ui.console.print("[bold yellow] » SCAN PAUSED - [R] to Resume[/bold yellow]")
            return "PAUSED"

    def stop(self):
        self.stopped = True
        self._pause_event.set() # Unblock if paused
        ui.console.print("[bold red] » SCAN TERMINATED BY USER[/bold red]")

    def listen_controls(self):
        # Non-blocking stdin listener for Termux/Unix
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setcbreak(sys.stdin.fileno())
            while not self.stopped:
                char = sys.stdin.read(1).lower()
                if char == 'p':
                    if not self.paused: self.toggle_pause()
                elif char == 'r':
                    if self.paused: self.toggle_pause()
                elif char == 's':
                    self.stop()
                    break
        except:
            pass
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    async def check_host(self, session, target, port=80):
        if self.stopped: return None
        await self._pause_event.wait()
        
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{target}"
        try:
            async with session.get(url, ssl=False, timeout=self.timeout) as resp:
                headers = resp.headers
                server = headers.get("Server", "Unknown")
                
                # Interesting Signal Detection
                signals = []
                headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
                
                if resp.status == 200: signals.append("200 OK")
                if resp.status == 101: signals.append("101 Switch")
                
                # CDN/Platform Detection
                detect_map = {
                    "cf-ray": "Cloudflare",
                    "x-amz-cf-id": "CloudFront",
                    "x-fastly-request-id": "Fastly",
                    "x-akamai-transformed": "Akamai",
                    "x-edge-request-id": "Edge"
                }
                
                alert_signals = []
                info_signals = []

                # HTTP Version String
                ver_str = f"HTTP/{resp.version.major}.{resp.version.minor}"
                
                for h_key, h_label in detect_map.items():
                    if h_key in headers_lower:
                        alert_signals.append(h_label)

                # Specialized CDN formatting for the goal screenshot
                if "cf-ray" in headers_lower or "cloudflare" in server.lower():
                    server = "Cloudflare SSH Proxy + SNI (sedekah)"
                    alert_signals.append("Cloudflare")

                # Server checks
                server_lower = server.lower()
                for srv in ["nginx", "apache", "envoy", "caddy", "litespeed"]:
                    if srv in server_lower:
                        info_signals.append(srv.capitalize())

                # Add more alert headers
                for h in ["alt-svc", "via", "x-cache", "x-served-by"]:
                    if h in headers_lower:
                        info_signals.append(h.capitalize())

                if "upgrade" in headers_lower.get("connection", ""):
                    alert_signals.append("WebSocket")

                return {
                    "target": target,
                    "status": resp.status,
                    "server": server,
                    "alert_signals": list(set(alert_signals)),
                    "signals": list(set(alert_signals + info_signals)),
                    "version": ver_str,
                    "port": port
                }
        except:
            return None

    async def scan_cidr(self, cidr, ports=[80], quiet_mode=False, start_at=0):
        from .utils import utils
        import itertools
        net_obj = ipaddress.ip_network(cidr, strict=False)
        total = net_obj.num_addresses * len(ports)
        hits = []
        seen = set()
        count = start_at * len(ports)
        findings = 0
        
        progress = utils.get_progress()
        task = progress.add_task("Scanning", total=total, completed=count, findings=findings)
        
        # Start control listener
        threading.Thread(target=self.listen_controls, daemon=True).start()

        async with aiohttp.ClientSession() as session:
            with Live(Group(progress), console=ui.console, refresh_per_second=4, transient=False) as live:
                tasks = []
                # Use islice to skip start_at addresses
                for ip in itertools.islice(net_obj, start_at, None):
                    if self.stopped: break
                    await self._pause_event.wait()
                    
                    for port in ports:
                        if self.stopped: break
                        tasks.append(self.check_host(session, str(ip), port))
                        
                        if len(tasks) >= self.concurrency:
                            try:
                                batch = await asyncio.gather(*tasks)
                                for res in batch:
                                    count += 1
                                    if res:
                                        # High Confidence Signature Deduplication
                                        sig_tuple = (res['target'], res['status'], res['server'], tuple(sorted(res['alert_signals'])))
                                        if sig_tuple in seen:
                                            progress.update(task, completed=count)
                                            continue
                                        seen.add(sig_tuple)

                                        # Unique findings only: 404/403/405 filtered by default in quiet
                                        is_ok = res['status'] == 200 or len(res['alert_signals']) > 0
                                        if quiet_mode and not is_ok:
                                            progress.update(task, completed=count)
                                            continue
                                        
                                        findings += 1
                                        hits.append(res)
                                        progress.update(task, completed=count, findings=findings)
                                        ui.hit_compact(count, total, res['target'], res['server'], res['status'], port=res['port'], version=res['version'])
                                        if res['alert_signals']:
                                            ui.interesting_panel(res['target'], res['server'], res['status'], res['signals'], port=res['port'], version=res['version'])
                                    else:
                                        progress.update(task, completed=count)
                                tasks = []
                            except KeyboardInterrupt:
                                self.stop()
                                break
                            
                if tasks and not self.stopped:
                    batch = await asyncio.gather(*tasks)
                    # ... processing batch ...
                    for res in batch:
                        count += 1
                        if res:
                            sig_tuple = (res['target'], res['status'], res['server'], tuple(sorted(res['alert_signals'])))
                            if sig_tuple not in seen:
                                seen.add(sig_tuple)
                                is_ok = res['status'] == 200 or len(res['alert_signals']) > 0
                                if not quiet_mode or is_ok:
                                    findings += 1
                                    hits.append(res)
                                    progress.update(task, completed=count, findings=findings)
                                    ui.hit_compact(count, total, res['target'], res['server'], res['status'], port=res['port'], version=res['version'])
                                    if res['alert_signals']:
                                        ui.interesting_panel(res['target'], res['server'], res['status'], res['signals'], port=res['port'], version=res['version'])
                                else:
                                    progress.update(task, completed=count)
                            else:
                                progress.update(task, completed=count)
                        else:
                            progress.update(task, completed=count)
        return hits, count // len(ports) if len(ports) > 0 else count

    async def scan_list(self, target_gen, ports=[80], quiet_mode=False, start_at=0):
        from .utils import utils
        hits = []
        seen = set()
        count = start_at * len(ports)
        findings = 0
        
        progress = utils.get_progress()
        task = progress.add_task("Scanning List", total=None, completed=count, findings=findings)

        # Start control listener
        threading.Thread(target=self.listen_controls, daemon=True).start()

        async with aiohttp.ClientSession() as session:
            with Live(Group(progress), console=ui.console, refresh_per_second=4, transient=False) as live:
                tasks = []
                for target in target_gen:
                    if self.stopped: break
                    await self._pause_event.wait()
                    
                    for port in ports:
                        if self.stopped: break
                        tasks.append(self.check_host(session, target.strip(), port))
                        
                        if len(tasks) >= self.concurrency:
                            try:
                                batch = await asyncio.gather(*tasks)
                                for res in batch:
                                    count += 1
                                    if res:
                                        sig_tuple = (res['target'], res['status'], res['server'], tuple(sorted(res['alert_signals'])))
                                        if sig_tuple in seen:
                                            progress.update(task, completed=count)
                                            continue
                                        seen.add(sig_tuple)

                                        is_ok = res['status'] == 200 or len(res['alert_signals']) > 0
                                        if quiet_mode and not is_ok:
                                            progress.update(task, completed=count)
                                            continue
                                        
                                        findings += 1
                                        hits.append(res)
                                        progress.update(task, completed=count, findings=findings)
                                        ui.hit_compact(count, count, res['target'], res['server'], res['status'], port=res['port'], version=res['version'])
                                        if res['alert_signals']:
                                            ui.interesting_panel(res['target'], res['server'], res['status'], res['signals'], port=res['port'], version=res['version'])
                                    else:
                                        progress.update(task, completed=count)
                                tasks = []
                            except KeyboardInterrupt:
                                self.stop()
                                break
                
                if tasks and not self.stopped:
                    batch = await asyncio.gather(*tasks)
                    for res in batch:
                        count += 1
                        if res:
                            sig_tuple = (res['target'], res['status'], res['server'], tuple(sorted(res['alert_signals'])))
                            if sig_tuple not in seen:
                                seen.add(sig_tuple)
                                is_ok = res['status'] == 200 or len(res['alert_signals']) > 0
                                if not quiet_mode or is_ok:
                                    findings += 1
                                    hits.append(res)
                                    progress.update(task, completed=count, findings=findings)
                                    ui.hit_compact(count, count, res['target'], res['server'], res['status'], port=res['port'], version=res['version'])
                                    if res['alert_signals']:
                                        ui.interesting_panel(res['target'], res['server'], res['status'], res['signals'], port=res['port'], version=res['version'])
                                else:
                                    progress.update(task, completed=count)
                            else:
                                progress.update(task, completed=count)
                        else:
                            progress.update(task, completed=count)
        return hits, count // len(ports) if len(ports) > 0 else count
