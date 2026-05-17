import asyncio
import aiohttp
import ipaddress
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
            return "RESUMED"
        else:
            self._pause_event.clear()
            self.paused = True
            return "PAUSED"

    def stop(self):
        self.stopped = True
        self._pause_event.set() # Unblock if paused

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
                    "x-edge-request-id": "Edge",
                    "alt-svc": "Alt-Svc",
                    "via": "Proxy/Via",
                    "x-cache": "Cache Hit",
                    "x-served-by": "LoadBalancer"
                }
                
                for h_key, h_label in detect_map.items():
                    if h_key in headers_lower:
                        signals.append(h_label)

                # Server checks
                server_lower = server.lower()
                for srv in ["nginx", "apache", "envoy", "caddy", "litespeed"]:
                    if srv in server_lower:
                        signals.append(srv.capitalize())

                # Protocol
                if resp.version == aiohttp.HttpVersion11:
                    signals.append("HTTP/1.1")
                elif resp.version == aiohttp.HttpVersion10:
                    signals.append("HTTP/1.0")
                
                # TLS/SSL Check (Basic) - If we're on 443 and got here, it's TLS
                if protocol == "https":
                    signals.append("TLS")

                if "upgrade" in headers_lower.get("connection", ""):
                    signals.append("WS:Supported")

                return {
                    "target": target,
                    "status": resp.status,
                    "server": server,
                    "signals": list(set(signals)),
                    "version": str(resp.version),
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
                                        sig_tuple = (res['target'], res['status'], res['server'], tuple(sorted(res['signals'])))
                                        if sig_tuple in seen:
                                            progress.update(task, completed=count)
                                            continue
                                        seen.add(sig_tuple)

                                        # Unique findings only: 404/403/405 filtered by default in quiet
                                        is_ok = res['status'] == 200 or len(res['signals']) > 0
                                        if quiet_mode and not is_ok:
                                            progress.update(task, completed=count)
                                            continue
                                        
                                        findings += 1
                                        hits.append(res)
                                        progress.update(task, completed=count, findings=findings)
                                        ui.hit_compact(count, total, res['target'], res['server'], res['status'], port=res['port'], version=res['version'])
                                        if res['signals']:
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
                            sig_tuple = (res['target'], res['status'], res['server'], tuple(sorted(res['signals'])))
                            if sig_tuple not in seen:
                                seen.add(sig_tuple)
                                is_ok = res['status'] == 200 or len(res['signals']) > 0
                                if not quiet_mode or is_ok:
                                    findings += 1
                                    hits.append(res)
                                    progress.update(task, completed=count, findings=findings)
                                    ui.hit_compact(count, total, res['target'], res['server'], res['status'], port=res['port'], version=res['version'])
                                    if res['signals']:
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
                                        sig_tuple = (res['target'], res['status'], res['server'], tuple(sorted(res['signals'])))
                                        if sig_tuple in seen:
                                            progress.update(task, completed=count)
                                            continue
                                        seen.add(sig_tuple)

                                        is_ok = res['status'] == 200 or len(res['signals']) > 0
                                        if quiet_mode and not is_ok:
                                            progress.update(task, completed=count)
                                            continue
                                        
                                        findings += 1
                                        hits.append(res)
                                        progress.update(task, completed=count, findings=findings)
                                        ui.hit_compact(count, count, res['target'], res['server'], res['status'], port=res['port'], version=res['version'])
                                        if res['signals']:
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
                            sig_tuple = (res['target'], res['status'], res['server'], tuple(sorted(res['signals'])))
                            if sig_tuple not in seen:
                                seen.add(sig_tuple)
                                is_ok = res['status'] == 200 or len(res['signals']) > 0
                                if not quiet_mode or is_ok:
                                    findings += 1
                                    hits.append(res)
                                    progress.update(task, completed=count, findings=findings)
                                    ui.hit_compact(count, count, res['target'], res['server'], res['status'], port=res['port'], version=res['version'])
                                    if res['signals']:
                                        ui.interesting_panel(res['target'], res['server'], res['status'], res['signals'], port=res['port'], version=res['version'])
                                else:
                                    progress.update(task, completed=count)
                            else:
                                progress.update(task, completed=count)
                        else:
                            progress.update(task, completed=count)
        return hits, count // len(ports) if len(ports) > 0 else count
