import asyncio
import aiohttp
import ipaddress
from .ui import ui

from rich.live import Live
from rich.console import Group

class AsyncScanner:
    def __init__(self, concurrency=50):
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=3)

    async def check_host(self, session, target, port=80):
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{target}"
        try:
            async with session.get(url, ssl=False, timeout=self.timeout) as resp:
                server = resp.headers.get("Server", "Unknown")
                return {
                    "target": target,
                    "status": resp.status,
                    "server": server
                }
        except:
            return None

    async def scan_cidr(self, cidr, ports=[80]):
        from .utils import utils
        network = ipaddress.ip_network(cidr, strict=False)
        total = network.num_addresses * len(ports)
        hits = []
        count = 0
        
        progress = utils.get_progress()
        task = progress.add_task("Scanning", total=total)
        
        async with aiohttp.ClientSession() as session:
            with Live(Group(progress), console=ui.console, refresh_per_second=4) as live:
                tasks = []
                for ip in network:
                    for port in ports:
                        tasks.append(self.check_host(session, str(ip), port))
                        if len(tasks) >= self.concurrency:
                            batch = await asyncio.gather(*tasks)
                            for res in batch:
                                count += 1
                                progress.update(task, completed=count)
                                if res:
                                    hits.append(res)
                                    ui.hit_compact(count, total, res['target'], res['server'], res['status'])
                            tasks = []
                
                if tasks:
                    batch = await asyncio.gather(*tasks)
                    for res in batch:
                        count += 1
                        progress.update(task, completed=count)
                        if res:
                            hits.append(res)
                            ui.hit_compact(count, total, res['target'], res['server'], res['status'])
        return hits

    async def scan_list(self, targets, ports=[80]):
        from .utils import utils
        hits = []
        total = len(targets) * len(ports)
        count = 0
        
        progress = utils.get_progress()
        task = progress.add_task("Scanning", total=total)

        async with aiohttp.ClientSession() as session:
            with Live(Group(progress), console=ui.console, refresh_per_second=4) as live:
                tasks = []
                for target in targets:
                    for port in ports:
                        tasks.append(self.check_host(session, target.strip(), port))
                        if len(tasks) >= self.concurrency:
                            batch = await asyncio.gather(*tasks)
                            for res in batch:
                                count += 1
                                progress.update(task, completed=count)
                                if res:
                                    hits.append(res)
                                    ui.hit_compact(count, total, res['target'], res['server'], res['status'])
                            tasks = []
                if tasks:
                    batch = await asyncio.gather(*tasks)
                    for res in batch:
                        count += 1
                        progress.update(task, completed=count)
                        if res:
                            hits.append(res)
                            ui.hit_compact(count, total, res['target'], res['server'], res['status'])
        return hits
