import asyncio
import aiohttp
import ipaddress
from .ui import ui

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
        network = ipaddress.ip_network(cidr, strict=False)
        total = network.num_addresses
        hits = []
        
        # Generator for chunk scanning
        async with aiohttp.ClientSession() as session:
            tasks = []
            count = 0
            for ip in network:
                for port in ports:
                    tasks.append(self.check_host(session, str(ip), port))
                    if len(tasks) >= self.concurrency:
                        batch = await asyncio.gather(*tasks)
                        for res in batch:
                            if res:
                                hits.append(res)
                                ui.hit_compact(res['target'], res['server'], res['status'])
                        tasks = []
                        count += self.concurrency
                
            if tasks:
                batch = await asyncio.gather(*tasks)
                for res in batch:
                    if res:
                        hits.append(res)
        return hits

    async def scan_list(self, targets, ports=[80]):
        hits = []
        async with aiohttp.ClientSession() as session:
            tasks = []
            for target in targets:
                for port in ports:
                    tasks.append(self.check_host(session, target.strip(), port))
                    if len(tasks) >= self.concurrency:
                        batch = await asyncio.gather(*tasks)
                        for res in batch:
                            if res:
                                hits.append(res)
                                ui.hit_compact(res['target'], res['server'], res['status'])
                        tasks = []
            if tasks:
                batch = await asyncio.gather(*tasks)
                for res in batch:
                    if res:
                        hits.append(res)
        return hits
