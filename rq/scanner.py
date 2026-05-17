import asyncio
import aiohttp
import json
import os
import time
import ipaddress
from .ui import ui

class AsyncScanner:
    def __init__(self, mode, targets, ports=[80, 443]):
        self.mode = mode
        self.targets = targets # List of IPs or domains
        self.ports = ports
        self.resume_file = f"cache/resume_{mode.lower()}.json"
        
        self.current_idx = 0
        self.hits = 0
        self.results = []
        self.is_paused = False
        self.should_stop = False
        
        if not os.path.exists("cache"): os.makedirs("cache")
        if not os.path.exists("results"): os.makedirs("results")

    def save_state(self):
        with open(self.resume_file, "w") as f:
            json.dump({"idx": self.current_idx, "hits": self.hits}, f)

    def load_state(self):
        if os.path.exists(self.resume_file):
            with open(self.resume_file, "r") as f:
                data = json.load(f)
                self.current_idx = data.get("idx", 0)
                self.hits = data.get("hits", 0)
                return True
        return False

    async def scan_worker(self, session, target, port):
        if self.should_stop: return
        while self.is_paused:
            await asyncio.sleep(1)
            
        url = f"http{'s' if port == 443 else ''}://{target}:{port}"
        try:
            async with session.get(url, timeout=3, allow_redirects=False) as resp:
                # Basic useful signals only
                server = resp.headers.get("Server", "Unknown")
                status = resp.status
                
                # Report hit
                self.hits += 1
                hit_data = f"{target}:{port} | {server} | {status}"
                self.results.append(hit_data)
                
                # Check for CDN
                cdn = "No"
                if any(h in resp.headers for h in ["CF-Ray", "x-amz-cf-id"]): cdn = "Yes"
                
                # For high speed bulk, we don't print full panel every hit unless requested
                # but we can do a compact log
        except:
            pass

    async def run(self):
        ui.info(f"Preparing {len(self.targets)} targets...")
        
        if self.load_state():
            ui.warning(f"Resume state found at index {self.current_idx}. Continuing...")
        
        chunk_size = 50
        connector = aiohttp.TCPConnector(limit=chunk_size, ssl=False)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for i in range(self.current_idx, len(self.targets)):
                if self.should_stop: break
                
                target = self.targets[i]
                for port in self.ports:
                    tasks.append(self.scan_worker(session, target, port))
                
                self.current_idx = i
                
                if len(tasks) >= chunk_size:
                    await asyncio.gather(*tasks)
                    tasks = []
                    ui.progress_ui(self.current_idx, len(self.targets), target, self.hits)
                    self.save_state()
            
            if tasks:
                await asyncio.gather(*tasks)

        ui.success(f"Scan Finished. Hits: {self.hits}")
        if os.path.exists(self.resume_file): os.remove(self.resume_file)
        
        # Save results
        out_path = f"results/scan_{int(time.time())}.txt"
        with open(out_path, "w") as f:
            f.write("\n".join(self.results))
        ui.success(f"Log saved: {out_path}")

