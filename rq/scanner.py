import socket
import requests
import threading
import time
import json
import os
import ipaddress
from queue import Queue
from .ui import UI

# Disable warnings for SSL
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Scanner:
    def __init__(self, mode, target, ports, resume_file=None):
        self.mode = mode
        self.target = target # File path or CIDR
        self.ports = ports if ports else [80, 443]
        self.resume_file = resume_file or f"results/{mode}_resume.json"
        
        self.queue = Queue()
        self.results = []
        self.seen = set()
        
        self.is_paused = threading.Event()
        self.is_paused.set() # Not paused initially
        self.should_stop = threading.Event()
        
        self.current_idx = 0
        self.total_targets = 0
        self.hits = 0
        self.threads_count = 50
        
        if not os.path.exists("results"):
            os.makedirs("results")

    def load_resume(self):
        if os.path.exists(self.resume_file):
            try:
                with open(self.resume_file, 'r') as f:
                    data = json.load(f)
                    self.current_idx = data.get('idx', 0)
                    return True
            except:
                pass
        return False

    def save_resume(self):
        with open(self.resume_file, 'w') as f:
            json.dump({'idx': self.current_idx}, f)

    def analyze_response(self, target, response):
        headers = response.headers
        server = headers.get('Server', 'Unknown')
        status = f"{response.status_code} {response.reason}"
        method = "GET"
        version = f"HTTP/{response.raw.version/10:.1f}" if hasattr(response.raw, 'version') else "HTTP/1.1"
        
        # Hints
        hints = []
        if 'Upgrade' in headers or 'websocket' in headers.get('Connection', '').lower():
            hints.append("WS-Upgrade")
        if any(h in headers for h in ['CF-Ray', 'cf-cache-status', 'Alt-Svc']):
            hints.append("CDN")
        if any(h in headers for h in ['Via', 'X-Cache']):
            hints.append("Proxy")
        
        hit_str = f"{target} | {server} | {status}"
        if hints:
            hit_str += f" | ({', '.join(hints)})"
            
        return {
            'target': target,
            'server': server,
            'status': status,
            'method': method,
            'version': version,
            'hit_str': hit_str
        }

    def worker(self):
        while not self.queue.empty() and not self.should_stop.is_set():
            self.is_paused.wait()
            
            idx, target, port = self.queue.get()
            self.current_idx = idx
            
            full_target = f"{target}:{port}"
            if full_target in self.seen:
                self.queue.task_done()
                continue
            self.seen.add(full_target)
            
            try:
                url = f"http{'s' if port == 443 else ''}://{target}:{port}"
                # Fast probe
                resp = requests.get(url, timeout=3, verify=False, allow_redirects=False)
                
                # Check for interesting headers/status
                analysis = self.analyze_response(full_target, resp)
                self.hits += 1
                self.results.append(analysis['hit_str'])
                
                UI.hit_panel(
                    analysis['target'], 
                    analysis['server'], 
                    analysis['status'], 
                    analysis['method'], 
                    analysis['version']
                )
                
                # Update progress UI (compensate for printing)
                # In real Termux, we might need to skip progress bar during HITs
            except (requests.exceptions.RequestException, socket.error):
                pass
            
            self.queue.task_done()

    def start(self):
        targets = []
        if self.mode == "FILE":
            if os.path.exists(self.target):
                with open(self.target, 'r') as f:
                    lines = [line.strip() for line in f if line.strip()]
                    for i, line in enumerate(lines):
                        for port in self.ports:
                            targets.append((i, line, port))
            else:
                UI.error(f"File not found: {self.target}")
                return
        elif self.mode == "CIDR":
            try:
                network = ipaddress.ip_network(self.target, strict=False)
                for i, ip in enumerate(network):
                    for port in self.ports:
                        targets.append((i, str(ip), port))
            except Exception as e:
                UI.error(f"Invalid CIDR: {e}")
                return

        self.total_targets = len(targets)
        
        # Apply resume
        start_at = 0
        if self.load_resume():
            start_at = self.current_idx
            UI.info(f"Resuming from index {start_at}")
        
        for t in targets[start_at:]:
            self.queue.put(t)

        UI.info(f"Starting scan with {self.threads_count} threads...")
        
        threads = []
        for _ in range(self.threads_count):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)

        # Control thread
        def monitor():
            while not self.queue.empty() and not self.should_stop.is_set():
                if self.is_paused.is_set():
                    UI.progress_bar(self.current_idx, self.total_targets, "Scanning...", self.hits, self.threads_count)
                time.sleep(1)

        monitor_thread = threading.Thread(target=monitor)
        monitor_thread.daemon = True
        monitor_thread.start()

        # Input loop for controls
        try:
            while not self.queue.empty() and not self.should_stop.is_set():
                # In a real tool, we'd use non-blocking input
                # For this version, we'll listen for basic commands if possible
                cmd = input().lower().strip()
                if cmd == 'p':
                    self.is_paused.clear()
                    UI.info("Paused. Press 'r' to resume or 'q' to quit.")
                elif cmd == 'r':
                    self.is_paused.set()
                    UI.info("Resuming...")
                elif cmd == 'q':
                    self.should_stop.set()
                    self.save_resume()
                    UI.info("Saving progress and quitting...")
                    break
        except KeyboardInterrupt:
            self.should_stop.set()
            self.save_resume()
            UI.info("\nInterrupted. Progress saved.")

        self.queue.join()
        UI.success("Scan complete.")
        
        save = input("Save results? [Y/N]: ").lower()
        if save == 'y':
            output_file = f"results/scan_{int(time.time())}.txt"
            with open(output_file, 'w') as f:
                f.write("\n".join(self.results))
            UI.success(f"Results saved to {output_file}")
            # Delete resume file on completion
            if os.path.exists(self.resume_file):
                os.remove(self.resume_file)
