import os
import datetime
import json
from rich.progress import Progress, BarColumn, TextColumn

class Utils:
    def __init__(self):
        self.settings_file = "settings.json"
        self.session_file = "session_state.json"
        self.defaults = {
            "threads": 50,
            "timeout": 5,
            "retries": 1,
            "chunk_size": 100,
            "ports": "80,443",
            "show_all": True,
            "save_logs": True,
            "quiet_mode": False
        }
        self.settings = self.load_settings()
        self.session = self.load_session()

    def load_settings(self):
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, "r") as f:
                    return {**self.defaults, **json.load(f)}
            except:
                return self.defaults
        return self.defaults

    def save_settings(self, new_settings):
        self.settings = new_settings
        with open(self.settings_file, "w") as f:
            json.dump(self.settings, f, indent=4)

    def load_session(self):
        if os.path.exists(self.session_file):
            try:
                with open(self.session_file, "r") as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_session(self, key, value):
        self.session[key] = value
        with open(self.session_file, "w") as f:
            json.dump(self.session, f, indent=4)

    @staticmethod
    def ensure_dirs():
        for d in ["results", "logs"]:
            if not os.path.exists(d):
                os.makedirs(d)

    @staticmethod
    def log_scan(mode, data):
        Utils.ensure_dirs()
        ts = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M')
        
        # Save JSON results
        jname = f"results/scan_{mode}_{ts}.json"
        with open(jname, "w") as f:
            json.dump(data, f, indent=4)
            
        # Categorized files
        cats = {
            "cloudflare": [],
            "cloudfront": [],
            "nginx": [],
            "interesting": []
        }
        
        # Save readable logs
        lname = f"logs/scan_{ts}.log"
        with open(lname, "w") as f:
            f.write(f"RQ INFRA ANALYSIS LOG | {ts}\n")
            f.write("=" * 60 + "\n\n")
            seen = set()
            for hit in data:
                t = hit.get('target')
                if t in seen: continue
                seen.add(t)
                
                stat = hit.get('status')
                serv = hit.get('server', 'Unknown').lower()
                sigs = hit.get('signals', [])
                sigs_str = ", ".join(sigs)
                
                line = f"[HTTP {stat}] {t:<25} | {serv:<12} | Signals: {sigs_str}\n"
                f.write(line)
                
                # Sort into categories
                added = False
                if any("cloudflare" in s.lower() for s in signals_to_check(hit)):
                    cats["cloudflare"].append(t)
                    added = True
                if any("cloudfront" in s.lower() for s in signals_to_check(hit)):
                    cats["cloudfront"].append(t)
                    added = True
                if "nginx" in serv:
                    cats["nginx"].append(t)
                    added = True
                
                if not added or len(sigs) > 2:
                    cats["interesting"].append(t)

        # Write categorized files
        for cat, targets in cats.items():
            if targets:
                with open(f"results/{cat}.txt", "a") as cf:
                    for target in sorted(list(set(targets))):
                        cf.write(f"{target}\n")

        return lname

def signals_to_check(hit):
    return hit.get('signals', []) + [hit.get('server', '')]

    @staticmethod
    def get_progress():
        return Progress(
            TextColumn("[bold cyan]『 RQ ACTIVE 』[/bold cyan]"),
            BarColumn(bar_width=15, style="grey15", complete_style="bright_cyan", finished_style="bright_green"),
            TextColumn("[bold white]{task.percentage:>3.0f}%[/bold white]"),
            TextColumn(" [dim]Findings: [bold yellow]{task.fields[findings]}[/bold yellow][/dim]"),
            expand=False
        )

utils = Utils()
