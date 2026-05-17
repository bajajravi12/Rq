import os
import datetime
import json
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

class Utils:
    @staticmethod
    def ensure_dirs():
        for d in ["results", "logs"]:
            if not os.path.exists(d):
                os.makedirs(d)

    @staticmethod
    def log_scan(id, data):
        Utils.ensure_dirs()
        fname = f"results/scan_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M')}.json"
        with open(fname, "w") as f:
            json.dump(data, f, indent=4)
        return fname

    @staticmethod
    def get_progress():
        return Progress(
            TextColumn("[bold cyan]『 RQ ACTIVE 』[/bold cyan]"),
            BarColumn(bar_width=15, style="grey15", complete_style="bright_cyan", finished_style="bright_green"),
            TextColumn("[bold white]{task.percentage:>3.0f}%[/bold white]"),
            expand=False
        )

utils = Utils()
