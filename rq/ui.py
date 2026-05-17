import os
import sys
from colorama import Fore, Style, init

init(autoreset=True)

class UI:
    @staticmethod
    def clear():
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def banner():
        UI.clear()
        banner = f"""
{Fore.RED}{Style.BRIGHT}    ██████╗  █████╗ ██╗   ██╗ █████╗ ███╗   ██╗
    ██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║
    ██████╔╝███████║██║   ██║███████║██╔██╗ ██║
    ██╔══██╗██╔══██║╚██╗ ██╔╝██╔══██║██║╚██╗██║
    ██║  ██║██║  ██║ ╚████╔╝ ██║  ██║██║ ╚████║
    ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝
    {Fore.WHITE}{Style.DIM}INFRA-X LITE v1.0.0 | Termux Optimized
        """
        print(banner)

    @staticmethod
    def menu():
        print(f"{Fore.RED}[1]{Fore.WHITE} FILE SCAN")
        print(f"{Fore.RED}[2]{Fore.WHITE} CIDR SCAN")
        print("\n" + Fore.RED + "» " + Fore.WHITE, end="")

    @staticmethod
    def progress_bar(current, total, ip, hits, threads):
        width = 10
        percent = (current / total) * 100
        filled = int(width * current // total)
        bar = '█' * filled + '░' * (width - filled)
        
        # Compact Termux UI
        sys.stdout.write(f"\r{Fore.RED}『 HUNTER ACTIVE 』{Fore.RESET}\n")
        sys.stdout.write(f"{Fore.WHITE}{ip}{Fore.RESET}\n")
        sys.stdout.write(f"{Fore.RED}{bar} {Fore.WHITE}{percent:.0f}%\n")
        sys.stdout.write(f"{Fore.RED}H:{hits} / T:{threads}{Fore.RESET}\n")
        # Move cursor back up 4 lines to overwrite
        sys.stdout.write("\033[4A")
        sys.stdout.flush()

    @staticmethod
    def hit_panel(target, server, status, method, version):
        print("\n" + Fore.RED + "╭──── HIT ────╮")
        print(f"{Fore.WHITE}Proxy   {target}")
        print(f"{Fore.WHITE}Server  {server}")
        print(f"{Fore.WHITE}Status  {status}")
        print(f"{Fore.WHITE}Method  {method}")
        print(f"{Fore.WHITE}Signal  Responsive")
        print(f"{Fore.WHITE}Version {version}")
        print(Fore.RED + "╰─────────────╯")

    @staticmethod
    def info(msg):
        print(f"{Fore.BLUE}[i]{Fore.WHITE} {msg}")

    @staticmethod
    def success(msg):
        print(f"{Fore.GREEN}[+]{Fore.WHITE} {msg}")

    @staticmethod
    def error(msg):
        print(f"{Fore.RED}[!]{Fore.WHITE} {msg}")
