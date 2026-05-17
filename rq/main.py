import os
import sys
from .ui import UI
from .scanner import Scanner

def get_txt_files():
    paths = [
        os.path.expanduser("~"),
        os.path.expanduser("~/storage/downloads"),
        os.path.expanduser("~/storage/shared"),
        os.path.expanduser("~/storage/documents")
    ]
    
    found_files = []
    for path in paths:
        if os.path.exists(path):
            try:
                for file in os.listdir(path):
                    if file.endswith(".txt"):
                        found_files.append(os.path.join(path, file))
            except:
                pass
    return found_files

def main():
    UI.banner()
    UI.menu()
    
    choice = input().strip()
    
    if choice == '1':
        # File Scan
        files = get_txt_files()
        UI.info("Detected .txt files:")
        for i, f in enumerate(files):
            print(f"{Fore.RED}[{i+1}]{Fore.WHITE} {f}")
        print(f"{Fore.RED}[C]{Fore.WHITE} Custom Path")
        
        f_choice = input("\nSelect file or enter 'C': ").strip()
        
        file_path = ""
        if f_choice.lower() == 'c':
            file_path = input("Enter custom path: ").strip()
        else:
            try:
                idx = int(f_choice) - 1
                file_path = files[idx]
            except:
                UI.error("Invalid selection")
                return

        ports_raw = input("Enter ports (default 80,443): ").strip()
        ports = [int(p.strip()) for p in ports_raw.split(',')] if ports_raw else [80, 443]
        
        scanner = Scanner("FILE", file_path, ports)
        scanner.start()

    elif choice == '2':
        # CIDR Scan
        cidr = input("Enter CIDR (e.g. 192.168.1.0/24): ").strip()
        if not cidr:
            UI.error("CIDR is required")
            return
            
        ports_raw = input("Enter ports (default 80,443): ").strip()
        ports = [int(p.strip()) for p in ports_raw.split(',')] if ports_raw else [80, 443]
        
        scanner = Scanner("CIDR", cidr, ports)
        scanner.start()
    
    else:
        UI.error("Invalid option")

if __name__ == "__main__":
    main()
