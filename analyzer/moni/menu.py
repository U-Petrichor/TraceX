import os
import sys
import platform

# Define scripts relative to project root
SCRIPTS = [
    {
        "name": "APT28 (Fancy Bear)",
        "sim": "analyzer/moni/simulate_apt28.py",
        "verify": "analyzer/moni/verify_apt28.py"
    },
    {
        "name": "APT29 (Cozy Bear)",
        "sim": "analyzer/moni/simulate_apt29.py",
        "verify": "analyzer/moni/verify_apt29.py"
    },
    {
        "name": "FIN7",
        "sim": "analyzer/moni/simulate_fin7.py",
        "verify": "analyzer/moni/verify_fin7.py"
    },
    {
        "name": "Indrik Spider",
        "sim": "analyzer/moni/simulate_indrik_spider.py",
        "verify": "analyzer/moni/verify_indrik_spider.py"
    },
    {
        "name": "LuminousMoth",
        "sim": "analyzer/moni/simulate_luminousmoth.py",
        "verify": "analyzer/moni/verify_luminousmoth.py"
    }
]

CLEANUP_SCRIPT = "analyzer/moni/cleanup_apt_data.py"

def clear_screen():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def run_script(path):
    if not os.path.exists(path):
        print(f"\n[!] Error: Script not found: {path}")
        return
    
    print(f"\n[+] Executing: {path}")
    print("-" * 50)
    # Run using the current python interpreter
    ret = os.system(f"{sys.executable} {path}")
    print("-" * 50)
    if ret == 0:
        print("[+] Execution successful.")
    else:
        print(f"[!] Execution failed with code {ret}.")

def main():
    while True:
        # clear_screen() # Optional: keep history visible
        print("\n==========================================")
        print("    TraceX APT Simulation Controller")
        print("==========================================")
        print("  0. Exit")
        print("  C. Clean Up / Reset All (Remove Buttons)")
        print("-" * 42)
        print("  #  | Group Name      | Actions")
        print("-" * 42)
        
        for i, item in enumerate(SCRIPTS):
            print(f"  {i+1}. | {item['name']:<15} | [S]imulate / [V]erify")

        choice = input("\nEnter choice (e.g., '1' for Sim, '1v' for Verify, 'C' for Cleanup): ").strip().lower()

        if choice == '0':
            print("Bye!")
            break
        
        if choice == 'c':
            run_script(CLEANUP_SCRIPT)
            continue

        # Parse numeric choice
        target_idx = -1
        is_verify = False
        
        try:
            if choice.endswith('v'):
                target_idx = int(choice[:-1]) - 1
                is_verify = True
            elif choice.endswith('s'): # optional 's' suffix
                target_idx = int(choice[:-1]) - 1
                is_verify = False
            else:
                target_idx = int(choice) - 1
                is_verify = False # Default to simulate
        except ValueError:
            print("\n[!] Invalid input.")
            continue

        if 0 <= target_idx < len(SCRIPTS):
            item = SCRIPTS[target_idx]
            script_to_run = item['verify'] if is_verify else item['sim']
            action_name = "Verification" if is_verify else "Simulation"
            
            print(f"\n[*] Selected: {item['name']} - {action_name}")
            run_script(script_to_run)
        else:
            print("\n[!] Invalid selection number.")

if __name__ == "__main__":
    # Ensure we are in the project root if run from subfolder
    # (Assuming script is in analyzer/moni/)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # If we are in analyzer/moni, go up two levels to project root
    # But user is likely running from project root as 'python analyzer/moni/menu.py'
    # So we just trust relative paths or check cwd
    
    if not os.path.exists("analyzer"):
        print("[!] Warning: Please run this script from the project root (e.g., 'python analyzer/moni/menu.py')")
    
    main()
