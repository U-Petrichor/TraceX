import time
import os
import subprocess
import sys

def check_audit_env():
    print("="*60)
    print(" 🕵️‍♂️ TraceX Auditd Environment Checker")
    print("="*60)

    # 1. Check Root
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("❌ Error: Must run as root.")
        sys.exit(1)
    print("✅ Running as root")

    # 2. Check Rules
    print("\n[Step 1] Checking Audit Rules (auditctl -l)...")
    try:
        rules = subprocess.check_output(["auditctl", "-l"]).decode()
        if not rules.strip() or rules.strip() == "No rules":
            print("⚠️  No audit rules active.")
        else:
            print(rules.strip())
            
        if "/etc/passwd" not in rules and "passwd_read" not in rules:
            print("\n⚠️  WARNING: No specific rule found for /etc/passwd!")
            print("👉 Run this command to enable monitoring:")
            print("   auditctl -w /etc/passwd -p r -k passwd_read")
        else:
            print("✅ Rule for /etc/passwd detected.")
    except FileNotFoundError:
        print("❌ Error: 'auditctl' command not found. Is auditd installed?")
        return
    except Exception as e:
        print(f"❌ Error checking rules: {e}")

    # 3. Monitor Log File
    log_file = "/var/log/audit/audit.log"
    if not os.path.exists(log_file):
        print(f"\n❌ Error: Log file {log_file} does not exist.")
        return

    print(f"\n[Step 2] Monitoring {log_file} for new events...")
    print("👉 Please run 'sudo cat /etc/passwd' in another terminal NOW.")
    print("   (Press Ctrl+C to stop monitoring when you see logs)\n")

    try:
        f = open(log_file, 'r')
        f.seek(0, 2) # Go to end
        
        while True:
            line = f.readline()
            if line:
                print(f"📄 New Log: {line.strip()}")
                if "type=EOE" in line:
                    print("   (EOE Detected - Event should flush)")
            else:
                time.sleep(0.1)
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as e:
        print(f"\n❌ Error reading file: {e}")

if __name__ == "__main__":
    check_audit_env()
