import time
import subprocess
import os
import sys
import json
from datetime import datetime

# === Imports Setup ===
# Ensure project root is in sys.path to allow absolute imports
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from collector.host_collector.log_parser import HostLogParser
except ImportError:
    # Fallback for local testing if running directly in folder
    sys.path.append(current_dir)
    from log_parser import HostLogParser

try:
    from elasticsearch import Elasticsearch
except ImportError:
    print("[-] Error: 'elasticsearch' module missing. Please run: pip install elasticsearch")
    sys.exit(1)

# === Configuration ===
LOG_FILE = "/var/log/audit/audit.log"
ES_HOST = "http://localhost:9200"

def clean_dict(d):
    """Recursively remove empty strings to avoid ES mapper_parsing_exception"""
    if not isinstance(d, dict):
        return d
    return {k: clean_dict(v) for k, v in d.items() if v != ""}

def make_raw_doc(line_str):
    """Wraps unknown logs into a JSON document"""
    return {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "message": line_str,
        "event": {
            "category": "raw_log",
            "dataset": "unknown"
        }
    }

def main():
    # === Root Check ===
    # os.geteuid() is only available on Unix
    if hasattr(os, 'geteuid') and os.geteuid() != 0:
        print("[-] Error: Must run as root to read audit logs! Use 'sudo python3 ...'")
        sys.exit(1)

    # === Initialization ===
    print(f"[*] Connecting to Elasticsearch at {ES_HOST}...")
    try:
        es = Elasticsearch(ES_HOST)
        if not es.ping():
            print(f"[-] Warning: Could not connect to ES at {ES_HOST}. Check Docker is running.")
        else:
            print("[+] Connected to ES successfully.")
    except Exception as e:
        print(f"[-] Error connecting to ES: {e}")
        sys.exit(1)

    parser = HostLogParser()
    index_name = f"unified-logs-{datetime.utcnow().strftime('%Y.%m.%d')}"
    
    print(f"[*] Monitoring log file: {LOG_FILE}")
    print(f"[*] Target Index: {index_name}")

    if not os.path.exists(LOG_FILE):
        print(f"[-] Warning: {LOG_FILE} does not exist. Tail will wait for it to appear.")

    # === Core Loop: Tail -F ===
    # Using subprocess to run tail -F which handles log rotation automatically
    try:
        proc = subprocess.Popen(
            ['tail', '-F', LOG_FILE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
    except FileNotFoundError:
        print("[-] Error: 'tail' command not found. Ensure you are running on a Linux system with coreutils installed.")
        sys.exit(1)

    print("[*] Agent is running. Waiting for events...")

    try:
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            
            try:
                line_str = line.decode('utf-8').strip()
            except UnicodeDecodeError:
                continue

            if not line_str:
                continue

            # === Step 1: Detection ===
            # Check if the line looks like a standard Auditd log
            is_auditd = "type=" in line_str and "msg=audit" in line_str

            if is_auditd:
                # === Step 2: Smart Path (Auditd) ===
                # Pass to parser. It handles buffering internally.
                event = parser.parse(line_str, log_type="auditd")
                
                # Only ingest if we get a complete event back (not None)
                if event:
                    doc = event.to_dict()
                    doc = clean_dict(doc)
                    
                    # Logging for visibility
                    cmd_line = doc.get('process', {}).get('command_line', 'Unknown')
                    print(f"[+] Sending Auditd Event: {cmd_line}")
                    
                    try:
                        es.index(index=index_name, document=doc)
                    except Exception as e:
                        print(f"[-] ES Write Error (Auditd): {e}")
                else:
                    # Returns None -> Buffering. Do NOTHING.
                    pass

            else:
                # === Step 3: Fallback Path (Unknown/Garbage) ===
                # Treat as raw log to prevent data loss
                print(f"[+] Sending Raw Log: {line_str[:50]}...")
                raw_doc = make_raw_doc(line_str)
                
                try:
                    es.index(index=index_name, document=raw_doc)
                except Exception as e:
                    print(f"[-] ES Write Error (Raw): {e}")

    except KeyboardInterrupt:
        print("\n[*] Stopping agent...")
        proc.terminate()

if __name__ == "__main__":
    main()
