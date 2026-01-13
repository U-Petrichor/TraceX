import time
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
STATE_FILE = os.path.join(current_dir, "agent_state.json")
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

def get_inode(filepath):
    """Get the inode of a file, return None if file doesn't exist"""
    try:
        return os.stat(filepath).st_ino
    except FileNotFoundError:
        return None

def load_state():
    """Load the last read position from disk"""
    if not os.path.exists(STATE_FILE):
        return None
    try:
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[-] Error loading state: {e}")
        return None

def save_state(inode, offset):
    """Save the current read position to disk"""
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump({"inode": inode, "offset": offset}, f)
    except Exception as e:
        print(f"[-] Error saving state: {e}")

def get_display_summary(doc):
    """Optimize display to avoid 'Unknown' flooding"""
    process = doc.get('process', {})
    event = doc.get('event', {})
    
    # Priority 1: Command Line
    cmd = process.get('command_line')
    if cmd and cmd != "Unknown":
        return f"CMD: {cmd}"
    
    # Priority 2: Action (e.g., login, started)
    action = event.get('action')
    if action:
        return f"ACTION: {action}"
        
    # Priority 3: Category (e.g., authentication, process)
    category = event.get('category')
    if category:
        return f"CATEGORY: {category}"
        
    # Priority 4: Try to find raw type in raw data if available
    raw_data = doc.get('raw', {}).get('data', {})
    if isinstance(raw_data, dict):
        raw_type = raw_data.get('type')
        if raw_type:
            return f"TYPE: {raw_type}"
            
    return "Event: (Details hidden)"

def main():
    # === Root Check ===
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
    print(f"[*] State file: {STATE_FILE}")
    print(f"[*] Target Index: {index_name}")

    # Wait for log file to exist
    while not os.path.exists(LOG_FILE):
        print(f"[-] Waiting for {LOG_FILE} to appear...")
        time.sleep(2)

    # === Resume Logic ===
    current_inode = get_inode(LOG_FILE)
    file_obj = open(LOG_FILE, 'r')
    saved_state = load_state()

    if saved_state and saved_state.get('inode') == current_inode:
        print(f"[+] Resuming from offset {saved_state['offset']}...")
        file_obj.seek(saved_state['offset'])
    else:
        print("[+] Starting from beginning of file (No state or rotation detected)...")
        file_obj.seek(0)

    print("[*] Agent is running with Reliable Checkpointing...")
    
    lines_processed = 0

    try:
        while True:
            # Save state current position before reading (or after? usually after successful process)
            # We track offset via file_obj.tell()
            
            line = file_obj.readline()
            
            if not line:
                # EOF reached. Check for rotation.
                try:
                    new_inode = get_inode(LOG_FILE)
                    if new_inode != current_inode:
                        print(f"[*] Log rotation detected (Inode {current_inode} -> {new_inode}). Reopening...")
                        file_obj.close()
                        file_obj = open(LOG_FILE, 'r')
                        current_inode = new_inode
                        file_obj.seek(0)
                        save_state(current_inode, 0)
                        continue
                except Exception as e:
                    print(f"[-] Error checking rotation: {e}")
                
                # No rotation, just wait for data
                time.sleep(0.1)
                continue

            # === Processing ===
            try:
                line_str = line.decode('utf-8').strip()
            except UnicodeDecodeError:
                # Still need to advance offset
                line_str = ""
            except AttributeError:
                # In case line is str (Python 3 open defaults to text mode unless 'rb')
                # open() above was called without 'b', so it is text mode.
                line_str = line.strip()

            if not line_str:
                continue

            # === Step 1: Detection ===
            is_auditd = "type=" in line_str and "msg=audit" in line_str

            if is_auditd:
                # === Step 2: Smart Path (Auditd) ===
                event = parser.parse(line_str, log_type="auditd")
                
                if event:
                    doc = event.to_dict()
                    doc = clean_dict(doc)
                    
                    # Display Optimization
                    summary = get_display_summary(doc)
                    print(f"[+] Smart Event: {summary}")
                    
                    try:
                        es.index(index=index_name, document=doc)
                    except Exception as e:
                        print(f"[-] ES Write Error (Auditd): {e}")
            else:
                # === Step 3: Fallback Path (Unknown) ===
                # print(f"[+] Raw Log: {line_str[:50]}...")
                # Reduce noise for raw logs too? Maybe just print count or sample
                # For now keeping it visible but maybe less verbose
                pass 
                # To strictly follow "Display Optimization", maybe we shouldn't flood raw logs either
                # But requirement was specifically "Fix 'Unknown' flooding" in Smart Events context.
                # I'll keep raw log print but minimal.
                # print(f"[+] Raw: {line_str[:40]}...") 
                
                raw_doc = make_raw_doc(line_str)
                try:
                    es.index(index=index_name, document=raw_doc)
                except Exception as e:
                    print(f"[-] ES Write Error (Raw): {e}")

            # === Checkpointing ===
            lines_processed += 1
            if lines_processed % 10 == 0:
                save_state(current_inode, file_obj.tell())

    except KeyboardInterrupt:
        print("\n[*] Stopping agent...")
        # Save final state
        save_state(current_inode, file_obj.tell())
        file_obj.close()
    except Exception as e:
        print(f"[-] Critical Error: {e}")
        # Try to save state
        save_state(current_inode, file_obj.tell())
        file_obj.close()
        sys.exit(1)

if __name__ == "__main__":
    main()
