import os
import sys
import json
import uuid
import glob
from datetime import datetime
from typing import List, Dict

# Add project root to sys.path to allow imports from collector
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from collector.common.es_client import ESClient

# Configuration
SOURCE_FILE = os.path.join(project_root, "analyzer", "test", "apt_events", "direct", "Indrik_Spider.jsonl")
ES_HOSTS = ["http://182.92.114.32:9200"]

def load_events(file_path: str) -> List[Dict]:
    """Load events from a JSONL file."""
    events = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"[-] Error decoding JSON in {file_path}: {e}")
    return events

def adjust_timestamps(events: List[Dict]) -> List[Dict]:
    """
    Shift timestamps so the sequence ends 'now'.
    Also regenerates IDs to avoid conflicts.
    """
    if not events:
        return []

    # 1. Parse original timestamps to find the relative offsets
    parsed_events = []
    for event in events:
        ts_str = event.get("@timestamp") or event.get("timestamp")
        if not ts_str:
            continue
        
        # Handle "Z" at the end
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1]
        
        try:
            # Try parsing with microseconds
            dt = datetime.fromisoformat(ts_str)
        except ValueError:
            continue
            
        parsed_events.append((dt, event))

    if not parsed_events:
        return events

    # Find the latest time in the original dataset
    max_time = max(t for t, _ in parsed_events)
    
    # Calculate shift needed to bring max_time to NOW
    now = datetime.utcnow()
    time_shift = now - max_time

    adjusted_events = []
    for dt, event in parsed_events:
        # Shift time
        new_time = dt + time_shift
        new_ts_str = new_time.isoformat() + "Z"
        
        # Update timestamp
        event["@timestamp"] = new_ts_str
        if "timestamp" in event:
            event["timestamp"] = new_ts_str
            
        # Also update process.start_time if it exists and looks like a date
        if "process" in event and "start_time" in event["process"]:
            p_ts = event["process"]["start_time"]
            if not p_ts: # Handle empty string
                event["process"]["start_time"] = None
            elif p_ts:
                 if p_ts.endswith("Z"): p_ts = p_ts[:-1]
                 try:
                     p_dt = datetime.fromisoformat(p_ts)
                     new_p_dt = p_dt + time_shift
                     event["process"]["start_time"] = new_p_dt.isoformat() + "Z"
                 except ValueError:
                     pass

        # Regenerate ID
        if "event" in event:
            event["event"]["id"] = str(uuid.uuid4())

        # Clean up empty IP strings which cause mapper_parsing_exception in ES
        def clean_empty_ips(d):
            if isinstance(d, dict):
                for k, v in d.items():
                    if isinstance(v, dict):
                        clean_empty_ips(v)
                    elif isinstance(v, str) and v == "" and k in ["ip", "src_ip", "dst_ip", "source_ip", "dest_ip", "destination_ip"]:
                         d[k] = None 
                    if k in ["source", "destination"] and isinstance(v, dict):
                        if "ip" in v and v["ip"] == "":
                            v["ip"] = None
            return d
        
        event = clean_empty_ips(event)
        
        adjusted_events.append(event)
        
    return adjusted_events

def simulate_file(file_path: str, es_client: ESClient):
    """Process a single file and ingest into ES."""
    filename = os.path.basename(file_path)
    print(f"[*] Processing {filename}...")
    
    events = load_events(file_path)
    if not events:
        print(f"[-] No events found in {filename}")
        return

    adjusted_events = adjust_timestamps(events)
    print(f"[*] Prepared {len(adjusted_events)} events (Time-shifted to end at {datetime.utcnow().isoformat()}Z)")

    adjusted_events.sort(key=lambda x: x.get("@timestamp", ""))

    result = es_client.write_events_bulk(adjusted_events)
    
    print(f"[+] Ingestion result for {filename}: {result}")
    
    if result.get("failed", 0) > 0:
        print(f"[-] Detected {result['failed']} failures in {filename}. Retrying first failure to capture error...")
        from elasticsearch.helpers import bulk
        date_str = datetime.utcnow().strftime("%Y.%m.%d")
        index_name = f"unified-logs-{date_str}"
        
        actions = []
        for event in adjusted_events:
            actions.append({
                "_index": index_name,
                "_source": event
            })
            
        try:
            bulk(es_client.es, actions[:1], raise_on_error=True)
        except Exception as e:
            import traceback
            print(f"[-] Sample Error Traceback:")
            traceback.print_exc()
            if hasattr(e, 'errors'):
                print(f"[-] Bulk Errors: {json.dumps(e.errors, indent=2)}")

def main():
    print("🚀 Starting Indrik_Spider Attack Simulation Ingestion...")
    print(f"[*] Source File: {SOURCE_FILE}")

    try:
        es_client = ESClient(hosts=ES_HOSTS)
        if not es_client.es.ping():
            print(f"❌ Cannot connect to Elasticsearch at {ES_HOSTS[0]}")
            return
        print("✅ Elasticsearch connected.")
    except Exception as e:
        print(f"❌ Error initializing ESClient: {e}")
        return

    if not os.path.exists(SOURCE_FILE):
        print(f"[-] Source file not found: {SOURCE_FILE}")
        return

    try:
        simulate_file(SOURCE_FILE, es_client)
        
        # Create marker file for frontend
        marker_path = os.path.join(project_root, "web", "backend", "active_simulations", "Indrik_Spider.jsonl")
        try:
            os.makedirs(os.path.dirname(marker_path), exist_ok=True)
            with open(marker_path, 'w') as f:
                f.write("active")
            print(f"[+] Created active simulation marker: {marker_path}")
        except Exception as e:
            print(f"[-] Failed to create marker file: {e}")
            
    except Exception as e:
        print(f"[-] Failed to process {SOURCE_FILE}: {e}")

    print("🏁 Indrik Spider Simulation complete.")

if __name__ == "__main__":
    main()
