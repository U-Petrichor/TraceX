import sys
import os
import json
import logging
from datetime import datetime
from elasticsearch import Elasticsearch

# Ensure we can import collector modules
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from collector.host_collector.log_parser import HostLogParser
from collector.host_collector.auditd_agent import clean_dict

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

def debug_audit_flow():
    print("="*60)
    print(" 🕵️‍♂️ TraceX Auditd Log Flow Diagnostic Tool")
    print("="*60)

    # 1. Simulate a real 'sudo cat /etc/passwd' log sequence
    # This sequence includes SYSCALL, EXECVE, PROCTITLE, PATH(s), and EOE
    # Note: Timestamps and IDs must match for aggregation
    audit_id = "1000"
    ts = datetime.now().timestamp()
    prefix = f"msg=audit({ts:.3f}:{audit_id}):"
    
    raw_logs = [
        f'type=SYSCALL {prefix} arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffe1234 a2=0 a3=0 items=1 ppid=1234 pid=5678 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="cat" exe="/usr/bin/cat" subj=unconfined key="passwd_read"',
        f'type=EXECVE {prefix} argc=2 a0="cat" a1="/etc/passwd"',
        f'type=PROCTITLE {prefix} proctitle=636174002F6574632F706173737764',
        f'type=PATH {prefix} item=0 name="/etc/passwd" inode=13579 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0',
        f'type=EOE {prefix}'
    ]

    print(f"\n[Step 1] Simulating Auditd Logs (ID: {audit_id})...")
    parser = HostLogParser()
    
    events_found = []
    
    for i, line in enumerate(raw_logs):
        print(f"  Processing line {i+1}: {line[:60]}...")
        # Use the same logic as auditd_agent.py
        is_auditd_candidate = "type=" in line or "msg=audit" in line
        
        if is_auditd_candidate:
            result = parser.parse(line, log_type="auditd")
            if result:
                print(f"  ✅ Parser returned an event at line {i+1}!")
                events_found.append(result)
            else:
                print(f"  ⏳ Parser buffering... (returned None)")
        else:
            print(f"  ❌ Line not recognized as auditd candidate")

    if not events_found:
        print("\n[❌ Error] Parser failed to aggregate the logs into a UnifiedEvent!")
        print("Possible reasons:")
        print("  1. Missing EOE record in input?")
        print("  2. Parser logic expects different field formats?")
        return

    print(f"\n[Step 2] Event Object Inspection")
    event = events_found[0]
    print(f"  Category: {event.event.category}")
    print(f"  Action: {event.event.action}")
    print(f"  Process: {event.process.executable} (PID: {event.process.pid})")
    print(f"  File: {event.file.path}")
    
    # 2. Test Cleaning Logic
    print(f"\n[Step 3] Data Cleaning Verification")
    doc = event.to_dict()
    print(f"  Original Keys: {len(doc.keys())}")
    
    cleaned_doc = clean_dict(doc)
    # Check if empty fields are gone
    if "network" in cleaned_doc and cleaned_doc["network"] == {}:
        print("  ❌ clean_dict failed to remove empty 'network' dict!")
    elif any(v == "" for v in cleaned_doc.values()):
        print("  ❌ clean_dict failed to remove empty strings!")
    else:
        print("  ✅ clean_dict seems to work correctly.")
        # print(json.dumps(cleaned_doc, indent=2))

    # 3. Test ES Write
    print(f"\n[Step 4] Elasticsearch Write Test")
    es_host = "http://localhost:9200"
    try:
        es = Elasticsearch(es_host)
        if not es.ping():
            print(f"  ❌ Cannot connect to ES at {es_host}")
            return
            
        # Use Beijing Time for index naming (matching agent logic)
        from datetime import timedelta
        beijing_time = datetime.utcnow() + timedelta(hours=8)
        index_name = f"unified-logs-{beijing_time.strftime('%Y.%m.%d')}"
        
        print(f"  Target Index: {index_name}")
        res = es.index(index=index_name, document=cleaned_doc)
        print(f"  ✅ Write Success! ID: {res['_id']}")
        print(f"  Result: {res['result']}")
        
    except Exception as e:
        print(f"  ❌ ES Write Failed: {e}")
        # Check for mapper parsing exception details
        if hasattr(e, 'info'):
            print(f"  ES Error Info: {e.info}")

if __name__ == "__main__":
    debug_audit_flow()
