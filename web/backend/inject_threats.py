import sys
import os
import random
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, "/root/TraceX")

from collector.common.es_client import ESClient

def inject_threats(count=10):
    es = ESClient(hosts=["http://localhost:9200"])
    
    tactics = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation", 
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", 
        "Collection", "Exfiltration", "Command and Control"
    ]
    
    techniques = [
        "T1059 (Command and Scripting Interpreter)", 
        "T1053 (Scheduled Task/Job)", 
        "T1078 (Valid Accounts)", 
        "T1003 (OS Credential Dumping)", 
        "T1021 (Remote Services)",
        "T1566 (Phishing)",
        "T1190 (Exploit Public-Facing Application)",
        "T1059.001 (PowerShell)",
        "T1003.001 (LSASS Memory)"
    ]
    
    events = []
    now = datetime.utcnow()
    
    print(f"Injecting {count} threat events...")
    
    for i in range(count):
        # Time distribution: mostly recent
        dt = now - timedelta(minutes=random.randint(1, 60*12))
        
        tactic = random.choice(tactics)
        technique = random.choice(techniques)
        severity = random.choice(["high", "medium", "critical"]) # Ensure they are threats
        confidence = random.uniform(0.6, 0.95) # Ensure > 0.5
        
        # Make IP more realistic
        # Source IP: Public IP ranges (simulating external attackers)
        src_octet1 = random.choice([45, 103, 192, 185, 203, 59, 14, 1, 27])
        src_ip = f"{src_octet1}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        
        # Destination IP: Private ranges (simulating internal targets)
        dst_ip = f"192.168.1.{random.randint(10, 50)}"

        event = {
            "@timestamp": dt.isoformat() + "Z",
            "host": {"name": f"host-{random.randint(1,5)}"},
            "source": {"ip": src_ip, "port": random.randint(10000, 60000)},
            "destination": {"ip": dst_ip, "port": random.choice([80, 443, 445, 3389, 22])},
            "event": {
                "dataset": "injected_threat", 
                "action": "detected",
                "category": "threat"
            },
            "threat": {
                "tactic": {"name": tactic},
                "technique": {"name": technique},
                "confidence": confidence
            },
            "detection": {
                "severity": severity,
                "confidence": confidence
            },
            "tags": ["attack", "simulated"],
            "message": f"Simulated threat event: {technique} via {tactic}"
        }
        events.append(event)
        
    # Write to ES
    res = es.write_events_bulk(events, index_prefix="unified-logs")
    print(f"Injection complete: {res}")

if __name__ == "__main__":
    inject_threats(15)
