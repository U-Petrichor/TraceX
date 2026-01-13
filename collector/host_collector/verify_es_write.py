import time
import os
import sys
from datetime import datetime

# Ensure project root is in sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from elasticsearch import Elasticsearch
except ImportError:
    print("[-] Error: 'elasticsearch' module missing. Please run: pip install elasticsearch")
    sys.exit(1)

ES_HOST = "http://localhost:9200"

def verify_es_write():
    print(f"[*] Connecting to Elasticsearch at {ES_HOST}...")
    try:
        es = Elasticsearch(ES_HOST)
        if not es.ping():
            print(f"[-] Error: Could not connect to ES at {ES_HOST}. Check Docker is running.")
            return
        
        print("[+] Connected to ES successfully.")
        
        # Test Index Name logic same as agent
        today_str = datetime.utcnow().strftime('%Y.%m.%d')
        index_name = f"unified-logs-{today_str}"
        print(f"[*] Target Index (Agent Logic): {index_name}")
        
        # Test Document
        test_doc = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "message": "TraceX ES Write Verification Test",
            "event": {
                "category": "test",
                "action": "verification"
            },
            "host": {
                "name": "verification-script"
            }
        }
        
        print(f"[*] Attempting to write test document to {index_name}...")
        res = es.index(index=index_name, document=test_doc)
        
        print(f"[+] Write Result: {res['result']}")
        print(f"[+] Document ID: {res['_id']}")
        print(f"[+] Index: {res['_index']}")
        
        print("\n[*] Verifying data readability...")
        time.sleep(1) # Allow ES to refresh
        
        # Search back
        query = {
            "query": {
                "match": {
                    "_id": res['_id']
                }
            }
        }
        search_res = es.search(index=index_name, body=query)
        hits = search_res['hits']['hits']
        
        if len(hits) > 0:
            print(f"[+] Successfully read back document: {hits[0]['_source']['message']}")
            print("[SUCCESS] Elasticsearch write capability verified.")
        else:
            print("[-] Warning: Document written but not found immediately (might be refresh delay).")

    except Exception as e:
        print(f"[-] Critical Error: {e}")

if __name__ == "__main__":
    verify_es_write()
