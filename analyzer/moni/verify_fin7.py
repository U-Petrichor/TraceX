import os
import sys
import json
from elasticsearch import Elasticsearch

# Add project root to sys.path to allow imports from collector
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Configuration
ES_HOSTS = ["http://182.92.114.32:9200"]

def verify_data():
    print("🚀 Verifying FIN7 Data Ingestion...")
    try:
        es = Elasticsearch(ES_HOSTS)
        if not es.ping():
            print(f"❌ Cannot connect to Elasticsearch at {ES_HOSTS[0]}")
            return
        
        # 1. Query recently indexed documents
        print("\n🔍 Querying recent documents (last 5 minutes)...")
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": "now-5m"
                                }
                            }
                        }
                    ]
                }
            },
            "size": 5,
            "sort": [{"@timestamp": "desc"}]
        }
        
        # Search across all relevant indices
        res = es.search(index="unified-logs*", body=query)
        hits = res['hits']['hits']
        
        print(f"[*] Found {res['hits']['total']['value']} recent documents.")
        
        if hits:
            print("\n📝 Latest Document Sample:")
            print(json.dumps(hits[0]['_source'], indent=2, ensure_ascii=False))
        else:
            print("[-] No documents found in the last 5 minutes.")
            
    except Exception as e:
        print(f"❌ Error during verification: {e}")

if __name__ == "__main__":
    verify_data()
