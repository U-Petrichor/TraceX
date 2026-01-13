import unittest
import os
import sys
import json
import warnings
from datetime import datetime

# Add project root to sys.path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from collector.host_collector.log_parser import HostLogParser
from collector.common.schema import UnifiedEvent

# Try to import elasticsearch, skip tests if missing
try:
    from elasticsearch import Elasticsearch
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False

class TestWindowsESIntegration(unittest.TestCase):
    
    def setUp(self):
        if not ES_AVAILABLE:
            self.skipTest("Elasticsearch library not installed")
        
        self.es_url = "http://localhost:9200"
        self.es = Elasticsearch(self.es_url)
        
        # Check connection
        try:
            if not self.es.ping():
                self.skipTest(f"Cannot connect to Elasticsearch at {self.es_url}")
        except Exception as e:
            self.skipTest(f"Connection failed: {str(e)}")
            
        self.parser = HostLogParser()
        # Use the specific index name requested for presentation
        # Dynamic index name: unified-logs-{YYYY.MM.DD}
        self.index_name = f"unified-logs-{datetime.utcnow().strftime('%Y.%m.%d')}"

    def test_ingest_real_data(self):
        """Ingest real simulation data for presentation (Persisted)"""
        
        print(f"\n[*] Starting data ingestion into index: {self.index_name}")
        
        # Generate timestamps for "now" so data appears current in Kibana
        now_iso = datetime.utcnow().isoformat() + "Z"
        
        mock_logs = [
            # 1. Login Event (4624)
            {
                "EventID": 4624,
                "TimeCreated": now_iso,
                "EventData": {
                    "TargetUserName": "Umut_Admin",
                    "IpAddress": "10.0.0.5",
                    "LogonType": "2", # Interactive
                    "TargetDomainName": "CONTOSO"
                }
            },
            # 2. Process Creation (4688) - Suspicious PowerShell
            {
                "EventID": 4688,
                "TimeCreated": now_iso,
                "EventData": {
                    "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQAoAFsAQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAIgBIADQAcwBJAEAA...",
                    "ProcessId": "0x1A2B",
                    "ParentProcessId": "0x04D2"
                }
            },
            # 3. File Access (4663) - Sensitive File
            {
                "EventID": 4663,
                "TimeCreated": now_iso,
                "EventData": {
                    "ObjectName": "C:\\Secret\\project.docx",
                    "ProcessName": "C:\\Windows\\System32\\notepad.exe",
                    "AccessMask": "0x2"
                }
            }
        ]
        
        for i, raw_log in enumerate(mock_logs):
            # Parse
            unified_event = self.parser.parse(raw_log, log_type="windows")
            self.assertIsInstance(unified_event, UnifiedEvent)
            
            # Write to ES
            doc = unified_event.to_dict()
            try:
                resp = self.es.index(index=self.index_name, document=doc, refresh=True)
            except TypeError:
                # Fallback for older clients
                resp = self.es.index(index=self.index_name, body=doc, refresh=True)
            
            # Verify success
            self.assertIn(resp['result'], ['created', 'updated'])
            print(f"[+] Ingested Event {raw_log['EventID']} - Result: {resp['result']}")

        # Print Kibana queries for the user
        print("\n" + "="*60)
        print("DATA INGESTION COMPLETE - READY FOR PRESENTATION")
        print("="*60)
        print("Use these Lucene queries in Kibana (Discover) to find the logs:")
        print(f"1. Find Admin Login:       user.name:\"Umut_Admin\"")
        print(f"2. Find Suspicious Shell:  process.name:\"powershell.exe\"")
        print(f"3. Find Secret File:       file.name:\"project.docx\"")
        print("="*60 + "\n")

    # NOTE: tearDown method intentionally removed to persist data in Elasticsearch
    
if __name__ == "__main__":
    unittest.main()
