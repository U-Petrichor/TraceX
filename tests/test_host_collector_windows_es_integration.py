import unittest
import os
import sys
import json
import warnings

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
        self.index_name = "test-windows-logs-integration"

    def test_parse_and_write_windows_event(self):
        """Integration test: Parse Windows 4624 event and write to ES"""
        
        # 1. Create sample flat-structure Windows 4624 (Login) event
        raw_event = {
            "EventID": 4624,
            "TimeCreated": "2023-10-27T10:00:00.000000Z",
            "EventData": {
                "TargetUserName": "IntegrationUser",
                "IpAddress": "192.168.1.200",
                "LogonType": "2"
            }
        }
        
        # 2. Parse using HostLogParser
        unified_event = self.parser.parse(raw_event, log_type="windows")
        self.assertIsInstance(unified_event, UnifiedEvent)
        self.assertEqual(unified_event.user.name, "IntegrationUser")
        
        # 3. Write to ES
        # Use 'document' parameter for newer ES clients, 'body' for older
        doc = unified_event.to_dict()
        
        try:
            # Try newer API first
            resp = self.es.index(index=self.index_name, document=doc, refresh=True)
        except TypeError:
            # Fallback to older API
            resp = self.es.index(index=self.index_name, body=doc, refresh=True)
            
        # 4. Assert result
        self.assertEqual(resp['result'], 'created')
        
        # Verify by reading back (optional but good for integration)
        # Give it a moment for refresh
        search_res = self.es.search(index=self.index_name, q=f"user.name:IntegrationUser")
        self.assertGreater(search_res['hits']['total']['value'], 0)

    def tearDown(self):
        # Optional: Clean up index after test
        if ES_AVAILABLE and hasattr(self, 'es') and self.es.ping():
            try:
                self.es.indices.delete(index=self.index_name, ignore=[400, 404])
            except Exception:
                pass

if __name__ == "__main__":
    unittest.main()
