import sys
import os
import logging
from typing import List, Dict, Any, Optional

# Add project root to path
sys.path.append('/root')

from fastapi import FastAPI, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from TraceX.collector.common.es_client import ESClient
from TraceX.analyzer.attack_analyzer.context_engine import ContextEngine
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="TraceX Dashboard API")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
current_dir = os.path.dirname(os.path.abspath(__file__))
web_root = os.path.dirname(current_dir)
assets_dir = os.path.join(web_root, "assets")

if os.path.exists(assets_dir):
    app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

@app.get("/")
async def read_root():
    return FileResponse(os.path.join(web_root, "index.html"))

@app.get("/{page_name}.html")
async def read_page(page_name: str):
    # Security check: only allow alphanumeric chars to prevent directory traversal
    if not page_name.replace("_", "").isalnum():
        return {"error": "Invalid page name"}, 400
    
    file_path = os.path.join(web_root, f"{page_name}.html")
    if os.path.exists(file_path) and os.path.isfile(file_path):
        return FileResponse(file_path)
    return {"error": "Page not found"}, 404

# Initialize clients
es_client = ESClient(hosts=["http://localhost:9200"])
context_engine = ContextEngine(es_client)

def get_time_range(hours: int):
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=hours)
    return start_time.isoformat() + "Z", end_time.isoformat() + "Z"

@app.get("/api/health")
def health_check():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

@app.get("/api/stats")
def get_stats(hours: int = 24):
    start_t, end_t = get_time_range(hours)
    
    # 1. Total Events
    try:
        total_resp = es_client.es.count(
            index="unified-logs*,network-flows*,honeypot-logs*,host-logs*",
            body={
                "query": {
                    "range": {
                        "@timestamp": {"gte": start_t, "lte": end_t}
                    }
                }
            },
            ignore_unavailable=True
        )
        total_events = total_resp.get("count", 0)
    except Exception as e:
        logger.error(f"Error counting total events: {e}")
        total_events = 0

    # 2. Threat Count (High Risk)
    # This is an approximation. Ideally we pre-calculate threats.
    # For now we count events with threat.confidence > 0.5 or tags including "attack"
    try:
        threat_resp = es_client.es.count(
            index="unified-logs*,network-flows*,honeypot-logs*,host-logs*",
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": start_t, "lte": end_t}}},
                            {"bool": {
                                "should": [
                                    {"range": {"threat.confidence": {"gte": 0.5}}},
                                    {"term": {"event.dataset": "cowrie"}},  # Honeypot logs are inherently suspicious
                                    {"match": {"tags": "attack"}}
                                ],
                                "minimum_should_match": 1
                            }}
                        ]
                    }
                }
            },
            ignore_unavailable=True
        )
        threat_count = threat_resp.get("count", 0)
    except Exception as e:
        logger.error(f"Error counting threats: {e}")
        threat_count = 0

    return {
        "total_events": total_events,
        "threat_count": threat_count,
        "period_hours": hours
    }

@app.get("/api/trend")
def get_trend(hours: int = 24, interval: str = "1h"):
    start_t, end_t = get_time_range(hours)
    
    try:
        resp = es_client.es.search(
            index="unified-logs*,network-flows*,honeypot-logs*,host-logs*",
            body={
                "size": 0,
                "query": {
                    "range": {
                        "@timestamp": {"gte": start_t, "lte": end_t}
                    }
                },
                "aggs": {
                    "events_over_time": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": interval
                        }
                    }
                }
            },
            ignore_unavailable=True
        )
        
        buckets = resp.get("aggregations", {}).get("events_over_time", {}).get("buckets", [])
        data = [{"time": b["key_as_string"], "count": b["doc_count"]} for b in buckets]
        return {"data": data}
    except Exception as e:
        logger.error(f"Error getting trend: {e}")
        return {"data": [], "error": str(e)}

@app.get("/api/attacks")
def get_attacks(hours: int = 24, limit: int = 50):
    start_t, end_t = get_time_range(hours)
    
    # Use ContextEngine to get high value events
    try:
        seeds = context_engine.get_seed_events((start_t, end_t), min_score=50)
        # Convert SafeEventWrapper back to dict if needed, but get_seed_events returns SafeEventWrapper
        # We need to serialize them
        results = []
        for s in seeds[:limit]:
            if hasattr(s, '_data'):
                results.append(s._data)
            else:
                results.append(s)
        return {"attacks": results}
    except Exception as e:
        logger.error(f"Error getting attacks: {e}")
        return {"attacks": [], "error": str(e)}

@app.get("/api/logs")
def get_logs(page: int = 1, size: int = 20, query: Optional[str] = None):
    start_from = (page - 1) * size
    
    es_query = {"match_all": {}}
    if query:
        es_query = {"multi_match": {"query": query, "fields": ["*"]}}
        
    try:
        resp = es_client.es.search(
            index="unified-logs*,network-flows*,honeypot-logs*,host-logs*",
            body={
                "from": start_from,
                "size": size,
                "query": es_query,
                "sort": [{"@timestamp": "desc"}]
            },
            ignore_unavailable=True
        )
        
        hits = resp.get("hits", {}).get("hits", [])
        logs = [h["_source"] for h in hits]
        total = resp.get("hits", {}).get("total", {}).get("value", 0)
        
        return {
            "data": logs,
            "total": total,
            "page": page,
            "size": size
        }
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return {"data": [], "total": 0, "error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
