# collector/common/es_client.py
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from datetime import datetime
import uuid

class ESClient:
    """Elasticsearch 客户端封装"""
    def __init__(self, hosts=["http://localhost:9200"]):
        # Add basic auth or token if needed, but for local docker usually defaults are fine.
        # Ensure retry logic and timeouts are robust
        self.es = Elasticsearch(
            hosts,
            max_retries=3,
            retry_on_timeout=True,
            request_timeout=30
        )
    
    def _infer_category(self, event: dict) -> str:
        memory = event.get("memory", {}) if isinstance(event.get("memory"), dict) else {}
        if memory.get("anomalies"):
            return "memory"
        
        action = str(event.get("event", {}).get("action", "") or "").lower()
        outcome = str(event.get("event", {}).get("outcome", "") or "").lower()
        user = event.get("user", {}).get("name") if isinstance(event.get("user"), dict) else ""
        src_ip = event.get("source", {}).get("ip") if isinstance(event.get("source"), dict) else ""
        if action and any(k in action for k in ("login", "logon", "logout", "logoff", "auth")):
            return "authentication"
        if outcome in ("success", "failure") and (user or src_ip):
            return "authentication"
        
        network = event.get("network", {}) if isinstance(event.get("network"), dict) else {}
        source = event.get("source", {}) if isinstance(event.get("source"), dict) else {}
        destination = event.get("destination", {}) if isinstance(event.get("destination"), dict) else {}
        if network.get("protocol") or source.get("ip") or destination.get("ip"):
            return "network"
        
        file_info = event.get("file", {}) if isinstance(event.get("file"), dict) else {}
        if file_info.get("path") or file_info.get("name"):
            return "file"
        
        process = event.get("process", {}) if isinstance(event.get("process"), dict) else {}
        if process.get("pid") or process.get("executable") or process.get("name"):
            return "process"
        
        return ""

    def _ensure_category(self, event: dict) -> None:
        if "event" not in event:
            event["event"] = {}
        if not event["event"].get("category"):
            inferred = self._infer_category(event)
            if inferred:
                event["event"]["category"] = inferred
    
    def write_event(self, event: dict, index_prefix: str = "unified-logs") -> str:
        """写入单条事件"""
        if "event" not in event:
            event["event"] = {}
        if "id" not in event["event"]:
            event["event"]["id"] = str(uuid.uuid4())
        if "@timestamp" not in event:
            event["@timestamp"] = datetime.utcnow().isoformat() + "Z"
        self._ensure_category(event)
        
        date_str = datetime.utcnow().strftime("%Y.%m.%d")
        index_name = f"{index_prefix}-{date_str}"
        result = self.es.index(index=index_name, document=event)
        return event["event"]["id"]
    
    def write_events_bulk(self, events: list, index_prefix: str = "unified-logs") -> dict:
        """批量写入事件"""
        date_str = datetime.utcnow().strftime("%Y.%m.%d")
        index_name = f"{index_prefix}-{date_str}"
        actions = []
        for event in events:
            if "event" not in event:
                event["event"] = {}
            if "id" not in event["event"]:
                event["event"]["id"] = str(uuid.uuid4())
            if "@timestamp" not in event:
                event["@timestamp"] = datetime.utcnow().isoformat() + "Z"
            self._ensure_category(event)
            actions.append({
                "_index": index_name,
                "_source": event
            })
        success, failed = bulk(self.es, actions, raise_on_error=False)
        return {"success": success, "failed": len(failed)}

    def query_events(self, start_time: str, end_time: str, 
                     index_prefix: str = "unified-logs",
                     filters: dict = None, size: int = 1000) -> list:
        """查询事件"""
        query = {
            "bool": {
                "must": [{"range": {"@timestamp": {"gte": start_time, "lte": end_time}}}]
            }
        }
        if filters:
            for field, value in filters.items():
                query["bool"]["must"].append({"term": {field: value}})
        
        result = self.es.search(
            index=f"{index_prefix}-*",
            query=query, size=size, sort=[{"@timestamp": "asc"}]
        )
        return [hit["_source"] for hit in result["hits"]["hits"]]
