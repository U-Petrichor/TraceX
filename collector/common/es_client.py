from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from datetime import datetime
import uuid

class ESClient:
    """Elasticsearch 客户端封装"""
    
    def __init__(self, hosts=["http://localhost:9200"]):
        self.es = Elasticsearch(hosts)
    
    def write_event(self, event: dict, index_prefix: str = "unified-logs") -> str:
        """写入单条事件"""
        if "event" not in event:
            event["event"] = {}
        if "id" not in event["event"]:
            event["event"]["id"] = str(uuid.uuid4())
        
        if "@timestamp" not in event:
            event["@timestamp"] = datetime.utcnow().isoformat() + "Z"
        
        date_str = datetime.utcnow().strftime("%Y.%m.%d")
        index_name = f"{index_prefix}-{date_str}"
        
        result = self.es.index(index=index_name, body=event)
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
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start_time,
                                "lte": end_time
                            }
                        }
                    }
                ]
            }
        }
        
        if filters:
            for field, value in filters.items():
                query["bool"]["must"].append({
                    "term": {field: value}
                })
        
        result = self.es.search(
            index=f"{index_prefix}-*",
            body={
                "query": query,
                "size": size,
                "sort": [{"@timestamp": "asc"}]
            }
        )
        return [hit["_source"] for hit in result["hits"]["hits"]]