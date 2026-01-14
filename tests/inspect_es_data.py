import sys
import os
import binascii

# 确保能引用项目模块
sys.path.append(os.getcwd())

try:
    from collector.common.es_client import ESClient
except ImportError:
    # 备用方案：如果找不到模块，直接用裸 ES 库
    from elasticsearch import Elasticsearch
    class ESClient:
        def __init__(self):
            self.es = Elasticsearch("http://localhost:9200")

es_client = ESClient()
print("🔍 正在连接 ES 查看最新 10 条原始日志...")

try:
    # 查询所有统一日志，按时间倒序
    resp = es_client.es.search(
        index="unified-logs*", 
        body={
            "query": {"match_all": {}}, 
            "size": 10, 
            "sort": [{"@timestamp": "desc"}]
        }
    )
except Exception as e:
    print(f"❌ ES 查询失败: {e}")
    exit()

hits = resp.get('hits', {}).get('hits', [])

if not hits:
    print("❌ ES 是空的！没有任何数据。")
    print("可能原因：")
    print("1. auditd_agent.py 没有成功写入 (检查 ENABLE_ES_WRITE)")
    print("2. 索引名称不对 (日期不对)")
    exit()

print(f"✅ 找到 {len(hits)} 条数据。正在分析内容...\n")

for i, hit in enumerate(hits):
    src = hit['_source']
    idx = hit['_index']
    
    # 获取命令行
    cmd = "N/A"
    if 'process' in src and 'command_line' in src['process']:
        cmd = src['process']['command_line']
    elif 'raw' in src and 'data' in src['raw']:
        cmd = src['raw']['data']
        
    print(f"📝 [Log #{i+1}] Index: {idx}")
    print(f"   原始 CMD: {cmd}")
    
    # 尝试 Hex 解码 (检测 Auditd 的 Hex 编码)
    try:
        if cmd != "N/A" and len(str(cmd)) > 20:
            # 去掉空格，看是不是纯 Hex
            clean_hex = str(cmd).replace(" ", "")
            if all(c in '0123456789ABCDEFabcdef' for c in clean_hex):
                decoded = binascii.unhexlify(clean_hex).decode('utf-8', errors='ignore')
                print(f"   🔓 [HEX 解码]: {decoded}")
                if "bash" in decoded or "wget" in decoded or "php" in decoded:
                    print("   🚨 >>> 发现攻击特征 (在 Hex 隐藏中) <<<")
    except:
        pass
        
    print("-" * 40)

