from collector.common.es_client import ESClient
import json
import binascii

es_client = ESClient()
print("🔍 正在连接 ES...")

# 1. 盲查：直接获取最新存入的 5 条日志 (不限索引，不限条件)
# 我们按 @timestamp 倒序，看看到底存进去了啥
try:
    resp = es_client.es.search(
        index="unified-logs*", 
        body={
            "query": {"match_all": {}}, 
            "size": 5, 
            "sort": [{"@timestamp": "desc"}]
        }
    )
except Exception as e:
    print(f"❌ ES 查询失败: {e}")
    exit()

hits = resp.get('hits', {}).get('hits', [])
print(f"📊 发现最新日志总数: {len(hits)}")

if not hits:
    print("❌ ES 里居然是空的？请检查 Agent 是否开启了 ENABLE_ES_WRITE = True")
    exit()

print("\n" + "="*50)
for i, hit in enumerate(hits):
    source = hit['_source']
    print(f"📝 [日志 #{i+1}] ID: {hit['_id']}")
    print(f"   索引: {hit['_index']}")
    print(f"   时间: {source.get('@timestamp')}")
    
    # 打印关键进程信息
    process = source.get('process', {})
    cmd = process.get('command_line') or "N/A"
    print(f"   字段 process.command_line: {cmd}")
    
    # 尝试检测是否为 Hex
    try:
        if len(cmd) > 20 and all(c in '0123456789ABCDEFabcdef' for c in str(cmd)):
            decoded = binascii.unhexlify(cmd).decode('utf-8', errors='ignore')
            print(f"   🔓 [Hex解码尝试]: {decoded}")
            if "bash -i" in decoded:
                print("   🚨 找到攻击特征 (在 Hex 中)！")
    except:
        pass

    # 打印其他可能存命令的字段
    print(f"   字段 raw.data: {source.get('raw', {}).get('data', 'N/A')}")
    print("-" * 30)

print("="*50)
