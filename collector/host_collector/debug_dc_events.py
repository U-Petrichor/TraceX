import json
import subprocess
import datetime
import sys
import os

# 确保能导入 log_parser
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from collector.host_collector.log_parser import HostLogParser

def run_debug():
    print("=== 开始 DC 日志抓取与解析测试 ===")
    
    # PowerShell 脚本 (与 win_agent_dc.py 中保持一致)
    ps_script = """
    $ids = @(4624, 4625, 4768, 4776, 4720, 4726)
    $time = (Get-Date).AddMinutes(-60) # 抓取过去 1 小时的日志，方便测试
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=$ids; StartTime=$time} -ErrorAction SilentlyContinue | 
    ForEach-Object {
        $evt = $_
        $xml = [xml]$evt.ToXml()
        $data = @{}
        # Handle different XML structures safely
        if ($xml.Event.EventData.Data) {
            $xml.Event.EventData.Data | ForEach-Object { 
                if ($_.Name) { $data[$_.Name] = $_.'#text' }
            }
        }
        
        @{
            TimeCreated = $evt.TimeCreated
            Id = $evt.Id
            Message = $evt.Message
            EventData = $data
        }
    } | ConvertTo-Json -Compress -Depth 2
    """
    
    print("[1/3] 正在执行 PowerShell 脚本 (查询过去1小时的 Security 日志)...")
    try:
        cmd = ["powershell", "-Command", ps_script]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if not result.stdout.strip():
            print("[-] PowerShell 未返回任何数据。请确认过去 1 小时内是否有相关事件 (4624/4625/4768/4776) 产生。")
            return

        data = result.stdout.strip()
        print(f"[+] PowerShell 返回数据长度: {len(data)} 字符")
        
        events = []
        if data.startswith('['):
            events = json.loads(data)
        else:
            events = [json.loads(data)]
            
        print(f"[+] 捕获到 {len(events)} 条原始事件")
        
    except Exception as e:
        print(f"[-] PowerShell 执行失败: {e}")
        return

    print("\n[2/3] 开始测试解析逻辑 (HostLogParser)...")
    parser = HostLogParser()
    parsed_count = 0
    
    for i, evt in enumerate(events):
        print(f"\n--- 事件 #{i+1} (ID: {evt.get('Id')}) ---")
        
        # 构造 log_parser 预期的输入
        raw_log = {
            "EventID": evt.get("Id"),
            "TimeCreated": evt.get("TimeCreated"),
            "EventData": evt.get("EventData", {}),
            "Message": evt.get("Message"),
            "System": {"EventID": evt.get("Id")}
        }
        
        # 打印部分原始数据用于调试
        print(f"原始 EventData: {json.dumps(raw_log['EventData'], ensure_ascii=False)}")
        
        try:
            unified = parser.parse(raw_log, log_type="windows")
            if unified:
                parsed_count += 1
                print(f"解析成功 -> Action: {unified.event.action}")
                print(f"            User:   {unified.user.name}")
                print(f"            Src IP: {unified.source.ip}")
                print(f"            Desc:   {unified.message[:50]}...")
            else:
                print("解析结果: None (被过滤或不支持)")
        except Exception as e:
            print(f"解析异常: {e}")

    print(f"\n[3/3] 测试完成。成功解析 {parsed_count}/{len(events)} 条事件。")
    print("如果在这里能看到 User 和 Src IP，说明 Agent 逻辑已修复。")
    print("请重新运行 python collector/host_collector/win_agent_dc.py")

if __name__ == "__main__":
    run_debug()
