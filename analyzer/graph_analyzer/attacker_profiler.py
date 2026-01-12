from typing import Dict, Any, List, Set

class AttackerProfiler:
    """
    攻击者画像生成器
    作用：基于攻击路径分析结果，提取攻击者的特征（IP、常用工具、技术偏好）。
    """
    
    def profile(self, attack_path: Dict[str, Any]) -> Dict[str, Any]:
        """
        生成画像
        
        Args:
            attack_path: path_rebuilder.rebuild() 的输出结果
            
        Returns:
            画像字典
        """
        source_ips: Set[str] = set()
        tools: Set[str] = set()
        techniques: Set[str] = set()
        target_hosts: Set[str] = set()
        
        stages = attack_path.get("stages", [])
        
        for stage in stages:
            for event in stage.get("events", []):
                # 1. 收集攻击源 IP
                ip = event.get("source", {}).get("ip")
                if ip:
                    source_ips.add(ip)
                
                # 2. 收集受害主机
                host = event.get("host", {}).get("name")
                if host:
                    target_hosts.add(host)
                
                # 3. 收集使用的工具 (Process Name)
                # 简单过滤：通常攻击工具也是进程
                proc_name = event.get("process", {}).get("name")
                if proc_name:
                    tools.add(proc_name)
                    
                # 4. 收集使用的技术
                tech_name = event.get("threat", {}).get("technique", {}).get("name")
                if tech_name:
                    techniques.add(tech_name)
        
        return {
            "attacker_profile": {
                "source_ips": list(source_ips),
                "target_hosts": list(target_hosts),
                "tools_used": list(tools),
                "techniques": list(techniques),
                "risk_level": "High" if len(stages) > 2 else "Medium",
                "attack_chain_depth": len(stages)
            }
        }