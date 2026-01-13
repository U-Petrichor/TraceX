
zeek容器持续采集数据，flow_parser_zeek.py负责增量更新并标准化存入ES。
输入以下命令：

```Bash
python3 /root/TraceX/collector/network_collector/flow_parser_zeek.py
```

输出：
```
root@iZ2ze082hzl5s9xfijazalZ:~/TraceX# python3 /root/TraceX/collector/network_collector/flow_parser_zeek.py
[*] 发现日志，开始实时监控 (轮转感知模式已开启)...
/usr/local/lib/python3.10/dist-packages/elasticsearch/connection/base.py:200: ElasticsearchWarning: Elasticsearch built-in security features are not enabled. Without authentication, your cluster could be accessible to anyone. See https://www.elastic.co/guide/en/elasticsearch/reference/7.17/security-minimal-setup.html to enable security.
  warnings.warn(message, category=ElasticsearchWarning)
[OK] 157.122.198.36 -> 172.26.155.27 (tcp)
[OK] 112.28.73.142 -> 172.26.155.27 (tcp)
[OK] 172.26.155.27 -> 20.205.243.166 (tcp)
[OK] 172.26.155.27 -> 100.100.2.136 (udp)
[OK] 172.26.155.27 -> 100.100.2.136 (udp)
[OK] 52.195.15.12 -> 172.26.155.27 (icmp)
[OK] 13.115.127.48 -> 172.26.155.27 (icmp)
[OK] 35.152.255.63 -> 172.26.155.27 (icmp)
[OK] 54.249.81.165 -> 172.26.155.27 (icmp)
[OK] 172.26.155.27 -> 20.205.243.166 (tcp)
[OK] 172.26.155.27 -> 100.100.2.136 (udp)
[OK] 172.26.155.27 -> 100.100.2.136 (udp)
[OK] 172.26.155.27 -> 100.100.3.1 (udp)
[OK] 172.26.155.27 -> 23.55.179.210 (tcp)
[OK] 172.26.155.27 -> 100.100.18.120 (tcp)
[OK] 172.26.155.27 -> 100.100.2.136 (udp)
[OK] 172.26.155.27 -> 100.100.2.136 (udp)
[OK] 172.26.155.27 -> 100.100.2.136 (udp)
[OK] 172.26.155.27 -> 100.100.2.136 (udp)
[*] 检测到文件轮转 (Inode 962278 -> 962553)，重新打开文件...
[OK] 54.64.35.21 -> 172.26.155.27 (icmp)
[OK] 15.161.103.249 -> 172.26.155.27 (icmp)
[OK] 15.161.188.196 -> 172.26.155.27 (icmp)
^C
[*] 监控已手动停止
```

使用`/root/TraceX/tests/test_zeek_data.py`验证存入ES的数据是否符合公共模块的标准化

运行命令`python3 /root/TraceX/tests/test_zeek_data.py`

```
root@iZ2ze082hzl5s9xfijazalZ:~/TraceX# python3 /root/TraceX/tests/test_zeek_data.py
=== 开始 Zeek 数据标准化测试 ===
[*] 正在从 ES 查询范围: 2026-01-13T08:40:42.311102Z 至 2026-01-13T08:50:42.311102Z
/usr/local/lib/python3.10/dist-packages/elasticsearch/connection/base.py:200: ElasticsearchWarning: Elasticsearch built-in security features are not enabled. Without authentication, your cluster could be accessible to anyone. See https://www.elastic.co/guide/en/elasticsearch/reference/7.17/security-minimal-setup.html to enable security.
  warnings.warn(message, category=ElasticsearchWarning)
[*] 找到 22 条原始记录，开始模式校验...

=== 测试报告 ===
通过: 22
失败: 0

[RESULT] 恭喜！Zeek 数据与公共 Schema 完全兼容。
```
数据全部通过测试。

可以在Kibana可视化界面实时查看存入ES的日志。（不要开梯子）
![](image.png)