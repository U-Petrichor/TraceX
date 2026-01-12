
运行转换脚本

`python3 /root/TraceX/collector/network_collector/flow_parser.py`

在本地模拟攻击

`ssh root@182.92.114.32 -p 2222`

输入错误的密码

```
C:\Users\62477>ssh root@182.92.114.32 -p 2222
root@182.92.114.32's password:
Permission denied, please try again.
root@182.92.114.32's password:
Permission denied, please try again.
root@182.92.114.32's password:
root@182.92.114.32: Permission denied (publickey,password).
```

服务器端实时捕获日志并转为标准格式存入ES
```
root@iZ2ze082hzl5s9xfijazalZ:~/TraceX# python3 /root/TraceX/collector/network_collector/flow_parser.py
开始解析蜜罐日志: /root/TraceX/infrastructure/range/honeypots/cowrie/var/log/cowrie/cowrie.json
/usr/local/lib/python3.10/dist-packages/elasticsearch/connection/base.py:200: ElasticsearchWarning: Elasticsearch built-in security features are not enabled. Without authentication, your cluster could be accessible to anyone. See https://www.elastic.co/guide/en/elasticsearch/reference/7.17/security-minimal-setup.html to enable security.
  warnings.warn(message, category=ElasticsearchWarning)
[2026-01-12T16:51:58.334154Z] 已存入 ES | 类别: host | 动作: cowrie.session.connect
[2026-01-12T16:51:58.339756Z] 已存入 ES | 类别: host | 动作: cowrie.client.version
[2026-01-12T16:51:58.341046Z] 已存入 ES | 类别: host | 动作: cowrie.client.kex
[2026-01-12T16:52:07.193624Z] 已存入 ES | 类别: host | 动作: cowrie.session.closed

```

运行检测代码，全部日志通过检测
`python3 /root/TraceX/tests/test_cowrie_data.py`

```
root@iZ2ze082hzl5s9xfijazalZ:~/TraceX# python3 /root/TraceX/tests/test_cowrie_data.py
[*] 开始自检时间段: 2026-01-11T16:54:56.364316Z 至 2026-01-12T16:54:56.364316Z
/usr/local/lib/python3.10/dist-packages/elasticsearch/connection/base.py:200: ElasticsearchWarning: Elasticsearch built-in security features are not enabled. Without authentication, your cluster could be accessible to anyone. See https://www.elastic.co/guide/en/elasticsearch/reference/7.17/security-minimal-setup.html to enable security.
  warnings.warn(message, category=ElasticsearchWarning)

========================================
📊 数据质量自检报告
========================================
总检查条数: 16
✅ 合格条数: 16
❌ 不合格条数: 0

健康分: 100.0/100
[优秀] 数据格式完美，组员 3 和 4 可以放心使用。
========================================
```
