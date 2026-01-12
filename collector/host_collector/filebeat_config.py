"""
Filebeat 配置文件备份
------------------
注意：此文件仅作归档参考。
实际生效的配置文件位于：/etc/filebeat/filebeat.yml

要确保 /etc/filebeat/filebeat.yml 内容如下：
"""

FILEBEAT_YML_CONTENT = """
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/audit/audit.log
  pipeline: "auditd-pipeline"

- type: log
  enabled: true
  paths:
    - /var/log/syslog
    - /var/log/messages
  pipeline: "syslog-pipeline"

setup.ilm.enabled: false
setup.template.name: "unified-logs"
setup.template.pattern: "unified-logs-*"
setup.template.overwrite: true

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "unified-logs-%{+yyyy.MM.dd}"

setup.kibana:
  host: "localhost:5601"
"""

if __name__ == "__main__":
    print("这是配置文件备份，请不要直接运行此脚本。")
    print(FILEBEAT_YML_CONTENT)