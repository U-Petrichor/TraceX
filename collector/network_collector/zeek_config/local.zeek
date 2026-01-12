# /root/TraceX/collector/network_collector/zeek_config/local.zeek

# 开启 JSON 格式日志输出
@load policy/tuning/json-logs.zeek

# 开启常用的协议解析脚本
@load protocols/conn/main
@load protocols/dns/main
@load protocols/http/main

# 禁用日志旋转（重要：确保手动运行的 parser 可以持续读取同一个文件）
redef Log::default_rotation_interval = 0;

event zeek_init() {
    print "Zeek 网络流量监控已启动，JSON 日志模式已开启...";
}