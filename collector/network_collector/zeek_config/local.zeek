# 1. 开启 JSON 格式日志输出 
@load policy/tuning/json-logs.zeek

# 2. 禁用日志轮转（适合持续采集），修正类型冲突 
redef Log::default_rotation_interval = 0 secs;

# 3. 启动反馈 
event zeek_init() {
    print "Zeek 网络流量监控已启动，JSON 日志模式已开启...";
}
