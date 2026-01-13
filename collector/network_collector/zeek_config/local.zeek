# 1. 开启 JSON 格式日志输出（这是解析脚本运行的基础）
@load policy/tuning/json-logs.zeek

# 2. 忽略校验和错误（解决云环境抓不到包的问题）
redef ignore_checksums = T;

# 3. 设置日志刷新/轮转频率
# 设为 1 min 可以强制 Zeek 每分钟将数据刷入磁盘并滚动文件。
redef Log::default_rotation_interval = 1 min;

# 4. 启动反馈
event zeek_init() {
    print "Zeek 网络流量监控已启动：JSON 模式已开启，校验和已忽略，日志每分钟刷新。";
}
