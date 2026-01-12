# 开启 JSON 格式日志输出
@load policy/tuning/json-logs.zeek

# 开启常用的协议解析脚本
@load protocols/conn/main
@load protocols/dns/main
@load protocols/http/main

# 针对靶场环境的网卡进行监听 (假设网卡名为 eth0)
event zeek_init() {
    print "Zeek 网络流量监控已启动...";
}