# 发现网络中的活动主机

利用ICMP数据包，通过使用ICMP的回送和回送响应消息来确定当前网络中处于活动状态的主机，即ping消息的请求和应答，将发送的ICMP的数据包类型设置为回送请求(类型号为8)，并显示在标准输出上。用命令行形式运行：scanhost Start_IP End_IP，其中scanhost为程序名；Start_IP为被搜索网段的开始IP；End_IP为被搜索网段的结束IP地址。

终端使用方法：

```shell
scanhost 39.156.66.6 39.156.66.15
```

# 实现路由追踪

运行traceroute即可