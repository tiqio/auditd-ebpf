# rsyslog 测试夹具

`packaging/rsyslog/60-auditd-ebpf.conf` 使用持久 imjournal 游标，并在服务完成 argv 策略后按原始
`%msg%` 写入事件流。远端测试必须替换示例 CA、客户端证书和
`audit-logs.example.invalid`，验证服务端身份不匹配时连接失败、恢复后磁盘队列继续发送。

