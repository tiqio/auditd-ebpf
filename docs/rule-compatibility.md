# 规则兼容矩阵

首版支持 `-a always,exit` syscall form、`-w/-p/-k` watch form、`arch`、`uid/euid`、
`gid/egid`、`success`、`path`、`dir`、`perm` 和必填单一 key。规则按文件名字节序和文件内顺序
执行 first-match。不支持项会拒绝整个候选规则集，不会静默降级。

