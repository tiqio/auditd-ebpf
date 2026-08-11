# Contract: check-rules Watch Coverage Output

## Command

```console
auditd-ebpf check-rules --rules-dir PATH --print-normalized
```

## Success Output

每条规则输出一行，字段顺序稳定。watch 规则必须包含以下字段：

```text
id=0 kind=Watch arch=None syscalls=<non-empty-symbolic-union> path=/tmp/ddtest dir=- perm=rw uid=- gid=- success=- key=ddtest argv=Inherit coverage_version=1 coverage_b64=<value> coverage_b32=<value>
```

### Field Rules

- `syscalls`：两个 ABI 有效 syscall 名的稳定并集，按规范化名称排序，watch 时不得为空。
- `coverage_version`：当前权限矩阵版本。
- `coverage_b64` / `coverage_b32`：按 `r,w,x,a` 顺序，仅输出规则请求权限；格式为
  `r:name1,name2|w:name1,name2`，值内部不包含空格。
- 同一个规则在相同版本程序、相同输入下必须逐字节稳定。
- coverage fields 参与规则摘要；矩阵版本或有效 syscall 变化必须改变 rule version。

## Example

```text
id=0 kind=Watch arch=None syscalls=open,openat,openat2,creat,truncate,ftruncate,fallocate,rename,renameat,renameat2,unlink,unlinkat,mkdir,mkdirat,rmdir,link,linkat,symlink,symlinkat,mknod,mknodat,readlink,readlinkat,getxattr,lgetxattr,fgetxattr,listxattr,llistxattr,flistxattr path=/tmp/ddtest dir=- perm=rw uid=- gid=- success=- key=ddtest argv=Inherit coverage_version=1 coverage_b64=r:open,openat,openat2,readlink,readlinkat,getxattr,lgetxattr,fgetxattr,listxattr,llistxattr,flistxattr|w:open,openat,openat2,creat,truncate,ftruncate,fallocate,rename,renameat,renameat2,unlink,unlinkat,mkdir,mkdirat,rmdir,link,linkat,symlink,symlinkat,mknod,mknodat coverage_b32=r:open,openat,openat2,readlink,readlinkat,getxattr,lgetxattr,fgetxattr,listxattr,llistxattr,flistxattr|w:open,openat,openat2,creat,truncate,ftruncate,fallocate,rename,renameat,renameat2,unlink,unlinkat,mkdir,mkdirat,rmdir,link,linkat,symlink,symlinkat,mknod,mknodat
```

实现允许采用按 syscall 编号排序而不是示例展示顺序，但契约测试必须固定唯一顺序。

## Failure Output

以下情况返回规则错误退出码 3，并包含文件、行号、错误码和原因：

| Code | Condition |
|------|-----------|
| `E_PERMISSION` | `-p` 缺失、为空、重复字符或包含非 `rwxa` 字符 |
| `E_PERMISSION_COVERAGE` | 任一请求权限在声明 ABI 上覆盖为空 |
| `E_SYSCALL_RANGE` | 展开得到 syscall 编号不在 0..512 |
| `E_WATCH_PATH` | 路径不是受支持绝对词法路径 |
| `E_KEY` | key 缺失、重复、为空或过长 |

任何规则失败时不得输出可用于启动的部分 rule version。
