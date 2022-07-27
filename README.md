# Yasso
强大的内网渗透辅助工具集-让Yasso像风一样 支持rdp，ssh，redis，postgres，mongodb，mssql，mysql，winrm等服务爆破，快速的端口扫描，强大的web指纹识别，各种内置服务的一键利用（包括ssh完全交互式登录，mssql提权，redis一键利用，mysql数据库查询，winrm横向利用，多种服务利用支持socks5代理执行）

# 新版功能
在原基础上更改扫描和爆破方式，去除不必要的功能，代码更加完善和整洁<br>
增加协议上的识别和端口识别
* 新版并未发布release版本，请自行clone去编译
# 功能
```
Usage:
  Yasso [command]

Available Commands:
  all         Use all scanner module (.attention) Traffic is very big   
  completion  Generate the autocompletion script for the specified shell
  exploit     Exploits to attack the service
  help        Help about any command
  service     Detection or blasting services by module

Flags:
  -h, --help            help for Yasso
      --output string   set logger file (default "result.txt")
```

- all 一键扫描功能
- exploit 常见服务利用（sqlserver，redis，ssh，向日葵等）
- service 服务爆破和子扫描模块

详情请-h参考
