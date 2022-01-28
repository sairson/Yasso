<h1>👾 Yasso - 亚索 👾</h1>

建议git下来自己编译，编译命令
```
go build -x -v -ldflags "-s -w"
```

![go](https://img.shields.io/badge/Go-1.16.4-blue)

[English Introduce](README_EN.md)

## 介绍 😈

Yasso 将作为一款内网辅助渗透工具集发布，它集合了许多实用功能，来帮助`Red team`成员在内网极端环境下的工具使用以及`Blue team`成员的内网自检,并且程序加入了代理功能以及`ants`
的扫描并发，在实现功能的同时追求准确和速度

[![asciicast](https://asciinema.org/a/fBxRVxLJ30eVo0dOz2e9mlAZL.svg)](https://asciinema.org/a/fBxRVxLJ30eVo0dOz2e9mlAZL)

使用格式为

```
Yasso [模块] [参数1] [参数2] [参数...]
```

模块里面的 `Flag` 代表当前命令的参数，`Global Flags` 代表全局参数（所有命令都可以用）

## 程序功能模块 👻

2022年1月7日更新 -H 参数均支持ip.txt的导入，如下

![image](https://user-images.githubusercontent.com/74412075/148518267-4f72e048-6aee-4ba6-b67d-a447468f2807.png)

2022年1月26日更新 crack 模块中 --ud --pass参数指定，由原本的字典变为字典和用户名指定模式（--ud "administrator,Oadmin" --pd "123456,11223"） 

![image](https://user-images.githubusercontent.com/74412075/151147036-3aa34477-327b-44ef-a633-0504d40b855a.png)


目前已有用功能模块 :

<b>all模块: 调用全部模块的完全扫描方式，速度更快，能力更强，ants与并发的完美结合</b>

```
Usage:
  Yasso all [flags]

Flags:
  -h, --help            help for all
  -H, --host hosts      Set hosts(The format is similar to Nmap)
      --noping          No use ping to scanner alive host (default true)
  -P, --ports ports     Set ports(The format is similar to Nmap)
      --proxy string    Set socks5 proxy
      --runtime int     Set scanner ants pool thread (default 100)
      --time duration   Set timeout  (default 1s)
```

<b>ping模块: 普通用户权限调用系统ping，root权限可以选择使用icmp数据包</b>

```
Use ping or icmp to scanner alive host

Usage:
  Yasso ping [flags]

Flags:
  -h, --help         help for ping
  -H, --host hosts   Set hosts(The format is similar to Nmap)
  -i, --icmp         Icmp packets are sent to check whether the host is alive(need root)
```

<b>crack模块: 强大的爆破模块和利用工具集 - 子工具集</b>

```
Available Commands:
  ftp         ftp burst module (support proxy)
  grdp        RDP burst module (support proxy)
  log4j       Open a socket listener to test log4J vulnerabilities offline
  mongo       MongoDB burst module (support proxy)
  mssql       SQL Server burst module and extend tools (not support proxy)
  mysql       MYSQL burst module and extend tools (support proxy)
  postgres    PostgreSQL burst module (not support proxy)
  redis       Redis burst and Redis extend tools (support proxy)
  smb         Smb burst module (not support proxy)
  ssh         SSH burst and SSH extend tools (support proxy)
  winrm       winrm burst and extend tools (support proxy)

Flags:
      --crack              make sure to use crack
  -h, --help               help for crack
  -H, --hosts string       to crack hosts address (crack Must)
      --pd string          pass dic path (.eg) pass.txt
      --port int           to crack hosts port (if not set use default)
      --proxy string       set socks5 proxy address
      --runtime int        set crack thread number (default 100)
      --timeout duration   crack module timeout(.eg) 1s (ns,ms,s,m,h) (default 1s)
      --ud string          user dic path (.eg) user.txt
```

程序主要分为多个子命令功能，每个功能都详细标注了用法，这里详细介绍子功能
<details>
<summary>ftp ftp服务爆破模块 - 支持socks5代理</summary>

```
Flags:
  -h, --help   help for ftp

Global Flags:
      --crack              make sure to use crack
  -H, --hosts string       to crack hosts address (crack Must)
      --pd string          pass dic path (.eg) pass.txt
      --port int           to crack hosts port (if not set use default)
      --proxy string       set socks5 proxy address
      --runtime int        set crack thread number (default 100)
      --timeout duration   crack module timeout(.eg) 1s (ns,ms,s,m,h) (default 1s)
      --ud string          user dic path (.eg) user.txt
```

</details>

<details>
<summary>grdp  rdp服务爆破模块 - 支持socks5代理</summary>

```
Flags:
      --domain string   set host domain
  -h, --help            help for grdp

Global Flags:
      --crack              make sure to use crack
  -H, --hosts string       to crack hosts address (crack Must)
      --pd string          pass dic path (.eg) pass.txt
      --port int           to crack hosts port (if not set use default)
      --proxy string       set socks5 proxy address
      --runtime int        set crack thread number (default 100)
      --timeout duration   crack module timeout(.eg) 1s (ns,ms,s,m,h) (default 1s)
      --ud string          user dic path (.eg) user.txt
```

</details>

<details>
<summary>log4j  log4j2 服务器 - 用于内网不出网手动的log4j漏洞检测</summary>

```
Flags:
  -b, --bind string   socket listen address (default "0.0.0.0:4568")
  -h, --help          help for log4j

Global Flags:
      --crack              make sure to use crack
  -H, --hosts string       to crack hosts address (crack Must)
      --pd string          pass dic path (.eg) pass.txt
      --port int           to crack hosts port (if not set use default)
      --proxy string       set socks5 proxy address
      --runtime int        set crack thread number (default 100)
      --timeout duration   crack module timeout(.eg) 1s (ns,ms,s,m,h) (default 1s)
      --ud string          user dic path (.eg) user.txt
```

</details>

<details>
<summary>mongo  mongodb服务爆破模块 - 支持socks5代理</summary>

```
Flags:
  -h, --help   help for mongo

Global Flags:
      --crack              make sure to use crack
  -H, --hosts string       to crack hosts address (crack Must)
      --pd string          pass dic path (.eg) pass.txt
      --port int           to crack hosts port (if not set use default)
      --proxy string       set socks5 proxy address
      --runtime int        set crack thread number (default 100)
      --timeout duration   crack module timeout(.eg) 1s (ns,ms,s,m,h) (default 1s)
      --ud string          user dic path (.eg) user.txt
```

</details>

<details>
<summary>mssql sql server 服务爆破模块和提权辅助模块 - 不支持socks5代理</summary>

```
Flags:
      --cld string           Execute WarSQLKit  Command (eg.) --cld "whoami"
  -c, --cmd string           Execute System command
  -h, --help                 help for mssql
      --hostname string      Remote Connect mssql address(brute param need false)
      --inkit int            install mssql SQLKit Rootkit [1,WarSQLKit] [2,SharpSQLKit(no echo)]
      --kithelp int          print SQLKit Use help
      --method int           Execute System command method [1,xpshell] [2,oleshell] (default 1)
      --pass string          Login ssh password
  -s, --sql string           Execute sql command
      --unkit int            uninstall mssql SQLKit Rootkit [1,WarSQLKit] [2,SharpSQLKit(no echo)]
      --upload stringArray   Use ole upload file (.eg) source,dest
      --user string          Login ssh username (default "sa")

Global Flags:
      --crack              make sure to use crack
  -H, --hosts string       to crack hosts address (crack Must)
      --pd string          pass dic path (.eg) pass.txt
      --port int           to crack hosts port (if not set use default)
      --proxy string       set socks5 proxy address
      --runtime int        set crack thread number (default 100)
      --timeout duration   crack module timeout(.eg) 1s (ns,ms,s,m,h) (default 1s)
      --ud string          user dic path (.eg) user.txt
```

</details>

<details>
<summary>mysq  mysql服务爆破模块和数据库查询 - 支持socks5代理</summary>

```
Flags:
  -C, --cmd string        mysql sql command
  -h, --help              help for mysql
      --hostname string   Remote Connect a Mysql (brute param need false)
      --pass string       Login ssh password
      --shell             create sql shell to exec sql command
      --user string       Login ssh username

Global Flags:
      --crack              make sure to use crack
  -H, --hosts string       to crack hosts address (crack Must)
      --pd string          pass dic path (.eg) pass.txt
      --port int           to crack hosts port (if not set use default)
      --proxy string       set socks5 proxy address
      --runtime int        set crack thread number (default 100)
      --timeout duration   crack module timeout(.eg) 1s (ns,ms,s,m,h) (default 1s)
      --ud string          user dic path (.eg) user.txt
```

</details>

<details>
<summary>postgres  PostgreSQL服务爆破模块 - 不支持socks5代理</summary>

```
Flags:
  -h, --help   help for postgres

Global Flags:
      --crack              make sure to use crack
  -H, --hosts string       to crack hosts address (crack Must)
      --pd string          pass dic path (.eg) pass.txt
      --port int           to crack hosts port (if not set use default)
      --proxy string       set socks5 proxy address
      --runtime int        set crack thread number (default 100)
      --timeout duration   crack module timeout(.eg) 1s (ns,ms,s,m,h) (default 1s)
      --ud string          user dic path (.eg) user.txt
```

</details>

<details>
<summary>redis  redis服务爆破模块，未授权检测，一键利用（写公钥，反弹shell） - 支持socks5代理</summary>

```
Flags:
  -h, --help              help for redis
      --hostname string   Redis will connect this address
      --pass string       set login pass
      --rebound string    Rebound shell address (eg.) 192.168.1.1:4444
      --rekey string      Write public key to Redis (eg.) id_rsa.pub

Global Flags:
      --crack              make sure to use crack
  -H, --hosts string       to crack hosts address (crack Must)
      --pd string          pass dic path (.eg) pass.txt
      --port int           to crack hosts port (if not set use default)
      --proxy string       set socks5 proxy address
      --runtime int        set crack thread number (default 100)
      --timeout duration   crack module timeout(.eg) 1s (ns,ms,s,m,h) (default 1s)
      --ud string          user dic path (.eg) user.txt
```

</details>

<details>
<summary>smb  smb服务爆破模块 - 不支持socks5代理</summary>

```
Flags:
  -h, --help   help for smb

Global Flags:
      --crack              make sure to use crack
  -H, --hosts string       to crack hosts address (crack Must)
      --pd string          pass dic path (.eg) pass.txt
      --port int           to crack hosts port (if not set use default)
      --proxy string       set socks5 proxy address
      --runtime int        set crack thread number (default 100)
      --timeout duration   crack module timeout(.eg) 1s (ns,ms,s,m,h) (default 1s)
      --ud string          user dic path (.eg) user.txt
```

</details>

<details>
<summary>ssh ssh服务爆破模块，完全交互shell连接 - 支持socks5代理</summary>

```
Flags:
  -h, --help              help for ssh
      --hostname string   Open an interactive SSH at that address(brute param need false)
      --key string        ssh public key path
      --pass string       Login ssh password
      --user string       Login ssh username

Global Flags:
      --crack              make sure to use crack
  -H, --hosts string       to crack hosts address (crack Must)
      --pd string          pass dic path (.eg) pass.txt
      --port int           to crack hosts port (if not set use default)
      --proxy string       set socks5 proxy address
      --runtime int        set crack thread number (default 100)
      --timeout duration   crack module timeout(.eg) 1s (ns,ms,s,m,h) (default 1s)
      --ud string          user dic path (.eg) user.txt
```

</details>

<details>
<summary>winrm winrm服务爆破模块，命令执行横向 - 支持socks5代理</summary>

```
Flags:
  -c, --cmd string        Execute system command
  -h, --help              help for winrm
      --hostname string   Open an interactive SSH at that address(brute param need false)
      --pass string       Login ssh password
      --shell             Get a cmd shell with WinRM
      --user string       Login ssh username

Global Flags:
      --crack              make sure to use crack
  -H, --hosts string       to crack hosts address (crack Must)
      --pd string          pass dic path (.eg) pass.txt
      --port int           to crack hosts port (if not set use default)
      --proxy string       set socks5 proxy address
      --runtime int        set crack thread number (default 100)
      --timeout duration   crack module timeout(.eg) 1s (ns,ms,s,m,h) (default 1s)
      --ud string          user dic path (.eg) user.txt
```

</details>


<b>ps 模块: 采用ants协程的端口扫描，速度更快，更准确 - 不支持socks5代理</b>

```
Usage:
  Yasso ps [flags]

Flags:
  -h, --help            help for ps
  -H, --hosts hosts     Set hosts(The format is similar to Nmap)
  -p, --ports ports     Set ports(The format is similar to Nmap)(eg.) 1-2000,3389
  -r, --runtime int     Set scanner ants pool thread (default 100)
  -t, --time duration   Set timeout (eg.) -t 50ms(ns,ms,s,m,h) (default 500ms)
```

<b>vulscan 模块: 主机漏洞扫描-支持ms17010，smbghost漏洞 - 支持socks5代理</b>

```
Usage:
  Yasso vulscan [flags]

Flags:
      --all            scan all vuln contains ms17010,smbghost
      --gs             scan smbghost
  -h, --help           help for vulscan
  -H, --hosts hosts    Set hosts(The format is similar to Nmap)
      --ms             scan ms17010
      --proxy string   Set socks5 proxy
```

<b>webscan模块: 完全的dismap移植，拥有更将强大的指纹识别 - 支持socks5代理</b>

```
Usage:
  Yasso webscan [flags]

Flags:
  -h, --help            help for webscan
  -H, --hosts hosts     Set hosts(The format is similar to Nmap)
      --ping            Use ping to scan alive host
  -p, --ports ports     Set ports(The format is similar to Nmap)(eg.) 1-2000,3389
      --proxy string    Set socks5 proxy and use it
  -r, --runtime int     Set scanner ants pool thread (default 508)
  -t, --time duration   Set timeout (eg.) -t 50ms(ns,ms,s,m,h) (default 1s)
```

<b>winscan模块: windows主机的netbios识别，oxid网卡发现，smb主机指纹 - 支持socks5代理</b>

```
netbios、smb、oxid scan

Usage:
  Yasso winscan [flags]

Flags:
      --all             Set all flag and use oxid,netbios,smb scan (default true)
  -h, --help            help for winscan
  -H, --hosts hosts     Set hosts(The format is similar to Nmap)
      --netbios         Set netbios flag and use netbios scan
      --oxid            Set oxid flag and use oxid scan
      --proxy string    Set socks5 proxy and use it
      --smb             Set smb flag and use smb scan
      --time duration   Set net conn timeout (default 1s)
```

## 使用例子👿

all 模块的扫描服务调用

```
Yasso.exe all -H 192.168.248.1/24
```

![image](https://user-images.githubusercontent.com/74412075/148240369-14cc4c77-e4f8-4fd1-8faa-e716852d3ed8.png)

mssql 的命令执行提权和WarSQLKit-clr提权Rookit安装卸载执行功能

```
Yasso.exe crack mssql --user sa --pass "admin@123" -c whoami --hostname 192.168.248.128 
Yasso.exe crack mssql --user sa --pass "admin@123" -c whoami --hostname 192.168.248.128 --method 2
Yasso.exe crack mssql --user sa --pass "admin@123" -c whoami --hostname 192.168.248.128 --inkit 1
Yasso.exe crack mssql --hostname 192.168.248.128 --user sa --pass "admin@123" --cld "sp_getSqlHash"
Yasso.exe crack mssql --hostname 192.168.248.128 --user sa --pass "admin@123" --cld "whoami"
Yasso.exe crack mssql --user sa --pass "admin@123" -c whoami --hostname 192.168.248.128 --unkit 1
```

![image](https://user-images.githubusercontent.com/74412075/148234003-8e2ceb59-95c5-4fc3-ad65-501294ddce6b.png)

winrm 的命令执行和交互shell

```
Yasso.exe crack winrm --hostname 192.168.248.128 -c "ipconfig /all" --pass "930517" --user "administrator"
```

![image](https://user-images.githubusercontent.com/74412075/148234337-80fabcef-a333-402d-8e97-e694b89119c0.png)

```
Yasso.exe crack winrm --hostname 192.168.248.128 --shell --pass "930517" --user "administrator"
```

![image](https://user-images.githubusercontent.com/74412075/148234486-037aaf56-fe11-40a0-9781-82b537ef9a37.png)

grdp的强大爆破功能

```
Yasso.exe crack grdp --domain "kilon.local" --pd .\pass.txt --ud .\user.txt -H 192.168.248.128/24 --crack
```

![image](https://user-images.githubusercontent.com/74412075/148234733-fbdc34e7-c73e-49f7-8942-3a1863915213.png)

ssh的交互式登陆

```
Yasso.exe crack ssh --hostname 192.168.248.219 --user root --pass kali
```

![image](https://user-images.githubusercontent.com/74412075/148235003-a72116d3-df9b-4b4e-9523-21d5f8b30e1b.png)

## 工具优势🤡

- 命令简单方便，模块功能调用简洁明了，方便拓展和添加各种新功能
- 集合了大量的常用功能，使得Yasso并不像常规的扫描器，而是作为工具集
- 强大的SQL渗透辅助功能，提供了常见的redis，mysql，mssql等数据库的一键提权和数据库操作
- 强大的并发爆破，使得大字典能获取更快的速度
- rdp和winrm的强势加入，使得内网横向更加迅速和方便快捷

## 免责声明🧐

本工具仅面向**合法授权**的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。**请勿对非授权目标进行扫描，这一点十分重要**

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在安装并使用本工具前，请您**务必审慎阅读、充分理解各条款内容**，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。
除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。

## 工具编写参考链接👀

```
https://github.com/shadow1ng/fscan 
https://github.com/k8gege/LadonGo
https://github.com/zyylhn/zscan
https://github.com/uknowsec/SharpSQLTools
https://github.com/mindspoof/MSSQL-Fileless-Rootkit-WarSQLKit
https://github.com/masterzen/winrm
https://github.com/tomatome/grdp
https://github.com/panjf2000/ants
```
