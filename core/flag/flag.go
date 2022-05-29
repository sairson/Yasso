package flag

import (
	"Yasso/core/logger"
	"Yasso/core/plugin"
	"Yasso/pkg/exploit"
	"github.com/spf13/cobra"
	"os"
	"time"
)

type allFlags struct {
	Hosts     string // 全局变量 标识ip列表或文件路径
	Ports     string // 全局变量 标识扫描的端口
	Timeout   int    // 全局变量 标识超时时间
	NoCrack   bool   // 全局变量 标识all模块是否开启爆破
	NoAlive   bool   // 全局变量 是否采用ping来判断存活主机
	User      string // 全局变量 标识all模块爆破使用用户名字典
	Pass      string // 全局变量 标识all模块爆破使用密码字典
	Thread    int    // 全局变量 标识all模块扫描时的线程数
	NoService bool   // 全局变量 标识all模块是否探测服务
	NoVulcan  bool   // 全局变量 标识all模块是否进行主机层漏扫
}

type BurpFlags struct {
	Hosts   string // 全局变量，标识ip列表或文件路径
	Method  string // 爆破的服务名称
	User    string // 爆破时采用的用户字典
	Pass    string // 爆破时采用的密码字典
	Thread  int    // 爆破时采用的线程数
	Timeout int    // 爆破的超时时间
	IsAlive bool   // 爆破前是否检测存活
}

var burp BurpFlags
var all allFlags

var rootCmd = &cobra.Command{
	Use:   "Yasso",
	Short: "\n_____.___.                         ____  ___\n\\__  |   |____    ______ __________\\   \\/  /\n /   |   \\__  \\  /  ___//  ___/  _ \\\\     / \n \\____   |/ __ \\_\\___ \\ \\___ (  <_> )     \\ \n / ______(____  /____  >____  >____/___/\\  \\\n \\/           \\/     \\/     \\/           \\_/\n",
}

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "Use all scanner module (.attention) Traffic is very big",
	Run: func(cmd *cobra.Command, args []string) {
		if all.Hosts == "" {
			_ = cmd.Help()
			return
		}
		scanner := plugin.NewAllScanner(all.Hosts, all.Ports, all.NoAlive, all.NoCrack, all.User, all.Pass, all.Thread, time.Duration(all.Timeout)*1000*time.Millisecond, all.NoService, all.NoVulcan)
		scanner.RunEnumeration()
	},
}

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Detection or blasting services by module",
	Run: func(cmd *cobra.Command, args []string) {
		if burp.Hosts == "" {
			_ = cmd.Help()
			return
		}
		plugin.BruteService(burp.User, burp.Pass, burp.Hosts, burp.Method, burp.Thread, time.Duration(burp.Timeout)*1000*time.Millisecond, burp.IsAlive)
	},
}

var ExpCmd = &cobra.Command{
	Use:   "exploit",
	Short: "Exploits to attack the service",
	Run: func(cmd *cobra.Command, args []string) {
		if cmd.HasSubCommands() {
			_ = cmd.Help()
		}
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&logger.LogFile, "output", "result.txt", "set logger file")
	allCmd.Flags().StringVar(&logger.LogJson, "json", "", "设置json格式输出文件")
	allCmd.Flags().StringVarP(&all.Hosts, "hosts", "H", "", "设置扫描的目标参数(.eg) \n[192.168.248.1/24]\n[192.168.248.1-255]\n[example.txt]")
	allCmd.Flags().StringVar(&all.Ports, "ports", "", "设置扫描的端口参数(.eg) null将采用默认端口号 top 1000")
	allCmd.Flags().IntVar(&all.Timeout, "timeout", 1, "设置扫描的超时时间 默认1秒")
	allCmd.Flags().BoolVar(&all.NoCrack, "no-crack", false, "设置扫描时是否爆破脆弱服务")
	allCmd.Flags().BoolVar(&all.NoAlive, "no-alive", false, "设置扫描时是否先检测主机存活")
	allCmd.Flags().StringVar(&all.User, "user-dic", "", "设置扫描时爆破采用的用户名字典 (.eg) null将采用默认用户名字典")
	allCmd.Flags().StringVar(&all.Pass, "pass-dic", "", "设置扫描时爆破采用的密码字典 (.eg) null将采用默认密码字典")
	allCmd.Flags().IntVar(&all.Thread, "thread", 500, "设置扫描时的扫描线程 (.eg) 默认500 线程")
	allCmd.Flags().BoolVar(&all.NoService, "no-service", false, "设置扫描时是否探测服务")
	allCmd.Flags().BoolVar(&all.NoVulcan, "no-vuln", false, "设置扫描时是否检测主机层漏洞")
	rootCmd.AddCommand(allCmd)
	serviceCmd.Flags().StringVarP(&burp.Hosts, "hosts", "H", "", "设置扫描的目标参数(.eg) \n[192.168.248.1/24]\n[192.168.248.1-255]\n[example.txt]")
	serviceCmd.Flags().StringVar(&burp.Method, "module", "", "指定要爆破的服务名称(.eg) \n[mssql,ftp,ssh,mysql,rdp,postgres,redis,winrm,smb,mongo]\n以逗号分割,可同时爆破多个服务(--module ssh:22,mysql:3306,rdp:3389)")
	serviceCmd.Flags().IntVar(&burp.Thread, "thread", 500, "设置扫描时的扫描线程 (.eg) 默认500 线程")
	serviceCmd.Flags().StringVar(&burp.User, "user-dic", "", "设置扫描时爆破采用的用户名字典 (.eg) null将采用默认用户名字典")
	serviceCmd.Flags().StringVar(&burp.Pass, "pass-dic", "", "设置扫描时爆破采用的密码字典 (.eg) null将采用默认密码字典")
	serviceCmd.Flags().IntVar(&burp.Timeout, "timeout", 1, "设置爆破的超时时间 默认1秒")
	serviceCmd.Flags().BoolVar(&burp.IsAlive, "is-alive", true, "爆破前是否进行ping检测存活")
	rootCmd.AddCommand(serviceCmd)
	rootCmd.AddCommand(ExpCmd)
	// 利用模块命令
	ExpCmd.AddCommand(exploit.MssqlCmd)
	ExpCmd.AddCommand(exploit.SshCmd)
	ExpCmd.AddCommand(exploit.WinRmCmd)
	ExpCmd.AddCommand(exploit.RedisCmd)
	ExpCmd.AddCommand(exploit.SunLoginCmd)
	ExpCmd.AddCommand(exploit.LdapReaperCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(0)
	}
}
