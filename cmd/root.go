package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"time"
)

var (
	TimeDuration   time.Duration // 超时时间
	Hosts          string        // 全局host变量
	RunICMP        bool          // 是否执行ICMP
	Ports          string        // 需要解析的端口
	Runtime        int           // 运行的线程
	JsonBool       bool          // 是否使用日志
	PingBool       bool          // 是否执行ping操作
	UserDic        string        // 爆破的用户名路径
	PassDic        string        // 爆破的密码路径
	BruteFlag      bool          // 是否进行爆破
	ConnHost       string        // 单独变量的链接地址
	BrutePort      int           // 爆破使用的端口
	LoginUser      string        // 登陆使用的用户
	LoginPass      string        // 登陆使用的密码
	LoginPublicKey string        // 登陆使用的公钥路径
	ProxyHost      string        // 代理地址 user:pass@ip:port 格式
	SQLShellBool   bool          // 是否启动sql—shell
	SQLCommand     string        // sql语句单条命令行
	WinRMbool      bool          // winrm shell
)

var rootCmd = &cobra.Command{
	Use:   "Yasso",
	Short: "\n __  __     ______     ______     ______     ______    \n/\\ \\_\\ \\   /\\  __ \\   /\\  ___\\   /\\  ___\\   /\\  __ \\   \n\\ \\____ \\  \\ \\  __ \\  \\ \\___  \\  \\ \\___  \\  \\ \\ \\/\\ \\  \n \\/\\_____\\  \\ \\_\\ \\_\\  \\/\\_____\\  \\/\\_____\\  \\ \\_____\\ \n  \\/_____/   \\/_/\\/_/   \\/_____/   \\/_____/   \\/_____/ \n                                                       \n",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		Println(fmt.Sprintf("%v", err))
		os.Exit(1)
	}
}
