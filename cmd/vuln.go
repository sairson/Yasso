package cmd

import (
	"Yasso/config"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"github.com/spf13/cobra"
	"sync"
)

// smbghost eternalblue
var (
	ms17010bool bool
	smbGohstbool bool
	allbool bool
)
var VulCmd = &cobra.Command{
	Use: "vulscan",
	Short: "Host Vulnerability Scanning (support proxy)",
	Run: func(cmd *cobra.Command, args []string) {
		var ips []string
		if Hosts == "" {
			_ = cmd.Help()
			return
		}
		if Hosts != "" {
			ips, _ = ResolveIPS(Hosts)  // resolve ip to []string ips
		}else{
			Println("Yasso scanner need a hosts")
			return
		}
		if smbGohstbool == true || ms17010bool == true || allbool == true {
			Println(fmt.Sprintf("[Yasso] will scan %d host",len(ips)))
		}
		VulScan(ips,ms17010bool,allbool,smbGohstbool)
	},
}

func init(){
	VulCmd.Flags().StringVarP(&Hosts,"hosts","H","","Set `hosts`(The format is similar to Nmap)")
	VulCmd.Flags().StringVar(&ProxyHost,"proxy","","Set socks5 proxy")
	VulCmd.Flags().BoolVar(&smbGohstbool,"gs",false,"scan smbghost")
	VulCmd.Flags().BoolVar(&ms17010bool,"ms",false,"scan ms17010")
	VulCmd.Flags().BoolVar(&allbool,"all",false,"scan all vuln contains ms17010,smbghost")
	rootCmd.AddCommand(VulCmd)
}

func VulScan(ips []string,ms17010bool bool,allbool bool,smbGohstbool bool){
	var wg sync.WaitGroup

	go func() {
		for _,ip := range ips{
			tunnel <- ip
		}
	}()
	for i:=0;i<len(ips);i++{
		wg.Add(1)
		_ = ants.Submit(func() {
			ip := <- tunnel
			if ms17010bool == true || allbool == true {
				Ms17010Conn(config.HostIn{
					Host:    ip,
					Port:    445,
					TimeOut: TimeDuration,
				})
			}
			if smbGohstbool == true || allbool == true{
				SmbGhostConn(config.HostIn{
					Host: ip,
					Port: 445,
					TimeOut: TimeDuration,
				})
			}
			wg.Done()
		})
	}
	wg.Wait()
}