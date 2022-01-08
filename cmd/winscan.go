package cmd

import (
	"bytes"
	"fmt"
	"github.com/spf13/cobra"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var netbiosflag bool
var smbflag bool
var oxidflag bool
var allflag bool

var WinCmd = &cobra.Command{
	Use:   "winscan",
	Short: "netbios、smb、oxid scan",
	Run: func(cmd *cobra.Command, args []string) {
		var ips []string
		if Hosts == "" {
			_ = cmd.Help()
			return
		}
		if Hosts != "" {
			ips, _ = ResolveIPS(Hosts) // resolve ip to []string ips
		} else {
			Println("Yasso scanner need a hosts")
			return
		}
		Println(fmt.Sprintf("[Yasso] will scan %d host", len(ips)))
		winscan(ips, allflag)
	},
}

func init() {
	rootCmd.AddCommand(WinCmd)
	WinCmd.Flags().BoolVar(&smbflag, "smb", false, "Set smb flag and use smb scan")
	WinCmd.Flags().BoolVar(&netbiosflag, "netbios", false, "Set netbios flag and use netbios scan")
	WinCmd.Flags().BoolVar(&oxidflag, "oxid", false, "Set oxid flag and use oxid scan")
	WinCmd.Flags().BoolVar(&allflag, "all", true, "Set all flag and use oxid,netbios,smb scan")
	WinCmd.Flags().StringVarP(&Hosts, "hosts", "H", "", "Set `hosts`(The format is similar to Nmap) or ips.txt file path")
	WinCmd.Flags().DurationVar(&TimeDuration, "time", 1*time.Second, "Set net conn timeout")
	WinCmd.Flags().StringVar(&ProxyHost, "proxy", "", "Set socks5 proxy and use it")
}

func winscan(host []string, allay bool) {
	if netbiosflag == true {
		NbtScan(host)
	} else if smbflag == true {
		SmbScan(host)
	} else if oxidflag == true {
		OxidScan(host)
	} else if allay == true {
		runall(host)
	} else {
		Println("[*] Your need set netbios、smb、oxid flag")
	}
}

var oxidQuery1 = [...]byte{
	0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x10, 0xb8, 0x10,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10,
	0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a, 0x00, 0x00,
	0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
	0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00,
	0x00, 0x00,
}

var oxidQuery2 = [...]byte{
	0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x18, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x05, 0x00,
}

func ConncetNbios(ip string, port int) (string, int, error, []string) {
	nbname, err := netBios(ip)
	if nbname.msg != "" {
		return ip, port, nil, []string{nbname.msg}
	}
	return ip, port, err, nil
}

var smbQuery = [...]byte{
	0x00, 0x00, 0x00, 0xa4, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x40,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x81, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
	0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02,
	0x4d, 0x49, 0x43, 0x52, 0x4f, 0x53, 0x4f, 0x46, 0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52,
	0x4b, 0x53, 0x20, 0x31, 0x2e, 0x30, 0x33, 0x00, 0x02, 0x4d, 0x49, 0x43, 0x52, 0x4f, 0x53, 0x4f,
	0x46, 0x54, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x53, 0x20, 0x33, 0x2e, 0x30, 0x00,
	0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00, 0x02, 0x4c, 0x4d, 0x31, 0x2e,
	0x32, 0x58, 0x30, 0x30, 0x32, 0x00, 0x02, 0x53, 0x61, 0x6d, 0x62, 0x61, 0x00, 0x02, 0x4e, 0x54,
	0x20, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02, 0x4e, 0x54, 0x20,
	0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00,
}

var (
	UNIQUE_NAMES = map[string]string{
		"\x00": "Workstation Service",
		"\x03": "Messenger Service",
		"\x06": "RAS Server Service",
		"\x1F": "NetDDE Service",
		"\x20": "Server Service",
		"\x21": "RAS Client Service",
		"\xBE": "Network Monitor Agent",
		"\xBF": "Network Monitor Application",
		"\x1D": "Master Browser",
		"\x1B": "Domain Master Browser",
	}

	GROUP_NAMES = map[string]string{
		"\x00": "Domain Name",
		"\x1C": "Domain Controllers",
		"\x1E": "Browser Service Elections",
	}

	NetBIOS_ITEM_TYPE = map[string]string{
		"\x01\x00": "NetBIOS computer name",
		"\x02\x00": "NetBIOS domain name",
		"\x03\x00": "DNS computer name",
		"\x04\x00": "DNS domain name",
		"\x05\x00": "DNS tree name",
		"\x07\x00": "Time stamp",
	}
)

type NbnsName struct {
	unique    string
	group     string
	msg       string
	osversion string
}

func netBios(host string) (nbname NbnsName, err error) {
	nbname, err = getNbnsname(host)
	var payload0 []byte
	if err == nil {
		name := netbiosEncode(nbname.unique)
		payload0 = append(payload0, []byte("\x81\x00\x00D ")...)
		payload0 = append(payload0, name...)
		payload0 = append(payload0, []byte("\x00 EOENEBFACACACACACACACACACACACACA\x00")...)
	}
	realhost := fmt.Sprintf("%s:%v", host, 139)
	conn, err := GetConn(realhost, TimeDuration)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return
	}
	err = conn.SetDeadline(time.Now().Add(TimeDuration))
	if err != nil {
		return
	}

	if len(payload0) > 0 {
		_, err1 := conn.Write(payload0)
		if err1 != nil {
			return
		}
		_, err1 = readbytes(conn)
		if err1 != nil {
			return
		}
	}

	payload1 := []byte("\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00")
	payload2 := []byte("\x00\x00\x01\x0a\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00\x0c\xff\x00\x0a\x01\x04\x41\x32\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00\x00\xd4\x00\x00\xa0\xcf\x00\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x02\xce\x0e\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x33\x00\x37\x00\x39\x00\x30\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x32\x00\x00\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x35\x00\x2e\x00\x32\x00\x00\x00\x00\x00")
	_, err = conn.Write(payload1)
	if err != nil {
		return
	}
	_, err = readbytes(conn)
	if err != nil {
		return
	}

	_, err = conn.Write(payload2)
	if err != nil {
		return
	}
	ret, err := readbytes(conn)
	if err != nil || len(ret) < 45 {
		return
	}

	num1, err := bytetoint(ret[43:44][0])
	if err != nil {
		return
	}
	num2, err := bytetoint(ret[44:45][0])
	if err != nil {
		return
	}
	length := num1 + num2*256
	if len(ret) < 48+length {
		return
	}
	os_version := ret[47+length:]
	tmp1 := bytes.ReplaceAll(os_version, []byte{0x00, 0x00}, []byte{124})
	tmp1 = bytes.ReplaceAll(tmp1, []byte{0x00}, []byte{})
	msg1 := string(tmp1[:len(tmp1)-1])
	nbname.osversion = msg1
	index1 := strings.Index(msg1, "|")
	if index1 > 0 {
		nbname.osversion = nbname.osversion[:index1]
	}
	nbname.msg += "\n\t-------------------------------------------\n\t"
	nbname.msg += msg1 + "\n\t"
	start := bytes.Index(ret, []byte("NTLMSSP"))
	if len(ret) < start+45 {
		return
	}
	num1, err = bytetoint(ret[start+40 : start+41][0])
	if err != nil {
		return
	}
	num2, err = bytetoint(ret[start+41 : start+42][0])
	if err != nil {
		return
	}
	length = num1 + num2*256
	num1, err = bytetoint(ret[start+44 : start+45][0])
	if err != nil {
		return
	}
	offset, err := bytetoint(ret[start+44 : start+45][0])
	if err != nil || len(ret) < start+offset+length {
		return
	}
	index := start + offset
	for index < start+offset+length {
		item_type := ret[index : index+2]
		num1, err = bytetoint(ret[index+2 : index+3][0])
		if err != nil {
			return
		}
		num2, err = bytetoint(ret[index+3 : index+4][0])
		if err != nil {
			return
		}
		item_length := num1 + num2*256
		item_content := bytes.ReplaceAll(ret[index+4:index+4+item_length], []byte{0x00}, []byte{})
		index += 4 + item_length
		if string(item_type) == "\x07\x00" {
			//Time stamp, 暂时不想处理
		} else if NetBIOS_ITEM_TYPE[string(item_type)] != "" {
			nbname.msg += fmt.Sprintf("%-22s: %s\n\t", NetBIOS_ITEM_TYPE[string(item_type)], string(item_content))
		} else if string(item_type) == "\x00\x00" {
			break
		} else {
			nbname.msg += fmt.Sprintf("Unknown: %s\n\t", string(item_content))
		}
	}
	nbname.msg = strings.TrimSpace(nbname.msg)
	return nbname, err
}

func getNbnsname(host string) (nbname NbnsName, err error) {
	senddata1 := []byte{102, 102, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 32, 67, 75, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 0, 0, 33, 0, 1}
	realhost := fmt.Sprintf("%s:%v", host, 137)
	conn, err := net.DialTimeout("udp", realhost, TimeDuration)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return
	}
	err = conn.SetDeadline(time.Now().Add(TimeDuration))
	if err != nil {
		return
	}
	_, err = conn.Write(senddata1)
	if err != nil {
		return
	}
	text, err := readbytes(conn)
	if err != nil {
		return
	}
	if len(text) < 57 {
		return nbname, fmt.Errorf("no names available")
	}
	num, err := bytetoint(text[56:57][0])
	if err != nil {
		return
	}
	data := text[57:]
	msg := ""
	for i := 0; i < num; i++ {
		if len(data) < 18*i+16 {
			break
		}
		name := string(data[18*i : 18*i+15])
		flag_bit := data[18*i+15 : 18*i+16]
		if GROUP_NAMES[string(flag_bit)] != "" && string(flag_bit) != "\x00" {
			msg += fmt.Sprintf("%s G %s\n\t", name, GROUP_NAMES[string(flag_bit)])
		} else if UNIQUE_NAMES[string(flag_bit)] != "" && string(flag_bit) != "\x00" {
			msg += fmt.Sprintf("%s U %s\n\t", name, UNIQUE_NAMES[string(flag_bit)])
		} else if string(flag_bit) == "\x00" || len(data) >= 18*i+18 {
			name_flags := data[18*i+16 : 18*i+18][0]
			if name_flags >= 128 {
				nbname.group = strings.Replace(name, " ", "", -1)
				msg += fmt.Sprintf("%s G %s\n\t", name, GROUP_NAMES[string(flag_bit)])
			} else {
				nbname.unique = strings.Replace(name, " ", "", -1)
				msg += fmt.Sprintf("%s U %s\n\t", name, UNIQUE_NAMES[string(flag_bit)])
			}
		} else {
			msg += fmt.Sprintf("%s \n\t", name)
		}
	}
	nbname.msg += msg
	nbname.msg = strings.TrimSpace(nbname.msg)
	return
}

func bytetoint(text byte) (int, error) {
	num1 := fmt.Sprintf("%v", text)
	num, err := strconv.Atoi(num1)
	return num, err
}

func readbytes(conn net.Conn) (result []byte, err error) {
	buf := make([]byte, 4096)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		result = append(result, buf[0:count]...)
		if count < 4096 {
			break
		}
	}
	return result, err
}

func netbiosEncode(name string) (output []byte) {
	var names []int
	src := fmt.Sprintf("%-16s", name)
	for _, a := range src {
		char_ord := int(a)
		high_4_bits := char_ord >> 4
		low_4_bits := char_ord & 0x0f
		names = append(names, high_4_bits, low_4_bits)
	}
	for _, one := range names {
		out := one + 0x41
		output = append(output, byte(out))
	}
	return
}

func Connectoxid(ip string, port int) (string, int, error, []string) {
	conn, err := GetConn(fmt.Sprintf("%v:%v", ip, port), TimeDuration)
	if err != nil {
		return ip, port, err, nil
	}
	defer conn.Close()
	err, oxidres := oxidIpInfo(conn)
	if err != nil {
		return ip, port, err, nil
	} else {
		return ip, port, nil, oxidres
	}
}

func oxidIpInfo(conn net.Conn) (error, []string) {

	buf := make([]byte, 256)
	_, err := conn.Write(oxidQuery1[:])
	if err != nil {
		return err, nil
	}
	_, err = conn.Read(buf)
	if err != nil {
		return err, nil
	}
	_, err = conn.Write(oxidQuery2[:])
	if err != nil {
		return err, nil
	}
	_, err = conn.Read(buf)
	if err != nil {
		return err, nil
	}
	end := bytes.Index(buf, []byte{0x00, 0x00, 0x09, 0x00, 0xff, 0xff, 0x00, 0x00})
	if len(buf) < 40 || end == -1 {
		return fmt.Errorf(""), nil
	}
	buf = buf[40:end]
	var oxidRes []string
	for i := bytes.Index(buf, []byte{0x00, 0x00, 0x00}); i != -1; {
		res := buf[1:i]
		res = bytes.Replace(res, []byte{0x00}, []byte(""), -1)
		oxidRes = append(oxidRes, string(res))
		buf = buf[i+3:]
		i = bytes.Index(buf, []byte{0x00, 0x00, 0x00})
	}
	return nil, oxidRes
}

func smbinfo(conn net.Conn) (error, []string) {
	buf := make([]byte, 1024)
	_, err := conn.Write(smbQuery[:])
	if err != nil {
		return err, nil
	}
	_, err = conn.Read(buf)
	if err != nil {
		return err, nil
	}
	if len(buf) < 81 {
		return fmt.Errorf(""), nil
	}
	buf = buf[81:]
	end := bytes.Index(buf, []byte{0x00, 0x00, 0x00})
	var smbRes []string
	domain := buf[:end]
	hostname := buf[end:]
	domain = bytes.Replace(domain, []byte{0x00}, []byte(""), -1)
	hostname = bytes.Replace(hostname, []byte{0x00}, []byte(""), -1)
	smbRes = append(smbRes, "domain: "+string(domain))
	smbRes = append(smbRes, "hostname: "+string(hostname))
	return nil, smbRes
}

func Connectsmb(ip string, port int) (string, int, error, []string) {
	conn, err := GetConn(fmt.Sprintf("%v:%v", ip, port), TimeDuration)
	if err != nil {
		return ip, port, err, nil
	}
	defer conn.Close()
	ok, smbRes := smbinfo(conn)
	if ok == nil {
		return ip, port, nil, smbRes
	} else {
		return ip, port, ok, nil
	}
}

func OxidScan(host []string) {
	//result := PortScan(host,[]int{135})
	var wg sync.WaitGroup
	for _, v := range host {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()
			_, _, err, r := Connectoxid(v, 135)
			if err != nil {
				return
			}
			if len(r) >= 2 {
				Println(fmt.Sprintf("[OXID] Hostname %v Network %v", r[0], r[1:]))
			} else {
				Println(fmt.Sprintf("[OXID] %v", r))
			}
		}(v)
	}
	wg.Wait()
}

func SmbScan(host []string) {
	var wg sync.WaitGroup
	for _, v := range host {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()
			ip, _, err, r := Connectsmb(v, 445)
			if err != nil {
				return
			}
			if len(r) >= 2 {
				Println(fmt.Sprintf("[SMB] IP %s %v", ip, r))
			}
		}(v)
	}
	wg.Wait()
}

func NbtScan(host []string) {
	var wg sync.WaitGroup
	for _, v := range host {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()
			_, _, err, r := ConncetNbios(v, 139)
			if err != nil {
				return
			}
			for _, s := range r {
				Println(fmt.Sprintf("[+] %v", v))
				Println(fmt.Sprintf("\t%v", s))
			}

		}(v)
	}
	wg.Wait()
}

func runall(host []string) {
	var wg sync.WaitGroup
	for _, v := range host {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()
			func(v string) {
				_, _, err, r := ConncetNbios(v, 139)
				if err != nil {
					return
				}
				for _, s := range r {
					Println(fmt.Sprintf("[NBTBIOS] %v", v))
					Println(fmt.Sprintf("\t%v", s))
				}
			}(v)
			func(v string) {
				ip, _, err, r := Connectsmb(v, 445)
				if err != nil {
					return
				}
				if len(r) >= 2 {
					Println(fmt.Sprintf("[SMB] IP %s %v", ip, r))
				}
			}(v)
			func(v string) {
				_, _, err, r := Connectoxid(v, 135)
				if err != nil {
					return
				}
				if len(r) >= 2 {
					Println(fmt.Sprintf("[OXID] Hostname %v Network %v", r[0], r[1:]))
				} else {
					Println(fmt.Sprintf("[OXID] %v", r))
				}
			}(v)

		}(v)
	}
	wg.Wait()
}
