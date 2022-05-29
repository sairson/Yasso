package webscan

import (
	"Yasso/config"
	"Yasso/core/logger"
	"fmt"
	"regexp"
	"runtime"
	"strconv"
	"time"
)

type IdentifyResult struct {
	Type     string
	RespCode string
	Result   string
	ResultNc string
	Url      string
	Title    string
}

func DisMapConn(host string, port int, timeout time.Duration) bool {
	url := ParseUrl(host, strconv.Itoa(port))
	for _, r := range Identify(url, timeout) {
		if r.RespCode != "" {
			logger.Success(fmt.Sprintf("%v %v %v [%v]", r.Url, r.RespCode, r.Result, r.Title))
		}
	}
	return true
}

func Identify(url string, timeout time.Duration) []IdentifyResult {
	var DefaultFavicon string
	var CustomFavicon string
	var DefaultTarget string
	var CustomTarget string
	var Favicon string
	var RequestRule string
	var RespTitle string
	var RespBody string
	var RespHeader string
	var RespCode string
	var DefaultRespTitle string
	var DefaultRespBody string
	var DefaultRespHeader string
	var DefaultRespCode string
	var CustomRespTitle string
	var CustomRespBody string
	var CustomRespHeader string
	var CustomRespCode string
	for _, resp := range DefaultRequests(url, timeout) { // Default Request
		DefaultRespBody = resp.RespBody
		DefaultRespHeader = resp.RespHeader
		DefaultRespCode = resp.RespStatusCode
		DefaultRespTitle = resp.RespTitle
		DefaultTarget = resp.Url
		DefaultFavicon = resp.FaviconMd5
	}
	// start identify
	var identifyData []string
	var successType string
	for _, rule := range config.RuleData {
		if rule.Http.ReqMethod != "" { // Custom Request Result
			for _, resp := range CustomRequests(url, timeout, rule.Http.ReqMethod, rule.Http.ReqPath, rule.Http.ReqHeader, rule.Http.ReqBody) {
				CustomRespBody = resp.RespBody
				CustomRespHeader = resp.RespHeader
				CustomRespCode = resp.RespStatusCode
				CustomRespTitle = resp.RespTitle
				CustomTarget = resp.Url
				CustomFavicon = resp.FaviconMd5
			}
			url = CustomTarget
			Favicon = CustomFavicon
			RespBody = CustomRespBody
			RespHeader = CustomRespHeader
			RespCode = CustomRespCode
			RespTitle = CustomRespTitle
			// If the http request fails, then RespBody and RespHeader are both null
			// At this time, it is considered that the url does not exist
			if RespBody == RespHeader {
				continue
			}
			if rule.Mode == "" {
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "CustomRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
			}
			if rule.Mode == "or" {
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
			}
			if rule.Mode == "and" {
				index := 0
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						index = index + 1
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						index = index + 1
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						index = index + 1
					}
				}
				if index == 2 {
					identifyData = append(identifyData, rule.Name)
					RequestRule = "CustomRequest"
				}
			}
			if rule.Mode == "and|and" {
				index := 0
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						index = index + 1
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						index = index + 1
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						index = index + 1
					}
				}
				if index == 3 {
					identifyData = append(identifyData, rule.Name)
					RequestRule = "CustomRequest"
				}
			}
			if rule.Mode == "or|or" {
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
			}
			if rule.Mode == "and|or" {
				grep := regexp.MustCompile("(.*)\\|(.*)\\|(.*)")
				all_type := grep.FindStringSubmatch(rule.Type)
				//
				//Println(all_type)
				if len(regexp.MustCompile("header").FindAllStringIndex(all_type[1], -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(all_type[1], -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(all_type[1], -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
			}
			if rule.Mode == "or|and" {
				grep := regexp.MustCompile("(.*)\\|(.*)\\|(.*)")
				all_type := grep.FindStringSubmatch(rule.Type)
				//Println(all_type)
				if len(regexp.MustCompile("header").FindAllStringIndex(all_type[3], -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(all_type[3], -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(all_type[3], -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
			}
		} else { // Default Request Result
			url = DefaultTarget
			Favicon = DefaultFavicon
			RespBody = DefaultRespBody
			RespHeader = DefaultRespHeader
			RespCode = DefaultRespCode
			RespTitle = DefaultRespTitle
			// If the http request fails, then RespBody and RespHeader are both null
			// At this time, it is considered that the url does not exist
			if RespBody == RespHeader {
				continue
			}
			if rule.Mode == "" {
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
			}
			if rule.Mode == "or" {
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
			}
			if rule.Mode == "and" {
				index := 0
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						index = index + 1
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						index = index + 1
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						index = index + 1
					}
				}
				if index == 2 {
					identifyData = append(identifyData, rule.Name)
					RequestRule = "DefaultRequest"
				}
			}
			if rule.Mode == "and|and" {
				index := 0
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						index = index + 1
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						index = index + 1
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						index = index + 1
					}
				}
				if index == 3 {
					identifyData = append(identifyData, rule.Name)
					RequestRule = "DefaultRequest"
				}
			}
			if rule.Mode == "or|or" {
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
			}
			if rule.Mode == "and|or" {
				grep := regexp.MustCompile("(.*)\\|(.*)\\|(.*)")
				allType := grep.FindStringSubmatch(rule.Type)
				//Println(all_type)
				if len(regexp.MustCompile("header").FindAllStringIndex(allType[1], -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(allType[1], -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(allType[1], -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
			}
			if rule.Mode == "or|and" {
				grep := regexp.MustCompile("(.*)\\|(.*)\\|(.*)")
				all_type := grep.FindStringSubmatch(rule.Type)
				//Println(all_type)
				if len(regexp.MustCompile("header").FindAllStringIndex(all_type[3], -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(all_type[3], -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(all_type[3], -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
			}
		}
	}
	// identify
	if RequestRule == "DefaultRequest" {
		RespBody = DefaultRespBody
		RespHeader = DefaultRespHeader
		RespCode = DefaultRespCode
		RespTitle = DefaultRespTitle
		url = DefaultTarget
	} else if RequestRule == "CustomRequest" {
		url = CustomTarget
		RespBody = CustomRespBody
		RespHeader = CustomRespHeader
		RespCode = CustomRespCode
		RespTitle = CustomRespTitle
	}
	var identifyResult string
	var identifyResultNocolor string
	for _, result := range identifyData {
		if runtime.GOOS == "windows" {
			identifyResult += "[" + result + "]" + " "
		} else {
			identifyResult += "[" + result + "]" + " "
		}
	}
	for _, result := range identifyData {
		identifyResultNocolor += "[" + result + "]" + " "
	}

	Result := []IdentifyResult{
		{successType, RespCode, identifyResult, identifyResultNocolor, url, RespTitle},
	}
	return Result
}

func checkHeader(url, responseHeader string, ruleHeader string, name string, title string, RespCode string) bool {
	grep := regexp.MustCompile("(?i)" + ruleHeader)
	if len(grep.FindStringSubmatch(responseHeader)) != 0 {
		//fmt.Print("[header] ")
		return true
	} else {
		return false
	}
}

func checkBody(url, responseBody string, ruleBody string, name string, title string, RespCode string) bool {
	grep := regexp.MustCompile("(?i)" + ruleBody)
	if len(grep.FindStringSubmatch(responseBody)) != 0 {
		//fmt.Print("[body] ")
		return true
	} else {
		return false
	}
}

func checkFavicon(Favicon, ruleFaviconMd5 string) bool {
	grep := regexp.MustCompile("(?i)" + ruleFaviconMd5)
	if len(grep.FindStringSubmatch(Favicon)) != 0 {
		// fmt.Print("url")
		return true
	} else {
		return false
	}
}
