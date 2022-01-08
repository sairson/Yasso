package cmd

import (
	"Yasso/config"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"golang.org/x/net/proxy"
	"golang.org/x/text/encoding/simplifiedchinese"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

//TODO: dismap RespLab

type RespLab struct {
	Url            string
	RespBody       string
	RespHeader     string
	RespStatusCode string
	RespTitle      string
	FaviconMd5     string
}

func FaviconMd5(Url string, timeout time.Duration, Path string) string {
	var dial proxy.Dialer
	var client *http.Client
	if ProxyHost != "" {
		dial, _ = ConnBySOCKS5()
		client = &http.Client{
			Timeout: time.Duration(timeout),
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				Dial:            dial.Dial,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	} else {
		client = &http.Client{
			Timeout: time.Duration(timeout),
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	Url = Url + "/favicon.ico"
	req, err := http.NewRequest("GET", Url, nil)
	if err != nil {
		return ""
	}
	for key, value := range config.DefaultHeader {
		req.Header.Set(key, value)
	}
	//req.Header.Set("Accept-Language", "zh,zh-TW;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6")
	//req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
	//req.Header.Set("Cookie", "rememberMe=int")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body_bytes, err := ioutil.ReadAll(resp.Body)
	hash := md5.Sum(body_bytes)
	md5 := fmt.Sprintf("%x", hash)
	return md5
}

func DefaultRequests(Url string, timeout time.Duration) []RespLab {

	var redirect_url string
	var resp_title string
	var response_header string
	var response_body string
	var response_status_code string
	var res []string

	// 设置http请求客户端
	var dial proxy.Dialer
	var client *http.Client
	if ProxyHost != "" {
		dial, _ = ConnBySOCKS5()
		client = &http.Client{
			Timeout: time.Duration(timeout),
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				Dial:            dial.Dial,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	} else {
		client = &http.Client{
			Timeout: time.Duration(timeout),
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	req, err := http.NewRequest("GET", Url, nil)
	if err != nil {
		return nil
	}
	// 设置默认请求头
	for key, value := range config.DefaultHeader {
		req.Header.Set(key, value)
	}
	// 做http请求
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// 获取请求的状态马
	var status_code = resp.StatusCode
	response_status_code = strconv.Itoa(status_code)

	//TODO: 根据请求来拦截状态码，如果是30x则需要拦截url进行重定向

	if len(regexp.MustCompile("30").FindAllStringIndex(response_status_code, -1)) == 1 {
		// 进行重定向
		redirect_path := resp.Header.Get("Location") // 拦截url进行重定向请求
		if len(regexp.MustCompile("http").FindAllStringIndex(redirect_path, -1)) == 1 {
			redirect_url = redirect_path
		} else {
			redirect_url = Url + redirect_path
		}
		var client *http.Client
		if ProxyHost != "" {
			client = &http.Client{
				Timeout: time.Duration(timeout),
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					Dial:            dial.Dial,
				},
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
		} else {
			client = &http.Client{
				Timeout: time.Duration(timeout),
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
		}

		// 设置重定向请求
		req, err := http.NewRequest("GET", redirect_url, nil)
		if err != nil {
			return nil
		}
		for key, value := range config.DefaultHeader {
			req.Header.Set(key, value)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()

		//TODO: 解决两次的30x跳转问题
		var twoStatusCode = resp.StatusCode
		responseStatusCodeTwo := strconv.Itoa(twoStatusCode)
		if len(regexp.MustCompile("30").FindAllStringIndex(responseStatusCodeTwo, -1)) == 1 {
			redirectPath := resp.Header.Get("Location")
			if len(regexp.MustCompile("http").FindAllStringIndex(redirectPath, -1)) == 1 {
				redirect_url = redirectPath
			} else {
				redirect_url = Url + redirectPath
			}
			var client *http.Client
			if ProxyHost != "" {
				client = &http.Client{
					Timeout: time.Duration(timeout),
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
						Dial:            dial.Dial,
					},
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}
			} else {
				client = &http.Client{
					Timeout: time.Duration(timeout),
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					},
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}
			}

			req, err := http.NewRequest("GET", redirect_url, nil)
			if err != nil {
				return nil
			}
			for key, value := range config.DefaultHeader {
				req.Header.Set(key, value)
			}
			resp, err := client.Do(req)
			if err != nil {
				return nil
			}
			defer resp.Body.Close()
			// get response body for string
			bodyBytes, err := ioutil.ReadAll(resp.Body)
			response_body = string(bodyBytes)
			// Solve the problem of garbled body codes with unmatched numbers
			if !utf8.Valid(bodyBytes) {
				data, _ := simplifiedchinese.GBK.NewDecoder().Bytes(bodyBytes)
				response_body = string(data)
			}
			// Get Response title
			grepTitle := regexp.MustCompile("<title>(.*)</title>")
			if len(grepTitle.FindStringSubmatch(response_body)) != 0 {
				resp_title = grepTitle.FindStringSubmatch(response_body)[1]
			} else {
				resp_title = "None"
			}
			for name, values := range resp.Header {
				for _, value := range values {
					res = append(res, fmt.Sprintf("%s: %s", name, value))
				}
			}
			for _, re := range res {
				response_header += re + "\n"
			}
			favicon5 := FaviconMd5(Url, timeout, "")
			RespData := []RespLab{
				{redirect_url, response_body, response_header, response_status_code, resp_title, favicon5},
			}
			return RespData
		}
		// get response body for string
		body_bytes, err := ioutil.ReadAll(resp.Body)
		response_body = string(body_bytes)
		// Solve the problem of garbled body codes with unmatched numbers
		if !utf8.Valid(body_bytes) {
			data, _ := simplifiedchinese.GBK.NewDecoder().Bytes(body_bytes)
			response_body = string(data)
		}
		// Get Response title
		grep_title := regexp.MustCompile("<title>(.*)</title>")
		if len(grep_title.FindStringSubmatch(response_body)) != 0 {
			resp_title = grep_title.FindStringSubmatch(response_body)[1]
		} else {
			resp_title = "None"
		}
		// get response header for string
		for name, values := range resp.Header {
			for _, value := range values {
				res = append(res, fmt.Sprintf("%s: %s", name, value))
			}
		}
		for _, re := range res {
			response_header += re + "\n"
		}
		favicon5 := FaviconMd5(Url, timeout, "")
		RespData := []RespLab{
			{redirect_url, response_body, response_header, response_status_code, resp_title, favicon5},
		}
		return RespData
	}
	// get response body for string
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	response_body = string(bodyBytes)
	// Solve the problem of garbled body codes with unmatched numbers
	if !utf8.Valid(bodyBytes) {
		data, _ := simplifiedchinese.GBK.NewDecoder().Bytes(bodyBytes)
		response_body = string(data)
	}

	// Get Response title
	grep_title := regexp.MustCompile("<title>(.*)</title>")
	if len(grep_title.FindStringSubmatch(response_body)) != 0 {
		resp_title = grep_title.FindStringSubmatch(response_body)[1]
	} else {
		resp_title = "None"
	}
	// get response header for string
	for name, values := range resp.Header {
		for _, value := range values {
			res = append(res, fmt.Sprintf("%s: %s", name, value))
		}
	}
	for _, re := range res {
		response_header += re + "\n"
	}
	faviconmd5 := FaviconMd5(Url, timeout, "")
	RespData := []RespLab{
		{Url, response_body, response_header, response_status_code, resp_title, faviconmd5},
	}
	return RespData
}

func CustomRequests(Url string, timeout time.Duration, Method string, Path string, Header []string, Body string) []RespLab {
	var respTitle string
	// Splicing Custom Path
	u, err := url.Parse(Url)
	u.Path = path.Join(u.Path, Path)
	Url = u.String()
	if strings.HasSuffix(Path, "/") {
		Url = Url + "/"
	}

	var client *http.Client
	var dial proxy.Dialer
	if ProxyHost != "" {
		dial, _ = ConnBySOCKS5()
		client = &http.Client{
			Timeout: time.Duration(timeout),
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				Dial:            dial.Dial,
			},
		}
	} else {
		client = &http.Client{
			Timeout: time.Duration(timeout),
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}

	// Send Http requests

	body_byte := bytes.NewBuffer([]byte(Body))
	req, err := http.NewRequest(Method, Url, body_byte)
	if err != nil {
		return nil
	}

	// Set Requests Headers
	for _, header := range Header {
		grep_key := regexp.MustCompile("(.*): ")
		var header_key = grep_key.FindStringSubmatch(header)[1]
		grep_value := regexp.MustCompile(": (.*)")
		var header_value = grep_value.FindStringSubmatch(header)[1]
		req.Header.Set(header_key, header_value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	// Get Response Body for string
	body_bytes, err := ioutil.ReadAll(resp.Body)
	var response_body = string(body_bytes)
	// Solve the problem of garbled body codes with unmatched numbers
	if !utf8.Valid(body_bytes) {
		data, _ := simplifiedchinese.GBK.NewDecoder().Bytes(body_bytes)
		response_body = string(data)
	}
	// Get Response title
	grep_title := regexp.MustCompile("<title>(.*)</title>")
	if len(grep_title.FindStringSubmatch(response_body)) != 0 {
		respTitle = grep_title.FindStringSubmatch(response_body)[1]
	} else {
		respTitle = "None"
	}
	// Get Response Header for string
	var res []string
	for name, values := range resp.Header {
		for _, value := range values {
			res = append(res, fmt.Sprintf("%s: %s", name, value))
		}
	}
	var response_header string
	for _, re := range res {
		response_header += re + "\n"
	}
	// get response status code
	var status_code = resp.StatusCode
	response_status_code := strconv.Itoa(status_code)
	RespData := []RespLab{
		{Url, response_body, response_header, response_status_code, respTitle, ""},
	}
	return RespData
}

//dismap 解析IP

func ParseUrl(host string, port string) string {
	if port == "80" {
		return "http://" + host
	} else if port == "443" {
		return "https://" + host
	} else if len(regexp.MustCompile("443").FindAllStringIndex(port, -1)) == 1 {
		return "https://" + host + ":" + port
	} else {
		return "http://" + host + ":" + port
	}
}
