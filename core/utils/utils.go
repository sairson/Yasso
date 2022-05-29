package utils

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func ByteToStringParse(p []byte) string {
	var w []string
	var res string
	for i := 0; i < len(p); i++ {
		if p[i] > 32 && p[i] < 127 {
			w = append(w, string(p[i]))
			continue
		}
		asciiTo16 := fmt.Sprintf("\\x%s", hex.EncodeToString(p[i:i+1]))
		w = append(w, asciiTo16)
	}
	res = strings.Join(w, "")
	if strings.Contains(res, "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00") {
		s := strings.Split(res, "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00")
		return s[0]
	}
	return res
}
