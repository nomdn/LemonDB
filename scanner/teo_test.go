package main

import "testing"

func TestParseTEORegion(t *testing.T) {
	for _, s := range []string{"中国 江苏省 南京市 中国移动", "中国 江苏省 宿迁市 中国移动", "中国 北京市 中国移动", "中国 未知 未知 saiyutech.cn"} {
		a := parseTEORegion(s)
		t.Logf("%q → src=%q prov=%q city=%q isp=%q extra=%q", s, a.Src, a.Province, a.City, a.ISP, a.Extra)
	}
}
