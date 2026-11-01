package main

import "testing"

func TestZXLookup(t *testing.T) {
	s := &scanner{}
	z, err := openZX("../dbs/ipv6wry.db")
	if err != nil {
		t.Fatal(err)
	}
	s.zxDB = z
	cases := []string{
		"2400:3200::1",           // 浙江大学
		"2001:250:2000::1",       // 电子科技大学
		"2409:8900::1",           // 济南大学
		"2409:8a20:c677:9bd0::1", // 移动江苏（库只写中国，应返回空）
		"240e:1:1::1",
	}
	for _, ip := range cases {
		a := s.zx(ip)
		t.Logf("%-26s src=%-3s 省=%-6s 市=%-8s 县=%-6s isp=%-8s extra=%s",
			ip, a.Src, a.Province, a.City, a.County, a.ISP, a.Extra)
	}
}
