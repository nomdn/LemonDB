package main

import (
	"testing"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
	ip2regionSvc "github.com/lionsoul2014/ip2region/binding/golang/service"
)

// 用已知的境外 v6 地址检验本地库会不会瞎兜底成「北京」
func TestLocalDBsOnForeignV6(t *testing.T) {
	s := &scanner{}
	var err error
	s.ip2r, err = ip2regionSvc.NewIp2Region(mustConfig("../dbs/ip2region_v4.xdb", false), mustConfig("../dbs/ip2region_v6.xdb", true))
	if err != nil {
		t.Fatalf("ip2region: %v", err)
	}
	if s.geocnDB, err = maxminddb.Open("../dbs/GeoCN.mmdb"); err != nil {
		t.Fatalf("geocn: %v", err)
	}
	s.division = loadDivision("../dbs/full.txt")

	foreign := []string{
		"2606:4700::1111",   // Cloudflare US
		"2001:4860:4860::8888", // Google DNS
		"2a00:1450:4001::1", // Google EU
		"2001:db8::1",       // 文档保留段
		"2400:cb00::1",      // Cloudflare APAC
		"2a03:2880::1",      // Facebook
	}
	for _, ip := range foreign {
		a1 := s.ip2region(ip)
		a2 := s.geocn(ip)
		t.Logf("%-24s ip2region=[%s %s %s] geocn=[%s %s %s]", ip, a1.Province, a1.City, a1.ISP, a2.Province, a2.City, a2.County)
	}
}

// 再抽一批「省=北京」的国内 v6 段，看多少是 ip2region 独断
func TestBeijingSourceBreakdown(t *testing.T) {
	s := &scanner{}
	var err error
	s.ip2r, _ = ip2regionSvc.NewIp2Region(mustConfig("../dbs/ip2region_v4.xdb", false), mustConfig("../dbs/ip2region_v6.xdb", true))
	if s.geocnDB, err = maxminddb.Open("../dbs/GeoCN.mmdb"); err != nil {
		t.Fatalf("geocn: %v", err)
	}
	s.division = loadDivision("../dbs/full.txt")
	_ = err

	cases := []string{
		"2400:a5a0:1234::1",
		"2403:f8c0:1234::1",
		"2401:7bc0:1234::1",
		"2402:2e60:1234::1",
		"2405:b880:1234::1",
		"2409:8a20:c677:1234::1",
	}
	for _, ip := range cases {
		a1 := s.ip2region(ip)
		a2 := s.geocn(ip)
		t.Logf("%-26s ip2region=[%s/%s] geocn=[%s/%s]", ip, a1.Province, a1.City, a2.Province, a2.City)
	}
}
