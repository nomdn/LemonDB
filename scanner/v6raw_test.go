package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	ip2regionSvc "github.com/lionsoul2014/ip2region/binding/golang/service"
)

// 看 ip2region_v6 的原始 region 字符串布局
func TestV6Raw(t *testing.T) {
	svc, err := ip2regionSvc.NewIp2Region(mustConfig("../dbs/ip2region_v4.xdb", false), mustConfig("../dbs/ip2region_v6.xdb", true))
	if err != nil {
		t.Fatal(err)
	}
	addrs := []string{
		"2400:3200::1", "2408:8000::1", "240e:0:9000::1", "2409:8a00::1",
		"240e:d9c0::1", "2408:8207::1", "2001:250::1", "2409:8900::1",
	}
	for _, a := range addrs {
		r, err := svc.Search(a)
		if err != nil {
			fmt.Printf("%-16s ERR %v\n", a, err)
			continue
		}
		fmt.Printf("%-16s %q\n", a, r)
	}
	// 再从无市段里抽几个
	files, _ := filepath.Glob("seg-v6-*.jsonl")
	n := 0
	for _, f := range files {
		fh, _ := os.Open(f)
		dec := json.NewDecoder(fh)
		for dec.More() && n < 8 {
			var d struct {
				Start   string `json:"start"`
				Primary struct {
					Province string `json:"province"`
					City     string `json:"city"`
				} `json:"primary"`
			}
			if dec.Decode(&d) != nil {
				break
			}
			if d.Primary.City != "" || d.Primary.Province == "" {
				continue
			}
			r, err := svc.Search(d.Start)
			if err != nil {
				continue
			}
			n++
			fmt.Printf("%-40s 库省=%-5s ip2region=%q\n", d.Start, d.Primary.Province, r)
		}
		fh.Close()
		if n >= 8 {
			break
		}
	}
}
