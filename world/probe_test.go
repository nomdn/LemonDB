package main

import (
	"bufio"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	ip2location "github.com/ip2location/ip2location-go/v9"
)

func TestIP2LocVsKnown(t *testing.T) {
	db, _ := ip2location.OpenDB("../dbs/IP2LOCATION-LITE-DB11.IPV6.BIN")
	defer db.Close()
	files, _ := filepath.Glob("../scanner/seg-v6-*.jsonl")
	n := 0
	for _, f := range files {
		fh, _ := os.Open(f)
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<22), 1<<22)
		for sc.Scan() {
			var d struct {
				Start   string `json:"start"`
				Prefix  string `json:"prefix"`
				Primary struct {
					Src      string `json:"src"`
					Province string `json:"province"`
					City     string `json:"city"`
				} `json:"primary"`
			}
			if json.Unmarshal(sc.Bytes(), &d) != nil || d.Primary.City == "" {
				continue
			}
			if n >= 14 {
				break
			}
			n++
			a := netip.MustParseAddr(d.Start)
			r, err := db.Get_all(a.String())
			if err != nil {
				continue
			}
			t.Logf("%-26s 现库=%-6s/%-8s (src=%s)  ip2loc=%-14s/%-12s",
				d.Prefix, d.Primary.Province, d.Primary.City, d.Primary.Src, r.Region, r.City)
		}
		fh.Close()
	}
}
