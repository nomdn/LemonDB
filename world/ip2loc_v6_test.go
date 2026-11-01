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

func TestIP2LocOnV6NoCity(t *testing.T) {
	db, err := ip2location.OpenDB("../dbs/IP2LOCATION-LITE-DB11.IPV6.BIN")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	files, _ := filepath.Glob("../scanner/seg-v6-*.jsonl")
	n, hit, city, conflict := 0, 0, 0, 0
	type sample struct {
		pre, oldProv, newProv, newCity string
	}
	var samples []sample
	for _, f := range files {
		if filepath.Base(f) == "seg-v6-topup.jsonl" {
			continue
		}
		fh, _ := os.Open(f)
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<22), 1<<22)
		for sc.Scan() {
			var d struct {
				Prefix  string `json:"prefix"`
				Start   string `json:"start"`
				Primary struct {
					Province string `json:"province"`
					City     string `json:"city"`
				} `json:"primary"`
			}
			if json.Unmarshal(sc.Bytes(), &d) != nil || d.Start == "" || d.Primary.City != "" {
				continue
			}
			n++
			if n > 300 {
				break
			}
			a, err := netip.ParseAddr(d.Start)
			if err != nil {
				continue
			}
			r, err := db.Get_all(a.String())
			if err != nil || r.City == "" || r.City == "-" {
				continue
			}
			hit++
			if r.Country_short != "CN" {
				continue
			}
			city++
			if d.Primary.Province != "" && r.Region != "" && r.Region != d.Primary.Province {
				conflict++
			}
			if len(samples) < 10 {
				samples = append(samples, sample{d.Prefix, d.Primary.Province, r.Region, r.City})
			}
		}
		fh.Close()
	}
	t.Logf("抽 %d 个无市 v6 段: IP2Loc 给市 %d (%.1f%%), 其中中国 %d", n, hit, float64(hit)*100/float64(n), city)
	t.Logf("省与原段不一致: %d", conflict)
	for _, s := range samples {
		t.Logf("  %-24s 原省=%-6s ip2loc=%-16s %s", s.pre, s.oldProv, s.newProv, s.newCity)
	}
}
