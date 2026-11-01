package main

import (
	"bufio"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"lemondb/norm"
)

func TestZXProbe(t *testing.T) {
	z, err := openZX("../dbs/ipv6wry.db")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob("../scanner/seg-v6-*.jsonl")
	total, noCity, zxProv, zxCity, provMatch := 0, 0, 0, 0, 0
	for _, f := range files {
		fh, _ := os.Open(f)
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<22), 1<<22)
		for sc.Scan() {
			var d struct {
				Start   string `json:"start"`
				Primary struct {
					Province string `json:"province"`
					City     string `json:"city"`
				} `json:"primary"`
			}
			if json.Unmarshal(sc.Bytes(), &d) != nil || d.Start == "" {
				continue
			}
			total++
			if d.Primary.City != "" {
				continue
			}
			noCity++
			addr, err := netip.ParseAddr(d.Start)
			if err != nil {
				continue
			}
			pv, ct, _, ok := z.lookup(addr)
			if !ok {
				continue
			}
			zxProv++
			if ct != "" {
				zxCity++
			}
			if norm.NormProvince(pv) == d.Primary.Province {
				provMatch++
			}
		}
		fh.Close()
	}
	t.Logf("v6 段 %d, 无市 %d (%.1f%%)", total, noCity, float64(noCity)*100/float64(total))
	t.Logf("无市段里 ZX 有省 %d (%.1f%% of 无市), 有市 %d (%.1f%% of 无市)",
		zxProv, float64(zxProv)*100/float64(noCity), zxCity, float64(zxCity)*100/float64(noCity))
	t.Logf("其中省一致 %d (%.1f%% of ZX 命中)", provMatch, float64(provMatch)*100/float64(zxProv))
}
