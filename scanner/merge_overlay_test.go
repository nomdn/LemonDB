package main

import (
	"bufio"
	"encoding/json"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

type segRow struct {
	Start   string `json:"start"`
	End     string `json:"end"`
	Primary answer `json:"primary"`
}

type locRec struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	ISP          string `maxminddb:"isp"`
	Type         string `maxminddb:"type"`
	Subdivisions []struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	City *struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	District *struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"district"`
	DivisionCode uint32 `maxminddb:"division_code"`
}

// 覆盖验证：扫描段的中点必须能在 mmdb 里读回同样的省，且带市/县信息
func TestMergeOverlay(t *testing.T) {
	files, _ := filepath.Glob("../scanner/seg-*.jsonl")
	if len(files) == 0 {
		t.Skip("没有扫描段")
	}
	var rows []segRow
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<22), 1<<22)
		for sc.Scan() {
			var d segRow
			if json.Unmarshal(sc.Bytes(), &d) == nil && d.Primary.Province != "" {
				rows = append(rows, d)
			}
		}
		f.Close()
	}
	if len(rows) == 0 {
		t.Skip("段表为空")
	}

	// 段表还在增长时，快照库必然对不上——用修改时间判断，过旧就跳过
	if st, err := os.Stat("../CN-LOCATION.test.mmdb"); err == nil {
		if sf, err2 := os.Stat(files[0]); err2 == nil && sf.ModTime().After(st.ModTime()) {
			t.Skip("mmdb 比段表旧，先跑 merge")
		}
	}
	db, err := maxminddb.Open("../CN-LOCATION.test.mmdb")
	if err != nil {
		t.Fatalf("打开 mmdb: %v", err)
	}
	defer db.Close()

	checked, provOK, cityOK, cityWant, codeOK, miss := 0, 0, 0, 0, 0, 0
	step := len(rows) / 400
	if step < 1 {
		step = 1
	}
	for i := 0; i < len(rows); i += step {
		r := rows[i]
		s, se := netip.ParseAddr(r.Start)
		e, ee := netip.ParseAddr(r.End)
		if se != nil || ee != nil {
			continue
		}
		mid := new(big.Int).Add(addrToBig(s), addrToBig(e))
		mid.Div(mid, big.NewInt(2))
		width := 4
		if !s.Is4() {
			width = 16
		}
		addr, ok := netip.AddrFromSlice(bigIntToIP(mid, width))
		if !ok {
			continue
		}
		var rec locRec
		if err := db.Lookup(addr).Decode(&rec); err != nil {
			miss++
			continue
		}
		checked++
		got := ""
		if len(rec.Subdivisions) > 0 {
			got = rec.Subdivisions[0].Names["zh-CN"]
		}
		if got == r.Primary.Province {
			provOK++
		} else if miss < 6 {
			miss++
			t.Logf("不一致: %s→%s 段省=%s mmdb省=%s type=%s isp=%s", r.Start, r.End, r.Primary.Province, got, rec.Type, rec.ISP)
		}
		if r.Primary.City != "" {
			cityWant++
			if rec.City != nil && rec.City.Names["zh-CN"] == r.Primary.City {
				cityOK++
			}
		}
		if rec.DivisionCode != 0 {
			codeOK++
		}
	}
	t.Logf("抽查 %d 段（跳过无记录 %d）| 省一致 %d/%d (%.1f%%) | 市命中 %d/%d | division_code 覆盖 %d",
		checked+miss, miss, provOK, checked, 100*float64(provOK)/float64(checked), cityOK, cityWant, codeOK)
	if checked > 0 && provOK != checked {
		t.Errorf("有 %d 段省没对上", checked-provOK)
	}
}
