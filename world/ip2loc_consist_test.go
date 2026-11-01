package main

import (
	"bufio"
	"encoding/json"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	ip2location "github.com/ip2location/ip2location-go/v9"
)

// 段内多点采样，看 IP2Loc 给的市是否一致 —— 一致的段才能整段补市
func TestIP2LocConsistency(t *testing.T) {
	db, err := ip2location.OpenDB("../dbs/IP2LOCATION-LITE-DB11.IPV6.BIN")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	files, _ := filepath.Glob("../scanner/seg-v6-*.jsonl")
	var noCity []struct {
		start, end, pre, prov string
	}
	for _, f := range files {
		fh, _ := os.Open(f)
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<22), 1<<22)
		for sc.Scan() {
			var d struct {
				Start, End, Prefix string
				Primary            struct {
					Province string `json:"province"`
					City     string `json:"city"`
				} `json:"primary"`
			}
			if json.Unmarshal(sc.Bytes(), &d) != nil || d.Start == "" || d.Primary.City != "" {
				continue
			}
			noCity = append(noCity, struct{ start, end, pre, prov string }{d.Start, d.End, d.Prefix, d.Primary.Province})
		}
		fh.Close()
	}
	t.Logf("无市 v6 段总数 %d", len(noCity))

	K := 4
	same, diff, none := 0, 0, 0
	limit := 200
	for i := 0; i < len(noCity) && i < limit; i++ {
		s := noCity[i]
		a := netip.MustParseAddr(s.start)
		b := netip.MustParseAddr(s.end)
		ai := new(big.Int).SetBytes(a.AsSlice())
		bi := new(big.Int).SetBytes(b.AsSlice())
		span := new(big.Int).Sub(bi, ai)
		cities := map[string]int{}
		for k := 0; k < K; k++ {
			step := new(big.Int).Mul(span, big.NewInt(int64(k)))
			step.Div(step, big.NewInt(int64(K)))
			cur := new(big.Int).Add(ai, step)
			buf := make([]byte, 16)
			cur.FillBytes(buf)
			addr, ok := netip.AddrFromSlice(buf)
			if !ok {
				continue
			}
			r, err := db.Get_all(addr.String())
			if err != nil || r.City == "" || r.City == "-" {
				continue
			}
			cities[r.City]++
		}
		switch len(cities) {
		case 0:
			none++
		case 1:
			same++
		default:
			diff++
		}
	}
	n := same + diff + none
	t.Logf("抽 %d 段 x %d 点: 段内同市 %d (%.1f%%), 多市 %d (%.1f%%), 无市 %d (%.1f%%)",
		n, K, same, float64(same)*100/float64(n), diff, float64(diff)*100/float64(n), none, float64(none)*100/float64(n))
}
