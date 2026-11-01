package main

// 清洗公告段表：把「非中国大陆」的段剔除。
// 判据：用 GeoLite2-City 在段内取 5 个采样点，若没有一个返回 CN 就整段剔除；
// 部分 CN 的段保留（后面扫描时会按格细分，非 CN 的格自然拿不到数据）。

import (
	"bufio"
	"flag"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"strings"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

func main() {
	in := flag.String("in", "", "输入段表")
	out := flag.String("out", "", "输出段表")
	mmdb := flag.String("mmdb", "../dbs/GeoLite2-City.mmdb", "用于判国家的库")
	flag.Parse()

	db, err := maxminddb.Open(*mmdb)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	isCN := func(a netip.Addr) bool {
		var rec struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if err := db.Lookup(a).Decode(&rec); err != nil {
			return false
		}
		return rec.Country.ISOCode == "CN"
	}

	f, err := os.Open(*in)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w, err := os.Create(*out)
	if err != nil {
		panic(err)
	}
	defer w.Close()
	bw := bufio.NewWriter(w)
	defer bw.Flush()

	kept, dropped := 0, 0
	var dropList []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			continue
		}
		width := 16
		if p.Addr().Is4() {
			width = 4
		}
		base := new(big.Int).SetBytes(addrBytes(p.Addr()))
		size := new(big.Int).Lsh(big.NewInt(1), uint(width*8-p.Bits()))
		hit := false
		for i := int64(0); i < 5 && !hit; i++ {
			off := new(big.Int).Mul(size, big.NewInt(i))
			off.Div(off, big.NewInt(5))
			v := new(big.Int).Add(base, off)
			if a, ok := bigToAddr(v, width); ok {
				if isCN(a) {
					hit = true
				}
			}
		}
		if hit {
			fmt.Fprintln(bw, line)
			kept++
		} else {
			dropped++
			if len(dropList) < 30 {
				dropList = append(dropList, line)
			}
		}
	}
	fmt.Printf("%s: 保留 %d，剔除 %d（非中国大陆）\n", *in, kept, dropped)
	for _, d := range dropList {
		fmt.Println("  剔除:", d)
	}
}

func addrBytes(a netip.Addr) []byte {
	if a.Is4() {
		b := a.As4()
		return b[:]
	}
	b := a.As16()
	return b[:]
}

func bigToAddr(v *big.Int, width int) (netip.Addr, bool) {
	b := v.Bytes()
	if len(b) > width {
		return netip.Addr{}, false
	}
	buf := make([]byte, width)
	copy(buf[width-len(b):], b)
	return netip.AddrFromSlice(buf)
}
