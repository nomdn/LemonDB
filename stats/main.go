// stats 统计 mmdb 的 CIDR 长度分布与市区县覆盖。
package main

import (
	"flag"
	"fmt"
	"sort"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

type rec struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	District struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"district"`
}

func main() {
	path := flag.String("mmdb", "CN-LOCATION.mmdb", "库")
	flag.Parse()
	db, err := maxminddb.Open(*path)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	type cov struct{ total, prov, city, dist int }
	vc := map[bool]*cov{true: {}, false: {}}
	lenDist := map[bool]map[int]int{true: {}, false: {}}

	for res := range db.Networks() {
		p := res.Prefix()
		is4 := p.Addr().Is4()
		c := vc[is4]
		c.total++
		lenDist[is4][p.Bits()]++
		var r rec
		if res.Decode(&r) != nil {
			continue
		}
		if len(r.Subdivisions) > 0 && r.Subdivisions[0].Names["zh-CN"] != "" {
			c.prov++
		}
		if r.City.Names["zh-CN"] != "" {
			c.city++
		}
		if r.District.Names["zh-CN"] != "" {
			c.dist++
		}
	}

	for _, is4 := range []bool{true, false} {
		c := vc[is4]
		name := "v6"
		if is4 {
			name = "v4"
		}
		if c.total == 0 {
			continue
		}
		fmt.Printf("%s 前缀 %d: 有省 %.1f%%  有市 %.1f%%  有县 %.1f%%\n", name, c.total,
			float64(c.prov)*100/float64(c.total),
			float64(c.city)*100/float64(c.total),
			float64(c.dist)*100/float64(c.total))
		if os4 := lenDist[is4]; os4 != nil {
			ks := make([]int, 0, len(os4))
			for k := range os4 {
				ks = append(ks, k)
			}
			sort.Ints(ks)
			fmt.Print("   长度分布: ")
			for _, k := range ks {
				if os4[k]*1000/c.total < 5 && k > 20 {
					continue
				}
				fmt.Printf("/%d=%d ", k, os4[k])
			}
			fmt.Println()
		}
	}
}
