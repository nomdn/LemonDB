package main

import (
	"fmt"
	"sort"
	"testing"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

type asnRec struct {
	ASN uint32 `maxminddb:"autonomous_system_number"`
	Org string `maxminddb:"autonomous_system_organization"`
}

type locRec2 struct {
	ISP  string `maxminddb:"isp"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
}

func TestASNStats(t *testing.T) {
	db, err := maxminddb.Open("../CN-ASN.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	v4, v6, noOrg := 0, 0, 0
	asns := map[uint32]string{}
	for res := range db.Networks() {
		var r asnRec
		if res.Decode(&r) != nil {
			continue
		}
		if res.Prefix().Addr().Is4() {
			v4++
		} else {
			v6++
		}
		if r.Org == "" {
			noOrg++
		}
		asns[r.ASN] = r.Org
	}
	fmt.Printf("CN-ASN：v4 前缀 %d，v6 前缀 %d，去重 ASN %d 个，缺组织名 %d\n", v4, v6, len(asns), noOrg)

	type kv struct {
		k uint32
		v string
	}
	var list []kv
	for k, v := range asns {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].k < list[j].k })
	fmt.Println("前 6 个 ASN：")
	for i, e := range list {
		if i >= 6 {
			break
		}
		fmt.Printf("  AS%-8d %s\n", e.k, e.v)
	}
}

func TestISPStats(t *testing.T) {
	db, err := maxminddb.Open("../CN-LOCATION.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	total, hasISP, v4n, v4isp, v6n, v6isp := 0, 0, 0, 0, 0, 0
	for res := range db.Networks() {
		var r locRec2
		if res.Decode(&r) != nil {
			continue
		}
		total++
		is4 := res.Prefix().Addr().Is4()
		if is4 {
			v4n++
		} else {
			v6n++
		}
		if r.ISP != "" {
			hasISP++
			if is4 {
				v4isp++
			} else {
				v6isp++
			}
		}
	}
	fmt.Printf("CN-LOCATION isp 字段：%d/%d (%.1f%%)  v4 %.1f%%  v6 %.1f%%\n",
		hasISP, total, float64(hasISP)*100/float64(total),
		float64(v4isp)*100/float64(v4n), float64(v6isp)*100/float64(v6n))
}
