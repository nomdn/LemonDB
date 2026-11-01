package main

import (
	"fmt"
	"sort"
	"testing"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

func TestNoCity(t *testing.T) {
	db, err := maxminddb.Open("../CN-LOCATION.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	byProv := map[string]int{}
	muni := map[string]bool{"北京": true, "上海": true, "天津": true, "重庆": true}
	total, noCity, muniNoCity, noProv := 0, 0, 0, 0
	for res := range db.Networks() {
		var r rec
		if res.Decode(&r) != nil {
			continue
		}
		p := ""
		if len(r.Subdivisions) > 0 {
			p = r.Subdivisions[0].Names["zh-CN"]
		}
		total++
		if r.City.Names["zh-CN"] != "" {
			continue
		}
		noCity++
		if p == "" {
			noProv++
		}
		if muni[p] {
			muniNoCity++
		}
		byProv[p]++
	}
	type kv struct{ k string; v int }
	var list []kv
	for k, v := range byProv {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
	fmt.Printf("前缀 %d，无市 %d (%.1f%%)：直辖市无市 %d，无省 %d\n", total, noCity, float64(noCity)*100/float64(total), muniNoCity, noProv)
	for i, e := range list {
		if i >= 10 {
			break
		}
		k := e.k
		if k == "" {
			k = "(无省)"
		}
		fmt.Printf("  %-8s %6d\n", k, e.v)
	}
}
