package main

import (
	"fmt"
	"sort"
	"testing"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

func TestISPDist(t *testing.T) {
	db, _ := maxminddb.Open("../CN-LOCATION.mmdb")
	defer db.Close()
	cnt := map[string]int{}
	for res := range db.Networks() {
		var r struct {
			ISP string `maxminddb:"isp"`
		}
		if res.Decode(&r) != nil {
			continue
		}
		cnt[r.ISP]++
	}
	type kv struct {
		k string
		v int
	}
	var list []kv
	for k, v := range cnt {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
	for i, e := range list {
		if i >= 10 {
			break
		}
		k := e.k
		if k == "" {
			k = "(空)"
		}
		fmt.Printf("  %-10s %6d\n", k, e.v)
	}
}
