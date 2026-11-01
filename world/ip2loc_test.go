package main

import (
	"fmt"
	"net/netip"
	"testing"

	ip2location "github.com/ip2location/ip2location-go/v9"
)

func TestIP2LocSmoke(t *testing.T) {
	db, err := ip2location.OpenDB("../dbs/IP2LOCATION-LITE-DB11.IPV6.BIN")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, ip := range []string{"8.8.8.8", "210.140.0.1", "114.114.114.114", "2400:3200::1", "1.1.1.1"} {
		r, err := db.Get_all(ip)
		if err != nil {
			t.Logf("%-18s err %v", ip, err)
			continue
		}
		t.Logf("%-18s %s %s %s %.4f %.4f", ip, r.Country_short, r.Region, r.City, r.Latitude, r.Longitude)
	}
}

func BenchmarkIP2LocGetAll(b *testing.B) {
	db, err := ip2location.OpenDB("../dbs/IP2LOCATION-LITE-DB11.IPV6.BIN")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	base := netip.MustParseAddr("8.8.8.0")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a := base
		a = a.Next()
		_ = fmt.Sprint(a)
		db.Get_all("8.8.8.8")
	}
}
