package main

import (
	"testing"

	"net/netip"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

func TestCityNamesProbe(t *testing.T) {
	mm, err := maxminddb.Open("../dbs/GeoLite2-City.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	db, err := maxminddb.Open("../dbs/dbip-city-lite.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	ips := []string{"2401:3980::", "2400:7100::", "2001:250:3c04::", "223.64.1.1", "2409:8a20:2000::1", "2408:8000:1::1"}
	for _, ip := range ips {
		var rec struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
			Subdivisions []struct {
				ISOCode string            `maxminddb:"iso_code"`
				Names   map[string]string `maxminddb:"names"`
			} `maxminddb:"subdivisions"`
			City struct {
				Names map[string]string `maxminddb:"names"`
			} `maxminddb:"city"`
		}
		_ = mm.Lookup(netip.MustParseAddr(ip)).Decode(&rec)
		var rec2 struct {
			Country struct {
				ISOCode string `maxminddb:"country"`
			} `maxminddb:"country"`
			City struct {
				Names map[string]string `maxminddb:"names"`
			} `maxminddb:"city"`
		}
		_ = db.Lookup(netip.MustParseAddr(ip)).Decode(&rec2)
		t.Logf("%-22s maxmind: %s/%s zh=%q en=%q | dbip: zh=%q en=%q", ip,
			rec.Country.ISOCode, sub(rec.Subdivisions), rec.City.Names["zh-CN"], rec.City.Names["en"],
			rec2.City.Names["zh-CN"], rec2.City.Names["en"])
	}
}

func sub(s []struct {
	ISOCode string            `maxminddb:"iso_code"`
	Names   map[string]string `maxminddb:"names"`
}) string {
	if len(s) == 0 {
		return "-"
	}
	return s[0].ISOCode + "/" + s[0].Names["zh-CN"] + "/" + s[0].Names["en"]
}
