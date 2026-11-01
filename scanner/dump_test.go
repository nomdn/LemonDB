package main

import (
	"encoding/json"
	"net/netip"
	"testing"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

// 打印现有 CN-LOCATION.mmdb 的记录结构，确认 merge 时要写入的字段口径
func TestDumpLocationSchema(t *testing.T) {
	for _, p := range []string{"../CN-LOCATION.test.mmdb"} {
		r, err := maxminddb.Open(p)
		if err != nil {
			t.Logf("%s: %v", p, err)
			continue
		}
		for _, ip := range []string{"202.112.0.5", "223.68.218.79", "114.114.114.114", "2409:8a20:c677:9bd0::1"} {
			var v any
			if err := r.Lookup(netip.MustParseAddr(ip)).Decode(&v); err != nil {
				t.Logf("%s %s: %v", p, ip, err)
				continue
			}
			b, _ := json.Marshal(v)
			t.Logf("%s %s → %s", p, ip, b)
		}
		r.Close()
	}
}
