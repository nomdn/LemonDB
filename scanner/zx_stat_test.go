package main

import (
	"strings"
	"testing"
)

func TestZXCoverage(t *testing.T) {
	z, err := openZX("../dbs/ipv6wry.db")
	if err != nil {
		t.Fatal(err)
	}
	total := z.count
	cn, hasCity, hasUnit, onlyProv := 0, 0, 0, 0
	for i := 0; i < z.count; i++ {
		f := z.readRecord(z.indexOff(i))
		if len(f) == 0 {
			continue
		}
		parts := strings.Split(f[0], "\t")
		if parts[0] != "中国" {
			continue
		}
		cn++
		if len(parts) >= 3 && parts[2] != "" {
			hasCity++
		} else {
			onlyProv++
		}
		if len(f) >= 2 && strings.TrimSpace(f[1]) != "" {
			hasUnit++
		}
	}
	t.Logf("总记录 %d, 中国记录 %d", total, cn)
	t.Logf("有市 %d (%.1f%%), 只有省 %d (%.1f%%)", hasCity, float64(hasCity)*100/float64(cn), onlyProv, float64(onlyProv)*100/float64(cn))
	t.Logf("带归属单位 %d (%.1f%%)", hasUnit, float64(hasUnit)*100/float64(cn))
}
