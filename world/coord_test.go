package main

import "testing"

func TestCoordLookup(t *testing.T) {
	c := loadCoords("../divcoords/division-coords.json")
	if len(c.county) == 0 {
		t.Fatal("坐标表没加载")
	}
	cases := []uint32{
		320102, // 南京玄武区（区县级，直接命中）
		320100, // 南京（市级，质心）
		320000, // 江苏（省级，应落在南京附近）
		330100, // 杭州
		440300, // 深圳
		110000, // 北京
	}
	for _, code := range cases {
		lng, lat, radius, ok := c.lookup(code)
		if !ok {
			t.Errorf("%d 没查到", code)
			continue
		}
		t.Logf("%d → %.4f,%.4f radius=%d", code, lng, lat, radius)
	}
}
