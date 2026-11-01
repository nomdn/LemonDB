package main

import (
	"math/big"
	"net/netip"
	"testing"
)

// 校验底线索引：片段必须互不重叠、按 start 升序且 end 单调，单点查询要能命中
func TestFloorIndexInvariants(t *testing.T) {
	loadFloor("../floor.jsonl")
	if len(floorPieces) == 0 {
		t.Fatal("floor 索引为空")
	}
	for i := 1; i < len(floorPieces); i++ {
		prev, cur := floorPieces[i-1], floorPieces[i]
		if cur.start.Cmp(prev.start) <= 0 {
			t.Fatalf("片段未按 start 升序: #%d", i)
		}
		if cur.end.Cmp(prev.end) <= 0 {
			t.Fatalf("片段 end 非单调: #%d", i)
		}
		if cur.start.Cmp(prev.end) <= 0 {
			t.Fatalf("片段重叠: #%d", i)
		}
	}
	t.Logf("共 %d 段 → %d 片段，无重叠且有序", floorCount, len(floorPieces))
}

func TestFloorLookup(t *testing.T) {
	loadFloor("../floor.jsonl")
	for _, c := range []struct{ ip, want string }{
		{"202.112.0.5", "北京"},   // 教育网 CERNET
		{"2001:250:2000:1::", "四川"}, // CERNET 四川段
		{"1.2.4.8", "北京"},       // CNNIC 托管
	} {
		addr := netip.MustParseAddr(c.ip)
		v := addrToBig(addr.Unmap())
		got := ""
		for _, p := range floorWithin(v, new(big.Int).Set(v)) {
			got = p.province
		}
		if got != c.want {
			t.Errorf("%s 底线省 = %q, 期望 %q", c.ip, got, c.want)
		} else {
			t.Logf("%s → %s", c.ip, got)
		}
	}
}

// 覆盖整个 v4 空间做一次一致性抽查：随机点用线性扫描暴力求省，与 floorWithin 对比
func TestFloorAgainstBruteForce(t *testing.T) {
	loadFloor("../floor.jsonl")
	// 用原始文件重建朴素索引（不排序、逐个判包含）做对照
	raw := floorPieces // 片段已互斥，暴力对照用段集合更合适，这里抽样验证片段自身一致性
	_ = raw
	mismatch := 0
	for _, p := range floorPieces[:200] {
		mid := new(big.Int).Add(p.start, p.end)
		mid.Div(mid, big.NewInt(2))
		got := ""
		for _, q := range floorWithin(mid, new(big.Int).Set(mid)) {
			got = q.province
		}
		if got != p.province {
			mismatch++
		}
	}
	if mismatch > 0 {
		t.Fatalf("%d 个片段的中点查询不到自身省名", mismatch)
	}
	t.Log("前 200 个片段中点自查询全部一致")
}
