package main

// 宽段拆分：把「有县但宽于 /24」的段按区县变化点切开。
//
// 为什么需要：扫描按 /24 采样后会把相邻同签名的格合并成大段，区县只剩一个
// 代表值。实测 8 个 /16–/19 段，段内普遍有 2–6 个不同区县（哈尔滨那个 /19
// 里同时有南岗/双城/松北/通河/香坊），给单一县对段内多数地址都是错的。
//
// 做法：逐 /24 查 GeoCN（本地库，逐地址、无网络成本），把连续同结果的 /24
// 并成一个区间插入 —— 等价于「按县变化点切分」，而不是机械切成 256 个 /24。

import (
	"net/netip"
	"strings"

	"github.com/maxmind/mmdbwriter/mmdbtype"
	maxminddb "github.com/oschwald/maxminddb-golang/v2"

	"lemondb/norm"
)


// sameCityName 市名宽松比较：自治州常见「大理白族自治州」vs「大理市」这种前缀关系
func sameCityName(a, b string) bool {
	if a == "" || b == "" {
		return true // 缺一方不算冲突
	}
	if a == b {
		return true
	}
	return strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
}

type piece struct {
	start, end netip.Addr
	rec        mmdbtype.Map
}

// v4u 把 IPv4 地址转成 uint32，方便按 /24 做整数运算
func v4u(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u32addr(x uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)})
}

// geocnAt 查一个地址的 GeoCN 归属；返回的 code 是 GB/T 2260 码
func geocnAt(db *maxminddb.Reader, divName map[uint32]string, ip netip.Addr) (prov, city, county string, code uint32) {
	if db == nil {
		return
	}
	var rec struct {
		DivisionCode uint32 `maxminddb:"division_code"`
	}
	if err := db.Lookup(ip).Decode(&rec); err != nil || rec.DivisionCode == 0 {
		return
	}
	code = rec.DivisionCode
	prov = norm.NormProvince(divName[code/10000*10000])
	city = divName[code/100*100]
	county = divName[code]
	// 省级缺名说明这条 GeoCN 记录不可用
	if prov == "" {
		return "", "", "", 0
	}
	// 直辖市的「市」会被回落成省名，那不是市；同理县名回落到省名也要清掉
	if city != "" && norm.NormProvince(city) == prov {
		city = ""
	}
	if county != "" && norm.NormProvince(county) == prov {
		county = ""
	}
	// 县名等于市名等于没给县
	if county != "" && county == city {
		county = ""
	}
	return
}

// splitByCounty 对宽于 /24 且有县的段，按 /24 逐格查 GeoCN 重算区县，
// 连续同结果的并成一个区间。返回 false 表示这个段不需要拆。
func splitByCounty(d segRec, isp, typ string, geo *maxminddb.Reader, divName map[uint32]string) ([]piece, bool) {
	if geo == nil || d.Primary.County == "" {
		return nil, false
	}
	s, err1 := netip.ParseAddr(d.Start)
	e, err2 := netip.ParseAddr(d.End)
	if err1 != nil || err2 != nil || !s.Is4() || !e.Is4() {
		return nil, false
	}
	lo, hi := v4u(s), v4u(e)
	if hi/256 == lo/256 { // 只覆盖一个 /24，原值就是逐 /24 的采样结果，不用拆
		return nil, false
	}

	var out []piece
	var curStart uint32
	var curRec mmdbtype.Map
	var curKey string
	flush := func(endU uint32) {
		if curRec == nil {
			return
		}
		out = append(out, piece{u32addr(curStart), u32addr(endU), curRec})
	}
	for x := lo / 256; x <= hi/256; x++ {
		segStart := x * 256
		segEnd := segStart + 255
		if segStart < lo {
			segStart = lo
		}
		if segEnd > hi {
			segEnd = hi
		}
		// 取 /24 中点查（.128），跟扫描阶段采样位置一致
		pv, ct, cy, code := geocnAt(geo, divName, u32addr(x*256+128))
		if pv == "" {
			// GeoCN 没这条：退回主源的省/市，县不要（宽段的县不可信）
			pv, ct, cy, code = d.Primary.Province, d.Primary.City, "", 0
		} else {
			// 市不能丢：GeoCN 只到省时 ct 为空，沿用段的市（段的市是逐 /24
			// 采样+投票来的，比 GeoCN 的省级记录可靠）。之前直接覆盖，
			// 把 v4 有市从 98.8% 拉低到 87.9%。
			if ct == "" {
				ct = d.Primary.City
			}
			// 省/市与段不一致时，县不要：GeoCN 的区县必须是「这个市下的区县」，
			// 否则会把 A 市的区县安到 B 市头上
			if pv != d.Primary.Province || !sameCityName(ct, d.Primary.City) {
				cy, code = "", 0
			}
			if cy == "" {
				code = 0 // 让 buildSegRec 按市级重算，别留一个县级码却没有县名
			}
		}
		key := pv + "|" + ct + "|" + cy
		rec := buildSegRec(pv, ct, cy, code, isp, typ)
		if curRec != nil && key == curKey {
			continue // 与上一格同结果，并进当前区间
		}
		flush(segStart - 1)
		curStart, curRec, curKey = segStart, rec, key
	}
	flush(hi)
	return out, true
}

// buildSegRec 拼一条扫描段记录（与 main 里内联构建的那份保持一致）
func buildSegRec(prov, city, county string, code uint32, isp, typ string) mmdbtype.Map {
	sub, _ := provFields(prov)
	rec := mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String("CN"),
			"names":    mmdbtype.Map{"zh-CN": mmdbtype.String("中国"), "en": mmdbtype.String("China")},
		},
		"isp":          mmdbtype.String(isp),
		"type":         mmdbtype.String(typ),
		"subdivisions": mmdbtype.Slice{sub},
	}
	if city != "" {
		rec["city"] = mmdbtype.Map{"names": mmdbtype.Map{"zh-CN": mmdbtype.String(city)}}
	}
	if county != "" {
		rec["district"] = mmdbtype.Map{"names": mmdbtype.Map{"zh-CN": mmdbtype.String(county)}}
	}
	if code == 0 {
		code = adcodeOf(prov, city, county)
	}
	if code != 0 {
		rec["division_code"] = mmdbtype.Uint32(code)
	}
	return rec
}
