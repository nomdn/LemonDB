// world 世界定位库：GeoLite2 / dbip 打底，CN 精确层覆盖。
//
// 分层顺序（后插覆盖先插）：
//   dbip-city-lite  →  GeoLite2-City  →  CN-LOCATION
//
// 这样非中国大陆由 maxmind/dbip 填充，中国大陆用多源扫描结果，
// 输出字段统一（country/subdivisions/city/district/location/isp/type）。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	ip2location "github.com/ip2location/ip2location-go/v9"
	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

// maxmind / dbip 的通用记录结构
type baseRec struct {
	Continent struct {
		Code  string            `maxminddb:"code"`
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"continent"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	// Cloudflare 这类 anycast 只有注册国、没有定位国，用它兜底
	RegisteredCountry struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"registered_country"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
		TimeZone  string  `maxminddb:"time_zone"`
	} `maxminddb:"location"`
}

// CN-LOCATION.mmdb 的记录结构（与 merge 写入的字段一致）
type cnRec struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	District struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"district"`
	ISP          string `maxminddb:"isp"`
	Type         string `maxminddb:"type"`
	DivisionCode uint32 `maxminddb:"division_code"`
}

// mmdbwriter 只吃 *net.IPNet：v4 用 4 字节、v6 用 16 字节，位数不能混
func toIPNet(p netip.Prefix) *net.IPNet {
	a := p.Addr()
	if a.Is4() {
		b := a.As4()
		return &net.IPNet{IP: net.IP(b[:]), Mask: net.CIDRMask(p.Bits(), 32)}
	}
	b := a.As16()
	return &net.IPNet{IP: net.IP(b[:]), Mask: net.CIDRMask(p.Bits(), 128)}
}

func nameOf(m map[string]string, lang string) string {
	if m == nil {
		return ""
	}
	return m[lang]
}

// 把一条底层记录转成统一 schema；没有国家信息的直接跳过
func baseToMMDB(r baseRec) (mmdbtype.Map, bool) {
	iso, names := r.Country.ISOCode, r.Country.Names
	if iso == "" {
		iso, names = r.RegisteredCountry.ISOCode, r.RegisteredCountry.Names
	}
	if iso == "" {
		return nil, false
	}
	rec := mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String(iso),
			"names": mmdbtype.Map{
				"zh-CN": mmdbtype.String(nameOf(names, "zh-CN")),
				"en":    mmdbtype.String(nameOf(names, "en")),
			},
		},
	}
	if r.Continent.Code != "" {
		rec["continent"] = mmdbtype.Map{
			"code": mmdbtype.String(r.Continent.Code),
			"names": mmdbtype.Map{
				"zh-CN": mmdbtype.String(nameOf(r.Continent.Names, "zh-CN")),
				"en":    mmdbtype.String(nameOf(r.Continent.Names, "en")),
			},
		}
	}
	if len(r.Subdivisions) > 0 {
		var subs mmdbtype.Slice
		for _, s := range r.Subdivisions {
			sub := mmdbtype.Map{
				"names": mmdbtype.Map{
					"zh-CN": mmdbtype.String(nameOf(s.Names, "zh-CN")),
					"en":    mmdbtype.String(nameOf(s.Names, "en")),
				},
			}
			if s.ISOCode != "" {
				sub["iso_code"] = mmdbtype.String(s.ISOCode)
			}
			subs = append(subs, sub)
		}
		rec["subdivisions"] = subs
	}
	if c := nameOf(r.City.Names, "zh-CN"); c != "" || nameOf(r.City.Names, "en") != "" {
		rec["city"] = mmdbtype.Map{
			"names": mmdbtype.Map{
				"zh-CN": mmdbtype.String(c),
				"en":    mmdbtype.String(nameOf(r.City.Names, "en")),
			},
		}
	}
	if r.Location.Latitude != 0 || r.Location.Longitude != 0 {
		rec["location"] = mmdbtype.Map{
			"latitude":        mmdbtype.Float64(r.Location.Latitude),
			"longitude":       mmdbtype.Float64(r.Location.Longitude),
			"coord_system":    mmdbtype.String("wgs84"),
			"accuracy_radius": mmdbtype.Uint32(1000),
		}
	}
	return rec, true
}

// ---------- 行政区划坐标表（division-coords） ----------

type coordTable struct {
	county map[uint32][2]float64 // 六位区县，直接取政府驻地
	city   map[uint32][2]float64 // XXYY00，下辖区县质心
	prov   map[uint32][2]float64 // XX0000，优先省会 XX0100 的质心
}

func loadCoords(path string) *coordTable {
	t := &coordTable{
		county: map[uint32][2]float64{},
		city:   map[uint32][2]float64{},
		prov:   map[uint32][2]float64{},
	}
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("坐标表缺失（%v）：CN 段不带经纬度\n", err)
		return t
	}
	var raw map[string][2]float64
	if err := json.Unmarshal(b, &raw); err != nil {
		fmt.Printf("坐标表解析失败（%v）：CN 段不带经纬度\n", err)
		return t
	}

	type acc struct {
		n        int
		lng, lat float64
	}
	// 市 → adcode 最小的区县。GB/T 2260 里一个地级市最小编号基本就是主城区，
	// 市政府驻地就在那一带；取质心会飘到郊区甚至山区去，差几十公里。
	minCounty := map[uint32]uint32{}
	provAcc := map[uint32]*acc{}
	for k, v := range raw {
		code, err := strconv.ParseUint(k, 10, 32)
		if err != nil || v[0] == 0 && v[1] == 0 {
			continue
		}
		c := uint32(code)
		t.county[c] = v
		cc, pc := c/100*100, c/10000*10000
		if cur, ok := minCounty[cc]; !ok || c < cur {
			minCounty[cc] = c
		}
		if provAcc[pc] == nil {
			provAcc[pc] = &acc{}
		}
		provAcc[pc].n++
		provAcc[pc].lng += v[0]
		provAcc[pc].lat += v[1]
	}
	for cc, minCode := range minCounty {
		t.city[cc] = t.county[minCode]
	}
	// 省会固定是 XX01，直接借它的市级坐标；缺省会（直辖市）时退回全省质心。
	for k, a := range provAcc {
		if v, ok := t.city[k+100]; ok {
			t.prov[k] = v
		} else {
			t.prov[k] = [2]float64{a.lng / float64(a.n), a.lat / float64(a.n)}
		}
	}
	fmt.Printf("坐标表: 区县 %d 市 %d 省 %d\n", len(t.county), len(t.city), len(t.prov))
	return t
}

// 区县精确 → 市级质心 → 省级（省会）三级回退，radius 标明可信半径
func (t *coordTable) lookup(code uint32) (lng, lat float64, radius uint32, ok bool) {
	if code == 0 {
		return 0, 0, 0, false
	}
	if v, ok := t.county[code]; ok {
		return v[0], v[1], 5000, true
	}
	if v, ok := t.city[code/100*100]; ok {
		return v[0], v[1], 15000, true
	}
	if v, ok := t.prov[code/10000*10000]; ok {
		return v[0], v[1], 100000, true
	}
	return 0, 0, 0, false
}

// ---------- IP2Location 增强 ----------

// BIN 库没法直接遍历，就拿 GeoLite2 的网络当骨架、逐条补 IP2Loc 的坐标和城市。
// IP2Loc 的城市级覆盖比 GeoLite2 细得多（8.8.8.8 它能给到 Mountain View）。
type ip2locDB struct {
	db *ip2location.DB
}

func openIP2Loc(path string) *ip2locDB {
	if path == "" {
		return nil
	}
	db, err := ip2location.OpenDB(path)
	if err != nil {
		fmt.Printf("跳过 ip2location: %v\n", err)
		return nil
	}
	return &ip2locDB{db: db}
}

func (e *ip2locDB) close() { e.db.Close() }

func dash(s string) string {
	if s == "-" || s == "" {
		return ""
	}
	return s
}

// 按需补齐/覆盖：坐标以 IP2Loc 为准，名字只补空缺（GeoLite2 带中文名，优先保留）
func (e *ip2locDB) enhance(rec mmdbtype.Map, addr netip.Addr) {
	r, err := e.db.Get_all(addr.String())
	if err != nil {
		return
	}
	if rec["country"] == nil && dash(r.Country_short) != "" {
		rec["country"] = mmdbtype.Map{
			"iso_code": mmdbtype.String(r.Country_short),
			"names": mmdbtype.Map{
				"zh-CN": mmdbtype.String(dash(r.Country_long)),
				"en":    mmdbtype.String(dash(r.Country_long)),
			},
		}
	}
	if r.Latitude != 0 || r.Longitude != 0 {
		rec["location"] = mmdbtype.Map{
			"latitude":        mmdbtype.Float64(r.Latitude),
			"longitude":       mmdbtype.Float64(r.Longitude),
			"coord_system":    mmdbtype.String("wgs84"),
			"accuracy_radius": mmdbtype.Uint32(5000),
		}
	}
	if rec["city"] == nil && dash(r.City) != "" {
		rec["city"] = mmdbtype.Map{
			"names": mmdbtype.Map{"zh-CN": mmdbtype.String(r.City), "en": mmdbtype.String(r.City)},
		}
	}
	if rec["subdivisions"] == nil && dash(r.Region) != "" {
		rec["subdivisions"] = mmdbtype.Slice{
			mmdbtype.Map{
				"names": mmdbtype.Map{"zh-CN": mmdbtype.String(r.Region), "en": mmdbtype.String(r.Region)},
			},
		}
	}
}

func main() {
	cnPath := flag.String("cn", "CN-LOCATION.mmdb", "CN 精确层")
	out := flag.String("out", "LEMON-LOCATION.mmdb", "输出全球库")
	maxmindPath := flag.String("maxmind", "dbs/GeoLite2-City.mmdb", "GeoLite2-City")
	dbipPath := flag.String("dbip", "", "dbip-city-lite（可选，插在 maxmind 之下）")
	ip2locPath := flag.String("ip2loc", "dbs/IP2LOCATION-LITE-DB11.IPV6.BIN", "IP2Location DB11，用来补坐标")
	coordsPath := flag.String("coords", "divcoords/division-coords.json", "行政区划代码 → 经纬度（GCJ-02）")
	withCN := flag.Bool("with-cn", true, "是否用 CN 层覆盖中国大陆")
	flag.Parse()

	coords := loadCoords(*coordsPath)
	ip2loc := openIP2Loc(*ip2locPath)
	if ip2loc != nil {
		defer ip2loc.close()
	}

	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:        "world-ip-location",
		Languages:           []string{"zh-CN", "en"},
		IPVersion:           6,
		DisableIPv4Aliasing: true,
	})
	if err != nil {
		panic(err)
	}

	insertFail := 0
	insert := func(p netip.Prefix, rec mmdbtype.Map) {
		if err := tree.Insert(toIPNet(p), rec); err != nil {
			insertFail++
		}
	}

	// 底层库：先 dbip 再 maxmind，后者覆盖前者
	type layer struct {
		path string
		name string
	}
	var layers []layer
	if *dbipPath != "" {
		layers = append(layers, layer{*dbipPath, "dbip"})
	}
	if *maxmindPath != "" {
		layers = append(layers, layer{*maxmindPath, "maxmind"})
	}

	for _, l := range layers {
		db, err := maxminddb.Open(l.path)
		if err != nil {
			fmt.Printf("跳过 %s: %v\n", l.name, err)
			continue
		}
		defer db.Close()
		t0 := time.Now()
		n, skip := 0, 0
		for res := range db.Networks() {
			var r baseRec
			if err := res.Decode(&r); err != nil {
				skip++
				continue
			}
			rec, ok := baseToMMDB(r)
			if !ok && ip2loc == nil {
				skip++
				continue
			}
			if ip2loc != nil {
				if !ok {
					rec = mmdbtype.Map{}
				}
				ip2loc.enhance(rec, res.Prefix().Addr())
				if len(rec) == 0 {
					skip++
					continue
				}
			}
			insert(res.Prefix(), rec)
			n++
			if n%500000 == 0 {
				fmt.Printf("  %s: %d 条\n", l.name, n)
			}
		}
		fmt.Printf("%s 入库: %d 条（跳过 %d）耗时 %s\n", l.name, n, skip, time.Since(t0).Round(time.Second))
	}

	// CN 精确层覆盖
	if *withCN {
		cn, err := maxminddb.Open(*cnPath)
		if err != nil {
			fmt.Printf("跳过 CN 层: %v\n", err)
		} else {
			defer cn.Close()
			t0 := time.Now()
			n := 0
			for res := range cn.Networks() {
				var r cnRec
				if err := res.Decode(&r); err != nil {
					continue
				}
				if r.Country.ISOCode != "CN" {
					continue
				}
				rec := mmdbtype.Map{
					"country": mmdbtype.Map{
						"iso_code": mmdbtype.String("CN"),
						"names": mmdbtype.Map{
							"zh-CN": mmdbtype.String("中国"),
							"en":    mmdbtype.String("China"),
						},
					},
					"continent": mmdbtype.Map{
						"code": mmdbtype.String("AS"),
						"names": mmdbtype.Map{
							"zh-CN": mmdbtype.String("亚洲"),
							"en":    mmdbtype.String("Asia"),
						},
					},
				}
				if len(r.Subdivisions) > 0 {
					var subs mmdbtype.Slice
					for _, s := range r.Subdivisions {
						sub := mmdbtype.Map{
							"names": mmdbtype.Map{
								"zh-CN": mmdbtype.String(nameOf(s.Names, "zh-CN")),
								"en":    mmdbtype.String(nameOf(s.Names, "zh-CN")), // 国内没有英文名，英文视图沿用中文
							},
						}
						if s.ISOCode != "" {
							sub["iso_code"] = mmdbtype.String(s.ISOCode)
						}
						subs = append(subs, sub)
					}
					rec["subdivisions"] = subs
				}
				cityName := nameOf(r.City.Names, "zh-CN")
				if cityName != "" {
					rec["city"] = mmdbtype.Map{
						"names": mmdbtype.Map{"zh-CN": mmdbtype.String(cityName), "en": mmdbtype.String(cityName)},
					}
				}
				// 360 只给县时会被县→市回填补成同名，与市重复的县不写
				if d := nameOf(r.District.Names, "zh-CN"); d != "" && d != cityName {
					rec["district"] = mmdbtype.Map{
						"names": mmdbtype.Map{"zh-CN": mmdbtype.String(d), "en": mmdbtype.String(d)},
					}
				}
				if r.ISP != "" {
					rec["isp"] = mmdbtype.String(r.ISP)
				}
				if r.Type != "" {
					rec["type"] = mmdbtype.String(r.Type)
				}
				if r.DivisionCode != 0 {
					rec["division_code"] = mmdbtype.Uint32(r.DivisionCode)
				}
				// 境内坐标不取 GeoLite2（中国只有国家级默认点，会和省打架），
				// 用区划代码查政府驻地：区县精确、市/省按质心回退。
				if lng, lat, radius, ok := coords.lookup(r.DivisionCode); ok {
					rec["location"] = mmdbtype.Map{
						"latitude":        mmdbtype.Float64(lat),
						"longitude":       mmdbtype.Float64(lng),
						"accuracy_radius": mmdbtype.Uint32(radius),
						"coord_system":    mmdbtype.String("gcj02"),
					}
				}
				insert(res.Prefix(), rec)
				n++
			}
			fmt.Printf("CN 层覆盖: %d 段 耗时 %s\n", n, time.Since(t0).Round(time.Second))
		}
	}

	fout, err := os.Create(*out)
	if err != nil {
		panic(err)
	}
	if _, err := tree.WriteTo(fout); err != nil {
		panic(err)
	}
	fout.Close()
	st, _ := os.Stat(*out)
	fmt.Printf("%s 完成: %.2f MB（插入失败 %d）\n", *out, float64(st.Size())/1048576, insertFail)
}
