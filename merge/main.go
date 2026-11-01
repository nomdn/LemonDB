// merge —— 把扫描段表覆盖到 WHOIS 底线上，重建 CN-LOCATION.mmdb
//
// 输入：
//   - floor.jsonl    WHOIS 底线（省/运营商/类型，来自根构建器的 -floor-out）
//   - seg-*.jsonl    扫描器产出（市/县，scanner 分片输出）
//
// 覆盖规则（来自交接文档）：
//   - 扫描段 > WHOIS 底线
//   - 同段信息量：县 > 市 > 省
//   - 主源省为空的段不入库
//
// 插入顺序决定优先级：先大后小，小块最后落，自然覆盖大块。
// 记录结构与根构建器一致（country/isp/type/subdivisions），
// 市/县额外写 city / district，并在能对上行政区划时写 division_code，
// 与项目里 GeoCN 的读取方式（division_code → resolveDivision）保持一致。
package main

import (
	"bufio"
	"encoding/json"
	"net/netip"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	. "lemondb/norm"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

var provISO = map[string]string{}
var provEN = map[string]string{}

// division：行政区划名 → 代码（full.txt 提供 code\tname）
var division = map[string]uint32{}

type floorRec struct {
	Start    string `json:"start"`
	End      string `json:"end"`
	Province string `json:"province"`
	ISP      string `json:"isp"`
	Type     string `json:"type"`
}

type segRec struct {
	Start   string `json:"start"`
	End     string `json:"end"`
	Prefix  string `json:"prefix"`
	Primary struct {
		Src      string `json:"src"`
		Province string `json:"province"`
		City     string `json:"city"`
		County   string `json:"county"`
		ISP      string `json:"isp"`
		Adcode   int    `json:"adcode"`
	} `json:"primary"`
	// 陪跑源的答案：主源只到市时，用 geocn 的县补上（省/市一致才补）
	Sources map[string]struct {
		Province string `json:"province"`
		City     string `json:"city"`
		County   string `json:"county"`
	} `json:"sources"`
}

// 县 → 所在市（省名做键，避免「朝阳区」这类跨省同名）
var countyCity = map[string]string{}

// 直辖市「省即市」：源通常只给「北京」不给「北京市」，
// 下游按 city 取值就拿到空，这里直接补上市名。
var municipalities = map[string]bool{"北京": true, "上海": true, "天津": true, "重庆": true}

func cityOfMunicipality(prov string) string {
	p := strings.TrimSuffix(strings.TrimSpace(prov), "市")
	if municipalities[p] {
		return p + "市"
	}
	return ""
}

// rangeToCIDRs 区间 → CIDR（与根构建器同算法）
func rangeToCIDRs(startIP, endIP net.IP) []*net.IPNet {
	if startIP == nil || endIP == nil {
		return nil
	}
	if startIP.To4() != nil && endIP.To4() != nil {
		startIP, endIP = startIP.To4(), endIP.To4()
	} else {
		startIP, endIP = startIP.To16(), endIP.To16()
	}
	bits := len(startIP) * 8
	lo := new(big.Int).SetBytes(startIP)
	hi := new(big.Int).SetBytes(endIP)
	if hi.Cmp(lo) < 0 {
		return nil
	}
	one := big.NewInt(1)
	var out []*net.IPNet
	for lo.Cmp(hi) <= 0 {
		low := 0
		for low < bits && lo.Bit(low) == 0 {
			low++
		}
		size := new(big.Int).Sub(hi, lo)
		size.Add(size, one)
		if exp := size.BitLen() - 1; exp < low {
			low = exp
		}
		block := new(big.Int).Lsh(one, uint(low))
		prefixLen := bits - low
		b := lo.Bytes()
		ip := make(net.IP, bits/8)
		copy(ip[bits/8-len(b):], b)
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(prefixLen, bits)})
		lo.Add(lo, block)
	}
	return out
}

func loadDivision(path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Println("division:", err)
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "\t", 2)
		if len(parts) != 2 {
			continue
		}
		var code uint32
		fmt.Sscanf(parts[0], "%d", &code)
		if code == 0 {
			continue
		}
		name := strings.TrimSpace(parts[1])
		if _, dup := division[name]; !dup {
			division[name] = code
		}
		allCodes[name] = append(allCodes[name], code)
		if code%100 != 0 {
			kc := code / 100 * 100
			if cityDist[kc] == nil {
				cityDist[kc] = map[string]bool{}
			}
			cityDist[kc][name] = true
		}
	}
	// 建「省|县 → 市」反查，给只有县没有市的段补齐市级
	byCode := make(map[uint32]string, len(division))
	for n, c := range division {
		byCode[c] = n
	}
	for n, c := range division {
		if c%100 == 0 {
			continue // 省/市级本身跳过，只收区县
		}
		city, ok1 := byCode[c/100*100]
		prov, ok2 := byCode[c/10000*10000]
		if ok1 && ok2 {
			countyCity[prov+"|"+n] = city
		}
	}
}

// 市代码 → 下辖区县名；名称 → 全部代码（同名区县如「南山区」在鹤岗也在深圳，
// division 只留首个，查代码时会张冠李戴，所以另存一份全量的）
var cityDist = map[uint32]map[string]bool{}
var allCodes = map[string][]uint32{}

// countyInCity 判县名是否属于该市；市本身没有下级数据时放行，不误杀
func countyInCity(cityCode uint32, county string) bool {
	set := cityDist[cityCode]
	if len(set) == 0 {
		return true
	}
	if set[county] {
		return true
	}
	for _, suf := range []string{"市", "区", "县", "旗", "盟", "州"} {
		if set[strings.TrimSuffix(county, suf)] || set[county+suf] {
			return true
		}
	}
	return false
}

// adcodeOf 按「县 > 市 > 省」顺序尝试对出行政区划代码
// lookupDiv 名称 → 单个代码（名称缺失后后缀时补一次）
func lookupDiv(name string) uint32 {
	if name == "" {
		return 0
	}
	if c, ok := division[name]; ok {
		return c
	}
	for _, suf := range []string{"市", "省", "区", "县", "盟", "自治州", "旗"} {
		if c, ok := division[name+suf]; ok {
			return c
		}
	}
	return 0
}

// divCodes 名称 → 全部同名代码（区县重名很常见）
func divCodes(name string) []uint32 {
	if name == "" {
		return nil
	}
	if cs := allCodes[name]; len(cs) > 0 {
		return cs
	}
	for _, suf := range []string{"市", "省", "区", "县", "盟", "自治州", "旗"} {
		if cs := allCodes[name+suf]; len(cs) > 0 {
			return cs
		}
	}
	return nil
}

func adcodeOf(province, city, county string) uint32 {
	cityCode := lookupDiv(city)
	if county != "" {
		codes := divCodes(county)
		if cityCode != 0 {
			// 同名区县（南山区在鹤岗也在深圳）必须按父市挑，否则会把深圳的段
			// 标成鹤岗的代码，下游查坐标直接跨省
			kc := cityCode / 100 * 100
			for _, c := range codes {
				if c/100*100 == kc {
					return c
				}
			}
		}
		if len(codes) > 0 {
			return codes[0]
		}
	}
	if cityCode != 0 {
		return cityCode
	}
	for _, n := range []string{county, city} {
		if n == "" {
			continue
		}
		if c, ok := division[n]; ok {
			return c
		}
		// 补「市/省/区/县」后缀再试一次
		for _, suf := range []string{"市", "省", "区", "县", "盟", "自治州"} {
			if c, ok := division[n+suf]; ok {
				return c
			}
		}
	}
	// 省级：'内蒙古' → '内蒙古自治区'、'广西' → '广西壮族自治区' 这类只能靠前缀匹配
	if province != "" {
		for name, code := range division {
			if code%10000 == 0 && strings.HasPrefix(name, province) {
				return code
			}
		}
	}
	return 0
}

func provFields(province string) (mmdbtype.Map, string) {
	sub := mmdbtype.Map{"names": mmdbtype.Map{"zh-CN": mmdbtype.String(province)}}
	iso := ""
	if v, ok := provISO[province]; ok {
		iso = v
		sub["iso_code"] = mmdbtype.String(v)
	}
	if v, ok := provEN[province]; ok {
		sub["names"].(mmdbtype.Map)["en"] = mmdbtype.String(v)
	}
	return sub, iso
}

// ---------- 底线索引（用于给扫描段回填 ISP / type） ----------
//
// 扫描段的 ISP 覆盖率只有 8%，直接覆盖会把底线里的运营商/类型（教育网、IDC…）
// 冲成空串。所以把底线也归并成互斥片段，扫描段缺字段时按地址回填。

type fPiece struct {
	s, e     *big.Int
	prov     string
	isp      string
	typ      string
}

var fPieces []fPiece

func buildFloorIndex(recs []floorRec) {
	type ev struct {
		p   *big.Int
		add bool
		idx int
	}
	raw := make([]floorRec, len(recs))
	copy(raw, recs)
	sort.Slice(raw, func(i, j int) bool {
		si, sj := ipToBig(raw[i].Start), ipToBig(raw[j].Start)
		if c := si.Cmp(sj); c != 0 {
			return c < 0
		}
		return ipToBig(raw[i].End).Cmp(ipToBig(raw[j].End)) > 0
	})
	one := big.NewInt(1)
	evs := make([]ev, 0, len(raw)*2)
	for i := range raw {
		evs = append(evs, ev{ipToBig(raw[i].Start), true, i})
		evs = append(evs, ev{new(big.Int).Add(ipToBig(raw[i].End), one), false, i})
	}
	sort.Slice(evs, func(i, j int) bool {
		if c := evs[i].p.Cmp(evs[j].p); c != 0 {
			return c < 0
		}
		return !evs[i].add && evs[j].add
	})
	active := map[int]bool{}
	inner := func() int {
		best := -1
		for i := range active {
			if best < 0 {
				best = i
				continue
			}
			c := ipToBig(raw[i].Start).Cmp(ipToBig(raw[best].Start))
			if c == 0 {
				c = ipToBig(raw[best].End).Cmp(ipToBig(raw[i].End))
			}
			if c > 0 || (c == 0 && i < best) {
				best = i
			}
		}
		return best
	}
	for k := 0; k < len(evs); {
		p := evs[k].p
		for ; k < len(evs) && evs[k].p.Cmp(p) == 0; k++ {
			if evs[k].add {
				active[evs[k].idx] = true
			} else {
				delete(active, evs[k].idx)
			}
		}
		if k >= len(evs) || len(active) == 0 {
			continue
		}
		bi := inner()
		if bi < 0 {
			continue
		}
		end := new(big.Int).Sub(evs[k].p, one)
		if n := len(fPieces); n > 0 {
			last := &fPieces[n-1]
			if last.prov == raw[bi].Province && last.isp == raw[bi].ISP && last.typ == raw[bi].Type &&
				new(big.Int).Add(last.e, one).Cmp(p) == 0 {
				last.e = end
				continue
			}
		}
		fPieces = append(fPieces, fPiece{
			s: new(big.Int).Set(p), e: end,
			prov: raw[bi].Province, isp: raw[bi].ISP, typ: raw[bi].Type,
		})
	}
	sort.Slice(fPieces, func(i, j int) bool { return fPieces[i].s.Cmp(fPieces[j].s) < 0 })
	fmt.Printf("底线索引: %d 段 → %d 互斥片段\n", len(raw), len(fPieces))
}

func ipToBig(s string) *big.Int {
	ip := net.ParseIP(s)
	if ip == nil {
		return big.NewInt(0)
	}
	if v4 := ip.To4(); v4 != nil {
		return new(big.Int).SetBytes(v4)
	}
	return new(big.Int).SetBytes(ip.To16())
}

// floorAt 查某个地址落在哪条底线片段里
func floorAt(v *big.Int) (isp, typ, prov string, ok bool) {
	i := sort.Search(len(fPieces), func(i int) bool { return fPieces[i].e.Cmp(v) >= 0 })
	if i < len(fPieces) && fPieces[i].s.Cmp(v) <= 0 {
		return fPieces[i].isp, fPieces[i].typ, fPieces[i].prov, true
	}
	return "", "", "", false
}

func netType(isp string) string {
	switch isp {
	case "教育网":
		return "edu"
	case "阿里云", "腾讯云", "华为云", "百度云":
		return "idc"
	}
	return "broadband"
}

func main() {
	floorIn := flag.String("floor", "floor.jsonl", "WHOIS 底线段表")
	segGlob := flag.String("segs", "scanner/seg-*.jsonl", "扫描段表（支持通配）")
	divisionFile := flag.String("division", "dbs/full.txt", "行政区划表")
	out := flag.String("out", "CN-LOCATION.mmdb", "输出 mmdb")
	withFloor := flag.Bool("with-floor", true, "是否把底线作为基底一起写入")
	cnMMDB := flag.String("cn-mmdb", "dbs/GeoLite2-City.mmdb", "判国家的库：非中国大陆的扫描段一律丢弃")
	zxPath := flag.String("zx", "dbs/ipv6wry.db", "ZX ipv6wry，给 v6 段补市（省必须一致）")
	geoPath := flag.String("geocn", "dbs/GeoCN.mmdb", "GeoCN 本地库：宽段按 /24 重算区县")
	flag.Parse()

	loadDivision(*divisionFile)

	// division 是「名称→代码」，宽段拆分要反过来用「代码→名称」
	divName := make(map[uint32]string, len(division))
	for n, c := range division {
		if _, dup := divName[c]; !dup {
			divName[c] = n
		}
	}

	var geoDB *maxminddb.Reader
	if db, err := maxminddb.Open(*geoPath); err == nil {
		geoDB = db
		defer db.Close()
		fmt.Println("GeoCN 就绪：宽段按 /24 重算区县")
	} else {
		fmt.Println("跳过 GeoCN:", err, "（宽段的县保持原值）")
	}

	var zx *zxDB
	if db, err := openZX(*zxPath); err == nil {
		zx = db
		fmt.Println("ZX 就绪:", db.count, "条")
	} else {
		fmt.Println("跳过 ZX:", err)
	}

	// 非中国大陆的段不写进 CN 库：公告段表里混了微软/台湾等海外段，
	// 这些位置改由 maxmind/ip2location 在世界库那一层补。
	var cnDB *maxminddb.Reader
	if *cnMMDB != "" {
		if db, err := maxminddb.Open(*cnMMDB); err == nil {
			cnDB = db
			defer db.Close()
		} else {
			fmt.Println("跳过国家过滤:", err)
		}
	}
	isCN := func(a string) bool {
		if cnDB == nil {
			return true
		}
		ip := net.ParseIP(a)
		if ip == nil {
			return true
		}
		var rec struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if err := cnDB.Lookup(netip.MustParseAddr(a)).Decode(&rec); err != nil {
			return true
		}
		return rec.Country.ISOCode == "CN"
	}
	fmt.Println("行政区划:", len(division))

	// 省 ISO 3166-2 代码 + 英文名（与根构建器一致，来自 norm 表）
	for abbr, zh := range ProvinceByAbbr {
		provISO[zh] = abbr
	}
	for en, zh := range ProvinceByEnglish {
		if _, dup := provEN[zh]; !dup {
			provEN[zh] = en
		}
	}

	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:        "cn-ip-location",
		Languages:           []string{"zh-CN", "en"},
		IPVersion:           6,
		DisableIPv4Aliasing: true,
	})
	if err != nil {
		panic(err)
	}

	insertFail := 0
	insert := func(start, end string, rec mmdbtype.Map) int {
		s, e := net.ParseIP(start), net.ParseIP(end)
		n := 0
		for _, ipnet := range rangeToCIDRs(s, e) {
			if err := tree.Insert(ipnet, rec); err == nil {
				n++
			} else {
				insertFail++
			}
		}
		return n
	}

	floorCnt, segCnt := 0, 0

	if *withFloor {
		f, err := os.Open(*floorIn)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		type fItem struct {
			d    floorRec
			span *big.Int
		}
		var recs []fItem
		var rawFloor []floorRec
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var d floorRec
			if json.Unmarshal(sc.Bytes(), &d) != nil || d.Province == "" || d.Start == "" {
				continue
			}
			recs = append(recs, fItem{d, spanOf(d.Start, d.End)})
			rawFloor = append(rawFloor, d)
		}
		buildFloorIndex(rawFloor)
		// 大段先插、小段后插 → 更具体的段自然覆盖粗段（span 只算一次，避免排序里反复解析 IP）
		sort.Slice(recs, func(i, j int) bool { return recs[i].span.Cmp(recs[j].span) > 0 })
		for _, it := range recs {
			d := it.d
			sub, _ := provFields(d.Province)
			rec := mmdbtype.Map{
				"country": mmdbtype.Map{
					"iso_code": mmdbtype.String("CN"),
					"names":    mmdbtype.Map{"zh-CN": mmdbtype.String("中国"), "en": mmdbtype.String("China")},
				},
				"isp":          mmdbtype.String(d.ISP),
				"type":         mmdbtype.String(d.Type),
				"subdivisions": mmdbtype.Slice{sub},
			}
			// 直辖市的底线也要带市名：省即市，下游按 city 取值时不该拿空。
			// 这条之前漏了，库里 427 个北京/上海前缀因此没有 city。
			if mc := cityOfMunicipality(d.Province); mc != "" {
				rec["city"] = mmdbtype.Map{"names": mmdbtype.Map{"zh-CN": mmdbtype.String(mc)}}
			}
			if code := adcodeOf(d.Province, "", ""); code != 0 {
				rec["division_code"] = mmdbtype.Uint32(code) // 底线也带省级 adcode，便于下游统一处理
			}
			floorCnt += insert(d.Start, d.End, rec)
		}
		fmt.Printf("底线入库: %d 段 → %d CIDR\n", len(recs), floorCnt)
	}

	files, _ := filepath.Glob(*segGlob)
	var segs []segRec
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<22), 1<<22)
		for sc.Scan() {
			var d segRec
			if json.Unmarshal(sc.Bytes(), &d) != nil {
				continue
			}
			if d.Primary.Province == "" || d.Start == "" {
				continue // 无省 = 无归属，不覆盖底线
			}
			// 直辖市补市（省即市），放在所有补录之前：这是逻辑缺失，不是数据缺失
			if d.Primary.City == "" {
				d.Primary.City = cityOfMunicipality(d.Primary.Province)
			}
			// ZX 补录：ipv6wry 的 v6 记录比 bilibili/TEO 覆盖广，但它对运营商大段
			// 常把省份判错（2409:8a20:c6::/48 判成上海、实为江苏宿迁），
			// 所以只在「省一致」时采纳它的市/县，绝不用它改省。
			if zx != nil && d.Primary.City == "" && strings.Contains(d.Start, ":") {
				if addr, err := netip.ParseAddr(d.Start); err == nil {
					if pv, ct, cy, ok := zx.lookup(addr); ok && NormProvince(pv) == d.Primary.Province {
						if ct != "" {
							d.Primary.City = ct
							if !strings.HasSuffix(ct, "市") && !strings.HasSuffix(ct, "州") && !strings.HasSuffix(ct, "盟") {
								d.Primary.City = ct + "市"
							}
							if countyCity[d.Primary.Province+"|"+d.Primary.City] == "" && cy != "" {
								d.Primary.County = cy
							}
						}
					}
				}
			}
			// 县名等于市名是「只到市级」的回落产物（宿迁市/宿迁市），先清掉：
			// 它占着 County 字段会挡住下面从陪跑源取真县。
			// 36.149.123.193 就是踩了这个坑——360 明明给了泗洪县，
			// 但 County 被「宿迁市」占着，回填被跳过，最后又被当假县清空。
			if d.Primary.County != "" && d.Primary.City != "" && d.Primary.County == d.Primary.City {
				d.Primary.County = ""
				if c := adcodeOf(d.Primary.Province, d.Primary.City, ""); c != 0 && d.Primary.Adcode == int(c) {
					d.Primary.Adcode = 0
				}
			}
			// 主源（360/TEO/bilibili）常常只到市，本地 GeoCN 有县的话补上：
			// 省必须一致；市一致或缺省时采用，市名带前缀的（「大理白族自治州大理市」
			// vs 「大理白族自治州」）也算一致。
			// 顺序 geocn → 360：GeoCN 是本地库（稳定、带完整区县），360 只在它没答时兜底。
			for _, srcName := range []string{"geocn", "360"} {
				if d.Primary.County != "" {
					break
				}
				g, ok := d.Sources[srcName]
				// g.County == g.City（360 对「阿勒泰地区」这类会给地区名当县）
				// 和 g.County == 主源市名，都等于没给县，别拿来回填
				if !ok || g.County == "" || g.Province != d.Primary.Province ||
					g.County == g.City || g.County == d.Primary.City {
					continue
				}
				if d.Primary.City == "" || g.City == "" || g.City == d.Primary.City ||
					strings.HasPrefix(d.Primary.City, g.City) || strings.HasPrefix(g.City, d.Primary.City) {
					d.Primary.County = g.County
					if d.Primary.City == "" {
						if c, ok := countyCity[d.Primary.Province+"|"+g.County]; ok {
							d.Primary.City = c
						} else {
							d.Primary.City = g.City
						}
					}
				}
			}
			segs = append(segs, d)
		}
		f.Close()
	}
	// 同样先大后小：县/市级的小段最后落，优先保留信息量
	type sItem struct {
		d    segRec
		span *big.Int
	}
	items := make([]sItem, len(segs))
	for i, d := range segs {
		items[i] = sItem{d, spanOf(d.Start, d.End)}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].span.Cmp(items[j].span) > 0 })
	nonCN := 0
	for _, it := range items {
		d := it.d
		if !isCN(d.Start) {
			nonCN++
			continue // 非中国大陆：交给世界库那一层补
		}
		// 纯底线答案（src=floor 且没有市/县）不覆盖：底线记录自带 ISP/type，覆盖反而丢信息
		if d.Primary.Src == "floor" && d.Primary.City == "" && d.Primary.County == "" {
			continue
		}
		sub, _ := provFields(d.Primary.Province)
		isp := d.Primary.ISP
		typ := netType(isp)
		if isp == "" {
			// 扫描段普遍没有 ISP：按地址回填底线的运营商和类型，避免把教育网/IDC 冲成空
			if fi, ft, _, ok := floorAt(ipToBig(d.Start)); ok {
				isp, typ = fi, ft
				if typ == "" {
					typ = netType(isp)
				}
			}
		}
		// 宽于 /24 的段：县只是段代表值（段内常跨 2–6 个区县），按 /24 查 GeoCN 重算
		if pieces, ok := splitByCounty(d, isp, typ, geoDB, divName); ok {
			for _, pc := range pieces {
				segCnt += insert(pc.start.String(), pc.end.String(), pc.rec)
			}
			continue
		}
		rec := mmdbtype.Map{
			"country": mmdbtype.Map{
				"iso_code": mmdbtype.String("CN"),
				"names":    mmdbtype.Map{"zh-CN": mmdbtype.String("中国"), "en": mmdbtype.String("China")},
			},
			"isp":          mmdbtype.String(isp),
			"type":         mmdbtype.String(typ),
			"subdivisions": mmdbtype.Slice{sub},
		}
		// 县名等于市名意味着「只到市级」，区县信息是 GeoCN/360 的市级回落产物
		// （库=广州市/广州市 这种）。留着会被下游当成真区县，县级一致率被拉低，
		// 所以直接丢掉；adcode 若指的就是市码也清掉，让它按市级重算。
		if d.Primary.County != "" && d.Primary.County == d.Primary.City {
			d.Primary.County = ""
			if c := adcodeOf(d.Primary.Province, d.Primary.City, ""); c != 0 && d.Primary.Adcode == int(c) {
				d.Primary.Adcode = 0
			}
		}
		// 县级清洗：① 去掉重复的市名前缀（「大理白族自治州安龙县」→「安龙县」）；
		// ② 县名不属于该市的直接丢掉（「遵义市/贵阳市」「娄底市/长沙市」这类错配），
		// 错县比没县更糟，adcode 一并作废让它按市级重算。
		if d.Primary.County != "" && d.Primary.City != "" {
			if strings.HasPrefix(d.Primary.County, d.Primary.City) && d.Primary.County != d.Primary.City {
				d.Primary.County = strings.TrimPrefix(d.Primary.County, d.Primary.City)
			}
			if kc := adcodeOf(d.Primary.Province, d.Primary.City, ""); kc != 0 && !countyInCity(kc, d.Primary.County) {
				d.Primary.County = ""
				d.Primary.Adcode = 0
			}
		}
		if d.Primary.City != "" {
			rec["city"] = mmdbtype.Map{"names": mmdbtype.Map{"zh-CN": mmdbtype.String(d.Primary.City)}}
		}
		if d.Primary.County != "" {
			rec["district"] = mmdbtype.Map{"names": mmdbtype.Map{"zh-CN": mmdbtype.String(d.Primary.County)}}
		}
		code := uint32(d.Primary.Adcode)
		if code == 0 {
			code = adcodeOf(d.Primary.Province, d.Primary.City, d.Primary.County)
		}
		if code != 0 {
			rec["division_code"] = mmdbtype.Uint32(code)
		}
		segCnt += insert(d.Start, d.End, rec)
	}
	fmt.Printf("扫描段入库: %d 段 → %d CIDR（插入失败 %d）\n", len(segs), segCnt, insertFail)

	fout, err := os.Create(*out)
	if err != nil {
		panic(err)
	}
	if _, err := tree.WriteTo(fout); err != nil {
		panic(err)
	}
	fout.Close()
	st, _ := os.Stat(*out)
	fmt.Printf("%s 完成: %.2f MB\n", *out, float64(st.Size())/1048576)
}

// spanOf 地址跨度（用于排序，v4/v6 各自按自身数值比较即可）
func spanOf(start, end string) *big.Int {
	s, e := net.ParseIP(start), net.ParseIP(end)
	if s == nil || e == nil {
		return big.NewInt(0)
	}
	if s.To4() != nil && e.To4() != nil {
		s, e = s.To4(), e.To4()
	} else {
		s, e = s.To16(), e.To16()
	}
	d := new(big.Int).Sub(new(big.Int).SetBytes(e), new(big.Int).SetBytes(s))
	return d
}
