// LemonDB —— 中国 IP 归属地离线库构建器
//
// 阶段一（WHOIS 低精度底线）：
//
//	APNIC whois 全量 dump → RPSL 解析 → CN 对象省份/运营商挖掘
//	→ GeoLite2 兼容的 CN-LOCATION.mmdb + CN-ASN.mmdb（单树双栈）
//
// 阶段二（扫描，scanner/）：bilibili + 360（v4 县级）+ bilibili（v6）
// 多源探针，按 县 > 市 > 省 覆盖 WHOIS 底线；ZX(2021)/GeoCN 作 v6 种子。
package main

import . "lemondb/norm"

import (
	"bufio"
	"compress/gzip"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

type rpslObject struct {
	key     string // inetnum/inet6num/route 值，或 aut-num 的 AS 号
	netname string
	asName  string
	descr   []string
	country string
}

// parseRPSL 流式解析 dump；keyPrefix 指定对象键行（inetnum:/inet6num:/aut-num:/route:/route6:）
func parseRPSL(path, keyPrefix string, fn func(o rpslObject)) error {
	var sc *bufio.Scanner
	if strings.HasSuffix(path, ".gz") {
		gzf, err := os.Open(path)
		if err != nil {
			return err
		}
		defer gzf.Close()
		gz, err := gzip.NewReader(gzf)
		if err != nil {
			return err
		}
		sc = bufio.NewScanner(gz)
	} else {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		sc = bufio.NewScanner(f)
	}

	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var cur *rpslObject
	emit := func() {
		if cur != nil {
			fn(*cur)
			cur = nil
		}
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, keyPrefix):
			emit()
			cur = &rpslObject{key: strings.TrimSpace(line[strings.Index(line, ":")+1:])}
		case cur == nil:
		case strings.HasPrefix(line, "netname:"):
			cur.netname = strings.TrimSpace(line[strings.Index(line, ":")+1:])
		case strings.HasPrefix(line, "as-name:"):
			cur.asName = strings.TrimSpace(line[strings.Index(line, ":")+1:])
		case strings.HasPrefix(line, "descr:"):
			cur.descr = append(cur.descr, strings.TrimSpace(line[strings.Index(line, ":")+1:]))
		case strings.HasPrefix(line, "country:"):
			cur.country = strings.TrimSpace(line[strings.Index(line, ":")+1:])
		case strings.HasPrefix(line, "origin:"):
			cur.country = strings.TrimSpace(line[strings.Index(line, ":")+1:]) // route 对象借用 country 存 origin
		case line == "":
			emit()
		}
	}
	emit()
	return sc.Err()
}

// rangeToCIDRs 把 APNIC inetnum 的 "a - b" 区间（或 CIDR/单 IP）切成 CIDR 列表
func rangeToCIDRs(rng string) []*net.IPNet {
	var startIP, endIP net.IP
	parts := strings.Split(rng, " - ")
	if len(parts) == 2 {
		startIP = net.ParseIP(strings.TrimSpace(parts[0]))
		endIP = net.ParseIP(strings.TrimSpace(parts[1]))
	} else if _, ipnet, err := net.ParseCIDR(rng); err == nil {
		return []*net.IPNet{ipnet}
	} else if ip := net.ParseIP(strings.TrimSpace(rng)); ip != nil {
		startIP, endIP = ip, ip
	}
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
		if exp := size.BitLen() - 1; exp < low { // 块大小不得超过剩余区间
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

// lastAddr CIDR 的最后一个地址
func lastAddr(ipnet *net.IPNet) net.IP {
	ones, bits := ipnet.Mask.Size()
	ip := ipnet.IP
	if bits == 32 {
		v := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
		v |= 0xFFFFFFFF >> ones
		return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4()
	}
	// v6：仅低 64 位段的段尾足够用（本构建器的 v6 对象均为 CIDR）
	var hi [16]byte
	copy(hi[:], ip.To16())
	base := new(big.Int).SetBytes(hi[:])
	size := new(big.Int).Lsh(big.NewInt(1), uint(bits-ones))
	size.Sub(size, big.NewInt(1))
	base.Add(base, size)
	b := base.Bytes()
	out := make(net.IP, 16)
	copy(out[16-len(b):], b)
	return out
}

func parseUint(s string) uint32 {
	n := uint32(0)
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + uint32(c-'0')
	}
	return n
}

// writeCoverLists 从 APNIC dump 生成扫描器的公告段清单：
//
//	china.txt   → v4 CIDR，一行一个
//	china6.txt  → v6 CIDR
//
// 只按 country: CN 过滤，跟省名/运营商是否识别得出来无关——清单用来「划范围」，
// 范围小了才是灾难，识别不出来只是交给扫描阶段补。
//
// 必须先去重合并：APNIC 的 inetnum 有父子重叠记录（/16 分配里再登记 /24 指派），
// 两条都标 CN，直接逐条输出会把同一段算两遍——实测 411.1M 地址，而中国实际
// 公告空间约 344.1M，虚增 20% 的扫描量。合并重叠 + 相邻区间后再转 CIDR。
func writeCoverLists(dir, inetnumPath, inet6numPath string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	targets := []struct {
		file string // 输出文件名
		src  string // APNIC dump
		key  string // 对象键
		v4   bool   // 是否取 v4 地址族
	}{
		{"china.txt", inetnumPath, "inetnum:", true},
		{"china6.txt", inet6numPath, "inet6num:", false},
	}

	for _, t := range targets {
		ivs := collectCNIntervals(t.src, t.key, t.v4)
		ivs = mergeIntervals(ivs)

		f, err := os.Create(filepath.Join(dir, t.file))
		if err != nil {
			return err
		}
		w := bufio.NewWriter(f)
		n, addrs := 0, new(big.Int)
		for _, iv := range ivs {
			lo, hi := intToIP(iv.lo), intToIP(iv.hi)
			addrs.Add(addrs, new(big.Int).Sub(iv.hi, iv.lo))
			addrs.Add(addrs, big.NewInt(1))
			for _, ipnet := range rangeToCIDRs(lo.String() + " - " + hi.String()) {
				fmt.Fprintln(w, ipnet.String())
				n++
			}
		}
		if err := w.Flush(); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		// 地址数：v4 顺便报个 M，v6 那个量级报 M 没意义，直接给原始计数
		total := addrs.String()
		if t.v4 {
			mb := new(big.Float).Quo(new(big.Float).SetInt(addrs), big.NewFloat(1<<20))
			if f, _ := mb.Float64(); f > 0 {
				total = fmt.Sprintf("%s（%.1fM）", total, f)
			}
		}
		fmt.Printf("%s: %d 个 CN 公告段，%d 个 CIDR，%s 地址\n",
			filepath.Join(dir, t.file), len(ivs), n, total)
	}
	return nil
}

// interval 闭区间 [lo, hi]，用大整数存以便 v6 也能比
type interval struct {
	lo, hi *big.Int
}

// collectCNIntervals 把 dump 里 country: CN 的对象展开成闭区间
func collectCNIntervals(path, keyPrefix string, wantV4 bool) []interval {
	var out []interval
	err := parseRPSL(path, keyPrefix, func(o rpslObject) {
		if o.country != "CN" {
			return
		}
		for _, ipnet := range rangeToCIDRs(o.key) {
			// 地址族归位：inet6num 里偶尔出现 ::ffff: 写法的 v4 段
			if (ipnet.IP.To4() != nil) != wantV4 {
				continue
			}
			ip := net.IP(ipnet.IP)
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			lo := new(big.Int).SetBytes(ip)
			ones, bits := ipnet.Mask.Size()
			size := new(big.Int).Lsh(big.NewInt(1), uint(bits-ones))
			hi := new(big.Int).Sub(new(big.Int).Add(lo, size), big.NewInt(1))
			out = append(out, interval{lo, hi})
		}
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
	}
	return out
}

// mergeIntervals 排序后合并重叠与首尾相接的区间
func mergeIntervals(in []interval) []interval {
	sort.Slice(in, func(i, j int) bool { return in[i].lo.Cmp(in[j].lo) < 0 })
	out := make([]interval, 0, len(in))
	one := big.NewInt(1)
	for _, cur := range in {
		if len(out) == 0 {
			out = append(out, cur)
			continue
		}
		last := &out[len(out)-1]
		// cur.lo <= last.hi+1 即相邻或重叠
		if cur.lo.Cmp(new(big.Int).Add(last.hi, one)) <= 0 {
			if cur.hi.Cmp(last.hi) > 0 {
				last.hi = cur.hi
			}
			continue
		}
		out = append(out, cur)
	}
	return out
}

// intToIP 大整数还原成 IP（4 字节为 v4，否则 16 字节）
func intToIP(n *big.Int) net.IP {
	b := n.Bytes()
	size := 16
	if len(b) <= 4 {
		size = 4
	}
	ip := make(net.IP, size)
	copy(ip[size-len(b):], b)
	return ip
}

func main() {
	inetnum := flag.String("inetnum", "inetnum", "APNIC apnic.db.inetnum（解压后）")
	inet6num := flag.String("inet6num", "inet6num", "APNIC apnic.db.inet6num（解压后）")
	autnum := flag.String("autnum", "aut-num", "APNIC apnic.db.aut-num（解压后）")
	route4 := flag.String("route4", "", "APNIC apnic.db.route（可选，v4 ASN）")
	route6 := flag.String("route6", "", "APNIC apnic.db.route6（可选，v6 ASN）")
	outLoc := flag.String("out-location", "CN-LOCATION.mmdb", "")
	outASN := flag.String("out-asn", "CN-ASN.mmdb", "")
	floorOut := flag.String("floor-out", "", "底线段导出 JSONL（扫描器脚手架，可选）")
	coverOut := flag.String("cover-out", "", "公告段清单输出目录（china.txt / china6.txt），可选")
	flag.Parse()

	// ---------- 公告段清单 ----------
	// 扫描器按 china.txt / china6.txt 列出的 CN 公告段切格，原来这两个文件是手工
	// 维护的静态文件，月更时容易和 APNIC 脱节。既然 dump 已经在手上，直接生成：
	// 凡是 country: CN 的对象全收，**不要求**省市名识别成功（清单的目的只是划范围，
	// 识别不出来的段后面由扫描补，漏掉的段才是真损失）。
	if *coverOut != "" {
		if err := writeCoverLists(*coverOut, *inetnum, *inet6num); err != nil {
			panic(err)
		}
	}

	var floorW *bufio.Writer
	if *floorOut != "" {
		ff, err := os.Create(*floorOut)
		if err != nil {
			panic(err)
		}
		defer ff.Close()
		floorW = bufio.NewWriter(ff)
		defer floorW.Flush()
	}

	// ---------- aut-num：AS 号 → 组织 ----------
	orgByASN := map[string]string{}
	if err := parseRPSL(*autnum, "aut-num:", func(o rpslObject) {
		org := o.asName
		if len(o.descr) > 0 && o.descr[0] != "" {
			org = o.descr[0]
		}
		if o.key != "" && org != "" {
			orgByASN[strings.ToUpper(o.key)] = org
		}
	}); err != nil {
		fmt.Fprintln(os.Stderr, "aut-num:", err)
	}
	fmt.Println("aut-num:", len(orgByASN))

	// ---------- LOCATION 库 ----------
	locTree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "cn-ip-location",
		Languages:    []string{"zh-CN", "en"},
		IPVersion:    6,
		// v4 别名路径会让 v6 记录泄漏进 v4 查询空间（8.8.8.8 查出浙江的事故），
		// 关闭后 v4/v6 各归各位
		DisableIPv4Aliasing: true,
	})
	if err != nil {
		panic(err)
	}

	// ISO 3166-2:CN 省码 + 英文省名（由缩写/英文表反查构建）
	provISO := map[string]string{}
	provEN := map[string]string{}
	for abbr, zh := range ProvinceByAbbr {
		provISO[zh] = abbr
	}
	for en, zh := range ProvinceByEnglish {
		provISO[zh] = provISO[zh]
		if _, dup := provEN[zh]; !dup {
			provEN[zh] = en
		}
	}

	locCount := 0
	handle := func(o rpslObject) {
		if o.country != "CN" {
			return
		}
		province, isp := matchProvince(o.netname, o.descr)
		if province == "" && isp == "" {
			return
		}
		nettype := "broadband"
		switch isp {
		case "教育网":
			nettype = "edu"
		case "阿里云", "腾讯云", "华为云", "百度云":
			nettype = "idc"
		}
		rec := mmdbtype.Map{
			"country": mmdbtype.Map{
				"iso_code": mmdbtype.String("CN"),
				"names":    mmdbtype.Map{"zh-CN": mmdbtype.String("中国"), "en": mmdbtype.String("China")},
			},
			"isp":  mmdbtype.String(isp),
			"type": mmdbtype.String(nettype),
		}
		var subISO, subEN string
		if province != "" {
			sub := mmdbtype.Map{"names": mmdbtype.Map{"zh-CN": mmdbtype.String(province)}}
			if iso, ok := provISO[province]; ok {
				subISO = iso
				sub["iso_code"] = mmdbtype.String(iso)
			}
			if en, ok := provEN[province]; ok {
				subEN = en
				sub["names"].(mmdbtype.Map)["en"] = mmdbtype.String(en)
			}
			rec["subdivisions"] = mmdbtype.Slice{sub}
		}
		for _, ipnet := range rangeToCIDRs(o.key) {
			if err := locTree.Insert(ipnet, rec); err == nil {
				locCount++
				// 底线段导出：供扫描器当脚手架（省块切分 + 空洞定位）
				if floorW != nil {
					start := ipnet.IP.String()
					end := lastAddr(ipnet).String()
					fmt.Fprintf(floorW, "{\"start\":%q,\"end\":%q,\"province\":%q,\"iso\":%q,\"en\":%q,\"isp\":%q,\"type\":%q}\n",
						start, end, province, subISO, subEN, isp, nettype)
				}
			}
		}
	}
	if err := parseRPSL(*inetnum, "inetnum:", handle); err != nil {
		fmt.Fprintln(os.Stderr, "inetnum:", err)
	}
	if err := parseRPSL(*inet6num, "inet6num:", handle); err != nil {
		fmt.Fprintln(os.Stderr, "inet6num:", err)
	}

	lout, err := os.Create(*outLoc)
	if err != nil {
		panic(err)
	}
	if _, err := locTree.WriteTo(lout); err != nil {
		panic(err)
	}
	lout.Close()
	fmt.Printf("%s: %d 个 CIDR 入库\n", *outLoc, locCount)

	// ---------- ASN 库 ----------
	asnTree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:        "cn-ip-asn",
		Languages:           []string{"zh-CN", "en"},
		IPVersion:           6,
		DisableIPv4Aliasing: true,
	})
	if err != nil {
		panic(err)
	}
	asnCount := 0
	insertASN := func(o rpslObject) {
		origin := strings.ToUpper(o.country) // parseRPSL 借 country 存 origin
		if !strings.HasPrefix(origin, "AS") {
			return
		}
		for _, ipnet := range rangeToCIDRs(o.key) {
			rec := mmdbtype.Map{
				"autonomous_system_number":       mmdbtype.Uint32(parseUint(origin[2:])),
				"autonomous_system_organization": mmdbtype.String(orgByASN[origin]),
			}
			if err := asnTree.Insert(ipnet, rec); err == nil {
				asnCount++
			}
		}
	}
	if *route4 != "" {
		if err := parseRPSL(*route4, "route:", insertASN); err != nil {
			fmt.Fprintln(os.Stderr, "route4:", err)
		}
	}
	if *route6 != "" {
		if err := parseRPSL(*route6, "route6:", insertASN); err != nil {
			fmt.Fprintln(os.Stderr, "route6:", err)
		}
	}
	aout, err := os.Create(*outASN)
	if err != nil {
		panic(err)
	}
	if _, err := asnTree.WriteTo(aout); err != nil {
		panic(err)
	}
	aout.Close()
	fmt.Printf("%s: %d 条路由入库\n", *outASN, asnCount)
}
