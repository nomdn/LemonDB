// cnipdb —— 中国 IP 归属地离线库构建器
//
// 阶段一（WHOIS 低精度底线）：
//
//	APNIC whois 全量 dump → RPSL 解析 → CN 对象省份/运营商挖掘
//	→ GeoLite2 兼容的 CN-LOCATION.mmdb + CN-ASN.mmdb（单树双栈）
//
// 阶段二（扫描，scanner/）：bilibili + 360（v4 县级）+ bilibili（v6）
// 多源探针，按 县 > 市 > 省 覆盖 WHOIS 底线；ZX(2021)/GeoCN 作 v6 种子。
package main

import . "cnipdb/norm"

import (
	"bufio"
	"compress/gzip"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
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

func main() {
	inetnum := flag.String("inetnum", "inetnum", "APNIC apnic.db.inetnum（解压后）")
	inet6num := flag.String("inet6num", "inet6num", "APNIC apnic.db.inet6num（解压后）")
	autnum := flag.String("autnum", "aut-num", "APNIC apnic.db.aut-num（解压后）")
	route4 := flag.String("route4", "", "APNIC apnic.db.route（可选，v4 ASN）")
	route6 := flag.String("route6", "", "APNIC apnic.db.route6（可选，v6 ASN）")
	outLoc := flag.String("out-location", "CN-LOCATION.mmdb", "")
	outASN := flag.String("out-asn", "CN-ASN.mmdb", "")
	floorOut := flag.String("floor-out", "", "底线段导出 JSONL（扫描器脚手架，可选）")
	flag.Parse()

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
