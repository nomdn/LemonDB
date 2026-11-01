// asn —— LEMON-ASN.mmdb 全球 ASN 库分层合成
//
//	APNIC CN-ASN（floor 产物，CN 组织名最全）→ GeoLite2-ASN → dbip-asn-lite
// 后写的覆盖先写的同前缀记录；APNIC 只覆盖亚太，境外靠 GeoLite2/dbip 打底。
//
// 与 LEMON-LOCATION.mmdb 配套：三层统一搬 GeoLite2 兼容字段
// （autonomous_system_number / autonomous_system_organization），标准 mmdb 库直接读。
package main

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"


	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

// asnRecord GeoLite2 兼容的 ASN 记录。三个源都是这两个键，直接映射，无需转换。
type asnRecord struct {
	ASN uint32 `maxminddb:"autonomous_system_number"`
	Org string `maxminddb:"autonomous_system_organization"`
}

// layer 一个数据源：路径 + 描述（只用来打日志）
type layer struct {
	path string
	name string
}

func main() {
	out := flag.String("out", "LEMON-ASN.mmdb", "")
	geolite := flag.String("geolite", "dbs/GeoLite2-ASN.mmdb", "GeoLite2-ASN：全球打底")
	dbip := flag.String("dbip", "", "dbip-asn-lite：最底层补漏（可选）")
	apnic := flag.String("apnic", "CN-ASN.mmdb", "APNIC floor 产物：CN 段组织名最准，覆盖在最上")
	flag.Parse()

	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "lemon-asn",
		Languages:    []string{"en"},
		IPVersion:    6,
		// 与 LEMON-LOCATION 同款开关：v4 别名路径会让 v6 记录泄漏进 v4 查询
		DisableIPv4Aliasing: true,
	})
	if err != nil {
		panic(err)
	}

	// 从下往上叠：dbip 补漏 → geolite 主力 → APNIC 精修 CN
	layers := []layer{}
	if *dbip != "" {
		layers = append(layers, layer{*dbip, "dbip-asn-lite"})
	}
	if *geolite != "" {
		layers = append(layers, layer{*geolite, "GeoLite2-ASN"})
	}
	if *apnic != "" {
		layers = append(layers, layer{*apnic, "APNIC CN"})
	}

	total := 0
	for _, l := range layers {
		n, err := loadLayer(tree, l.path)
		if err != nil {
			// 缺一层不致命：GeoLite2 缺了境外就只剩 dbip，CN 不受影响
			fmt.Printf("跳过 %s: %v\n", l.name, err)
			continue
		}
		fmt.Printf("%-16s %6d 个前缀（%s）\n", l.name, n, l.path)
		total += n
	}

	f, err := os.Create(*out)
	if err != nil {
		panic(err)
	}
	if _, err := tree.WriteTo(f); err != nil {
		panic(err)
	}
	f.Close()
	fmt.Printf("%s: %d 个前缀入库\n", *out, total)
}

// loadLayer 把一个 mmdb 里的全部 ASN 记录插入树，返回插入条数
func loadLayer(tree *mmdbwriter.Tree, path string) (int, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	n := 0
	for res := range db.Networks() {
		if err := res.Err(); err != nil {
			return n, err
		}
		var rec asnRecord
		if err := res.Decode(&rec); err != nil || rec.ASN == 0 {
			continue // 无 ASN 的空壳记录没有搬运价值
		}
		if err := tree.Insert(toIPNet(res.Prefix()), recToMap(rec)); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func recToMap(r asnRecord) mmdbtype.Map {
	return mmdbtype.Map{
		"autonomous_system_number":       mmdbtype.Uint32(r.ASN),
		"autonomous_system_organization": mmdbtype.String(r.Org),
	}
}

// toIPNet netip.Prefix → *net.IPNet（v4/v6 各归各位，4-in-6 写法还原成 v4）
func toIPNet(p netip.Prefix) *net.IPNet {
	addr := p.Addr().Unmap()
	if addr.Is4() {
		b := addr.As4()
		return &net.IPNet{IP: net.IP(b[:]), Mask: net.CIDRMask(p.Bits(), 32)}
	}
	b := addr.As16()
	return &net.IPNet{IP: net.IP(b[:]), Mask: net.CIDRMask(p.Bits(), 128)}
}
