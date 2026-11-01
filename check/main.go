// check —— 成品 mmdb 的独立回查
//
// 扫描链路的主要判据是 TEO，回查必须用**没参与决策的源**才有意义：
//   v4：360（省/市/县）+ bilibili（省/市）
//   v6：bilibili（省/市）
//
// 做法：在段表里等距抽样，取段中点查成品库，再拿回查源的答案比对，
// 输出省/市/县一致率和不一致样例。只读，不改任何数据。
package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	. "lemondb/norm"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
	"resty.dev/v3"
)

type segRow struct {
	Start   string `json:"start"`
	End     string `json:"end"`
	Primary struct {
		Province string `json:"province"`
		City     string `json:"city"`
		County   string `json:"county"`
	} `json:"primary"`
}

type locRec struct {
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	City *struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	District *struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"district"`
}

type probe struct {
	Province, City, County string
}

var (
	bili = resty.New().SetTimeout(10 * time.Second).SetHeader("User-Agent", "Mozilla/5.0")
	s360 = resty.New().SetTimeout(10 * time.Second).SetHeader("User-Agent", "Mozilla/5.0").SetHeader("Referer", "http://ip.360.cn/")
	lbsC = resty.New().SetTimeout(10 * time.Second)
)

var (
	lbsKey, lbsSK string
	lbsMu         sync.Mutex
	lbsLast       time.Time
)

// askLBS 腾讯位置服务（独立于扫描主链路），QPS 只有 5，必须限速
func askLBS(ip string) probe {
	if lbsKey == "" || lbsSK == "" {
		return probe{}
	}
	lbsMu.Lock()
	if d := time.Since(lbsLast); d < 210*time.Millisecond {
		time.Sleep(210*time.Millisecond - d)
	}
	lbsLast = time.Now()
	lbsMu.Unlock()
	qs := "ip=" + ip + "&key=" + lbsKey
	sig := md5hex("/ws/location/v1/ip?"+qs, lbsSK)
	r, err := lbsC.R().Get("https://apis.map.qq.com/ws/location/v1/ip?" + qs + "&sig=" + sig)
	if err != nil || r.IsError() {
		return probe{}
	}
	var w struct {
		Status int `json:"status"`
		Result struct {
			AdInfo struct {
				Province string `json:"province"`
				City     string `json:"city"`
				District string `json:"district"`
			} `json:"ad_info"`
		} `json:"result"`
	}
	if err := json.Unmarshal(r.Bytes(), &w); err != nil || w.Status != 0 {
		return probe{}
	}
	a := w.Result.AdInfo
	return probe{Province: NormProvince(a.Province), City: a.City, County: a.District}
}

func md5hex(s, key string) string {
	h := md5.Sum([]byte(s + key))
	return hex.EncodeToString(h[:])
}

func askBili(ip string) probe {
	var w struct {
		Code int `json:"code"`
		Data struct {
			Province string `json:"province"`
			City     string `json:"city"`
			ISP      string `json:"isp"`
		} `json:"data"`
	}
	r, err := bili.R().SetQueryParam("ip", ip).SetResult(&w).Get("https://api.live.bilibili.com/ip_service/v1/ip_service/get_ip_addr")
	if err != nil || r.IsError() || w.Code != 0 {
		return probe{}
	}
	return probe{Province: NormProvince(w.Data.Province), City: w.Data.City}
}

func ask360(ip string) probe {
	if net.ParseIP(ip).To4() == nil {
		return probe{}
	}
	var w struct {
		Errno int    `json:"errno"`
		Data  string `json:"data"`
	}
	r, err := s360.R().SetQueryParam("ip", ip).Get("http://ip.360.cn/IPQuery/ipquery")
	if err != nil || r.IsError() || w.Errno != 0 {
		return probe{}
	}
	if err := json.Unmarshal(r.Bytes(), &w); err != nil || w.Errno != 0 {
		return probe{}
	}
	p, c, ct, _ := Parse360Region(w.Data)
	return probe{Province: p, City: c, County: ct}
}

func midOf(start, end string) (netip.Addr, bool) {
	s, e1 := netip.ParseAddr(start)
	e, e2 := netip.ParseAddr(end)
	if e1 != nil || e2 != nil || s.Is4() != e.Is4() {
		return netip.Addr{}, false
	}
	width := 16
	if s.Is4() {
		width = 4
	}
	var sb, eb []byte
	if width == 4 {
		a, b := s.As4(), e.As4()
		sb, eb = a[:], b[:]
	} else {
		a, b := s.As16(), e.As16()
		sb, eb = a[:], b[:]
	}
	lo := new(big.Int).SetBytes(sb)
	hi := new(big.Int).SetBytes(eb)
	mid := new(big.Int).Add(lo, hi)
	mid.Div(mid, big.NewInt(2))
	b := mid.Bytes()
	ip := make(net.IP, width)
	copy(ip[width-len(b):], b)
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// 直辖市「省即市」+ 自治州带前缀，严格相等会把正确结果判成不一致
var muniProv = map[string]bool{"北京": true, "上海": true, "天津": true, "重庆": true}

func cityMatch(srcProv, srcCity, gotCity string) bool {
	a := strings.TrimSuffix(strings.TrimSpace(srcCity), "市")
	b := strings.TrimSuffix(strings.TrimSpace(gotCity), "市")
	if b == "" {
		return false
	}
	if a == "" {
		pa := strings.TrimSuffix(strings.TrimSpace(srcProv), "市")
		return muniProv[pa] && (b == pa || strings.HasPrefix(b, pa))
	}
	return a == b || strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
}

func main() {
	mmdbPath := flag.String("mmdb", "CN-LOCATION.mmdb", "成品库")
	segGlob := flag.String("segs", "scanner/seg-*.jsonl", "段表")
	samples := flag.Int("n", 300, "抽样段数")
	workers := flag.Int("w", 6, "并发")
	v6only := flag.Bool("v6", false, "只查 v6")
	v4only := flag.Bool("v4", false, "只查 v4")
	coverList := flag.String("cover", "", "覆盖面检查：从该公告段列表随机取地址，看库里有没有记录")
	flag.StringVar(&lbsKey, "lbs-key", "", "腾讯位置服务 key（回查补充源）")
	flag.StringVar(&lbsSK, "lbs-sk", "", "腾讯位置服务 SK")
	flag.Parse()

	if *coverList != "" {
		coverageCheck(*mmdbPath, *coverList, *samples)
		return
	}

	db, err := maxminddb.Open(*mmdbPath)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	files, _ := filepath.Glob(*segGlob)
	var rows []segRow
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<22), 1<<22)
		for sc.Scan() {
			var d segRow
			if json.Unmarshal(sc.Bytes(), &d) == nil && d.Primary.Province != "" {
				isV6 := strings.Contains(d.Start, ":")
				if (*v6only && !isV6) || (*v4only && isV6) {
					continue
				}
				rows = append(rows, d)
			}
		}
		f.Close()
	}
	if len(rows) == 0 {
		fmt.Println("没有可用段")
		return
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Start < rows[j].Start })
	step := len(rows) / *samples
	if step < 1 {
		step = 1
	}
	var picked []segRow
	for i := 0; i < len(rows); i += step {
		picked = append(picked, rows[i])
	}
	fmt.Printf("段表 %d 段，抽样 %d 段\n", len(rows), len(picked))

	type result struct {
		ip                            string
		want, got                     probe
		src                           probe
		okProv, okCity, okCounty      bool
		hasCity, hasCounty, hasProv   bool
	}
	results := make([]result, len(picked))
	var wg sync.WaitGroup
	sem := make(chan struct{}, *workers)
	for i, r := range picked {
		addr, ok := midOf(r.Start, r.End)
		if !ok {
			continue
		}
		wg.Add(1)
		go func(i int, r segRow, ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var rec locRec
			_ = db.Lookup(netip.MustParseAddr(ip)).Decode(&rec)
			got := probe{}
			if len(rec.Subdivisions) > 0 {
				got.Province = NormProvince(rec.Subdivisions[0].Names["zh-CN"])
			}
			if rec.City != nil {
				got.City = rec.City.Names["zh-CN"]
			}
			if rec.District != nil {
				got.County = rec.District.Names["zh-CN"]
			}
			src := askBili(ip)
			if lb := askLBS(ip); lb.Province != "" {
				if src.Province == "" {
					src.Province = lb.Province
				}
				if src.City == "" {
					src.City = lb.City
				}
				if src.County == "" {
					src.County = lb.County
				}
			}
			if !strings.Contains(ip, ":") {
				if p360 := ask360(ip); p360.Province != "" {
					if src.Province == "" {
						src.Province = p360.Province
					}
					if src.City == "" {
						src.City = p360.City
					}
					src.County = p360.County
				}
			}
			results[i] = result{
				ip: ip, want: got, src: src,
				okProv:  src.Province != "" && src.Province == got.Province,
				okCity:  cityMatch(src.Province, src.City, got.City),
				okCounty: src.County != "" && got.County != "" && src.County == got.County,
				hasCity: got.City != "", hasCounty: got.County != "", hasProv: got.Province != "",
			}
		}(i, r, addr.String())
	}
	wg.Wait()

	var n, haveProv, provOK, cityCmp, cityOK, ctyCmp, ctyOK, srcEmpty int
	var bad []result
	for _, r := range results {
		if r.ip == "" {
			continue
		}
		n++
		if r.hasProv {
			haveProv++
		}
		if r.src.Province == "" {
			srcEmpty++
			continue
		}
		if r.okProv {
			provOK++
		} else if len(bad) < 8 {
			bad = append(bad, r)
		}
		if r.src.City != "" && r.hasCity {
			cityCmp++
			if r.okCity {
				cityOK++
			}
		}
		if r.src.County != "" && r.hasCounty {
			ctyCmp++
			if r.okCounty {
				ctyOK++
			}
		}
	}
	pct := func(a, b int) float64 {
		if b == 0 {
			return 0
		}
		return 100 * float64(a) / float64(b)
	}
	fmt.Printf("\n样本 %d | 库内有省 %d (%.1f%%) | 回查源无结果 %d\n", n, haveProv, pct(haveProv, n), srcEmpty)
	fmt.Printf("省一致 %d/%d (%.1f%%) | 市一致 %d/%d (%.1f%%) | 县一致 %d/%d (%.1f%%)\n",
		provOK, n-srcEmpty, pct(provOK, n-srcEmpty), cityOK, cityCmp, pct(cityOK, cityCmp), ctyOK, ctyCmp, pct(ctyOK, ctyCmp))
	if len(bad) > 0 {
		fmt.Println("\n不一致样例（库 vs 回查源）：")
		for _, b := range bad {
			fmt.Printf("  %-40s 库=%s/%s/%s  源=%s/%s/%s\n", b.ip, b.want.Province, b.want.City, b.want.County, b.src.Province, b.src.City, b.src.County)
		}
	}
}

// coverageCheck 从公告段列表里抽地址，统计成品库能给出省份的比例。
// 这个指标衡量的是「交付物覆盖面」——公告段里有、库里没有记录就是洞。
func coverageCheck(mmdbPath, listPath string, n int) {
	db, err := maxminddb.Open(mmdbPath)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	f, err := os.Open(listPath)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	var nets []netip.Prefix
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if p, err := netip.ParsePrefix(line); err == nil {
			nets = append(nets, p)
		}
	}
	if len(nets) == 0 {
		fmt.Println("列表为空")
		return
	}

	rand.Seed(42)
	hit, total := 0, 0
	var missing []string
	for i := 0; i < n; i++ {
		p := nets[rand.Intn(len(nets))]
		addr := p.Addr()
		width := 16
		if addr.Is4() {
			width = 4
		}
		var ab []byte
		if width == 4 {
			b := addr.As4()
			ab = b[:]
		} else {
			b := addr.As16()
			ab = b[:]
		}
		base := new(big.Int).SetBytes(ab)
		size := new(big.Int).Lsh(big.NewInt(1), uint(width*8-p.Bits()))
		off := new(big.Int).Rand(rand.New(rand.NewSource(int64(i*7919+13))), size)
		v := new(big.Int).Add(base, off)
		b := v.Bytes()
		ip := make(net.IP, width)
		copy(ip[width-len(b):], b)
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		total++
		var rec locRec
		if err := db.Lookup(a.Unmap()).Decode(&rec); err == nil && len(rec.Subdivisions) > 0 {
			hit++
		} else if len(missing) < 10 {
			missing = append(missing, a.Unmap().String()+" ("+p.String()+")")
		}
	}
	fmt.Printf("公告段抽样 %d 个地址：库内有省 %d (%.1f%%)，无记录 %d\n", total, hit, 100*float64(hit)/float64(total), total-hit)
	if len(missing) > 0 {
		fmt.Println("无记录样例：")
		for _, m := range missing {
			fmt.Println("  " + m)
		}
	}
}
