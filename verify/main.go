// verify —— LBS 验证后处理
//
// 读 segments.jsonl，按段跨度从大到小在预算内对段中点做 LBS 验证，
// 验证不符的段以 LBS 答案定案（保留原答案于 sources），输出 verified.jsonl。
package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"resty.dev/v3"

	"cnipdb/norm"
)

type answer struct {
	Src      string `json:"src"`
	Province string `json:"province,omitempty"`
	City     string `json:"city,omitempty"`
	County   string `json:"county,omitempty"`
	ISP      string `json:"isp,omitempty"`
	Adcode   int    `json:"adcode,omitempty"`
	Extra    string `json:"extra,omitempty"`
}

type segment struct {
	Start   string            `json:"start"`
	End     string            `json:"end"`
	Prefix  string            `json:"prefix"`
	Primary answer            `json:"primary"`
	Sources map[string]answer `json:"sources"`
}

func md5hex(s, key string) string {
	h := md5.Sum([]byte(s + key))
	return hex.EncodeToString(h[:])
}

func main() {
	in := flag.String("in", "segments.jsonl", "扫描段表输入")
	out := flag.String("out", "verified.jsonl", "验证后输出")
	key := flag.String("lbs-key", "", "腾讯 LBS key")
	sk := flag.String("lbs-sk", "", "腾讯 LBS SK")
	teoURL := flag.String("teo-url", "", "腾讯 EO 控制台 siaas 地址")
	teoCookie := flag.String("teo-cookie", "", "腾讯云控制台会话 cookie")
	budget := flag.Int("budget", 5500, "LBS 预算")
	minSpan := flag.Int64("min-span", 256, "最小验证跨度（地址数）")
	flag.Parse()

	if *key == "" || *sk == "" {
		fmt.Fprintln(os.Stderr, "需要 -lbs-key / -lbs-sk")
		os.Exit(1)
	}

	client := resty.New().SetTimeout(10 * time.Second)

	// 读段表
	var segs []segment
	inf, err := os.Open(*in)
	if err != nil {
		panic(err)
	}
	defer inf.Close()
	sc := bufio.NewScanner(inf)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var sg segment
		if json.Unmarshal(sc.Bytes(), &sg) == nil {
			segs = append(segs, sg)
		}
	}
	fmt.Println("段总数:", len(segs))

	// 计算跨度并排序（大到小）
	type item struct {
		idx  int
		span *big.Int
	}
	items := make([]item, 0, len(segs))
	for i := range segs {
		sa, e1 := netip.ParseAddr(segs[i].Start)
		ea, e2 := netip.ParseAddr(segs[i].End)
		if e1 != nil || e2 != nil {
			continue
		}
		var sb, eb []byte
		if sa.Is4() {
			b := sa.As4()
			sb = []byte(b[:])
		} else {
			b := sa.As16()
			sb = []byte(b[:])
		}
		if ea.Is4() {
			b := ea.As4()
			eb = []byte(b[:])
		} else {
			b := ea.As16()
			eb = []byte(b[:])
		}
		lo := new(big.Int).SetBytes(sb)
		hi := new(big.Int).SetBytes(eb)
		items = append(items, item{i, new(big.Int).Sub(hi, lo)})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].span.Cmp(items[j].span) > 0 })

	used := 0
	verified, mismatch := 0, 0
	for _, it := range items {
		if used >= *budget {
			break
		}
		seg := &segs[it.idx]
		span := it.span.Int64()
		if span < *minSpan {
			break // 排序后剩余的都是小段
		}
		// 段中点
		sa, _ := netip.ParseAddr(seg.Start)
		ea, _ := netip.ParseAddr(seg.End)
		var sb, eb []byte
		if sa.Is4() {
			b := sa.As4()
			sb = []byte(b[:])
		} else {
			b := sa.As16()
			sb = []byte(b[:])
		}
		if ea.Is4() {
			b := ea.As4()
			eb = []byte(b[:])
		} else {
			b := ea.As16()
			eb = []byte(b[:])
		}
		lo := new(big.Int).SetBytes(sb)
		hi := new(big.Int).SetBytes(eb)
		mid := new(big.Int).Add(lo, hi)
		mid.Div(mid, big.NewInt(2))
		mb := mid.Bytes()
		midIP := make(net.IP, 16)
		copy(midIP[16-len(mb):], mb)
		addr, _ := netip.AddrFromSlice(midIP)

		qs := "ip=" + addr.Unmap().String() + "&key=" + *key
		sig := md5hex("/ws/location/v1/ip?"+qs, *sk)
		r, err := client.R().Get("https://apis.map.qq.com/ws/location/v1/ip?" + qs + "&sig=" + sig)
		used++
		if err != nil || r.IsError() {
			continue
		}
		var w struct {
			Status int `json:"status"`
			Result struct {
				AdInfo struct {
					Province string `json:"province"`
					City     string `json:"city"`
					District string `json:"district"`
					Adcode   int    `json:"adcode"`
				} `json:"ad_info"`
			} `json:"result"`
		}
		if json.Unmarshal(r.Bytes(), &w) != nil || w.Status != 0 {
			continue
		}
		a := w.Result.AdInfo
		lb := answer{Src: "lbs", Province: a.Province, City: a.City, County: a.District, Adcode: a.Adcode}
		if lb.Province == "" {
			continue
		}
		verified++
		seg.Sources["lbs"] = lb
		// 验证不符：市级冲突时 LBS 定案（county 保留原值）
		if lb.City != "" && seg.Primary.City != "" && lb.City != seg.Primary.City {
			lb.County = seg.Primary.County
			seg.Primary = lb
			mismatch++
		}
		if used%200 == 0 {
			fmt.Printf("进度: 已用 %d/%d, 验证 %d, 修正 %d\n", used, *budget, verified, mismatch)
		}
	}
	fmt.Printf("完成: 验证 %d 段, 市级修正 %d 段, LBS 用量 %d\n", verified, mismatch, used)

	// ---------- teo 批量验证（腾讯 EdgeOne 控制台通道，IPs 数组一次 50 段） ----------
	if *teoURL != "" && *teoCookie != "" {
		teoClient := resty.New().SetTimeout(20 * time.Second)
		batch := 50
		teoHit, teoFix := 0, 0
		for lo := 0; lo < len(segs); lo += batch {
			hi := lo + batch
			if hi > len(segs) {
				hi = len(segs)
			}
			ips := make([]string, 0, hi-lo)
			for i := lo; i < hi; i++ {
				sa, e := netip.ParseAddr(segs[i].Start)
				if e != nil {
					ips = append(ips, segs[i].Start)
					continue
				}
				ips = append(ips, sa.Unmap().String())
			}
			body := map[string]any{
				"cgi": "/cgi/capi", "action": "DescribeIPRegion", "serviceType": "teo",
				"clientName": "teo", "sign": "v3",
				"data": map[string]any{
					"Version": "2022-09-01", "Language": "zh-CN", "Region": "ap-guangzhou",
					"IPs": ips, "Action": "DescribeIPRegion",
				},
				"region": "ap-guangzhou",
			}
			resp, err := teoClient.R().
				SetHeader("Cookie", *teoCookie).
				SetHeader("Origin", "https://console.cloud.tencent.com").
				SetHeader("Referer", "https://console.cloud.tencent.com/edgeone/ip").
				SetBody(body).Post(*teoURL)
			if err != nil || resp.IsError() {
				fmt.Println("teo 通道失败，终止 teo 验证:", err)
				break
			}
			var wrap struct {
				Code int `json:"code"`
				Data struct {
					Response struct {
						IPRegionInfo []struct {
							IP     string `json:"IP"`
							Region string `json:"Region"`
						} `json:"IPRegionInfo"`
					} `json:"Response"`
				} `json:"data"`
			}
			if json.Unmarshal(resp.Bytes(), &wrap) != nil || wrap.Code != 0 {
				fmt.Println("teo 会话失效，终止 teo 验证")
				break
			}
			byIP := map[string]string{}
			for _, it := range wrap.Data.Response.IPRegionInfo {
				byIP[strings.ToLower(it.IP)] = it.Region
			}
			for i := lo; i < hi; i++ {
				sa, e := netip.ParseAddr(segs[i].Start)
				if e != nil {
					continue
				}
				region, ok := byIP[strings.ToLower(sa.Unmap().String())]
				if !ok {
					continue
				}
				fields := strings.Fields(region)
				if len(fields) < 3 || fields[0] != "中国" {
					continue
				}
				teoHit++
				ta := answer{Src: "teo", Province: norm.NormProvince(fields[1]), City: fields[2], ISP: norm.NormISP(strings.Join(fields[3:], " "))}
				segs[i].Sources["teo"] = ta
				if ta.City != "" && segs[i].Primary.City != "" && ta.City != segs[i].Primary.City {
					ta.County = segs[i].Primary.County
					segs[i].Primary = ta
					teoFix++
				}
			}
			if lo%(batch*10) == 0 {
				fmt.Printf("teo 进度: %d/%d 段\n", hi, len(segs))
			}
		}
		fmt.Printf("teo 完成: 覆盖 %d 段, 市级修正 %d 段\n", teoHit, teoFix)
	}

	of, err := os.Create(*out)
	if err != nil {
		panic(err)
	}
	defer of.Close()
	w := bufio.NewWriter(of)
	for i := range segs {
		b, _ := json.Marshal(segs[i])
		w.Write(b)
		w.WriteByte('\n')
	}
	w.Flush()
	fmt.Println("输出:", *out)
}
