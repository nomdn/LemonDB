// rescan —— 对「宽于 /24 但有县」的段逐 /24 重查 360，拿到区县级真值。
//
// 背景：扫描阶段按 /24 采样后会把相邻同签名的格合并成大段，区县只保留一个
// 代表值。实测 30 个宽段里 27 个段内其实跨区县（周口市川汇区那段同时有
// 扶沟县/西华县/郸城县），所以宽段的 county 对段内多数地址是错的。
//
// 这里只重查 /20–/23 的段（太宽的段本来就跨区县，交给 merge 降级为只到市），
// 输出每个 /24 的真实省市县，供 merge 覆盖。
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"lemondb/norm"
)

type segRec struct {
	Start   string `json:"start"`
	End     string `json:"end"`
	Primary struct {
		Province string `json:"province"`
		City     string `json:"city"`
		County   string `json:"county"`
	} `json:"primary"`
}

type outRec struct {
	Prefix   string `json:"prefix"`
	Province string `json:"province"`
	City     string `json:"city"`
	County   string `json:"county"`
	ISP      string `json:"isp"`
}

func main() {
	segGlob := flag.String("segs", "../scanner/seg-v4*.jsonl", "扫描段文件")
	out := flag.String("out", "county24.jsonl", "输出：每个 /24 的省市县")
	workers := flag.Int("workers", 8, "并发数")
	gap := flag.Duration("gap", 80*time.Millisecond, "每个 worker 的请求间隔（全局 ≈ workers/gap）")
	minCells := flag.Int("min-cells", 2, "只重查覆盖 >= 这么多 /24 的段")
	maxCells := flag.Int("max-cells", 16, "覆盖超过这么多的段跳过（太宽，必然跨区县）")
	flag.Parse()

	// 1. 收集待查 /24
	type job struct{ ip string }
	var jobs []job
	seen := map[uint32]bool{}
	files, _ := filepath.Glob(*segGlob)
	segCnt := 0
	for _, p := range files {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<22), 1<<22)
		for sc.Scan() {
			var d segRec
			if json.Unmarshal(sc.Bytes(), &d) != nil || d.Start == "" {
				continue
			}
			if d.Primary.County == "" || d.Primary.County == d.Primary.City {
				continue
			}
			s, err1 := netip.ParseAddr(d.Start)
			e, err2 := netip.ParseAddr(d.End)
			if err1 != nil || err2 != nil || !s.Is4() {
				continue
			}
			lo := uint32(s.As4()[0])<<24 | uint32(s.As4()[1])<<16 | uint32(s.As4()[2])<<8 | uint32(s.As4()[3])
			hi := uint32(e.As4()[0])<<24 | uint32(e.As4()[1])<<16 | uint32(e.As4()[2])<<8 | uint32(e.As4()[3])
			n := hi/256 - lo/256 + 1
			if int(n) < *minCells || int(n) > *maxCells {
				continue
			}
			segCnt++
			for x := lo / 256; x <= hi/256; x++ {
				if seen[x] {
					continue
				}
				seen[x] = true
				ip := netip.AddrFrom4([4]byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)})
				jobs = append(jobs, job{ip: ip.String() + "/24 中点"})
			}
		}
		f.Close()
	}
	fmt.Printf("待重查段 %d 个，/24 共 %d 个\n", segCnt, len(jobs))
	if len(jobs) == 0 {
		return
	}

	// 2. 并发查询，限速 + 失败降速
	f, err := os.Create(*out)
	if err != nil {
		panic(err)
	}
	w := bufio.NewWriter(f)
	var mu sync.Mutex
	var done, fail int64
	var interval int64 = int64(*gap)
	ch := make(chan job, 1024)
	go func() {
		for _, j := range jobs {
			ch <- j
		}
		close(ch)
	}()

	client := &http.Client{Timeout: 10 * time.Second}
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				ip := j.ip
				if k := len(ip); k > 0 {
					// job.ip 存的是 "a.b.c.0/24 中点"，取前 3 段拼 .128
					var a, b, c int
					if _, err := fmt.Sscanf(ip, "%d.%d.%d.0/24", &a, &b, &c); err == nil {
						ip = fmt.Sprintf("%d.%d.%d.128", a, b, c)
					}
				}
				ans, ok := query(client, ip)
				time.Sleep(time.Duration(atomic.LoadInt64(&interval)))
				if !ok {
					atomic.AddInt64(&fail, 1)
					if atomic.LoadInt64(&fail)%20 == 0 {
						cur := atomic.LoadInt64(&interval)
						if cur < int64(300*time.Millisecond) {
							atomic.StoreInt64(&interval, cur+int64(20*time.Millisecond))
						}
					}
					continue
				}
				n := atomic.AddInt64(&done, 1)
				mu.Lock()
				b, _ := json.Marshal(ans)
				w.Write(b)
				w.WriteByte('\n')
				mu.Unlock()
				if n%5000 == 0 {
					el := time.Since(start).Seconds()
					fmt.Printf("  %d/%d  失败 %d  %.0f 条/秒\n", n, len(jobs), atomic.LoadInt64(&fail), float64(n)/el)
				}
			}
		}()
	}
	wg.Wait()
	w.Flush()
	f.Close()
	fmt.Printf("完成：成功 %d，失败 %d，耗时 %s\n", done, fail, time.Since(start).Round(time.Second))
}

// query 查一个 IP 的 360 归属，返回 /24 + 省市县
func query(client *http.Client, ip string) (outRec, bool) {
	u := "http://ip.360.cn/IPQuery/ipquery?ip=" + ip
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0")
	req.Header.Set("Referer", "http://ip.360.cn/")
	resp, err := client.Do(req)
	if err != nil {
		return outRec{}, false
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return outRec{}, false
	}
	var w struct {
		Errno int    `json:"errno"`
		Data  string `json:"data"`
	}
	if json.Unmarshal(body, &w) != nil || w.Errno != 0 {
		return outRec{}, false
	}
	p, c, ct, isp := norm.Parse360Region(w.Data)
	if p == "" {
		return outRec{}, false
	}
	// ip.x.y.z -> x.y.z.0/24
	a := netip.MustParseAddr(ip).As4()
	return outRec{
		Prefix:   fmt.Sprintf("%d.%d.%d.0/24", a[0], a[1], a[2]),
		Province: p, City: c, County: ct, ISP: isp,
	}, true
}
