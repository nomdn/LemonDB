// teo.go —— 腾讯 EO 控制台 DescribeIPRegion（siaas 通道）
//
// 这条通道是控制台内部接口，返回「中国 江苏省 宿迁市 中国移动」三级归属，
// v4/v6 都准，批量上限 100 IP/次，实测 4 并发约 800 IP/s、无限流报错。
// 它没有 LBS 那种每日配额，所以承担两件事：
//  1. 作为探针常驻源（走批量预取，单点查询只读缓存，不阻塞探针链路）
//  2. 作为段验证仲裁源，替代 LBS（LBS 降级为 TEO 无结果时的兜底）
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"resty.dev/v3"

	"lemondb/norm"
)

// teoConf 会话凭据（从控制台 Copy as cURL 里抄，会过期）
type teoConf struct {
	Cookie string `json:"cookie"`
	Csrf   string `json:"csrf"`
	T      string `json:"t"`
	Uin    string `json:"uin"`
}

type teoState struct {
	client *resty.Client
	conf   teoConf
	cache  sync.Map // ip → answer
	mu     sync.Mutex
	last   time.Time
	every  time.Duration
	calls  int
	ips    int
	errs   int
	dead   bool // 会话失效后不再尝试
}

func loadTeoConf(path string) (teoConf, error) {
	var c teoConf
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Uin == "" {
		c.Uin = "100039561594"
	}
	return c, nil
}

func (s *scanner) teoInit(path string) {
	if path == "" {
		return
	}
	c, err := loadTeoConf(path)
	if err != nil {
		fmt.Println("teo:", err, "(跳过)")
		return
	}
	s.teo = &teoState{
		client: resty.New().SetTimeout(25 * time.Second),
		conf:   c,
		every:  12 * time.Millisecond, // 批量口径下这点间隔即可，实测无限制
	}
	fmt.Println("teo: 通道就绪 (uin", c.Uin, ")")
}

// teoBatchOnce 一次 HTTP 调用，最多 100 个 IP；返回 ip → answer（无归属的 IP 不出现在结果里）
func (t *teoState) batchOnce(ips []string) (map[string]answer, error) {
	url := "https://siaas.cloud.tencent.com/cgi/capi?i=teo/DescribeIPRegion" +
		"&uin=" + t.conf.Uin + "&csrfCode=" + t.conf.Csrf + "&sign=v3&t=" + t.conf.T
	body := map[string]any{
		"cgi": "/cgi/capi", "action": "DescribeIPRegion", "serviceType": "teo",
		"clientName": "teo", "sign": "v3",
		"data": map[string]any{
			"Version": "2022-09-01", "Language": "zh-CN", "Region": "ap-guangzhou",
			"IPs": ips, "Action": "DescribeIPRegion",
		},
		"region": "ap-guangzhou",
	}
	resp, err := t.client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Accept", "application/json, text/plain, */*").
		SetHeader("Origin", "https://console.cloud.tencent.com").
		SetHeader("Referer", "https://console.cloud.tencent.com/edgeone/ip").
		SetHeader("Cookie", t.conf.Cookie).
		SetBody(body).
		Post(url)
	if err != nil {
		return nil, err
	}
	// resty 的 SetResult 有过 body 正确但结构体空的历史问题，一律手动 Unmarshal
	var raw struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Response struct {
				IPRegionInfo []struct {
					IP     string `json:"IP"`
					Region string `json:"Region"`
				} `json:"IPRegionInfo"`
			} `json:"Response"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp.Bytes(), &raw); err != nil {
		return nil, fmt.Errorf("teo 响应解析失败: %v", err)
	}
	if raw.Code != 0 {
		return nil, fmt.Errorf("teo 会话失效: code=%d %s", raw.Code, raw.Message)
	}
	out := make(map[string]answer, len(raw.Data.Response.IPRegionInfo))
	for _, it := range raw.Data.Response.IPRegionInfo {
		if debugTeo {
			fmt.Printf("[teo raw] %q → %q\n", it.IP, it.Region)
		}
		if a := parseTEORegion(it.Region); a.Src != "" {
			out[it.IP] = a
		}
	}
	return out, nil
}

var debugTeo = os.Getenv("TEO_DEBUG") != ""

// parseTEORegion 解析 "中国 江苏省 宿迁市 中国移动" / "中国 北京市 中国移动" / "中国 未知 未知 saiyutech.cn"
//
// TEO 的字段数不固定：有市级时 4 段，没有市级时 3 段（第 3 段直接是运营商）。
// 第 3 段必须判断是「市」还是「运营商」，否则会出现"中国移动市"这种脏数据。
func parseTEORegion(region string) answer {
	f := strings.Fields(region)
	if len(f) < 2 {
		return answer{}
	}
	province := norm.NormProvince(f[1])
	if province == "" {
		return answer{} // "未知" 或域名回落，整条丢弃
	}
	a := answer{Src: "teo", Province: province}
	if len(f) >= 3 && f[2] != "未知" {
		if isCityToken(f[2]) {
			a.City = f[2]
		} else if isp := norm.NormISP(f[2]); isp != "" {
			a.ISP = isp // 3 段格式：第 3 段是运营商
		} else {
			a.Extra = f[2]
		}
	}
	if len(f) >= 4 && f[3] != "未知" {
		if isp := norm.NormISP(f[3]); isp != "" {
			a.ISP = isp
		} else if a.Extra == "" {
			a.Extra = f[3]
		}
	}
	return a
}

// isCityToken 判断一段文本是不是城市名（地级市/自治州/盟/地区）
func isCityToken(s string) bool {
	if s == "" {
		return false
	}
	for _, suf := range []string{"市", "州", "盟", "地区"} {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}


func (t *teoState) throttle() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if d := time.Since(t.last); d < t.every {
		time.Sleep(t.every - d)
	}
	t.last = time.Now()
}

// prefetch 批量预取：把未缓存的 IP 按 100 一组灌进缓存。
// 注意：单次超过 100 个 IP 服务端会「静默返回空数组」而不是报错，必须自己切批。
func (s *scanner) teoPrefetch(ips []string) {
	t := s.teo
	if t == nil || t.dead || len(ips) == 0 {
		return
	}
	var todo []string
	for _, ip := range ips {
		if _, ok := t.cache.Load(ip); !ok {
			todo = append(todo, ip)
		}
	}
	for i := 0; i < len(todo); i += 100 {
		end := i + 100
		if end > len(todo) {
			end = len(todo)
		}
		chunk := todo[i:end]
		t.throttle()
		res, err := t.batchOnce(chunk)
		t.mu.Lock()
		t.calls++
		t.ips += len(chunk)
		if err != nil {
			t.errs++
			t.mu.Unlock()
			if strings.Contains(err.Error(), "会话失效") {
				t.dead = true
				fmt.Println("teo 通道失效，本次扫描不再使用:", err)
				return
			}
			continue
		}
		t.mu.Unlock()
		for _, ip := range chunk {
			if a, ok := res[ip]; ok {
				t.cache.Store(ip, a)
			} else {
				t.cache.Store(ip, answer{}) // 负缓存，避免重复问
			}
		}
	}
}

// teo 只读缓存；没预取到就返回空（保证探针链路不被单点 HTTP 拖慢）
func (s *scanner) teoLookup(ip string) answer {
	if s.teo == nil {
		return answer{}
	}
	if v, ok := s.teo.cache.Load(ip); ok {
		a, _ := v.(answer)
		return a
	}
	return answer{}
}
