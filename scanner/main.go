// scanner —— 多源扫描填充器
//
// 对运营商公告段做区间二分，每个探针点采集多源答案（bilibili/360 远程 +
// ip2region/GeoCN/maxmind/dbip/ip2location 本地），主源签名驱动二分，
// LBS 预算制仲裁分歧，产出段表 JSONL；merge 模式把段表覆盖进 CN-LOCATION.mmdb。
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
	"sync"
	"time"

	"github.com/ip2location/ip2location-go/v9"
	ip2regionSvc "github.com/lionsoul2014/ip2region/binding/golang/service"
	maxminddb "github.com/oschwald/maxminddb-golang/v2"
	"resty.dev/v3"

	"lemondb/norm"
)

var debugBili = os.Getenv("SCAN_DEBUG") != ""

// ---------- 探针答案 ----------

type answer struct {
	Src      string `json:"src"`
	Province string `json:"province,omitempty"`
	City     string `json:"city,omitempty"`
	County   string `json:"county,omitempty"`
	ISP      string `json:"isp,omitempty"`
	Adcode   int    `json:"adcode,omitempty"`
	Extra    string `json:"extra,omitempty"`
}

// sig 二分签名；无省视为无位置信息
func (a answer) sig() string { return a.Province + "|" + a.City + "|" + a.County + "|" + a.ISP }

func (a answer) empty() bool { return a.Province == "" }

// mergeAnswer 主源为基，county-capable 源在同省前提下补县
func mergeAnswer(primary answer, others map[string]answer) answer {
	out := primary
	for _, o := range others {
		if o.County != "" && out.County == "" && o.Province == out.Province {
			out.County = o.County
		}
	}
	return out
}

// ---------- 扫描器 ----------

type scanner struct {
	biliClient *resty.Client
	i360Client *resty.Client
	lbsClient  *resty.Client
	ip2r       *ip2regionSvc.Ip2Region
	zxDB       *zxDB // ZX ipv6wry：v6 专用本地库，教育网/机构段能到区县
	geocnDB    *maxminddb.Reader
	maxmindDB  *maxminddb.Reader
	dbipDB     *maxminddb.Reader
	ip2locDB   *ip2location.DB
	division   map[int]string
	countyCity map[string]string // "县|省" → 市：只有县没有市时用来补市
	lbsKey     string
	lbsSK      string
	lbsBudget  int
	st         *state
	memo       sync.Map // 探针 IP → probeRec
	arbMemo    sync.Map // 分歧模式 → LBS 裁决
	pending    []segment
	netMu      sync.Mutex // 远程源限速锁
	outMu      sync.Mutex // 输出写锁
	mu         sync.Mutex
	lastBili   time.Time
	last360    time.Time
	biliEvery  time.Duration
	i360Every  time.Duration
	probeCount int
	lost       map[string]int  // 源 → 被 LBS 判错次数
	no360      bool            // 关掉 360（被 403 封时用，避免每个请求挂到超时）
	err360     int             // 360 连续失败计数（触发自动降速）
	i360Base   time.Duration   // 360 的基准间隔（降速后要能回到这里）
	ok360      int             // 360 连续成功计数（触发回升）
	demoted    map[string]bool // 会话内降级的源
	pfxBudget  int             // 单前缀探针预算
	pfxUsed    int             // 当前前缀已用探针数
	teo        *teoState       // 腾讯 EO 控制台通道（省级+市级，批量 100/次）
	remoteCache sync.Map       // "ip|src" → answer：普查阶段批量预取的远程单点源结果
	biliWorkers int            // bilibili 并发数（限速仍在 throttle 里，66ms/次）
	census     bool            // v4 走 TEO 采样普查（关掉则逐块探针，可用 360 拿县级）
}

func (s *scanner) throttle(last *time.Time, every time.Duration) {
	s.netMu.Lock()
	defer s.netMu.Unlock()
	if d := time.Since(*last); d < every {
		s.netMu.Unlock()
		time.Sleep(every - d)
		s.netMu.Lock()
	}
	*last = time.Now()
}

// ---------- 各源 ----------

func (s *scanner) bilibili(ip string) answer {
	key := ip + "|bilibili"
	if v, ok := s.remoteCache.Load(key); ok {
		return v.(answer)
	}
	a := s.bilibiliFetch(ip)
	s.remoteCache.Store(key, a)
	return a
}

func (s *scanner) bilibiliFetch(ip string) answer {
	s.throttle(&s.lastBili, s.biliEvery)
	var w struct {
		Code int `json:"code"`
		Data struct {
			Province string `json:"province"`
			City     string `json:"city"`
			ISP      string `json:"isp"`
		} `json:"data"`
	}
	r, err := s.biliClient.R().SetQueryParam("ip", ip).SetResult(&w).Get("https://api.live.bilibili.com/ip_service/v1/ip_service/get_ip_addr")
	if err != nil || r.IsError() || w.Code != 0 {
		if debugBili {
			fmt.Printf("[bili miss] ip=%s err=%v http=%d code=%d\n", ip, err, r.StatusCode(), w.Code)
		}
		return answer{}
	}
	return answer{Src: "bilibili", Province: norm.NormProvince(w.Data.Province), City: w.Data.City, ISP: norm.NormISP(w.Data.ISP)}
}

func (s *scanner) ip360(ip string) answer {
	if s.no360 {
		return answer{}
	}
	if net.ParseIP(ip).To4() == nil {
		return answer{} // 360 仅 v4
	}
	key := ip + "|360"
	if v, ok := s.remoteCache.Load(key); ok {
		return v.(answer)
	}
	s.throttle(&s.last360, s.i360Every)
	r, err := s.i360Client.R().SetQueryParam("ip", ip).Get("http://ip.360.cn/IPQuery/ipquery")
	if err != nil || r.IsError() {
		// 熔断降速：连续失败就把间隔拉长，避免被限流后一路空手而归还看不出来
		s.netMu.Lock()
		s.err360++
		if s.err360%20 == 0 && s.i360Every < 300*time.Millisecond {
			s.i360Every += 20 * time.Millisecond
			fmt.Println("[360 降速] 连续失败", s.err360, "次，间隔调到", s.i360Every)
		}
		s.netMu.Unlock()
		return answer{}
	}
	// 成功就慢慢把间隔降回基准：只降不升会让限流后永远停在最慢档
	s.netMu.Lock()
	s.err360 = 0
	s.ok360++
	if s.ok360%200 == 0 && s.i360Every > s.i360Base {
		s.i360Every -= 5 * time.Millisecond
		if s.i360Every < s.i360Base {
			s.i360Every = s.i360Base
		}
	}
	s.netMu.Unlock()
	var w struct {
		Errno int    `json:"errno"`
		Data  string `json:"data"`
	}
	if err := json.Unmarshal(r.Bytes(), &w); err != nil || w.Errno != 0 {
		return answer{}
	}
	p, c, ct, isp := norm.Parse360Region(w.Data)
	a := answer{Src: "360", Province: p, City: c, County: ct, ISP: isp}
	s.remoteCache.Store(key, a)
	return a
}

// remotePrefetch 普查前批量预取远程单点源：bilibili（v4/v6）+ 360（仅 v4）。
// 「宁慢也要准」：远程源必须参与投票，不能因为慢就被跳过；
// 限速仍在 bilibili 66ms/360 100ms 的 throttle 里，这里只加并发把延迟藏起来。
func (s *scanner) remotePrefetch(ips []string, v4 bool) {
	if len(ips) == 0 {
		return
	}
	n := s.biliWorkers
	if n < 1 {
		n = 8
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			s.bilibili(ip)
			if v4 {
				s.ip360(ip)
			}
		}(ip)
	}
	wg.Wait()
}

func (s *scanner) ip2region(ip string) answer {
	if s.ip2r == nil {
		return answer{}
	}
	region, err := s.ip2r.Search(ip)
	if err != nil {
		return answer{}
	}
	p, c, isp := norm.ParseIP2Region(region)
	return answer{Src: "ip2region", Province: p, City: c, ISP: isp}
}

func (s *scanner) geocn(ip string) answer {
	if s.geocnDB == nil {
		return answer{}
	}
	var rec struct {
		DivisionCode uint32 `maxminddb:"division_code"`
		ISP          string `maxminddb:"isp"`
	}
	if err := s.geocnDB.Lookup(netip.MustParseAddr(ip)).Decode(&rec); err != nil || rec.DivisionCode == 0 {
		return answer{}
	}
	code := int(rec.DivisionCode)
	// 行政区字典里是「北京市 / 江苏省」全称，统一收敛到 norm 的短名，
	// 否则与 ip2region/TEO/floor 的「北京 / 江苏」对不上，段会碎且误触发省不一致仲裁
	province := norm.NormProvince(s.division[(code/10000)*10000])
	city := s.division[(code/100)*100]
	district := s.division[code]
	if province == "" {
		return answer{}
	}
	// division 里省级只有「省/直辖市」时，city 会回落成省名（湖南 → 湖南省）。
	// 那不是市，必须清掉，否则会被当成市级精度写进库。
	if city != "" && norm.NormProvince(city) == province {
		city = ""
	}
	if district != "" && norm.NormProvince(district) == province {
		district = ""
	}
	return answer{Src: "geocn", Province: province, City: city, County: district, ISP: norm.NormISP(rec.ISP)}
}

// 英文通道：只存档
func (s *scanner) mmdbCity(db *maxminddb.Reader, src, ip string) answer {
	if db == nil {
		return answer{}
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Location struct {
			Latitude  float64 `maxminddb:"latitude"`
			Longitude float64 `maxminddb:"longitude"`
		} `maxminddb:"location"`
	}
	if err := db.Lookup(netip.MustParseAddr(ip)).Decode(&rec); err != nil || rec.Country.ISOCode != "CN" {
		return answer{}
	}
	extra := ""
	if rec.Location.Latitude != 0 {
		extra = fmt.Sprintf("%.4f,%.4f", rec.Location.Latitude, rec.Location.Longitude)
	}
	return answer{Src: src, Extra: rec.City.Names["en"] + " " + extra}
}

func md5hex(s, key string) string {
	h := md5.Sum([]byte(s + key))
	return hex.EncodeToString(h[:])
}

func (s *scanner) lbs(ip string) answer {
	if s.lbsKey == "" || s.lbsSK == "" || s.lbsBudget <= 0 {
		return answer{}
	}
	s.mu.Lock()
	s.lbsBudget--
	if s.st != nil {
		s.st.LBSUsed++
	}
	s.mu.Unlock()
	qs := "ip=" + ip + "&key=" + s.lbsKey
	sig := md5hex("/ws/location/v1/ip?"+qs, s.lbsSK)
	r, err := s.lbsClient.R().Get("https://apis.map.qq.com/ws/location/v1/ip?" + qs + "&sig=" + sig)
	if err != nil || r.IsError() {
		return answer{}
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
	if err := json.Unmarshal(r.Bytes(), &w); err != nil || w.Status != 0 {
		return answer{}
	}
	a := w.Result.AdInfo
	p := norm.NormProvince(a.Province)
	if p == "" {
		return answer{}
	}
	return answer{Src: "lbs", Province: p, City: a.City, County: a.District, Adcode: a.Adcode}
}

// ---------- 探针 ----------

type probeRec struct {
	primary answer
	all     map[string]answer
}

func (s *scanner) probe(ip string, v4 bool) (answer, map[string]answer) {
	if v, ok := s.memo.Load(ip); ok {
		a := v.(probeRec)
		return a.primary, a.all
	}
	// 远程源并行（bilibili/360 各自限速互不阻塞），本地库串行快读
	var wgR sync.WaitGroup
	var muR sync.Mutex
	all := map[string]answer{}
	primary := answer{}
	setSrc := func(a answer) {
		if a.Src == "" {
			return
		}
		muR.Lock()
		all[a.Src] = a
		if primary.Src == "" && !a.empty() {
			primary = a
		}
		muR.Unlock()
	}
	wgR.Add(1)
	go func() { defer wgR.Done(); setSrc(s.bilibili(ip)) }()
	if v4 {
		wgR.Add(1)
		go func() { defer wgR.Done(); setSrc(s.ip360(ip)) }()
	}
	wgR.Add(1)
	go func() { defer wgR.Done(); setSrc(s.geocn(ip)) }()
	if v4 {
		wgR.Add(1)
		go func() { defer wgR.Done(); setSrc(s.ip2region(ip)) }()
	} else {
		wgR.Add(1)
		go func() { defer wgR.Done(); setSrc(s.zx(ip)) }()
	}
	wgR.Wait()
	// TEO 走批量预取的缓存，不再发单点请求
	if a := s.teoLookup(ip); a.Src != "" {
		setSrc(a)
	}
	// 源优先级：
	//   v4 360(可到县) > bilibili > teo > ip2region > geocn
	//   v6 teo > zx > bilibili > geocn
	// v6 不再使用 ip2region：实测它把宿迁判成盐城（2409:8a20 段），
	// 且解析出「北京 41%」这类系统性偏差，属于会污染整库的错误源。
	pick := []string{"teo", "zx", "bilibili", "geocn"}
	if v4 {
		pick = []string{"360", "bilibili", "teo", "ip2region", "geocn"}
	}
	for _, src := range pick {
		if a, ok := all[src]; ok && !a.empty() {
			primary = a
			break
		}
	}
	// 陪跑：英文通道存档
	if a := s.mmdbCity(s.maxmindDB, "maxmind", ip); a.Src != "" {
		all["maxmind"] = a
	}
	if a := s.mmdbCity(s.dbipDB, "dbip", ip); a.Src != "" {
		all["dbip"] = a
	}
	if s.ip2locDB != nil {
		rec, err := s.ip2locDB.Get_all(ip)
		if err == nil && rec.Country_long == "China" {
			all["ip2location"] = answer{Src: "ip2location", Province: norm.NormProvince(rec.Region), Extra: rec.City}
		}
	}

	s.mu.Lock()
	s.probeCount++
	s.mu.Unlock()

	rec := probeRec{primary: primary, all: all}
	s.memo.Store(ip, rec)
	return primary, all
}

// quickAnswer 普查用的零网络成本答案：TEO 批量缓存 + GeoCN + ip2region。
// 远程单点源（bilibili/360）单次约 3 秒，普查阶段不调用。
// GeoCN 能给到县，若与主源省市一致则补县（与 probe 的 mergeAnswer 同口径）。
func (s *scanner) quickAnswer(ip string) answer {
	a, _ := s.quickAll(ip, !strings.Contains(ip, ":"))
	return a
}

// quickAll 普查采样点的「陪跑」查询：TEO 走批量预取（零额外网络），
// 本地库直接读，全部结果都要留下来存档。主源由 pick 顺序决定，
// 其余源是陪跑 —— 它们不参与定案，但提供票数和字段补全。
func (s *scanner) quickAll(ip string, v4 bool) (answer, map[string]answer) {
	all := map[string]answer{}
	if a := s.teoLookup(ip); a.Src != "" {
		all[a.Src] = a
	}
	if v4 {
		if a := s.ip2region(ip); a.Src != "" {
			all[a.Src] = a
		}
	} else {
		// v6 用 ZX ipv6wry 取代 ip2region（后者 v6 实测把宿迁判成盐城）
		if a := s.zx(ip); a.Src != "" {
			all[a.Src] = a
		}
	}
	if a := s.geocn(ip); a.Src != "" {
		all[a.Src] = a
	}
	// 远程单点源（普查前已批量预取进 remoteCache）：bilibili 双栈，360 仅 v4
	for _, src := range []string{"bilibili", "360"} {
		if v, ok := s.remoteCache.Load(ip + "|" + src); ok {
			if a := v.(answer); a.Src != "" {
				all[a.Src] = a
			}
		}
	}

	// 主源优先级（宁慢也要准）：v4 360 能到县，放最前；v6 bilibili 判得最贴近实网
	pick := []string{"bilibili", "teo", "zx", "geocn"}
	if v4 {
		pick = []string{"360", "bilibili", "teo", "ip2region", "geocn"}
	}
	var best answer
	for _, k := range pick {
		if a, ok := all[k]; ok && !a.empty() {
			best = a
			break
		}
	}
	if best.Src == "" {
		return answer{}, all
	}
	if best.County == "" {
		if g := all["geocn"]; g.County != "" && g.Province == best.Province &&
			(best.City == "" || g.City == best.City) {
			best.County = g.County
		}
	}
	// 只有县没有市（360 常见）：用行政区字典反推市
	if best.City == "" && best.County != "" {
		best.City = s.cityByCounty(best.Province, best.County)
	}
	return best, all
}

// cityByCounty 只有县/区、没有市时，用行政区字典把市反推出来。
// 360 偶尔只给「泉山区」不给「徐州市」，这种正是要靠字典补的。
func (s *scanner) cityByCounty(province, county string) string {
	if province == "" || county == "" || s.countyCity == nil {
		return ""
	}
	return s.countyCity[county+"|"+province]
}

// arbitrate 三源投票仲裁：主源之外还有源给出省级结论时，票多者定案。
// 平票保留主源（宁缺毋滥，不为了「看起来确定了」而改判）。
func (s *scanner) arbitrate(primary answer, sources map[string]answer) answer {
	if primary.Province == "" {
		return primary
	}
	votes := map[string]int{primary.Province: 1}
	bysrc := map[string]answer{}
	for k, a := range sources {
		if k == primary.Src || a.Province == "" {
			continue
		}
		votes[a.Province]++
		bysrc[a.Province] = a
	}
	top, topN := primary.Province, votes[primary.Province]
	for p, n := range votes {
		if n > topN {
			top, topN = p, n
		}
	}
	if top == primary.Province {
		return s.fillCity(primary, sources)
	}
	alt := bysrc[top]
	alt.County = primary.County // 县名沿用（新省的下级不一定同名，交给下游决定是否丢弃）
	return s.fillCity(alt, sources)
}

// 源优先级（票数打平时按这个顺序取，保证结果确定）
var srcPrio = map[string]int{"360": 1, "bilibili": 2, "teo": 3, "zx": 4, "ip2region": 5, "geocn": 6}

// fillCity 有省无市时，从「同省的陪跑源」里投票补市：票多者胜，平票按源优先级。
// 不这么补的话，主源（比如 TEO 只给省）会把陪跑源已经答出的市白白丢掉。
func (s *scanner) fillCity(primary answer, sources map[string]answer) answer {
	if primary.City != "" || primary.Province == "" {
		return primary
	}
	counts := map[string]int{}
	cand := map[string]answer{}
	for k, a := range sources {
		if k == primary.Src || a.Province != primary.Province || a.City == "" {
			continue
		}
		counts[a.City]++
		if cur, ok := cand[a.City]; !ok || srcPrio[k] < srcPrio[cur.Src] {
			cand[a.City] = a
		}
	}
	bestCity, bestN := "", 0
	for c, n := range counts {
		if n > bestN || (n == bestN && srcPrio[cand[c].Src] < srcPrio[cand[bestCity].Src]) {
			bestCity, bestN = c, n
		}
	}
	if bestCity == "" {
		return primary
	}
	a := cand[bestCity]
	primary.City = a.City
	if primary.County == "" {
		primary.County = a.County
	}
	if primary.ISP == "" {
		primary.ISP = a.ISP
	}
	return primary
}

// ---------- 区间二分 ----------

// blockAddr 前缀内第 i 个 gran 块的首地址
// 步长 = 2^(bits-gran)：块 i 起点 = base + i × 2^(bits-gran)
func blockAddr(base netip.Addr, i *big.Int, gran, prefixLen int) netip.Addr {
	width := 16
	var b []byte
	if base.Is4() {
		b4 := base.As4()
		width = 4
		b = []byte(b4[:])
	} else {
		b16 := base.As16()
		b = []byte(b16[:])
	}
	bits := width * 8
	lo := new(big.Int).SetBytes(b)
	step := new(big.Int).Lsh(i, uint(bits-gran))
	lo.Add(lo, step)
	nb := lo.Bytes()
	ip := make(net.IP, width)
	copy(ip[width-len(nb):], nb)
	addr, _ := netip.AddrFromSlice(ip)
	return addr
}

// collect 暂存段，前缀扫完统一验证落盘
func (s *scanner) collect(seg segment) {
	s.pending = append(s.pending, seg)
}

type segment struct {
	Start   string            `json:"start"`
	End     string            `json:"end"`
	Prefix  string            `json:"prefix"`
	Primary answer            `json:"primary"`
	Sources map[string]answer `json:"sources"`
	Span    *big.Int          `json:"-"` // 块数（LBS 验证优先级排序用）
}

// scanPrefix v2：底线脚手架 + 分块普查
//
// 1. 用底线库把前缀切成「已知省块 + 空洞」
// 2. 已知省块：探针只补市级（省来自底线），块数按大小分配、上限 256
// 3. 空洞：普查兜底（块数 ≤ 预算份额）
// 4. 相邻同答案块合并成段
func (s *scanner) scanPrefix(cidr string, out *bufio.Writer, v4 bool, gran int) {
	ipp, err := netip.ParsePrefix(cidr)
	if err != nil {
		return
	}
	base := ipp.Addr()
	L := ipp.Bits()
	s.pfxUsed = 0
	// TEO 缓存只服务于「当前前缀」：prefetch → 采样 → 段中点复核都在同一个前缀内完成。
	// 不清的话全量跑下来每个进程要攒几十万条 IP → answer，内存一路涨。
	if s.teo != nil {
		s.teo.cache.Clear()
	}
	// 远程源缓存同样只服务当前前缀，否则全量跑下来内存会一直涨
	s.remoteCache.Range(func(k, _ any) bool {
		s.remoteCache.Delete(k)
		return true
	})

	width := 16
	var baseBytes []byte
	if base.Is4() {
		b4 := base.As4()
		width = 4
		baseBytes = []byte(b4[:])
	} else {
		b16 := base.As16()
		baseBytes = []byte(b16[:])
	}
	bits := width * 8
	lo := new(big.Int).SetBytes(baseBytes)
	hi := new(big.Int).Add(lo, new(big.Int).Lsh(big.NewInt(1), uint(bits-L)))
	hi.Sub(hi, big.NewInt(1))

	// ---- 底线切分 ----
	type part struct {
		lo, hi   *big.Int
		province string
	}
	var parts []part
	one := big.NewInt(1)
	cursor := new(big.Int).Set(lo)
	for _, fs := range floorWithin(lo, hi) {
		fsLo, fsHi := fs.start, fs.end
		if fsLo.Cmp(lo) < 0 {
			fsLo = new(big.Int).Set(lo)
		}
		if fsHi.Cmp(hi) > 0 {
			fsHi = new(big.Int).Set(hi)
		}
		if fsHi.Cmp(fsLo) < 0 || fsHi.Cmp(cursor) < 0 {
			continue // 已覆盖过的段，跳过
		}
		if fsLo.Cmp(cursor) > 0 { // 空洞：cursor .. fsLo-1（闭区间，不能含 fsLo）
			parts = append(parts, part{new(big.Int).Set(cursor), new(big.Int).Sub(fsLo, one), ""})
		}
		// 底线段与已覆盖区间取交集，避免 floor 段自身重叠时重复普查
		sLo := new(big.Int).Set(cursor)
		if fsLo.Cmp(cursor) > 0 {
			sLo = new(big.Int).Set(fsLo)
		}
		parts = append(parts, part{sLo, new(big.Int).Set(fsHi), fs.province})
		cursor = new(big.Int).Add(fsHi, one)
	}
	if cursor.Cmp(hi) <= 0 {
		parts = append(parts, part{new(big.Int).Set(cursor), new(big.Int).Set(hi), ""})
	}

	// ---- 预算分配（按大小，单块 8~512） ----
	total := big.NewInt(0)
	for _, p := range parts {
		size := new(big.Int).Sub(p.hi, p.lo)
		size.Add(size, big.NewInt(1))
		total.Add(total, size)
	}
	share := new(big.Int).Div(total, big.NewInt(int64(s.pfxBudget)))
	if share.Sign() == 0 {
		share = big.NewInt(1)
	}

	emitPart := func(p part) {
		if p.province == "" {
			p.province = ""
		}
		// 块数：大小/份额，8~512
		n := new(big.Int).Div(p.lo, share)
		_ = n
		size := new(big.Int).Sub(p.hi, p.lo)
		size.Add(size, big.NewInt(1))
		nChunks := new(big.Int).Div(size, share)
		if nChunks.Sign() == 0 {
			nChunks = big.NewInt(1)
		}
		if nChunks.Cmp(big.NewInt(512)) > 0 {
			nChunks = big.NewInt(512)
		}
		if nChunks.Cmp(big.NewInt(8)) < 0 {
			nChunks = big.NewInt(8)
		}
		chunkSize := new(big.Int).Div(size, nChunks)
		if chunkSize.Sign() == 0 {
			chunkSize = big.NewInt(1)
		}
		// 小前缀防退化：pfxBudget 大于块总数时 share=1，/24 会被切成 256 个
		// 逐地址块（一枪一个 IP，一个 /24 烧 256 发探针，4238 个 /24 就是
		// 百万级请求）。块最小压到 32 个地址——/24 即 8 块，采样密度与主扫描
		// 「一个 /24 一格」对齐；大前缀的 chunkSize 远大于 32，不受影响。
		if chunkSize.Cmp(big.NewInt(32)) < 0 && width == 4 {
			chunkSize = big.NewInt(32)
			nChunks = new(big.Int).Div(size, chunkSize)
			if nChunks.Sign() == 0 {
				nChunks = big.NewInt(1)
			}
		}

		// ---- TEO 采样普查 ----
		// 远程源单次 3 秒时逐块探针完全不划算（一个 /24 要 13 分钟），
		// 而普查 400 个采样点只需 4 次 TEO 调用（约 2 秒），本地库零成本。
		// 代价是丢了 360 的县级精度；需要县级时用 -census=false 走分块探针。
		//
		// 注意：TEO 会话失效（cookie 过期）时**仍然走普查**——此时 quickAnswer
		// 自动退化成 geocn + ip2region 两个本地库，没有网络成本；若退回分块探针会
		// 每块 3 秒，整轮直接崩掉。
		if s.census {
			s.teoCensus(p.lo, p.hi, p.province, cidr, v4, width, gran)
			return
		}

		// ---- 块中点先全算出来，再一次性批量预取 TEO（100 IP/次）----
		var mids, ends []*big.Int
		for ci := int64(0); ; ci++ {
			clo := new(big.Int).Add(p.lo, new(big.Int).Mul(chunkSize, big.NewInt(ci)))
			if clo.Cmp(p.hi) > 0 {
				break
			}
			chi := new(big.Int).Add(clo, chunkSize)
			chi.Sub(chi, big.NewInt(1))
			if chi.Cmp(p.hi) > 0 {
				chi.Set(p.hi)
			}
			mid := new(big.Int).Add(clo, chi)
			mid.Div(mid, big.NewInt(2))
			mids = append(mids, mid)
			ends = append(ends, chi)
			if chi.Cmp(p.hi) >= 0 {
				break
			}
		}
		if s.teo != nil {
			ips := make([]string, len(mids))
			for i, m := range mids {
				ips[i] = bigIntToIP(m, width).String()
			}
			s.teoPrefetch(ips)
		}

		var prev answer
		for ci := 0; ci < len(mids); ci++ {
			chunkHi := ends[ci]
			chunkLo := new(big.Int).Set(p.lo)
			if ci > 0 {
				chunkLo = new(big.Int).Add(ends[ci-1], big.NewInt(1))
			}
			addr, _ := netip.AddrFromSlice(bigIntToIP(mids[ci], width))

			a, all := s.probe(addr.Unmap().String(), v4)
			if a.empty() && p.province != "" {
				// 探针全空：底线省名兜底
				a = answer{Src: "floor", Province: p.province}
				all["floor"] = a
			}

			if ci > 0 && prev.sig() == a.sig() && prev.Src != "floor" {
				// 与前块同答案：扩段
				if len(s.pending) > 0 {
					s.pending[len(s.pending)-1].End = startAdd(chunkHi, width).String()
				}
			} else {
				span := new(big.Int).Sub(chunkHi, chunkLo)
				span.Add(span, big.NewInt(1))
				span.Div(span, new(big.Int).Lsh(big.NewInt(1), uint(width*8-gran)))
				s.collect(segment{
					Start: startAdd(chunkLo, width).String(), End: startAdd(chunkHi, width).String(),
					Prefix: cidr, Primary: a, Sources: all, Span: span,
				})
			}
			prev = a

			if chunkHi.Cmp(p.hi) >= 0 {
				break
			}
		}
	}
	for _, p := range parts {
		emitPart(p)
	}
	s.verifyAndFlush(out)
}

// startAdd 大数 → IP 字符串（宽度感知）
func startAdd(n *big.Int, width int) net.IP {
	b := n.Bytes()
	ip := make(net.IP, width)
	copy(ip[width-len(b):], b)
	return ip
}

// segMidpoint 段中点（start/end 均为闭区间端点）
func segMidpoint(seg *segment) (netip.Addr, bool) {
	sa, e1 := netip.ParseAddr(seg.Start)
	ea, e2 := netip.ParseAddr(seg.End)
	if e1 != nil || e2 != nil {
		return netip.Addr{}, false
	}
	width := 4
	if !sa.Is4() {
		width = 16
	}
	mid := new(big.Int).Add(addrToBig(sa.Unmap()), addrToBig(ea.Unmap()))
	mid.Div(mid, big.NewInt(2))
	addr, ok := netip.AddrFromSlice(bigIntToIP(mid, width))
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// verifyAndFlush 段收集完毕：先批量用 TEO 验段中点（免费、100 IP/次），
// TEO 无结果的段再用 LBS 兜底（预算制）。之后全部落盘。
//
// 仲裁规则（宁缺毋滥）：
//   - 省不一致 → 以 TEO 定案（TEO 省级实测准）
//   - 市不一致 → 只有原本没市（floor 兜底）时才采纳 TEO，其余仅记录不覆盖
func (s *scanner) verifyAndFlush(out *bufio.Writer) {
	if len(s.pending) == 0 {
		return
	}
	// 不同 floor part / 空洞会切出首尾相接、答案完全一致的段，先合并再验证。
	// pending 在此前是按地址顺序产出的，所以线性合并即可。
	merged := make([]segment, 0, len(s.pending))
	for _, seg := range s.pending {
		if n := len(merged); n > 0 {
			last := &merged[n-1]
			if last.Prefix == seg.Prefix && last.Primary.sig() == seg.Primary.sig() && adjacentSeg(*last, seg) {
				last.End = seg.End
				if last.Span != nil && seg.Span != nil {
					last.Span = new(big.Int).Add(last.Span, seg.Span)
				}
				continue
			}
		}
		merged = append(merged, seg)
	}
	s.pending = merged

	sort.Slice(s.pending, func(i, j int) bool {
		if s.pending[i].Span == nil {
			return false
		}
		if s.pending[j].Span == nil {
			return true
		}
		return s.pending[i].Span.Cmp(s.pending[j].Span) > 0
	})

	// 候选段中点一次性批量预取 TEO
	var mids []string
	for i := range s.pending {
		seg := &s.pending[i]
		if seg.Span != nil && seg.Span.Cmp(big.NewInt(4)) > 0 && !seg.Primary.empty() {
			if a, ok := segMidpoint(seg); ok {
				mids = append(mids, a.String())
			}
		}
	}
	if s.teo != nil && len(mids) > 0 {
		s.teoPrefetch(mids)
	}

	s.outMu.Lock()
	defer s.outMu.Unlock()
	for i := range s.pending {
		seg := &s.pending[i]
		if seg.Span != nil && seg.Span.Cmp(big.NewInt(4)) > 0 && !seg.Primary.empty() {
			if addr, ok := segMidpoint(seg); ok {
				ip := addr.String()
				verified := false
				// 段太大时中点结论不足以代表整段（v6 粗格一段就是 2^98 个地址），
				// 只记录不覆盖，避免一个采样点改写一整片。
				tooBig := seg.Span == nil || seg.Span.Cmp(big.NewInt(65536)) > 0
				if tv := s.teoLookup(ip); tv.Src != "" {
					seg.Sources["teo_verify"] = tv
					if !tooBig {
						switch {
						case seg.Primary.Src != "teo" && tv.Province != "" && tv.Province != seg.Primary.Province:
							tv.County = seg.Primary.County
							seg.Primary = tv // 主源不是 TEO：TEO 作为独立仲裁者定案
						case seg.Primary.Src != "teo" && tv.City != "" && seg.Primary.City == "":
							tv.County = seg.Primary.County
							seg.Primary = tv // 原本没市：补市
						case seg.Primary.Src == "teo" && tv.Province != "" && tv.Province != seg.Primary.Province:
							// 主源就是 TEO，自己复核自己不算仲裁，只标记冲突留给下游
							seg.Sources["teo_conflict"] = tv
						}
					}
					verified = seg.Primary.Src == "teo" || tooBig || tv.Province == seg.Primary.Province
				}
				// —— 市级/县级补全：段中点专门再问一次「市级精度」的源 ——
				// 采样点格宽 /16~/>/36 时中点落点可能正好在 TEO 的空档，导致有省无市；
				// bilibili 只要 80ms 且是市级精度，值得为每个缺市段单独补一针。
				if !tooBig && seg.Primary.Province != "" && seg.Primary.City == "" {
					for _, cand := range []answer{s.bilibili(ip), s.ip360(ip)} {
						if cand.Src == "" || cand.City == "" || cand.Province != seg.Primary.Province {
							continue
						}
						seg.Sources[cand.Src+"_city"] = cand
						seg.Primary.City = cand.City
						seg.Primary.County = cand.County // 市县同源，保证不自相矛盾
						if seg.Primary.ISP == "" {
							seg.Primary.ISP = cand.ISP
						}
						break
					}
				}
				// 有市缺县：360 是唯一能到县的源（仅 v4），同省同市才采信
				if !tooBig && seg.Primary.City != "" && seg.Primary.County == "" {
					if c := s.ip360(ip); c.County != "" && c.Province == seg.Primary.Province &&
						(c.City == "" || c.City == seg.Primary.City) {
						seg.Sources["360_county"] = c
						seg.Primary.County = c.County
					}
				}
				// 兜底：任何情况下「有县无市」都用字典补市，避免库里出现「江苏 泉山区」这种残记录
				if seg.Primary.City == "" && seg.Primary.County != "" {
					if ct := s.cityByCounty(seg.Primary.Province, seg.Primary.County); ct != "" {
						seg.Primary.City = ct
					}
				}
				if !verified && s.lbsBudget > 0 {
					if lb := s.lbs(ip); lb.Src != "" {
						seg.Sources["lbs"] = lb
						if lb.City != "" && seg.Primary.City != "" && lb.City != seg.Primary.City {
							lb.County = seg.Primary.County
							seg.Primary = lb // 验证不符：LBS 定案
						}
					}
				}
			}
		}
		b, _ := json.Marshal(*seg)
		out.Write(b)
		out.WriteByte(10)
	}
	s.pending = s.pending[:0]
}

// ---------- 底线脚手架 ----------
//
// floor.jsonl 是「粗段套细段」的嵌套结构：23 万条里 21.8 万条的 end 不是单调递增，
// 直接在 end 上二分必然失效（会从错误的索引开扫、漏掉整段）。所以先做一次扫描线
// 归并，把嵌套/重叠压成互不重叠的片段，每个坐标点取「最内层」（start 最大、同 start
// 取 end 最小）的省名；之后查询就是在 start 上的普通二分。

type floorPiece struct {
	start, end *big.Int
	province   string
}

var floorPieces []floorPiece
var floorCount int

func loadFloor(path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Println("floor:", err)
		return
	}
	defer f.Close()

	floorPieces = floorPieces[:0]
	floorCount = 0

	type rawSeg struct {
		s, e     *big.Int
		province string
	}
	var raw []rawSeg
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var d struct {
			Start, End, Province, Iso, En string
		}
		if json.Unmarshal(sc.Bytes(), &d) != nil || d.Province == "" {
			continue
		}
		sa, e1 := netip.ParseAddr(d.Start)
		ea, e2 := netip.ParseAddr(d.End)
		if e1 != nil || e2 != nil {
			continue
		}
		sv, ev := addrToBig(sa.Unmap()), addrToBig(ea.Unmap())
		if sv.Cmp(ev) > 0 {
			continue
		}
		raw = append(raw, rawSeg{sv, ev, norm.NormProvince(d.Province)})
	}
	floorCount = len(raw)
	if len(raw) == 0 {
		return
	}

	// start 升序；同 start 时 end 降序（大段在前，便于扫描线判定最内层）
	sort.Slice(raw, func(i, j int) bool {
		if c := raw[i].s.Cmp(raw[j].s); c != 0 {
			return c < 0
		}
		return raw[i].e.Cmp(raw[j].e) > 0
	})

	// 事件点：start 进入、end+1 退出
	type ev struct {
		p   *big.Int
		add bool
		idx int
	}
	evs := make([]ev, 0, len(raw)*2)
	one := big.NewInt(1)
	for i := range raw {
		evs = append(evs, ev{raw[i].s, true, i})
		evs = append(evs, ev{new(big.Int).Add(raw[i].e, one), false, i})
	}
	sort.Slice(evs, func(i, j int) bool {
		if c := evs[i].p.Cmp(evs[j].p); c != 0 {
			return c < 0
		}
		return !evs[i].add && evs[j].add // 同一坐标先退出再进入
	})

	active := map[int]bool{}
	innermost := func() int {
		best := -1
		for i := range active {
			if best < 0 {
				best = i
				continue
			}
			c := raw[i].s.Cmp(raw[best].s)
			if c == 0 {
				c = raw[best].e.Cmp(raw[i].e) // end 更小的更内层
			}
			if c > 0 || (c == 0 && i < best) { // 完全相同则按索引，保证结果确定
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
		bi := innermost()
		if bi < 0 || raw[bi].province == "" {
			continue
		}
		end := new(big.Int).Sub(evs[k].p, one) // 片段 [p, 下一个事件点-1]
		// 相邻同省片段直接合并，压低片段数
		if n := len(floorPieces); n > 0 {
			last := &floorPieces[n-1]
			if last.province == raw[bi].province &&
				new(big.Int).Add(last.end, one).Cmp(p) == 0 {
				last.end = end
				continue
			}
		}
		floorPieces = append(floorPieces, floorPiece{new(big.Int).Set(p), end, raw[bi].province})
	}
	fmt.Printf("floor 脚手架: %d 段 → %d 互斥片段\n", floorCount, len(floorPieces))
}

// floorWithin 返回与 [lo,hi] 相交的片段（片段互不重叠且按 start 升序，end 单调）
func floorWithin(lo, hi *big.Int) []floorPiece {
	i := sort.Search(len(floorPieces), func(i int) bool {
		return floorPieces[i].end.Cmp(lo) >= 0
	})
	var out []floorPiece
	for ; i < len(floorPieces); i++ {
		if floorPieces[i].start.Cmp(hi) > 0 {
			break
		}
		out = append(out, floorPieces[i])
	}
	return out
}

// ---------- 状态与主流程 ----------

type state struct {
	Done    map[string]bool `json:"done"`
	LBSUsed int             `json:"lbs_used"`
	Day     string          `json:"day"`
}

func loadState(p string) *state {
	st := &state{Done: map[string]bool{}, Day: time.Now().Format("2006-01-02")}
	if b, err := os.ReadFile(p); err == nil {
		json.Unmarshal(b, st)
	}
	if st.Day != time.Now().Format("2006-01-02") {
		st.LBSUsed = 0
		st.Day = time.Now().Format("2006-01-02")
	}
	return st
}

func (st *state) save(p string) {
	b, _ := json.MarshalIndent(st, "", " ")
	// 先写临时文件再改名：扫描器被 kill 时若直接覆盖，可能留下半截 JSON，
	// loadState 解析失败会静默当空状态 → 整轮重扫、产出重复段。
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0644) != nil {
		return
	}
	os.Rename(tmp, p)
}

func loadDivision(path string) map[int]string {
	m := map[int]string{}
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "\t", 2)
		if len(parts) == 2 {
			var code int
			fmt.Sscanf(parts[0], "%d", &code)
			if fields := strings.Fields(parts[1]); len(fields) > 0 {
				m[code] = fields[0]
			}
		}
	}
	return m
}

func mustConfig(path string, v6 bool) *ip2regionSvc.Config {
	var c *ip2regionSvc.Config
	var err error
	if v6 {
		c, err = ip2regionSvc.NewV6Config(ip2regionSvc.VIndexCache, path, 20)
	} else {
		c, err = ip2regionSvc.NewV4Config(ip2regionSvc.VIndexCache, path, 20)
	}
	if err != nil {
		panic(err)
	}
	return c
}

func main() {
	dbs := flag.String("dbs", "dbs", "本地库目录")
	v4list := flag.String("v4list", "", "v4 公告段列表（默认取 -dbs/china.txt）")
	v6list := flag.String("v6list", "", "v6 公告段列表（默认取 -dbs/china6.txt）")
	out := flag.String("out", "segments.jsonl", "")
	stateF := flag.String("state", "scan-state.json", "")
	lbsKey := flag.String("lbs-key", "", "")
	lbsSK := flag.String("lbs-sk", "", "")
	lbsBudget := flag.Int("lbs-budget", 5500, "LBS 每日预算")
	limit := flag.Int("limit", 0, "仅扫描前 N 个前缀（烟囱测试）")
	prefixes := flag.String("prefix", "", "逗号分隔的指定前缀（烟囱测试）")
	only := flag.String("only", "", "v4 / v6，空=先 v6 后 v4")
	maxMin := flag.Int("max-minutes", 300, "最长运行分钟数")
	pfxBudget := flag.Int("prefix-budget", 2500, "单前缀探针预算（超限粗普查兜底）")
	teoConfPath := flag.String("teo-conf", "../teo-conf.json", "TEO 控制台会话凭据（不填=不用该源）")
	doneExtra := flag.String("done-extra", "", "额外读取这些状态文件的已完成前缀（逗号分隔）")
	biliWorkers := flag.Int("bili-workers", 10, "远程源并发数；12 个进程共用一条出口 IP，调大反而被限流")
	censusOn := flag.Bool("census", true, "v4 用 TEO 采样普查（关掉走逐块探针，能拿 360 县级）")
	gap360 := flag.Duration("360-gap", 40*time.Millisecond, "360 查询基准间隔（被限流后调大）")
	no360 := flag.Bool("no-360", false, "跳过 360（被 403 封时避免请求挂到超时）")
	shard := flag.String("shard", "", "分片 i/n（按列表行号取模，多进程并行用）")
	flag.Parse()

	// 分片：多进程各跑 i/n，前缀互不重叠，产出直接拼接即可
	shardIdx, shardN := 0, 1
	if *shard != "" {
		var i, n int
		if _, err := fmt.Sscanf(*shard, "%d/%d", &i, &n); err == nil && n > 0 && i >= 0 && i < n {
			shardIdx, shardN = i, n
		} else {
			fmt.Println("分片参数无效，忽略:", *shard)
		}
	}

	if *v4list == "" {
		*v4list = *dbs + "/china.txt"
	}
	if *v6list == "" {
		*v6list = *dbs + "/china6.txt"
	}

	s := &scanner{
		lbsKey: *lbsKey, lbsSK: *lbsSK,
		biliClient: resty.New().SetTimeout(10*time.Second).SetHeader("User-Agent", "Mozilla/5.0"),
		i360Client: resty.New().SetTimeout(10*time.Second).SetHeader("User-Agent", "Mozilla/5.0").SetHeader("Referer", "http://ip.360.cn/"),
		lbsClient:  resty.New().SetTimeout(10 * time.Second),
		biliEvery:  30 * time.Millisecond, i360Every: *gap360,
		i360Base: *gap360,
		no360: *no360,
		biliWorkers: *biliWorkers,
		pfxBudget: *pfxBudget,
		census:    *censusOn,
	}
	var err error
	s.ip2r, err = ip2regionSvc.NewIp2Region(mustConfig(*dbs+"/ip2region_v4.xdb", false), mustConfig(*dbs+"/ip2region_v6.xdb", true))
	if err != nil {
		fmt.Println("ip2region:", err)
	}
	if s.geocnDB, err = maxminddb.Open(*dbs + "/GeoCN.mmdb"); err != nil {
		s.geocnDB = nil
	}
	if s.maxmindDB, err = maxminddb.Open(*dbs + "/GeoLite2-City.mmdb"); err != nil {
		s.maxmindDB = nil
	}
	if s.dbipDB, err = maxminddb.Open(*dbs + "/dbip-city-lite.mmdb"); err != nil {
		s.dbipDB = nil
	}
	if s.ip2locDB, err = ip2location.OpenDB(*dbs + "/IP2LOCATION-LITE-DB11.IPV6.BIN"); err != nil {
		s.ip2locDB = nil
	}
	if z, err := openZX(*dbs + "/ipv6wry.db"); err != nil {
		fmt.Println("ipv6wry:", err)
	} else {
		s.zxDB = z
		fmt.Printf("ZX ipv6wry 就绪: %d 条记录\n", z.count)
	}

	st := loadState(*stateF)
	// 追加读取其他分片的状态：v6 跑完后要把 6 个进程挪去 v4，
	// 不共享 done 集合就会互相重扫同一批前缀。
	if *doneExtra != "" {
		for _, extra := range strings.Split(*doneExtra, ",") {
			extra = strings.TrimSpace(extra)
			if extra == "" {
				continue
			}
			var o state
			if b, err := os.ReadFile(extra); err == nil && json.Unmarshal(b, &o) == nil {
				for k := range o.Done {
					st.Done[k] = true
				}
			}
		}
	}
	s.st = st
	s.lbsBudget = *lbsBudget - st.LBSUsed
	if s.lbsBudget < 0 {
		s.lbsBudget = 0
	}

	loadFloor("../floor.jsonl")

	s.teoInit(*teoConfPath)

	s.division = loadDivision(*dbs + "/full.txt")
	// 县 → 市 反查（带省名做键，避免「朝阳区」这种跨省同名）
	s.countyCity = map[string]string{}
	for code, name := range s.division {
		pc, cc := code/10000*10000, code/100*100
		if code == pc || code == cc {
			continue // 省/市本级跳过，只收区县
		}
		cityName, provName := s.division[cc], s.division[pc]
		prov := norm.NormProvince(provName)
		if cityName == "" || prov == "" || cityName == provName {
			continue
		}
		s.countyCity[name+"|"+prov] = cityName
	}
	fmt.Printf("本地库就绪: ip2region=%v geocn=%v maxmind=%v dbip=%v ip2loc=%v division=%d | floor=%d段/%d片段\n",
		s.ip2r != nil, s.geocnDB != nil, s.maxmindDB != nil, s.dbipDB != nil, s.ip2locDB != nil, len(s.division), floorCount, len(floorPieces))

	granFor := func(cidr string) int {
		if strings.Contains(cidr, ":") {
			return 48
		}
		return 24
	}

	of, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer of.Close()
	w := bufio.NewWriter(of)
	defer w.Flush()

	deadline := time.Now().Add(time.Duration(*maxMin) * time.Minute)
	runList := func(path string, v4 bool) {
		pf, err := os.Open(path)
		if err != nil {
			return
		}
		defer pf.Close()
		sc := bufio.NewScanner(pf)
		n := 0
		row := 0
		for sc.Scan() {
			cidr := strings.TrimSpace(sc.Text())
			// 分片必须按「文件行号」算，不能按「未完成行号」算：
			// 断点续跑时已完成的行会被跳过，用过滤后的行号会让分片整体错位，
			// 导致各分片互相越界重扫（实测 v6 因此被扫了 4480 个，超过列表总数）。
			idx := row
			row++
			if cidr == "" || st.Done[cidr] {
				continue
			}
			if shardN > 1 && idx%shardN != shardIdx {
				continue
			}
			n++
			if *limit > 0 && n > *limit {
				break
			}
			if time.Now().After(deadline) {
				fmt.Println("到达时间上限，落盘退出")
				break
			}
			s.scanPrefix(cidr, w, v4, granFor(cidr))
			st.Done[cidr] = true
			if n%20 == 0 {
				w.Flush()
				st.save(*stateF)
				logLine := fmt.Sprintf("进度: %s 完成 %d 前缀 (探针 %d, LBS %d/%d)", map[bool]string{true: "v4", false: "v6"}[v4], n, s.probeCount, st.LBSUsed, *lbsBudget)
				fmt.Println(logLine)
			}
		}
		w.Flush()
		st.save(*stateF)
	}

	if *prefixes != "" {
		for _, cidr := range strings.Split(*prefixes, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" || st.Done[cidr] {
				continue
			}
			v4 := !strings.Contains(cidr, ":")
			s.scanPrefix(cidr, w, v4, granFor(cidr))
			st.Done[cidr] = true
			w.Flush()
			st.save(*stateF)
		}
	} else {
		switch *only {
		case "v4":
			runList(*v4list, true)
		case "v6":
			runList(*v6list, false)
		default:
			runList(*v6list, false)
			runList(*v4list, true)
		}
	}
	st.save(*stateF)
	fmt.Println("扫描结束: 探针", s.probeCount, "LBS", st.LBSUsed)
}

// adjacentSeg 判断两段是否首尾相接（a.end + 1 == b.start）
func adjacentSeg(a, b segment) bool {
	ea, e1 := netip.ParseAddr(a.End)
	sb, e2 := netip.ParseAddr(b.Start)
	if e1 != nil || e2 != nil || ea.Is4() != sb.Is4() {
		return false
	}
	return new(big.Int).Add(addrToBig(ea.Unmap()), big.NewInt(1)).Cmp(addrToBig(sb.Unmap())) == 0
}
