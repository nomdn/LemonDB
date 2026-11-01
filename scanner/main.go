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

	"cnipdb/norm"
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
	geocnDB    *maxminddb.Reader
	maxmindDB  *maxminddb.Reader
	dbipDB     *maxminddb.Reader
	ip2locDB   *ip2location.DB
	division   map[int]string
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
	demoted    map[string]bool // 会话内降级的源
	pfxBudget  int             // 单前缀探针预算
	pfxUsed    int             // 当前前缀已用探针数
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
	if net.ParseIP(ip).To4() == nil {
		return answer{} // 360 仅 v4
	}
	s.throttle(&s.last360, s.i360Every)
	r, err := s.i360Client.R().SetQueryParam("ip", ip).Get("http://ip.360.cn/IPQuery/ipquery")
	if err != nil || r.IsError() {
		return answer{}
	}
	var w struct {
		Errno int    `json:"errno"`
		Data  string `json:"data"`
	}
	if err := json.Unmarshal(r.Bytes(), &w); err != nil || w.Errno != 0 {
		return answer{}
	}
	p, c, ct, isp := norm.Parse360Region(w.Data)
	return answer{Src: "360", Province: p, City: c, County: ct, ISP: isp}
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
	province := s.division[(code/10000)*10000]
	city := s.division[(code/100)*100]
	district := s.division[code]
	if province == "" {
		return answer{}
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
	go func() { defer wgR.Done(); setSrc(s.ip2region(ip)) }()
	wgR.Add(1)
	go func() { defer wgR.Done(); setSrc(s.geocn(ip)) }()
	wgR.Wait()
	// 主源优先级：v4 360(县) > bilibili > ip2region > geocn；v6 bilibili > geocn > ip2region
	pick := []string{"bilibili", "ip2region", "geocn"}
	if v4 {
		pick = []string{"360", "bilibili", "ip2region", "geocn"}
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
	cursor := new(big.Int).Set(lo)
	for _, fs := range floorWithin(lo, hi) {
		fsLo, fsHi := fs.start, fs.end
		if fsLo.Cmp(lo) < 0 {
			fsLo = new(big.Int).Set(lo)
		}
		if fsHi.Cmp(hi) > 0 {
			fsHi = new(big.Int).Set(hi)
		}
		if fsLo.Cmp(cursor) > 0 { // 空洞
			parts = append(parts, part{new(big.Int).Set(cursor), new(big.Int).Set(fsLo), ""})
		}
		if fsLo.Cmp(cursor) >= 0 {
			parts = append(parts, part{new(big.Int).Set(fsLo), new(big.Int).Set(fsHi), fs.province})
			cursor = new(big.Int).Set(fsHi)
		}
	}
	if cursor.Cmp(hi) < 0 {
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

		var prev answer
		chunkLo := new(big.Int).Set(p.lo)
		for ci := int64(0); ; ci++ {
			chunkHi := new(big.Int).Add(chunkLo, chunkSize)
			chunkHi.Sub(chunkHi, big.NewInt(1))
			if chunkHi.Cmp(p.hi) > 0 {
				chunkHi.Set(p.hi)
			}
			// 块中点探针
			mid := new(big.Int).Add(chunkLo, chunkHi)
			mid.Div(mid, big.NewInt(2))
			mb := mid.Bytes()
			midIP := make(net.IP, width)
			copy(midIP[width-len(mb):], mb)
			addr, _ := netip.AddrFromSlice(midIP)

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
				s.collect(segment{
					Start: startAdd(chunkLo, width).String(), End: startAdd(chunkHi, width).String(),
					Prefix: cidr, Primary: a, Sources: all,
				})
			}
			prev = a

			if chunkHi.Cmp(p.hi) >= 0 {
				break
			}
			chunkLo.Add(chunkHi, big.NewInt(1))
			if s.probeCount > 1<<30 {
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

// verifyAndFlush 段收集完毕：按跨度从大到小对段中点做 LBS 验证（预算制），
// 之后全部落盘。未验证段保留主源答案原样。
func (s *scanner) verifyAndFlush(out *bufio.Writer) {
	if len(s.pending) == 0 {
		return
	}
	sort.Slice(s.pending, func(i, j int) bool {
		return s.pending[i].Span.Cmp(s.pending[j].Span) > 0
	})
	s.outMu.Lock()
	defer s.outMu.Unlock()
	for i := range s.pending {
		seg := &s.pending[i]
		if s.lbsBudget > 0 && seg.Span != nil && seg.Span.Cmp(big.NewInt(4)) > 0 && !seg.Primary.empty() {
			sa, e1 := netip.ParseAddr(seg.Start)
			ea, e2 := netip.ParseAddr(seg.End)
			if e1 == nil && e2 == nil {
				var sab, eab []byte
				if sa.Is4() {
					b4 := sa.As4()
					sab = []byte(b4[:])
				} else {
					b16 := sa.As16()
					sab = []byte(b16[:])
				}
				if ea.Is4() {
					b4 := ea.As4()
					eab = []byte(b4[:])
				} else {
					b16 := ea.As16()
					eab = []byte(b16[:])
				}
				mid := new(big.Int).Add(new(big.Int).SetBytes(sab), new(big.Int).SetBytes(eab))
				mid.Div(mid, big.NewInt(2))
				mb := mid.Bytes()
				midIP := make(net.IP, 16)
				copy(midIP[16-len(mb):], mb)
				addr, _ := netip.AddrFromSlice(midIP)
				if lb := s.lbs(addr.Unmap().String()); lb.Src != "" {
					seg.Sources["lbs"] = lb
					if lb.City != "" && seg.Primary.City != "" && lb.City != seg.Primary.City {
						lb.County = seg.Primary.County
						seg.Primary = lb // 验证不符：LBS 定案
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

type floorSeg struct {
	start, end *big.Int
	province   string
	iso, en    string
}

var floorSegs []floorSeg

func loadFloor(path string) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Println("floor:", err)
		return
	}
	defer f.Close()
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
		floorSegs = append(floorSegs, floorSeg{
			start: new(big.Int).SetBytes(sb), end: new(big.Int).SetBytes(eb),
			province: d.Province, iso: d.Iso, en: d.En,
		})
	}
	sort.Slice(floorSegs, func(i, j int) bool { return floorSegs[i].start.Cmp(floorSegs[j].start) < 0 })
	fmt.Println("floor 脚手架:", len(floorSegs))
}

// floorWithin 返回与 [lo,hi] 相交的底线段（lo/hi 为 16 字节大数）
func floorWithin(lo, hi *big.Int) []floorSeg {
	// 二分找第一个 end >= lo 的段
	i := sort.Search(len(floorSegs), func(i int) bool {
		return floorSegs[i].end.Cmp(lo) >= 0
	})
	var out []floorSeg
	for ; i < len(floorSegs); i++ {
		if floorSegs[i].start.Cmp(hi) > 0 {
			break
		}
		out = append(out, floorSegs[i])
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
	os.WriteFile(p, b, 0644)
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
	flag.Parse()

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
		biliEvery:  66 * time.Millisecond, i360Every: 100 * time.Millisecond,
		pfxBudget: *pfxBudget,
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

	st := loadState(*stateF)
	s.st = st
	s.lbsBudget = *lbsBudget - st.LBSUsed
	if s.lbsBudget < 0 {
		s.lbsBudget = 0
	}

	loadFloor("../floor.jsonl")

	s.division = loadDivision(*dbs + "/full.txt")
	fmt.Printf("本地库就绪: ip2region=%v geocn=%v maxmind=%v dbip=%v ip2loc=%v division=%d | floor=%d\n",
		s.ip2r != nil, s.geocnDB != nil, s.maxmindDB != nil, s.dbipDB != nil, s.ip2locDB != nil, len(s.division), len(floorSegs))

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
		for sc.Scan() {
			cidr := strings.TrimSpace(sc.Text())
			if cidr == "" || st.Done[cidr] {
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
