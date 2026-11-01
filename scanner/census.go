// census.go —— TEO 驱动的采样普查
//
// 传统做法对每个 gran 块中点都发远程探针，而 bilibili/360 现在单次 3 秒（实测），
// 一个 /24 就要 13 分钟。这里换成采样普查：段内均匀取 N 个点（上限 400），
// 用 TEO 批量问答（100 IP/次 → 4 次 HTTP 拿满 400 个答案，约 2 秒），
// 相邻样本答案交界处直接切段；大格（≥4096 地址）再用少量真实探针收紧边界。
//
// 精度：≤400 地址的段逐地址采样（等价于点满），更大段按 size/400 的格宽切分。
package main

import (
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
)

const (
	censusMaxSample = 400  // TEO 单次 100，400 = 4 次调用
	censusRefineSol = 256 // 格宽 ≥/24（256 个地址）就开着收边界，v4 现在按 /22 打底，必须收紧
	censusRefineMax = 256  // 单前缀收敛边界的探针总预算
)

// pc 省级+市级签名：收敛边界时只看这两级（各源县/运营商字段口径不一致）
func (a answer) pc() string { return a.Province + "|" + a.City }

// teoCensus 对 [lo,hi] 做采样普查并产出段（直接进 pending）
//
// province 为 WHOIS 底线给的省（可能为空），用作 TEO 无结果时的兜底。
func (s *scanner) teoCensus(lo, hi *big.Int, province, cidr string, v4 bool, width, gran int) {
	size := new(big.Int).Sub(hi, lo)
	size.Add(size, big.NewInt(1))
	if size.Sign() <= 0 {
		return
	}

	// ---- 1. 采样规格：对齐到「市级分配单元」，不再固定 400 等分 ----
	// v4 的市级分配单元是 /24，v6 是 /32。以前固定 400 等分，一个 /20 的 v6 段
	// 只能撒 1024 个点覆盖 2^60 个地址，绝大多数 /32 根本没被采到 —— 这就是
	// 「有省无市」占大头的原因（2408:8000::/20 里 2408:882c::/32 明明是沈阳，
	// 却因为没采到而整段输出「中国 联通」）。
	const maxCells = 65536
	unit := 24 // v4：/24 是市级/县级分配单元，逐格扫
	if !v4 {
		unit = 36 // v6：/36 是移动/电信的市级分配粒度
	}
	L := 0
	if ipp, err := netip.ParsePrefix(cidr); err == nil {
		L = ipp.Bits()
	}
	cellBits := unit
	if L > cellBits {
		cellBits = L // 前缀比分配单元还窄，整段就是一格
	}
	if L+16 < cellBits {
		cellBits = L + 16 // 2^16 = 65536 格上限；超了才放大格宽（不能截断，截断会让尾部不产出）
	}
	bits := 128
	if v4 {
		bits = 32
	}
	cell := new(big.Int).Lsh(big.NewInt(1), uint(bits-cellBits))
	aligned := true

	// ---- 2. 取样本点（每格中点）并批量预取 TEO ----
	// 底线切分会让 part 起点落在 /36 内部（floor.jsonl 有 146 段如此），
	// 直接从 lo 起步会让整段采样格整体偏移、跨 /36 边界把两个城市混进一格。
	// 处理：头块 [lo, 下一个 /36 边界-1] 单独成一格，之后严格按 /36 步进。
	var ips []string
	var lows, highs []*big.Int
	maxSamples := maxCells + 2 // 头块 + 收尾格各留一格余量
	addCell := func(clo, chi *big.Int) {
		mid := new(big.Int).Add(clo, chi)
		mid.Div(mid, big.NewInt(2))
		ips = append(ips, bigIntToIP(mid, width).String())
		lows = append(lows, new(big.Int).Set(clo))
		highs = append(highs, new(big.Int).Set(chi))
	}
	cur := new(big.Int).Set(lo)
	if aligned {
		if rem := new(big.Int).Mod(cur, cell); rem.Sign() != 0 {
			next := new(big.Int).Sub(cell, rem)
			next.Add(next, cur)
			headHi := new(big.Int).Sub(next, big.NewInt(1))
			if headHi.Cmp(hi) > 0 {
				headHi.Set(hi)
			}
			addCell(cur, headHi)
			cur = next
		}
	}
	for len(ips) < maxSamples && cur.Cmp(hi) <= 0 {
		chi := new(big.Int).Add(cur, cell)
		chi.Sub(chi, big.NewInt(1))
		last := chi.Cmp(hi) >= 0
		if last {
			chi.Set(hi)
		}
		addCell(cur, chi)
		if last {
			break
		}
		cur = new(big.Int).Add(chi, big.NewInt(1))
	}
	// cell = floor(size/sampleN) 时 400 格凑不满整段（例：16384/400=40，400格只到 16000），
	// 采样格上限一到就会漏掉尾部 —— 必须补一个收尾格，保证整段无缝覆盖。
	if cur.Cmp(hi) <= 0 {
		addCell(cur, new(big.Int).Set(hi))
	}
	s.teoPrefetch(ips)
	s.remotePrefetch(ips, v4) // bilibili / 360 也参与投票，慢一点但准

	// ---- 3. 组答案：TEO 批量 + 本地库（零网络成本），底线省兜底 ----
	// 远程单点源（bilibili/360）当前单次约 3 秒，普查阶段一律不碰，只在收紧边界时少量调用。
	ans := make([]answer, len(ips))
	perIP := make([]map[string]answer, len(ips)) // 每个采样点的全部源答案（陪跑也留档）
	for i, ip := range ips {
		a, all := s.quickAll(ip, v4)
		if a.Src == "" && province != "" {
			a = answer{Src: "floor", Province: province}
		}
		perIP[i] = all
		ans[i] = a
	}

	// ---- 3.5 采样格过粗时不给市级结论 ----
	// 格比 /36 还粗时（/19~/25 骨干段被迫放大格宽），一格覆盖几十个 /36 分配块，
	// 采样点落到哪个城市纯属偶然，按格给市等于编造精度 —— 混了就只保留省。
	cell36 := new(big.Int).Lsh(big.NewInt(1), 92) // /36 的地址数
	if cell.Cmp(cell36) > 0 {
		distinct := map[string]bool{}
		for _, a := range ans {
			if a.City != "" {
				distinct[a.City] = true
			}
		}
		if len(distinct) > 1 {
			for i := range ans {
				ans[i].City = ""
				ans[i].County = ""
			}
		}
	}

	// ---- 4. 相邻同签名合并成组 ----
	if os.Getenv("CENSUS_DEBUG") != "" {
		n := 8
		if len(ips) < n {
			n = len(ips)
		}
		for i := 0; i < n; i++ {
			fmt.Printf("[census] %s → %s %s %s %s\n", ips[i], ans[i].Src, ans[i].Province, ans[i].City, ans[i].County)
		}
		fmt.Printf("[census] sampleN=%d cell=%s size=%s groups-前样本数=%d\n", len(ips), cell.String(), size.String(), len(ips))
	}
	type group struct{ from, to int }
	var groups []group
	for i := range ans {
		if i == 0 || ans[i].pc() != ans[i-1].pc() {
			groups = append(groups, group{from: i, to: i})
		} else {
			groups[len(groups)-1].to = i
		}
	}

	// ---- 5. 大格段做边界收紧（只对 v4；v6 的分界在 2^80 量级，二分 64 针无意义）----
	refineLeft := censusRefineMax
	if cell.Cmp(big.NewInt(censusRefineSol)) >= 0 { // v4/v6 都要收边界：格再细也可能跨市
		for gi := 0; gi+1 < len(groups) && refineLeft > 0; gi++ {
			g, next := groups[gi], groups[gi+1]
			gapLo, gapHi := highs[g.to], lows[next.from]
			boundary, used := s.refineBoundary(gapLo, gapHi, ans[g.from], ans[next.from], width, v4, refineLeft)
			refineLeft -= used
			if boundary != nil && boundary.Cmp(highs[g.to]) > 0 {
				highs[g.to] = boundary // 本组尾巴延伸到收敛点
				lows[next.from] = new(big.Int).Add(boundary, big.NewInt(1))
			}
		}
	}

	// ---- 6. 落段 ----
	blockSize := new(big.Int).Lsh(big.NewInt(1), uint(width*8-gran))
	for _, g := range groups {
		start, end := lows[g.from], highs[g.to]
		span := new(big.Int).Sub(end, start)
		span.Add(span, big.NewInt(1))
		span.Div(span, blockSize)
		// 本组所有采样点的陪跑答案并集：存档 + 投票
		grpAll := map[string]answer{}
		for i := g.from; i <= g.to; i++ {
			for k, v := range perIP[i] {
				grpAll[k] = v
			}
		}
		prim := s.arbitrate(ans[g.from], grpAll)
		s.collect(segment{
			Start:   bigIntToIP(start, width).String(),
			End:     bigIntToIP(end, width).String(),
			Prefix:  cidr,
			Primary: prim,
			Sources: grpAll,
			Span:    span,
		})
	}
}

// refineBoundary 在 [gapLo, gapHi] 里二分找「答案从 left 变成 right」的分界点。
// gapLo 归 left、gapHi 归 right；返回最后一个属于 left 的地址。
// 只在真实探针答出同样的省市时才算「仍是 left」，避免县/运营商口径差异干扰收敛。
func (s *scanner) refineBoundary(gapLo, gapHi *big.Int, left, right answer, width int, v4 bool, budget int) (*big.Int, int) {
	if gapHi.Cmp(gapLo) <= 0 {
		return gapLo, 0
	}
	lo := new(big.Int).Set(gapLo)
	hi := new(big.Int).Set(gapHi)
	used := 0
	for used < budget {
		if new(big.Int).Sub(hi, lo).Cmp(big.NewInt(1)) <= 0 {
			break // 已相邻
		}
		mid := new(big.Int).Add(lo, hi)
		mid.Div(mid, big.NewInt(2))
		a, _ := s.probe(bigIntToIP(mid, width).String(), v4)
		used++
		s.pfxUsed++
		if !a.empty() && a.pc() == left.pc() {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo, used
}

func cloneAll(m map[string]answer) map[string]answer {
	out := make(map[string]answer, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// bigIntToIP 大数 → IP（宽度感知）
func bigIntToIP(n *big.Int, width int) net.IP {
	b := n.Bytes()
	ip := make(net.IP, width)
	copy(ip[width-len(b):], b)
	return ip
}

// addrToBig 地址 → 大数
func addrToBig(a netip.Addr) *big.Int {
	if a.Is4() {
		b := a.As4()
		return new(big.Int).SetBytes(b[:])
	}
	b := a.As16()
	return new(big.Int).SetBytes(b[:])
}
