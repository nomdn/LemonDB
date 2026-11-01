package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"lemondb/norm"
)

// ZX ipv6wry.db（IPDB 格式 v1）读取器
//
// 文件布局：
//   0-3   "IPDB"
//   4-5   version(2, LE)        本库是 1
//   6     offLen  记录偏移字节数（1~4）
//   7     ipLen   地址字节数（4=v4，8=v6；v6 只存高 64 位）
//   8-15  count   记录数(int64 LE)
//   16-23 idx0    索引区起始偏移(int64 LE)
//   24    fieldCnt(v2 新增，v1 恒为 2)
//   25-31 reserve
//   32-   数据区：连续 UTF-8 字符串，0x00 结尾；0x02+offLen 表示重定向到另一条记录；0x01 废弃
//   索引区：{ IP[ipLen] LE, offset[offLen] LE } × count，按 IP 升序
//
// 注意 v6 库只存地址的前 8 字节（高 64 位），因此精度上限是 /64，
// 对本项目需要的 /48 粒度完全够用。
type zxDB struct {
	data   []byte
	count  int
	idx0   int
	esz    int
	offLen int
	ipLen  int
}

func openZX(path string) (*zxDB, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < 32 || string(b[:4]) != "IPDB" {
		return nil, fmt.Errorf("%s 不是 IPDB 文件", path)
	}
	z := &zxDB{data: b}
	z.offLen = int(b[6])
	z.ipLen = int(b[7])
	z.count = int(binary.LittleEndian.Uint64(b[8:16]))
	z.idx0 = int(binary.LittleEndian.Uint64(b[16:24]))
	z.esz = z.ipLen + z.offLen
	if z.offLen < 1 || z.offLen > 4 || z.ipLen != 8 || z.count <= 0 {
		return nil, fmt.Errorf("%s 头信息异常：offLen=%d ipLen=%d count=%d", path, z.offLen, z.ipLen, z.count)
	}
	if z.idx0+z.count*z.esz > len(b) {
		return nil, fmt.Errorf("%s 索引区越界", path)
	}
	return z, nil
}

// indexKey 取索引项里的 IP 键（小端存的 uint64）
func (z *zxDB) indexKey(i int) uint64 {
	p := z.idx0 + i*z.esz
	return binary.LittleEndian.Uint64(z.data[p : p+8])
}

// indexOff 取索引项里的记录偏移
func (z *zxDB) indexOff(i int) int {
	p := z.idx0 + i*z.esz + z.ipLen
	var v int
	for k := 0; k < z.offLen; k++ {
		v |= int(z.data[p+k]) << (8 * k)
	}
	return v
}

// readRecord 从偏移处读出一条记录的全部字段，重定向最多跟 4 层
func (z *zxDB) readRecord(off int) []string {
	var fields []string
	for depth := 0; depth < 4 && off > 0 && off < len(z.data); depth++ {
		p := off
		redirected := false
		fields = fields[:0]
		for p < len(z.data) {
			b := z.data[p]
			if b == 0 { // 记录结束
				return fields
			}
			if b == 1 { // 废弃标记
				p++
				continue
			}
			if b == 2 { // 重定向
				tgt := 0
				for k := 0; k < z.offLen; k++ {
					tgt |= int(z.data[p+1+k]) << (8 * k)
				}
				if tgt == off { // 自指，防死循环
					return fields
				}
				off = tgt
				redirected = true
				break
			}
			c := p
			for c < len(z.data) && z.data[c] != 0 {
				c++
			}
			fields = append(fields, string(z.data[p:c]))
			p = c + 1
		}
		if !redirected {
			return fields
		}
	}
	return fields
}

// zx 查一条 IPv6 地址。库只给到「国家 / 省 / 市 / 区」+ 单位名，且大量运营商大段只写「中国」，
// 这种情况下返回空 answer，让后面的源接手（宁缺毋滥）。
func (s *scanner) zx(ip string) answer {
	if s.zxDB == nil {
		return answer{}
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return answer{}
	}
	a16 := addr.As16()
	key := binary.BigEndian.Uint64(a16[:8]) // 高 64 位

	// 二分：找最后一个 indexKey <= key 的索引
	lo, hi := 0, s.zxDB.count-1
	if s.zxDB.indexKey(0) > key {
		return answer{}
	}
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if s.zxDB.indexKey(mid) <= key {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	fields := s.zxDB.readRecord(s.zxDB.indexOff(lo))
	if len(fields) == 0 {
		return answer{}
	}
	// fields[0] = "中国\t江苏省\t宿迁市"（最多再带一个区），fields[1] = 单位/运营商
	parts := strings.Split(fields[0], "\t")
	if parts[0] != "中国" { // 只看国内记录
		return answer{}
	}
	// 关键取舍：库里「中国\t上海市」这类只有省/市、没有归属单位的粗记录，
	// 实测会给出与 TEO/bilibili 相反的省（2409:8a20:c6::/48 被判成上海，实为江苏宿迁）。
	// 这类记录不可信，直接丢弃；只有带单位名的具体段（高校/机构）才采纳。
	if len(fields) < 2 || strings.TrimSpace(fields[1]) == "" {
		return answer{}
	}
	if len(parts) < 2 {
		return answer{}
	}
	province := norm.NormProvince(parts[1])
	if province == "" {
		return answer{}
	}
	a := answer{Src: "zx", Province: province}
	if len(parts) >= 3 && parts[2] != "" {
		city := parts[2]
		if !strings.HasSuffix(city, "市") && !strings.HasSuffix(city, "盟") && !strings.HasSuffix(city, "州") {
			city += "市"
		}
		a.City = city
	}
	if len(parts) >= 4 && parts[3] != "" {
		a.County = parts[3]
	}
	if isp := norm.NormISP(fields[1]); isp != "" {
		a.ISP = isp
	} else {
		a.Extra = fields[1] // 学校/单位名，仅存档
	}
	return a
}
