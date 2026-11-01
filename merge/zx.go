package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// ZX ipv6wry.db（IPDB 格式 v1）读取器 —— merge 侧独立副本。
//
// 和 scanner/zx.go 的区别：那边为了不污染投票，要求记录必须带归属单位；
// 这里只做「补录」，调用方会校验省必须一致，所以粗记录也能用上它的市。
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
		return nil, fmt.Errorf("%s 头信息异常", path)
	}
	if z.idx0+z.count*z.esz > len(b) {
		return nil, fmt.Errorf("%s 索引区越界", path)
	}
	return z, nil
}

func (z *zxDB) indexKey(i int) uint64 {
	p := z.idx0 + i*z.esz
	return binary.LittleEndian.Uint64(z.data[p : p+8])
}

func (z *zxDB) indexOff(i int) int {
	p := z.idx0 + i*z.esz + z.ipLen
	var v int
	for k := 0; k < z.offLen; k++ {
		v |= int(z.data[p+k]) << (8 * k)
	}
	return v
}

func (z *zxDB) readRecord(off int) []string {
	var fields []string
	for depth := 0; depth < 4 && off > 0 && off < len(z.data); depth++ {
		p := off
		redirected := false
		fields = fields[:0]
		for p < len(z.data) {
			b := z.data[p]
			if b == 0 {
				return fields
			}
			if b == 1 {
				p++
				continue
			}
			if b == 2 {
				tgt := 0
				for k := 0; k < z.offLen; k++ {
					tgt |= int(z.data[p+1+k]) << (8 * k)
				}
				if tgt == off {
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

// lookup 返回省/市/县（原样，不做规范化），由调用方比对省名
func (z *zxDB) lookup(addr netip.Addr) (province, city, county string, ok bool) {
	if z == nil || !addr.Is6() || addr.Is4In6() {
		return "", "", "", false
	}
	a16 := addr.As16()
	key := binary.BigEndian.Uint64(a16[:8])
	if z.indexKey(0) > key {
		return "", "", "", false
	}
	lo, hi := 0, z.count-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if z.indexKey(mid) <= key {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	fields := z.readRecord(z.indexOff(lo))
	if len(fields) == 0 {
		return "", "", "", false
	}
	parts := strings.Split(fields[0], "\t")
	if parts[0] != "中国" || len(parts) < 2 {
		return "", "", "", false
	}
	province = strings.TrimSpace(parts[1])
	if len(parts) >= 3 {
		city = strings.TrimSpace(parts[2])
	}
	if len(parts) >= 4 {
		county = strings.TrimSpace(parts[3])
	}
	return province, city, county, province != ""
}
