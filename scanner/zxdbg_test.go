package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestZXDebug(t *testing.T) {
	z, err := openZX("../dbs/ipv6wry.db")
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := netip.ParseAddr("2409:8a20:c677:9bd0::1")
	a16 := addr.As16()
	key := binary.BigEndian.Uint64(a16[:8])
	lo, hi := 0, z.count-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if z.indexKey(mid) <= key {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	t.Logf("key=%016x idx=%d idxkey=%016x off=%d", key, lo, z.indexKey(lo), z.indexOff(lo))
	t.Logf("next idxkey=%016x", z.indexKey(lo+1))
	t.Logf("fields=%q", z.readRecord(z.indexOff(lo)))
}
