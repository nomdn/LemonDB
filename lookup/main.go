// lookup 查一个或多个 IP 在库里的归属，输出 JSON。
//
//	go run ./lookup -mmdb LEMON-LOCATION.mmdb 8.8.8.8 114.114.114.114
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

func main() {
	mmdbPath := flag.String("mmdb", "CN-LOCATION.mmdb", "成品库")
	flag.Parse()

	db, err := maxminddb.Open(*mmdbPath)
	if err != nil {
		fmt.Println("打开失败:", err)
		os.Exit(1)
	}
	defer db.Close()

	for _, arg := range flag.Args() {
		var rec any
		res := db.Lookup(netip.MustParseAddr(arg))
		if !res.Found() {
			fmt.Printf("%-18s <无记录>\n", arg)
			continue
		}
		if err := res.Decode(&rec); err != nil {
			fmt.Printf("%-18s 解码失败: %v\n", arg, err)
			continue
		}
		b, _ := json.Marshal(rec)
		fmt.Printf("%-18s %s\n", arg, string(b))
	}
}
