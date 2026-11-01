#!/usr/bin/env bash
# LemonDB 一键流水线：WHOIS 底线 → 多源扫描 → 合并 → 回查
#
# 用法：
#   ./build.sh dbs      拉取依赖库到 dbs/（链接同 ipw-cn src/ipdb，GH_PROXY 可加速）
#   ./build.sh floor    只重建 WHOIS 底线（需要 apnic dump 已下载）
#   ./build.sh scan     跑扫描（v6 六片 + v4 六片，v6 结束后自动切 v4 十二片，可重复执行）
#   ./build.sh merge    合并扫描段到 CN-LOCATION.mmdb
#   ./build.sh world    全球库：GeoLite2/dbip 打底，CN 层覆盖 → LEMON-LOCATION.mmdb
#   ./build.sh asn      全球 ASN：GeoLite2-ASN 打底，APNIC CN 覆盖 → LEMON-ASN.mmdb
#   ./build.sh check    覆盖面 + 独立回查
#   ./build.sh all      floor → scan → merge → world → asn → check
#
# 依赖：apnic dump 解压后的 inetnum / inet6num / aut-num / route / route6，
#       dbs/ 下的依赖库（./build.sh dbs 一键拉齐，或见 scripts/fetch-dbs.sh），
#       divcoords/division-coords.json（world 阶段用），
#       以及 teo-conf.json（腾讯 EO 控制台会话，过期后需重新抓 cookie）。

set -euo pipefail
cd "$(dirname "$0")"

# Windows（Git Bash）上 Go 产物带 .exe 后缀，Linux/CI 上没有
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=.exe ;; *) EXE= ;; esac

SHARDS=${SHARDS:-6}
LBS_KEY=${LBS_KEY:-}
LBS_SK=${LBS_SK:-}
LBS_BUDGET=${LBS_BUDGET:-5400}

floor_build() {
  echo "== floor: WHOIS 底线 =="
  go run . \
    -inetnum inetnum -inet6num inet6num -autnum aut-num \
    -route4 route -route6 route6 \
    -out-location CN-LOCATION.mmdb -out-asn CN-ASN.mmdb \
    -floor-out floor.jsonl -cover-out dbs
}

dbs_fetch() {
  echo "== dbs: 拉依赖库 =="
  bash scripts/fetch-dbs.sh dbs
}

scan_run() {
  echo "== scan: v6 六片 + v4 六片，v6 跑完后自动切 v4 十二片 =="
  ( cd scanner && go build -o scan16$EXE . )
  # run_v4_final.sh 是守护：轮询 st6-*.json，够了就杀掉旧进程、按 12 片续跑 v4，
  # 已完成的前缀通过 -done-extra 继承，不重扫。
  ( cd scanner && ./run_v4_final.sh ) &
  local guard=$!
  ( cd scanner && ./run_all.sh )
  wait "$guard" 2>/dev/null || true
  echo "扫描结束，段表："; wc -l scanner/seg-v*.jsonl | tail -1
}

merge_run() {
  echo "== merge: 覆盖底线 =="
  ( cd merge && go build -o merge$EXE . )
  # -zx 给 v6 补市、-geocn 让宽段按 /24 重算区县（缺这两个产物会退回低保真版本）
  ./merge/merge$EXE -floor floor.jsonl -segs "scanner/seg-v*.jsonl" \
    -division dbs/full.txt -zx dbs/ipv6wry.db -geocn dbs/GeoCN.mmdb \
    -out CN-LOCATION.mmdb
}

world_run() {
  echo "== world: maxmind/dbip 打底 + CN 层覆盖 → LEMON-LOCATION.mmdb =="
  ( cd world && go build -o world$EXE . )
  ./world/world$EXE -cn CN-LOCATION.mmdb -maxmind dbs/GeoLite2-City.mmdb \
    -ip2loc dbs/IP2LOCATION-LITE-DB11.IPV6.BIN \
    -coords divcoords/division-coords.json \
    -dbip "${WORLD_DBIP:-}" -out LEMON-LOCATION.mmdb
}

asn_run() {
  echo "== asn: 全球 ASN（APNIC CN 覆盖 GeoLite2-ASN）→ LEMON-ASN.mmdb =="
  ( cd asn && go build -o asn$EXE . )
  ./asn/asn$EXE -geolite dbs/GeoLite2-ASN.mmdb -apnic CN-ASN.mmdb \
    -dbip "${ASN_DBIP:-dbs/dbip-asn-lite.mmdb}" -out LEMON-ASN.mmdb
}

check_run() {
  echo "== check: 覆盖面 =="
  ( cd check && go build -o check$EXE . )
  ./check/check$EXE -mmdb CN-LOCATION.mmdb -cover dbs/china.txt -n 800
  ./check/check$EXE -mmdb CN-LOCATION.mmdb -cover dbs/china6.txt -n 600
  echo "== check: 独立回查（360/bilibili）=="
  ./check/check$EXE -mmdb CN-LOCATION.mmdb -segs "scanner/seg-*.jsonl" -n 200 -w 8
}

case "${1:-all}" in
  dbs)   dbs_fetch ;;
  floor) floor_build ;;
  scan)  scan_run ;;
  merge) merge_run ;;
  world) world_run ;;
  asn)   asn_run ;;
  check) check_run ;;
  all)   floor_build; scan_run; merge_run; world_run; asn_run; check_run ;;
  *) echo "用法: $0 {dbs|floor|scan|merge|world|asn|check|all}"; exit 1 ;;
esac
