#!/usr/bin/env bash
# 拉取构建依赖库到 dbs/
#
# 链接来源：ipw-cn 仓库 src/ipdb/ipdb.go 里的那张下载表（生产环境日更用的同一批
# 地址），这里按构建需要挑子集；另外补了两个 ipw-cn 用不到、但本流水线要的库
# （ZX ipv6wry、dbip，均为可选）。
#
# 用法：
#   ./scripts/fetch-dbs.sh                       # 拉到 ./dbs
#   ./scripts/fetch-dbs.sh /data/dbs             # 指定目录
#   FORCE=1 ./scripts/fetch-dbs.sh               # 已有文件也重下（月更时用）
#   GH_PROXY=https://ghfast.top ./scripts/fetch-dbs.sh   # 国内走加速前缀
#   ./scripts/fetch-dbs.sh dbs --optional        # 顺带拉 GeoLite2-ASN / dbip / qqwry
#
# 退出码：必需库缺失或下载失败 → 1；可选库失败只告警。
set -uo pipefail

DEST=${1:-dbs}
[[ $DEST == --* ]] && DEST=dbs
OPTIONAL=0
for a in "$@"; do [[ $a == --optional ]] && OPTIONAL=1; done

GH_PROXY=${GH_PROXY:-}
GH_PROXY=${GH_PROXY%/}
FORCE=${FORCE:-0}
FAIL=0

mkdir -p "$DEST"

err() { echo "::error::$*"; echo "错误：$*" >&2; }
warn() { echo "::warning::$*"; echo "警告：$*" >&2; }

# gh_url <直链>：有 GH_PROXY 就先走加速前缀再走直连，没有就只走直连
gh_url() {
  local u=$1
  if [ -n "$GH_PROXY" ]; then
    printf '%s\n%s\n' "$GH_PROXY/$u" "$u"
  else
    printf '%s\n' "$u"
  fi
}

# fetch <目标路径> <url...>：按顺序试候选地址，成功才落盘（.part 中转，避免半截文件）
fetch() {
  local dest=$1
  shift
  local tmp="$dest.part" u
  for u in "$@"; do
    printf '  ← %s\n' "$u"
    if curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 900 \
      -o "$tmp" "$u" 2>/dev/null && [ -s "$tmp" ]; then
      mv -f "$tmp" "$dest"
      printf '    ✓ %-40s %s\n' "$(basename "$dest")" "$(du -h "$dest" | cut -f1)"
      return 0
    fi
    rm -f "$tmp"
  done
  return 1
}

# need <文件名> <url...>：必需库
need() {
  local name=$1
  shift
  if [ -s "$DEST/$name" ] && [ "$FORCE" != 1 ]; then
    printf '  = %-40s 已存在，跳过\n' "$name"
    return 0
  fi
  fetch "$DEST/$name" "$@" || { err "$name 下载失败"; FAIL=1; }
}

# opt <文件名> <url...>：可选库，失败只告警
opt() {
  local name=$1
  shift
  if [ -s "$DEST/$name" ] && [ "$FORCE" != 1 ]; then
    printf '  = %-40s 已存在，跳过\n' "$name"
    return 0
  fi
  fetch "$DEST/$name" "$@" || warn "$name 不可用（可选，相关精度会降级）"
}

# unzip_entry <压缩包> <目标文件名>：解出 zip 里第一个匹配的文件
unzip_entry() {
  local zip=$1 dst=$2 tmp found
  command -v unzip >/dev/null || { warn "没有 unzip，跳过 $zip"; return 1; }
  tmp=$(mktemp -d)
  unzip -o -q "$zip" -d "$tmp" || { rm -rf "$tmp"; return 1; }
  found=$(find "$tmp" -type f -iname "$dst" | head -1)
  [ -n "$found" ] || found=$(find "$tmp" -type f -iname '*.BIN' | head -1)
  [ -n "$found" ] || { rm -rf "$tmp"; return 1; }
  mv -f "$found" "$DEST/$dst"
  rm -rf "$tmp"
  printf '    ✓ %-40s %s\n' "$dst" "$(du -h "$DEST/$dst" | cut -f1)"
}

# un7z_entry <压缩包> <目标文件名>
un7z_entry() {
  local sz=$1 dst=$2 tmp found bin
  for bin in 7z 7zz 7za 7zr; do command -v "$bin" >/dev/null && break; bin=; done
  [ -n "${bin:-}" ] || { warn "没有 7z 解压工具，跳过 $(basename "$sz")"; return 1; }
  tmp=$(mktemp -d)
  "$bin" x -y -o"$tmp" "$sz" >/dev/null 2>&1 || { rm -rf "$tmp"; return 1; }
  found=$(find "$tmp" -type f -iname "$dst" | head -1)
  [ -n "$found" ] || { rm -rf "$tmp"; return 1; }
  mv -f "$found" "$DEST/$dst"
  rm -rf "$tmp"
  printf '    ✓ %-40s %s\n' "$dst" "$(du -h "$DEST/$dst" | cut -f1)"
}

echo "依赖库 → $DEST/（GH_PROXY='${GH_PROXY:-无}' FORCE=$FORCE 可选库=$OPTIONAL）"

# ── 必需：CN 层 ────────────────────────────────────────────────
# GeoCN：区划回填 / 宽段按 /24 重算的主力本地库
need GeoCN.mmdb $(gh_url "https://github.com/ljxi/GeoCN/releases/latest/download/GeoCN.mmdb")
# full.txt：GB/T 2260 名称→代码表（宽段拆分靠它）
need full.txt \
  $(gh_url "https://raw.githubusercontent.com/ljxi/GeoCN/main/data/full.txt") \
  "https://cdn.jsdelivr.net/gh/ljxi/GeoCN@main/data/full.txt" \
  "https://fastly.jsdelivr.net/gh/ljxi/GeoCN@main/data/full.txt"
# ip2region：陪跑源（v4 有区县、v6 到市）
need ip2region_v4.xdb \
  $(gh_url "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb") \
  "https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v4.xdb"
need ip2region_v6.xdb \
  $(gh_url "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb") \
  "https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/data/ip2region_v6.xdb"

# ── 必需：世界层 ──────────────────────────────────────────────
need GeoLite2-City.mmdb $(gh_url "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb")
# GeoLite2-ASN：LEMON-ASN 全球 ASN 库的主力层
need GeoLite2-ASN.mmdb $(gh_url "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb")

# ── 必需：IP2Location DB11（zip 发布，解出 BIN）─────────────────
IP2LOC_ZIP="$DEST/IP2LOCATION-LITE-DB11.IPV6.BIN.ZIP"
if [ -s "$DEST/IP2LOCATION-LITE-DB11.IPV6.BIN" ] && [ "$FORCE" != 1 ]; then
  printf '  = %-40s 已存在，跳过\n' IP2LOCATION-LITE-DB11.IPV6.BIN
else
  if fetch "$IP2LOC_ZIP" $(gh_url "https://github.com/nomdn/ip2location/releases/latest/download/IP2LOCATION-LITE-DB11.IPV6.BIN.ZIP"); then
    unzip_entry "$IP2LOC_ZIP" IP2LOCATION-LITE-DB11.IPV6.BIN || { err "IP2Location 解压失败"; FAIL=1; }
    rm -f "$IP2LOC_ZIP"
  else
    err "IP2Location DB11 下载失败"
    FAIL=1
  fi
fi

# ── 可选：ZX ipv6wry（2021 年后停更，只用来给 v6 补市，+0.1pt）──
ZX_ZIP="$DEST/ip.7z"
if [ ! -s "$DEST/ipv6wry.db" ] || [ "$FORCE" = 1 ]; then
  if fetch "$ZX_ZIP" "https://ip.zxinc.org/ip.7z"; then
    un7z_entry "$ZX_ZIP" ipv6wry.db || warn "ipv6wry.db 解压失败（可选）"
    rm -f "$ZX_ZIP"
  else
    warn "ipv6wry.db 不可用（可选，v6 市级补全少一点点）"
  fi
fi

if [ "$OPTIONAL" = 1 ]; then
  opt qqwry.ipdb $(gh_url "https://raw.githubusercontent.com/nmgliangwei/qqwry.ipdb/main/qqwry.ipdb")
  # dbip-asn-lite：LEMON-ASN 的最底层补漏（缺了就只剩 GeoLite2-ASN，可用）
  opt dbip-asn-lite.mmdb $(gh_url "https://github.com/jcjc-dev/mmdb-latest/releases/download/dbip-latest/dbip-asn-lite.mmdb")

  if [ ! -s "$DEST/dbip-city-lite.mmdb" ] || [ "$FORCE" = 1 ]; then
    DBIP_GZ="$DEST/dbip-city-lite.mmdb.gz"
    if fetch "$DBIP_GZ" $(gh_url "https://raw.githubusercontent.com/wp-statistics/DbIP-City-lite/master/dbip-city-lite.mmdb.gz"); then
      gunzip -f "$DBIP_GZ" && printf '    ✓ %-40s %s\n' dbip-city-lite.mmdb "$(du -h "$DEST/dbip-city-lite.mmdb" | cut -f1)"
    else
      warn "dbip-city-lite 不可用（可选）"
    fi
  fi
fi

echo
echo "现有 $DEST/："
ls -lh "$DEST" | tail -n +2 | awk '{printf "  %-42s %s\n", $9, $5}'

if [ "$FAIL" != 0 ]; then
  err "必需库不完整，构建会产出低质量结果"
  exit 1
fi
echo "依赖库就绪"
