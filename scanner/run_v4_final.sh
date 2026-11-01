#!/usr/bin/env bash
# v4 收尾守护：等 v6 全部分片跑完，把它们占用的进程槽位挪给 v4，
# 并把 v4 重切成 12 片。旧分片的已完成前缀用 -done-extra 继承，不重扫。
#
# 为什么要切：v4 前缀按 index%6 分片时负载极不均（有一个分片 249 个、另一个 0 个），
# 12 片能把长尾摊薄。切完剩下的前缀已经被前一轮扫掉一部分，所以这轮只是补尾。
set -uo pipefail
cd "$(dirname "$0")"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) BIN=./scan16.exe; WIN=1 ;;
  *) BIN=./scan16; WIN= ;;
esac

DBS=${DBS:-../dbs}
V6_LIST=${V6_LIST:-$DBS/china6.txt}
SHARDS=${V4_SHARDS:-12}
MAX_MIN=${MAX_MIN:-240}

# v6 完成数：所有 st6-*.json 的 done 并集大小（不是简单相加，分片间可能重叠）
count_done() {
  local py
  py=$(command -v python3 || command -v python)
  "$py" - "$@" <<'EOF'
import glob, json, sys
s = set()
for f in glob.glob("st6-*.json"):
    try:
        s |= set(json.load(open(f)).get("done", {}))
    except Exception:
        pass
print(len(s))
EOF
}

TOTAL=$(grep -cv '^\s*$' "$V6_LIST" 2>/dev/null || echo 0)
echo "v6 前缀总数 $TOTAL，等待扫描完成……"
while :; do
  n=$(count_done)
  [ "$n" -ge "$TOTAL" ] && break
  sleep 20
done

echo "v6 已完成 $n 个前缀，切换到 v4 $SHARDS 分片"
if [ -n "$WIN" ]; then
  taskkill //F //IM scan16.exe >/dev/null 2>&1
else
  pkill -f 'scan16 -dbs' >/dev/null 2>&1
fi
sleep 2

TEO_CONF=${TEO_CONF:-../teo-conf.json}
TEO_ARG=""
[ -f "$TEO_CONF" ] && TEO_ARG="-teo-conf $TEO_CONF"

EXTRA=$(ls st4-*.json 2>/dev/null | paste -sd, -)
for i in $(seq 0 $((SHARDS - 1))); do
  $BIN -dbs "$DBS" $TEO_ARG -only v4 -shard "$i/$SHARDS" \
    -lbs-budget 300 -done-extra "$EXTRA" -max-minutes "$MAX_MIN" \
    -out "seg-v4b-$i.jsonl" -state "st4b-$i.json" > "log-v4b-$i.txt" 2>&1 &
done
wait
echo "v4 全部结束"
