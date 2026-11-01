#!/usr/bin/env bash
# 扫描入口：v6 与 v4 各起 N 片并行，跑完退出。
# v6 先跑完的话，run_v4_final.sh 会把槽位接管给 v4（切十二片续跑），
# 所以这两个脚本要一起用，build.sh scan 已经串好了。
set -uo pipefail
cd "$(dirname "$0")"

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) BIN=./scan16.exe ;;
  *) BIN=./scan16 ;;
esac

DBS=${DBS:-../dbs}
V6_SHARDS=${V6_SHARDS:-6}
V4_SHARDS=${V4_SHARDS:-6}
MAX_MIN=${MAX_MIN:-240}
LBS_BUDGET=${LBS_BUDGET:-450}

# TEO 控制台会话是可选源：没有凭据就退化成 bilibili/360/本地库
TEO_CONF=${TEO_CONF:-../teo-conf.json}
TEO_ARG=""
[ -f "$TEO_CONF" ] && TEO_ARG="-teo-conf $TEO_CONF"

EXTRA_ARG=""
[ -n "${NO360:-}" ] && EXTRA_ARG="$EXTRA_ARG -no-360"
[ -n "${GAP360:-}" ] && EXTRA_ARG="$EXTRA_ARG -360-gap $GAP360"

echo "== v6 $V6_SHARDS 片 + v4 $V4_SHARDS 片并行（每片上限 ${MAX_MIN} 分钟）=="
for i in $(seq 0 $((V6_SHARDS - 1))); do
  $BIN -dbs "$DBS" $TEO_ARG -only v6 -shard "$i/$V6_SHARDS" -lbs-budget "$LBS_BUDGET" \
    -out "seg-v6-$i.jsonl" -state "st6-$i.json" -max-minutes "$MAX_MIN" $EXTRA_ARG \
    > "log-v6-$i.txt" 2>&1 &
done
for i in $(seq 0 $((V4_SHARDS - 1))); do
  $BIN -dbs "$DBS" $TEO_ARG -only v4 -shard "$i/$V4_SHARDS" -lbs-budget "$LBS_BUDGET" \
    -out "seg-v4-$i.jsonl" -state "st4-$i.json" -max-minutes "$MAX_MIN" $EXTRA_ARG \
    > "log-v4-$i.txt" 2>&1 &
done
wait
echo "全部结束"
