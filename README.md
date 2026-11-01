# LemonDB

全球 IP 归属地 + ASN 离线库构建器，中国大陆是高精度层（省 / 市 / 区县 + 运营商 + 区划码），境外由 GeoLite2 / dbip / IP2Location 打底。输入 APNIC WHOIS + 若干在线/离线数据源，输出可直接查询的 mmdb：

| 产物 | 内容 | 覆盖 |
|---|---|---|
| `LEMON-LOCATION.mmdb` | 全球：国家 / 省 / 市 / 区县 + 经纬度（国内 GCJ-02、境外 WGS-84）；中国大陆含运营商 / 网络类型 / GB/T 2260 区划码 | 575 万条 maxmind 打底 + CN 高精度层覆盖 |
| `LEMON-ASN.mmdb` | 全球自治系统号 + 组织名 | GeoLite2-ASN 打底 + APNIC CN 精修，约 117 万前缀 |

`CN-LOCATION.mmdb` / `CN-ASN.mmdb` 是构建中间产物（仅中国大陆、CN 层原始形态），不对外发布。

单树双栈，读取侧用任意标准 mmdb 库即可（`maxminddb-golang`、`maxminddb`、`libmaxminddb`），零适配。

## 架构

```
APNIC whois dump ──► floor（WHOIS 底线：省 + 运营商 + 类型）
                     ├─► china.txt / china6.txt（CN 公告段清单，同一份 dump 生成）
                     └─► CN-ASN.mmdb（APNIC 区域 ASN）
                                  │
                                  ▼
                       scan（多源采样 + 投票 + 合并段）
                         v4 /24 一格、v6 /36 一格
                                  │ seg-v4*.jsonl / seg-v6*.jsonl
                                  ▼
                       merge（底线 + 扫描段 → CN-LOCATION.mmdb）
                         直辖市补市 / 假县清洗 / 宽段按县切分 / adcode 回填
                                  │
                                  ▼
                       world（maxmind 打底 + ip2location 补坐标 + CN 覆盖）
                                  │
                                  ▼
                       LEMON-LOCATION.mmdb ──► check（覆盖面 + 独立回查）

CN-ASN.mmdb ──► asn（GeoLite2-ASN 打底 + dbip 补漏 + APNIC CN 精修）──► LEMON-ASN.mmdb
```

关键原则：**一个主源 + 多个陪跑源 + 同省投票仲裁**，不是链式兜底。每个采样点查全部源、全部写入 `sources`，同省票多者胜、平票按源优先级。这样任何单一源的抖动都不会直接污染结果。

## 数据源与角色

| 源 | 类型 | 粒度 | 参与方式 | 限制 |
|---|---|---|---|---|
| **360** | 在线 | 省/市/**县** | v4 主源 | 唯一远程县级源；**仅 v4**；高频会 403，间隔 ≥120ms |
| **bilibili** | 在线 | 省/市 | v4/v6 主源 | 给市最准（v6 85.8%），但只覆盖 41.3% 的段；`x/web-interface/zone` 已失效，用 `api.live` 那个 |
| **TEO** | 在线 | 省/市 + 运营商 | v4/v6 主源 | 覆盖最广（85.7%），但只 38.2% 给到市；依赖控制台 cookie，会过期 |
| **GeoCN** | 本地 | 省/市/**县** | 陪跑 + 回填 | v6 部分 75% 只到省；宽段拆分的主力 |
| **ZX ipv6wry** | 本地 | 省/市 | v6 补市 | 省一致才采纳，绝不用它改省（会把移动大段判错） |
| **ip2region** | 本地 | 省/市 | 陪跑 | v6 布局无区县字段，对移动大段一律给"北京市" |
| **LBS（腾讯位置）** | 在线 | 省/市 | 仅兜底 | v6 实测返回 382 无法定位；v4 省一致仅 60%，不参与投票 |
| **GeoLite2 / dbip / ip2location** | 本地 | 世界 | world / asn 层 | 中国只到国家级，不参与 CN 层；ASN 层给全球打底 |

## 目录

```
main.go               floor：APNIC → floor.jsonl / CN-ASN.mmdb / china*.txt
scanner/              scan：采样、多源查询、投票、合并段
  run_all.sh          v6/v4 各 N 片并行入口
  run_v4_final.sh     v6 跑完后把槽位接管给 v4，切 12 片续跑
merge/                merge：底线 + 段 → CN-LOCATION.mmdb
  split.go            宽段按区县变化点切分
world/                world：全球库分层合并 → LEMON-LOCATION.mmdb
asn/                  asn：全球 ASN 分层合并 → LEMON-ASN.mmdb
check/                验收：覆盖面 + 独立回查
lookup/               单 IP 查询
stats/                覆盖率统计
rescan/               定向补扫（逐 /24 查 360，供宽段重算用）
filter/               用 GeoLite2 清洗公告段里的境外段
mmdbls.py             纯 Python 的 mmdblookup 替代（打印结构 / --json）
scripts/fetch-dbs.sh  依赖库下载（CI 与本地共用，链接同 ipw-cn src/ipdb）
build.sh              一键流水线
```

## 构建

### 本地

```bash
# 1. 拉依赖库（链接取自 ipw-cn src/ipdb 的同款下载表；国内可加 GH_PROXY 加速前缀）：
./build.sh dbs
#    或 GH_PROXY=https://gh-proxy.com ./build.sh dbs
#    可选库（dbip-asn-lite / dbip-city / qqwry）：./scripts/fetch-dbs.sh dbs --optional

# 2. 把 APNIC dump 解压到根目录：
#    inetnum inet6num aut-num route route6

# 3. 全流程
./build.sh all

# 或分阶段
./build.sh floor     # WHOIS 底线（5 分钟，顺带生成 china.txt / china6.txt）
./build.sh scan      # 在线扫描（4 小时量级，可反复执行，状态续跑）
./build.sh merge     # 合并扫描段（20 秒）
./build.sh world     # 全球库（7 分钟）
./build.sh asn       # 全球 ASN（7 秒）
./build.sh check     # 验收
```

`scan` 可以随时中断重跑：每个分片有 `st*.json` 状态文件，已完成的前缀不会重扫。

### CI

`.github/workflows/build.yml` 每月 1 号自动跑，也可以手动触发（支持 `skip_scan` 只重建底线）。

**不再需要手工准备 release**：依赖库由 `.github/actions/fetch-dbs` 调
`scripts/fetch-dbs.sh` 直接下载——就是 ipw-cn 仓库 `src/ipdb/ipdb.go` 里生产环境
日更用的那张下载表（GeoLite2-City / GeoLite2-ASN、GeoCN.mmdb、full.txt、
ip2region v4/v6、IP2Location DB11、ZX ipv6wry 等），按月缓存（`dbs-YYYYMM`），
月初自动换新。ZX 的 `ipv6wry.db` 来自 https://ip.zxinc.org/ip.7z（该库 2021 年后
停更，仅用来给 v6 补市，解压工具缺失或站点不可达时自动跳过）。

`china.txt` / `china6.txt` 同样不用手工维护：floor 阶段从同一份 APNIC dump 生成
（按 `country: CN` 收全量、合并重叠区间后转 CIDR，约 4237 段 / 334.7M 地址），
通过 `cover` artifact 传给 scan 和 publish。

**只发布全球版**：release 里是 `LEMON-LOCATION.mmdb` + `LEMON-ASN.mmdb`；
`CN-LOCATION.mmdb` / `CN-ASN.mmdb` 是中间产物，不进 release。

唯一可选的 secret 是 **`TEO_CONF`**（TEO 控制台会话 JSON）。没有就自动降级（少一个源，市级覆盖率会掉）。

> CI 跑在海外 runner 上，360 / bilibili 的可用性和国内不一致，量大的构建建议本地跑、CI 只做兜底重建。

## 各阶段要点

### floor（WHOIS 底线）

从 APNIC `inetnum` / `inet6num` 挖省名：`CHINANET-XX` / `CMNET-XX` / `UNICOM-XX` 缩写、中英文省名、城市名映射；再按 ASN 与组织名标运营商和类型（broadband / idc / edu）。

产出 `floor.jsonl` 作为"兜底段"：扫描拿不到答案的地址用它填省和运营商。**底线不覆盖扫描结果**，只在空白处生效。

### scan（采样 + 投票）

- v4 按 `/24` 一格（一个市/县级分配单元），v6 按 `/36` 一格；`/7` 及更宽的公告段把格宽放大到 `L+16`，上限 65536 格。
- 每格取中点，查全部源 → 同省投票 → 平票按优先级 `360 > bilibili > teo > zx > ip2region > geocn`。
- 相邻同签名的格合并成段，段里保留全部源的原始答案（`sources` 字段），供 merge 阶段回填。
- 并发：12 个进程共用一条出口 IP，360 会被限流，基准间隔 40ms 起、失败自动降速；被封时用 `-no-360` 跑完剩余前缀。

### merge（合成 CN 库）

按顺序做五件事，每一步都对应一个曾经踩过的坑：

1. **底线入库**，直辖市「省即市」补 `city`（源对北京只给省，`city` 为空会让下游误判缺市）
2. **扫描段入库**，按 span 从大到小插，小段自然覆盖粗段
3. **假县清洗**：`county == city` 是市级回落产物（`宿迁市/宿迁市`），先清空**再**从陪跑源回填真县——顺序反了会把真县挡在门外（`36.149.123.193` 丢泗洪县就是这么来的）
4. **宽段按县变化点切分**：有县且跨多个 `/24` 的段，逐 `/24` 查 GeoCN 重算区县，连续同结果的并成一个区间。段内普遍跨 2–6 个区县（哈尔滨一个 `/19` 里有南岗/双城/松北/通河/香坊），保留段代表值等于对多数地址给错
5. **adcode**：同名区县（`南山区` 在鹤岗也在深圳）按父市 `c/100*100` 匹配，不能只按名字取首个

### world（世界库）

`GeoLite2 打底 → IP2Location 补坐标/城市 → CN 层覆盖`。

CN 段覆盖时用 `division_code` 查 `divcoords/division-coords.json` 拿政府驻地坐标：区县级 5 km、市级 15 km（取最小编号区县，即主城区）、省级 100 km（省会）。**不给 CN 段挂 maxmind 坐标**——GeoLite2 对中国只有国家级默认点，挂上去会和省级结果打架。

### asn（全球 ASN）

`dbip-asn-lite 补漏 → GeoLite2-ASN 主力 → APNIC CN 精修`（后写的覆盖同前缀）。

三个源都是 GeoLite2 兼容的 `autonomous_system_number` / `autonomous_system_organization` 两个键，直接搬运不重编码。APNIC 只覆盖亚太，境外全靠 GeoLite2/dbip；CN 段的组织名（中英文）由 floor 从 WHOIS 挖出，比 GeoLite2 准，所以盖在最上面。

### check（验收）

```bash
./check/check -mmdb CN-LOCATION.mmdb -cover dbs/china.txt -n 800           # 公告段覆盖
./check/check -mmdb CN-LOCATION.mmdb -segs "scanner/seg-*.jsonl" -n 300 -w 8  # 独立回查
```

比对口径要注意：市名用「省即市 + 互为前缀」宽松比较，严格相等会把直辖市和自治州判成不一致。

## 当前基线

```
LEMON-LOCATION.mmdb 57.4 MB  maxmind 5,757,408 条 + CN 层 373,732 段
LEMON-ASN.mmdb      ~11 MB   GeoLite2-ASN 1,101,739 + APNIC CN 68,277 前缀
CN-LOCATION.mmdb     3.14 MB  v4 283,466 前缀（省 100% / 市 99.5% / 县 70.5%）
                             v6  90,266 前缀（省 100% / 市 88.1% / 县  5.6%）
CN-ASN.mmdb          1.5 MB  v4 46,405 / v6 21,873 前缀，去重 11,862 个 ASN
```

验收：独立回查 301 段，省 99.0%、市 100%、县 68.1%；公告段抽样 v4 96.6%、v6 86.3% 有记录（缺口是公告段里混入的境外/anycast 段）。

## 已知限制

| 项 | 现状 | 原因 |
|---|---|---|
| v6 县 5.6% | 上限约 9.6% | GeoCN 的 v6 数据 75% 只到省，`/48` 再采样也挖不出；360 不支持 v6 |
| v6 市 88.1% | 剩余 12% 是移动骨干 anycast + 四源全空 | `2409:2000::/24` 抽 20 点有 12 个返回"亚太地区"，给市反而是错的 |
| 区县准确率 ~50% | 天花板 | 抽 50 个有县前缀用 360 反查：区县完全命中 46%、同市异县 52%、跨市 2%。两个独立源在同一个 `/24` 上对区县也只有 52% 共识 |
| ASN 源月更 | GeoLite2-ASN / dbip 是月级快照 | 免费源没有日更通道，商业库是最终出路 |
| 境外城市中文名 | 部分是英文 | IP2Location 补的城市没有中文映射表 |

## 工具

```bash
# 查任意 IP（树状 + 类型标注）
python mmdbls.py LEMON-LOCATION.mmdb 8.8.8.8 --meta
# JSON 输出
python mmdbls.py CN-LOCATION.mmdb 114.114.114.114 223.5.5.5 --json
# Go 版单点查询
go run ./lookup -mmdb CN-LOCATION.mmdb 8.8.8.8
# 覆盖率统计
go run ./stats -mmdb CN-LOCATION.mmdb
```

`mmdbls.py` 是自己解析 MMDB 二进制的（Windows 没有官方 `mmdblookup` 二进制），保留值的原始类型，输出与 `mmdblookup` 对齐，已和官方 `maxminddb` 库交叉验证一致。

## 维护提示

- **TEO cookie 会过期**，过期后 v6 市级覆盖率明显下降，日志里 `teo` 会大面积缺席，需要重新抓。
- **360 会封 IP**，12 进程 × 40ms 被封过；6 进程 × 120ms 是实测安全值。被封后用 `-no-360` 收尾，那批前缀没有县级数据（约 0.11%）。
- **`-no-360` 那批段**（`122.224.0.0/12` 等 7 个前缀）县级缺失是已知的，不补。
- **坐标表 `divcoords`** 是外部仓库，每月更新；重跑 world 即可更新坐标，不用重扫。
- **改 merge 的清洗逻辑时**，记得同时看 `check` 侧的比对口径——两边都用严格相等会互相骗过。
