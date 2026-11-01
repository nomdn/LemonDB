# cnipdb

中国 IP 归属地离线库构建器。阶段一产出 **WHOIS 低精度底线库**（GeoLite2 兼容双 mmdb），阶段二叠加**多源扫描**（bilibili/360）做市级覆盖。

## 产出

| 文件 | 内容 | Schema |
|---|---|---|
| `CN-LOCATION.mmdb` | 省（subdivisions）+ 运营商（isp）+ 网络类型（type: broadband/idc/edu） | GeoLite2-City 兼容（country/subdivisions）+ 自定义字段 |
| `CN-ASN.mmdb` | 自治系统号 + 组织 | GeoLite2-ASN 兼容 |

单树双栈（IPv4/IPv6 均可查询，`DisableIPv4Aliasing` 关闭别名防串扰）。读取侧用任意标准 mmdb 库即可，零适配。

## 数据来源

- **APNIC whois 全量 dump**（ftp.apnic.net/apnic/whois/）：inetnum/inet6num/aut-num/route/route6
- 省份挖掘：CHINANET-XX/CMNET-XX/UNICOM-XX 缩写、中文/英文省名、城市名映射
- 运营商专项：教育网/鹏博士/华数/广电/阿里云/腾讯云/华为云/百度云

覆盖率（阶段一实测）：CN inetnum 对象 86 万，**按地址量 79% 标到省**；CMNET 大段与全部 v6 内部分配不在 whois 里——由阶段二扫描补齐。

## 构建

```bash
# 从 https://ftp.apnic.net/apnic/whois/ 下载 dump 并解压后：
go run . \
  -inetnum inetnum -inet6num inet6num -autnum aut-num \
  -route4 route -route6 route6 \
  -out-location CN-LOCATION.mmdb -out-asn CN-ASN.mmdb
```

## 已知边界（阶段一）

- CMNET（AS9808/AS56046 等）的省市分布：whois 无省级标记，待阶段二扫描
- 中国移动 v6 运营段（2409::/20 等）：同上
- 精度定位：省级底线 + 运营商/类型标注，市级由扫描阶段覆盖
