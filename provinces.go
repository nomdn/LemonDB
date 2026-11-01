package main

import . "cnipdb/norm"

import "strings"

// 省份识别字典：netname/descr → 省。
// 覆盖 CHINANET 缩写、中文全名、拼音/英文名、主要城市名。
// 覆盖率实测（APNIC inetnum 全量）：CN 对象 86 万，按地址量 79% 可标到省。

// matchProvince 从 netname+descr 挖省份；ispHint 运营商线索（可空）
func matchProvince(netname string, descr []string) (province, ispHint string) {
	// CHINANET-JS / CHINANET-JS-CITY 体系
	if strings.HasPrefix(netname, "CHINANET-") {
		seg := strings.SplitN(strings.TrimPrefix(netname, "CHINANET-"), "-", 2)[0]
		if p, ok := ProvinceByAbbr[seg]; ok {
			return p, "电信"
		}
	}
	if strings.HasPrefix(netname, "CHINANET") && len(netname) > 8 {
		if p, ok := ProvinceByAbbr[netname[8:10]]; ok {
			return p, "电信"
		}
	}
	// 联通/移动的缩写体系（UNICOM-JS / CMNET-JS）
	for prefix, isp := range map[string]string{"UNICOM-": "联通", "CMNET-": "移动", "CU-": "联通"} {
		if strings.HasPrefix(netname, prefix) {
			seg := strings.SplitN(strings.TrimPrefix(netname, prefix), "-", 2)[0]
			if p, ok := ProvinceByAbbr[seg]; ok {
				return p, isp
			}
		}
	}
	hay := netname + " " + strings.Join(descr, " ")
	// 英文省名（APNIC descr 惯例）
	for en, p := range ProvinceByEnglish {
		if strings.Contains(hay, en) {
			return p, ispHintFrom(hay)
		}
	}
	// 中文省名
	for full, p := range ProvinceFull {
		if strings.Contains(hay, full) {
			return p, ispHintFrom(hay)
		}
	}
	// 城市名 → 省
	for c, p := range CityToProvince {
		if strings.Contains(hay, c) {
			return p, ispHintFrom(hay)
		}
	}
	return "", ispHintFrom(hay)
}

// ispHintFrom 从文本里辨认运营商专项
func ispHintFrom(hay string) string {
	switch {
	case strings.Contains(hay, "教育网"), strings.Contains(strings.ToUpper(hay), "CERNET"), strings.Contains(strings.ToUpper(hay), "EDU"):
		return "教育网"
	case strings.Contains(hay, "鹏博士"), strings.Contains(strings.ToUpper(hay), "DRPENG"), strings.Contains(hay, "长城宽带"):
		return "鹏博士"
	case strings.Contains(hay, "华数"), strings.Contains(strings.ToUpper(hay), "WASU"):
		return "华数"
	case strings.Contains(hay, "广电"), strings.Contains(strings.ToUpper(hay), "CBS"):
		return "广电"
	case strings.Contains(hay, "阿里"), strings.Contains(strings.ToUpper(hay), "ALIYUN"), strings.Contains(strings.ToUpper(hay), "ALISOFT"):
		return "阿里云"
	case strings.Contains(hay, "腾讯"), strings.Contains(strings.ToUpper(hay), "TENCENT"):
		return "腾讯云"
	case strings.Contains(hay, "华为"), strings.Contains(strings.ToUpper(hay), "HUAWEI"):
		return "华为云"
	case strings.Contains(hay, "百度"), strings.Contains(strings.ToUpper(hay), "BAIDU"):
		return "百度云"
	}
	return ""
}
