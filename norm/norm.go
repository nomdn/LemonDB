// normalize.go —— 多源答案归一化：确定性映射，无猜测
package norm

import (
	"regexp"
	"strings"
)

var suffixRe = regexp.MustCompile(`(维吾尔|壮族|回族)?自治区$|(省|市|盟)$`)

// NormProvince 省级归一：剥后缀 + 别名表 → 标准名（北京/江苏/内蒙古…），未命中返回空
func NormProvince(s string) string {
	if s == "" {
		return ""
	}
	s = strings.TrimSpace(s)
	if p, ok := ProvinceByEnglish[s]; ok {
		return p
	}
	stripped := suffixRe.ReplaceAllString(s, "")
	if p, ok := ProvinceFull[stripped]; ok {
		return p
	}
	if p, ok := ProvinceByAbbr[stripped]; ok {
		return p
	}
	// 含省名的长串（如 "中国 江苏省 宿迁市"）
	for full, p := range ProvinceFull {
		if strings.Contains(s, full) {
			return p
		}
	}
	for en, p := range ProvinceByEnglish {
		if strings.Contains(s, en) {
			return p
		}
	}
	return ""
}

var ispAlias = []struct{ needle, norm string }{
	{"移动", "移动"}, {"CMCC", "移动"}, {"China Mobile", "移动"},
	{"电信", "电信"}, {"China Telecom", "电信"}, {"CHINANET", "电信"}, {"Telecom", "电信"},
	{"联通", "联通"}, {"China Unicom", "联通"}, {"UNICOM", "联通"},
	{"教育网", "教育网"}, {"CERNET", "教育网"},
	{"鹏博士", "鹏博士"}, {"长城宽带", "鹏博士"}, {"DRPENG", "鹏博士"},
	{"华数", "华数"}, {"WASU", "华数"},
	{"广电", "广电"},
	{"阿里", "阿里云"}, {"ALIYUN", "阿里云"}, {"ALISOFT", "阿里云"},
	{"腾讯", "腾讯云"}, {"TENCENT", "腾讯云"},
	{"华为", "华为云"}, {"HUAWEI", "华为云"},
	{"百度", "百度云"}, {"BAIDU", "百度云"},
	{"京东", "京东云"}, {"快手", "快手"}, {"字节", "字节云"}, {"火山", "字节云"},
}

// squash 去除所有非字母数字字符并转大写（Dr.Peng → DRPENG）
func squash(s string) string {
	var b strings.Builder
	for _, c := range strings.ToUpper(s) {
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c > 127 {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// NormISP 运营商归一：别名表顺序匹配（压扁后比较，忽略点号/空格/大小写）
func NormISP(s string) string {
	if s == "" {
		return ""
	}
	if n := NormISP2(squash(s)); n != "" {
		return n
	}
	// 中文 needle 对原文直接包含匹配（squash 会保留中文）
	for _, a := range ispAlias {
		if strings.Contains(s, a.needle) {
			return a.norm
		}
	}
	return ""
}

func NormISP2(sq string) string {
	for _, a := range ispAlias {
		if strings.Contains(sq, squash(a.needle)) && squash(a.needle) != "" {
			return a.norm
		}
	}
	return ""
}

var municipality = map[string]bool{"北京": true, "天津": true, "上海": true, "重庆": true}

// Parse360Region 解析 360 /IPQuery/ipquery 的 data："江苏省宿迁市泗洪县	移动"
func Parse360Region(data string) (province, city, county, isp string) {
	seg := strings.SplitN(data, "	", 2)
	region := strings.TrimSpace(seg[0])
	if len(seg) == 2 {
		isp = NormISP(strings.TrimSpace(seg[1]))
	}
	rest := region
	// 自治区全称前缀
	arPrefix := map[string]string{
		"内蒙古自治区": "内蒙古", "广西壮族自治区": "广西", "宁夏回族自治区": "宁夏",
		"新疆维吾尔自治区": "新疆", "西藏自治区": "西藏",
	}
	for full, p := range arPrefix {
		if strings.HasPrefix(rest, full) {
			province, rest = p, rest[len(full):]
			break
		}
	}
	// 省
	if i := strings.Index(rest, "省"); i > 0 {
		province, rest = rest[:i], rest[i+3:]
	}
	// 直辖市："上海市浦东新区" → 省=上海 市=上海
	for m := range municipality {
		if strings.HasPrefix(rest, m+"市") {
			province, city, rest = m, m+"市", rest[len(m)+3:]
			break
		}
	}
	// 市
	if province != "" && strings.Contains(rest, "市") {
		if i := strings.Index(rest, "市"); i >= 0 {
			city, rest = rest[:i+3], rest[i+3:]
		}
	}
	// 县/区/旗
	if strings.HasSuffix(rest, "县") || strings.HasSuffix(rest, "区") || strings.HasSuffix(rest, "旗") {
		county = rest
	} else if rest != "" && city == "" {
		city = rest
	}
	if province == "" {
		province = NormProvince(region)
	}
	// 非中国一级行政区（外国名等）不算省，整条降级为无省级
	if _, ok := ProvinceFull[province]; !ok {
		return "", "", "", isp
	}
	if municipality[province] && city == "" {
		city = province + "市"
	}
	return province, city, county, isp
}

// ParseIP2Region 解析 "国家|区域|省|市|ISP"
func ParseIP2Region(s string) (province, city, isp string) {
	p := strings.Split(s, "|")
	if len(p) >= 5 {
		isp = NormISP(p[4])
	}
	if len(p) >= 4 {
		province = NormProvince(p[2])
		// 城市守卫：全国性网络（教育网/骨干网）的"城市"是垃圾值，不落市字段
		if province != "" && p[3] != "" && p[3] != "0" &&
			!strings.Contains(p[3], "教育") && !strings.Contains(p[3], "中国") && !strings.Contains(p[3], "骨干") {
			city = p[3]
			if !strings.HasSuffix(city, "市") {
				city += "市"
			}
		}
	}
	return province, city, isp
}
