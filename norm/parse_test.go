package norm

import "testing"

// v4 / v6 两种 ip2region 布局都要能正确解析
func TestParseIP2RegionLayouts(t *testing.T) {
	cases := []struct {
		in, prov, city, isp, note string
	}{
		{"中国|0|江苏省|宿迁市|移动", "江苏", "宿迁市", "移动", "v4 布局"},
		{"中国|0|北京|北京市|联通", "北京", "北京市", "联通", "v4 直辖市"},
		{"中国|江苏省|盐城市|移动|CN", "江苏", "盐城市", "移动", "v6 布局"},
		{"中国|北京市|北京市|电信|CN", "北京", "北京市", "电信", "v6 直辖市"},
		{"中国|四川省|成都市|电子科技大学|CN", "四川", "成都市", "", "v6 教育网"},
		{"中国|0|0|0|0", "", "", "", "全零"},
	}
	for _, c := range cases {
		p, ct, isp := ParseIP2Region(c.in)
		if p != c.prov || ct != c.city || isp != c.isp {
			t.Errorf("%s %q → (%q,%q,%q)，期望 (%q,%q,%q)", c.note, c.in, p, ct, isp, c.prov, c.city, c.isp)
		}
	}
}
