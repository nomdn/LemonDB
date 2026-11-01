package main

// dot import 是**文件级**的：main.go 里的 `import . "lemondb/norm"` 不会传染到这个
// 测试文件，早先这里直接调 Parse360Region 所以 `go test .` 一直编译不过。
import . "lemondb/norm"

import "testing"

func TestParse360Region(t *testing.T) {
	cases := []struct{ in, p, c, ct, isp string }{
		{"江苏省宿迁市泗洪县\t移动", "江苏", "宿迁市", "泗洪县", "移动"},
		{"陕西省西安市雁塔区\t电信", "陕西", "西安市", "雁塔区", "电信"},
		{"北京市\t移动", "北京", "北京市", "", "移动"},
		{"上海市\t电信", "上海", "上海市", "", "电信"},
		{"美国", "", "", "", ""}, // 外国名不落省字段
		{"内蒙古自治区呼和浩特市\t联通", "内蒙古", "呼和浩特市", "", "联通"},
	}
	for _, c := range cases {
		p, ci, ct, isp := Parse360Region(c.in)
		if p != c.p || ci != c.c || ct != c.ct || isp != c.isp {
			t.Errorf("%q → (%q,%q,%q,%q) 期望 (%q,%q,%q,%q)", c.in, p, ci, ct, isp, c.p, c.c, c.ct, c.isp)
		}
	}
}

func TestNorm(t *testing.T) {
	if NormProvince("Jiangsu") != "江苏" || NormProvince("江苏省") != "江苏" || NormProvince("Nei Mongol") != "内蒙古" {
		t.Error("province norm")
	}
	if NormISP("China Mobile communications corporation") != "移动" || NormISP("CERNET") != "教育网" || NormISP("Dr.Peng") != "鹏博士" {
		t.Error("isp norm")
	}
	if p, c, i := ParseIP2Region("中国|0|江苏省|盐城市|移动"); p != "江苏" || c != "盐城市" || i != "移动" {
		t.Errorf("ip2region: %q %q %q", p, c, i)
	}
}
