package norm

// 省份/城市/运营商字典（builder 与 scanner 共用）

var ProvinceByAbbr = map[string]string{
	"BJ": "北京", "TJ": "天津", "HE": "河北", "SX": "山西", "NM": "内蒙古", "LN": "辽宁",
	"JL": "吉林", "HL": "黑龙江", "SH": "上海", "JS": "江苏", "ZJ": "浙江", "AH": "安徽",
	"FJ": "福建", "JX": "江西", "SD": "山东", "HA": "河南", "HB": "湖北", "HN": "湖南",
	"GD": "广东", "GX": "广西", "HI": "海南", "CQ": "重庆", "SC": "四川", "GZ": "贵州",
	"YN": "云南", "XZ": "西藏", "SN": "陕西", "GS": "甘肃", "QH": "青海", "NX": "宁夏", "XJ": "新疆",
}

var ProvinceFull = map[string]string{
	"北京": "北京", "天津": "天津", "河北": "河北", "山西": "山西", "内蒙古": "内蒙古", "辽宁": "辽宁",
	"吉林": "吉林", "黑龙江": "黑龙江", "上海": "上海", "江苏": "江苏", "浙江": "浙江", "安徽": "安徽",
	"福建": "福建", "江西": "江西", "山东": "山东", "河南": "河南", "湖北": "湖北", "湖南": "湖南",
	"广东": "广东", "广西": "广西", "海南": "海南", "重庆": "重庆", "四川": "四川", "贵州": "贵州",
	"云南": "云南", "西藏": "西藏", "陕西": "陕西", "甘肃": "甘肃", "青海": "青海", "宁夏": "宁夏", "新疆": "新疆",
}

var ProvinceByEnglish = map[string]string{
	"Beijing": "北京", "Tianjin": "天津", "Hebei": "河北", "Shanxi": "山西", "Nei Mongol": "内蒙古",
	"Inner Mongolia": "内蒙古", "Liaoning": "辽宁", "Jilin": "吉林", "Heilongjiang": "黑龙江",
	"Shanghai": "上海", "Jiangsu": "江苏", "Zhejiang": "浙江", "Anhui": "安徽", "Fujian": "福建",
	"Jiangxi": "江西", "Shandong": "山东", "Henan": "河南", "Hubei": "湖北", "Hunan": "湖南",
	"Guangdong": "广东", "Guangxi": "广西", "Hainan": "海南", "Chongqing": "重庆", "Sichuan": "四川",
	"Guizhou": "贵州", "Yunnan": "云南", "Tibet": "西藏", "Shaanxi": "陕西", "Gansu": "甘肃",
	"Qinghai": "青海", "Ningxia": "宁夏", "Xinjiang": "新疆",
}

var CityToProvince = map[string]string{
	"Nanjing": "江苏", "Suzhou": "江苏", "Wuxi": "江苏", "Changzhou": "江苏", "Nantong": "江苏",
	"Xuzhou": "江苏", "Yangzhou": "江苏", "Kunshan": "江苏", "Hangzhou": "浙江", "Ningbo": "浙江",
	"Wenzhou": "浙江", "Jiaxing": "浙江", "Shaoxing": "浙江", "Jinhua": "浙江", "Taizhou": "浙江",
	"Guangzhou": "广东", "Shenzhen": "广东", "Dongguan": "广东", "Foshan": "广东", "Zhuhai": "广东",
	"Zhongshan": "广东", "Huizhou": "广东", "Shantou": "广东", "Chengdu": "四川", "Mianyang": "四川",
	"Leshan": "四川", "Wuhan": "湖北", "Yichang": "湖北", "Xiangyang": "湖北", "Xi'an": "陕西",
	"Xian": "陕西", "Zhengzhou": "河南", "Luoyang": "河南", "Kaifeng": "河南", "Jinan": "山东",
	"Qingdao": "山东", "Weifang": "山东", "Zibo": "山东", "Yantai": "山东", "Shenyang": "辽宁",
	"Dalian": "辽宁", "Anshan": "辽宁", "Fushun": "辽宁", "Changchun": "吉林", "Harbin": "黑龙江",
	"Daqing": "黑龙江", "Qiqihar": "黑龙江", "Shijiazhuang": "河北", "Tangshan": "河北",
	"Baoding": "河北", "Taiyuan": "山西", "Hefei": "安徽", "Fuzhou": "福建", "Xiamen": "福建",
	"Quanzhou": "福建", "Zhangzhou": "福建", "Nanchang": "江西", "Changsha": "湖南", "Nanning": "广西",
	"Liuzhou": "广西", "Guilin": "广西", "Kunming": "云南", "Guiyang": "贵州", "Lanzhou": "甘肃",
	"Urumqi": "新疆", "Haikou": "海南", "Lhasa": "西藏", "Xining": "青海", "Yinchuan": "宁夏",
	"Hohhot": "内蒙古", "Baotou": "内蒙古",
}
