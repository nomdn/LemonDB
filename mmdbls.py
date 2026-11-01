#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mmdbls —— 复刻 mmdblookup 的输出格式，直接读 mmdb 二进制。

不依赖 maxminddb 库，自己解析搜索树 + data section，这样才能拿到值的
真实类型（uint16/uint32/double...），mmdblookup 的方括号标注就是靠这个。

用法:
    python mmdbls.py WORLD-LOCATION.mmdb 36.149.123.193
    python mmdbls.py CN-LOCATION.mmdb 114.114.114.114 --meta
"""
import sys
import json
import struct
import ipaddress

MARKER = b"\xab\xcd\xefMaxMind.com"

# 类型编号 → mmdblookup 里显示的名字
TYPE_NAMES = {
    2: "utf8_string",
    3: "double",
    4: "bytes",
    5: "uint16",
    6: "uint32",
    7: "map",
    8: "int32",
    9: "uint64",
    10: "uint128",
    11: "array",
    14: "float",
    15: "boolean",
}


class Decoder:
    def __init__(self, buf, base=0):
        self.buf = buf
        self.base = base  # data section 在文件里的起点，pointer 用它换算

    def _ctrl(self, off):
        """解析 control byte，返回 (type, size, 新偏移)。size 是元素个数或字节数。"""
        ctrl = self.buf[off]
        off += 1
        typ = ctrl >> 5
        if typ == 0:  # extended type
            typ = self.buf[off] + 7
            off += 1
        size = ctrl & 0x1F
        if size == 29:
            size = 29 + self.buf[off]
            off += 1
        elif size == 30:
            size = 285 + int.from_bytes(self.buf[off:off + 2], "big")
            off += 2
        elif size == 31:
            size = 65821 + int.from_bytes(self.buf[off:off + 3], "big")
            off += 3
        return typ, size, off

    def decode(self, off):
        """返回 (python值, 类型编号, 新偏移)。"""
        typ, size, off = self._ctrl(off)

        if typ == 1:  # pointer：size 的高 2 位是 pointer 宽度，低 3 位是值的高位
            psize = (size >> 3) & 0x3
            v = size & 0x7
            if psize == 0:
                ptr = (v << 8) | self.buf[off]
                off += 1
            elif psize == 1:
                ptr = (v << 16) | int.from_bytes(self.buf[off:off + 2], "big")
                ptr += 2048
                off += 2
            elif psize == 2:
                ptr = (v << 24) | int.from_bytes(self.buf[off:off + 3], "big")
                ptr += 526336
                off += 3
            else:
                ptr = int.from_bytes(self.buf[off:off + 4], "big")
                off += 4
            # 解引用后要把被指向值的类型带出来，否则上层会把 pointer
            # 当成一种独立类型，渲染时拿不到真实标注
            val, vtyp, _ = self.decode(self.base + ptr)
            return val, vtyp, off

        if typ == 2:
            return self.buf[off:off + size].decode("utf-8", "replace"), typ, off + size
        if typ == 3:
            return struct.unpack(">d", self.buf[off:off + 8])[0], typ, off + 8
        if typ == 4:
            return self.buf[off:off + size], typ, off + size
        if typ in (5, 6, 9, 10):
            return int.from_bytes(self.buf[off:off + size], "big"), typ, off + size
        if typ == 8:
            return int.from_bytes(self.buf[off:off + size], "big", signed=True), typ, off + size
        if typ == 14:
            return struct.unpack(">f", self.buf[off:off + 4])[0], typ, off + 4
        if typ == 15:
            return size != 0, typ, off
        if typ == 7:  # map
            out = {}
            for _ in range(size):
                k, _, off = self.decode(off)
                v, vt, off = self.decode(off)
                out[k] = (v, vt)
            return out, typ, off
        if typ == 11:  # array
            out = []
            for _ in range(size):
                v, vt, off = self.decode(off)
                out.append((v, vt))
            return out, typ, off
        raise ValueError("未知类型 %d @%d" % (typ, off))


class Reader:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.buf = f.read()
        idx = self.buf.rfind(MARKER)
        if idx < 0:
            raise ValueError("不是 mmdb 文件：找不到 metadata 标记")
        self.meta_off = idx + len(MARKER)
        raw, _, _ = Decoder(self.buf, self.meta_off).decode(self.meta_off)
        self.meta_raw = raw                                  # 值仍带类型标注
        self.meta = {k: v for k, (v, _) in raw.items()}      # 剥掉类型的裸值

        self.node_count = self.meta["node_count"]
        self.record_size = self.meta["record_size"]
        self.ip_version = self.meta["ip_version"]
        self.node_bytes = self.record_size // 4
        # 搜索树之后有 16 字节分隔符，但 MMDB 的 data pointer 已经把这 16
        # 字节算进去了（pointer - node_count = 记录偏移 + 16），所以基准取
        # 搜索树末尾、不加 16，否则整条记录会偏后 16 字节。
        self.data_base = self.node_count * self.node_bytes
        # 记录指针的绝对偏移 = data_base + (pointer - node_count)；
        # 而记录内部 pointer 引用的字符串/子结构，基准是分隔符之后的真实
        # data 起点，所以 Decoder 的 base 要再 +16。
        self.dec = Decoder(self.buf, self.data_base + 16)

    def _record(self, node, side):
        """读某个节点的左(0)/右(1)记录值。"""
        off = node * self.node_bytes
        b = self.buf[off:off + self.node_bytes]
        if self.record_size == 24:
            return int.from_bytes(b[0:3], "big") if side == 0 else int.from_bytes(b[3:6], "big")
        if self.record_size == 28:
            if side == 0:
                return ((b[3] & 0xF0) << 20) | int.from_bytes(b[0:3], "big")
            return ((b[3] & 0x0F) << 24) | int.from_bytes(b[4:7], "big")
        return int.from_bytes(b[0:4], "big") if side == 0 else int.from_bytes(b[4:8], "big")

    def lookup(self, ip):
        addr = ipaddress.ip_address(ip)
        bits = bin(int(addr))[2:].zfill(addr.max_prefixlen)
        # ipv6 库里 IPv4 走 ::/96 那一段，前面补 96 个 0
        if self.ip_version == 6 and addr.version == 4:
            bits = "0" * 96 + bits
        elif addr.version != self.ip_version:
            return None, None, None
        node = 0
        for i, ch in enumerate(bits):
            node = self._record(node, int(ch))
            # node == node_count 是「这个前缀没有记录」的哨兵值，
            # node > node_count 才是真正的 data pointer
            if node == self.node_count:
                return None, None, None
            if node > self.node_count:
                # 走到数据指针：node - node_count = data section 内的偏移
                off = self.data_base + (node - self.node_count)
                val, typ, _ = self.dec.decode(off)
                if self.ip_version == 6 and addr.version == 4:
                    prefix = "%s/%d" % (ip, i + 1 - 96) if i + 1 > 96 else "::/%d" % (i + 1)
                else:
                    prefix = "%s/%d" % (ipaddress.ip_network(
                        "%s/%d" % (ip, i + 1), strict=False).network_address, i + 1)
                return val, typ, prefix
        return None, None, None


def render(val, typ, depth, out):
    """mmdblookup 风格：每个值单独标类型，容器换行缩进。"""
    pad = "  " * depth
    name = TYPE_NAMES.get(typ, "?")
    if typ == 7:  # map
        out.append("{\n")
        for k, (v, vt) in val.items():
            out.append('%s  "%s": ' % (pad, k))
            render(v, vt, depth + 1, out)
        out.append("%s}\n" % pad)
    elif typ == 11:  # array
        out.append("[\n")
        for v, vt in val:
            out.append("%s  - " % pad)
            render(v, vt, depth + 1, out)
        out.append("%s]\n" % pad)
    elif typ == 15:
        out.append("%s <boolean>\n" % ("true" if val else "false"))
    elif typ in (5, 6, 9, 10, 8):
        out.append("%s <%s>\n" % (val, name))
    elif typ in (3, 14):
        out.append("%s <%s>\n" % (val, name))
    else:
        out.append("%s <%s>\n" % (val, name))


def dump(reader, ip, f, out):
    try:
        val, typ, prefix = reader.lookup(ip)
    except Exception as e:
        out.append("%s  查询失败: %s\n" % (ip, e))
        return
    if val is None:
        out.append("%s  (库里没有这条记录)\n" % ip)
        return
    out.append("%s  → 命中 %s\n" % (ip, prefix))
    render(val, typ, 0, out)
    out.append("\n")


def plain(val, typ):
    """把 (值, 类型) 的嵌套结构还原成纯 python 对象，方便丢给 json.dumps。"""
    if typ == 7:
        return {k: plain(v, t) for k, (v, t) in val.items()}
    if typ == 11:
        return [plain(v, t) for v, t in val]
    return val


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return
    path = sys.argv[1]
    ips = [a for a in sys.argv[2:] if not a.startswith("--")]
    r = Reader(path)

    if "--meta" in sys.argv:
        print("== metadata ==")
        for k, (v, t) in r.meta_raw.items():
            print("  %-28s %s" % (k, plain(v, t)))
        print()

    if "--json" in sys.argv:
        rows = []
        for ip in ips:
            val, typ, prefix = r.lookup(ip)
            rows.append({"ip": ip, "prefix": prefix,
                         "record": plain(val, typ) if val is not None else None})
        if len(rows) == 1:
            print(json.dumps(rows[0], ensure_ascii=False, indent=2))
        else:
            print(json.dumps(rows, ensure_ascii=False, indent=2))
        return

    out = []
    for ip in ips:
        dump(r, ip, path, out)
    sys.stdout.write("".join(out))


if __name__ == "__main__":
    main()
