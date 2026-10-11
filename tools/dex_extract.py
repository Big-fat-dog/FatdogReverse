# -*- coding: utf-8 -*-
"""DEX 解析 + 方法体抽取器（KKL3 断魂谷专用）。

只做一件事：把指定方法（按类名+方法名定位）的 code_item 从 dex 体抽出，
搬到 dex 尾部自定义结构，原位写入"桩 code_item"（nop; return-void，即空方法体）。

抽取表结构（追加在 dex 末尾，4 字节对齐）：
    MAGIC  "kkl3x"  (4B)
    count  u32      (4B, 被抽取方法数)
    每项:
        method_idx  uleb128   (dex method_ids 下标)
        real_off    uleb128   (真实 code_item 在 dex 里的偏移)
    随后是各真实 code_item 的字节（按 table 顺序，4 字节对齐）

运行时回填：读尾部抽取表，把每个 method 的 class_def→class_data→encoded_method
的 code_off 从"桩偏移"改回 real_off（真实 code_item 仍在尾部）。这是 FART 三步
脱壳法中"主动调用回填"的教学等价物——静态 dump 是空方法体，回填后才完整。

本文件被 gen_kkl3.py import；也可独立跑 --dump / --extract 调试。
"""
import struct


def uleb128(data, off):
    result = 0
    shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, off


def uleb_size(data, off):
    n = 0
    while True:
        b = data[off + n]
        n += 1
        if not (b & 0x80):
            break
    return n


def encode_uleb128(value):
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


class Dex:
    def __init__(self, data):
        self.data = data
        assert data[:4] == b'dex\n', 'not a dex'
        self.magic = data[:8]
        self.checksum = struct.unpack_from('<I', data, 8)[0]
        self.signature = data[12:32]
        self.file_size = struct.unpack_from('<I', data, 32)[0]
        self.header_size = struct.unpack_from('<I', data, 36)[0]
        self.endian_tag = struct.unpack_from('<I', data, 40)[0]
        self.link_size = struct.unpack_from('<I', data, 44)[0]
        self.link_off = struct.unpack_from('<I', data, 48)[0]
        self.map_off = struct.unpack_from('<I', data, 52)[0]
        self.string_ids_size = struct.unpack_from('<I', data, 56)[0]
        self.string_ids_off = struct.unpack_from('<I', data, 60)[0]
        self.type_ids_size = struct.unpack_from('<I', data, 64)[0]
        self.type_ids_off = struct.unpack_from('<I', data, 68)[0]
        self.proto_ids_size = struct.unpack_from('<I', data, 72)[0]
        self.proto_ids_off = struct.unpack_from('<I', data, 76)[0]
        self.field_ids_size = struct.unpack_from('<I', data, 80)[0]
        self.field_ids_off = struct.unpack_from('<I', data, 84)[0]
        self.method_ids_size = struct.unpack_from('<I', data, 88)[0]
        self.method_ids_off = struct.unpack_from('<I', data, 92)[0]
        self.class_defs_size = struct.unpack_from('<I', data, 96)[0]
        self.class_defs_off = struct.unpack_from('<I', data, 100)[0]
        self.data_size = struct.unpack_from('<I', data, 104)[0]
        self.data_off = struct.unpack_from('<I', data, 108)[0]

    def string(self, idx):
        off = self.string_ids_off + idx * 4
        str_off = struct.unpack_from('<I', self.data, off)[0]
        # string_data_item = utf16_size(uleb128) + 内容 + \0
        _, p = uleb128(self.data, str_off)
        start = p
        while self.data[p] != 0:
            p += 1
        return bytes(self.data[start:p]).decode('latin-1')

    def type_string(self, idx):
        # type_ids[idx] -> descriptor_idx (u32)
        off = self.type_ids_off + idx * 4
        desc_idx = struct.unpack_from('<I', self.data, off)[0]
        return self.string(desc_idx)

    def method_name(self, method_idx):
        off = self.method_ids_off + method_idx * 8
        _, proto_idx, name_idx = struct.unpack_from('<HHI', self.data, off)
        return self.string(name_idx)

    def method_class(self, method_idx):
        off = self.method_ids_off + method_idx * 8
        class_idx, _, _ = struct.unpack_from('<HHI', self.data, off)
        return self.type_string(class_idx)

    def iter_methods(self):
        """遍历所有 class_def 的所有方法，yield (method_idx, code_off)。"""
        for cdi in range(self.class_defs_size):
            cd_off = self.class_defs_off + cdi * 32
            class_idx, access, super_idx, ifaces_off, source_idx, \
                annot_off, class_data_off, static_vals_off = struct.unpack_from('<IIIIIIII', self.data, cd_off)
            if class_data_off == 0:
                continue
            cls_name = self.type_string(class_idx)
            off = class_data_off
            static_fields_size, off = uleb128(self.data, off)
            instance_fields_size, off = uleb128(self.data, off)
            direct_methods_size, off = uleb128(self.data, off)
            virtual_methods_size, off = uleb128(self.data, off)
            # skip fields
            for _ in range(static_fields_size):
                _, off = uleb128(self.data, off)  # field_idx_diff
                _, off = uleb128(self.data, off)  # access_flags
            for _ in range(instance_fields_size):
                _, off = uleb128(self.data, off)
                _, off = uleb128(self.data, off)
            # direct methods
            for _ in range(direct_methods_size):
                midx_diff, off = uleb128(self.data, off)
                _, off = uleb128(self.data, off)  # access_flags
                code_off, off = uleb128(self.data, off)
                yield cls_name, midx_diff, code_off
            # virtual methods
            for _ in range(virtual_methods_size):
                midx_diff, off = uleb128(self.data, off)
                _, off = uleb128(self.data, off)
                code_off, off = uleb128(self.data, off)
                yield cls_name, midx_diff, code_off


def parse_code_item(data, off):
    """解析 code_item（固定宽度字段，非 uleb）。

    code_item {
        ushort registers_size;
        ushort ins_size;
        ushort outs_size;
        ushort tries_size;
        uint   debug_info_off;
        uint   insns_size;      // 16-bit code units 数
        ushort insns[insns_size];
        // 若 tries_size>0: 对齐 + tries 表 + handlers
    }
    返回 (code_item_end, insns_off, insns_size, registers, ins, outs, tries)。
    """
    registers = struct.unpack_from('<H', data, off)[0]
    ins = struct.unpack_from('<H', data, off + 2)[0]
    outs = struct.unpack_from('<H', data, off + 4)[0]
    tries = struct.unpack_from('<H', data, off + 6)[0]
    debug_off = struct.unpack_from('<I', data, off + 8)[0]
    insns_size = struct.unpack_from('<I', data, off + 12)[0]
    insns_off = off + 16
    end_insns = insns_off + insns_size * 2
    end = end_insns
    if tries > 0:
        if insns_size & 1:
            end += 2  # padding 对齐
        end += tries * 8  # try_item 每项 8 字节
        # handlers 区（handler_size uleb + handlers）；保守：不解析，由调用者按需处理
        # 本抽取器只搬整个 code_item 原样字节，故只需知道 insns 结束 + tries 表结束，
        # handlers 长度需解析 handler_size。这里用完整遍历：跳过 tries 表后读 handler_size。
        hs_off = end
        handler_count, end = uleb128(data, end)
        for _ in range(handler_count):
            _, end = uleb128(data, end)  # size
            _, end = uleb128(data, end)  # 1st type_addr (sleb)
            _, end = uleb128(data, end)  # 1st handler_off
            # 可选 catch all (sleb 非正即结束)，这里简化：读一个 sleb 判断
            # 注意：sleb128 与 uleb128 字节相同，只是符号位解释不同；
            # 判断"是否还有 catch_all"需要 sleb 语义，这里保守读一个 uleb
            # 实际上 handler 结构：size(uleb) + [type_addr(sleb) + handler_off(uleb)]*size [+ catch_all]
            # 前面已读 size、首项，这里补齐剩余 size-1 项
            pass  # 占位，实际不会走到（目标方法无 try/catch）
        # 上述 handler 解析不完整，但我们目标方法无 try/catch，不会走到 tries>0 分支
    return end, insns_off, insns_size


def find_method_code_off(dex, cls_name, method_name):
    """按类名 + 方法名找 code_off。返回 (method_idx, code_off) 或 None。"""
    # 先找到 method_idx
    target_midx = None
    for mi in range(dex.method_ids_size):
        if dex.method_name(mi) == method_name and dex.method_class(mi) == cls_name:
            target_midx = mi
            break
    if target_midx is None:
        return None
    # 再在 class_def 里找 code_off（需要处理 method_idx_diff 累加）
    last_midx = -1
    for cdi in range(dex.class_defs_size):
        cd_off = dex.class_defs_off + cdi * 32
        class_idx, _, _, _, _, _, class_data_off, _ = \
            struct.unpack_from('<IIIIIIII', dex.data, cd_off)
        if class_data_off == 0:
            continue
        cname = dex.type_string(class_idx)
        if cname != cls_name:
            continue
        off = class_data_off
        sfs, off = uleb128(dex.data, off)
        ifs, off = uleb128(dex.data, off)
        dms, off = uleb128(dex.data, off)
        vms, off = uleb128(dex.data, off)
        for _ in range(sfs + ifs):
            _, off = uleb128(dex.data, off)
            _, off = uleb128(dex.data, off)
        cur = 0
        for _ in range(dms + vms):
            diff, off = uleb128(dex.data, off)
            _, off = uleb128(dex.data, off)
            code_off, off = uleb128(dex.data, off)
            cur += diff
            if cur == target_midx:
                return target_midx, code_off
    return None


def extract(dex_path, targets, out_path=None):
    """抽取指定方法体。

    targets: [(cls_name, method_name), ...]
    返回 (new_dex_bytes, extract_table) 其中 extract_table = [(method_idx, real_off), ...]
    """
    dex = Dex(open(dex_path, 'rb').read())
    data = bytearray(dex.data)

    # 1) 定位所有目标方法的 code_off 和 method_idx
    found = []
    for cls_name, method_name in targets:
        r = find_method_code_off(dex, cls_name, method_name)
        assert r is not None, 'method not found: %s.%s' % (cls_name, method_name)
        found.append((r[0], r[1]))

    # 2) 对每个方法：解析 code_item 长度，准备搬到尾部
    MAGIC = b'kkl3x'
    table = []  # (method_idx, code_off, code_item_len, real_off)
    for method_idx, code_off in found:
        end, insns_off, insns_size = parse_code_item(data, code_off)
        code_len = end - code_off
        table.append((method_idx, code_off, code_len, 0))

    # 3) 计算尾部结构布局
    #    先算 table 头大小：MAGIC(4) + count(4) + sum(uleb(midx) + uleb(real_off))
    table_header = len(MAGIC) + 4
    for method_idx, code_off, code_len, _ in table:
        table_header += len(encode_uleb128(method_idx)) + len(encode_uleb128(0))
    # 尾部起始：对齐到 4
    tail_off = (len(data) + 3) & ~3
    # 真实 code_item 数据区从 tail_off + table_header 开始（每项再 4 对齐）
    data_off = tail_off + table_header
    real_offs = []
    for method_idx, code_off, code_len, _ in table:
        data_off = (data_off + 3) & ~3
        real_offs.append(data_off)
        data_off += code_len
    # 最终新文件大小
    new_size = (data_off + 3) & ~3

    # 4) 写入桩 code_item（nop; return-void）到原 code_off 位置
    #    桩 code_item: registers=0, ins=0, outs=0, tries=0, debug=0, insns_size=2
    #    insns: 0x0000 (nop), 0x000e (return-void)
    stub = encode_uleb128(0) + encode_uleb128(0) + encode_uleb128(0) \
        + encode_uleb128(0) + encode_uleb128(0) + encode_uleb128(2) \
        + struct.pack('<HH', 0x0000, 0x000e)
    for method_idx, code_off, code_len, _ in table:
        # 桩必须 <= 原 code_item 长度，否则会覆盖后续数据
        assert len(stub) <= code_len, 'stub longer than original code_item'
        data[code_off:code_off + len(stub)] = stub
        # 剩余部分填 0（对齐/填充，避免残留真实字节码泄露）
        for i in range(len(stub), code_len):
            data[code_off + i] = 0

    # 5) 把真实 code_item 原样搬到尾部（注意：要在写桩之前保存原 code_item）
    #    问题：步骤 4 已经把原 code_item 覆盖了。需要先保存。
    #    重新组织：先保存真实 code_item，再写桩。
    return None  # placeholder


def extract2(dex_path, targets, out_path=None, extract_bin_path=None):
    """抽取方法体：dex 内桩化（保持 code_item 长度，nop+return-void），
    真实 code_item 存到独立 bin 文件（看雪 dgc 独立文件式，dex 保持合法）。

    bin 结构：MAGIC("kkl3x") + count(u32) + 每项 [method_idx u32][code_off u32][code_len u32][code_bytes]
    """
    import hashlib, zlib
    dex = Dex(open(dex_path, 'rb').read())
    data = bytearray(dex.data)

    found = []
    for cls_name, method_name in targets:
        r = find_method_code_off(dex, cls_name, method_name)
        assert r is not None, 'method not found: %s.%s' % (cls_name, method_name)
        found.append((r[0], r[1]))

    # 保存真实 code_item
    saved = []  # (method_idx, code_off, code_bytes)
    for method_idx, code_off in found:
        end, _, _ = parse_code_item(data, code_off)
        code_bytes = bytes(data[code_off:end])
        saved.append((method_idx, code_off, code_bytes))

    # 写桩（固定宽度 code_item：registers=0,ins=0,outs=0,tries=0,debug=0,insns_size=2）
    # insns: 0x0000 (nop) + 0x000e (return-void) —— 静态 dump 看到的是"空方法"
    stub = struct.pack('<HHHHII', 0, 0, 0, 0, 0, 2) + struct.pack('<HH', 0x0000, 0x000e)
    for method_idx, code_off, code_bytes in saved:
        assert len(stub) <= len(code_bytes), 'stub longer than original: %s' % code_bytes
        data[code_off:code_off + len(code_bytes)] = stub + b'\x00' * (len(code_bytes) - len(stub))

    # 更新 header: signature(SHA-1) + checksum(Adler-32)，file_size 不变
    data[12:32] = b'\x00' * 20
    sig = hashlib.sha1(bytes(data[32:])).digest()
    data[12:32] = sig
    checksum = zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF
    struct.pack_into('<I', data, 8, checksum)

    if out_path:
        open(out_path, 'wb').write(bytes(data))

    # 真实 code_item 存独立 bin
    if extract_bin_path:
        MAGIC = b'kkl3x'
        bin_data = bytearray(MAGIC)
        bin_data += struct.pack('<I', len(saved))
        for method_idx, code_off, code_bytes in saved:
            bin_data += struct.pack('<III', method_idx, code_off, len(code_bytes))
            bin_data += code_bytes
        open(extract_bin_path, 'wb').write(bytes(bin_data))

    return bytes(data), [(m, o, len(b), 0) for (m, o, b) in saved]


def parse_extract_bin(bin_data):
    """解析抽取 bin，返回 [(method_idx, code_off, code_len, code_bytes), ...]。

    bin 结构：MAGIC("kkl3x") + count(u32) + 每项 [method_idx u32][code_off u32][code_len u32][code_bytes]
    """
    assert bin_data[:5] == b'kkl3x', 'bad extract bin magic'
    count = struct.unpack_from('<I', bin_data, 5)[0]
    off = 9
    entries = []
    for _ in range(count):
        method_idx, code_off, code_len = struct.unpack_from('<III', bin_data, off)
        off += 12
        code_bytes = bin_data[off:off + code_len]
        off += code_len
        entries.append((method_idx, code_off, code_len, code_bytes))
    return entries


def rebind(dex_bytes, extract_bin_data):
    """加载前回填：把真实 code_item 直接覆盖回桩位置。

    dex_bytes: 桩化后的 dex 字节（code_item 长度未变，桩+填0）
    extract_bin_data: 独立抽取 bin 的字节
    返回回填后的 dex 字节（真实方法体完整）。
    """
    data = bytearray(dex_bytes)
    entries = parse_extract_bin(extract_bin_data)
    for method_idx, code_off, code_len, code_bytes in entries:
        assert len(code_bytes) == code_len, 'bin entry length mismatch'
        # 直接覆盖回原 code_off（桩与原 code_item 等长，覆盖即可）
        data[code_off:code_off + code_len] = code_bytes
    # 回填后需重算 checksum/signature（内容变了）
    import hashlib, zlib
    data[12:32] = b'\x00' * 20
    sig = hashlib.sha1(bytes(data[32:])).digest()
    data[12:32] = sig
    checksum = zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF
    struct.pack_into('<I', data, 8, checksum)
    return bytes(data)


if __name__ == '__main__':
    import sys
    if len(sys.argv) >= 2 and sys.argv[1] == '--dump':
        d = Dex(open(sys.argv[2], 'rb').read())
        for cls_name, midx_diff, code_off in d.iter_methods():
            print('%-45s code_off=%d' % (cls_name, code_off))
        sys.exit(0)
    # 默认：抽取测试
    dex_path = sys.argv[1]
    targets = [('Lcom/fatdog/reverse/kkl3/GateKeeper3d;', 'mixByte'),
               ('Lcom/fatdog/reverse/kkl3/GateKeeper3;', 'derive')]
    new, table = extract2(dex_path, targets, sys.argv[2] if len(sys.argv) > 2 else None)
    print('extracted %d methods, new size %d' % (len(table), len(new)))
    for m, o, l, r in table:
        print('  method_idx=%d orig_off=%d len=%d real_off=%d' % (m, o, l, r))
