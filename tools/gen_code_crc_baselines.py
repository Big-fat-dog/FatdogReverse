#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KL13 真实代码段 CRC-32 基线烘焙器。

从 NDK 构建产物 app/libs/<abi>/libmantis.so 里定位导出符号 guard，
取其起始 KL13_GUARD_CRC_WINDOW 字节，用标准 CRC-32（同 Python
zlib.crc32）计算基线，写入 app/jni/kl13_crc_baseline.h。运行时
verify_crc() 用同一算法对 guard 代码段重新算 CRC，patch 指令即可检出。

用法:
    python tools/gen_code_crc_baselines.py           # 烘焙并写头文件
    python tools/gen_code_crc_baselines.py --verify  # 校验当前 .so 与头文件是否一致
"""
import os
import re
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIBS = os.path.join(HERE, 'app', 'libs')
JNI = os.path.join(HERE, 'app', 'jni')
HEADER = os.path.join(JNI, 'kl13_crc_baseline.h')
SYMBOL = 'guard'
ABIS = (
    ('arm64-v8a', 'KL13_GUARD_CRC_BASELINE_ARM64'),
    ('armeabi-v7a', 'KL13_GUARD_CRC_BASELINE_ARMEABI_V7A'),
)
WINDOW = 256


def fail(msg):
    sys.stderr.write('gen_code_crc_baselines: %s\n' % msg)
    sys.exit(1)


def read_at(f, size, off):
    f.seek(off)
    data = f.read(size)
    if len(data) != size:
        fail('short read at offset %#x (want %d bytes)' % (off, size))
    return data


def parse_elf(path):
    """返回 (is64, loads, symbols)，loads 为 (p_vaddr, p_offset, p_filesz) 列表。"""
    with open(path, 'rb') as f:
        ident = read_at(f, 16, 0)
        if ident[:4] != b'\x7fELF':
            fail('%s: not an ELF file' % path)
        is64 = ident[4] == 2
        if is64:
            ehdr = read_at(f, 64, 0)
            e_phoff, e_shoff = struct.unpack_from('<QQ', ehdr, 32)
            e_phentsize, e_phnum = struct.unpack_from('<HH', ehdr, 54)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', ehdr, 58)
        else:
            ehdr = read_at(f, 52, 0)
            e_phoff, e_shoff = struct.unpack_from('<II', ehdr, 28)
            e_phentsize, e_phnum = struct.unpack_from('<HH', ehdr, 42)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', ehdr, 46)

        loads = []
        for i in range(e_phnum):
            ph = read_at(f, e_phentsize, e_phoff + i * e_phentsize)
            p_type = struct.unpack_from('<I', ph, 0)[0]
            if p_type != 1:  # PT_LOAD
                continue
            if is64:
                p_offset, p_vaddr = struct.unpack_from('<QQ', ph, 8)
                p_filesz = struct.unpack_from('<Q', ph, 32)[0]
            else:
                p_offset, p_vaddr = struct.unpack_from('<II', ph, 4)
                p_filesz = struct.unpack_from('<I', ph, 16)[0]
            loads.append((p_vaddr, p_offset, p_filesz))

        shdrs = []
        for i in range(e_shnum):
            shdrs.append(read_at(f, e_shentsize, e_shoff + i * e_shentsize))

        def shdr_field(sh, name):
            if is64:
                offs = {'offset': 24, 'size': 32, 'link': 40, 'entsize': 56}
                fmt = {'offset': 'Q', 'size': 'Q', 'link': 'I', 'entsize': 'Q'}
            else:
                offs = {'offset': 16, 'size': 20, 'link': 24, 'entsize': 36}
                fmt = {'offset': 'I', 'size': 'I', 'link': 'I', 'entsize': 'I'}
            return struct.unpack_from('<' + fmt[name], sh, offs[name])[0]

        symbols = {}
        for sh in shdrs:
            sh_type = struct.unpack_from('<I', sh, 4)[0]
            if sh_type not in (2, 11):  # SHT_SYMTAB / SHT_DYNSYM
                continue
            sh_link = struct.unpack_from('<I', sh, 40 if is64 else 24)[0]
            if sh_link >= len(shdrs):
                continue
            sh_off = shdr_field(sh, 'offset')
            sh_size = shdr_field(sh, 'size')
            sh_entsize = shdr_field(sh, 'entsize')
            if sh_entsize == 0:
                continue
            strtab = shdrs[sh_link]
            str_off = shdr_field(strtab, 'offset')
            str_size = shdr_field(strtab, 'size')
            strblob = read_at(f, str_size, str_off)
            for pos in range(0, sh_size, sh_entsize):
                ent = read_at(f, sh_entsize, sh_off + pos)
                if is64:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', ent, 0)
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from('<IIIBBH', ent, 0)
                if st_shndx == 0 or st_value == 0:
                    continue
                end = strblob.find(b'\x00', st_name)
                name = strblob[st_name:end].decode('ascii', 'replace')
                symbols.setdefault(name, (st_value, st_size))
        return is64, loads, symbols


def vaddr_to_offset(vaddr, loads):
    for p_vaddr, p_offset, p_filesz in loads:
        if p_vaddr <= vaddr and vaddr + WINDOW <= p_vaddr + p_filesz:
            return p_offset + (vaddr - p_vaddr)
    return None


def compute_baselines():
    result = {}
    for abi, _ in ABIS:
        path = os.path.join(LIBS, abi, 'libmantis.so')
        if not os.path.isfile(path):
            fail('missing %s (run ndk-build first)' % path)
        is64, loads, symbols = parse_elf(path)
        if SYMBOL not in symbols:
            fail('%s: symbol %s not found' % (abi, SYMBOL))
        st_value, st_size = symbols[SYMBOL]
        if st_size == 0:
            fail('%s: symbol %s has zero size' % (abi, SYMBOL))
        file_off = vaddr_to_offset(st_value, loads)
        if file_off is None:
            fail('%s: guard window crosses PT_LOAD boundary (reduce KL13_GUARD_CRC_WINDOW)' % abi)
        with open(path, 'rb') as f:
            code = read_at(f, WINDOW, file_off)
        result[abi] = zlib.crc32(code) & 0xffffffff
    return result


def read_header_values():
    if not os.path.isfile(HEADER):
        fail('missing %s' % HEADER)
    with open(HEADER, 'rb') as f:
        text = f.read().decode('utf-8', 'replace')
    values = {}
    for _, macro in ABIS:
        m = re.search(r'#define\s+%s\s+0x([0-9a-fA-F]+)' % macro, text)
        if not m:
            fail('header missing %s' % macro)
        values[macro] = int(m.group(1), 16)
    return values


def write_header(baselines):
    lines = [
        '#ifndef KL13_CRC_BASELINE_H',
        '#define KL13_CRC_BASELINE_H',
        '',
        '/* 自动生成：tools/gen_code_crc_baselines.py，请勿手改。 */',
        '#define KL13_GUARD_CRC_WINDOW %d' % WINDOW,
    ]
    for abi, macro in ABIS:
        lines.append('#define %s 0x%08xu' % (macro, baselines[abi]))
    lines.extend(['', '#endif /* KL13_CRC_BASELINE_H */', ''])
    with open(HEADER, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines))


def main():
    verify = '--verify' in sys.argv[1:]
    baselines = compute_baselines()
    for abi, macro in ABIS:
        print('%-11s %s = 0x%08x' % (abi, macro, baselines[abi]))
    if verify:
        old = read_header_values()
        bad = False
        for abi, macro in ABIS:
            if old[macro] != baselines[abi]:
                sys.stderr.write('%s mismatch: header 0x%08x vs so 0x%08x\n'
                                 % (macro, old[macro], baselines[abi]))
                bad = True
        if bad:
            fail('baseline does not match current libmantis.so; rebuild after baking')
        print('verify ok: baselines match the baked header')
    else:
        write_header(baselines)
        print('wrote', os.path.relpath(HEADER, HERE))


if __name__ == '__main__':
    main()
