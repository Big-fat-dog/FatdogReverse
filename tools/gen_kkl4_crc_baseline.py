#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KKL4 真实代码段 CRC-32 基线烘焙器（libkkl4.so，锁妖塔）。

从 NDK 构建产物 app/libs/<abi>/libkkl4.so 定位四个导出符号，取其起始
KKL4_CRC_WINDOW 字节，用标准 CRC-32（同 Python zlib.crc32）计算基线，
写入 app/jni/kkl4_crc_baseline.h。运行时 kkl4.cpp 对相同内存窗口重算，
patch 任一窗口内指令或 inline hook 都会导致不匹配并触发密钥投毒。

用法:
    python tools/gen_kkl4_crc_baseline.py            # 烘焙并写头文件
    python tools/gen_kkl4_crc_baseline.py --verify   # 校验当前 so 与头文件
    python tools/gen_kkl4_crc_baseline.py --dir <so目录根>
"""
import os
import re
import struct
import sys
import zlib

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JNI = os.path.join(HERE, 'app', 'jni')
HEADER = os.path.join(JNI, 'kkl4_crc_baseline.h')
LIBS = os.path.join(HERE, 'app', 'libs')
ABIS = (
    ('arm64-v8a', 'ARM64'),
    ('armeabi-v7a', 'ARMEABI_V7A'),
)
WINDOW = 512
SYMBOLS = (
    ('open', 'Java_com_fatdog_reverse_Kkl4Native_nativeOpen', 'KKL4_CRC_OPEN'),
    ('sign', 'Java_com_fatdog_reverse_Kkl4Native_nativeSign', 'KKL4_CRC_SIGN'),
    ('commit', 'Java_com_fatdog_reverse_Kkl4Native_nativeCommit', 'KKL4_CRC_COMMIT'),
    ('check', 'kkl4_crc_check', 'KKL4_CRC_CHECK'),
)


def fail(msg):
    sys.stderr.write('gen_kkl4_crc_baseline: %s\n' % msg)
    sys.exit(1)


def read_at(f, size, off):
    f.seek(off)
    data = f.read(size)
    if len(data) != size:
        fail('short read at offset %#x (want %d bytes)' % (off, size))
    return data


def parse_elf(path):
    """返回 (is64, loads, symbols)，loads 为 (p_vaddr, p_offset, p_filesz)。"""
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


def compute_baselines(libs_root):
    result = {}
    for abi, _ in ABIS:
        path = os.path.join(libs_root, abi, 'libkkl4.so')
        if not os.path.isfile(path):
            fail('missing %s (run ndk-build first)' % path)
        is64, loads, symbols = parse_elf(path)
        entry = {}
        for _, symbol, macro in SYMBOLS:
            if symbol not in symbols:
                fail('%s: symbol %s not found' % (abi, symbol))
            st_value, st_size = symbols[symbol]
            if st_size == 0:
                fail('%s: symbol %s has zero size' % (abi, symbol))
            file_off = vaddr_to_offset(st_value, loads)
            if file_off is None:
                fail('%s: %s window crosses PT_LOAD boundary (reduce KKL4_CRC_WINDOW)'
                     % (abi, symbol))
            with open(path, 'rb') as f:
                code = read_at(f, WINDOW, file_off)
            entry[macro] = zlib.crc32(code) & 0xffffffff
        result[abi] = entry
    return result


def read_header_values():
    if not os.path.isfile(HEADER):
        fail('missing %s' % HEADER)
    with open(HEADER, 'rb') as f:
        text = f.read().decode('utf-8', 'replace')
    values = {}
    for _, suffix in ABIS:
        for _, _, macro in SYMBOLS:
            full = '%s_%s' % (macro, suffix)
            m = re.search(r'#define\s+%s\s+0x([0-9a-fA-F]+)' % full, text)
            if not m:
                fail('header missing %s' % full)
            values[full] = int(m.group(1), 16)
    return values


def write_header(baselines):
    lines = [
        '#ifndef KKL4_CRC_BASELINE_H',
        '#define KKL4_CRC_BASELINE_H',
        '',
        '/* 自动生成：tools/gen_kkl4_crc_baseline.py，请勿手改。 */',
        '#define KKL4_CRC_WINDOW %d' % WINDOW,
    ]
    for abi, suffix in ABIS:
        for _, _, macro in SYMBOLS:
            lines.append('#define %s_%s 0x%08xu' % (macro, suffix, baselines[abi][macro]))
    lines.extend(['', '#endif /* KKL4_CRC_BASELINE_H */', ''])
    with open(HEADER, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines))


def main():
    libs_root = LIBS
    args = sys.argv[1:]
    if '--dir' in args:
        i = args.index('--dir')
        if i + 1 >= len(args):
            fail('--dir requires a path')
        libs_root = os.path.abspath(args[i + 1])
        del args[i:i + 2]
    verify = '--verify' in args
    baselines = compute_baselines(libs_root)
    for abi, _ in ABIS:
        for _, symbol, macro in SYMBOLS:
            suffix = next(s for a, s in ABIS if a == abi)
            print('%-11s %-38s %s_%s = 0x%08x'
                  % (abi, symbol, macro, suffix, baselines[abi][macro]))
    if verify:
        old = read_header_values()
        bad = False
        for abi, suffix in ABIS:
            for _, _, macro in SYMBOLS:
                full = '%s_%s' % (macro, suffix)
                if old[full] != baselines[abi][macro]:
                    sys.stderr.write('%s mismatch: header 0x%08x vs so 0x%08x\n'
                                     % (full, old[full], baselines[abi][macro]))
                    bad = True
        if bad:
            fail('baseline does not match current libkkl4.so; rebuild after baking')
        print('verify ok: baselines match the baked header')
    else:
        write_header(baselines)
        print('wrote', os.path.relpath(HEADER, HERE))


if __name__ == '__main__':
    main()
