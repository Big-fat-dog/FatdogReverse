# -*- coding: utf-8 -*-
"""签名基准一致性自检（L43-L47「签名校验对抗」五关）。

背景
----
L43-L47 五关都把「原包签名证书的 SHA-256」烘焙进了代码：
  L43  Wi.PA(^0x3C) + Vk.PB(^0x5A)            —— 纯 Java，拆两段分藏
  L44  pearl.c  BENCH_X(^0x66)                —— native 比对
  L45  coral.c  BENCH_X(^0x66)                —— native 自读 base.apk 后再比
  L46  amber.c  BENCH_X(^0x66) + server.py    —— 派生签名密钥，两侧必须同值
  L47  felix.c  BENCH_X(^0x66) + CRC 烘焙基线 + server.py

证书只由 keystore 里那一对 (私钥, 证书) 决定，与 APK 内容无关；但 keystore 一旦被
重建（build_apk.py 发现文件缺失就会 keytool -genkeypair 重来一把），基准全部失效：
五关会静默变成「一进来就被判定为重打包」，玩家无论怎么逆都过不了。
本脚本把「实际签名证书摘要」和所有烘焙点逐一对拍，任何一处漂移都直接报错。

用法
----
    python tools/verify_signature_baseline.py                  # 用 keystore/debug.keystore 现算
    python tools/verify_signature_baseline.py --apk FatdogReverse.apk   # 用 apksigner 读已签名 APK
    python tools/verify_signature_baseline.py --digest 198ea4e3...      # 直接给摘要

退出码 0 表示全部一致；1 表示有不一致（并列出具体位置）。
"""
import argparse
import hashlib
import io
import os
import re
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JNI = os.path.join(HERE, 'app', 'jni')
SRC = os.path.join(HERE, 'app', 'src', 'com', 'fatdog', 'reverse')
KEYSTORE = os.path.join(HERE, 'keystore', 'debug.keystore')
KS_PASS = 'android'
KS_ALIAS = 'androiddebugkey'

RESULTS = []


def check(name, ok, detail=''):
    RESULTS.append((name, ok, detail))
    print('  [%s] %-46s %s' % ('PASS' if ok else 'FAIL', name, detail))
    return ok


def read(path):
    return io.open(path, encoding='utf-8', errors='ignore').read()


# ---------------------------------------------------------------- 摘要来源
def digest_from_apk(apk):
    sdk = os.environ.get('ANDROID_SDK_ROOT') or os.environ.get('ANDROID_HOME')
    cands = []
    if sdk:
        bt = os.path.join(sdk, 'build-tools')
        if os.path.isdir(bt):
            for d in sorted(os.listdir(bt), reverse=True):
                for n in ('apksigner.bat', 'apksigner'):
                    p = os.path.join(bt, d, n)
                    if os.path.isfile(p):
                        cands.append(p)
    if not cands:
        raise SystemExit('找不到 apksigner：请设置 ANDROID_SDK_ROOT，或改用 --digest/--keystore')
    out = subprocess.run([cands[0], 'verify', '--print-certs', apk],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    txt = out.stdout.decode('utf-8', 'replace')
    m = re.search(r'SHA-256 digest:\s*([0-9a-fA-F]{64})', txt)
    if not m:
        raise SystemExit('apksigner 没吐出证书 SHA-256，输出：\n' + txt[:800])
    return m.group(1).lower()


def digest_from_keystore(ks=KEYSTORE):
    java_home = os.environ.get('JAVA_HOME', '')
    keytool = os.path.join(java_home, 'bin', 'keytool.exe') if java_home else 'keytool'
    if not (os.path.isfile(keytool) or keytool == 'keytool'):
        keytool = 'keytool'
    fd, tmp = tempfile.mkstemp(suffix='.cer')
    os.close(fd)
    try:
        out = subprocess.run([keytool, '-exportcert', '-keystore', ks,
                              '-storepass', KS_PASS, '-alias', KS_ALIAS, '-file', tmp],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if out.returncode != 0 or os.path.getsize(tmp) == 0:
            raise SystemExit('keytool 导出失败：\n' + out.stdout.decode('utf-8', 'replace'))
        return hashlib.sha256(open(tmp, 'rb').read()).hexdigest()
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


# ---------------------------------------------------------------- 各烘焙点
def java_split_digest():
    """L43：Wi.PA ^0x3C ‖ Vk.PB ^0x5A"""
    pa_m = re.search(r'int\[\]\s*PA\s*=\s*\{(.*?)\};', read(os.path.join(SRC, 'Wi.java')), re.S)
    pb_m = re.search(r'int\[\]\s*PB\s*=\s*\{(.*?)\};', read(os.path.join(SRC, 'Vk.java')), re.S)
    if not (pa_m and pb_m):
        return None, 'Wi.PA / Vk.PB 没找到'
    nums = lambda s: [int(x) for x in re.findall(r'\d+', s)]
    pa, pb = nums(pa_m.group(1)), nums(pb_m.group(1))
    s = ''.join(chr(v ^ 0x3C) for v in pa) + ''.join(chr(v ^ 0x5A) for v in pb)
    if not re.fullmatch(r'[0-9a-fA-F]{64}', s):
        return None, '解出来不是 64 位 hex：%r' % s[:80]
    return s.lower(), 'PA=%d 项 / PB=%d 项' % (len(pa), len(pb))


def c_bench_digest(fname):
    """native：unsigned char BENCH_X[32] ^0x66"""
    m = re.search(r'BENCH_X\[32\]\s*=\s*\{(.*?)\};', read(os.path.join(JNI, fname)), re.S)
    if not m:
        return None, 'BENCH_X 没找到'
    b = [int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', m.group(1))]
    if len(b) != 32:
        return None, 'BENCH_X 只有 %d 字节' % len(b)
    return bytes(v ^ 0x66 for v in b).hex(), '32 字节'


def felix_crc():
    """L47：CRC32(MARK_X ‖ DMARK_X ‖ BENCH_X) 与 M9_CRC_BASELINE 比对"""
    s = read(os.path.join(JNI, 'felix.c'))
    mm = re.search(r'MARK_X\[\]\s*=\s*\{(.*?)\};', s, re.S)
    dm = re.search(r'DMARK_X\[\]\s*=\s*\{(.*?)\};', s, re.S)
    bm = re.search(r'BENCH_X\[32\]\s*=\s*\{(.*?)\};', s, re.S)
    cm = re.search(r'#define\s+M9_CRC_BASELINE\s+0x([0-9A-Fa-f]{8})', s)
    if not (mm and dm and bm and cm):
        return False, 0, 0, 'MARK_X/DMARK_X/BENCH_X/M9_CRC_BASELINE 有缺失'
    dec = lambda x: [int(v) for v in re.findall(r'\d+', x)]
    bench = [int(v, 16) for v in re.findall(r'0x([0-9a-fA-F]{2})', bm.group(1))]
    buf = bytes(dec(mm.group(1)) + dec(dm.group(1)) + bench)
    got = zlib.crc32(buf) & 0xFFFFFFFF
    want = int(cm.group(1), 16)
    return got == want, got, want, '覆盖 %d 字节' % len(buf)


def server_hash(tag):
    m = re.search(r'_%s_CERT_HASH\s*=\s*bytes\.fromhex\("([0-9a-fA-F]{64})"\)' % tag,
                  read(os.path.join(HERE, 'server.py')))
    return m.group(1).lower() if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--apk', help='已签名 APK（用 apksigner 读签名证书摘要）')
    ap.add_argument('--digest', help='直接指定证书 SHA-256（64 位 hex）')
    ap.add_argument('--keystore', help='keystore 路径（默认 keystore/debug.keystore）')
    a = ap.parse_args()

    if a.digest:
        ref, src_desc = a.digest.lower().strip(), '--digest'
    elif a.apk:
        ref, src_desc = digest_from_apk(a.apk), 'apksigner(' + os.path.basename(a.apk) + ')'
    else:
        ref, src_desc = digest_from_keystore(a.keystore or KEYSTORE), 'keystore'
    if not re.fullmatch(r'[0-9a-f]{64}', ref):
        print('实际摘要格式不对：%r' % ref)
        return 1

    print('实际签名证书 SHA-256（%s）:' % src_desc)
    print('  ' + ref)
    print()

    print('各烘焙点：')
    j, jd = java_split_digest()
    check('L43  Wi.PA/Vk.PB', j == ref, jd)
    for fname, lv in (('pearl.c', 'L44'), ('coral.c', 'L45'), ('amber.c', 'L46'), ('felix.c', 'L47')):
        d, dd = c_bench_digest(fname)
        check('%s  %s BENCH_X' % (lv, fname), d == ref, dd)
    for tag, lv in (('L46', 'L46'), ('L47', 'L47')):
        h = server_hash(tag)
        check('%s  server.py _%s_CERT_HASH' % (lv, tag), h == ref, '缺失' if h is None else '')

    print()
    ok, got, want, dd = felix_crc()
    check('L47  felix.c CRC 烘焙基线', ok, dd + ('  got=0x%08X want=0x%08X' % (got, want)))

    cer = os.path.join(HERE, 'certs', 'app_signing.cer')
    if os.path.isfile(cer):
        h = hashlib.sha256(open(cer, 'rb').read()).hexdigest()
        check('certs/app_signing.cer', h == ref, '%d 字节' % os.path.getsize(cer))
    else:
        check('certs/app_signing.cer', False, '文件不存在')

    bad = [n for n, o, _ in RESULTS if not o]
    print()
    if bad:
        print('不一致 %d 处：%s' % (len(bad), ', '.join(bad)))
        print('keystore 换过？把上面「实际摘要」重新烘焙进这些位置（BENCH_X 用摘要 ^0x66，'
              'L47 还要重算 CRC），或用旧 keystore 重新签名。')
        return 1
    print('全部一致（%d 项 / ALL PASS）' % len(RESULTS))
    return 0


if __name__ == '__main__':
    sys.exit(main())
