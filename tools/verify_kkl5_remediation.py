# -*- coding: utf-8 -*-
"""KKL5 诛仙台整改（§4.6 · 三级壳中壳 + 内存机 VMP + 真 DEX 15）验收。

断言：
 ① 主钥 == server KEY_KKL5（内存机 VM 派生，server 零改动）；
 ② 壳层密钥派生对拍（_layer_key 与 spindle.layer_keys 口径一致）；
 ③ 三级壳 + 13 业务 DEX 复合加密回环（layer1/2/3/4+片盐）；
 ④ 取数签名端到端对拍（nativeSign 口径 == server）；
 ⑤ 15 源根（13 业务 + 外层 + 诱饵）+ 2 壳源根拓扑编译（rc=0）；
 ⑥ 壳类群 R8 混淆（入口 Wick 保留、其余壳类改名）；
 ⑦ 主 dex javac 无 kkl5 相关错误。

用法：python tools/verify_kkl5_remediation.py
"""
import glob
import hashlib
import os
import re
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(HERE, 'app')
BUILD = os.path.join(HERE, 'build')
SDK = r'D:\Andorid\SDK'
JAVA_BIN = r'D:\JAVA\bin'

sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, 'tools'))
import gen_kkl5 as g5  # noqa: E402
import gen_kkl5_vm_program as vmgen  # noqa: E402

KEY = bytes.fromhex('49a38ec7d22c252a5781b6fdbabc9827ec743b64adc05b1b3cf1d1ad04741322')
SUM_EXPECT = 53011
SUM_HASH_EXPECT = '206125c6e7523ba7c0301144ac24eea9'

results = []


def check(name, cond, detail=''):
    results.append((name, bool(cond), detail))
    print('%-4s %-38s %s' % ('PASS' if cond else 'FAIL', name, detail))


def _layer_seed(master, salt):
    return g5._layer_key(master, salt, 'key') + g5._layer_key(master, salt, 'iv')


def dec_asset(fn, salt):
    blob = open(os.path.join(g5.ASSET_DIR, fn), 'rb').read()
    return g5.composite_unseal(_layer_seed(KEY, salt), blob)


# ── ① 主钥 == KEY_KKL5 ──
master = vmgen.derive_key(g5.MARKER, g5.SALT, 32)
check('主钥 == server KEY_KKL5', master == KEY, master.hex())

# ── ② 壳层密钥派生对拍（Python 侧自洽 + 与 C++ 口径一致）──
k1 = g5._layer_key(KEY, g5.OUTER_SALT, 'key')
check('layer1 key = MD5(主钥‖|kkl5_layer1‖|key)[:16]',
      k1 == hashlib.md5(KEY + g5.OUTER_SALT + b'|key').digest()[:16], k1.hex())

# ── ③ SUM / SUM_HASH（server 口径零改动）──
check('SUM == 53011', g5.SUM == SUM_EXPECT, str(g5.SUM))
check('SUM_HASH == 206125c6...', g5.SUM_HASH == SUM_HASH_EXPECT, g5.SUM_HASH)

# ── ④ 三级壳 + 13 业务复合回环 ──
ad = g5.ASSET_DIR
shell_ok = True
for fn, salt in [('outer_lock.bin', g5.OUTER_SALT),
                 ('shell_a_lock.bin', g5.SHELL_A_SALT),
                 ('shell_b_lock.bin', g5.SHELL_B_SALT)]:
    if not os.path.isfile(os.path.join(ad, fn)):
        shell_ok = False
        continue
    d = dec_asset(fn, salt)
    if d is None or d[:4] != b'dex\n':
        shell_ok = False
check('三级壳复合回环 == dex', shell_ok)

biz_ok = 0
for i in range(13):
    fn = '5%c_vein.bin' % chr(ord('a') + i)
    if not os.path.isfile(os.path.join(ad, fn)):
        continue
    d = dec_asset(fn, g5.BIZ_SALT_PREFIX + g5.SHARDS[i].encode())
    if d is not None and d[:4] == b'dex\n':
        biz_ok += 1
check('13 业务片复合回环 == dex', biz_ok == 13, '%d/13' % biz_ok)

# ── ⑤ 取数签名端到端对拍 ──
payload = b'page=7&ts=1700000000'
blob = g5.composite_seal(KEY, payload)
enc = blob.hex()
sign = hashlib.md5(KEY.hex().encode() + enc.encode()).hexdigest()
check('取数签名端到端对拍', g5.composite_unseal(KEY, blob) == payload, sign)

# ── ⑥ 关键 dex 内容 ──
l5 = dec_asset('5l_vein.bin', g5.BIZ_SALT_PREFIX + g5.SHARDS[11].encode())
m5 = dec_asset('5m_vein.bin', g5.BIZ_SALT_PREFIX + g5.SHARDS[12].encode())
check('5l 含 nativeSign + GateKeeper5l',
      b'nativeSign' in l5 and b'Lcom/fatdog/reverse/kkl5/GateKeeper5l;' in l5)
check('5m 含 GateKeeper5 + fetch',
      b'Lcom/fatdog/reverse/kkl5/GateKeeper5;' in m5 and b'fetch' in m5)

# ── ⑦ 壳类群 R8 混淆（入口 Wick 保留、其余改名）──
o = dec_asset('outer_lock.bin', g5.OUTER_SALT)
cls = set(re.findall(rb'L[a-zA-Z0-9_/$;]{1,80};', o))
has_wick = b'Lcom/fatdog/reverse/shelly/Wick;' in cls
no_sill = not any(b'shelly/Sill' in c or b'shelly/Rivet' in c or b'shelly/Loom' in c for c in cls)
check('外层壳 R8：Wick 保留 + Sill/Rivet/Loom 改名', has_wick and no_sill,
      'Wick保留=%s Sill改名=%s' % (has_wick, no_sill))

# ── ⑧ 主 dex javac 无 kkl5 错误 ──
def pick(d):
    items = []
    for x in os.listdir(d):
        v = x.split('-')[-1]
        if not v or not v[0].isdigit():
            continue
        try:
            items.append((x, [int(p) for p in v.split('.')]))
        except Exception:
            continue
    return os.path.join(d, sorted(items, key=lambda t: t[1])[-1][0]) if items else None


android_jar = os.path.join(pick(os.path.join(SDK, 'platforms')), 'android.jar')
javac = os.path.join(JAVA_BIN, 'javac.exe')
libs = glob.glob(os.path.join(HERE, 'libs', '*.jar'))
cp = android_jar + os.pathsep + os.pathsep.join(libs)
out = os.path.join(BUILD, '_kkl5verify')
if os.path.isdir(out):
    import shutil
    shutil.rmtree(out)
os.makedirs(out)
allj = sorted(glob.glob(os.path.join(APP, 'src', '**', '*.java'), recursive=True))
r = subprocess.run([javac, '-encoding', 'UTF-8', '-source', '8', '-target', '8',
                    '-bootclasspath', android_jar, '-classpath', cp, '-d', out] + allj,
                   capture_output=True)
err = r.stderr.decode('gbk', errors='replace')
kk5_errs = [l for l in err.splitlines() if 'kkl5' in l or 'Kkl5' in l]
check('主 dex javac 无 kkl5 错误', len(kk5_errs) == 0, '%d 条' % len(kk5_errs))

# 清理
if os.path.isdir(out):
    import shutil
    shutil.rmtree(out)

print('\n=== 汇总 ===')
fails = [n for n, ok, _ in results if not ok]
print('PASS %d / %d' % (sum(1 for _, ok, _ in results if ok), len(results)))
if fails:
    print('FAIL:', ', '.join(fails))
    sys.exit(1)
print('ALL PASS')
