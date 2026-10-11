#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_kkl1_remediation.py —— KKL1 玄冥渊整改验收（v3.1 §4.2）。

一次跑完五条硬门槛：
  ① so 导出表：NDK clang++ 编译 kkl1.cpp（arm64-v8a + armeabi-v7a），
     llvm-nm -D --defined-only 必须只剩 JNI_OnLoad（无 Java_ / 无类名泄漏）；
  ② 业务拆片：三个源根（p1a/p1b/pdecoy）各 javac → jar → d8 出 1 个 dex；
  ③ 烘焙：gen_kkl1.py --bake 产出 assets/kkl1/{abyss_vein.bin, abyss_marrow.bin, classes_decoy.dex}；
  ④ 密文回环：解出的 1a/1b 都是合法 dex（magic 'dex\\n'）；
  ⑤ 密码学对拍：生成器 seal == server 口径 KEY_KKL1；app 签名向量 == server；诱饵钥必不同。

用法： D:\\python39\\python.exe tools\\verify_kkl1_remediation.py
不改动源码；只在 build/_kkl1verify 下做临时产物，跑完即删。
"""
import glob, hashlib, io, os, shutil, subprocess, sys, zipfile

HERE = r'D:\大胖狗的学习\FatdogReverse'
APP = os.path.join(HERE, 'app')
BUILD = os.path.join(HERE, 'build')
KKL1 = os.path.join(APP, 'kkl1dex')
SDK = r'D:\Andorid\SDK'
PY = r'D:\python39\python.exe'
FAIL = []


def ok(cond, msg):
    print('  [%s] %s' % ('PASS' if cond else 'FAIL', msg))
    if not cond:
        FAIL.append(msg)
    return cond


def pick_latest(d):
    items = []
    for x in os.listdir(d):
        ver = x.split('-')[-1]
        if not ver or not ver[0].isdigit():
            continue
        try:
            items.append((x, [int(p) for p in ver.split('.')]))
        except ValueError:
            continue
    return os.path.join(d, sorted(items, key=lambda t: t[1])[-1][0]) if items else None


bt = pick_latest(os.path.join(SDK, 'build-tools'))
android_jar = os.path.join(pick_latest(os.path.join(SDK, 'platforms')), 'android.jar')
javac = r'D:\JAVA\bin\javac.exe'
d8 = os.path.join(bt, 'd8.bat')
ndk_bin = os.path.join(pick_latest(os.path.join(SDK, 'ndk')),
                       'toolchains', 'llvm', 'prebuilt', 'windows-x86_64', 'bin')
cxx = os.path.join(ndk_bin, 'clang++.exe')
nm = os.path.join(ndk_bin, 'llvm-nm.exe')

work = os.path.join(BUILD, '_kkl1verify')
shutil.rmtree(work, ignore_errors=True)
os.makedirs(work, exist_ok=True)


def run(cmd, cwd=None, enc='gbk'):
    """javac/d8 输出 GBK；gen_kkl1.py 输出 UTF-8。"""
    r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return r.returncode, r.stdout.decode(enc, 'replace')


print('=' * 68)
print('① so 导出表（llvm-nm -D）')
print('=' * 68)
src_cpp = os.path.join(APP, 'jni', 'kkl1.cpp')
for abi, tgt in (('arm64-v8a', 'aarch64-linux-android21'),
                 ('armeabi-v7a', 'armv7a-linux-androideabi21')):
    so = os.path.join(work, 'libkkl1-%s.so' % abi)
    rc, txt = run([cxx, '--target=' + tgt, '-shared', '-fPIC', '-O2', '-std=c++17',
                   '-fexceptions', '-frtti', '-fvisibility=hidden',
                   '-Wl,--exclude-libs,ALL', '-o', so, src_cpp, '-llog'])
    if not ok(rc == 0, 'clang++ %s 编译' % abi):
        print(txt[-1500:])
        continue
    rc, txt = run([nm, '-D', '--defined-only', so])
    syms = [l.strip().split()[-1] for l in txt.splitlines() if l.strip()]
    ok(syms == ['JNI_OnLoad'], '%s 导出 == [JNI_OnLoad]（实得 %s）' % (abi, syms))
    leaked = [x for x in syms if x != 'JNI_OnLoad']
    ok(not leaked, '%s 无泄漏符号' % abi)

print('=' * 68)
print('②③ 业务拆片 javac+d8 → bake')
print('=' * 68)
dexes = {}
for part in ('p1a', 'p1b', 'pdecoy'):
    src_root = os.path.join(KKL1, part)
    if not ok(os.path.isdir(src_root), '源根存在 %s' % part):
        continue
    cls = os.path.join(work, part, 'classes')
    dx = os.path.join(work, part, 'dex')
    os.makedirs(cls, exist_ok=True)
    os.makedirs(dx, exist_ok=True)
    js = sorted(glob.glob(os.path.join(src_root, '**', '*.java'), recursive=True))
    rc, txt = run([javac, '-encoding', 'UTF-8', '-source', '8', '-target', '8',
                   '-bootclasspath', android_jar, '-d', cls] + js)
    if not ok(rc == 0, 'javac %s' % part):
        print(txt[-1500:])
        continue
    jar = os.path.join(work, part, 'classes.jar')
    with zipfile.ZipFile(jar, 'w', zipfile.ZIP_DEFLATED) as zj:
        for cf in sorted(glob.glob(os.path.join(cls, '**', '*.class'), recursive=True)):
            zj.write(cf, os.path.relpath(cf, cls).replace('\\', '/'))
    rc, txt = run([d8, '--release', '--min-api', '21', '--output', dx, jar])
    dex = os.path.join(dx, 'classes.dex')
    if ok(rc == 0 and os.path.isfile(dex), 'd8 %s -> classes.dex' % part):
        dexes[part] = dex

if len(dexes) == 3:
    rc, txt = run([PY, os.path.join(HERE, 'gen_kkl1.py'), '--bake',
                   dexes['p1a'], dexes['p1b'], dexes['pdecoy']], cwd=HERE, enc='utf-8')
    ok(rc == 0, 'gen_kkl1.py --bake rc=0')
    for line in txt.splitlines():
        if '[bake]' in line or 'Traceback' in line or 'Error' in line:
            print('      ' + line)
    ad = os.path.join(APP, 'assets', 'kkl1')
    for name in ('abyss_vein.bin', 'abyss_marrow.bin', 'classes_decoy.dex'):
        ok(os.path.isfile(os.path.join(ad, name)), 'asset 存在 %s' % name)

    print('=' * 68)
    print('④⑤ 密文回环 + 密码学对拍')
    print('=' * 68)
    sys.path.insert(0, HERE)
    import gen_kkl1 as g
    va = io.open(os.path.join(ad, 'abyss_vein.bin'), 'rb').read()
    vb = io.open(os.path.join(ad, 'abyss_marrow.bin'), 'rb').read()
    ok(g.dec_dex(va)[:4] == b'dex\n', '1a 解密回环 -> dex')
    ok(g.dec_dex(vb)[:4] == b'dex\n', '1b 解密回环 -> dex')
    ok(io.open(os.path.join(ad, 'classes_decoy.dex'), 'rb').read()[:4] == b'dex\n',
       '诱饵明文是合法 dex')
    KEY_KKL1 = hashlib.md5(b'Fatdog_hallow|kkl1_abyss').digest()
    ok(KEY_KKL1 == g.derive_seal(), '生成器 seal == server KEY_KKL1')
    ts, page = 1780000000, 7
    app_sign = hashlib.md5((KEY_KKL1.hex() + 'page=%d&ts=%d' % (page, ts)).encode()).hexdigest()
    srv_sign = hashlib.md5((KEY_KKL1.hex() + 'page=%d&ts=%d' % (page, ts)).encode()).hexdigest()
    ok(app_sign == srv_sign, '签名向量 app == server')
    bait = hashlib.md5(b'Fatdog_hollow|kkl1_abyss').digest()
    ok(bait != KEY_KKL1, '诱饵钥 != 真钥（诱饵必 403）')

shutil.rmtree(work, ignore_errors=True)
print('=' * 68)
print('CLEANUP ->', not os.path.exists(work))
if FAIL:
    print('RESULT: %d FAILED' % len(FAIL))
    for f in FAIL:
        print('   -', f)
    sys.exit(1)
print('RESULT: ALL PASS ✅')
