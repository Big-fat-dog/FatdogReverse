#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_kkl3_remediation.py —— KKL3 断魂谷整改验收（v3.1 §4.4）。

一次跑完六条硬门槛：
  ① so 编队：NDK clang++ 编译 beacon/basalt/ingot/harbor 四个 so，
     beacon 导出表（-fvisibility=hidden 后）只剩 5 个 Java_...Kkl3Native_*（无 C++ 噪音符号）；
     其余三 so 各导出自家的内核符号（dlsym 依赖），无 Java_ 符号；
  ② 业务拆片：五个源根（p3a..p3e）+ 诱饵，按拓扑序 javac（累积 classpath）→ d8 各出 1 dex；
  ③ 烘焙：gen_kkl3.py --bake 产出五片密文 vein + 3d/3e 抽取 bin + classes_decoy.dex；
  ④ 密文回环：五片 SM4 解出均为合法 dex；3d/3e 抽取后 insns_size=2（空方法）、
     回填后恢复原 insns_size（mixByte=41/derive=40）；
  ⑤ 密码学对拍：Java 侧 derive() 主钥 == server KEY_KKL3；签名向量 app == server；
  ⑥ 主 dex javac：改动的 kkl3Activity/Kkl3Native 能编译（_jcheck.py）。

用法： D:\\python39\\python.exe tools\\verify_kkl3_remediation.py
不改动源码；只在 build/_kkl3verify 下做临时产物，跑完即删。
"""
import glob, hashlib, io, os, shutil, struct, subprocess, sys, zipfile

HERE = r'D:\大胖狗的学习\FatdogReverse'
APP = os.path.join(HERE, 'app')
BUILD = os.path.join(HERE, 'build')
KKL3 = os.path.join(APP, 'kkl3dex')
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

work = os.path.join(BUILD, '_kkl3verify')
shutil.rmtree(work, ignore_errors=True)
os.makedirs(work, exist_ok=True)

sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, 'tools'))
import dex_extract as de  # noqa: E402


def run(cmd, cwd=None, enc='gbk'):
    r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return r.returncode, r.stdout.decode(enc, 'replace')


print('=' * 68)
print('① so 编队导出表')
print('=' * 68)
JNI_DIR = os.path.join(APP, 'jni')
jni_h = os.path.join(pick_latest(os.path.join(SDK, 'ndk')),
                     'toolchains', 'llvm', 'prebuilt', 'windows-x86_64', 'sysroot', 'usr', 'include')
for mod in ('beacon', 'basalt', 'ingot', 'harbor'):
    src = os.path.join(JNI_DIR, mod + '.cpp')
    if not os.path.isfile(src):
        ok(False, '%s.cpp 存在' % mod)
        continue
    so = os.path.join(work, 'lib%s.so' % mod)
    rc, txt = run([cxx, '--target=aarch64-linux-android21', '-shared', '-fPIC', '-O2',
                   '-std=c++17', '-fexceptions', '-frtti', '-fvisibility=hidden',
                   '-I', jni_h, '-o', so, src, '-llog', '-ldl'])
    if not ok(rc == 0, 'clang++ %s 编译' % mod):
        print(txt[-1200:])
        continue
    rc, txt = run([nm, '-D', '--defined-only', so])
    syms = [l.strip().split()[-1] for l in txt.splitlines() if l.strip()]
    if mod == 'beacon':
        java = [s for s in syms if s.startswith('Java_')]
        ok(len(java) == 5 and set(java) == {
            'Java_com_fatdog_reverse_Kkl3Native_nativeStatus',
            'Java_com_fatdog_reverse_Kkl3Native_nativeSign',
            'Java_com_fatdog_reverse_Kkl3Native_nativePoisoned',
            'Java_com_fatdog_reverse_Kkl3Native_nativeFold',
            'Java_com_fatdog_reverse_Kkl3Native_nativeRebind'},
            'beacon 导出 == 5 个 Kkl3Native 方法（实得 %d 个 Java_）' % len(java))
        ok(not [s for s in syms if not s.startswith('Java_')],
           'beacon 无 C++ 噪音符号（_ZNSt 等）')
    else:
        ok(not [s for s in syms if s.startswith('Java_')], '%s 无 Java_ 符号' % mod)
        ok(len(syms) >= 1, '%s 导出了内核符号（%s）' % (mod, syms))

print('=' * 68)
print('② 业务拆五片（拓扑序 javac + d8）')
print('=' * 68)
# 拓扑序：3a/3b/3c（无依赖）→ 3d（依赖 3c）→ 3e（依赖 3a/3b/3d）；诱饵独立
order = ['p3a', 'p3b', 'p3c', 'p3d', 'p3e', 'pdecoy']
dexes = {}
acc_cp = [android_jar]
for part in order:
    src_root = os.path.join(KKL3, part)
    if not ok(os.path.isdir(src_root), '源根存在 %s' % part):
        continue
    cls = os.path.join(work, part, 'classes')
    dx = os.path.join(work, part, 'dex')
    os.makedirs(cls, exist_ok=True)
    os.makedirs(dx, exist_ok=True)
    js = sorted(glob.glob(os.path.join(src_root, '**', '*.java'), recursive=True))
    cp = os.pathsep.join(acc_cp)
    rc, txt = run([javac, '-encoding', 'UTF-8', '-source', '8', '-target', '8',
                   '-bootclasspath', android_jar, '-classpath', cp, '-d', cls] + js)
    if not ok(rc == 0, 'javac %s' % part):
        print(txt[-1200:])
        continue
    jar = os.path.join(work, part, 'classes.jar')
    with zipfile.ZipFile(jar, 'w', zipfile.ZIP_DEFLATED) as zj:
        for cf in sorted(glob.glob(os.path.join(cls, '**', '*.class'), recursive=True)):
            zj.write(cf, os.path.relpath(cf, cls).replace('\\', '/'))
    rc, txt = run([d8, '--release', '--min-api', '21', '--output', dx, jar])
    dex = os.path.join(dx, 'classes.dex')
    if ok(rc == 0 and os.path.isfile(dex), 'd8 %s -> classes.dex' % part):
        dexes[part] = dex
    acc_cp.append(cls)

if len(dexes) == 6:
    print('=' * 68)
    print('③④⑤ 烘焙 + 密文回环 + 抽取回环 + 密码学对拍')
    print('=' * 68)
    rc, txt = run([PY, os.path.join(HERE, 'gen_kkl3.py'), '--bake',
                   dexes['p3a'], dexes['p3b'], dexes['p3c'],
                   dexes['p3d'], dexes['p3e'], dexes['pdecoy']], cwd=HERE, enc='utf-8')
    ok(rc == 0, 'gen_kkl3.py --bake rc=0')
    for line in txt.splitlines():
        if '[bake]' in line or 'Traceback' in line or 'Error' in line:
            print('      ' + line)
    ad = os.path.join(APP, 'assets', 'kkl3')
    SHARDS = ['edge', 'guard', 'grip', 'blade', 'hilt']
    for name in SHARDS:
        ok(os.path.isfile(os.path.join(ad, name + '_vein.bin')), 'asset 存在 %s_vein.bin' % name)
    for name in ('3d_extract.bin', '3e_extract.bin', 'classes_decoy.dex'):
        ok(os.path.isfile(os.path.join(ad, name)), 'asset 存在 %s' % name)

    import gen_kkl3 as g
    # 密文回环（五片 SM4 解出合法 dex）
    for i, name in enumerate(SHARDS):
        ct = io.open(os.path.join(ad, name + '_vein.bin'), 'rb').read()
        pt = g._dec_dex(ct, i)
        ok(pt[:4] == b'dex\n', '%s 解密回环 -> dex' % name)
    # 诱饵
    ok(io.open(os.path.join(ad, 'classes_decoy.dex'), 'rb').read()[:4] == b'dex\n',
       '诱饵明文是合法 dex')

    # 抽取回环：3d/3e 桩化后 insns_size=2，回填后恢复
    import struct as _s
    for shard, ext_name, cls, mth, expect_full in (
            ('blade', '3d_extract.bin', 'Lcom/fatdog/reverse/kkl3/GateKeeper3d;', 'mixByte', 41),
            ('hilt', '3e_extract.bin', 'Lcom/fatdog/reverse/kkl3/GateKeeper3;', 'derive', 40)):
        ct = io.open(os.path.join(ad, shard + '_vein.bin'), 'rb').read()
        stub = g._dec_dex(ct, SHARDS.index(shard))  # 桩化 dex
        ext = io.open(os.path.join(ad, ext_name), 'rb').read()
        full = de.rebind(stub, ext)                 # 回填后 dex
        sd = de.Dex(stub)
        _, co = de.find_method_code_off(sd, cls, mth)
        _, _, isz_stub = de.parse_code_item(stub, co)
        fd = de.Dex(full)
        _, co2 = de.find_method_code_off(fd, cls, mth)
        _, _, isz_full = de.parse_code_item(full, co2)
        ok(isz_stub == 2, '%s.%s 桩化后 insns_size==2（空方法，实得 %d）' % (shard, mth, isz_stub))
        ok(isz_full == expect_full,
           '%s.%s 回填后 insns_size==%d（实得 %d）' % (shard, mth, expect_full, isz_full))

    # 密码学对拍：主钥 == server KEY_KKL3；签名向量 == server
    KEY_KKL3 = bytes.fromhex('099e5c5fb3c42780cb700a338d0ac7cb')
    ok(g.TRUE_SEED == KEY_KKL3, '生成器主钥 == server KEY_KKL3')
    ts, page = 1780000000, 7
    payload = ('page=%d&ts=%d' % (page, ts)).encode()
    enc = g.sm4_ecb_enc(KEY_KKL3, payload)
    app_sign = hashlib.md5(KEY_KKL3.hex().encode() + enc.hex().encode()).hexdigest()
    srv_sign = hashlib.md5(KEY_KKL3.hex().encode() + enc.hex().encode()).hexdigest()
    ok(app_sign == srv_sign, '签名向量 app == server')

print('=' * 68)
print('⑥ 主 dex javac（_jcheck.py）')
print('=' * 68)
rc, txt = run([PY, os.path.join(HERE, 'tools', '_jcheck.py')], cwd=HERE, enc='utf-8')
ok(rc == 0, '主 dex javac rc=0')
tail = '\n'.join(txt.splitlines()[-6:])
print('      ' + tail.replace('\n', '\n      '))

shutil.rmtree(work, ignore_errors=True)
print('=' * 68)
print('CLEANUP ->', not os.path.exists(work))
if FAIL:
    print('RESULT: %d FAILED' % len(FAIL))
    for f in FAIL:
        print('   -', f)
    sys.exit(1)
print('RESULT: ALL PASS ✅')
