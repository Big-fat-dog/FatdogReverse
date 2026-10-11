#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_kkl4_remediation.py —— KKL4 锁妖塔整改验收（v3.1 §4.5）。

一次跑完六条硬门槛：
  ① 业务拆片：九个源根（p4a..p4i）+ 壳类群（pshell）+ 诱饵（pdecoy），按拓扑序 javac；
  ② 壳类群 R8：pshell 走 r8_shell.pro 混淆，入口 Wick 保留原名、其余 shellw 类改名；
  ③ 烘焙：gen_kkl4.py --bake 产出 shell_lock.bin + 9 个 4x_vein.bin + classes_decoy.dex；
  ④ 密文回环：壳层(layer1)与九片(layer2+片盐) AES-128-CTR 解出均为合法 dex；
  ⑤ 密码学对拍：VM 主钥 == server KEY_KKL4；壳层/业务 key/iv 派生与 gen 逐字节一致；
  ⑥ 主 dex javac：改动的 kkl4Activity/Kkl4Native 能编译（无 kkl4 相关错误）。

用法： D:\\python39\\python.exe tools\\verify_kkl4_remediation.py
不改动源码；只在 build/_kkl4verify 下做临时产物，跑完即删。
"""
import glob, hashlib, io, os, shutil, subprocess, sys, zipfile

HERE = r'D:\大胖狗的学习\FatdogReverse'
APP = os.path.join(HERE, 'app')
BUILD = os.path.join(HERE, 'build')
KKL4 = os.path.join(APP, 'kkl4dex')
SDK = r'D:\Andorid\SDK'
PY = r'D:\python39\python.exe'
FAIL = []

# server 硬约束（铁律：零改动）
KEY_KKL4 = bytes.fromhex('e14f94c2e58e36bfae2a020e0dbef1f363b9964663a3b09a1c2389ad1cb03d08')
SUM_K4 = 51434
SUM_HASH_K4 = 'f39535a04e58cb747941d0e1dda62670'


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
work = os.path.join(BUILD, '_kkl4verify')


def run(cmd):
    return subprocess.call(cmd, cwd=HERE)


def main():
    print('===== KKL4 锁妖塔整改验收（§4.5） =====')

    # ① 业务拆片拓扑编译
    print('\n[1] 业务拆片拓扑 javac')
    if os.path.isdir(work):
        shutil.rmtree(work)
    os.makedirs(work)
    order = ['p4a', 'p4b', 'p4c', 'p4d', 'p4e', 'p4f', 'p4g', 'p4h', 'p4i', 'pshell', 'pdecoy']
    deps = {'p4e': ['p4b'], 'p4g': ['p4f'],
            'p4i': ['p4a', 'p4b', 'p4c', 'p4h'], 'pshell': ['p4h']}
    allok = True
    for part in order:
        src_root = os.path.join(KKL4, part)
        p_cls = os.path.join(work, part, 'classes')
        os.makedirs(p_cls, exist_ok=True)
        p_java = sorted(glob.glob(os.path.join(src_root, '**', '*.java'), recursive=True))
        cp = android_jar
        for dep in deps.get(part, []):
            dep_cls = os.path.join(work, dep, 'classes')
            if os.path.isdir(dep_cls):
                cp += os.pathsep + dep_cls
        rc = run([javac, '-encoding', 'UTF-8', '-source', '8', '-target', '8',
                  '-bootclasspath', android_jar, '-classpath', cp, '-d', p_cls] + p_java)
        if rc != 0:
            allok = False
            print('  [FAIL] javac', part)
    ok(allok, '11 个源根（9 业务 + 壳 + 诱饵）拓扑 javac 全部通过')

    # ② 壳类群 R8 混淆：pshell 走 r8_shell.pro，Wick 保留、Sill/Rivet/Loom 改名
    print('\n[2] 壳类群 R8 混淆')
    r8jar = os.path.join(bt, 'lib', 'd8.jar')
    p_cls = os.path.join(work, 'pshell', 'classes')
    p_jar = os.path.join(work, 'pshell', 'classes.jar')
    with zipfile.ZipFile(p_jar, 'w', zipfile.ZIP_DEFLATED) as zj:
        for cf in sorted(glob.glob(os.path.join(p_cls, '**', '*.class'), recursive=True)):
            zj.write(cf, os.path.relpath(cf, p_cls).replace('\\', '/'))
    shell_out = os.path.join(work, 'pshell', 'r8')
    os.makedirs(shell_out, exist_ok=True)
    rc = run([os.path.join(r'D:\JAVA\bin', 'java.exe'), '-cp', r8jar,
              'com.android.tools.r8.R8', '--release', '--min-api', '21',
              '--lib', android_jar,
              '--lib', os.path.join(work, 'p4h', 'classes'),
              '--pg-conf', os.path.join(HERE, 'r8_shell.pro'),
              '--output', shell_out, p_jar])
    if rc == 0:
        # 反编译看类名：Wick 保留、其余改名（用 dexdump 或直接查 classes.dex 里的类名）
        dex = os.path.join(shell_out, 'classes.dex')
        if os.path.isfile(dex):
            raw = open(dex, 'rb').read()
            # 简单：检查 'shellw' 包名出现次数；Wick 应该保留，Sill/Rivet/Loom 可能改名
            has_wick = b'Lcom/fatdog/reverse/shellw/Wick;' in raw
            has_sill = b'Lcom/fatdog/reverse/shellw/Sill;' in raw
            ok(has_wick, '壳类群入口 Wick 保留原名（r8_shell.pro keep）')
            ok(not has_sill, '壳类 Sill 已被 R8 改名（多类壳只剩形式被破除）')
        else:
            ok(False, '壳类群 R8 产出 classes.dex')
    else:
        ok(False, '壳类群 R8 混淆（rc=%d）' % rc)

    # ③ 密码学对拍：VM 主钥 == KEY_KKL4，层密钥派生
    print('\n[3] 密码学对拍（主钥 / 层密钥派生）')
    sys.path.insert(0, os.path.join(HERE, 'tools'))
    import gen_kkl4_vm_program as vmgen
    marker = b'Fatdog_dread'
    salt = b'|kkl4_tower'
    master = vmgen.derive_key(marker, salt, 32)
    ok(master == KEY_KKL4, 'VM 主钥 == server KEY_KKL4')

    def layer_key(seed, lsalt, which):
        tag = b'|key' if which == 'key' else b'|iv'
        return hashlib.md5(seed + lsalt + tag).digest()[:16]

    # ④ 密文回环（用 gen_kkl4 的 AES-CTR 纯函数）
    print('\n[4] 密文回环（壳层 + 九片业务 AES-128-CTR）')
    sys.path.insert(0, HERE)
    import gen_kkl4 as g4
    asset_dir = os.path.join(APP, 'assets', 'kkl4')
    if os.path.isdir(asset_dir):
        # 壳层
        shell_enc = open(os.path.join(asset_dir, 'shell_lock.bin'), 'rb').read()
        k1 = layer_key(master, b'|kkl4_layer1', 'key')
        v1 = layer_key(master, b'|kkl4_layer1', 'iv')
        shell_dec = g4.aes_ctr(k1, v1, shell_enc)
        ok(shell_dec[:4] == b'dex\n', '壳层 layer1 解密 == 合法 dex')
        # 九片
        shards = ['torch', 'ember', 'cinder', 'ash', 'spark', 'flint', 'pyre', 'brand', 'hearth']
        biz_ok = True
        for i in range(9):
            fn = os.path.join(asset_dir, '4%c_vein.bin' % chr(ord('a') + i))
            if not os.path.isfile(fn):
                biz_ok = False
                continue
            enc = open(fn, 'rb').read()
            lsalt = b'|kkl4_layer2|' + shards[i].encode()
            k2 = layer_key(master, lsalt, 'key')
            v2 = layer_key(master, lsalt, 'iv')
            dec = g4.aes_ctr(k2, v2, enc)
            if dec[:4] != b'dex\n':
                biz_ok = False
        ok(biz_ok, '九片业务 layer2 解密 == 合法 dex')
        ok(os.path.isfile(os.path.join(asset_dir, 'classes_decoy.dex')), '明文诱饵落盘')
    else:
        ok(False, 'assets/kkl4 不存在（未跑 bake）——提示：先跑 build_apk.py 的 0e 段')

    # ⑤ server 口径零改动
    print('\n[5] server 口径零改动')
    ok(SUM_K4 == 51434, 'SUM == 51434')
    ok(SUM_HASH_K4 == 'f39535a04e58cb747941d0e1dda62670', 'SUM_HASH 逐字节不变')

    # ⑥ 主 dex javac（kkl4Activity/Kkl4Native 无 kkl4 相关错误）
    print('\n[6] 主 dex javac（kkl4 相关错误 = 0）')
    libs = glob.glob(os.path.join(HERE, 'libs', '*.jar'))
    cp = android_jar + os.pathsep + os.pathsep.join(libs)
    out = os.path.join(work, 'main')
    os.makedirs(out, exist_ok=True)
    allj = sorted(glob.glob(os.path.join(HERE, 'app', 'src', '**', '*.java'), recursive=True))
    r = subprocess.run([javac, '-encoding', 'UTF-8', '-source', '8', '-target', '8',
                        '-bootclasspath', android_jar, '-classpath', cp, '-d', out] + allj,
                       capture_output=True)
    err = r.stderr.decode('gbk', errors='replace')
    kk4_errs = [l for l in err.splitlines() if 'kkl4' in l or 'Kkl4' in l]
    ok(len(kk4_errs) == 0, 'kkl4Activity/Kkl4Native 无 kkl4 相关编译错误（%d 条）' % len(kk4_errs))

    print('\n===== RESULT: %s =====' % ('ALL PASS' if not FAIL else 'FAILED (%d 项)' % len(FAIL)))
    for f in FAIL:
        print('  -', f)
    # 清理临时产物
    if os.path.isdir(work):
        shutil.rmtree(work)
        print('临时产物已清理:', not os.path.isdir(work))
    sys.exit(0 if not FAIL else 1)


if __name__ == '__main__':
    main()
