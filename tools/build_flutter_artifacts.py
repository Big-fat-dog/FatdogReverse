# -*- coding: utf-8 -*-
"""tools/build_flutter_artifacts.py —— 生成并抽取「真实 Flutter 产物」

产出（供碧落天专题 KL36-KL40 作真实逆向对象）：
  lib/arm64-v8a/libapp.so       Dart AOT 快照（业务代码）
  lib/arm64-v8a/libflutter.so   Flutter 引擎（含 Dart VM / BoringSSL / Skia）
  assets/flutter_assets/**      资源
最终复制到主工程：app/libs/arm64-v8a/ 与 app/assets/flutter_assets/

关键工程约束（都踩过）：
  1) **构建必须发生在 ASCII 路径下** —— 本仓库根目录含中文（大胖狗的学习），
     AGP 会直接报 "Your project path contains non-ASCII characters" 并失败。
     故版本库内只保留"源"（tools/flutter_probe/{pubspec.yaml,lib/}），
     实际构建在 ASCII 暂存目录（默认 %LOCALAPPDATA%\\fatdog_flutter_build）进行。
  2) **services.gradle.org 在国内常不可达**（实测 ConnectException/超时），
     构建前把 gradle-wrapper 的 distributionUrl 改写成国内镜像（默认腾讯云）。
  3) 依赖走国内镜像：PUB_HOSTED_URL / FLUTTER_STORAGE_BASE_URL。

用法：
  python tools/build_flutter_artifacts.py              # 明文产物（KL36 / KL39）
  python tools/build_flutter_artifacts.py --obfuscate  # 混淆产物（KL37 / KL40）

可用环境变量覆盖：FLUTTER_SDK / ANDROID_SDK_ROOT / FLUTTER_BUILD_DIR /
                 PUB_HOSTED_URL / FLUTTER_STORAGE_BASE_URL / GRADLE_DIST_MIRROR
"""
import argparse
import io
import os
import re
import shutil
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(HERE, 'flutter_probe')          # 版本库内的源（pubspec + lib/）
APP = os.path.join(ROOT, 'app')

FLUTTER_SDK = os.environ.get('FLUTTER_SDK', r'D:\Andorid\SDK\flutter')
FLUTTER = os.path.join(FLUTTER_SDK, 'bin', 'flutter.bat')
ANDROID_SDK = os.environ.get('ANDROID_SDK_ROOT', r'D:\Andorid\SDK')

PUB_MIRROR = os.environ.get('PUB_HOSTED_URL', 'https://pub.flutter-io.cn')
STORAGE_MIRROR = os.environ.get('FLUTTER_STORAGE_BASE_URL', 'https://storage.flutter-io.cn')
GRADLE_MIRROR = os.environ.get('GRADLE_DIST_MIRROR', 'https://mirrors.cloud.tencent.com/gradle/')

# ASCII 构建暂存目录（绝不能落在含中文的仓库根下）
_default_stage = os.path.join(
    os.environ.get('LOCALAPPDATA') or os.path.expanduser('~'), 'fatdog_flutter_build')
STAGE = os.environ.get('FLUTTER_BUILD_DIR') or _default_stage

ABI = 'arm64-v8a'
APK_REL = os.path.join('build', 'app', 'outputs', 'flutter-apk', 'app-release.apk')
PROJECT_NAME = 'fatdog_probe'


def log(msg):
    print(msg, flush=True)


def run(args, cwd=None):
    """以 shell 方式调用（flutter.bat 必须经 cmd 解析）。"""
    cmd = ' '.join(args)
    log('>>> (cwd=%s) %s' % (cwd or os.getcwd(), cmd))
    env = dict(os.environ, ANDROID_SDK_ROOT=ANDROID_SDK, ANDROID_HOME=ANDROID_SDK)
    if PUB_MIRROR:
        env['PUB_HOSTED_URL'] = PUB_MIRROR
    if STORAGE_MIRROR:
        env['FLUTTER_STORAGE_BASE_URL'] = STORAGE_MIRROR
    r = subprocess.run(cmd, shell=True, cwd=cwd, env=env)
    if r.returncode != 0:
        sys.exit('[!] 命令失败(exit=%d): %s' % (r.returncode, cmd))
    return r.returncode


def sync_sources():
    """把版本库内的源同步进 ASCII 暂存目录（pubspec + lib/）。
    逐文件覆盖 + 只删源里已不存在的文件（不做整目录 rmtree，避免触发批量删除保护）。"""
    os.makedirs(STAGE, exist_ok=True)
    shutil.copy2(os.path.join(SRC, 'pubspec.yaml'), os.path.join(STAGE, 'pubspec.yaml'))

    src_lib = os.path.join(SRC, 'lib')
    dst_lib = os.path.join(STAGE, 'lib')
    os.makedirs(dst_lib, exist_ok=True)
    keep = set()
    for dp, dn, fn in os.walk(src_lib):
        rel = os.path.relpath(dp, src_lib)
        target_dir = dst_lib if rel == '.' else os.path.join(dst_lib, rel)
        os.makedirs(target_dir, exist_ok=True)
        for f in fn:
            dst = os.path.join(target_dir, f)
            shutil.copy2(os.path.join(dp, f), dst)
            keep.add(os.path.normcase(os.path.abspath(dst)))

    dropped = 0
    for dp, dn, fn in os.walk(dst_lib):
        for f in fn:
            p = os.path.normcase(os.path.abspath(os.path.join(dp, f)))
            if p not in keep:
                try:
                    os.remove(os.path.join(dp, f))
                    dropped += 1
                except OSError:
                    pass
    log('[*] 源已同步到构建目录：%s（清理过期源 %d 个）' % (STAGE, dropped))


def patch_gradle_wrapper():
    """gradle-wrapper 的发行版地址改写成国内镜像（services.gradle.org 在国内常不可达）。"""
    p = os.path.join(STAGE, 'android', 'gradle', 'wrapper', 'gradle-wrapper.properties')
    if not os.path.isfile(p) or not GRADLE_MIRROR:
        return
    s = io.open(p, encoding='utf-8').read()
    lines = s.splitlines()
    changed = False
    for i, l in enumerate(lines):
        if not l.startswith('distributionUrl='):
            continue
        m = re.search(r'(gradle-[\d.]+-(?:all|bin)\.zip)', l)
        if not m:
            continue
        new = 'distributionUrl=' + GRADLE_MIRROR + m.group(1)
        if new != l:
            log('[*] Gradle 发行版改写: %s' % m.group(1))
            lines[i] = new
            changed = True
    if changed:
        io.open(p, 'w', encoding='utf-8', newline='').write('\n'.join(lines) + '\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--obfuscate', action='store_true', help='开启 Dart 混淆（KL37 / KL40 用）')
    args = ap.parse_args()

    if not os.path.isfile(FLUTTER):
        sys.exit('[!] 找不到 flutter.bat：%s（可用环境变量 FLUTTER_SDK 覆盖）' % FLUTTER)
    if not os.path.isdir(SRC):
        sys.exit('[!] 找不到探针源目录：%s' % SRC)
    if any(ord(c) > 127 for c in STAGE):
        sys.exit('[!] 构建目录含非 ASCII 字符，AGP 会拒绝构建：%s' % STAGE)

    run([FLUTTER, '--version'], cwd=STAGE if os.path.isdir(STAGE) else HERE)
    sync_sources()

    if not os.path.isdir(os.path.join(STAGE, 'android')):
        log('[*] 生成 Android 工程骨架（flutter create）')
        run([FLUTTER, 'create', '--platforms=android',
             '--project-name', PROJECT_NAME, '--org', 'com.fatdog.probe', '.'], cwd=STAGE)
        sync_sources()          # create 会写默认 main.dart，覆盖回我们的版本

    patch_gradle_wrapper()
    run([FLUTTER, 'pub', 'get'], cwd=STAGE)

    build_cmd = [FLUTTER, 'build', 'apk', '--release',
                 '--target-platform', 'android-arm64']
    if args.obfuscate:
        build_cmd += ['--obfuscate', '--split-debug-info=build/symbols']
    run(build_cmd, cwd=STAGE)

    apk = os.path.join(STAGE, APK_REL)
    if not os.path.isfile(apk):
        sys.exit('[!] 未找到产物 APK：%s' % apk)

    # ---- 抽取到主工程（原地覆盖，只清理真正过期的文件；避免批量删除） ----
    out_libs = os.path.join(APP, 'libs', ABI)
    out_assets = os.path.join(APP, 'assets', 'flutter_assets')
    os.makedirs(out_libs, exist_ok=True)
    os.makedirs(out_assets, exist_ok=True)

    got = []
    written = set()
    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
        for so in ('libapp.so', 'libflutter.so'):
            ent = 'lib/%s/%s' % (ABI, so)
            if ent not in names:
                sys.exit('[!] 产物 APK 缺少 %s' % ent)
            dst = os.path.join(out_libs, so)
            with z.open(ent) as src, open(dst, 'wb') as fp:
                shutil.copyfileobj(src, fp)
            got.append((ent, dst, os.path.getsize(dst)))
        fa = [n for n in names if n.startswith('assets/flutter_assets/')]
        for n in fa:
            rel = n[len('assets/flutter_assets/'):]
            if not rel or n.endswith('/'):
                continue
            dst = os.path.join(out_assets, rel.replace('/', os.sep))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with z.open(n) as src, open(dst, 'wb') as fp:
                shutil.copyfileobj(src, fp)
            written.add(os.path.normcase(os.path.abspath(dst)))
        log('[*] flutter_assets 写入条目：%d' % len(fa))

    # 清理过期文件（新产物里不再存在的；稳态下通常为 0）
    stale = []
    for dp, dn, fn in os.walk(out_assets):
        for f in fn:
            p = os.path.normcase(os.path.abspath(os.path.join(dp, f)))
            if p not in written:
                stale.append(os.path.join(dp, f))
    for p in stale:
        try:
            os.remove(p)
        except OSError:
            pass
    if stale:
        log('[*] 清理过期资源 %d 个' % len(stale))

    log('')
    log('==== 产物落盘 ====')
    for ent, dst, size in got:
        log('  %-28s -> %s  (%.1f MB)' % (ent, os.path.relpath(dst, ROOT), size / 1048576.0))

    # 哨兵校验：对象池里能否看到 FDK 标记（明文/混淆都应可见——Flutter 混淆不加密字符串）
    try:
        blob = open(os.path.join(out_libs, 'libapp.so'), 'rb').read()
        idx = blob.find(b'FDK')
        if idx >= 0:
            seg = blob[idx:idx + 64].split(b'\x00')[0]
            log('[*] 对象池哨兵命中 @0x%x : %r' % (idx, seg))
        else:
            log('[!] 未在 libapp.so 中搜到 FDK 哨兵 —— 伴生 so 将走镜像兜底常量')
    except Exception as e:
        log('[!] 哨兵校验异常：%r' % (e,))

    log('')
    log('[+] 完成。下一步：python build_apk.py（会以 lib/%s/ 与 assets/ 打进 APK）' % ABI)


if __name__ == '__main__':
    main()
