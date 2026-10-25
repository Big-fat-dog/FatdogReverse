# -*- coding: utf-8 -*-
"""FatdogReverse APK 构建脚本（无需 Android Studio / Gradle）。

依赖：
  1) JDK 17+（本机 PyCharm 自带 JBR 即可，脚本会自动探测）
  2) Android SDK：build-tools（aapt2/d8/apksigner/zipalign）+ platforms/android-XX/android.jar
3) NDK（**必需**，不是可选）：启动期 FatdogApp/AppInit、MainActivity、WarmUp 会静态
       System.loadLibrary 装载 60 个 so（jni/ 下 160 个 LOCAL_MODULE 全量编译）。
       缺 NDK 时构建会直接报错退出——因为打不出 lib/ 的 APK 装上必闪退
       （Application.onCreate 抛 UnsatisfiedLinkError，点图标瞬间退出、连第一帧都没有）。

设置 ANDROID_SDK_ROOT（或 ANDROID_HOME）指向 SDK 根目录后运行：
    python build_apk.py
产物：FatdogReverse.apk（含图标、资源、单 classes.dex（R8 打包全部关卡，含关卡 20 的 AdBox/a20Activity）、assets/config.json、lib/*.so、META-INF 签名）
"""
import glob
import os
import re
import shutil
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, 'app')
BUILD = os.path.join(HERE, 'build')
# 签名 keystore 固定放项目根 keystore/（build/ 每次会被清空，绝不能放进去）。
KEYSTORE = os.path.join(HERE, 'keystore', 'debug.keystore')

# 关卡 15+ 的 OkHttp 依赖：只打这份白名单，避免把大 jar 全塞进 dex。
# 这些 jar 会被 R8 编进 classes.dex；classes2 里的类引用它们时用 --lib 解析即可。
LIB_JAR_NAMES = ('okhttp-4.12.0.jar', 'okio-jvm-3.6.0.jar', 'kotlin-stdlib-1.8.22.jar', 'annotations.jar')


# 碧落天真实 Flutter 产物回填 ----------------------------------------------------
# tools/build_flutter_artifacts.py 会把 libapp.so / libflutter.so 抽进 app/libs/，
# 但 ndk-build 的 clean-installed-binaries 目标会 `rm libs/<abi>/*` 清空整个目录
# （防打包陈旧模块），会连带把它们冲掉。故必须在 ndk-build **之后**从 Flutter
# 构建暂存 APK 重新抽取，否则最终 APK 里没有真实产物、碧落天只能走镜像兜底。
def _flutter_stage_apk():
    la = os.environ.get('LOCALAPPDATA') or os.path.expanduser('~')
    stage = os.environ.get('FLUTTER_BUILD_DIR') or os.path.join(la, 'fatdog_flutter_build')
    return os.path.join(stage, 'build', 'app', 'outputs', 'flutter-apk', 'app-release.apk')


def inject_flutter_libs(app_dir):
    apk = _flutter_stage_apk()
    abi = 'arm64-v8a'
    if not os.path.isfile(apk):
        print('提示: 未找到 Flutter 产物 APK（%s）' % apk)
        print('      碧落天 KL36-40/KL40b 将走镜像兜底常量；如需真实产物先跑:')
        print('      python tools/build_flutter_artifacts.py')
        return
    out = os.path.join(app_dir, 'libs', abi)
    os.makedirs(out, exist_ok=True)
    got = []
    try:
        with zipfile.ZipFile(apk) as z:
            names = set(z.namelist())
            for so in ('libapp.so', 'libflutter.so'):
                ent = 'lib/%s/%s' % (abi, so)
                if ent not in names:
                    print('警告: Flutter 产物 APK 缺少 %s，跳过' % ent)
                    continue
                dst = os.path.join(out, so)
                with z.open(ent) as src, open(dst, 'wb') as fp:
                    shutil.copyfileobj(src, fp)
                got.append((so, os.path.getsize(dst)))
    except Exception as e:
        print('警告: 回填 Flutter 产物失败：%r' % (e,))
        return
    for so, size in got:
        print('Flutter 产物回填: libs/%s/%s (%.1f MB)' % (abi, so, size / 1048576.0))
    if not got:
        print('提示: 未回填任何 Flutter 产物 so。')


def find_sdk():
    for k in ('ANDROID_SDK_ROOT', 'ANDROID_HOME'):
        v = os.environ.get(k)
        if v and os.path.isdir(v):
            return v
    guesses = [
        os.path.expandvars(r'%LOCALAPPDATA%\Android\Sdk'),
        r'D:\Andorid\SDK',
        r'C:\Android\Sdk', r'C:\Android', r'E:\Android\Sdk', r'D:\Android\Sdk',
        os.path.expanduser('~/Android/Sdk'),
    ]
    for g in guesses:
        if os.path.isdir(g):
            return g
    sys.exit('找不到 Android SDK。请安装 SDK 并设置 ANDROID_SDK_ROOT，详见 README.md。')


def pick_latest(d):
    """Pick newest version dir; supports 36.0.0 / android-37.0 / 26.1.10909125."""
    if not os.path.isdir(d):
        return None
    items = []
    for x in os.listdir(d):
        ver = x.split('-')[-1]
        if not ver or not ver[0].isdigit():
            continue
        try:
            items.append((x, [int(p) for p in ver.split('.')]))
        except ValueError:
            continue
    if not items:
        return None
    return os.path.join(d, sorted(items, key=lambda t: t[1])[-1][0])


def find_java():
    java_home = os.environ.get('JAVA_HOME')
    if java_home:
        return os.path.join(java_home, 'bin')
    for c in (r'D:\JAVA\bin', r'E:\PyCharm 2025.3.3\jbr\bin', r'C:\Program Files\Java\latest\bin', r'C:\Program Files\Java'):
        if os.path.isdir(c) and os.path.isfile(os.path.join(c, 'javac.exe')):
            return c
    found = shutil.which('javac')
    if found:
        return os.path.dirname(found)
    sys.exit('找不到 JDK（javac）。')


def find_ndk(sdk):
    for k in ('ANDROID_NDK_ROOT', 'ANDROID_NDK_HOME'):
        v = os.environ.get(k)
        if v and os.path.isdir(v):
            return v
    d = os.path.join(sdk, 'ndk')
    if os.path.isdir(d):
        latest = pick_latest(d)
        if latest:
            return latest
    return None


def required_native_libs():
    """抓出所有 System.loadLibrary("x") 的库名（全工程，不只是启动期）。

    启动期真正致命的是 Application.onCreate / Activity 类初始化里那几个静态块：
    少一个 so 就抛 UnsatisfiedLinkError，进程在 Application 阶段直接死掉，
    用户看到的就是"点开就闪退"。所以这些库必须逐个在 lib/<abi>/ 里存在。
    """
    names = set()
    src = os.path.join(APP, 'src')
    for root, _dirs, files in os.walk(src):
        for fn in files:
            if not fn.endswith('.java'):
                continue
            with open(os.path.join(root, fn), encoding='utf-8', errors='replace') as f:
                text = f.read()
            for m in re.finditer(r'System\.loadLibrary\(\s*"([^"]+)"\s*\)', text):
                names.add(m.group(1))
    return names


def run(cmd, **kw):
    # 新版构建工具对含中文的绝对路径支持不佳：统一以项目根为工作目录，
    # 项目内路径改写为相对路径（SDK/JDK 等外部路径保持不变）。
    if 'cwd' not in kw:
        kw['cwd'] = HERE
        fixed = []
        for c in cmd:
            if isinstance(c, str) and os.path.isabs(c):
                try:
                    if os.path.commonpath([c, HERE]) == HERE:
                        c = os.path.relpath(c, HERE)
                except ValueError:
                    pass
            fixed.append(c)
        cmd = fixed
    print('>>', ' '.join(cmd))
    subprocess.check_call(cmd, **kw)


def main():
    sdk = find_sdk()
    bt = pick_latest(os.path.join(sdk, 'build-tools'))
    platform = pick_latest(os.path.join(sdk, 'platforms'))
    if not bt:
        sys.exit('缺少 build-tools：sdkmanager "build-tools;34.0.0"')
    if not platform:
        sys.exit('缺少 platforms：sdkmanager "platforms;android-34"')
    android_jar = os.path.join(platform, 'android.jar')
    if not os.path.isfile(android_jar):
        sys.exit('缺少 android.jar: ' + android_jar)

    java_bin = find_java()
    os.environ['JAVA_HOME'] = os.path.dirname(java_bin)
    javac = os.path.join(java_bin, 'javac.exe')
    keytool = os.path.join(java_bin, 'keytool.exe')
    aapt2 = os.path.join(bt, 'aapt2.exe')
    d8 = os.path.join(bt, 'd8.bat')
    zipalign = os.path.join(bt, 'zipalign.exe')
    apksigner = os.path.join(bt, 'apksigner.bat')

    lib_jars = [os.path.join(HERE, 'libs', n) for n in LIB_JAR_NAMES]
    for j in lib_jars:
        if not os.path.isfile(j):
            sys.exit('缺少依赖 jar（libs/ 下应有一份）: ' + j)
    lib_cp = os.pathsep.join(lib_jars)

    # 0) 兼容历史布局：旧 key 曾在 build/ 下且会被下面的 rmtree 删除，先迁到 keystore/。
    legacy_ks = os.path.join(BUILD, 'debug.keystore')
    if not os.path.isfile(KEYSTORE) and os.path.isfile(legacy_ks):
        os.makedirs(os.path.dirname(KEYSTORE), exist_ok=True)
        shutil.copy2(legacy_ks, KEYSTORE)
        print('签名 keystore 迁移到:', KEYSTORE)

    shutil.rmtree(BUILD, ignore_errors=True)
    os.makedirs(os.path.join(BUILD, 'classes'))

    # 0a) KKL1 玄冥渊：业务拆两片（p1a/p1b）+ 明文诱饵（pdecoy），三个源根
    #     各自独立编译成一个 dex（源码在 app/kkl1dex 下，不进主 dex）；
    #     再 gen_kkl1.py 烘焙 assets（p1a/p1b 加密、pdecoy 明文；必须在
    #     aapt2 link -A assets 之前完成）。
    kkl1_src = os.path.join(APP, 'kkl1dex')
    if os.path.isdir(kkl1_src):
        k1_dexes = {}
        for part in ('p1a', 'p1b', 'pdecoy'):
            src_root = os.path.join(kkl1_src, part)
            if not os.path.isdir(src_root):
                print('警告: 缺少 kkl1 源根: ' + src_root)
                continue
            p_cls = os.path.join(BUILD, 'kkl1dex', part, 'classes')
            p_dex_dir = os.path.join(BUILD, 'kkl1dex', part, 'dex')
            os.makedirs(p_cls, exist_ok=True)
            os.makedirs(p_dex_dir, exist_ok=True)
            p_java = sorted(glob.glob(os.path.join(src_root, '**', '*.java'), recursive=True))
            run([javac, '-encoding', 'UTF-8', '-source', '8', '-target', '8',
                 '-bootclasspath', android_jar, '-d', p_cls] + p_java)
            p_jar = os.path.join(BUILD, 'kkl1dex', part, 'classes.jar')
            with zipfile.ZipFile(p_jar, 'w', zipfile.ZIP_DEFLATED) as zj:
                for cf in sorted(glob.glob(os.path.join(p_cls, '**', '*.class'), recursive=True)):
                    zj.write(cf, os.path.relpath(cf, p_cls).replace('\\', '/'))
            run([d8, '--release', '--min-api', '21', '--output', p_dex_dir, p_jar])
            p_dex = os.path.join(p_dex_dir, 'classes.dex')
            if os.path.isfile(p_dex):
                k1_dexes[part] = p_dex
            else:
                print('警告: 未找到 kkl1(%s) dex 输出: %s' % (part, p_dex))
        if all(k in k1_dexes for k in ('p1a', 'p1b', 'pdecoy')):
            run([sys.executable, os.path.join(HERE, 'gen_kkl1.py'), '--bake',
                 k1_dexes['p1a'], k1_dexes['p1b'], k1_dexes['pdecoy']])
        else:
            print('警告: kkl1 三个业务 dex 不齐，跳过烘焙')

    # 0b) KKL2 万剑冢：业务拆三片（p2a/p2b/p2c），三个源根各自独立编译成一个 dex
    #     （源码在 app/kkl2dex 下，不进主 dex）；再 gen_kkl2.py 烘焙 assets（三片各自
    #     AES-128-CBC 加密；必须在 aapt2 link -A assets 之前完成）。
    kkl2_src = os.path.join(APP, 'kkl2dex')
    if os.path.isdir(kkl2_src):
        k2_dexes = {}
        for part in ('p2a', 'p2b', 'p2c'):
            src_root = os.path.join(kkl2_src, part)
            if not os.path.isdir(src_root):
                print('警告: 缺少 kkl2 源根: ' + src_root)
                continue
            p_cls = os.path.join(BUILD, 'kkl2dex', part, 'classes')
            p_dex_dir = os.path.join(BUILD, 'kkl2dex', part, 'dex')
            os.makedirs(p_cls, exist_ok=True)
            os.makedirs(p_dex_dir, exist_ok=True)
            p_java = sorted(glob.glob(os.path.join(src_root, '**', '*.java'), recursive=True))
            run([javac, '-encoding', 'UTF-8', '-source', '8', '-target', '8',
                 '-bootclasspath', android_jar, '-d', p_cls] + p_java)
            p_jar = os.path.join(BUILD, 'kkl2dex', part, 'classes.jar')
            with zipfile.ZipFile(p_jar, 'w', zipfile.ZIP_DEFLATED) as zj:
                for cf in sorted(glob.glob(os.path.join(p_cls, '**', '*.class'), recursive=True)):
                    zj.write(cf, os.path.relpath(cf, p_cls).replace('\\', '/'))
            run([d8, '--release', '--min-api', '21', '--output', p_dex_dir, p_jar])
            p_dex = os.path.join(p_dex_dir, 'classes.dex')
            if os.path.isfile(p_dex):
                k2_dexes[part] = p_dex
            else:
                print('警告: 未找到 kkl2(%s) dex 输出: %s' % (part, p_dex))
        if all(k in k2_dexes for k in ('p2a', 'p2b', 'p2c')):
            run([sys.executable, os.path.join(HERE, 'gen_kkl2.py'), '--bake',
                 k2_dexes['p2a'], k2_dexes['p2b'], k2_dexes['p2c']])
        else:
            print('警告: kkl2 三个业务 dex 不齐，跳过烘焙')

    # 0c) KKL5 诛仙台：三级壳中壳（外层 y.* + 壳 A + 壳 B）+ 13 业务 DEX（5a..5m）+ 明文诱饵
    #     （源码在 app/kkl5dex 与 app/kkl5shell，不进主 dex）；壳类群走 r8_shell.pro（R8 混淆）；
    #     片间按拓扑序编译；再 gen_kkl5.py --bake 做壳层/业务分片复合加密埋 assets/kkl5/。
    kkl5_src = os.path.join(APP, 'kkl5dex')
    kkl5_shell_src = os.path.join(APP, 'kkl5shell')
    if os.path.isdir(kkl5_src):
        # 外层 y.*（app/kkl5dex/p_outer）+ 壳 A（app/kkl5shell/a）+ 壳 B（app/kkl5shell/b）
        # + 13 业务（app/kkl5dex/p5a..p5m）+ 诱饵（app/kkl5dex/pdecoy）
        # 编译顺序按拓扑序（依赖在前）；bake 顺序单独指定（outer/shell_a/shell_b 在前）。
        k5_compile_order = (['p5a', 'p5b', 'p5c', 'p5d', 'p5f', 'p5h', 'p5i', 'p5j', 'p5l',
                             'p5e', 'p5g', 'p5k', 'p5m', 'shell_b', 'shell_a', 'p_outer', 'pdecoy'])
        k5_bake_order = (['p_outer', 'shell_a', 'shell_b'] +
                         ['p5%s' % c for c in 'abcdefghijklm'] + ['pdecoy'])
        k5_root = {}   # part -> 源根目录
        k5_root['p_outer'] = os.path.join(kkl5_src, 'p_outer')
        k5_root['shell_a'] = os.path.join(kkl5_shell_src, 'a')
        k5_root['shell_b'] = os.path.join(kkl5_shell_src, 'b')
        for c in 'abcdefghijklm':
            k5_root['p5%s' % c] = os.path.join(kkl5_src, 'p5%s' % c)
        k5_root['pdecoy'] = os.path.join(kkl5_src, 'pdecoy')
        # 片间依赖：5e 依赖 5b、5k 依赖 5d、5g 依赖 5f、5m 依赖 5a/5b/5c/5h/5l、
        #           壳 B 依赖业务片 5l（bindingClass 返回 GateKeeper5l.class）、
        #           壳 A 依赖壳 B（nextClass 返回 shellz.Wick.class）、
        #           外层依赖壳 A（nextClass 返回 shellx.Wick.class）。
        k5_deps = {
            'p5e': ['p5b'], 'p5k': ['p5d'], 'p5g': ['p5f'],
            'p5m': ['p5a', 'p5b', 'p5c', 'p5h', 'p5l'],
            'shell_b': ['p5l'],
            'shell_a': ['shell_b'],
            'p_outer': ['shell_a'],
        }
        k5_dexes = {}
        for part in k5_compile_order:
            src_root = k5_root[part]
            if not os.path.isdir(src_root):
                print('警告: 缺少 kkl5 源根: ' + src_root)
                continue
            p_cls = os.path.join(BUILD, 'kkl5dex', part, 'classes')
            p_dex_dir = os.path.join(BUILD, 'kkl5dex', part, 'dex')
            os.makedirs(p_cls, exist_ok=True)
            os.makedirs(p_dex_dir, exist_ok=True)
            p_java = sorted(glob.glob(os.path.join(src_root, '**', '*.java'), recursive=True))
            cp = android_jar
            for dep in k5_deps.get(part, []):
                dep_cls = os.path.join(BUILD, 'kkl5dex', dep, 'classes')
                if os.path.isdir(dep_cls):
                    cp += os.pathsep + dep_cls
            run([javac, '-encoding', 'UTF-8', '-source', '8', '-target', '8',
                 '-bootclasspath', android_jar, '-classpath', cp, '-d', p_cls] + p_java)
            p_jar = os.path.join(BUILD, 'kkl5dex', part, 'classes.jar')
            with zipfile.ZipFile(p_jar, 'w', zipfile.ZIP_DEFLATED) as zj:
                for cf in sorted(glob.glob(os.path.join(p_cls, '**', '*.class'), recursive=True)):
                    zj.write(cf, os.path.relpath(cf, p_cls).replace('\\', '/'))
            if part in ('p_outer', 'shell_a', 'shell_b'):
                # 壳类群走 R8 混淆（r8_shell.pro：keep 入口 Wick，其余壳类改名）
                r8_shell_pro = os.path.join(HERE, 'r8_shell.pro')
                shell_r8_jar = os.path.join(bt, 'lib', 'd8.jar')
                lib_args = ['--lib', android_jar]
                for dep in k5_deps.get(part, []):
                    dep_cls = os.path.join(BUILD, 'kkl5dex', dep, 'classes')
                    if os.path.isdir(dep_cls):
                        lib_args += ['--lib', dep_cls]
                run([os.path.join(java_bin, 'java.exe'), '-cp', shell_r8_jar,
                     'com.android.tools.r8.R8',
                     '--release', '--min-api', '21'] +
                     lib_args +
                     ['--pg-conf', r8_shell_pro,
                      '--output', p_dex_dir, p_jar])
            else:
                run([d8, '--release', '--min-api', '21', '--output', p_dex_dir, p_jar])
            p_dex = os.path.join(p_dex_dir, 'classes.dex')
            if os.path.isfile(p_dex):
                k5_dexes[part] = p_dex
            else:
                print('警告: 未找到 kkl5(%s) dex 输出: %s' % (part, p_dex))
        if all(k in k5_dexes for k in k5_bake_order):
            # bake 期望顺序：outer + shell_a + shell_b + 5a..5m + decoy
            run([sys.executable, os.path.join(HERE, 'gen_kkl5.py'), '--bake'] +
                [k5_dexes[k] for k in k5_bake_order])
        else:
            print('警告: kkl5 十七个 dex 不齐，跳过烘焙')

    # 0d) KKL3 断魂谷：业务拆五片（p3a..p3e）+ 明文诱饵（pdecoy），六个源根各自编译成一个 dex
    #     （源码在 app/kkl3dex 下，不进主 dex）；片间有引用，按拓扑序编译（3a/3b/3c → 3d(依赖3c)
    #     → 3e(依赖3a/3b/3d) → pdecoy）；再 gen_kkl3.py --bake 做方法体抽取（3d/3e）+ SM4 加密埋 assets。
    kkl3_src = os.path.join(APP, 'kkl3dex')
    if os.path.isdir(kkl3_src):
        k3_order = ['p3a', 'p3b', 'p3c', 'p3d', 'p3e', 'pdecoy']
        k3_deps = {'p3d': ['p3c'], 'p3e': ['p3a', 'p3b', 'p3d']}
        k3_dexes = {}
        for part in k3_order:
            src_root = os.path.join(kkl3_src, part)
            if not os.path.isdir(src_root):
                print('警告: 缺少 kkl3 源根: ' + src_root)
                continue
            p_cls = os.path.join(BUILD, 'kkl3dex', part, 'classes')
            p_dex_dir = os.path.join(BUILD, 'kkl3dex', part, 'dex')
            os.makedirs(p_cls, exist_ok=True)
            os.makedirs(p_dex_dir, exist_ok=True)
            p_java = sorted(glob.glob(os.path.join(src_root, '**', '*.java'), recursive=True))
            cp = android_jar
            for dep in k3_deps.get(part, []):
                dep_cls = os.path.join(BUILD, 'kkl3dex', dep, 'classes')
                if os.path.isdir(dep_cls):
                    cp += os.pathsep + dep_cls
            run([javac, '-encoding', 'UTF-8', '-source', '8', '-target', '8',
                 '-bootclasspath', android_jar, '-classpath', cp, '-d', p_cls] + p_java)
            p_jar = os.path.join(BUILD, 'kkl3dex', part, 'classes.jar')
            with zipfile.ZipFile(p_jar, 'w', zipfile.ZIP_DEFLATED) as zj:
                for cf in sorted(glob.glob(os.path.join(p_cls, '**', '*.class'), recursive=True)):
                    zj.write(cf, os.path.relpath(cf, p_cls).replace('\\', '/'))
            run([d8, '--release', '--min-api', '21', '--output', p_dex_dir, p_jar])
            p_dex = os.path.join(p_dex_dir, 'classes.dex')
            if os.path.isfile(p_dex):
                k3_dexes[part] = p_dex
            else:
                print('警告: 未找到 kkl3(%s) dex 输出: %s' % (part, p_dex))
        if all(k in k3_dexes for k in k3_order):
            run([sys.executable, os.path.join(HERE, 'gen_kkl3.py'), '--bake'] +
                [k3_dexes[k] for k in k3_order])
        else:
            print('警告: kkl3 六个业务 dex 不齐，跳过烘焙')

    # 0e) KKL4 锁妖塔：多类壳（w.* 壳类群）+ 九片业务 DEX（4a..4i）+ 明文诱饵（pdecoy）。
    #     十一个源根各自编译成一个 dex（源码在 app/kkl4dex 下，不进主 dex）；
    #     壳类群走 r8_shell.pro（R8 混淆）；片间按拓扑序编译；
    #     再 gen_kkl4.py --bake 做壳层/业务分片 AES-128-CTR 加密埋 assets/kkl4/。
    kkl4_src = os.path.join(APP, 'kkl4dex')
    if os.path.isdir(kkl4_src):
        k4_order = ['p4a', 'p4b', 'p4c', 'p4d', 'p4e', 'p4f', 'p4g', 'p4h', 'p4i', 'pshell', 'pdecoy']
        k4_deps = {'p4e': ['p4b'], 'p4g': ['p4f'],
                   'p4i': ['p4a', 'p4b', 'p4c', 'p4h'], 'pshell': ['p4h']}
        k4_dexes = {}
        for part in k4_order:
            src_root = os.path.join(kkl4_src, part)
            if not os.path.isdir(src_root):
                print('警告: 缺少 kkl4 源根: ' + src_root)
                continue
            p_cls = os.path.join(BUILD, 'kkl4dex', part, 'classes')
            p_dex_dir = os.path.join(BUILD, 'kkl4dex', part, 'dex')
            os.makedirs(p_cls, exist_ok=True)
            os.makedirs(p_dex_dir, exist_ok=True)
            p_java = sorted(glob.glob(os.path.join(src_root, '**', '*.java'), recursive=True))
            cp = android_jar
            for dep in k4_deps.get(part, []):
                dep_cls = os.path.join(BUILD, 'kkl4dex', dep, 'classes')
                if os.path.isdir(dep_cls):
                    cp += os.pathsep + dep_cls
            run([javac, '-encoding', 'UTF-8', '-source', '8', '-target', '8',
                 '-bootclasspath', android_jar, '-classpath', cp, '-d', p_cls] + p_java)
            p_jar = os.path.join(BUILD, 'kkl4dex', part, 'classes.jar')
            with zipfile.ZipFile(p_jar, 'w', zipfile.ZIP_DEFLATED) as zj:
                for cf in sorted(glob.glob(os.path.join(p_cls, '**', '*.class'), recursive=True)):
                    zj.write(cf, os.path.relpath(cf, p_cls).replace('\\', '/'))
            if part == 'pshell':
                # 壳类群走 R8 混淆（r8_shell.pro：keep 入口 Wick，其余 shellw 类改名）
                r8_shell_pro = os.path.join(HERE, 'r8_shell.pro')
                shell_r8_jar = os.path.join(bt, 'lib', 'd8.jar')
                run([os.path.join(java_bin, 'java.exe'), '-cp', shell_r8_jar,
                     'com.android.tools.r8.R8',
                     '--release', '--min-api', '21',
                     '--lib', android_jar,
                     '--lib', os.path.join(BUILD, 'kkl4dex', 'p4h', 'classes'),
                     '--pg-conf', r8_shell_pro,
                     '--output', p_dex_dir, p_jar])
            else:
                run([d8, '--release', '--min-api', '21', '--output', p_dex_dir, p_jar])
            p_dex = os.path.join(p_dex_dir, 'classes.dex')
            if os.path.isfile(p_dex):
                k4_dexes[part] = p_dex
            else:
                print('警告: 未找到 kkl4(%s) dex 输出: %s' % (part, p_dex))
        if all(k in k4_dexes for k in k4_order):
            # bake 期望顺序：shell(pshell) 第一，然后 4a..4i，最后 decoy
            bake_order = ['pshell'] + [k for k in k4_order if k not in ('pshell', 'pdecoy')] + ['pdecoy']
            run([sys.executable, os.path.join(HERE, 'gen_kkl4.py'), '--bake'] +
                [k4_dexes[k] for k in bake_order])
        else:
            print('警告: kkl4 十一个业务 dex 不齐，跳过烘焙')
    # 1) aapt2：编译资源 + 链接生成未签名 APK 与 R.java
    res_zip = os.path.join(BUILD, 'res.zip')
    res_dir = os.path.join(APP, 'res')
    if os.path.isdir(res_dir) and os.listdir(res_dir):
        run([aapt2, 'compile', '--dir', res_dir, '-o', res_zip])
        link_cmd = [aapt2, 'link', '-o', os.path.join(BUILD, 'unsigned.apk'),
                    '-I', android_jar,
                    '--manifest', os.path.join(APP, 'AndroidManifest.xml'),
                    '-A', os.path.join(APP, 'assets'),
                    '--java', os.path.join(BUILD, 'gen'),
                    '--min-sdk-version', '21', '--target-sdk-version', '34',
                    '--version-code', '1', '--version-name', '1.0',
                    res_zip]
    else:
        link_cmd = [aapt2, 'link', '-o', os.path.join(BUILD, 'unsigned.apk'),
                    '-I', android_jar,
                    '--manifest', os.path.join(APP, 'AndroidManifest.xml'),
                    '-A', os.path.join(APP, 'assets'),
                    '--java', os.path.join(BUILD, 'gen'),
                    '--min-sdk-version', '21', '--target-sdk-version', '34',
                    '--version-code', '1', '--version-name', '1.0']
    run(link_cmd)

    # 2) javac：源码 + R.java + libs jar 一起编译（OkHttp 等在 classpath 上）
    srcs = glob.glob(os.path.join(APP, 'src', '**', '*.java'), recursive=True)
    srcs += glob.glob(os.path.join(BUILD, 'gen', '**', '*.java'), recursive=True)
    run([javac, '-encoding', 'UTF-8', '-source', '8', '-target', '8',
         '-bootclasspath', android_jar,
         '-classpath', android_jar + os.pathsep + lib_cp,
         '-d', os.path.join(BUILD, 'classes')] + srcs)

    # 3) R8：带 keep 规则的混淆 + 打包，产出 classes.dex。
    #    keep 规则见 r8.pro：除关卡 19 加密包 com.fatdog.reverse.o.** 外全部保留原名（可读），
    #    第三方 jar（okhttp/okio/kotlin）作为输入参与打包并被 keep 保留。
    #    R8 只接受 jar/zip 输入，先把 build/classes 打成 jar。
    classes_jar = os.path.join(BUILD, 'classes.jar')
    with zipfile.ZipFile(classes_jar, 'w', zipfile.ZIP_DEFLATED) as zj:
        for cf in glob.glob(os.path.join(BUILD, 'classes', '**', '*.class'), recursive=True):
            zj.write(cf, os.path.relpath(cf, os.path.join(BUILD, 'classes')).replace('\\', '/'))
    #    d8.bat 与 R8 同源码，build-tools/lib/d8.jar 里就有 com.android.tools.r8.R8。
    r8_jar = os.path.join(bt, 'lib', 'd8.jar')
    r8_pro = os.path.join(HERE, 'r8.pro')
    dex_r8 = os.path.join(BUILD, 'dex_r8')
    os.makedirs(dex_r8, exist_ok=True)
    run([os.path.join(java_bin, 'java.exe'), '-cp', r8_jar, 'com.android.tools.r8.R8',
         '--release', '--min-api', '21',
         '--lib', android_jar,
         '--pg-conf', r8_pro,
         '--output', dex_r8,
         classes_jar] + lib_jars)

    # 4) NDK 编译各关 so（**必需**）
    #    启动期会静态装载 60 个 so；APK 里没有 lib/ 时，Application.onCreate 就抛
    #    UnsatisfiedLinkError，表现为"安装成功、点开闪退、没有任何界面"。
    #    因此这里绝不降级跳过：没有 NDK / 没有 ndk-build 一律直接失败。
    need_libs = required_native_libs()
    ndk = find_ndk(sdk)
    libs = {}
    if ndk:
        ndk_build = os.path.join(ndk, 'ndk-build.cmd')
        if os.path.isfile(ndk_build):
            # KL29 TLV 基准帧：纯数据头，先烘焙再编译 so
            run([sys.executable, os.path.join(HERE, 'tools', 'gen_tlv_reference.py')])
            run([ndk_build, '-C', APP])
            # KL13 真实代码段 CRC：烘焙基线 → 重编 → 校验（循环直到稳定）
            gen_baseline = os.path.join(HERE, 'tools', 'gen_code_crc_baselines.py')
            for attempt in range(3):
                run([sys.executable, gen_baseline])
                run([ndk_build, '-C', APP])
                try:
                    run([sys.executable, gen_baseline, '--verify'])
                    break
                except subprocess.CalledProcessError:
                    if attempt == 2:
                        raise
            # KL15 libshale 真实代码段 CRC：同样烘焙基线 → 重编 → 校验
            gen_shale = os.path.join(HERE, 'tools', 'gen_shale_crc_baseline.py')
            for attempt in range(3):
                run([sys.executable, gen_shale])
                run([ndk_build, '-C', APP])
                try:
                    run([sys.executable, gen_shale, '--verify'])
                    break
                except subprocess.CalledProcessError:
                    if attempt == 2:
                        raise
            # 4b) 回填 Flutter 真实产物：ndk-build 会清空 libs/<abi>/*，须在其后重抽。
            inject_flutter_libs(APP)
            # 逐 ABI 校验：启动期要加载的 so 必须一个不缺，否则这个 ABI 直接不算数。
            # （以前这里不校验，没 NDK 时会安静地打出"没有 lib/ 的 APK"，
            #   装机后 100% 闪退——issue 里最常见的一类。）
            for abi in ('arm64-v8a', 'armeabi-v7a'):
                sos = sorted(glob.glob(os.path.join(APP, 'libs', abi, '*.so')))
                present = set(os.path.basename(x) for x in sos)
                missing = sorted(n for n in need_libs if ('lib%s.so' % n) not in present)
                if missing:
                    print('跳过 ABI %s：缺 %d 个启动期 so（%s%s）'
                          % (abi, len(missing), ', '.join(missing[:4]),
                             ' ...' if len(missing) > 4 else ''))
                    continue
                if 'libc++_shared.so' not in present:
                    print('跳过 ABI %s：缺 libc++_shared.so（APP_STL := c++_shared）' % abi)
                    continue
                libs[abi] = sos
            total = sum(len(v) for v in libs.values())
            print('NDK 产物:', total, '个 so /',
                  ', '.join('%s=%d' % (a, len(v)) for a, v in libs.items()))
            if 'arm64-v8a' not in libs:
                sys.exit('arm64-v8a 的 native 库不完整，打出来的 APK 在 64 位设备上必闪退。\n'
                         '先删掉 app/obj 与 app/libs 再重跑；仍失败请检查 jni/ 的编译错误。')
        else:
            sys.exit('找到 NDK 目录但没有 ndk-build.cmd：%s\n'
                     '打不出 lib/ 的 APK 装上必闪退，不能继续。请重装 NDK。' % ndk)
    else:
        sys.exit('未找到 NDK。FatdogReverse 的启动路径会静态装载 60 个 so，\n'
                 '缺少 lib/ 的 APK 安装后点开必闪退（UnsatisfiedLinkError）。\n'
                 '请安装 NDK 后重试：\n'
                 '    sdkmanager "ndk;26.1.10909125"\n'
                 '或设置环境变量 ANDROID_NDK_ROOT 指向 NDK 目录。')

    # 5) 把 dex / so 塞进 APK
    unsigned = os.path.join(BUILD, 'unsigned.apk')
    with zipfile.ZipFile(unsigned, 'a') as z:
        for df in sorted(glob.glob(os.path.join(dex_r8, 'classes*.dex'))):
            z.write(df, os.path.basename(df))
        for abi, sos in libs.items():
            for so in sos:
                z.write(so, 'lib/%s/%s' % (abi, os.path.basename(so)),
                        compress_type=zipfile.ZIP_STORED)

    # 5b) 打包后复核：确认启动期 so 真的进包了（防止 zip 阶段漏写）。
    with zipfile.ZipFile(unsigned) as z:
        packed = set(n for n in z.namelist() if n.startswith('lib/'))
    for abi in libs:
        miss = sorted(n for n in need_libs
                      if ('lib/%s/lib%s.so' % (abi, n)) not in packed)
        if miss:
            sys.exit('APK 里缺少启动期 so（%s）: %s ...\n'
                     '这样装上去必闪退，已中止。' % (abi, ', '.join(miss[:5])))
    print('启动期 so 复核通过:', len(need_libs), '个库 /', ', '.join(sorted(libs)))

    # 6) zipalign 对齐
    aligned = os.path.join(BUILD, 'aligned.apk')
    run([zipalign, '-f', '4', unsigned, aligned])

    # 7) 签名 keystore：固定放项目根 keystore/（构建清理不删除，仅缺失时生成一次）
    ks = KEYSTORE
    if not os.path.isfile(ks):
        os.makedirs(os.path.dirname(ks), exist_ok=True)
        run([keytool, '-genkeypair', '-keystore', ks, '-alias', 'androiddebugkey',
             '-storepass', 'android', '-keypass', 'android',
             '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000',
             '-dname', 'CN=Android Debug,O=Android,C=US'])

    # 8) apksigner 签名（默认 v1+v2：META-INF 三件套 + APK Signature Block）
    out_apk = os.path.join(HERE, 'FatdogReverse.apk')
    run([apksigner, 'sign', '--ks', ks, '--ks-key-alias', 'androiddebugkey',
         '--ks-pass', 'pass:android', '--key-pass', 'pass:android',
         '--out', out_apk, aligned])

    # 8b) 签名基准自检：L43-L47「签名校验对抗」五关把**原包证书的 SHA-256**烘焙进了
    #     Java 类（L43）、四份 so（L44-L47）、felix 的 CRC 基线和 server.py（L46/L47）。
    #     证书指纹只由 keystore 决定、与 APK 内容无关；但 keystore 缺失时上面的第 7 步
    #     会静默生成一把新钥匙 —— 那一刻这五关全部变成"玩家一进来就被判定为重打包"，
    #     而且不会报任何错。所以签完名立刻拿实际签名证书对拍所有烘焙点，不一致就中止。
    print()
    print('>> 校验签名基准（L43-L47）')
    if subprocess.call([sys.executable, os.path.join('tools', 'verify_signature_baseline.py'),
                        '--keystore', os.path.relpath(ks, HERE)], cwd=HERE) != 0:
        sys.exit('签名基准与代码内烘焙值不一致（详见上面的 FAIL 行），已中止构建。\n'
                 '要么用回原 keystore 重新签名，要么把实际摘要重新烘焙进 L43-L47。')

    print()
    print('构建成功:', out_apk)
    print('APK 内容:')
    with zipfile.ZipFile(out_apk) as z:
        for n in z.namelist():
            print('   ', n)
    print('安装: adb install -r', out_apk)


if __name__ == '__main__':
    main()
