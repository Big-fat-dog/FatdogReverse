# -*- coding: utf-8 -*-
"""FatdogReverse APK 构建脚本（无需 Android Studio / Gradle）。

依赖：
  1) JDK 17+（本机 PyCharm 自带 JBR 即可，脚本会自动探测）
  2) Android SDK：build-tools（aapt2/d8/apksigner/zipalign）+ platforms/android-XX/android.jar
3) NDK（关卡 25 必需）：装了就自动编译 jni/ 里的 libnative.so（arm64-v8a + armeabi-v7a）。
       关卡 25 的 JNI 门禁与 native HMAC 签名都在这个 so 里，缺了进不去。

设置 ANDROID_SDK_ROOT（或 ANDROID_HOME）指向 SDK 根目录后运行：
    python build_apk.py
产物：FatdogReverse.apk（含图标、资源、单 classes.dex（R8 打包全部关卡，含关卡 20 的 AdBox/a20Activity）、assets/config.json、可选 lib/*.so、META-INF 签名）
"""
import glob
import os
import shutil
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, 'app')
BUILD = os.path.join(HERE, 'build')

# 关卡 15+ 的 OkHttp 依赖：只打这份白名单，避免把大 jar 全塞进 dex。
# 这些 jar 会被 R8 编进 classes.dex；classes2 里的类引用它们时用 --lib 解析即可。
LIB_JAR_NAMES = ('okhttp-4.12.0.jar', 'okio-jvm-3.6.0.jar', 'kotlin-stdlib-1.8.22.jar', 'annotations.jar')


def find_sdk():
    for k in ('ANDROID_SDK_ROOT', 'ANDROID_HOME'):
        v = os.environ.get(k)
        if v and os.path.isdir(v):
            return v
    guesses = [
        os.path.expandvars(r'%LOCALAPPDATA%\Android\Sdk'),
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
    for c in (r'E:\PyCharm 2025.3.3\jbr\bin', r'C:\Program Files\Java'):
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


def run(cmd, **kw):
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

    shutil.rmtree(BUILD, ignore_errors=True)
    os.makedirs(os.path.join(BUILD, 'classes'))

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

    # 4) 可选：NDK 编译 libnative.so（关卡 25 的 JNI 校验 + 结构装饰）
    ndk = find_ndk(sdk)
    libs = {}
    if ndk:
        ndk_build = os.path.join(ndk, 'ndk-build.cmd')
        if os.path.isfile(ndk_build):
            run([ndk_build, '-C', APP])
            for abi in ('arm64-v8a', 'armeabi-v7a'):
                so = os.path.join(APP, 'libs', abi, 'libnative.so')
                if os.path.isfile(so):
                    libs[abi] = so
            print('NDK 产物:', ', '.join(libs.keys()) or '无')
        else:
            print('警告: 找到 NDK 目录但缺少 ndk-build.cmd，跳过 so 编译')
    else:
        print('提示: 未找到 NDK，跳过 libnative.so（APK 仍可构建，只是少了 lib/ 目录的结构装饰）。')
        print('      安装: sdkmanager "ndk;26.1.10909125"（或设置 ANDROID_NDK_ROOT）')

    # 5) 把 dex / so 塞进 APK
    unsigned = os.path.join(BUILD, 'unsigned.apk')
    with zipfile.ZipFile(unsigned, 'a') as z:
        for df in sorted(glob.glob(os.path.join(dex_r8, 'classes*.dex'))):
            z.write(df, os.path.basename(df))
        for abi, so in libs.items():
            z.write(so, 'lib/%s/libnative.so' % abi, compress_type=zipfile.ZIP_STORED)

    # 6) zipalign 对齐
    aligned = os.path.join(BUILD, 'aligned.apk')
    run([zipalign, '-f', '4', unsigned, aligned])

    # 7) 生成调试 keystore（只生成一次）
    ks = os.path.join(BUILD, 'debug.keystore')
    if not os.path.isfile(ks):
        run([keytool, '-genkeypair', '-keystore', ks, '-alias', 'androiddebugkey',
             '-storepass', 'android', '-keypass', 'android',
             '-keyalg', 'RSA', '-keysize', '2048', '-validity', '10000',
             '-dname', 'CN=Android Debug,O=Android,C=US'])

    # 8) apksigner 签名（默认 v1+v2：META-INF 三件套 + APK Signature Block）
    out_apk = os.path.join(HERE, 'FatdogReverse.apk')
    run([apksigner, 'sign', '--ks', ks, '--ks-key-alias', 'androiddebugkey',
         '--ks-pass', 'pass:android', '--key-pass', 'pass:android',
         '--out', out_apk, aligned])

    print()
    print('构建成功:', out_apk)
    print('APK 内容:')
    with zipfile.ZipFile(out_apk) as z:
        for n in z.namelist():
            print('   ', n)
    print('安装: adb install -r', out_apk)


if __name__ == '__main__':
    main()
