# -*- coding: utf-8 -*-
"""javac 全量自检：严格复刻 build_apk.py 的 javac 步骤（含 run() 的相对路径改写）。
只编译，不产出 APK；不触碰 src/res/assets/native。"""
import glob, os, subprocess, sys, shutil

HERE = r'D:\大胖狗的学习\FatdogReverse'
APP = os.path.join(HERE, 'app')
BUILD = os.path.join(HERE, 'build')
LIB_JAR_NAMES = ('okhttp-4.12.0.jar', 'okio-jvm-3.6.0.jar', 'kotlin-stdlib-1.8.22.jar', 'annotations.jar')


def find_sdk():
    for k in ('ANDROID_SDK_ROOT', 'ANDROID_HOME'):
        v = os.environ.get(k)
        if v and os.path.isdir(v):
            return v
    for g in (r'D:\Andorid\SDK', r'D:\Android\Sdk', r'C:\Android\Sdk'):
        if os.path.isdir(g):
            return g
    return None


def pick_latest(d):
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
    jh = os.environ.get('JAVA_HOME')
    if jh and os.path.isfile(os.path.join(jh, 'bin', 'javac.exe')):
        return os.path.join(jh, 'bin')
    for c in (r'D:\JAVA\bin',):
        if os.path.isdir(c) and os.path.isfile(os.path.join(c, 'javac.exe')):
            return c
    f = shutil.which('javac')
    return os.path.dirname(f) if f else None


sdk = find_sdk()
android_jar = os.path.join(pick_latest(os.path.join(sdk, 'platforms')), 'android.jar')
java_bin = find_java()
javac = os.path.join(java_bin, 'javac.exe')
print('javac      :', javac)
print('android.jar:', android_jar)
print('exists     :', os.path.isfile(javac), os.path.isfile(android_jar))

lib_jars = [os.path.join(HERE, 'libs', n) for n in LIB_JAR_NAMES]
for j in lib_jars:
    print('lib        :', os.path.basename(j), os.path.isfile(j))
lib_cp = os.pathsep.join(lib_jars)

srcs = glob.glob(os.path.join(APP, 'src', '**', '*.java'), recursive=True)
gen = glob.glob(os.path.join(BUILD, 'gen', '**', '*.java'), recursive=True)
print('src java   :', len(srcs), '| gen java:', len(gen))
assert gen, 'build/gen 缺失（先跑一次 build_apk.py 生成 R.java）'

out = os.path.join(BUILD, '_jcheck')
shutil.rmtree(out, ignore_errors=True)
os.makedirs(out, exist_ok=True)

cmd = [javac, '-encoding', 'UTF-8', '-source', '8', '-target', '8',
       '-bootclasspath', android_jar,
       '-classpath', android_jar + os.pathsep + lib_cp,
       '-d', out] + srcs + gen

# 复刻 run()：cwd=项目根，项目内绝对路径改相对
fixed = []
for c in cmd:
    if isinstance(c, str) and os.path.isabs(c):
        try:
            if os.path.commonpath([c, HERE]) == HERE:
                c = os.path.relpath(c, HERE)
        except ValueError:
            pass
    fixed.append(c)

print('>> running javac ...')
r = subprocess.run(fixed, cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
outtxt = r.stdout.decode('gbk', 'replace')
warn = [l for l in outtxt.splitlines() if 'warning' in l.lower() or '警告' in l]
err = [l for l in outtxt.splitlines() if 'error' in l.lower() or '错误' in l]
print('rc =', r.returncode, '| warnings:', len(warn), '| errors:', len(err))
ncls = 0
for rt, ds, fs in os.walk(out):
    ncls += len([f for f in fs if f.endswith('.class')])
print('classes produced:', ncls)
if err:
    print('--- errors ---')
    for l in err[:40]:
        print('   ', l)
if r.returncode != 0:
    print('--- full tail ---')
    print('\n'.join(outtxt.splitlines()[-40:]))
shutil.rmtree(out, ignore_errors=True)
print('CLEANUP _jcheck ->', not os.path.exists(out))
sys.exit(r.returncode)
