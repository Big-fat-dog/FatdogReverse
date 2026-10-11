# -*- coding: utf-8 -*-
"""
verify_kl7_cpp.py —— 流沙河 KL7「裂魂之匣」C++ 化验收（容器 + RAII + 虚派发）。

断言四条硬门槛：
  ① C++ 端 enc/sign 与生成器/服务端 Python 镜像逐字节一致（算法语义零漂移）；
  ② server.py 端到端验签：真钥 `_kl7_try(KL7_MASTER, ...)` True、诱饵 `DECOY_KL7` 被拒；
  ③ 源码特征：frost.cpp 含 std::array / DesVariant / class Codec / virtual / extern "C"，
     且无旧 frost.c 残留、Android.mk 已指向 frost.cpp；
  ④ 宿主 g++ 编译 C++ 源码通过（-DM2_HOST_TEST 自带 main，跑出 sample enc/sign）。

用法（须用带 fastapi 的解释器，本项目为 D:\\python39\\python.exe）：
    D:\\python39\\python.exe tools/verify_kl7_cpp.py

自带临时目录，跑完自动删除并核实。退出码 0 = 全过；1 = 有失败。
"""
import os
import re
import sys
import shutil
import tempfile
import subprocess
import importlib.util

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GXX = os.environ.get("FDR_GXX", r"D:\mingw64\bin\g++.exe")
CPP = os.path.join(ROOT, "app", "jni", "frost.cpp")


def _run(cmd, cwd, check=True):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True)
    if check and r.returncode != 0:
        print("  !! 命令失败:", " ".join(cmd))
        print("  " + r.stderr.decode("utf-8", "replace").replace("\n", "\n  "))
        raise SystemExit(1)
    return r


def main():
    failures = []

    # ---------- ③ 源码特征（最便宜的先查） ----------
    print("=== ③ 源码特征 ===")
    if not os.path.exists(CPP):
        print("  !! 找不到 frost.cpp:", CPP)
        return 1
    src = open(CPP, encoding="utf-8").read()
    for feat, pat in [
        ("std::array 载表", r"std::array<unsigned char, 64>"),
        ("DesVariant 换血点打包", r"struct DesVariant"),
        ("class Codec 抽象基类", r"class Codec"),
        ("虚函数派发", r"virtual"),
        ("RAII 析构 secure_zero", r"virtual ~Codec"),
        ("工厂 make_codec", r"make_codec"),
        ("RegisterNatives 动态注册", r"RegisterNatives"),
        ("导出仅 JNI_OnLoad", r'extern "C" JNIEXPORT jint JNICALL JNI_OnLoad'),
    ]:
        ok = bool(re.search(pat, src))
        print("  %-24s : %s" % (feat, ok))
        if not ok:
            failures.append("feat:" + feat)

    # 中性化检查：不应出现 decoy_seal / fold / spin 这类直白导出名
    for bad in ["m2_decoy_seal", "m2_fold", "m2_spin"]:
        if bad in src:
            print("  !! 仍存在直白导出名:", bad)
            failures.append("bad-name:" + bad)

    # 旧 frost.c 应已删除
    old_c = os.path.join(ROOT, "app", "jni", "frost.c")
    ok_no_old = not os.path.exists(old_c)
    print("  旧 frost.c 已删除          :", ok_no_old)
    if not ok_no_old:
        failures.append("old-c-remains")

    # Android.mk 应指向 frost.cpp
    mk = open(os.path.join(ROOT, "app", "jni", "Android.mk"), encoding="utf-8").read()
    ok_mk = bool(re.search(r"LOCAL_MODULE := frost\s*\nLOCAL_SRC_FILES := frost\.cpp", mk))
    print("  Android.mk -> frost.cpp    :", ok_mk)
    if not ok_mk:
        failures.append("mk-not-cpp")

    # ---------- ④ 宿主编译 + 跑 sample ----------
    print("=== ④ 宿主编译 + sample ===")
    tmp = tempfile.mkdtemp(prefix="fdr_kl7_cpp_")
    try:
        exe = os.path.join(tmp, "frosttest.exe")
        r = _run([GXX, "-std=c++17", "-DM2_HOST_TEST", CPP, "-o", exe], cwd=tmp)
        out = subprocess.run([exe], cwd=tmp, capture_output=True)
        txt = out.stdout.decode("utf-8", "replace")
        if out.returncode != 0:
            print("  !! 宿主程序崩溃 rc=%d" % out.returncode)
            print(txt)
            failures.append("host-run-crash")
        else:
            enc = re.search(r"sample_enc\s+=\s+(\S+)", txt)
            sign = re.search(r"sample_sign\s+=\s+(\S+)", txt)
            if enc and sign:
                cpp_enc, cpp_sign = enc.group(1), sign.group(1)
                print("  C++ sample_enc  =", cpp_enc[:32] + "...")
                print("  C++ sample_sign =", cpp_sign)
            else:
                print("  !! 未解析出 sample_enc/sign")
                failures.append("parse-sample")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        print("  临时目录已清理:", "不存在" if not os.path.exists(tmp) else "!! 仍存在")

    # ---------- ①② Python 镜像对拍 + 服务端验签 ----------
    print("=== ①② Python 镜像对拍 + 服务端验签 ===")
    spec = importlib.util.spec_from_file_location("fdr_gen7", os.path.join(ROOT, "gen_kl7.py"))
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)

    spec2 = importlib.util.spec_from_file_location("fdr_server", os.path.join(ROOT, "server.py"))
    srv = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(srv)

    key = srv.KL7_MASTER
    decoy = srv.DECOY_KL7[0]

    cases = [(1, 1787013761, "1a2b3c4d", "android-34"),
             (7, 1700000123, "deadbeef", "emu-30"),
             (50, 1700000001, "cafe1234", "android-35"),
             (100, 1234567890, "00ff00ff", "release-keys")]

    n = ok = dec = 0
    fails_b = []
    for page, ts, nonce, dev in cases:
        # Python 镜像（gen_kl7.py 的 core_enc/core_sign）
        enc = gen.core_enc(page, ts, nonce, dev).hex()
        sign = gen.core_sign(enc)
        # 服务端验签：真钥
        if srv._kl7_try(key, page, ts, nonce, enc, sign):
            ok += 1
        else:
            fails_b.append((page, ts, "real-rejected"))
        # 诱饵应被拒
        if not srv._kl7_try(decoy, page, ts, nonce, enc, sign):
            dec += 1
        else:
            fails_b.append((page, ts, "decoy-accepted"))
        n += 1

    ok_b = (ok == n and dec == n and n > 0)
    print("  服务端验签 真钥 %d/%d 诱饵被拒 %d/%d :" % (ok, n, dec, n), ok_b)
    if fails_b:
        print("    失败明细:", fails_b)
    if not ok_b:
        failures.append("server-e2e")

    # 关键对拍：C++ 宿主 sample 与 Python 镜像逐字节一致
    if 'cpp_enc' in dir():
        py_enc = gen.core_enc(1, 1787013761, "1a2b3c4d", "android-34").hex()
        py_sign = gen.core_sign(py_enc)
        ok_match = (cpp_enc == py_enc and cpp_sign == py_sign)
        print("  C++/Python enc+sign 逐字节一致 :", ok_match)
        if not ok_match:
            print("    cpp_enc =", cpp_enc)
            print("    py_enc  =", py_enc)
            failures.append("cpp-python-mismatch")

    print("\n===== 汇总 =====")
    if failures:
        print("  FAIL:", ", ".join(failures))
        return 1
    print("  全部通过（源码特征 + 宿主编译 + Python 镜像对拍 + 服务端验签）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
