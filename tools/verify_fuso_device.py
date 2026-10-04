#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
verify_fuso_device.py — 真机验证 fuso_probe.h（扶桑树 KL26/27/28 共用检测头）

背景（2026-10-04）：
    KL26/KL27 首日真机开箱即闪退，根因是 headless 的宿主自测**测不到**的问题——
    Android 10+ 把系统库的 .text 映射为 --xp（只执行、不可读），
    fuso_libc_prologue() 直接 memcmp(sym, disk, 16) → SIGSEGV(SEGV_ACCERR)，
    打开关卡即闪退。宿主没有 /proc，这几路会整路跳过，所以宿主「全绿」毫无意义。

本脚本做的事：
    1) 用 NDK clang 把 tools/fuso_device_probe.c 交叉编译成 arm64/arm32 可执行文件
    2) push 到设备 /data/local/tmp 运行
    3) 断言：
       - 进程未被信号杀死（真的不崩）
       - 字节级对拍 match >= 1（证明 6/7 是「真读到了并比对」，不是被守卫跳过）
       - 干净环境各信号为 0
    4) 清理设备与本地临时文件

用法：
    python tools/verify_fuso_device.py            # 默认 arm64 + arm32
    python tools/verify_fuso_device.py --abi arm64
    python tools/verify_fuso_device.py --ndk 28.2.13676358
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JNI = os.path.join(ROOT, "app", "jni")
PROBE = os.path.join(ROOT, "tools", "fuso_device_probe.c")

SDK_CANDIDATES = [r"D:\Andorid\SDK", r"D:\Android\SDK"]
ADB_CANDIDATES = [r"D:\Andorid\SDK\platform-tools\adb.exe", r"D:\Android\SDK\platform-tools\adb.exe"]

ABI_TARGETS = {
    "arm64": "aarch64-linux-android21",
    "arm32": "armv7a-linux-androideabi21",
}


def find_adb():
    for c in ADB_CANDIDATES:
        if os.path.exists(c):
            return c
    return "adb"


def find_ndk(force=None):
    for sdk in SDK_CANDIDATES:
        ndkdir = os.path.join(sdk, "ndk")
        if not os.path.isdir(ndkdir):
            continue
        versions = sorted(os.listdir(ndkdir), reverse=True) if force is None else [force]
        for v in versions:
            root = os.path.join(ndkdir, v, "toolchains", "llvm", "prebuilt", "windows-x86_64")
            if os.path.exists(os.path.join(root, "bin", "clang.exe")):
                return v, root
    return None, None


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", **kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--abi", choices=["arm64", "arm32", "both"], default="both")
    ap.add_argument("--ndk", default=None, help="指定 NDK 版本目录名")
    args = ap.parse_args()

    ver, ndkroot = find_ndk(args.ndk)
    if not ndkroot:
        print("× 找不到 NDK（llvm prebuilt windows-x86_64）")
        return 1
    clang = os.path.join(ndkroot, "bin", "clang.exe")
    sysroot = os.path.join(ndkroot, "sysroot")
    adb = find_adb()
    print("NDK   :", ver)
    print("adb   :", adb)

    dev = run([adb, "devices"])
    if "device" not in dev.stdout.replace("List of devices attached", ""):
        print("× 无设备连接")
        print(dev.stdout)
        return 1

    abis = ["arm64", "arm32"] if args.abi == "both" else [args.abi]
    tmpdir = tempfile.mkdtemp(prefix="fuso_dev_")
    ok_all = True
    device_files = []

    try:
        for abi in abis:
            out = os.path.join(tmpdir, "fusoprobe_" + abi)
            r = run([clang, "--target=" + ABI_TARGETS[abi], "--sysroot=" + sysroot,
                     "-std=c11", "-O1", "-fPIE", "-pie", "-Wall", "-Wextra",
                     "-I", JNI, "-o", out, PROBE])
            if r.returncode:
                print("[%s] × 编译失败\n%s" % (abi, (r.stdout + r.stderr)[:800]))
                ok_all = False
                continue

            remote = "/data/local/tmp/fusoprobe_" + abi
            device_files.append(remote)
            run([adb, "push", out, remote])
            run([adb, "shell", "chmod", "755", remote])
            rr = run([adb, "shell", remote])

            text = rr.stdout or ""
            print("\n================ %s ================" % abi)
            print(text.rstrip())
            if rr.stderr.strip():
                print("stderr:", rr.stderr.strip()[:300])

            # ---- 断言 ----
            problems = []
            if "DONE (no crash)" not in text or rr.returncode != 0:
                problems.append("进程异常退出（可能被信号杀死）")
            m = re.search(r"match=(\d+) mismatch=(\d+) skip=(\d+)", text)
            if not m:
                problems.append("对拍段落缺失")
            else:
                match, mismatch = int(m.group(1)), int(m.group(2))
                if match < 1:
                    problems.append("字节级对拍 0 命中 → 6/7 可能是被守卫跳过的死代码")
                if mismatch:
                    problems.append("干净环境出现 mismatch=%d（误报）" % mismatch)
            for sig in ["signal_trial", "tracerpid", "smaps_dirty", "anon_exec",
                        "trampoline", "libc_prologue", "libc_scan", "libc_got"]:
                mm = re.search(re.escape(sig) + r"\s*:\s*(\d+)", text)
                if mm and mm.group(1) != "0":
                    problems.append("干净环境 %s=%s（误报，应为 0）" % (sig, mm.group(1)))

            if problems:
                ok_all = False
                for p in problems:
                    print("  [FAIL]", p)
            else:
                print("  [PASS] 不崩 + 对拍有效 + 干净环境无信号")
    finally:
        for f in device_files:
            run([adb, "shell", "rm", "-f", f])
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
        print("\n清理：设备临时文件已删；本地临时目录 %s 存在=%s"
              % (tmpdir, os.path.exists(tmpdir)))

    print("\n总判定 :", "ALL PASS" if ok_all else "有 FAIL")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
