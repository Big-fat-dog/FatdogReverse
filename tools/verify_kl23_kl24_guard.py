#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
verify_kl23_kl24_guard.py — 真机验证 KL23（libsun.so）/ KL24（libice.so）的检测是否真的能触发

背景（2026-11-23）：
    用户启动 frida-server 后，KL23 状态恒为 maps=0 / dt=1 / auxv=0（三路 AND 永不成立），
    KL24 恒为 0/4（阈值 ≥2 永不达）。真机定位到：
      KL23 ① maps 只扫前 16KB（真机 maps ≈260KB，注入映射在表尾，必漏）
      KL23 ③ auxv 依赖读 /proc/self/exe（zygote_exec，untrusted_app 被 SELinux 拦）→ 恒 0
      KL24 四路等权阈值 2，但四路现实互斥（attach 后 TracerPid 归 0 等）→ 真实 attach 也只 1 分
    修法：maps 改流式行缓冲；auxv 改纯内存程序头表自洽；KL24 改加权评分（直证 2 分）。

本脚本做的事：
    1) 用 NDK clang 把 tools/kl23_kl24_probe.c（直接 #include 关卡源码，零逻辑漂移）
       交叉编译成 arm64/arm32 可执行文件
    2) 生成一个 libfrida_probe.so 模拟注入映射（名字含 frida 的 r-xp 段）
    3) push 到设备 /data/local/tmp 运行，解析 KEY=VALUE
    4) 断言：
       - 干净环境：KL23 maps/combined=0、KL24 phase=1 / score=0 / detect=0（不误报）
       - KL23 结构守卫：auxv=1、dt=1（不能再恒 0）
       - 模拟注入后：maps=1 且 combined=1（AND 三路整链能成立）
       - ptrace 挂住后：KL24 tracerpid=1、score>=2、detect=1（能触发）
    5) 清理设备与本地临时文件

用法：
    python tools/verify_kl23_kl24_guard.py            # 默认 arm64 + arm32
    python tools/verify_kl23_kl24_guard.py --abi arm64
    python tools/verify_kl23_kl24_guard.py --ndk 28.2.13676358
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JNI = os.path.join(ROOT, "app", "jni")
PROBE = os.path.join(ROOT, "tools", "kl23_kl24_probe.c")

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


def kv(text, key):
    m = re.search(r"^" + re.escape(key) + r"=(\d+)\s*$", text, re.M)
    return int(m.group(1)) if m else None


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
        print("× 无设备连接（本脚本必须真机跑，宿主没有 /proc/self/maps 与 auxv）")
        print(dev.stdout)
        return 1

    abis = ["arm64", "arm32"] if args.abi == "both" else [args.abi]
    tmpdir = tempfile.mkdtemp(prefix="kl2324_dev_")
    ok_all = True
    device_files = []
    device_dirs = []

    # 探针 dlopen 的模拟注入 so（文件名必须含 frida；通过目录传入，避免污染父进程 cmdline）
    frida_src = os.path.join(tmpdir, "frida_probe.c")
    with open(frida_src, "w", encoding="utf-8") as f:
        f.write("int frida_probe_pad(void){return 42;}\n")

    try:
        for abi in abis:
            target = ABI_TARGETS[abi]
            out = os.path.join(tmpdir, "kl_probe_" + abi)
            r = run([clang, "--target=" + target, "--sysroot=" + sysroot,
                     "-std=c11", "-O1", "-fPIE", "-pie", "-Wall",
                     "-I", JNI, "-o", out, PROBE, "-ldl"])
            if r.returncode:
                print("[%s] × 探针编译失败\n%s" % (abi, (r.stdout + r.stderr)[:900]))
                ok_all = False
                continue

            so_out = os.path.join(tmpdir, "libfrida_probe_" + abi + ".so")
            r = run([clang, "--target=" + target, "--sysroot=" + sysroot,
                     "-O1", "-shared", "-fPIC", "-o", so_out, frida_src])
            if r.returncode:
                print("[%s] × 模拟注入 so 编译失败\n%s" % (abi, (r.stdout + r.stderr)[:900]))
                ok_all = False
                continue

            remote = "/data/local/tmp/kl23probe_" + abi
            remote_dir = "/data/local/tmp/kl23probe_" + abi + "_so"
            device_files.append(remote)
            device_dirs.append(remote_dir)
            run([adb, "shell", "mkdir", "-p", remote_dir])
            run([adb, "push", out, remote])
            run([adb, "push", so_out, remote_dir + "/libfrida_probe.so"])
            run([adb, "shell", "chmod", "755", remote])
            run([adb, "shell", "chmod", "644", remote_dir + "/libfrida_probe.so"])

            rr = run([adb, "shell", "KL_PROBE_DIR=%s %s" % (remote_dir, remote)])
            text = rr.stdout or ""
            print("\n================ %s ================" % abi)
            print(text.rstrip())
            if rr.stderr.strip():
                print("stderr:", rr.stderr.strip()[:300])

            problems = []
            expect = {
                "KL23_DT": 1,
                "KL23_AUXV": 1,          # 关键：修复后必须为 1，不能再恒 0
                "KL23_MAPS": 0,          # 干净环境无 frida 映射
                "KL23_COMBINED": 0,      # 干净环境不误报
                "KL_PROBE_DLOPEN": 1,
                "KL23_MAPS_INJECTED": 1,     # 注入后能命中（流式扫完整 maps）
                "KL23_COMBINED_INJECTED": 1,  # 三路 AND 整链成立
                "KL24_PHASE": 1,             # 加载期干净
                "KL24_CLEAN_TRACERPID": 0,
                "KL24_CLEAN_SCORE": 0,
                "KL24_CLEAN_DETECT": 0,
                "KL24_TRACED_TRACERPID": 1,  # ptrace 直证
                "KL24_TRACED_DETECT": 1,
                "KL24_TRACED_EXIT": 0,
            }
            for k, want in expect.items():
                got = kv(text, k)
                if got is None:
                    problems.append("缺少 %s" % k)
                elif got != want:
                    problems.append("%s=%s（应为 %s）" % (k, got, want))

            sc = kv(text, "KL24_TRACED_SCORE")
            if sc is None:
                problems.append("缺少 KL24_TRACED_SCORE")
            elif sc < 2:
                problems.append("KL24_TRACED_SCORE=%d < 阈值 2（加权评分未生效）" % sc)

            if problems:
                ok_all = False
                for p in problems:
                    print("  [FAIL]", p)
            else:
                print("  [PASS] KL23 三路可触发 / KL24 加权可触发 / 干净环境不误报")
    finally:
        for f in device_files:
            run([adb, "shell", "rm", "-f", f])
        for d in device_dirs:
            run([adb, "shell", "rm", "-rf", d])
        shutil.rmtree(tmpdir, ignore_errors=True)
        print("\n清理：设备临时文件已删；本地临时目录 %s 存在=%s"
              % (tmpdir, os.path.exists(tmpdir)))

    print("\n总判定 :", "ALL PASS" if ok_all else "有 FAIL")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
