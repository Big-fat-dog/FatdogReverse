#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""L47 幽冥合卷 · native 解密路径回归验收

背景（2026-10-27）：libfelix 的 nativeDecrypt 把未清零的栈缓冲直接交给
NewStringUTF，PKCS7 填充(0x07) + 上一栈帧残留(enc_hex 片段) 被当成明文返回，
客户端 Integer.parseInt 抛 NumberFormatException:
    For input string: "64␇␇␇␇␇␇␇7ab87ffa3f9a"

本脚本做三件事：
  1) 编 felix.c 的宿主自测（-DM9_HOST_TEST），断言 CRC / AES 回环 / 解密截断三项；
  2) 静态检查 nativeDecrypt 走 m9_decrypt_text 且该函数显式补 NUL；
  3) 用 server.py 真实密文（真 + 诱饵两条派生路径）对拍 C 侧解密结果。

用法：python tools/verify_l47_native.py
"""
import importlib.util
import io
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
JNI = os.path.join(ROOT, "app", "jni")
GCC = r"D:\mingw64\bin\gcc.exe"

ok = True


def fail(msg):
    global ok
    ok = False
    print("[FAIL] " + msg)


def step(title):
    print("\n=== " + title + " ===")


# ---------------------------------------------------------------- 1) 宿主自测
step("1. 宿主自测（felix.c -DM9_HOST_TEST）")
exe = os.path.join(JNI, "_l47_selftest.exe")
cmd = [GCC, "-DM9_HOST_TEST", "-O2", "-Wall", "-Wextra", "-o", exe, "felix.c"]
r = subprocess.run(cmd, cwd=JNI, capture_output=True, text=True)
if r.returncode != 0:
    fail("编译失败:\n" + (r.stderr or "")[:800])
else:
    if r.stderr.strip():
        print("编译警告:\n" + r.stderr.strip()[:800])
    r = subprocess.run([exe], cwd=JNI, capture_output=True, text=True)
    out = r.stdout
    print(out.strip())
    checks = [
        ("CRC 基准", lambda: "-> PASS" in out and "0xe3bcc2cd" in out),
        ("AES 回环 page=1", lambda: "dec(page=1) = page=1 (len=6" in out),
        ("解密按长度截断", lambda: "trim=PASS" in out),
        ("明文内容一致", lambda: "body=PASS" in out),
        ("守卫真路径", lambda: "sealed_ok(real) = 1" in out),
        ("守卫诱饵路径", lambda: "sealed_ok(bad cert) = 0" in out),
    ]
    for name, fn in checks:
        print(("  [OK]   " if fn() else "  [FAIL] ") + name)
        if not fn():
            fail(name)

# ---------------------------------------------------------------- 2) 静态检查
step("2. 源码静态检查")
src = io.open(os.path.join(JNI, "felix.c"), encoding="utf-8").read()
if "m9_decrypt_text(hex, v, out, sizeof(out))" not in src:
    fail("nativeDecrypt 没有走 m9_decrypt_text（可能被改回直接 NewStringUTF(plain)）")
else:
    print("  [OK]   nativeDecrypt -> m9_decrypt_text")

m = re.search(r"static int m9_decrypt_text\(.*?\n\}", src, re.S)
if not m:
    fail("找不到 m9_decrypt_text 实现")
else:
    body = m.group(0)
    for need, desc in (("memset(plain, 0, sizeof(plain))", "解密缓冲清零"),
                       ("out[pt_len] = 0", "按明文长度补 NUL"),
                       ("pt_len >= cap", "目标缓冲容量校验")):
        print(("  [OK]   " if need in body else "  [FAIL] ") + desc)
        if need not in body:
            fail(desc)

if re.search(r"NewStringUTF\(env,\s*\(const char \*\)plain\)", src):
    fail("仍存在 NewStringUTF(env, (const char *)plain) 直传未截断缓冲")
else:
    print("  [OK]   无直传 plain 缓冲")

# PKCS7 填充下标（曾用 block[j - full] 产生负下标写坏栈）
if "block[j - full]" in src:
    fail("AES 加密填充仍用 block[j - full]（负下标越界）")
else:
    print("  [OK]   填充下标无负值")

# ---------------------------------------------------------------- 3) 真密文对拍
step("3. 服务端真实密文对拍（真 / 诱饵）")
probe = os.path.join(JNI, "_l47_probe.c")
probe_exe = os.path.join(JNI, "_l47_probe.exe")
probe_src = """#define M9_HOST_TEST 1
#define main felix_selftest_main
#include "felix.c"
#undef main
int main(int argc, char **argv) {
    char out[129];
    int n;
    setvbuf(stdout, NULL, _IONBF, 0);
    g_door = M9_DOOR_OPEN;
    g_crc_ready = 1; g_checked = 1;
    g_guard.audit = 1; g_guard.tick = 0xABCD; g_guard.recheck = 1;
    g_guard.cert_ok = (argc > 3 && argv[3][0] == 'd') ? 0 : 1;
    n = m9_decrypt_text(argv[2], argv[1], out, sizeof(out));
    if (n <= 0) return 1;
    printf("%s", out);
    return 0;
}
"""
try:
    io.open(probe, "w", encoding="utf-8", newline="").write(probe_src)
    r = subprocess.run([GCC, "-O2", "-Wall", "-o", probe_exe, "_l47_probe.c"],
                       cwd=JNI, capture_output=True, text=True)
    if r.returncode != 0:
        fail("probe 编译失败: " + (r.stderr or "")[:400])
    else:
        spec = importlib.util.spec_from_file_location("srv", os.path.join(ROOT, "server.py"))
        srv = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(srv)
        vt = "0123456789abcdef"
        for tag, marker, src_nums, mode in (
                ("真数据", srv._L47_MARKER, srv.NUMS47, "real"),
                ("诱饵数据", srv._L47_DMARKER, srv.NUMS47_DIRTY, "decoy")):
            body = "page=1|nums=" + ",".join(str(n) for n in src_nums[:srv.PER_PAGE47])
            d = srv.aes_enc(srv._l47_key(marker, vt), body.encode()).hex()
            r = subprocess.run([probe_exe, vt, d, mode], cwd=JNI,
                               capture_output=True, text=True)
            got = r.stdout
            if got == body:
                print("  [OK]   %s  %d 字节密文 → 明文完全一致" % (tag, len(d) // 2))
            else:
                fail("%s 解密不一致: %r != %r" % (tag, got[:60], body[:60]))
finally:
    for p in (probe, probe_exe, exe):
        if os.path.isfile(p):
            os.remove(p)

print("\n" + ("ALL PASS" if ok else "存在失败项"))
sys.exit(0 if ok else 1)
