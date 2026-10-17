# -*- coding: utf-8 -*-
"""L26 mTLS 资产自检：确认 app/assets/mt_client.p12 是 Android 能读的 legacy PKCS12。

背景（2026-10-17 真机踩坑）：
Android 的 PKCS12 KeyStore（BouncyCastle）只认 PBES1
（pbeWithSHA1And3-KeyTripleDES-CBC / RC2-40）+ HmacPBESHA1。
用 cryptography 的 BestAvailableEncryption() 会写成 PBES2/PBKDF2/AES-256-CBC，
App 里 KeyStore.load() 抛 "NoSuchAlgorithmException: 1.2.840.113549.1.5.12"，
表现是第 26 关一进页面就请求失败，连 TLS 握手都发不出去。

用法：
    python tools/verify_l26_mtls.py
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P12 = os.path.join(HERE, "app", "assets", "mt_client.p12")
PASS = "fatdemo_mt26"
GOOD = "pbeWithSHA1And3-KeyTripleDES-CBC"


def find_openssl():
    p = shutil.which("openssl")
    if p:
        return p
    for c in (r"C:\Program Files\Git\usr\bin\openssl.exe",
              r"C:\Program Files\Git\mingw64\bin\openssl.exe",
              r"C:\Program Files (x86)\Git\usr\bin\openssl.exe"):
        if os.path.exists(c):
            return c
    return None


def main():
    ok = True
    if not os.path.exists(P12):
        print("FAIL: 缺少 " + P12)
        return 1

    openssl = find_openssl()
    if not openssl:
        print("FAIL: 找不到 openssl，无法解析 p12 的加密算法")
        return 1

    r = subprocess.run([openssl, "pkcs12", "-in", P12, "-passin", "pass:" + PASS,
                        "-info", "-noout"],
                       capture_output=True, text=True, errors="ignore")
    info = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0:
        print("FAIL: 用密码 %s 打不开 p12\n%s" % (PASS, info))
        return 1

    print("--- p12 加密算法 ---")
    for line in info.strip().splitlines():
        print("  " + line.strip())

    if "PBES2" in info or "PBKDF2" in info:
        print("FAIL: 仍是 PBES2/PBKDF2，Android 解不开（见 SKILL.md 坑位 15）")
        ok = False
    if GOOD not in info:
        print("FAIL: 未使用 %s" % GOOD)
        ok = False
    if "MAC: sha1" not in info:
        print("FAIL: MAC 不是 sha1（Android 只支持 HmacPBESHA1）")
        ok = False

    # 私钥必须能取出来（KeyManagerFactory 需要 PrivateKeyEntry）
    r2 = subprocess.run([openssl, "pkcs12", "-in", P12, "-passin", "pass:" + PASS,
                         "-nocerts", "-nodes"],
                        capture_output=True, text=True, errors="ignore")
    if "PRIVATE KEY" not in (r2.stdout or ""):
        print("FAIL: 取不到私钥（不是 PrivateKeyEntry？）")
        ok = False

    print("\n" + ("ALL PASS" if ok else "FAILED") + "  <- " + os.path.relpath(P12, HERE))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
