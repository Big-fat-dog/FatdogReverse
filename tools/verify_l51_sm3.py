#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""L51 SM3 一致性验收（2026-11-17 修回标准 SM3 后新增）

校验三件事：
  1. server.py 的 sm3_hash 与标准 SM3（hashlib / 官方测试向量）逐字节一致
  2. libturtle 的 sm3_hex（C++）与标准 SM3 一致，覆盖 55/56/64/65 等填充边界
  3. L51 端到端：用**标准 SM3**（hashlib）算 sig，跑满 100 页全部 200，求和 51340；
     用旧的"长度字段写字节数"实现算 sig，必须 403

用法：python tools/verify_l51_sm3.py
可选：环境变量 MINGW_GXX 指定宿主 g++（默认 D:/mingw64/bin/g++.exe）
"""
import hashlib
import importlib.util
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(HERE)

FAIL = []


def check(name, cond, detail=""):
    print(("[PASS] " if cond else "[FAIL] ") + name + (("  " + detail) if detail else ""))
    if not cond:
        FAIL.append(name)


def load_server():
    spec = importlib.util.spec_from_file_location("srv_l51", os.path.join(HERE, "server.py"))
    srv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(srv)
    return srv


# ---------- 1) 服务端 SM3 = 标准 SM3 ----------
def check_server_sm3(srv):
    vectors = [
        (b"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
        (b"abcd" * 16, "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"),
    ]
    ok = True
    for msg, expect in vectors:
        got = srv.sm3_hash(msg).hex()
        ok &= (got == expect)
        print("       长度 %d: %s" % (len(msg), got))
    check("server.sm3_hash 命中官方测试向量", ok)

    ok = True
    for n in (0, 1, 3, 55, 56, 63, 64, 65, 119, 120, 200):
        data = bytes((i * 37 + 11) & 0xFF for i in range(n))
        ok &= (srv.sm3_hash(data).hex() == hashlib.new("sm3", data).hexdigest())
    check("server.sm3_hash == hashlib('sm3')（含填充边界 55/56/64/65）", ok)


# ---------- 2) libturtle 的 C++ SM3 = 标准 SM3 ----------
TURTLE_MAIN = r"""
#include <cstdio>
#include <cstring>
#include <string>
#include <cstdint>
#include <vector>
extern "C" const char* tt_mark(const unsigned char* data, int len);
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const int sizes[] = {0, 1, 3, 55, 56, 63, 64, 65, 119, 120, 200};
    std::vector<unsigned char> buf;
    for (int k = 0; k < (int)(sizeof(sizes)/sizeof(sizes[0])); k++) {
        int n = sizes[k];
        buf.assign(n > 0 ? n : 1, 0);
        for (int i = 0; i < n; i++) buf[i] = (unsigned char)((i * 37 + 11) & 0xFF);
        printf("%d %s\n", n, tt_mark(buf.data(), n));
    }
    return 0;
}
"""


def check_native_sm3():
    gxx = os.environ.get("MINGW_GXX", r"D:/mingw64/bin/g++.exe")
    if not os.path.isfile(gxx):
        print("[SKIP] 未找到宿主 g++（%s），跳过 C++ 侧校验" % gxx)
        return
    tmpdir = tempfile.mkdtemp(prefix="l51sm3_")
    main_cpp = os.path.join(tmpdir, "main.cpp")
    exe = os.path.join(tmpdir, "t.exe")
    with open(main_cpp, "w", encoding="utf-8") as f:
        f.write(TURTLE_MAIN)
    try:
        cp = subprocess.run([gxx, "-O2", "-Wall", "-Wextra", "-o", exe,
                             os.path.join(HERE, "app", "jni", "turtle.cpp"), main_cpp],
                            capture_output=True, text=True)
        if cp.returncode != 0:
            check("libturtle 宿主编译", False, (cp.stderr or "")[:400])
            return
        check("libturtle 宿主编译", True)
        out = subprocess.run([exe], capture_output=True, text=True).stdout
        ok = True
        for line in out.strip().splitlines():
            n_s, got = line.split()
            n = int(n_s)
            data = bytes((i * 37 + 11) & 0xFF for i in range(n))
            ok &= (got == hashlib.new("sm3", data).hexdigest())
        check("libturtle.sm3_hex == 标准 SM3（含填充边界）", ok)
    finally:
        for p in (main_cpp, exe):
            if os.path.exists(p):
                os.remove(p)
        if os.path.isdir(tmpdir):
            os.rmdir(tmpdir)


# ---------- 3) L51 端到端 ----------
def sm3_byte_len_bug(msg, srv):
    """旧实现：填充长度字段写字节数（非标准），仅用于反例。"""
    n = len(msg)
    m = msg + b"\x80" + b"\x00" * ((55 - n) % 64) + n.to_bytes(8, "big")
    V = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
         0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
    for i in range(0, len(m), 64):
        V = srv._sm3_cf(V, m[i:i + 64])
    return b"".join(v.to_bytes(4, "big") for v in V).hex()


def check_e2e(srv):
    from Crypto.Cipher import DES3
    from Crypto.Util.Padding import pad

    srv._check_ts = lambda t: None          # 绕 600s 时间窗，纯协议校验
    ts = 1794663996

    def enc_of(page):
        return DES3.new(srv.KEY51_3DES[:24], DES3.MODE_ECB) \
                    .encrypt(pad(("page=%d&ts=%d" % (page, ts)).encode(), 8)).hex()

    total, ok, status = 0, True, ""
    for page in range(1, 101):
        enc = enc_of(page)
        sig = hashlib.new("sm3", srv.KEY51_SM3_SALT + enc.encode()).hexdigest()
        try:
            r = srv.api_l51(enc=enc, sig=sig, ts=ts)
        except Exception as e:                                  # noqa: BLE001
            ok = False
            status = "page %d -> %s %s" % (page, getattr(e, "status_code", "?"),
                                           getattr(e, "detail", e))
            break
        total += sum(r["nums"])
        ok &= (r["page"] == page and len(r["nums"]) == 10)
    check("100 页 × 标准 SM3 → 全部 200", ok, status)
    check("求和 = 51340", total == 51340, "实得 %d" % total)

    enc1 = enc_of(1)
    rejected = False
    try:
        srv.api_l51(enc=enc1, sig=sm3_byte_len_bug(srv.KEY51_SM3_SALT + enc1.encode(), srv), ts=ts)
    except Exception as e:                                      # noqa: BLE001
        rejected = (getattr(e, "status_code", 0) == 403)
    check("旧『字节数填充』的 sig 被 403 拒绝", rejected)


def main():
    srv = load_server()
    import sys as _sys
    _sys.modules["srv_l51"] = srv
    check_server_sm3(srv)
    check_native_sm3()
    check_e2e(srv)
    print()
    if FAIL:
        print("结果：%d 项 FAIL -> %s" % (len(FAIL), ", ".join(FAIL)))
        return 1
    print("结果：ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
